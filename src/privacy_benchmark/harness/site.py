"""Render a publishable run bundle as a static GitHub Pages site.

The site is a *view* over bundles that have already cleared the publication gate, not a
second artifact of record. Every page is regenerated from the bundle, so a page can never
drift from the evidence it describes, and the receipt plus the release asset remain what a
reader cites.

Four decisions shape this module, and each of them is a way the obvious implementation
would misrepresent a run:

**The gate is re-derived, never assumed.** :func:`build_site` runs
:func:`~privacy_benchmark.harness.publishing.evaluate_publication` itself rather than
trusting a caller, a receipt on disk, or the report's own opinion. It matters that both
gates are consulted: ``evaluate_publication`` knows about policy status, redaction, and
per-subject terms reviews, while the report's :func:`~privacy_benchmark.harness.report.publishable`
knows about execution mode and completion, and each knows things the other does not. A page
is the artifact most likely to be read without the run that produced it, so it is the last
point at which a non-canonical run can be kept off the public site.

**A refusal is rendered, not raised.** When the gate refuses, the reasons go *into* the
page. The two alternatives are "publish it" or "emit no output", and the second is the one
a reader most needs: a bundle that was refused with its reasons shown is a record, while a
bundle that vanished is indistinguishable from one that never ran.

**HTML is built from the models, not by converting the markdown report.** The markdown
report is a rendering; parsing it back into a table would make every cell a re-derivation
of a string. Both views are produced from the same rollup, and the markdown ships verbatim
beside the HTML as the raw artifact, so a reader can diff what they are looking at against
what the benchmark actually emitted.

**The confidence interval cannot be separated from its rate.** A page is quotable in a way
a diff is not — one cell gets screenshotted, copied into a chat, and read with no other
context — so the interval is rendered inside the same cell as the rate, and a cell with no
interval says so rather than showing a bare percentage.

HTMX 4 enhances a site that already works. GitHub Pages serves static files, so the
"server" is the filesystem: every fragment htmx can request is pre-rendered here, and the
page is fully readable with JavaScript disabled. The attributes htmx adds are progressive
enhancement over content that is already present, never the only copy of it.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from pathlib import Path

from privacy_benchmark.harness.analysis import BundleAnalysis, load_bundle, rollup_bundle
from privacy_benchmark.harness.publishing import evaluate_publication
from privacy_benchmark.harness.report import (
    ReportProvenance,
    provenance_of,
    publishable,
    render_report,
)
from privacy_benchmark.spec.models import CheckRollup, RollupOutcome, RunRollup
from privacy_benchmark.spec.operations import OperationsRegistry, PublicationTarget

#: Pinned to an exact version, deliberately without a subresource-integrity hash. htmx 4
#: ships under the npm `next` dist-tag and 2.x remains `latest` until early 2027, so
#: `unpkg.com/htmx.org/dist/...` resolves to 2.x and the page then silently runs with the
#: implicit attribute inheritance that htmx 4 removed. An exact pin is what prevents that.
#: SRI is omitted rather than filled with a placeholder: a wrong hash makes the browser
#: refuse the script outright, which is a worse and more confusing failure than a pinned
#: version without one.
HTMX_SOURCE = "https://unpkg.com/htmx.org@4.0.0/dist/htmx.min.js"

#: The two outcomes that establish a product property. Every other cell is marked as
#: establishing nothing, in the cell itself rather than only in the page's footnotes.
ESTABLISHING = frozenset({RollupOutcome.PASS, RollupOutcome.FAIL})

#: Rendered in a cell for a planned check that has no rollup at all. Deliberately distinct
#: from a cell reporting `inconclusive`: a missing measurement and a measurement that
#: established nothing are different facts.
ABSENT_CELL = "—"


class SiteError(RuntimeError):
    """Raised when a site cannot be built at all."""


@dataclass(frozen=True, slots=True)
class SitePage:
    """One rendered file and where it belongs in the site."""

    path: str
    text: str


@dataclass(frozen=True, slots=True)
class SiteResult:
    """What a build produced, so a caller can report it without re-reading the tree."""

    bundle_id: str
    output_directory: Path
    pages: tuple[SitePage, ...]
    publishable: bool
    not_publishable_because: tuple[str, ...]


def _escape(value: str) -> str:
    return html.escape(value, quote=True)


def _depth(path: str) -> int:
    """How many path segments sit above a page, for building a root-relative prefix.

    Derived from the path rather than passed in, because a hand-passed depth is wrong the
    moment a page moves and fails silently as a 404 rather than as an error.
    """

    return path.count("/")


def _interval(check: CheckRollup) -> str | None:
    """The 95% interval qualifying a rate, or None when none was established."""

    if check.pass_rate is None or check.pass_rate_low is None or check.pass_rate_high is None:
        return None
    return f"{check.pass_rate_low * 100:.1f}&ndash;{check.pass_rate_high * 100:.1f}%"


def _cell(check: CheckRollup | None, repetitions: int) -> str:
    """Render one check/app cell, keeping a rate and its interval inseparable.

    The interval only means something next to the rate it qualifies, and a cell is the unit
    a reader copies out of context, so they are emitted as one element rather than as two
    columns of a table further down the page.
    """

    if check is None:
        return f'<td class="cell cell--absent" title="no result recorded">{ABSENT_CELL}</td>'

    established = check.outcome in ESTABLISHING
    rate = ""
    # The matrix withholds a rate for a single-repetition run, and this must agree with it:
    # a page is the wider surface, so a percentage appearing here but not there would be
    # the more over-read copy of the two.
    if repetitions > 1 and check.pass_rate is not None:
        interval = _interval(check)
        rate = f'<span class="rate">{check.pass_rate * 100:.0f}%</span>'
        rate += (
            f'<span class="interval">95% CI {interval}</span>'
            if interval is not None
            else '<span class="interval">no interval established</span>'
        )

    classes = "cell--pass" if established else "cell--no-property"
    return (
        f'<td class="cell {classes}">'
        f'<span class="outcome">{_escape(check.outcome.value)}</span>{rate}</td>'
    )


def _outcomes_table(rollup: RunRollup) -> str:
    """Apps as columns, checks as rows.

    The same orientation contract the markdown matrix holds: a reader compares apps down a
    column with the check held fixed, which is the only comparison these results support.
    Row order follows the plan's declared check order and column order the plan's declared
    subject order, so a suite that declares Signal, WhatsApp, Telegram renders that way and
    column order never implies a ranking.
    """

    index = {
        (check.check.check_id, subject.subject.subject_id): check
        for subject in rollup.subjects
        for check in subject.checks
    }
    order: list[str] = []
    for subject in rollup.subjects:
        for check in subject.checks:
            if check.check.check_id not in order:
                order.append(check.check.check_id)

    head = "".join(
        '<th scope="col" class="app">'
        f"{_escape(subject.client_name or subject.subject.subject_id)}</th>"
        for subject in rollup.subjects
    )
    body = "".join(
        "<tr>"
        f'<th scope="row" class="check">{_escape(check_id)}</th>'
        + "".join(
            _cell(index.get((check_id, subject.subject.subject_id)), rollup.repetitions)
            for subject in rollup.subjects
        )
        + "</tr>"
        for check_id in order
    )

    return (
        '<table class="outcomes">'
        "<caption>One column per app, one row per check. Read down a column to compare apps "
        "on a single check, which is the only comparison these results support. A rate "
        "appears only where the plan repeated the check, and never without its interval.</caption>"
        '<thead><tr><th scope="col" class="corner">check</th>'
        f"{head}</tr></thead>"
        f"<tbody>{body}</tbody>"
        "</table>"
    )


def _reason_table(rollup: RunRollup) -> str:
    """The reason codes, which are what actually distinguish two non-establishing cells."""

    rows = "".join(
        "<tr>"
        f"<td><code>{_escape(check.check.check_id)}</code></td>"
        f"<td><code>{_escape(subject.subject.subject_id)}</code></td>"
        f'<td class="outcome">{_escape(check.outcome.value)}</td>'
        "<td>"
        + (
            ", ".join(f"<code>{_escape(code)}</code>" for code in check.reason_codes)
            if check.reason_codes
            else '<span class="muted">none recorded</span>'
        )
        + "</td></tr>"
        for subject in rollup.subjects
        for check in subject.checks
    )
    return (
        '<table class="reasons">'
        "<thead><tr><th>check</th><th>subject</th><th>outcome</th><th>reason codes</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def _gate_banner(reasons: tuple[str, ...]) -> str:
    """Render publication refusals in the page rather than raising them."""

    if not reasons:
        return (
            '<p class="gate gate--open" id="publication-gate">'
            "This run cleared the publication gate: complete, produced by GitHub Actions, "
            "with every subject&rsquo;s provider-terms review approved.</p>"
        )
    items = "".join(f"<li>{_escape(reason)}</li>" for reason in reasons)
    return (
        '<div class="gate gate--closed" id="publication-gate">'
        "<h2>Not a benchmark result</h2>"
        "<p>This run did not clear the publication gate. It is published so the reason is "
        "on the record, not so it can be cited:</p>"
        f"<ul>{items}</ul></div>"
    )


def _facts(provenance: ReportProvenance) -> str:
    """Provenance, so any cell on the page traces back to a run."""

    fields = (
        ("Suite", provenance.suite),
        ("Plan", provenance.plan_id),
        ("Bundle", provenance.bundle_id),
        ("Mode", provenance.execution_mode.value),
        ("Completion", provenance.completion.value),
        ("Repetitions", str(provenance.repetition_count)),
        ("Subjects", str(provenance.subject_count)),
        ("Evidence records", str(provenance.evidence_count)),
    )
    return (
        '<dl class="facts">'
        + "".join(
            f"<div><dt>{_escape(label)}</dt><dd><code>{_escape(value)}</code></dd></div>"
            for label, value in fields
        )
        + "</dl>"
    )


def _results(rollup: RunRollup, provenance: ReportProvenance, reasons: tuple[str, ...]) -> str:
    """The swappable results region, complete on its own.

    A complete region rather than a diff against the shell, because htmx 4 re-fetches on
    history restore instead of replaying a stored snapshot, so a fragment that only carried
    a patch would render an empty page on back navigation.
    """

    return (
        f"{_gate_banner(reasons)}{_facts(provenance)}"
        f"{_outcomes_table(rollup)}"
        f"<h2>Reason codes</h2>"
        f"{_reason_table(rollup)}"
    )


def _page(*, title: str, body: str, path: str, with_htmx: bool) -> str:
    """Wrap content in the site shell.

    Every internal link is relative. A GitHub project site is served from a repository
    subpath, so a leading ``/`` resolves to the domain root and 404s on a page that builds
    and lints cleanly.
    """

    root = "../" * _depth(path)
    script = f'  <script src="{HTMX_SOURCE}"></script>\n' if with_htmx else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_escape(title)}</title>
<link rel="stylesheet" href="{root}static/site.css">
{script}</head>
<body>
<a class="skip" href="#main">Skip to results</a>
<header class="masthead">
  <p class="wordmark">Communication Privacy Benchmark</p>
  <p class="tagline">Per-check, per-subject outcomes. No overall privacy grade.</p>
</header>
<main id="main">
{body}
</main>
<footer class="colophon">
  <p>Generated from a checksummed run bundle and regenerated from that bundle on every
  publish; a page is never edited by hand. The release asset and its receipt remain the
  artifact of record.</p>
</footer>
</body>
</html>
"""


def _index_page(run_ids: tuple[str, ...], path: str) -> str:
    items = "".join(
        f'<li><a href="runs/{_escape(run_id)}/">{_escape(run_id)}</a></li>' for run_id in run_ids
    )
    body = (
        "<h1>Published runs</h1>"
        "<p>Every run listed here cleared the publication gate. A run that did not clear it "
        "is still published with its refusal shown, so the reason is on the record rather "
        "than inferred from an absence.</p>"
        f'<ul class="runs">{items}</ul>'
    )
    return _page(title="Published runs", body=body, path=path, with_htmx=True)


def _manifest_page(bundle_id: str, pages: tuple[SitePage, ...], path: str) -> str:
    """A self-describing index of the build.

    GitHub Pages has no server, so a page cannot ask what else exists. Writing the list to
    disk keeps the site inspectable without a backend and lets a later build diff against
    it.
    """

    entries = "".join(f"<li><code>{_escape(page.path)}</code></li>" for page in pages)
    body = (
        f"<h1>Build manifest</h1><p>Bundle <code>{_escape(bundle_id)}</code>.</p><ul>{entries}</ul>"
    )
    return _page(title="Build manifest", body=body, path=path, with_htmx=False)


CSS = """/* Communication Privacy Benchmark report styles.
   Decisive and non-establishing cells differ in fill, in ink, and in a dotted underline.
   Three channels rather than one on purpose: the outcome word is always present, and the
   underline is what preserves the distinction in print or for a reader who cannot
   separate the two fills. */
:root {
  --ink: #16181d; --muted: #5b6270; --line: #d8dce4; --bg: #ffffff;
  --pass-bg: #e8f5ec; --pass-ink: #14532d;
  --fail-bg: #fdecec; --fail-ink: #7a1d1d;
  --none-bg: #f4f5f7; --none-ink: #414852;
  --open-bg: #eef4ff; --open-line: #3b62b5;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ink: #e8eaee; --muted: #a2aab8; --line: #333842; --bg: #14161a;
    --pass-bg: #14301f; --pass-ink: #a7e0bd;
    --fail-bg: #35191a; --fail-ink: #f0b0ae;
    --none-bg: #21242b; --none-ink: #c3c9d4;
    --open-bg: #16203a; --open-line: #5b81cf;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 16px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
}
main, .masthead, .colophon { max-width: 64rem; margin: 0 auto; padding: 0 1.25rem; }
.skip { position: absolute; left: -9999px; }
.skip:focus {
  left: 1rem; top: 1rem; z-index: 10; background: var(--bg);
  padding: .5rem .75rem; border: 2px solid var(--line);
}
.masthead { padding-top: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--line); }
.wordmark { margin: 0; font-weight: 650; letter-spacing: -.01em; }
.tagline { margin: .25rem 0 0; color: var(--muted); font-size: .95rem; }
h1 { font-size: 1.5rem; margin: 1.75rem 0 .5rem; letter-spacing: -.015em; }
h2 { font-size: 1.05rem; margin: 1.75rem 0 .25rem; }
code { font: .85em/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; }
.muted { color: var(--muted); }
table { border-collapse: collapse; width: 100%; margin: .75rem 0 1rem; font-size: .95rem; }
caption {
  caption-side: top; text-align: left; color: var(--muted);
  font-size: .875rem; padding-bottom: .5rem;
}
th, td {
  text-align: left; padding: .5rem .625rem;
  border-bottom: 1px solid var(--line); vertical-align: top;
}
thead th {
  font-size: .75rem; text-transform: uppercase;
  letter-spacing: .05em; color: var(--muted);
}
.outcomes .corner, .outcomes .check { font-weight: 600; }
.outcomes .app, .outcomes .check { white-space: nowrap; }
.cell .outcome { font-weight: 600; }
.cell .rate { font-weight: 400; color: var(--muted); }
.cell .interval { display: block; font-size: .78rem; color: var(--muted); }
.cell--pass { background: var(--pass-bg); color: var(--pass-ink); }
.cell--fail { background: var(--fail-bg); color: var(--fail-ink); }
.cell--no-property {
  background: var(--none-bg); color: var(--none-ink);
  text-decoration: underline dotted 1px; text-underline-offset: 3px;
}
.cell--absent { color: var(--muted); text-align: center; }
.facts { display: flex; flex-wrap: wrap; gap: .5rem 1.75rem; margin: 1rem 0; padding: 0; }
.facts div { min-width: 9rem; }
.facts dt {
  font-size: .72rem; text-transform: uppercase;
  letter-spacing: .05em; color: var(--muted);
}
.facts dd { margin: .1rem 0 0; }
.gate { border: 1px solid; border-radius: 6px; padding: .875rem 1rem; margin: 1.25rem 0; }
.gate h2 { margin: 0 0 .35rem; font-size: 1rem; }
.gate p { margin: 0; }
.gate ul { margin: .5rem 0 0; padding-left: 1.1rem; }
.gate--open { background: var(--open-bg); border-color: var(--open-line); }
.gate--closed {
  background: var(--fail-bg); border-color: var(--fail-line); color: var(--fail-ink);
}
.runs { padding-left: 1.1rem; }
.runs li { margin: .3rem 0; }
.controls { display: flex; align-items: center; gap: .75rem; margin: 1rem 0 0; }
.controls button {
  font: inherit; padding: .35rem .8rem; cursor: pointer;
  color: var(--ink); background: var(--bg);
  border: 1px solid var(--line); border-radius: 5px;
}
.colophon {
  margin-top: 2.5rem; padding-top: 1rem; padding-bottom: 2.5rem;
  border-top: 1px solid var(--line); color: var(--muted); font-size: .875rem;
}
/* htmx request states. Opacity-based and delayed, so a static-file fetch that resolves
   faster than the delay never flashes a spinner implying a slow round trip. */
.htmx-indicator { opacity: 0; transition: opacity 200ms ease-in; }
.htmx-request .htmx-indicator, .htmx-request.htmx-indicator { opacity: 1; }
.htmx-request { cursor: progress; }
@media (prefers-reduced-motion: reduce) {
  .htmx-indicator { transition: none; }
}
"""


def build_site(
    *,
    bundle_directory: Path,
    output_directory: Path,
    root: Path,
) -> SiteResult:
    """Render one bundle as a static site.

    Refuses only when the policy itself forbids a page. Everything else — an incomplete
    run, a local run, a subject whose review is pending — renders a page carrying its own
    refusal, because a refusal a reader can see is a better outcome than a page that is
    simply absent.
    """

    # One load, two gates. `load_report` reads the bundle a second time to hand the
    # publication gate an analysis it cannot derive from a rollup, so the three lines it
    # performs are done here once and the verified analysis is shared by both.
    analysis: BundleAnalysis = load_bundle(bundle_directory)
    rollup = rollup_bundle(analysis)
    provenance = provenance_of(analysis, rollup)

    registry = OperationsRegistry.load(root)
    policy = registry.policy

    if policy.publication.target is not PublicationTarget.GITHUB_PAGES:
        raise SiteError(
            f"operations policy {policy.operations_id}@{policy.version} names publication "
            f"target {policy.publication.target.value!r}, not 'github_pages'; refusing to "
            "build a page for a policy that does not permit one"
        )

    # Both gates, because each knows something the other does not:
    # `evaluate_publication` knows about policy status, redaction, and per-subject terms
    # reviews, while `publishable` knows about execution mode and completion. Deduplicated
    # so a page lists each unmet obligation once.
    reasons = list(evaluate_publication(analysis=analysis, registry=registry).reasons)
    reasons.extend(reason for reason in publishable(provenance) if reason not in reasons)
    settled = tuple(reasons)

    run_id = str(provenance.bundle_id)
    results = _results(rollup, provenance, settled)
    run_prefix = f"runs/{run_id}/"
    fragment_path = f"{run_prefix}fragments/run.html"

    report_page = _page(
        title=f"{provenance.suite} report",
        path=f"runs/{run_id}/index.html",
        with_htmx=True,
        body=(
            f'<div id="results">{results}</div>'
            '<p class="controls">'
            f'<button type="button" hx-get="{fragment_path.removeprefix(run_prefix)}" '
            'hx-target="#results" hx-swap="innerHTML">Reload results</button>'
            '<span class="muted">Rendered from the bundle; the page is a view, not the '
            "record.</span></p>"
            "<h2>Raw report</h2>"
            '<p><a href="report.md">report.md</a> is the text this page renders.</p>'
        ),
    )
    fragment_page = _page(
        title=f"{provenance.suite} results",
        path=fragment_path,
        with_htmx=True,
        body=f'<div id="results">{results}</div>',
    )

    body_pages = (
        SitePage(f"{run_prefix}index.html", report_page),
        SitePage(fragment_path, fragment_page),
        SitePage(f"{run_prefix}report.md", render_report(rollup, provenance)),
    )
    # The manifest lists the run's own files, not the site-wide pages, so it stays a record
    # of this bundle rather than a second index that drifts from `index.html`.
    pages = (
        SitePage("index.html", _index_page((run_id,), "index.html")),
        *body_pages,
        SitePage("manifest.html", _manifest_page(run_id, body_pages, "manifest.html")),
    )

    output_directory.mkdir(parents=True, exist_ok=True)
    for page in pages:
        destination = output_directory / page.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(page.text, encoding="utf-8")
    (output_directory / "static").mkdir(parents=True, exist_ok=True)
    (output_directory / "static" / "site.css").write_text(CSS, encoding="utf-8")

    return SiteResult(
        bundle_id=run_id,
        output_directory=output_directory,
        pages=tuple(pages),
        publishable=not settled,
        not_publishable_because=settled,
    )


__all__ = [
    "ABSENT_CELL",
    "CSS",
    "ESTABLISHING",
    "HTMX_SOURCE",
    "SiteError",
    "SitePage",
    "SiteResult",
    "build_site",
]
