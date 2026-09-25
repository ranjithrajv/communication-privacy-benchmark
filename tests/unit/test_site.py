"""Site rendering from a finalized run bundle.

A published page is the artifact most likely to be read without the run that produced it:
it is indexable, quotable cell by cell, and cached indefinitely. The contract this file
protects is therefore mostly *refusal* — a policy that does not permit pages must not get
one, and a run that did not clear the gate must say so on the page rather than vanish.

The remaining risk is a page that renders faithfully but subtly lies: a rate printed
without its interval, a non-establishing cell styled like a clean one, or an orientation
that quietly transposes apps and checks. Those are asserted here at the rendered-HTML
boundary, because that is the surface a reader actually receives.
"""

from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from privacy_benchmark.harness.site import HTMX_SOURCE, SiteError, build_site

_VOID = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "source",
    "track",
    "wbr",
}


class _WellFormed(HTMLParser):
    """Assert balanced tags, so a malformed page cannot pass as a rendering."""

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.problems: list[str] = []

    def handle_starttag(self, tag: str, attrs: object) -> None:
        if tag not in _VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if not self.stack:
            self.problems.append(f"stray </{tag}>")
        elif self.stack[-1] != tag:
            self.problems.append(f"expected </{self.stack[-1]}>, got </{tag}>")
        else:
            self.stack.pop()


def _assert_well_formed(text: str, label: str) -> None:
    parser = _WellFormed()
    parser.feed(text)
    assert not parser.problems, f"{label}: {parser.problems[:3]}"
    assert not parser.stack, f"{label}: unclosed {parser.stack}"


@pytest.fixture
def bundle(repository_root: Path, tmp_path: Path):
    """Aggregate a real bundle of `repetitions` repetitions through the harness.

    Built from the same production entry points a run uses, because the contract is what a
    reader is actually handed. The repetition count is overridden on the plan since the
    checked-in smoke suite pins one, and a rate only exists once a check repeats.
    """

    from privacy_benchmark.adapters.fake import FakeAdapter
    from privacy_benchmark.harness.aggregation import aggregate_run
    from privacy_benchmark.harness.execution import run_execution
    from privacy_benchmark.harness.planning import build_run_plan
    from privacy_benchmark.spec.models import ExecutionMode
    from privacy_benchmark.spec.registry import Registry

    def _build(repetitions: int) -> Path:
        plan = build_run_plan(
            repository_root / "suites" / "smoke" / "1.0.0" / "suite.toml",
            repository_root,
            execution_mode=ExecutionMode.LOCAL,
            github=None,
        )
        if repetitions != plan.repetitions:
            plan = plan.model_copy(
                update={"repetitions": repetitions, "expected_execution_count": repetitions}
            )
        registry = Registry.load(repository_root)
        subject_ref, check_ref = plan.subjects[0], plan.checks[0]
        subject = registry.resolve_subject(
            f"{subject_ref.subject_id}@{subject_ref.subject_version}"
        )
        check = registry.resolve_check(f"{check_ref.check_id}@{check_ref.version}")
        workdir = tmp_path / f"exec-{repetitions}"
        for repetition in range(1, repetitions + 1):
            asyncio.run(
                run_execution(
                    plan=plan,
                    subject=subject,
                    checks=(check,),
                    execution_dir=workdir / subject_ref.subject_id / f"{repetition:04d}",
                    repetition=repetition,
                    adapter=FakeAdapter(),
                )
            )
        out = tmp_path / f"bundle-{repetitions}"
        aggregate_run(plan=plan, executions_root=workdir, output_dir=out)
        return out

    return _build


@pytest.fixture
def built(repository_root: Path, tmp_path: Path, bundle) -> Path:
    """A built site for a three-repetition run, which is the case that shows a rate."""

    source = bundle(3)
    site = tmp_path / "site"
    build_site(bundle_directory=source, output_directory=site, root=repository_root)
    return site


def _page(site: Path, name: str) -> str:
    return (site / name).read_text(encoding="utf-8")


def test_a_page_is_refused_when_the_policy_does_not_permit_one(
    repository_root: Path, tmp_path: Path, bundle
) -> None:
    from privacy_benchmark.spec.operations import OperationsRegistry

    registry = OperationsRegistry.load(repository_root)
    policy = registry.policy
    assert policy.publication.target.value == "github_pages", (
        "the checked-in policy must permit pages, or this test is asserting nothing"
    )

    # The refusal is driven through a real policy file that names a different venue, so the
    # guard is exercised on a parsed policy rather than a mock. The file is copied rather
    # than symlinked: a symlinked directory would let `write_text` follow the link and edit
    # the checked-in policy, which is exactly the kind of test that corrupts its own fixture.
    refusing_root = tmp_path / "refusing-root"
    version_directory = refusing_root / "operations" / "1.0.0"
    version_directory.mkdir(parents=True)
    checked_in = repository_root / "operations" / "1.0.0" / "operations.toml"
    policy_path = version_directory / "operations.toml"
    policy_path.write_text(
        checked_in.read_text().replace('target = "github_pages"', 'target = "github_releases"')
    )
    assert checked_in.read_text() != policy_path.read_text(), "the copy must differ"

    output = tmp_path / "site"
    with pytest.raises(SiteError, match="github_releases"):
        build_site(bundle_directory=bundle(1), output_directory=output, root=refusing_root)
    assert not output.exists(), "a refused policy must leave no site behind"


def test_a_run_that_fails_the_gate_says_so_on_the_page(
    repository_root: Path, tmp_path: Path, bundle
) -> None:
    # The harness smoke run is local and complete, so it fails the canonical gate. The page
    # must still exist and must name the reason: a refused run rendered is a record, while a
    # refused run that vanished is indistinguishable from one that never ran.
    site = tmp_path / "site"
    result = build_site(bundle_directory=bundle(1), output_directory=site, root=repository_root)

    assert result.publishable is False
    assert result.not_publishable_because
    assert (site / "index.html").is_file()

    report = next(path for path in site.rglob("index.html") if "runs" in path.parts)
    text = _page(site, str(report.relative_to(site)))
    assert "Not a benchmark result" in text
    assert "gate--closed" in text
    assert "local mode" in text


def test_a_decisive_rate_is_never_printed_without_its_interval(built: Path) -> None:
    report = next(path for path in built.rglob("index.html") if "runs" in path.parts)
    text = _page(built, str(report.relative_to(built)))

    # Every percentage in the page must sit in a cell that also states its interval. This is
    # the single most over-readable claim a page can make, because a cell gets copied out
    # of context: `pass 100%` on three repetitions is anywhere in [44%, 100%].
    percentages = re.findall(r'<span class="rate">(\d+%)</span>', text)
    assert percentages, "a three-repetition run must render a rate"
    assert text.count("95% CI") == len(percentages)

    # The interval is an entity-escaped en dash, so the bounds are read as entities rather
    # than matched as literal text. Three passing repetitions are [43.9%, 100%], and that
    # lower bound is the whole point: it is what stops `pass` reading as a guarantee.
    interval = re.search(r"95% CI ([\d.]+)&ndash;([\d.]+)%", text)
    assert interval is not None
    low, high = (float(bound) for bound in interval.groups())
    assert (low, high) == pytest.approx((43.9, 100.0))


def test_a_single_repetition_prints_no_rate_at_all(
    repository_root: Path, tmp_path: Path, bundle
) -> None:
    # One observation supports no proportion. The markdown matrix withholds the rate for
    # this case, so the page must agree rather than being the copy that shows a percentage.
    site = tmp_path / "site"
    build_site(bundle_directory=bundle(1), output_directory=site, root=repository_root)
    report = next(path for path in site.rglob("index.html") if "runs" in path.parts)

    text = _page(site, str(report.relative_to(site)))
    assert 'class="rate"' not in text
    assert "95% CI" not in text


def test_apps_head_the_columns_and_checks_run_down_the_rows(built: Path) -> None:
    report = next(path for path in built.rglob("index.html") if "runs" in path.parts)
    text = _page(built, str(report.relative_to(built)))

    header = re.search(r"<thead>(.*?)</thead>", text, re.DOTALL)
    assert header is not None
    columns = re.findall(r'<th scope="col"[^>]*>([^<]+)</th>', header.group(1))
    rows = re.findall(r'<th scope="row" class="check">([^<]+)</th>', text)

    # Transposing swaps these two lists, and an assertion that only counted cells would
    # pass on a transposed table too.
    assert columns == ["check", "Fake Client"]
    assert rows == ["harness.smoke"]


def test_every_rendered_page_is_well_formed(built: Path) -> None:
    pages = sorted(built.rglob("*.html"))
    assert len(pages) >= 4
    for page in pages:
        _assert_well_formed(page.read_text(encoding="utf-8"), str(page.relative_to(built)))


def test_the_page_works_without_javascript(built: Path) -> None:
    report = next(path for path in built.rglob("index.html") if "runs" in path.parts)
    text = _page(built, str(report.relative_to(built)))

    # GitHub Pages serves static files, so htmx is enhancement over content already in the
    # document. The results table is present in the served HTML, not fetched into it, or the
    # page would be unreadable without JavaScript and would depend on a CDN staying up.
    assert '<div id="results">' in text
    assert '<table class="outcomes">' in text
    assert "harness.smoke" in text


def test_htmx_is_pinned_and_loaded_only_where_it_is_used(built: Path) -> None:
    report = next(path for path in built.rglob("index.html") if "runs" in path.parts)
    text = _page(built, str(report.relative_to(built)))

    # htmx 4 ships under the npm `next` tag while 2.x remains `latest` until early 2027,
    # so an unpinned reference silently resolves to 2.x and runs with the implicit
    # inheritance htmx 4 removed. The exact version is what prevents that.
    assert HTMX_SOURCE.endswith("htmx.org@4.0.0/dist/htmx.min.js")
    assert HTMX_SOURCE in text
    # The manifest takes no script, so it must not pay for one.
    assert HTMX_SOURCE not in _page(built, "manifest.html")


def test_internal_links_are_relative_so_a_project_subpath_resolves(built: Path) -> None:
    for page in built.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        for attribute in re.findall(r'(?:href|src)="([^"]+)"', text):
            if attribute.startswith(("http://", "https://", "#")):
                continue
            assert not attribute.startswith("/"), (
                f"{page.relative_to(built)} links to {attribute}; a leading slash resolves "
                "to the domain root and 404s on a GitHub project site"
            )


def test_the_markdown_report_ships_beside_the_page(built: Path) -> None:
    reports = list(built.rglob("report.md"))
    assert len(reports) == 1
    text = reports[0].read_text(encoding="utf-8")

    # The page is a rendering; this is the artifact it renders. Shipping both means a
    # reader can diff what they are looking at against what the benchmark emitted.
    assert text.startswith("# smoke@1.0.0 report")
    assert "## Reason codes" in text


def test_the_manifest_lists_this_runs_files(built: Path) -> None:
    manifest = _page(built, "manifest.html")

    # A record of this bundle, not a second site index: two indexes would drift, and the
    # manifest's job is to say which files a given bundle produced.
    assert "report.md" in manifest
    assert "fragments/run.html" in manifest
    # It lists this run's files, so it must not also be a second site index.
    assert "Published runs" not in manifest


def test_a_fragment_is_complete_rather_than_a_patch(built: Path) -> None:
    # htmx 4 re-fetches on history restore instead of replaying a stored snapshot, so a
    # fragment carrying only a diff would render an empty page on back navigation.
    fragment = next(built.rglob("fragments/run.html"))
    text = _page(built, str(fragment.relative_to(built)))

    assert '<table class="outcomes">' in text
    assert "harness.smoke" in text
    _assert_well_formed(text, "fragment")


def test_the_stylesheet_distinguishes_decisive_from_non_establishing(built: Path) -> None:
    css = _page(built, "static/site.css")

    # Three channels rather than one, so the distinction survives print and colour
    # blindness: the outcome word, the fill, and a dotted underline.
    assert ".cell--pass" in css
    assert ".cell--fail" in css
    assert ".cell--no-property" in css
    assert "underline dotted" in css


def test_the_outcome_word_is_always_present_in_a_cell(built: Path) -> None:
    report = next(path for path in built.rglob("index.html") if "runs" in path.parts)
    text = _page(built, str(report.relative_to(built)))

    cells = re.findall(r'<td class="cell[^"]*">(.*?)</td>', text, re.DOTALL)
    assert cells
    for cell in cells:
        assert re.search(r'<span class="outcome">\w+</span>', cell), (
            "a cell must name its outcome in text, not only in colour"
        )
