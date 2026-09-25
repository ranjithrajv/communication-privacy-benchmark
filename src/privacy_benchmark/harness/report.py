"""Renders a publication-ready report from a finalized run bundle.

The matrix itself is not reimplemented here. :func:`render_rollup_matrix` in
:mod:`privacy_benchmark.harness.analysis` already turns a rollup into a check-by-subject
table, and this module reuses it rather than keeping a second layout that could drift
from the first.

What is added is everything a reader needs in order to *not over-read* that table:

- the run's provenance, so a row can be traced to a suite, a plan, and a mode;
- an explicit statement that a cell is per-check and per-subject, never a grade;
- the reason codes, which are the stable key for comparing two runs; and
- a caveat whenever the run was local, incomplete, or otherwise not publishable.

That last part is the reason this is a separate module rather than a format flag on the
rollup command. Producing a table that looks authoritative from a bundle that was never
canonical is the failure this project exists to prevent, so the renderer has to be able
to refuse, and a shared helper has no business deciding that.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from privacy_benchmark.harness.analysis import (
    AnalysisError,
    BundleAnalysis,
    load_bundle,
    render_rollup_matrix,
    rollup_bundle,
)
from privacy_benchmark.spec.models import (
    CheckRollup,
    CompletionState,
    ExecutionMode,
    ResultStatus,
    RunRollup,
)


class ReportError(ValueError):
    """Raised when a bundle cannot be rendered as a report."""


#: Statuses that establish a product property. Everything else says the sample did not
#: establish one, and the report must never present them as a finding.
DECISIVE_STATUSES = frozenset({ResultStatus.PASS, ResultStatus.FAIL})

#: Cell markers. A dash is a cell with no result at all, which is different from a cell
#: whose result is `not_tested` or `inconclusive`.
_MISSING = "—"


@dataclass(frozen=True, slots=True)
class ReportProvenance:
    """Everything needed to trace a report back to the run that produced it."""

    bundle_id: str
    suite: str
    plan_id: str
    created_at: datetime
    completion: CompletionState
    execution_mode: ExecutionMode
    repetition_count: int
    subject_count: int
    evidence_count: int


def load_report(bundle_directory: Path) -> tuple[RunRollup, ReportProvenance]:
    """Verify a bundle and return its rollup and provenance together.

    A bundle is refused rather than rendered with warnings when its checksums do not
    verify, because a report is the one artifact a reader is likely to quote without
    re-running the benchmark.
    """

    try:
        bundle = load_bundle(bundle_directory)
    except AnalysisError as error:
        raise ReportError(str(error)) from error
    rollup = rollup_bundle(bundle)
    return rollup, provenance_of(bundle, rollup)


def provenance_of(bundle: BundleAnalysis, rollup: RunRollup) -> ReportProvenance:
    manifest = bundle.manifest
    modes = {execution.execution_mode for execution in manifest.execution_manifests}
    mode = modes.pop() if len(modes) == 1 else ExecutionMode.LOCAL
    return ReportProvenance(
        bundle_id=str(manifest.bundle_id),
        suite=f"{manifest.plan.suite_id}@{manifest.plan.suite_version}",
        plan_id=str(manifest.plan.plan_id),
        created_at=manifest.created_at,
        completion=manifest.completion,
        execution_mode=mode,
        repetition_count=rollup.repetitions,
        subject_count=len(rollup.subjects),
        evidence_count=manifest.evidence_count,
    )


def publishable(provenance: ReportProvenance) -> tuple[str, ...]:
    """Reasons this report must not be presented as a published benchmark result.

    Returned as a list rather than a boolean so a caller can render the reasons
    verbatim instead of collapsing them into one word.
    """

    reasons: list[str] = []
    if provenance.execution_mode is not ExecutionMode.GITHUB_ACTIONS:
        reasons.append(
            f"execution mode is `{provenance.execution_mode.value}`, not "
            "`github_actions`; a local run cannot become a canonical result"
        )
    if provenance.completion is not CompletionState.COMPLETE:
        reasons.append(f"bundle completion is `{provenance.completion.value}`")
    if not provenance.repetition_count:
        reasons.append("no repetitions were planned")
    return tuple(reasons)


def _check_index(rollup: RunRollup) -> dict[tuple[str, str], CheckRollup]:
    return {
        (check.check.check_id, subject.subject.subject_id): check
        for subject in rollup.subjects
        for check in subject.checks
    }


def _reason_cell(check: CheckRollup | None) -> str:
    if check is None:
        return _MISSING
    if not check.reason_codes:
        return _MISSING
    return ", ".join(f"`{code}`" for code in check.reason_codes)


def render_report(rollup: RunRollup, provenance: ReportProvenance) -> str:
    """Render the full report: provenance, caveats, matrix, and reason codes.

    The matrix is delegated to the analysis module so both renderings of a rollup agree.
    """

    reasons = publishable(provenance)
    lines: list[str] = [
        f"# {provenance.suite} report",
        "",
        "Per-check, per-subject outcomes. There is no overall privacy grade, and a row "
        "must not be read as one: each cell is the outcome of one check against one "
        "subject configuration.",
        "",
        "## Run",
        "",
        f"- Bundle: `{provenance.bundle_id}`",
        f"- Plan: `{provenance.plan_id}`",
        f"- Suite: `{provenance.suite}`",
        f"- Created: {provenance.created_at.astimezone().isoformat()}",
        f"- Mode: `{provenance.execution_mode.value}`",
        f"- Completion: `{provenance.completion.value}`",
        f"- Repetitions: {provenance.repetition_count}",
        f"- Subjects: {provenance.subject_count}",
        f"- Evidence records: {provenance.evidence_count}",
    ]

    lines += ["", "## Outcomes", "", render_rollup_matrix(rollup)]

    if reasons:
        lines += [
            "",
            "## Not publishable",
            "",
            "This run must not be presented as a benchmark result:",
            "",
            *(f"- {reason}" for reason in reasons),
        ]

    lines += ["", "## Reason codes", "", _reason_table(rollup), ""]
    lines += [
        "Reason codes are the stable key for comparing two runs. A verdict may be "
        "restated in different words without changing its code, and two runs that "
        "share a code are comparable even when their prose differs.",
        "",
        "An `inconclusive`, `partial`, `unsupported`, or `not_tested` outcome states that "
        "the sample did not establish a product property. Only `pass` and `fail` do, and "
        "only those two are ordered when two runs are compared.",
        "",
    ]
    return "\n".join(lines)


def _reason_table(rollup: RunRollup) -> str:
    header = ["check", "subject", "outcome", "reason codes"]
    rows: list[list[str]] = [
        [
            check.check.check_id,
            subject.subject.subject_id,
            check.outcome.value,
            _reason_cell(check),
        ]
        for subject in rollup.subjects
        for check in subject.checks
    ]
    if not rows:
        return _MISSING
    table = [header, ["---"] * len(header)]
    table.extend(rows)
    return "\n".join("| " + " | ".join(row) + " |" for row in table)


def write_report(bundle_directory: Path, output: Path) -> str:
    """Render a bundle's report and write it outside the checksummed bundle.

    Derived analysis is never written into a run bundle: the bundle's checksums cover
    its own files, and adding to it would invalidate the evidence it vouches for.
    """

    resolved_output = output.resolve()
    resolved_bundle = bundle_directory.resolve()
    if resolved_output == resolved_bundle or resolved_bundle in resolved_output.parents:
        raise ReportError(
            f"refusing to write a report inside the run bundle at {bundle_directory}; a "
            "bundle's checksums cover its own contents"
        )

    rollup, provenance = load_report(bundle_directory)
    text = render_report(rollup, provenance)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    return text


__all__ = [
    "DECISIVE_STATUSES",
    "ReportError",
    "ReportProvenance",
    "load_report",
    "provenance_of",
    "publishable",
    "render_report",
    "write_report",
]
