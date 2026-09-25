"""Roll repeated results up into stable outcomes and compare two run bundles.

Aggregation copies per-repetition results verbatim so the evidence record stays
untouched.  This module adds the two derived views the benchmark needs to be
defensible:

* a :class:`~privacy_benchmark.spec.models.RunRollup`, which reports how stable each
  per-check outcome was across the planned repetitions; and
* a :class:`~privacy_benchmark.spec.models.RunComparison`, which reports the direction
  of change between two bundles without ever collapsing checks into a single score.

Both views are derived analysis.  Neither is a benchmark result, neither is canonical,
and neither may be written back into a checksummed run bundle.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from statistics import NormalDist
from uuid import uuid7

from privacy_benchmark.spec.models import (
    CheckDelta,
    CheckRef,
    CheckResult,
    CheckRollup,
    ComparisonVerdict,
    ResultStatus,
    RollupOutcome,
    RunBundleManifest,
    RunComparison,
    RunRollup,
    StatusTally,
    SubjectDefinition,
    SubjectRef,
    SubjectRollup,
    utc_now,
)
from privacy_benchmark.spec.serialization import (
    read_model_json,
    verify_checksums,
    write_model_json,
)

#: Two-sided 95% interval.  The Wilson score interval is used instead of the normal
#: approximation because planned repetition counts are small (often three), where the
#: normal approximation is badly biased at rates near 0 and 1.
CONFIDENCE_Z = NormalDist().inv_cdf(0.975)

#: Statuses that establish a stable product property and may therefore be ordered.
DECISIVE_STATUSES = frozenset({ResultStatus.PASS, ResultStatus.FAIL})

_STATUS_ORDER = {status: index for index, status in enumerate(ResultStatus)}

_RATE_PRECISION = 6


class AnalysisError(RuntimeError):
    """Raised when a bundle cannot be analyzed safely."""


@dataclass(frozen=True, slots=True)
class BundleAnalysis:
    """A verified bundle manifest together with its loaded results."""

    directory: Path
    manifest: RunBundleManifest
    results: dict[tuple[str, str, str], tuple[CheckResult, ...]]


def load_bundle(directory: Path) -> BundleAnalysis:
    """Verify checksums and load every result referenced by a run bundle."""

    checksum_errors = verify_checksums(directory)
    if checksum_errors:
        raise AnalysisError(f"invalid run bundle {directory}: " + "; ".join(checksum_errors))

    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file():
        raise AnalysisError(f"missing run bundle manifest: {manifest_path}")
    manifest = read_model_json(manifest_path, RunBundleManifest)

    collected: dict[tuple[str, str, str], list[CheckResult]] = {}
    for execution in manifest.execution_manifests:
        subject_id = execution.subject.subject_id
        for result_ref in execution.results:
            relative = f"results/{subject_id}/{execution.repetition:04d}/{result_ref.check_id}.json"
            result_path = directory / relative
            if not result_path.is_file():
                raise AnalysisError(f"missing result document: {relative}")
            result = read_model_json(result_path, CheckResult)
            if result.execution_id != execution.execution_id:
                raise AnalysisError(
                    f"result {result.result_id} does not belong to execution "
                    f"{execution.execution_id}"
                )
            key = (subject_id, execution.subject.subject_version, result.check.check_id)
            collected.setdefault(key, []).append(result)

    grouped: dict[tuple[str, str, str], tuple[CheckResult, ...]] = {
        key: tuple(sorted(items, key=lambda item: item.started_at))
        for key, items in collected.items()
    }
    return BundleAnalysis(directory=directory, manifest=manifest, results=grouped)


def _round(value: float) -> float:
    return round(value, _RATE_PRECISION)


def wilson_interval(successes: int, trials: int) -> tuple[float, float]:
    """Return the 95% Wilson score interval for a binomial proportion."""

    if trials <= 0:
        raise ValueError("wilson_interval requires at least one trial")
    if not 0 <= successes <= trials:
        raise ValueError("successes must be within the trial count")

    proportion = successes / trials
    denominator = 1 + CONFIDENCE_Z**2 / trials
    center = (proportion + CONFIDENCE_Z**2 / (2 * trials)) / denominator
    margin = (
        CONFIDENCE_Z
        / denominator
        * math.sqrt(proportion * (1 - proportion) / trials + CONFIDENCE_Z**2 / (4 * trials**2))
    )
    return (
        _round(min(max(center - margin, 0.0), 1.0)),
        _round(min(max(center + margin, 0.0), 1.0)),
    )


def classify_outcome(statuses: tuple[ResultStatus, ...]) -> RollupOutcome:
    """Reduce repeated statuses to a stability verdict.

    A verdict is only reported when every planned repetition agreed.  A sample that
    mixes a decisive status with a non-decisive one is inconclusive rather than a pass
    or a fail, because it does not establish a product property.
    """

    if not statuses:
        return RollupOutcome.INCOMPLETE
    observed = set(statuses)
    if observed == {ResultStatus.NOT_APPLICABLE}:
        return RollupOutcome.NOT_APPLICABLE
    if observed == {ResultStatus.UNSUPPORTED}:
        return RollupOutcome.UNSUPPORTED
    if observed == {ResultStatus.PASS}:
        return RollupOutcome.PASS
    if observed == {ResultStatus.FAIL}:
        return RollupOutcome.FAIL
    if observed >= DECISIVE_STATUSES:
        return RollupOutcome.FLAKY
    return RollupOutcome.INCONCLUSIVE


def build_check_rollup(
    *,
    check: CheckRef,
    subject: SubjectRef,
    results: tuple[CheckResult, ...],
    expected_observations: int,
) -> CheckRollup:
    """Summarize one check's repetitions, including an under-sampled guard."""

    statuses = tuple(result.status for result in results)
    pass_count = sum(1 for status in statuses if status is ResultStatus.PASS)
    fail_count = sum(1 for status in statuses if status is ResultStatus.FAIL)
    decisive_count = pass_count + fail_count

    if decisive_count:
        pass_rate: float | None = _round(pass_count / decisive_count)
        pass_rate_low, pass_rate_high = wilson_interval(pass_count, decisive_count)
    else:
        pass_rate = None
        pass_rate_low = None
        pass_rate_high = None

    outcome = classify_outcome(statuses)
    if len(results) < expected_observations:
        # An under-sampled run cannot support a stability claim, whatever it observed.
        outcome = RollupOutcome.INCOMPLETE

    tallies = tuple(
        StatusTally(status=status, count=count)
        for status, count in sorted(
            Counter(statuses).items(), key=lambda item: _STATUS_ORDER[item[0]]
        )
    )

    return CheckRollup(
        check=check,
        subject=subject,
        outcome=outcome,
        observations=len(results),
        expected_observations=expected_observations,
        pass_count=pass_count,
        fail_count=fail_count,
        decisive_count=decisive_count,
        pass_rate=pass_rate,
        pass_rate_low=pass_rate_low,
        pass_rate_high=pass_rate_high,
        statuses=tallies,
        reason_codes=tuple(sorted({result.reason_code for result in results})),
    )


def rollup_bundle(bundle: BundleAnalysis) -> RunRollup:
    """Summarize every planned check and subject in a bundle."""

    manifest = bundle.manifest
    plan = manifest.plan

    definitions: dict[tuple[str, str], SubjectDefinition] = {}
    keys: set[tuple[str, str]] = set()
    for execution in manifest.execution_manifests:
        key = (execution.subject.subject_id, execution.subject.subject_version)
        definitions.setdefault(key, execution.subject)
        keys.add(key)
    # A planned subject with no executions at all still gets reported, so an absent
    # measurement is visible in the rollup instead of silently missing from it.
    keys.update((ref.subject_id, ref.subject_version) for ref in plan.subjects)

    subject_rollups: list[SubjectRollup] = []
    for subject_id, subject_version in sorted(keys):
        subject_ref = SubjectRef(subject_id=subject_id, subject_version=subject_version)
        definition = definitions.get((subject_id, subject_version))
        subject_rollups.append(
            SubjectRollup(
                subject=subject_ref,
                client_name=definition.client.name if definition else None,
                client_version=definition.client.version if definition else None,
                platform=definition.platform if definition else None,
                checks=tuple(
                    build_check_rollup(
                        check=check_ref,
                        subject=subject_ref,
                        results=bundle.results.get(
                            (subject_id, subject_version, check_ref.check_id), ()
                        ),
                        expected_observations=plan.repetitions,
                    )
                    for check_ref in plan.checks
                ),
            )
        )

    return RunRollup(
        rollup_id=uuid7(),
        bundle_id=manifest.bundle_id,
        suite_id=plan.suite_id,
        suite_version=plan.suite_version,
        plan_id=plan.plan_id,
        created_at=utc_now(),
        bundle_created_at=manifest.created_at,
        bundle_completion=manifest.completion,
        repetitions=plan.repetitions,
        subjects=tuple(subject_rollups),
    )


def _decisive_rank(outcome: RollupOutcome) -> int | None:
    if outcome is RollupOutcome.PASS:
        return 1
    if outcome is RollupOutcome.FAIL:
        return 0
    return None


@dataclass(frozen=True, slots=True)
class _RollupEntry:
    """One subject and check pair, with the versions that produced it."""

    check: CheckRollup
    subject_version: str
    check_version: str


def _index_rollup(rollup: RunRollup) -> dict[tuple[str, str], _RollupEntry]:
    """Key a rollup by subject id and check id only.

    Subject and check versions are deliberately excluded from the key so that a client
    or check version bump is reported as a change instead of splitting into two rows.
    """

    return {
        (subject.subject.subject_id, check.check.check_id): _RollupEntry(
            check=check,
            subject_version=subject.subject.subject_version,
            check_version=check.check.version,
        )
        for subject in rollup.subjects
        for check in subject.checks
    }


def _classify_change(
    baseline: CheckRollup | None, candidate: CheckRollup | None
) -> ComparisonVerdict:
    if baseline is None:
        return ComparisonVerdict.NEW
    if candidate is None:
        return ComparisonVerdict.REMOVED
    if baseline.outcome is candidate.outcome:
        return ComparisonVerdict.UNCHANGED
    before = _decisive_rank(baseline.outcome)
    after = _decisive_rank(candidate.outcome)
    if before is None or after is None:
        return ComparisonVerdict.UNORDERABLE
    if after > before:
        return ComparisonVerdict.IMPROVED
    return ComparisonVerdict.REGRESSED


def compare_rollups(baseline: RunRollup, candidate: RunRollup) -> RunComparison:
    """Compare two rollups and classify each change without scoring it."""

    # Ordering follows the runs, not the analysis: a baseline rolled up after the
    # candidate is still the baseline.
    if baseline.bundle_created_at > candidate.bundle_created_at:
        raise AnalysisError("the baseline bundle cannot be newer than the candidate bundle")

    baseline_index = _index_rollup(baseline)
    candidate_index = _index_rollup(candidate)

    deltas: list[CheckDelta] = []
    counts: Counter[ComparisonVerdict] = Counter()

    for key in sorted(set(baseline_index) | set(candidate_index)):
        # Iterating the union guarantees at least one side is present, so exactly one
        # of these is never-None and can supply the reference identifiers.
        found = baseline_index.get(key)
        updated = candidate_index.get(key)
        entry = updated or found
        if entry is None:
            continue
        subject_id, check_id = key

        before = found.check if found else None
        after = updated.check if updated else None
        verdict = _classify_change(before, after)
        counts[verdict] += 1
        deltas.append(
            CheckDelta(
                check=CheckRef(check_id=check_id, version=entry.check.check.version),
                subject=SubjectRef(subject_id=subject_id, subject_version=entry.subject_version),
                verdict=verdict,
                baseline_outcome=before.outcome if before else None,
                candidate_outcome=after.outcome if after else None,
                baseline_check_version=found.check_version if found else None,
                candidate_check_version=updated.check_version if updated else None,
                baseline_subject_version=found.subject_version if found else None,
                candidate_subject_version=updated.subject_version if updated else None,
                baseline_pass_rate=before.pass_rate if before else None,
                candidate_pass_rate=after.pass_rate if after else None,
                version_changed=(
                    found.subject_version != updated.subject_version
                    or found.check_version != updated.check_version
                )
                if found and updated
                else False,
            )
        )

    return RunComparison(
        comparison_id=uuid7(),
        created_at=utc_now(),
        baseline_bundle_id=baseline.bundle_id,
        candidate_bundle_id=candidate.bundle_id,
        baseline_created_at=baseline.bundle_created_at,
        candidate_created_at=candidate.bundle_created_at,
        baseline_suite=f"{baseline.suite_id}@{baseline.suite_version}",
        candidate_suite=f"{candidate.suite_id}@{candidate.suite_version}",
        improved=counts[ComparisonVerdict.IMPROVED],
        regressed=counts[ComparisonVerdict.REGRESSED],
        unchanged=counts[ComparisonVerdict.UNCHANGED],
        unorderable=counts[ComparisonVerdict.UNORDERABLE],
        added=counts[ComparisonVerdict.NEW],
        removed=counts[ComparisonVerdict.REMOVED],
        deltas=tuple(deltas),
    )


def summarize_rollup(rollup: RunRollup) -> dict[str, int]:
    """Return rollup outcome counts across every subject and check."""

    counts: Counter[RollupOutcome] = Counter()
    for subject in rollup.subjects:
        for check in subject.checks:
            counts[check.outcome] += 1
    return {outcome.value: count for outcome, count in counts.items()}


#: Rendered in a cell when a planned check has no rollup for that subject.
_MISSING_CELL = "—"

#: Corner cell of the matrix. Naming it makes the orientation assertable: the contract
#: is that this label heads the app columns, so a transposed table fails a test rather
#: than reaching a reader as a differently-shaped and differently-scoped claim.
MATRIX_CORNER_LABEL = "check"


def _subject_label(subject: SubjectRollup) -> str:
    """Name a subject for a column header, falling back to its registry identifier.

    The client name is preferred so a column reads as an app a reader recognises. The
    registry id is the honest fallback when no execution supplied a definition: an
    invented product name would be worse than an opaque one.
    """

    return subject.client_name or subject.subject.subject_id


def _matrix_cell(check: CheckRollup, repetitions: int) -> str:
    """Render one check/subject intersection.

    The outcome is the cell's primary content. A pass rate is appended only when the
    plan actually repeated the check and the sample established a decisive rate, so a
    single-repetition run reads as a plain outcome rather than a misleading 100%.
    """

    if repetitions > 1 and check.pass_rate is not None:
        return f"{check.outcome.value} {round(check.pass_rate * 100)}%"
    return check.outcome.value


def render_rollup_matrix(rollup: RunRollup) -> str:
    """Render the rollup with apps as columns and checks as rows.

    **Apps across the top, checks down the side.** That orientation is a reporting
    contract, not a formatting preference:

    - a reader compares apps by reading down a column, holding the check fixed, which is
      the only comparison the benchmark actually supports;
    - holding a check fixed is what makes two apps comparable at all, since each column
      is one pinned app *configuration* rather than a product in the abstract;
    - the transpose would present each app as its own list of verdicts, which reads as a
      per-app summary and invites exactly the single score this project refuses to
      produce.

    It is also the easy direction to get wrong, because :class:`RunRollup` stores one
    entry per subject and is therefore already app-major. This function is the only
    place that lays the table out, and both the analysis and report test suites assert
    the orientation, so a transpose has to be made deliberately to survive.

    Subjects keep the plan's declared order rather than being sorted, so a suite that
    declares Signal, WhatsApp, then Telegram renders in that order. Column order is
    reporting layout only and never implies a ranking; the table states outcomes per
    check and does not collapse them into a score.
    """

    check_order: list[str] = []
    cells: dict[tuple[str, str], str] = {}
    for subject in rollup.subjects:
        subject_id = subject.subject.subject_id
        for check in subject.checks:
            check_id = check.check.check_id
            if check_id not in check_order:
                check_order.append(check_id)
            cells[(check_id, subject_id)] = _matrix_cell(check, rollup.repetitions)

    headers = [MATRIX_CORNER_LABEL, *(_subject_label(subject) for subject in rollup.subjects)]
    rows = [
        [
            check_id,
            *(
                cells.get((check_id, subject.subject.subject_id), _MISSING_CELL)
                for subject in rollup.subjects
            ),
        ]
        for check_id in check_order
    ]
    widths = [max(len(cell) for cell in column) for column in zip(headers, *rows, strict=True)]

    def render_row(cells_in_row: list[str]) -> str:
        return "  ".join(
            cell.ljust(width) for cell, width in zip(cells_in_row, widths, strict=True)
        ).rstrip()

    return "\n".join([render_row(headers), *(render_row(row) for row in rows)])


def _reject_output_inside_bundle(output: Path, bundle: Path) -> None:
    """Refuse to write derived analysis into a checksummed run bundle."""

    resolved_output = output.resolve()
    resolved_bundle = bundle.resolve()
    if resolved_output == resolved_bundle or resolved_bundle in resolved_output.parents:
        raise AnalysisError(
            f"refusing to write derived analysis inside the run bundle: {resolved_bundle}"
        )


def write_rollup(bundle_directory: Path, output: Path) -> RunRollup:
    """Verify, summarize, and persist a rollup outside the source bundle."""

    _reject_output_inside_bundle(output, bundle_directory)
    rollup = rollup_bundle(load_bundle(bundle_directory))
    write_model_json(output, rollup)
    return rollup


def write_comparison(
    *, baseline_directory: Path, candidate_directory: Path, output: Path
) -> RunComparison:
    """Verify both bundles, compare them, and persist the comparison."""

    _reject_output_inside_bundle(output, baseline_directory)
    _reject_output_inside_bundle(output, candidate_directory)
    baseline = rollup_bundle(load_bundle(baseline_directory))
    candidate = rollup_bundle(load_bundle(candidate_directory))
    comparison = compare_rollups(baseline, candidate)
    write_model_json(output, comparison)
    return comparison
