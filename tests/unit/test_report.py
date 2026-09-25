"""Report rendering from a finalized run bundle.

A report is the artifact a reader quotes without re-running the benchmark, so the
contract this file protects is mostly refusal: a run that was not canonical must say
so, and a bundle whose checksums do not verify must not be rendered at all.

The matrix itself is owned by the analysis module's rollup tests. What is unique to
report rendering is the provenance, the not-publishable section, the reason codes, and
the confidence interval that has to travel with every rate the matrix prints.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

from privacy_benchmark.harness.analysis import MATRIX_CORNER_LABEL
from privacy_benchmark.harness.report import (
    ReportError,
    ReportProvenance,
    load_report,
    publishable,
    render_report,
    write_report,
)
from privacy_benchmark.spec.models import CompletionState, ExecutionMode, RollupOutcome

#: The clause that tells a reader which outcomes establish no product property. Matched on
#: its meaning rather than its full text so the wording can change without a false failure.
_NON_ESTABLISHING_CLAUSE = "states that the sample did not establish a product property"


def _build_bundle(repository_root: Path, tmp_path: Path, *, repetitions: int) -> Path:
    """Aggregate a real bundle of `repetitions` repetitions through the harness.

    Assembled from the same production entry points a run uses rather than from
    hand-written documents, because the contract under test is what a reader would
    actually be handed. The repetition count is overridden on the plan because the
    checked-in smoke suite pins one, and a pass rate only exists once a check repeats.
    """

    from privacy_benchmark.adapters.fake import FakeAdapter
    from privacy_benchmark.harness.aggregation import aggregate_run
    from privacy_benchmark.harness.execution import run_execution
    from privacy_benchmark.harness.planning import build_run_plan
    from privacy_benchmark.spec.registry import Registry

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
    subject = registry.resolve_subject(f"{subject_ref.subject_id}@{subject_ref.subject_version}")
    check = registry.resolve_check(f"{check_ref.check_id}@{check_ref.version}")

    for repetition in range(1, repetitions + 1):
        asyncio.run(
            run_execution(
                plan=plan,
                subject=subject,
                checks=(check,),
                execution_dir=tmp_path / "exec" / subject_ref.subject_id / f"{repetition:04d}",
                repetition=repetition,
                adapter=FakeAdapter(),
            )
        )
    bundle = tmp_path / "bundle"
    aggregate_run(plan=plan, executions_root=tmp_path / "exec", output_dir=bundle)
    return bundle


@pytest.fixture
def smoke_bundle(repository_root: Path, tmp_path: Path) -> Path:
    return _build_bundle(repository_root, tmp_path, repetitions=1)


@pytest.fixture
def repeated_bundle(repository_root: Path, tmp_path: Path) -> Path:
    return _build_bundle(repository_root, tmp_path, repetitions=3)


def _replace[ProvenanceT: ReportProvenance](
    provenance: ProvenanceT, **changes: object
) -> ProvenanceT:
    """A copy of a provenance with fields replaced, for the publishability cases."""

    values = {field: getattr(provenance, field) for field in provenance.__slots__}
    values.update(changes)
    return type(provenance)(**values)


def test_a_report_states_its_provenance(smoke_bundle: Path) -> None:
    rollup, provenance = load_report(smoke_bundle)
    text = render_report(rollup, provenance)

    assert provenance.suite == "smoke@1.0.0"
    assert str(provenance.bundle_id) in text
    assert str(provenance.plan_id) in text
    assert "harness.smoke" in text
    assert "Fake Client" in text


def test_a_local_run_is_never_reported_as_publishable(smoke_bundle: Path) -> None:
    rollup, provenance = load_report(smoke_bundle)
    reasons = publishable(provenance)

    assert provenance.execution_mode is ExecutionMode.LOCAL
    assert reasons, "a local run must carry at least one reason it is not publishable"
    text = render_report(rollup, provenance)
    assert "## Not publishable" in text
    assert "github_actions" in text


def test_a_canonical_complete_run_is_publishable(smoke_bundle: Path) -> None:
    rollup, provenance = load_report(smoke_bundle)
    canonical = _replace(provenance, execution_mode=ExecutionMode.GITHUB_ACTIONS)

    assert publishable(canonical) == ()
    assert "## Not publishable" not in render_report(rollup, canonical)


def test_an_incomplete_bundle_is_never_publishable(smoke_bundle: Path) -> None:
    _, provenance = load_report(smoke_bundle)
    incomplete = _replace(
        provenance,
        execution_mode=ExecutionMode.GITHUB_ACTIONS,
        completion=CompletionState.INCOMPLETE,
    )
    assert any("completion" in reason for reason in publishable(incomplete))


def test_a_tampered_bundle_is_refused_rather_than_rendered(smoke_bundle: Path) -> None:
    target = next((smoke_bundle / "results").rglob("*.json"))
    target.write_text(target.read_text() + " ")

    with pytest.raises(ReportError, match="checksum"):
        load_report(smoke_bundle)


def test_a_report_is_never_written_inside_the_bundle_it_describes(smoke_bundle: Path) -> None:
    with pytest.raises(ReportError, match="inside the run bundle"):
        write_report(smoke_bundle, smoke_bundle / "report.md")


def test_the_report_says_outcomes_are_not_a_grade(smoke_bundle: Path) -> None:
    rollup, provenance = load_report(smoke_bundle)
    text = render_report(rollup, provenance)

    assert "no overall privacy grade" in text
    assert "Reason codes are the stable key" in text


def _outcomes_block(text: str) -> list[str]:
    """The table lines of the report's Outcomes section, caption excluded."""

    block = text.split("## Outcomes", 1)[1].split("## Stability", 1)[0]
    return [line for line in block.splitlines() if line.strip()]


def test_apps_head_the_columns_and_checks_run_down_the_rows(smoke_bundle: Path) -> None:
    rollup, provenance = load_report(smoke_bundle)
    text = render_report(rollup, provenance)

    caption, header, *rows = _outcomes_block(text)

    # The orientation is the contract, so it is asserted on the published artifact
    # rather than only on the renderer. Transposing swaps these two tokens, which is why
    # the app name and the check id are both named explicitly: an assertion that only
    # counted columns would pass on a transposed table too.
    #
    # Columns are split on the two-space gutter rather than on whitespace, because the
    # matrix is width-padded and an app name may itself contain a space.
    corner, *app_columns = re.split(r"\s{2,}", header.strip())
    assert corner == MATRIX_CORNER_LABEL
    assert app_columns == ["Fake Client"]
    assert [row.split()[0] for row in rows] == ["harness.smoke"]
    assert "One column per app, one row per check" in caption


def test_the_report_names_the_reason_code_for_each_cell(smoke_bundle: Path) -> None:
    rollup, provenance = load_report(smoke_bundle)
    text = render_report(rollup, provenance)

    assert "`harness.fixture-observed`" in text


def test_the_report_only_names_outcomes_a_cell_can_actually_show(smoke_bundle: Path) -> None:
    rollup, provenance = load_report(smoke_bundle)
    text = render_report(rollup, provenance)

    (clause,) = [line for line in text.splitlines() if _NON_ESTABLISHING_CLAUSE in line]
    named = set(re.findall(r"`([^`]+)`", clause))
    establishing = {"pass", "fail"}
    every_outcome = {outcome.value for outcome in RollupOutcome}

    # `partial` and `not_tested` are ResultStatus values that no RollupOutcome can take,
    # so no cell can ever display them. The two outcomes a cell can display were missing
    # from the sentence instead, which left a reader guessing whether they established a
    # property.
    assert named - establishing == every_outcome - establishing
    assert establishing <= named, "the clause must also name the outcomes that do establish one"


def test_a_reported_pass_rate_is_published_with_its_interval(repeated_bundle: Path) -> None:
    rollup, provenance = load_report(repeated_bundle)
    text = render_report(rollup, provenance)

    # Three passing repetitions are the exact case the interval exists for. The rate on
    # its own reads as a guarantee, and 43.9% is the honest lower bound at that size, so
    # a report that printed the rate without the bound would overstate every column.
    assert "pass 100%" in text
    assert "100.0% | 43.9%-100.0%" in text


def test_a_single_repetition_publishes_neither_a_rate_nor_an_interval(
    smoke_bundle: Path,
) -> None:
    rollup, provenance = load_report(smoke_bundle)
    text = render_report(rollup, provenance)

    # One observation supports no proportion, so a rate printed here would be a
    # fabricated statistic rather than a wide interval. Scoped to the matrix, which is
    # the only place a cell's rate appears.
    matrix = text.split("## Outcomes", 1)[1].split("## Stability", 1)[0]
    (row,) = [line for line in matrix.splitlines() if line.startswith("harness.smoke")]
    assert row.split() == ["harness.smoke", "pass"]
    assert "No cell in this run established a decisive sample" in text


def test_the_report_is_written_verbatim_to_its_output(smoke_bundle: Path, tmp_path: Path) -> None:
    output = tmp_path / "out" / "report.md"
    text = write_report(smoke_bundle, output)

    assert output.read_text() == text
    assert text.startswith("# smoke@1.0.0 report")
