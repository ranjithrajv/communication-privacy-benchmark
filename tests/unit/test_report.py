"""Report rendering from a finalized run bundle.

A report is the artifact a reader quotes without re-running the benchmark, so the
contract this file protects is mostly refusal: a run that was not canonical must say
so, and a bundle whose checksums do not verify must not be rendered at all.

The matrix itself is owned by the analysis module's rollup tests. What is unique to
report rendering is the provenance, the not-publishable section, and the reason codes.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from privacy_benchmark.harness.report import (
    ReportError,
    load_report,
    publishable,
    render_report,
    write_report,
)
from privacy_benchmark.spec.models import CompletionState, ExecutionMode


@pytest.fixture
def smoke_bundle(repository_root: Path, tmp_path: Path) -> Path:
    """Build a real bundle through the harness, so the report reads genuine output.

    Assembled from the same production entry points a run uses rather than from
    hand-written documents, because the contract under test is what a reader would
    actually be handed.
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
    registry = Registry.load(repository_root)
    subject_ref, check_ref = plan.subjects[0], plan.checks[0]
    subject = registry.resolve_subject(f"{subject_ref.subject_id}@{subject_ref.subject_version}")
    check = registry.resolve_check(f"{check_ref.check_id}@{check_ref.version}")

    asyncio.run(
        run_execution(
            plan=plan,
            subject=subject,
            checks=(check,),
            execution_dir=tmp_path / "exec",
            repetition=1,
            adapter=FakeAdapter(),
        )
    )
    bundle = tmp_path / "bundle"
    aggregate_run(plan=plan, executions_root=tmp_path / "exec", output_dir=bundle)
    return bundle


def _replace(provenance: object, **changes: object) -> object:
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
    canonical = type(provenance)(
        **{
            **{field: getattr(provenance, field) for field in provenance.__slots__},
            "execution_mode": ExecutionMode.GITHUB_ACTIONS,
        }
    )
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


def test_the_report_names_the_reason_code_for_each_cell(smoke_bundle: Path) -> None:
    rollup, provenance = load_report(smoke_bundle)
    text = render_report(rollup, provenance)

    assert "`harness.fixture-observed`" in text


def test_the_report_is_written_verbatim_to_its_output(smoke_bundle: Path, tmp_path: Path) -> None:
    output = tmp_path / "out" / "report.md"
    text = write_report(smoke_bundle, output)

    assert output.read_text() == text
    assert text.startswith("# smoke@1.0.0 report")
