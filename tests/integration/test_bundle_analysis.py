"""Roll-up and comparison over real aggregated run bundles."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from privacy_benchmark.adapters.base import (
    AdapterEvidence,
    AdapterOutcome,
    ensure_identifier,
)
from privacy_benchmark.cli.main import main
from privacy_benchmark.harness.aggregation import aggregate_run
from privacy_benchmark.harness.analysis import (
    AnalysisError,
    load_bundle,
    rollup_bundle,
    write_comparison,
    write_rollup,
)
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.harness.execution import run_execution
from privacy_benchmark.spec.models import (
    CheckDefinition,
    CheckResult,
    CompletionState,
    EvidenceClass,
    EvidenceKind,
    RedactionPolicy,
    ResultStatus,
    RollupOutcome,
    RunBundleManifest,
    RunComparison,
    RunPlan,
    RunRollup,
)
from privacy_benchmark.spec.registry import Registry
from privacy_benchmark.spec.serialization import (
    json_bytes,
    read_model_json,
    verify_checksums,
    write_bytes_atomic,
    write_checksums,
)


class _ScriptedAdapter:
    """An adapter that reports a fixed status sequence, one status per repetition."""

    adapter_id = "scripted"
    version = "1.0.0"

    def __init__(self, statuses: tuple[ResultStatus, ...]) -> None:
        self._statuses = statuses
        self._calls = 0

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        status = self._statuses[min(self._calls, len(self._statuses) - 1)]
        self._calls += 1
        evidence_id = ensure_identifier(
            f"{context.execution_id}.{check.check_id}.scripted", field_name="evidence_id"
        )
        payload = json_bytes(
            {
                "check_id": check.check_id,
                "execution_id": str(context.execution_id),
                "status": status.value,
            }
        )
        return AdapterOutcome(
            status=status,
            reason_code="scripted.observed",
            summary=f"The scripted adapter reported {status.value}.",
            details={"scripted": True},
            evidence=(
                AdapterEvidence(
                    evidence_id=evidence_id,
                    evidence_class=EvidenceClass.SYNTHETIC,
                    kind=EvidenceKind.OTHER,
                    media_type="application/json",
                    payload=payload,
                    redaction=RedactionPolicy(
                        policy_id="scripted-none", applied=False, raw_retention="not-retained"
                    ),
                    metadata={"scripted": True},
                ),
            ),
        )


def _repetitions(plan: RunPlan, count: int) -> RunPlan:
    data = plan.model_dump(mode="python")
    data["repetitions"] = count
    data["expected_execution_count"] = count
    return RunPlan.model_validate(data)


def _build_bundle(
    *,
    plan: RunPlan,
    registry: Registry,
    executions_root: Path,
    output_dir: Path,
    statuses: tuple[ResultStatus, ...],
    executions: int | None = None,
) -> Path:
    adapter = _ScriptedAdapter(statuses)
    subject = registry.resolve_subject("fake-client@1.0.0")
    check = registry.resolve_check("harness.smoke@1.0.0")
    for repetition in range(1, (executions or plan.repetitions) + 1):
        asyncio.run(
            run_execution(
                plan=plan,
                subject=subject,
                checks=(check,),
                adapter=adapter,
                execution_dir=executions_root / "fake-client" / f"{repetition:04d}",
                repetition=repetition,
            )
        )
    aggregate_run(plan=plan, executions_root=executions_root, output_dir=output_dir)
    return output_dir


@pytest.fixture
def three_repetition_plan(local_plan: RunPlan) -> RunPlan:
    return _repetitions(local_plan, 3)


def test_rollup_reports_a_stable_pass(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    bundle = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
        statuses=(ResultStatus.PASS,),
    )
    rollup = write_rollup(bundle, tmp_path / "rollup.json")
    assert rollup.repetitions == 3
    check = rollup.subjects[0].checks[0]
    assert check.outcome is RollupOutcome.PASS
    assert check.observations == 3
    assert check.pass_rate == 1.0
    assert check.pass_rate_low is not None
    assert check.pass_rate_low < 1.0


def test_rollup_reports_a_flaky_result(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    bundle = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
        statuses=(ResultStatus.PASS, ResultStatus.FAIL, ResultStatus.PASS),
    )
    rollup = rollup_bundle(load_bundle(bundle))
    check = rollup.subjects[0].checks[0]
    assert check.outcome is RollupOutcome.FLAKY
    assert check.pass_count == 2
    assert check.fail_count == 1
    assert check.pass_rate == pytest.approx(2 / 3, abs=1e-6)


def test_rollup_marks_an_under_sampled_bundle_incomplete(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    bundle = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
        statuses=(ResultStatus.PASS,),
        executions=2,
    )
    rollup = rollup_bundle(load_bundle(bundle))
    assert rollup.bundle_completion is CompletionState.INCOMPLETE
    assert rollup.subjects[0].checks[0].outcome is RollupOutcome.INCOMPLETE


def test_rollup_refuses_to_write_inside_the_bundle(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    bundle = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
        statuses=(ResultStatus.PASS,),
    )
    with pytest.raises(AnalysisError, match="inside the run bundle"):
        write_rollup(bundle, bundle / "rollup.json")
    assert verify_checksums(bundle) == []


def test_rollup_rejects_a_tampered_bundle(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    bundle = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
        statuses=(ResultStatus.PASS,),
    )
    manifest = bundle / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")
    with pytest.raises(AnalysisError, match="invalid run bundle"):
        load_bundle(bundle)


def test_rollup_output_validates_against_the_public_schema(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    runner = CliRunner()
    bundle = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
        statuses=(ResultStatus.PASS,),
    )
    rollup_path = tmp_path / "rollup.json"
    result = runner.invoke(main, ["rollup", "--bundle", str(bundle), "--output", str(rollup_path)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["outcomes"] == {"pass": 1}

    validation = runner.invoke(
        main,
        ["schemas", "validate", "--kind", "run-rollup", str(rollup_path)],
    )
    assert validation.exit_code == 0, validation.output
    assert read_model_json(rollup_path, RunRollup).repetitions == 3


def test_compare_reports_a_regression(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    baseline = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "baseline-executions",
        output_dir=tmp_path / "baseline",
        statuses=(ResultStatus.PASS,),
    )
    candidate = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "candidate-executions",
        output_dir=tmp_path / "candidate",
        statuses=(ResultStatus.FAIL,),
    )
    comparison = write_comparison(
        baseline_directory=baseline,
        candidate_directory=candidate,
        output=tmp_path / "comparison.json",
    )
    assert comparison.regressed == 1
    assert comparison.improved == 0
    assert comparison.deltas[0].verdict.value == "regressed"
    assert comparison.baseline_created_at <= comparison.candidate_created_at


def test_compare_refuses_to_write_inside_a_bundle(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    baseline = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "baseline-executions",
        output_dir=tmp_path / "baseline",
        statuses=(ResultStatus.PASS,),
    )
    with pytest.raises(AnalysisError, match="inside the run bundle"):
        write_comparison(
            baseline_directory=baseline,
            candidate_directory=baseline,
            output=baseline / "comparison.json",
        )


def test_compare_output_validates_and_can_gate_on_regression(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    runner = CliRunner()
    baseline = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "baseline-executions",
        output_dir=tmp_path / "baseline",
        statuses=(ResultStatus.PASS,),
    )
    candidate = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "candidate-executions",
        output_dir=tmp_path / "candidate",
        statuses=(ResultStatus.FAIL,),
    )
    comparison_path = tmp_path / "comparison.json"
    result = runner.invoke(
        main,
        [
            "compare",
            "--baseline",
            str(baseline),
            "--candidate",
            str(candidate),
            "--output",
            str(comparison_path),
            "--fail-on-regression",
        ],
    )
    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["regressed"] == 1

    validation = runner.invoke(
        main,
        ["schemas", "validate", "--kind", "run-comparison", str(comparison_path)],
    )
    assert validation.exit_code == 0, validation.output
    assert read_model_json(comparison_path, RunComparison).regressed == 1


def test_compare_does_not_gate_without_the_flag(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    runner = CliRunner()
    baseline = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "baseline-executions",
        output_dir=tmp_path / "baseline",
        statuses=(ResultStatus.PASS,),
    )
    candidate = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "candidate-executions",
        output_dir=tmp_path / "candidate",
        statuses=(ResultStatus.FAIL,),
    )
    result = runner.invoke(
        main,
        [
            "compare",
            "--baseline",
            str(baseline),
            "--candidate",
            str(candidate),
            "--output",
            str(tmp_path / "comparison.json"),
        ],
    )
    assert result.exit_code == 0, result.output


def test_rollup_exit_code_signals_an_incomplete_bundle(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    runner = CliRunner()
    bundle = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
        statuses=(ResultStatus.PASS,),
        executions=2,
    )
    result = runner.invoke(
        main, ["rollup", "--bundle", str(bundle), "--output", str(tmp_path / "rollup.json")]
    )
    assert result.exit_code == 2, result.output
    assert json.loads(result.output)["outcomes"] == {"incomplete": 1}


def test_rollup_reports_every_planned_check_and_subject(
    tmp_path: Path, local_plan: RunPlan, registry: Registry
) -> None:
    bundle = _build_bundle(
        plan=local_plan,
        registry=registry,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
        statuses=(ResultStatus.PASS,),
    )
    rollup = rollup_bundle(load_bundle(bundle))
    assert rollup.subjects[0].client_version == "1.0.0"
    assert rollup.subjects[0].platform is not None
    assert [check.check.check_id for check in rollup.subjects[0].checks] == ["harness.smoke"]


def test_rollup_reports_a_result_whose_execution_id_was_swapped(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    bundle = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
        statuses=(ResultStatus.PASS,),
    )
    result_path = bundle / "results" / "fake-client" / "0002" / "harness.smoke.json"
    data = read_model_json(result_path, CheckResult).model_dump(mode="json")
    data["execution_id"] = "00000000-0000-7000-8000-000000000000"
    write_bytes_atomic(result_path, json_bytes(data))
    write_checksums(bundle)
    with pytest.raises(AnalysisError, match="does not belong to execution"):
        load_bundle(bundle)


def test_rollup_requires_a_manifest(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    write_checksums(empty)
    with pytest.raises(AnalysisError, match="missing run bundle manifest"):
        load_bundle(empty)


def test_rollup_reports_a_missing_result_document(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    bundle = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
        statuses=(ResultStatus.PASS,),
    )
    target = bundle / "results" / "fake-client" / "0001" / "harness.smoke.json"
    target.unlink()
    write_checksums(bundle)
    with pytest.raises(AnalysisError, match="missing result document"):
        load_bundle(bundle)


def test_bundle_manifest_round_trips_unchanged(
    tmp_path: Path, three_repetition_plan: RunPlan, registry: Registry
) -> None:
    bundle = _build_bundle(
        plan=three_repetition_plan,
        registry=registry,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
        statuses=(ResultStatus.PASS,),
    )
    manifest = read_model_json(bundle / "manifest.json", RunBundleManifest)
    assert manifest.execution_manifests[0].results[0].status is ResultStatus.PASS
