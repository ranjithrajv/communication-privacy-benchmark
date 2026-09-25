"""Run bundle aggregation tests."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from privacy_benchmark.adapters.fake import FakeAdapter
from privacy_benchmark.harness.aggregation import AggregationError, aggregate_run
from privacy_benchmark.harness.execution import run_execution
from privacy_benchmark.spec.models import (
    CompletionState,
    RunBundleManifest,
    RunPlan,
)
from privacy_benchmark.spec.registry import Registry
from privacy_benchmark.spec.serialization import read_model_json, verify_checksums


def _two_repetition_plan(plan: RunPlan) -> RunPlan:
    data = plan.model_dump(mode="python")
    data["repetitions"] = 2
    data["expected_execution_count"] = 2
    return RunPlan.model_validate(data)


def _run(
    plan: RunPlan,
    registry: Registry,
    execution_dir: Path,
    repetition: int,
) -> None:
    subject = registry.resolve_subject("fake-client@1.0.0")
    checks = (registry.resolve_check("harness.smoke@1.0.0"),)
    asyncio.run(
        run_execution(
            plan=plan,
            subject=subject,
            checks=checks,
            adapter=FakeAdapter(),
            execution_dir=execution_dir,
            repetition=repetition,
        )
    )


def test_aggregate_marks_missing_repetitions_incomplete(
    tmp_path: Path, local_plan: RunPlan, registry: Registry
) -> None:
    plan = _two_repetition_plan(local_plan)
    _run(plan, registry, tmp_path / "executions" / "fake-client" / "0001", 1)
    outcome = aggregate_run(
        plan=plan,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
    )
    assert outcome.manifest.completion is CompletionState.INCOMPLETE
    assert len(outcome.manifest.missing_subjects) == 1
    assert outcome.manifest.result_count == 1
    assert outcome.evidence_count == 1
    assert verify_checksums(outcome.output_dir) == []


def test_aggregate_complete_bundle(tmp_path: Path, local_plan: RunPlan, registry: Registry) -> None:
    plan = _two_repetition_plan(local_plan)
    _run(plan, registry, tmp_path / "executions" / "fake-client" / "0001", 1)
    _run(plan, registry, tmp_path / "executions" / "fake-client" / "0002", 2)
    outcome = aggregate_run(
        plan=plan,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
    )
    manifest = read_model_json(outcome.output_dir / "manifest.json", RunBundleManifest)
    assert manifest.completion is CompletionState.COMPLETE
    assert manifest.result_count == 2
    assert manifest.evidence_count == 2
    assert len(list((outcome.output_dir / "results").rglob("*.json"))) == 2
    assert len(list((outcome.output_dir / "evidence").rglob("*.record.json"))) == 2
    assert verify_checksums(outcome.output_dir) == []


def test_aggregate_rejects_tampered_execution(
    tmp_path: Path, local_plan: RunPlan, registry: Registry
) -> None:
    _run(local_plan, registry, tmp_path / "executions" / "fake-client" / "0001", 1)
    payload = tmp_path / "executions" / "fake-client" / "0001" / "manifest.json"
    payload.write_text(payload.read_text() + " ")
    with pytest.raises(AggregationError, match="invalid execution bundle"):
        aggregate_run(
            plan=local_plan,
            executions_root=tmp_path / "executions",
            output_dir=tmp_path / "bundle",
        )
