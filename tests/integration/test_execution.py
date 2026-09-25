"""Execution and finalization integration tests."""

from __future__ import annotations

import asyncio
from pathlib import Path

from privacy_benchmark.adapters.base import AdapterOutcome
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.harness.execution import (
    finalize_execution,
    manifest_exit_code,
    run_execution,
)
from privacy_benchmark.spec.models import (
    CheckDefinition,
    CheckResult,
    CompletionState,
    ResultStatus,
    RunPlan,
    SubjectDefinition,
)
from privacy_benchmark.spec.registry import Registry
from privacy_benchmark.spec.serialization import read_model_json, verify_checksums


class ProductFailAdapter:
    adapter_id = "product-fail"
    version = "1.0.0"

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        return AdapterOutcome(
            status=ResultStatus.FAIL,
            reason_code="fixture.privacy-violation",
            summary="A synthetic product failure that must not fail the workflow.",
            details={"canonical": False},
        )


class FailingAdapter:
    adapter_id = "failing"
    version = "1.0.0"

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        raise RuntimeError("sensitive secret that must not be written")


class InvalidContractAdapter:
    adapter_id = "invalid-contract"
    version = "1.0.0"

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        return AdapterOutcome(
            status=ResultStatus.FAIL,
            reason_code="INVALID REASON CODE",
            summary="Intentionally violates the public result contract.",
        )


def _definitions(
    registry: Registry,
) -> tuple[SubjectDefinition, tuple[CheckDefinition, ...]]:
    subject = registry.resolve_subject("fake-client@1.0.0")
    checks = (registry.resolve_check("harness.smoke@1.0.0"),)
    return subject, checks


def test_product_fail_is_a_successful_execution(
    tmp_path: Path, local_plan: RunPlan, registry: Registry
) -> None:
    subject, checks = _definitions(registry)
    outcome = asyncio.run(
        run_execution(
            plan=local_plan,
            subject=subject,
            checks=checks,
            adapter=ProductFailAdapter(),
            execution_dir=tmp_path / "execution",
            repetition=1,
        )
    )
    result = read_model_json(outcome.execution_dir / "results" / "harness.smoke.json", CheckResult)
    assert result.status is ResultStatus.FAIL
    assert result.error is None
    assert outcome.exit_code == 0
    assert outcome.manifest.completion is CompletionState.COMPLETE
    assert verify_checksums(outcome.execution_dir) == []


def test_adapter_exception_becomes_redacted_error_result(
    tmp_path: Path, local_plan: RunPlan, registry: Registry
) -> None:
    subject, checks = _definitions(registry)
    outcome = asyncio.run(
        run_execution(
            plan=local_plan,
            subject=subject,
            checks=checks,
            adapter=FailingAdapter(),
            execution_dir=tmp_path / "execution",
            repetition=1,
        )
    )
    result_payload = (outcome.execution_dir / "results" / "harness.smoke.json").read_text()
    assert "sensitive secret" not in result_payload
    result = read_model_json(outcome.execution_dir / "results" / "harness.smoke.json", CheckResult)
    assert result.status is ResultStatus.ERROR
    assert result.error is not None
    assert result.error.type == "RuntimeError"
    assert outcome.exit_code == 1


def test_contract_failure_still_produces_finalized_error_bundle(
    tmp_path: Path, local_plan: RunPlan, registry: Registry
) -> None:
    subject, checks = _definitions(registry)
    outcome = asyncio.run(
        run_execution(
            plan=local_plan,
            subject=subject,
            checks=checks,
            adapter=InvalidContractAdapter(),
            execution_dir=tmp_path / "execution",
            repetition=1,
        )
    )
    result = read_model_json(outcome.execution_dir / "results" / "harness.smoke.json", CheckResult)
    assert result.status is ResultStatus.ERROR
    assert result.reason_code == "execution.incomplete"
    assert outcome.exit_code == 1
    assert verify_checksums(outcome.execution_dir) == []


def test_finalize_creates_error_for_missing_result(
    tmp_path: Path, local_plan: RunPlan, registry: Registry
) -> None:
    subject, checks = _definitions(registry)
    outcome = asyncio.run(
        run_execution(
            plan=local_plan,
            subject=subject,
            checks=checks,
            adapter=ProductFailAdapter(),
            execution_dir=tmp_path / "execution",
            repetition=1,
        )
    )
    (outcome.execution_dir / "results" / "harness.smoke.json").unlink()
    manifest = finalize_execution(execution_dir=outcome.execution_dir, plan=local_plan)
    result = read_model_json(outcome.execution_dir / "results" / "harness.smoke.json", CheckResult)
    assert result.status is ResultStatus.ERROR
    assert result.reason_code == "execution.incomplete"
    assert manifest_exit_code(manifest) == 1
    assert verify_checksums(outcome.execution_dir) == []
