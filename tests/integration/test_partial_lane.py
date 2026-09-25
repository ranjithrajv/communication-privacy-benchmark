"""A partly-implemented suite must degrade honestly.

Six of the ten declared checks have no adapter yet, on purpose: each is waiting on
infrastructure or a licence review rather than on code. The risk is not that they stay
unimplemented, it is that a partly-implemented suite quietly under-reports coverage. A
check with no adapter must surface as ``unsupported`` all the way through to the roll-up
verdict, never as a pass, never as a missing row, and never dropped from the count.

This is the guard that makes it safe to add a check before its adapter exists.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from privacy_benchmark.adapters.base import AdapterOutcome, CheckAdapter
from privacy_benchmark.harness.aggregation import aggregate_run
from privacy_benchmark.harness.analysis import load_bundle, rollup_bundle
from privacy_benchmark.harness.execution import ExecutionOutcome, run_execution
from privacy_benchmark.spec.models import (
    CheckDefinition,
    CheckRef,
    CheckResult,
    CompletionState,
    ResultStatus,
    RunPlan,
    SubjectRef,
)
from privacy_benchmark.spec.registry import Registry
from privacy_benchmark.spec.serialization import read_model_json, verify_checksums

#: A real draft check with no adapter, so the mixed suite is the real corpus shape.
UNIMPLEMENTED = "email.referrer-disclosure@1.0.0"
IMPLEMENTED = "harness.smoke@1.0.0"


class PartialAdapter:
    """Answers only the checks it claims, like a lane-specific adapter does."""

    adapter_id = "partial"
    version = "1.0.0"

    def __init__(self, supported: set[str]) -> None:
        self._supported = supported

    async def execute_check(self, check: CheckDefinition, context: object) -> AdapterOutcome:
        if check.check_id not in self._supported:
            return AdapterOutcome(
                status=ResultStatus.UNSUPPORTED,
                reason_code="partial.unsupported",
                summary=f"{check.check_id} has no adapter in this lane.",
                details={"supported": False},
            )
        return AdapterOutcome(
            status=ResultStatus.PASS,
            reason_code="partial.observed",
            summary="A synthetic observation.",
        )


@pytest.fixture
def mixed_plan(local_plan: RunPlan, registry: Registry) -> RunPlan:
    return local_plan.model_copy(
        update={
            "checks": (
                CheckRef(check_id="harness.smoke", version="1.0.0"),
                CheckRef(check_id="email.referrer-disclosure", version="1.0.0"),
            ),
            "subjects": (SubjectRef(subject_id="fake-client", subject_version="1.0.0"),),
            "expected_execution_count": 1,
            "repetitions": 1,
        }
    )


def _run(
    plan: RunPlan, registry: Registry, execution_dir: Path, adapter: CheckAdapter
) -> ExecutionOutcome:
    return asyncio.run(
        run_execution(
            plan=plan,
            subject=registry.resolve_subject("fake-client@1.0.0"),
            checks=tuple(
                registry.resolve_check(f"{ref.check_id}@{ref.version}") for ref in plan.checks
            ),
            adapter=adapter,
            execution_dir=execution_dir,
            repetition=1,
        )
    )


class TestMixedSuiteDegradesHonestly:
    def test_an_unimplemented_check_reports_unsupported(
        self,
        tmp_path: Path,
        mixed_plan: RunPlan,
        registry: Registry,
    ) -> None:
        outcome = _run(
            mixed_plan,
            registry,
            tmp_path / "0001",
            PartialAdapter({"harness.smoke"}),
        )
        result = read_model_json(
            tmp_path / "0001" / "results" / "email.referrer-disclosure.json", CheckResult
        )
        assert result.status is ResultStatus.UNSUPPORTED
        # Unsupported is not an error: nothing went wrong, the lane simply cannot answer.
        assert result.error is None
        assert outcome.manifest.completion is CompletionState.COMPLETE
        assert outcome.exit_code == 0

    def test_the_bundle_still_counts_every_declared_check(
        self, tmp_path: Path, mixed_plan: RunPlan, registry: Registry
    ) -> None:
        _run(mixed_plan, registry, tmp_path / "0001", PartialAdapter({"harness.smoke"}))
        outcome = aggregate_run(
            plan=mixed_plan,
            executions_root=tmp_path,
            output_dir=tmp_path / "bundle",
        )
        # Both checks are in the bundle: an unimplemented check is not a missing row.
        assert outcome.manifest.result_count == 2
        assert len(list((outcome.output_dir / "results").rglob("*.json"))) == 2

    def test_the_rollup_reports_unsupported_not_pass(
        self, tmp_path: Path, mixed_plan: RunPlan, registry: Registry
    ) -> None:
        _run(
            mixed_plan,
            registry,
            tmp_path / "executions" / "fake-client" / "0001",
            PartialAdapter({"harness.smoke"}),
        )
        outcome = aggregate_run(
            plan=mixed_plan,
            executions_root=tmp_path / "executions",
            output_dir=tmp_path / "bundle",
        )
        rollup = rollup_bundle(load_bundle(outcome.output_dir))
        by_check = {item.check.check_id: item for item in rollup.subjects[0].checks}
        assert set(by_check) == {"harness.smoke", "email.referrer-disclosure"}
        assert by_check["harness.smoke"].outcome.value == "pass"
        assert by_check["email.referrer-disclosure"].outcome.value == "unsupported"

    def test_an_unsupported_check_carries_no_pass_rate(
        self, tmp_path: Path, mixed_plan: RunPlan, registry: Registry
    ) -> None:
        """A check nobody ran has no pass rate, and must not be given one."""

        _run(
            mixed_plan,
            registry,
            tmp_path / "executions" / "fake-client" / "0001",
            PartialAdapter({"harness.smoke"}),
        )
        outcome = aggregate_run(
            plan=mixed_plan,
            executions_root=tmp_path / "executions",
            output_dir=tmp_path / "bundle",
        )
        rollup = rollup_bundle(load_bundle(outcome.output_dir))
        unsupported = next(
            item
            for item in rollup.subjects[0].checks
            if item.check.check_id == "email.referrer-disclosure"
        )
        assert unsupported.pass_rate is None
        assert unsupported.decisive_count == 0
        assert unsupported.observations == 1

    def test_evidence_and_checksums_survive_a_partial_lane(
        self, tmp_path: Path, mixed_plan: RunPlan, registry: Registry
    ) -> None:
        _run(
            mixed_plan,
            registry,
            tmp_path / "executions" / "fake-client" / "0001",
            PartialAdapter({"harness.smoke"}),
        )
        outcome = aggregate_run(
            plan=mixed_plan,
            executions_root=tmp_path / "executions",
            output_dir=tmp_path / "bundle",
        )
        assert verify_checksums(outcome.output_dir) == []


class TestUnimplementedChecksAreDeclared:
    def test_every_unimplemented_check_says_what_it_is_waiting_for(
        self, registry: Registry
    ) -> None:
        """A check with no adapter must not read as though it had been measured."""

        for check in registry.checks.values():
            if check.adapter_id != "unimplemented":
                continue
            assert check.status.value == "draft", check.check_id
            assert "Unimplemented because" in check.description, check.check_id

    def test_no_active_canonical_check_lacks_an_adapter(self, registry: Registry) -> None:
        for check in registry.checks.values():
            if check.status.value == "active" and check.canonical:
                assert check.adapter_id not in {"unimplemented", "fake"}, check.check_id
