"""Evidence-integrity tests for run-bundle aggregation.

Aggregation is the gate that makes a result publishable. It verifies bundle checksums,
plan and subject binding, evidence correlation, and payload hashes. A defect here is the
worst kind this project can ship: every published row becomes unsound and nothing looks
broken.

Every ``raise`` branch in ``harness/aggregation.py`` is exercised here. Where a test
needs to reach a deeper check it re-writes the execution checksums first, so the tamper
being asserted is the one that fires rather than the generic checksum guard.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from uuid import uuid7

import pytest

from privacy_benchmark.adapters.base import AdapterEvidence, AdapterOutcome, CheckAdapter
from privacy_benchmark.harness.aggregation import AggregationError, aggregate_run
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.harness.execution import run_execution
from privacy_benchmark.spec.models import (
    CheckDefinition,
    CompletionState,
    EvidenceClass,
    EvidenceKind,
    EvidenceRecord,
    ExecutionManifest,
    RedactionPolicy,
    ResultStatus,
    RunPlan,
)
from privacy_benchmark.spec.registry import Registry
from privacy_benchmark.spec.serialization import (
    json_bytes,
    read_model_json,
    verify_checksums,
    write_bytes_atomic,
    write_checksums,
    write_model_json,
)

#: A fixed evidence id, so two executions collide and the duplicate guard must fire.
#: The real fake adapter derives it from the execution id and cannot collide.
COLLIDING_EVIDENCE_ID = "fixture.colliding-evidence"


class FixedEvidenceAdapter:
    """An adapter that always emits the same evidence id."""

    adapter_id = "fixed-evidence"
    version = "1.0.0"

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        return AdapterOutcome(
            status=ResultStatus.PASS,
            reason_code="fixture.observed",
            summary="A synthetic observation.",
            evidence=(
                AdapterEvidence(
                    evidence_id=COLLIDING_EVIDENCE_ID,
                    evidence_class=EvidenceClass.SYNTHETIC,
                    kind=EvidenceKind.OTHER,
                    media_type="application/json",
                    payload=json_bytes({"check_id": check.check_id}),
                    redaction=RedactionPolicy(
                        policy_id="fixture-none", applied=False, raw_retention="not-retained"
                    ),
                ),
            ),
        )


class NoEvidenceAdapter:
    """An adapter that emits a result and no evidence."""

    adapter_id = "no-evidence"
    version = "1.0.0"

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        return AdapterOutcome(
            status=ResultStatus.PASS,
            reason_code="fixture.observed",
            summary="A synthetic observation with no evidence attached.",
        )


def _plan(plan: RunPlan, repetitions: int) -> RunPlan:
    data = plan.model_dump(mode="python")
    data["repetitions"] = repetitions
    data["expected_execution_count"] = repetitions
    return RunPlan.model_validate(data)


def _run(
    *,
    plan: RunPlan,
    registry: Registry,
    executions: Path,
    repetition: int,
    adapter: CheckAdapter | None = None,
) -> Path:
    from privacy_benchmark.adapters.fake import FakeAdapter

    execution_dir = executions / "fake-client" / f"{repetition:04d}"
    asyncio.run(
        run_execution(
            plan=plan,
            subject=registry.resolve_subject("fake-client@1.0.0"),
            checks=(registry.resolve_check("harness.smoke@1.0.0"),),
            adapter=adapter or FakeAdapter(),
            execution_dir=execution_dir,
            repetition=repetition,
        )
    )
    return execution_dir


def _reseal(execution_dir: Path) -> None:
    """Re-write checksums so a deeper integrity check is the one that fires."""

    write_checksums(execution_dir)


def _patch_manifest(execution_dir: Path, **changes: object) -> None:
    manifest = read_model_json(execution_dir / "manifest.json", ExecutionManifest)
    write_model_json(execution_dir / "manifest.json", manifest.model_copy(update=changes))
    _reseal(execution_dir)


def _patch_json(execution_dir: Path, relative: str, **changes: object) -> None:
    """Rewrite one JSON document inside an execution and re-seal the execution."""

    path = execution_dir / relative
    document = json.loads(path.read_text())
    document.update(changes)
    write_bytes_atomic(path, json_bytes(document))
    _reseal(execution_dir)


@pytest.fixture
def one_execution(tmp_path: Path, local_plan: RunPlan, registry: Registry) -> Path:
    return _run(
        plan=local_plan, registry=registry, executions=tmp_path / "executions", repetition=1
    )


class TestGuardsThatStopBadInput:
    def test_no_manifests_is_refused(self, tmp_path: Path, local_plan: RunPlan) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(AggregationError, match="no execution manifests found"):
            aggregate_run(plan=local_plan, executions_root=empty, output_dir=tmp_path / "bundle")

    def test_a_non_empty_output_is_refused_without_force(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        output = tmp_path / "bundle"
        output.mkdir()
        (output / "leftover.json").write_text("{}")
        with pytest.raises(AggregationError, match="output directory is not empty"):
            aggregate_run(
                plan=local_plan,
                executions_root=tmp_path / "executions",
                output_dir=output,
            )

    def test_force_replaces_a_non_empty_output(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        output = tmp_path / "bundle"
        output.mkdir()
        (output / "leftover.json").write_text("{}")
        outcome = aggregate_run(
            plan=local_plan,
            executions_root=tmp_path / "executions",
            output_dir=output,
            force=True,
        )
        assert not (output / "leftover.json").exists()
        assert verify_checksums(outcome.output_dir) == []

    def test_an_execution_from_another_plan_is_refused(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        _patch_manifest(one_execution, plan_id=uuid7(), run_id=uuid7())
        with pytest.raises(AggregationError, match="belongs to another plan"):
            aggregate_run(
                plan=local_plan,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )

    def test_an_unplanned_subject_is_refused(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        manifest = read_model_json(one_execution / "manifest.json", ExecutionManifest)
        _patch_manifest(
            one_execution,
            subject=manifest.subject.model_copy(update={"subject_id": "not-in-the-plan"}),
        )
        with pytest.raises(AggregationError, match="unplanned subject"):
            aggregate_run(
                plan=local_plan,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )

    def test_a_result_from_another_execution_is_refused(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        _patch_json(one_execution, "results/harness.smoke.json", execution_id=str(uuid7()))
        with pytest.raises(AggregationError, match="wrong execution id"):
            aggregate_run(
                plan=local_plan,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )


class TestEvidenceIntegrity:
    """The checks that stand between a doctored payload and a published result."""

    def _evidence_paths(self, execution_dir: Path) -> tuple[Path, Path]:
        record_path = next((execution_dir / "evidence").glob("*.json"))
        evidence_id = record_path.stem
        payload = next((execution_dir / "evidence").glob(f"{evidence_id}.payload*"))
        return record_path, payload

    def test_evidence_from_another_execution_is_refused(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        record_path, _ = self._evidence_paths(one_execution)
        _patch_json(
            one_execution,
            record_path.relative_to(one_execution).as_posix(),
            execution_id=str(uuid7()),
        )
        with pytest.raises(AggregationError, match="wrong execution id"):
            aggregate_run(
                plan=local_plan,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )

    def test_a_doctored_payload_fails_its_checksum(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        record_path, payload = self._evidence_paths(one_execution)
        record = read_model_json(record_path, EvidenceRecord)
        # Same length, different bytes: only the hash can catch this.
        write_bytes_atomic(payload, b"x" * record.size_bytes)
        _reseal(one_execution)
        with pytest.raises(AggregationError, match="checksum does not match record"):
            aggregate_run(
                plan=local_plan,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )

    def test_a_wrong_recorded_size_is_refused(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        record_path, _ = self._evidence_paths(one_execution)
        record = read_model_json(record_path, EvidenceRecord)
        # The hash still matches, so only the size cross-check can catch this.
        _patch_json(
            one_execution,
            record_path.relative_to(one_execution).as_posix(),
            size_bytes=record.size_bytes + 1,
        )
        with pytest.raises(AggregationError, match="size does not match record"):
            aggregate_run(
                plan=local_plan,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )

    def test_a_missing_payload_is_refused(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        _, payload = self._evidence_paths(one_execution)
        payload.unlink()
        _reseal(one_execution)
        with pytest.raises(AggregationError, match="exactly one payload file"):
            aggregate_run(
                plan=local_plan,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )

    def test_an_extra_payload_is_refused(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        _, payload = self._evidence_paths(one_execution)
        shutil.copy2(payload, payload.with_name(f"{payload.name}.copy"))
        _reseal(one_execution)
        with pytest.raises(AggregationError, match="exactly one payload file"):
            aggregate_run(
                plan=local_plan,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )

    def test_an_evidence_id_reused_across_executions_is_refused(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        plan = _plan(local_plan, 2)
        for repetition in (1, 2):
            _run(
                plan=plan,
                registry=registry,
                executions=tmp_path / "executions",
                repetition=repetition,
                adapter=FixedEvidenceAdapter(),
            )
        with pytest.raises(AggregationError, match="duplicate evidence id"):
            aggregate_run(
                plan=plan,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )


class TestPlanAccounting:
    def test_a_repetition_beyond_the_plan_is_refused(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        """A stale execution from a wider plan must not be folded into a narrower one.

        Without a range check, an execution claiming repetition 7 of a 1-repetition plan
        counts toward the subject's total and the bundle still reports complete.
        """
        wide = _plan(local_plan, 2)
        second = _run(
            plan=wide,
            registry=registry,
            executions=tmp_path / "executions",
            repetition=2,
            adapter=NoEvidenceAdapter(),
        )
        _run(
            plan=wide,
            registry=registry,
            executions=tmp_path / "executions",
            repetition=1,
            adapter=NoEvidenceAdapter(),
        )
        narrow = wide.model_copy(update={"repetitions": 1, "expected_execution_count": 1})
        with pytest.raises(AggregationError, match=r"outside the planned 1\.\.1"):
            aggregate_run(
                plan=narrow,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )
        assert second.exists()

    def test_two_manifests_sharing_an_execution_id_are_refused(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        plan = _plan(local_plan, 2)
        first = _run(
            plan=plan,
            registry=registry,
            executions=tmp_path / "executions",
            repetition=1,
            adapter=NoEvidenceAdapter(),
        )
        clone = tmp_path / "executions" / "fake-client" / "0002"
        shutil.copytree(first, clone)
        _patch_manifest(clone, repetition=2)
        with pytest.raises(AggregationError, match="duplicate execution manifests"):
            aggregate_run(
                plan=plan,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )

    def test_a_repetition_position_reused_by_another_execution_is_refused(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        """Two executions claiming the same repetition must not aggregate.

        The repetition axis is what makes a pass rate mean anything. If two distinct
        executions both claim repetition 1, the second silently overwrites the first
        result while ``result_count`` still counts both, so the bundle would claim
        COMPLETE with a repetition that was never measured and a result file that no
        longer matches the manifests describing it.
        """
        plan = _plan(local_plan, 2)
        first = _run(
            plan=plan,
            registry=registry,
            executions=tmp_path / "executions",
            repetition=1,
            adapter=NoEvidenceAdapter(),
        )
        clone = tmp_path / "executions" / "fake-client" / "0002"
        shutil.copytree(first, clone)
        # A genuinely distinct execution that nonetheless claims repetition 1.
        _patch_manifest(clone, execution_id=uuid7())
        _patch_json(
            clone,
            "results/harness.smoke.json",
            execution_id=str(
                read_model_json(clone / "manifest.json", ExecutionManifest).execution_id
            ),
        )
        with pytest.raises(AggregationError, match="repetition"):
            aggregate_run(
                plan=plan,
                executions_root=tmp_path / "executions",
                output_dir=tmp_path / "bundle",
            )


class TestHonestBundle:
    def test_a_clean_bundle_counts_what_it_wrote(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        outcome = aggregate_run(
            plan=local_plan,
            executions_root=tmp_path / "executions",
            output_dir=tmp_path / "bundle",
        )
        written = sorted(
            path.relative_to(outcome.output_dir).as_posix()
            for path in (outcome.output_dir / "results").rglob("*.json")
        )
        assert outcome.manifest.completion is CompletionState.COMPLETE
        assert outcome.manifest.result_count == len(written)
        assert outcome.manifest.evidence_count == outcome.evidence_count
        assert verify_checksums(outcome.output_dir) == []

    def test_a_refused_aggregation_never_writes_a_manifest(
        self, tmp_path: Path, local_plan: RunPlan, one_execution: Path
    ) -> None:
        _patch_manifest(one_execution, plan_id=uuid7(), run_id=uuid7())
        output = tmp_path / "bundle"
        with pytest.raises(AggregationError):
            aggregate_run(
                plan=local_plan, executions_root=tmp_path / "executions", output_dir=output
            )
        # A half-written bundle must not be mistakable for a real one.
        assert not (output / "manifest.json").exists()
        assert not (output / "checksums.sha256").exists()
