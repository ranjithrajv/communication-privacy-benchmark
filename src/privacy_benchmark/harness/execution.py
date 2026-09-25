"""Execute checks and guarantee a finalized result manifest."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid7

from pydantic import BaseModel, ConfigDict

from privacy_benchmark.adapters.base import AdapterEvidence, CheckAdapter
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.spec.constants import SCHEMA_VERSION
from privacy_benchmark.spec.models import (
    AdapterRef,
    CheckDefinition,
    CheckRef,
    CheckResult,
    CollectorRef,
    CompletionState,
    ErrorInfo,
    EvidenceRecord,
    ExecutionManifest,
    ExecutionMode,
    GitHubProvenance,
    ResultFileRef,
    ResultStatus,
    RunPlan,
    SubjectDefinition,
    SubjectRef,
    utc_now,
)
from privacy_benchmark.spec.serialization import (
    read_model_json,
    sha256_bytes,
    write_bytes_atomic,
    write_checksums,
    write_model_json,
)

logger = logging.getLogger(__name__)


class ExecutionState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    execution_id: UUID
    plan_id: UUID
    repetition: int
    subject: SubjectDefinition
    execution_mode: ExecutionMode
    github: GitHubProvenance | None = None
    adapter_id: str
    adapter_version: str
    started_at: datetime


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    execution_dir: Path
    manifest: ExecutionManifest
    exit_code: int


def _evidence_suffix(media_type: str) -> str:
    if media_type == "application/json":
        return ".json"
    if media_type in {"application/vnd.tcpdump.pcap", "application/x-pcapng"}:
        return ".pcapng"
    if media_type.startswith("text/"):
        return ".txt"
    return ".bin"


def _store_evidence(
    evidence: AdapterEvidence,
    *,
    execution_id: UUID,
    collected_at: datetime,
    adapter_id: str,
    adapter_version: str,
    execution_dir: Path,
) -> EvidenceRecord:
    suffix = _evidence_suffix(evidence.media_type)
    evidence_path = execution_dir / "evidence" / f"{evidence.evidence_id}.payload{suffix}"
    write_bytes_atomic(evidence_path, evidence.payload)
    record = EvidenceRecord(
        evidence_id=evidence.evidence_id,
        execution_id=execution_id,
        evidence_class=evidence.evidence_class,
        kind=evidence.kind,
        media_type=evidence.media_type,
        sha256=sha256_bytes(evidence.payload),
        size_bytes=len(evidence.payload),
        source_uri=evidence.source_uri,
        collected_at=collected_at,
        collector=CollectorRef(name=adapter_id, version=adapter_version),
        redaction=evidence.redaction,
        metadata=dict(evidence.metadata),
    )
    write_model_json(execution_dir / "evidence" / f"{evidence.evidence_id}.json", record)
    return record


def _error_result(
    *,
    plan: RunPlan,
    subject: SubjectDefinition,
    check: CheckRef,
    execution_id: UUID,
    adapter_id: str,
    adapter_version: str,
    started_at: datetime,
    completed_at: datetime,
    error: ErrorInfo,
    reason_code: str,
    summary: str,
) -> CheckResult:
    return CheckResult(
        result_id=uuid7(),
        run_id=plan.plan_id,
        execution_id=execution_id,
        check=check,
        subject=SubjectRef(subject_id=subject.subject_id, subject_version=subject.subject_version),
        adapter=AdapterRef(id=adapter_id, version=adapter_version),
        status=ResultStatus.ERROR,
        reason_code=reason_code,
        summary=summary,
        started_at=started_at,
        completed_at=completed_at,
        error=error,
    )


async def _execute_checks(
    *,
    plan: RunPlan,
    subject: SubjectDefinition,
    checks: tuple[CheckDefinition, ...],
    context: ExecutionContext,
    adapter: CheckAdapter,
) -> list[ResultFileRef]:
    references: list[ResultFileRef] = []
    for check in checks:
        started_at = utc_now()
        try:
            outcome = await adapter.execute_check(check, context)
        except Exception as error:
            completed_at = utc_now()
            result = _error_result(
                plan=plan,
                subject=subject,
                check=CheckRef(check_id=check.check_id, version=check.version),
                execution_id=context.execution_id,
                adapter_id=adapter.adapter_id,
                adapter_version=adapter.version,
                started_at=started_at,
                completed_at=completed_at,
                error=ErrorInfo(
                    type=type(error).__name__,
                    message="Adapter execution failed; sensitive exception details were redacted.",
                    retryable=True,
                ),
                reason_code="adapter.exception",
                summary="The adapter did not complete this check.",
            )
        else:
            completed_at = utc_now()
            evidence_ids: list[str] = []
            for evidence in outcome.evidence:
                record = _store_evidence(
                    evidence,
                    execution_id=context.execution_id,
                    collected_at=completed_at,
                    adapter_id=adapter.adapter_id,
                    adapter_version=adapter.version,
                    execution_dir=context.execution_dir,
                )
                evidence_ids.append(record.evidence_id)
            result = CheckResult(
                result_id=uuid7(),
                run_id=plan.plan_id,
                execution_id=context.execution_id,
                check=CheckRef(check_id=check.check_id, version=check.version),
                subject=SubjectRef(
                    subject_id=subject.subject_id,
                    subject_version=subject.subject_version,
                ),
                adapter=AdapterRef(id=adapter.adapter_id, version=adapter.version),
                status=outcome.status,
                reason_code=outcome.reason_code,
                summary=outcome.summary,
                started_at=started_at,
                completed_at=completed_at,
                evidence_refs=tuple(evidence_ids),
                details=dict(outcome.details),
            )

        relative_path = f"results/{check.check_id}.json"
        write_model_json(context.execution_dir / relative_path, result)
        references.append(
            ResultFileRef(
                check_id=check.check_id,
                version=check.version,
                status=result.status,
                path=relative_path,
            )
        )
    return references


async def run_execution(
    *,
    plan: RunPlan,
    subject: SubjectDefinition,
    checks: tuple[CheckDefinition, ...],
    adapter: CheckAdapter,
    execution_dir: Path,
    repetition: int,
) -> ExecutionOutcome:
    execution_id = uuid7()
    started_at = utc_now()
    context = ExecutionContext(
        plan=plan,
        subject=subject,
        checks=checks,
        execution_id=execution_id,
        execution_dir=execution_dir,
        adapter_id=adapter.adapter_id,
        repetition=repetition,
        started_at=started_at,
    )
    state = ExecutionState(
        execution_id=execution_id,
        plan_id=plan.plan_id,
        repetition=repetition,
        subject=subject,
        execution_mode=plan.execution_mode,
        github=plan.github,
        adapter_id=adapter.adapter_id,
        adapter_version=adapter.version,
        started_at=started_at,
    )
    write_model_json(execution_dir / "execution-state.json", state)
    try:
        await _execute_checks(
            plan=plan,
            subject=subject,
            checks=checks,
            context=context,
            adapter=adapter,
        )
    except Exception:
        logger.exception("Execution failed; finalizing missing checks as error results")
    finally:
        manifest = finalize_execution(execution_dir=execution_dir, plan=plan)
    return ExecutionOutcome(
        execution_dir=execution_dir,
        manifest=manifest,
        exit_code=manifest_exit_code(manifest),
    )


def finalize_execution(*, execution_dir: Path, plan: RunPlan) -> ExecutionManifest:
    state = read_model_json(execution_dir / "execution-state.json", ExecutionState)
    if state.plan_id != plan.plan_id:
        raise ValueError("execution state does not belong to the supplied run plan")

    references: list[ResultFileRef] = []
    completed_at = utc_now()
    for check_ref in plan.checks:
        relative_path = f"results/{check_ref.check_id}.json"
        result_path = execution_dir / relative_path
        if not result_path.is_file():
            result = _error_result(
                plan=plan,
                subject=state.subject,
                check=check_ref,
                execution_id=state.execution_id,
                adapter_id=state.adapter_id,
                adapter_version=state.adapter_version,
                started_at=state.started_at,
                completed_at=completed_at,
                error=ErrorInfo(
                    type="IncompleteExecution",
                    message="The check did not produce a final result.",
                    retryable=True,
                ),
                reason_code="execution.incomplete",
                summary="The execution ended before this check produced a result.",
            )
            write_model_json(result_path, result)
        result = read_model_json(result_path, CheckResult)
        expected_subject = SubjectRef(
            subject_id=state.subject.subject_id,
            subject_version=state.subject.subject_version,
        )
        if result.execution_id != state.execution_id:
            raise ValueError(f"result {result.result_id} belongs to another execution")
        if result.check != check_ref or result.subject != expected_subject:
            raise ValueError(f"result {result.result_id} does not match its planned position")
        references.append(
            ResultFileRef(
                check_id=result.check.check_id,
                version=result.check.version,
                status=result.status,
                path=relative_path,
            )
        )

    manifest = ExecutionManifest(
        execution_id=state.execution_id,
        run_id=plan.plan_id,
        plan_id=plan.plan_id,
        repetition=state.repetition,
        subject=state.subject,
        execution_mode=state.execution_mode,
        github=state.github,
        adapter_id=state.adapter_id,
        started_at=state.started_at,
        completed_at=completed_at,
        completion=CompletionState.COMPLETE,
        results=tuple(references),
    )
    write_model_json(execution_dir / "manifest.json", manifest)
    write_checksums(execution_dir)
    return manifest


def manifest_exit_code(manifest: ExecutionManifest) -> int:
    return 1 if any(result.status is ResultStatus.ERROR for result in manifest.results) else 0
