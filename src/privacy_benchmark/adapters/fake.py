"""Deterministic fake adapter for account-free smoke tests."""

from __future__ import annotations

from privacy_benchmark.adapters.base import (
    AdapterError,
    AdapterEvidence,
    AdapterOutcome,
    ensure_identifier,
)
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.spec.models import (
    CheckDefinition,
    EvidenceClass,
    EvidenceKind,
    RedactionPolicy,
    ResultStatus,
)
from privacy_benchmark.spec.serialization import json_bytes


class FakeAdapter:
    adapter_id = "fake"
    version = "1.0.0"

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        if check.check_id != "harness.smoke":
            raise AdapterError(f"fake adapter cannot execute product check {check.check_id}")

        evidence_id = ensure_identifier(
            f"{context.execution_id}.{check.check_id}.fixture", field_name="evidence_id"
        )
        payload = json_bytes(
            {
                "check_id": check.check_id,
                "check_version": check.version,
                "execution_id": str(context.execution_id),
                "subject_id": context.subject.subject_id,
                "subject_version": context.subject.subject_version,
                "synthetic": True,
            }
        )
        evidence = AdapterEvidence(
            evidence_id=evidence_id,
            evidence_class=EvidenceClass.SYNTHETIC,
            kind=EvidenceKind.OTHER,
            media_type="application/json",
            payload=payload,
            source_uri=f"fixture://privacy-benchmark/{evidence_id}",
            redaction=RedactionPolicy(
                policy_id="fixture-none",
                applied=False,
                raw_retention="not-retained",
            ),
            metadata={"fixture": True, "account_free": True},
        )
        return AdapterOutcome(
            status=ResultStatus.PASS,
            reason_code="harness.fixture-observed",
            summary="The account-free fixture completed the full adapter and result path.",
            details={"canonical": False, "synthetic": True},
            evidence=(evidence,),
        )
