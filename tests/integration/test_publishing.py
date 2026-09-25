"""Publication gate: what may become a published canonical result, and what may not."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from privacy_benchmark.adapters.base import (
    AdapterEvidence,
    AdapterOutcome,
    ensure_identifier,
)
from privacy_benchmark.harness.aggregation import aggregate_run
from privacy_benchmark.harness.analysis import load_bundle
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.harness.execution import run_execution
from privacy_benchmark.harness.publishing import (
    PublicationError,
    evaluate_publication,
    stage_publication,
)
from privacy_benchmark.spec.models import (
    CheckDefinition,
    EvidenceClass,
    EvidenceKind,
    ExecutionMode,
    GitHubProvenance,
    PublicationReceipt,
    RedactionPolicy,
    ResultStatus,
    RunPlan,
)
from privacy_benchmark.spec.operations import (
    OperationsPolicy,
    OperationsRegistry,
    PolicyStatus,
    PublicationTarget,
    ReviewDecision,
)
from privacy_benchmark.spec.registry import Registry
from privacy_benchmark.spec.serialization import json_bytes, read_model_json

TODAY = datetime.now(UTC).date()
PROVENANCE = GitHubProvenance(
    repository="owner/repository",
    workflow="Email benchmark",
    job="measure",
    run_id=4242,
    run_attempt=1,
    commit_sha="a" * 40,
)


class _RedactingAdapter:
    """Emits evidence whose redaction state the test controls."""

    adapter_id = "redacting"
    version = "1.0.0"

    def __init__(self, *, redacted: bool) -> None:
        self._redacted = redacted

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        evidence_id = ensure_identifier(
            f"{context.execution_id}.{check.check_id}.evidence", field_name="evidence_id"
        )
        return AdapterOutcome(
            status=ResultStatus.PASS,
            reason_code="fixture.observed",
            summary="Fixture observation.",
            evidence=(
                AdapterEvidence(
                    evidence_id=evidence_id,
                    evidence_class=EvidenceClass.MEASURED,
                    kind=EvidenceKind.OTHER,
                    media_type="application/json",
                    payload=json_bytes({"check_id": check.check_id}),
                    redaction=RedactionPolicy(
                        policy_id="fixture-redaction",
                        applied=self._redacted,
                        raw_retention="30-days-then-delete",
                    ),
                ),
            ),
        )


def _canonical_plan(local_plan: RunPlan) -> RunPlan:
    """The same smoke plan, but produced by a GitHub Actions run."""

    data: dict[str, Any] = local_plan.model_dump(mode="python")
    data["execution_mode"] = ExecutionMode.GITHUB_ACTIONS
    data["github"] = PROVENANCE
    return RunPlan.model_validate(data)


def _bundle(
    tmp_path: Path,
    plan: RunPlan,
    registry: Registry,
    *,
    redacted: bool = True,
    executions: int | None = None,
) -> Any:
    subject = registry.resolve_subject("fake-client@1.0.0")
    check = registry.resolve_check("harness.smoke@1.0.0")
    for repetition in range(1, (executions or plan.repetitions) + 1):
        asyncio.run(
            run_execution(
                plan=plan,
                subject=subject,
                checks=(check,),
                adapter=_RedactingAdapter(redacted=redacted),
                execution_dir=tmp_path / "executions" / "fake-client" / f"{repetition:04d}",
                repetition=repetition,
            )
        )
    aggregate_run(
        plan=plan,
        executions_root=tmp_path / "executions",
        output_dir=tmp_path / "bundle",
    )
    return load_bundle(tmp_path / "bundle")


def _policy(
    *,
    status: PolicyStatus = PolicyStatus.ACTIVE,
    target: PublicationTarget = PublicationTarget.GITHUB_RELEASES,
    decision: ReviewDecision = ReviewDecision.APPROVED,
    redaction_required: bool = True,
) -> OperationsPolicy:
    return OperationsPolicy.model_validate(
        {
            "operations_id": "lab-operations",
            "version": "1.0.0",
            "status": status,
            "title": "Publication fixture",
            "description": "A policy fixture exercising the publication gate.",
            "reference_vantage": {
                "vantage_id": "reference-vantage",
                "country_code": "DE",
                "network_type": "residential-fiber",
            },
            "retention": {
                "policy_id": "retention-v1",
                "raw_retention": "30-days-then-delete",
                "published_retention": "indefinite",
                "redaction_required": redaction_required,
                "redaction_rules": ["strip account identifiers"] if redaction_required else [],
            },
            "publication": {
                "target": target,
                "cadence": "weekly" if target is not PublicationTarget.NONE else "never",
                "append_only": True,
                "attested": True,
            },
            "runner_lanes": [
                {
                    "runner_class": "self_hosted_macos",
                    "lane_id": "mac-lane",
                    "provisioning": "provisioned",
                    "hosting": "lab",
                }
            ],
            "terms_reviews": [
                {
                    "subject_id": "fake-client",
                    "subject_version": "1.0.0",
                    "decision": decision,
                    "provider": "Fixture",
                    "terms_uri": "https://example.invalid/terms",
                    "reviewed_on": TODAY,
                    "reviewed_by": "fixture",
                    "permitted_actions": ["open a synthetic message"]
                    if decision is ReviewDecision.APPROVED
                    else [],
                }
            ],
        }
    )


def _registry(policy: OperationsPolicy) -> OperationsRegistry:
    return OperationsRegistry(
        root=Path(), policy=policy, path=Path("operations/1.0.0/operations.toml")
    )


class TestPublicationGateRefusals:
    """Each unmet obligation is reported, and the bundle is refused."""

    def test_a_locally_produced_bundle_is_not_publishable(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        # The load-bearing invariant: a bundle built outside GitHub Actions is
        # development output, however complete and well-formed it is.
        analysis = _bundle(tmp_path, local_plan, registry)

        decision = evaluate_publication(analysis, _registry(_policy()))

        assert not decision.allowed
        assert any("requires a GitHub Actions run" in reason for reason in decision.reasons)

    def test_a_draft_policy_refuses_publication(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        analysis = _bundle(tmp_path, _canonical_plan(local_plan), registry)

        decision = evaluate_publication(analysis, _registry(_policy(status=PolicyStatus.DRAFT)))

        assert not decision.allowed
        assert any("is draft, not active" in reason for reason in decision.reasons)

    def test_a_disabled_target_refuses_publication(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        analysis = _bundle(tmp_path, _canonical_plan(local_plan), registry)

        decision = evaluate_publication(analysis, _registry(_policy(target=PublicationTarget.NONE)))

        assert not decision.allowed
        assert any("publication target is disabled" in reason for reason in decision.reasons)

    def test_a_pending_terms_review_refuses_publication(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        analysis = _bundle(tmp_path, _canonical_plan(local_plan), registry)

        decision = evaluate_publication(
            analysis, _registry(_policy(decision=ReviewDecision.PENDING))
        )

        assert not decision.allowed
        assert any("pending provider-terms review" in reason for reason in decision.reasons)

    def test_unredacted_evidence_refuses_publication(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        analysis = _bundle(tmp_path, _canonical_plan(local_plan), registry, redacted=False)

        decision = evaluate_publication(analysis, _registry(_policy()))

        assert not decision.allowed
        assert any("requires redaction" in reason for reason in decision.reasons)

    def test_every_unmet_obligation_is_reported_at_once(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        # An operator turning a lane on should see the whole list, not one reason per run.
        analysis = _bundle(tmp_path, local_plan, registry, redacted=False)

        decision = evaluate_publication(
            analysis,
            _registry(
                _policy(
                    status=PolicyStatus.DRAFT,
                    target=PublicationTarget.NONE,
                    decision=ReviewDecision.PENDING,
                )
            ),
        )

        assert not decision.allowed
        # A locally produced bundle trips two distinct checks, so six obligations are
        # outstanding: draft policy, disabled target, non-Actions mode, absent
        # provenance, pending terms review, and unredacted evidence.
        assert len(decision.reasons) == 6
        expected = (
            "is draft, not active",
            "publication target is disabled",
            "produced in local mode",
            "carries no GitHub Actions provenance",
            "has a pending provider-terms review",
            "requires redaction",
        )
        for fragment in expected:
            assert any(fragment in reason for reason in decision.reasons), fragment

    def test_a_refused_bundle_writes_no_receipt(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        analysis = _bundle(tmp_path, local_plan, registry)
        staging = tmp_path / "staging"

        with pytest.raises(PublicationError, match="not publishable"):
            stage_publication(
                analysis=analysis, registry=_registry(_policy()), staging_directory=staging
            )

        assert not staging.exists() or not list(staging.iterdir())


class TestPublicationStaging:
    """A bundle that clears every gate is recorded, once."""

    def test_a_canonical_bundle_receives_a_receipt(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        analysis = _bundle(tmp_path, _canonical_plan(local_plan), registry)

        receipt = stage_publication(
            analysis=analysis,
            registry=_registry(_policy()),
            staging_directory=tmp_path / "staging",
        )

        assert receipt.target == PublicationTarget.GITHUB_RELEASES.value
        assert receipt.github == PROVENANCE
        assert receipt.attested is True
        assert receipt.result_count == analysis.manifest.result_count
        assert receipt.evidence_count == analysis.manifest.evidence_count
        assert [(ref.subject_id, ref.subject_version) for ref in receipt.subjects] == [
            ("fake-client", "1.0.0")
        ]
        assert len(receipt.bundle_digest) == 64

    def test_the_receipt_pins_the_exact_bundle_bytes(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        analysis = _bundle(tmp_path, _canonical_plan(local_plan), registry)

        receipt = stage_publication(
            analysis=analysis,
            registry=_registry(_policy()),
            staging_directory=tmp_path / "staging",
        )

        assert receipt.bundle_id == analysis.manifest.bundle_id
        assert receipt.plan_id == analysis.manifest.plan.plan_id
        written = read_model_json(
            tmp_path / "staging" / f"{receipt.bundle_id}.receipt.json", PublicationReceipt
        )
        assert written == receipt

    def test_publication_is_append_only(
        self, tmp_path: Path, local_plan: RunPlan, registry: Registry
    ) -> None:
        # A second attempt to publish the same bundle must not silently re-stamp it.
        analysis = _bundle(tmp_path, _canonical_plan(local_plan), registry)
        operations = _registry(_policy())
        staging = tmp_path / "staging"
        stage_publication(analysis=analysis, registry=operations, staging_directory=staging)

        with pytest.raises(PublicationError, match="already exists"):
            stage_publication(analysis=analysis, registry=operations, staging_directory=staging)
