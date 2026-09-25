"""The publication gate must be proven to open, not only to refuse.

The checked-in policy has ``publication.target = "none"`` and every provider-terms review
is pending, so the only path reachable in this repository today is the refusal. That
means the moment someone selects a target and approves a review, the succeeding path runs
for the first time in production, on a real weekly run, with a real account behind it.

These tests construct a fully satisfying bundle and policy so the opening path is
exercised in CI. They are the difference between a flag flip being a configuration change
and being a deployment.
"""

from __future__ import annotations

import asyncio
from datetime import date
from pathlib import Path

import pytest

from privacy_benchmark.adapters.fake import FakeAdapter
from privacy_benchmark.harness.aggregation import aggregate_run
from privacy_benchmark.harness.analysis import load_bundle
from privacy_benchmark.harness.execution import run_execution
from privacy_benchmark.harness.planning import build_run_plan
from privacy_benchmark.harness.publishing import (
    PublicationError,
    evaluate_publication,
    stage_publication,
)
from privacy_benchmark.spec.models import CompletionState, ExecutionMode, GitHubProvenance
from privacy_benchmark.spec.operations import (
    AccountProcedure,
    AccountProcedureStatus,
    OperationsPolicy,
    OperationsRegistry,
    PolicyStatus,
    ProvisioningState,
    PublicationPolicy,
    PublicationTarget,
    ReferenceVantage,
    RetentionPolicy,
    ReviewDecision,
    RunnerLane,
    TermsReview,
)
from privacy_benchmark.spec.registry import Registry
from privacy_benchmark.spec.serialization import verify_checksums

GITHUB = GitHubProvenance(
    repository="owner/repository",
    workflow="Email benchmark",
    job="measure",
    run_id=12345,
    run_attempt=1,
    commit_sha="a" * 40,
)


def _satisfying_policy() -> OperationsPolicy:
    """A policy that satisfies every publication requirement.

    Built by hand rather than by editing the checked-in one, so the test does not
    depend on, or weaken, the real policy that keeps the lanes blocked.
    """

    return OperationsPolicy.model_validate(
        {
            "operations_id": "test-lab",
            "version": "1.0.0",
            "status": PolicyStatus.ACTIVE,
            "title": "A policy that clears the publication gate",
            "description": "Constructed for the publication tests only.",
            "reference_vantage": ReferenceVantage(
                vantage_id="reference-de", country_code="DE", network_type="residential"
            ),
            "retention": RetentionPolicy(
                policy_id="retention-v1",
                raw_retention="30-days",
                published_retention="indefinite",
                redaction_required=False,
            ),
            "publication": PublicationPolicy(
                target=PublicationTarget.GITHUB_RELEASES, cadence="weekly"
            ),
            "runner_lanes": (
                RunnerLane(
                    runner_class="github_hosted_ubuntu",
                    lane_id="ci",
                    provisioning=ProvisioningState.PROVISIONED,
                    hosting="github-hosted",
                ),
            ),
            "account_procedures": (
                AccountProcedure(
                    provider="None",
                    account_type="synthetic",
                    slot_id="slot-0001",
                    status=AccountProcedureStatus.APPROVED,
                    authentication_method="none",
                    recovery_process="Not applicable to a synthetic fixture.",
                    recovery_tested=True,
                ),
            ),
            "terms_reviews": (
                TermsReview(
                    subject_id="fake-client",
                    subject_version="1.0.0",
                    decision=ReviewDecision.APPROVED,
                    provider="none",
                    terms_uri="fixture://no-provider-terms-apply",
                    reviewed_on=date.today(),
                    reviewed_by="test",
                    permitted_actions=("measure the account-free fixture",),
                ),
            ),
        }
    )


def _registry(policy: OperationsPolicy) -> OperationsRegistry:
    return OperationsRegistry(root=Path(), path=Path("test"), policy=policy)


def _canonical_bundle(tmp_path: Path, registry: Registry) -> Path:
    """Aggregate a bundle that satisfies every publication requirement."""

    plan = build_run_plan(
        Path(registry.root) / "suites" / "smoke" / "1.0.0" / "suite.toml",
        Path(registry.root),
        execution_mode=ExecutionMode.GITHUB_ACTIONS,
        github=GITHUB,
    )
    execution_dir = tmp_path / "executions" / "fake-client" / "0001"
    asyncio.run(
        run_execution(
            plan=plan,
            subject=registry.resolve_subject("fake-client@1.0.0"),
            checks=(registry.resolve_check("harness.smoke@1.0.0"),),
            adapter=FakeAdapter(),
            execution_dir=execution_dir,
            repetition=1,
        )
    )
    output = tmp_path / "bundle"
    aggregate_run(plan=plan, executions_root=tmp_path / "executions", output_dir=output)
    return output


@pytest.fixture
def canonical(tmp_path: Path, repository_root: Path) -> Path:
    registry = Registry.load(repository_root)
    return _canonical_bundle(tmp_path, registry)


class TestTheGateOpens:
    def test_a_satisfying_bundle_is_allowed_to_publish(self, canonical: Path) -> None:
        analysis = load_bundle(canonical)
        decision = evaluate_publication(analysis, _registry(_satisfying_policy()))
        assert decision.allowed is True, decision.reasons
        assert decision.reasons == ()

    def test_a_receipt_is_written_outside_the_bundle(self, canonical: Path, tmp_path: Path) -> None:
        analysis = load_bundle(canonical)
        staging = tmp_path / "staging"
        receipt = stage_publication(
            analysis=analysis,
            registry=_registry(_satisfying_policy()),
            staging_directory=staging,
        )
        assert receipt.target == "github_releases"
        assert receipt.bundle_id == analysis.manifest.bundle_id
        assert receipt.github is not None
        assert receipt.github.run_id == 12345
        # The receipt is named for the bundle, so a staging area is append-only.
        assert (staging / f"{receipt.bundle_id}.receipt.json").is_file()
        assert not (staging / "receipt.json").exists()
        # Publishing must never mutate the evidence it attests to.
        assert verify_checksums(canonical) == []

    def test_the_receipt_digest_identifies_the_exact_bundle(self, canonical: Path) -> None:
        analysis = load_bundle(canonical)
        first = stage_publication(
            analysis=analysis,
            registry=_registry(_satisfying_policy()),
            staging_directory=Path("/tmp/receipt-a.json"),
        )
        second = stage_publication(
            analysis=load_bundle(canonical),
            registry=_registry(_satisfying_policy()),
            staging_directory=Path("/tmp/staging-b"),
        )
        assert first.bundle_digest == second.bundle_digest
        assert len(first.bundle_digest) == 64


class TestTheGateStaysShut:
    """Each refusal is a distinct obligation, so a failure names the one unmet."""

    def _refusals(self, canonical: Path, **overrides: object) -> list[str]:
        policy = _satisfying_policy()
        data = policy.model_dump(mode="python")
        for key, value in overrides.items():
            data[key] = value
        decision = evaluate_publication(
            load_bundle(canonical), _registry(OperationsPolicy.model_validate(data))
        )
        assert decision.allowed is False
        return list(decision.reasons)

    def test_a_disabled_target_is_refused(self, canonical: Path) -> None:
        reasons = self._refusals(
            canonical,
            publication=PublicationPolicy(target=PublicationTarget.NONE, cadence="never"),
        )
        assert any("target is disabled" in reason for reason in reasons)

    def test_a_draft_policy_is_refused(self, canonical: Path) -> None:
        policy = _satisfying_policy().model_copy(update={"status": PolicyStatus.DRAFT})
        decision = evaluate_publication(load_bundle(canonical), _registry(policy))
        assert decision.allowed is False
        assert any("not active" in reason for reason in decision.reasons)

    def test_a_pending_review_is_refused(self, canonical: Path) -> None:
        policy = _satisfying_policy()
        pending = policy.terms_reviews[0].model_copy(
            update={"decision": ReviewDecision.PENDING, "permitted_actions": ()}
        )
        decision = evaluate_publication(
            load_bundle(canonical),
            _registry(policy.model_copy(update={"terms_reviews": (pending,)})),
        )
        assert decision.allowed is False
        assert any("pending provider-terms review" in reason for reason in decision.reasons)

    def test_staging_refuses_a_blocked_bundle(self, canonical: Path, tmp_path: Path) -> None:
        policy = _satisfying_policy().model_copy(update={"status": PolicyStatus.DRAFT})
        with pytest.raises(PublicationError):
            stage_publication(
                analysis=load_bundle(canonical),
                registry=_registry(policy),
                staging_directory=tmp_path / "staging",
            )
        assert not (tmp_path / "staging").exists()

    def test_a_local_bundle_never_publishes(self, tmp_path: Path, repository_root: Path) -> None:
        """The load-bearing invariant: only a GitHub Actions run is canonical."""

        registry = Registry.load(repository_root)
        plan = build_run_plan(
            repository_root / "suites" / "smoke" / "1.0.0" / "suite.toml",
            repository_root,
            execution_mode=ExecutionMode.LOCAL,
            github=None,
        )
        execution_dir = tmp_path / "local" / "fake-client" / "0001"
        asyncio.run(
            run_execution(
                plan=plan,
                subject=registry.resolve_subject("fake-client@1.0.0"),
                checks=(registry.resolve_check("harness.smoke@1.0.0"),),
                adapter=FakeAdapter(),
                execution_dir=execution_dir,
                repetition=1,
            )
        )
        output = tmp_path / "local-bundle"
        aggregate_run(plan=plan, executions_root=tmp_path / "local", output_dir=output)
        decision = evaluate_publication(load_bundle(output), _registry(_satisfying_policy()))
        assert decision.allowed is False
        assert any("local mode" in reason for reason in decision.reasons)

    def test_an_incomplete_bundle_is_refused(self, tmp_path: Path, repository_root: Path) -> None:
        registry = Registry.load(repository_root)
        plan = build_run_plan(
            repository_root / "suites" / "smoke" / "1.0.0" / "suite.toml",
            repository_root,
            execution_mode=ExecutionMode.GITHUB_ACTIONS,
            github=GITHUB,
        ).model_copy(update={"repetitions": 2, "expected_execution_count": 2})
        execution_dir = tmp_path / "partial" / "fake-client" / "0001"
        asyncio.run(
            run_execution(
                plan=plan,
                subject=registry.resolve_subject("fake-client@1.0.0"),
                checks=(registry.resolve_check("harness.smoke@1.0.0"),),
                adapter=FakeAdapter(),
                execution_dir=execution_dir,
                repetition=1,
            )
        )
        output = tmp_path / "partial-bundle"
        aggregate_run(plan=plan, executions_root=tmp_path / "partial", output_dir=output)
        assert load_bundle(output).manifest.completion is CompletionState.INCOMPLETE
        decision = evaluate_publication(load_bundle(output), _registry(_satisfying_policy()))
        assert decision.allowed is False
        assert any("only a complete bundle" in reason for reason in decision.reasons)
