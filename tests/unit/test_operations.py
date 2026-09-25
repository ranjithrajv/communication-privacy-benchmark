"""Operational policy validation and the canonical-approval gate."""

from __future__ import annotations

import tomllib
from datetime import date, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from privacy_benchmark.spec.operations import (
    OPERATIONS_POLICY_VERSION,
    AccountProcedure,
    AccountProcedureStatus,
    CanonicalGateError,
    OperationsError,
    OperationsPolicy,
    OperationsRegistry,
    PolicyStatus,
    ProvisioningState,
    PublicationPolicy,
    PublicationTarget,
    ReferenceVantage,
    RetentionPolicy,
    ReviewDecision,
    TermsReview,
)

REVIEWED_ON = date(2026, 9, 25)


@pytest.fixture
def policy(repository_root: Path) -> OperationsPolicy:
    return OperationsRegistry.load(repository_root).policy


def _review(**overrides: object) -> TermsReview:
    values: dict[str, object] = {
        "subject_id": "signal-android-default",
        "subject_version": "1.0.0",
        "decision": ReviewDecision.APPROVED,
        "provider": "Signal",
        "terms_uri": "https://signal.org/legal/terms-of-service/",
        "reviewed_on": REVIEWED_ON,
        "reviewed_by": "reviewer",
        "permitted_actions": ["send a synthetic canary message"],
    }
    values.update(overrides)
    return TermsReview.model_validate(values)


def _policy(**overrides: object) -> OperationsPolicy:
    values: dict[str, object] = {
        "operations_id": "lab-operations",
        "version": "1.0.0",
        "status": PolicyStatus.DRAFT,
        "title": "Test policy",
        "description": "A minimal policy used by the operations tests.",
        "reference_vantage": ReferenceVantage(
            vantage_id="reference-de", country_code="DE", network_type="residential"
        ),
        "retention": RetentionPolicy(
            policy_id="retention-v1",
            raw_retention="30-days",
            published_retention="indefinite",
            redaction_rules=["strip account identifiers"],
        ),
        "publication": PublicationPolicy(target=PublicationTarget.NONE, cadence="never"),
        "runner_lanes": (
            {
                "runner_class": "self_hosted_android",
                "lane_id": "android-bank",
                "provisioning": ProvisioningState.UNPROVISIONED,
                "hosting": "self-hosted",
            },
        ),
        "terms_reviews": (_review(),),
    }
    values.update(overrides)
    return OperationsPolicy.model_validate(values)


class TestCheckedInPolicy:
    def test_the_repository_policy_loads(self, policy: OperationsPolicy) -> None:
        assert policy.status is PolicyStatus.DRAFT
        assert policy.reference_vantage.country_code == "DE"

    def test_the_policy_version_matches_the_harness_expectation(
        self, repository_root: Path
    ) -> None:
        loaded = OperationsRegistry.load(repository_root)
        assert loaded.policy.version == OPERATIONS_POLICY_VERSION

    def test_every_real_subject_has_a_recorded_review(self, policy: OperationsPolicy) -> None:
        reviewed = {(item.subject_id, item.subject_version) for item in policy.terms_reviews}
        assert ("signal-android-default", "1.0.0") in reviewed
        assert ("whatsapp-android-default", "1.0.0") in reviewed
        assert ("telegram-android-default", "1.0.0") in reviewed

    def test_no_real_subject_is_approved_yet(self, policy: OperationsPolicy) -> None:
        approved = {
            item.subject_id
            for item in policy.terms_reviews
            if item.decision is ReviewDecision.APPROVED
        }
        assert approved == {"fake-client"}

    def test_no_lane_or_canary_claims_to_be_provisioned(self, policy: OperationsPolicy) -> None:
        lanes = [lane.provisioning for lane in policy.runner_lanes]
        services = [service.provisioning for service in policy.canary_services]
        assert set(lanes) == {ProvisioningState.UNPROVISIONED}
        assert set(services) == {ProvisioningState.UNPROVISIONED}

    def test_publication_is_disabled(self, policy: OperationsPolicy) -> None:
        assert policy.publication.target is PublicationTarget.NONE
        assert policy.publication.cadence == "never"

    def test_no_account_procedure_is_approved(self, policy: OperationsPolicy) -> None:
        assert {item.status for item in policy.account_procedures} == {AccountProcedureStatus.DRAFT}
        assert not any(item.recovery_tested for item in policy.account_procedures)

    def test_every_slot_is_unique(self, policy: OperationsPolicy) -> None:
        slots = [item.slot_id for item in policy.account_procedures]
        assert len(slots) == len(set(slots))


class TestRegistryLoading:
    def test_a_missing_policy_is_reported_clearly(self, tmp_path: Path) -> None:
        with pytest.raises(OperationsError, match="missing operations policy"):
            OperationsRegistry.load(tmp_path)

    def test_a_malformed_policy_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "operations" / OPERATIONS_POLICY_VERSION
        path.mkdir(parents=True)
        (path / "operations.toml").write_text("this is not = valid = toml\n")
        with pytest.raises(OperationsError):
            OperationsRegistry.load(tmp_path)

    def test_an_incomplete_policy_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "operations" / OPERATIONS_POLICY_VERSION
        path.mkdir(parents=True)
        (path / "operations.toml").write_text('schema_version = "1alpha1"\n')
        with pytest.raises(ValidationError, match="operations_id"):
            OperationsRegistry.load(tmp_path)


class TestPolicyInvariants:
    def test_a_placeholder_country_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="real country"):
            ReferenceVantage(vantage_id="v", country_code="ZZ", network_type="unknown")

    def test_a_redacting_policy_must_name_a_rule(self) -> None:
        with pytest.raises(ValidationError, match="must name at least one rule"):
            RetentionPolicy(
                policy_id="r",
                raw_retention="30-days",
                published_retention="indefinite",
                redaction_required=True,
                redaction_rules=(),
            )

    def test_a_policy_that_redacts_nothing_needs_no_rule(self) -> None:
        policy = RetentionPolicy(
            policy_id="r",
            raw_retention="not-retained",
            published_retention="indefinite",
            redaction_required=False,
        )
        assert policy.redaction_rules == ()

    def test_a_disabled_publication_target_must_be_silent(self) -> None:
        with pytest.raises(ValidationError, match="cadence 'never'"):
            PublicationPolicy(target=PublicationTarget.NONE, cadence="weekly")

    def test_a_duplicate_runner_class_is_rejected(self) -> None:
        lane = {
            "runner_class": "self_hosted_android",
            "lane_id": "android-bank",
            "provisioning": "unprovisioned",
            "hosting": "self-hosted",
        }
        with pytest.raises(ValidationError, match="runner class may be declared only once"):
            _policy(runner_lanes=(lane, lane))

    def test_a_duplicate_account_slot_is_rejected(self) -> None:
        procedure = AccountProcedure(
            provider="Signal",
            account_type="synthetic-mobile-number",
            slot_id="slot-1",
            status=AccountProcedureStatus.DRAFT,
            authentication_method="sms",
            recovery_process="documented",
        )
        with pytest.raises(ValidationError, match="account slot may be declared only once"):
            _policy(account_procedures=(procedure, procedure))

    def test_a_duplicate_terms_review_is_rejected(self) -> None:
        with pytest.raises(Exception, match="only one terms review"):
            _policy(terms_reviews=(_review(), _review()))


class TestAccountProcedure:
    def test_approval_requires_a_tested_recovery(self) -> None:
        with pytest.raises(Exception, match="tested recovery process"):
            AccountProcedure(
                provider="Signal",
                account_type="synthetic-mobile-number",
                slot_id="slot-1",
                status=AccountProcedureStatus.APPROVED,
                authentication_method="sms",
                recovery_process="documented",
            )

    def test_a_tested_recovery_can_be_approved(self) -> None:
        procedure = AccountProcedure(
            provider="Signal",
            account_type="synthetic-mobile-number",
            slot_id="slot-1",
            status=AccountProcedureStatus.APPROVED,
            authentication_method="sms",
            recovery_process="documented",
            recovery_tested=True,
        )
        assert procedure.status is AccountProcedureStatus.APPROVED


class TestTermsReview:
    def test_approval_requires_permitted_actions(self) -> None:
        with pytest.raises(Exception, match="enumerate the permitted actions"):
            _review(permitted_actions=())

    def test_a_pending_review_cannot_permit_actions(self) -> None:
        with pytest.raises(Exception, match="cannot permit actions yet"):
            _review(decision=ReviewDecision.PENDING)

    def test_a_rejected_review_may_record_no_actions(self) -> None:
        review = _review(decision=ReviewDecision.REJECTED, permitted_actions=())
        assert review.decision is ReviewDecision.REJECTED

    def test_a_review_cannot_be_dated_in_the_future(self) -> None:
        with pytest.raises(Exception, match="dated in the future"):
            _review(reviewed_on=date.today() + timedelta(days=1))

    def test_conditions_may_constrain_an_approval(self) -> None:
        review = _review(conditions=["low frequency only"])
        assert review.conditions == ("low frequency only",)


class TestCanonicalGate:
    def test_an_approved_subject_passes(self, repository_root: Path) -> None:
        loaded = OperationsRegistry.load(repository_root)
        approvals = loaded.require_canonical_approval((("fake-client", "1.0.0"),))
        assert [review.subject_id for review in approvals] == ["fake-client"]

    def test_a_pending_subject_is_refused(self, repository_root: Path) -> None:
        loaded = OperationsRegistry.load(repository_root)
        with pytest.raises(CanonicalGateError, match="pending provider-terms review"):
            loaded.require_canonical_approval((("signal-android-default", "1.0.0"),))

    def test_an_unreviewed_subject_is_refused(self, repository_root: Path) -> None:
        # The subject id must be a real, registered subject with its review removed:
        # an unknown id would be refused by the same branch, so the test would pass
        # without ever proving that a known-but-unreviewed subject is blocked.
        loaded = OperationsRegistry.load(repository_root)
        unreviewed = tuple(
            item
            for item in loaded.policy.terms_reviews
            if item.subject_id != "signal-android-default"
        )
        refusing = OperationsRegistry(
            root=loaded.root,
            path=loaded.path,
            policy=loaded.policy.model_copy(update={"terms_reviews": unreviewed}),
        )
        with pytest.raises(CanonicalGateError, match="no recorded provider-terms review"):
            refusing.require_canonical_approval((("signal-android-default", "1.0.0"),))

    def test_every_blocked_subject_is_reported(self, repository_root: Path) -> None:
        loaded = OperationsRegistry.load(repository_root)
        with pytest.raises(CanonicalGateError) as error:
            loaded.require_canonical_approval(
                (
                    ("signal-android-default", "1.0.0"),
                    ("whatsapp-android-default", "1.0.0"),
                    ("telegram-android-default", "1.0.0"),
                )
            )
        assert str(error.value).count("pending provider-terms review") == 3

    def test_a_rejected_subject_is_refused(self, repository_root: Path) -> None:
        loaded = OperationsRegistry.load(repository_root)
        rejected = tuple(
            item.model_copy(update={"decision": ReviewDecision.REJECTED})
            for item in loaded.policy.terms_reviews
        )
        refusing = OperationsRegistry(
            root=loaded.root,
            path=loaded.path,
            policy=loaded.policy.model_copy(update={"terms_reviews": rejected}),
        )
        with pytest.raises(CanonicalGateError, match="rejected provider-terms review"):
            refusing.require_canonical_approval((("signal-android-default", "1.0.0"),))


def test_the_checked_in_file_parses_as_toml(repository_root: Path) -> None:
    path = repository_root / "operations" / OPERATIONS_POLICY_VERSION / "operations.toml"
    with path.open("rb") as handle:
        document = tomllib.load(handle)
    assert document["operations_id"] == "lab-operations"
