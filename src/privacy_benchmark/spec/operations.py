"""Checked-in operational policy that gates canonical benchmark runs.

The architecture decision record lists operational questions that must be answered
before any canonical measurement: which subjects form a pilot, where canary services
and devices live, which network vantage is the reference, how accounts are recovered,
which automation each provider's terms permit, and what evidence retention and
redaction apply.

Those answers are operational policy, not check logic, so they live in a versioned
document under ``operations/`` and are validated like any other checked-in definition.
The gate exists because the largest existential risk in this project is not a wrong
result; it is a provider account termination caused by automating an interaction the
provider's terms do not permit.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from privacy_benchmark.spec.constants import ID_PATTERN, SCHEMA_VERSION
from privacy_benchmark.spec.models import (
    Identifier,
    RunnerClass,
    StrictModel,
    Version,
)

OPERATIONS_DIRECTORY = "operations"
OPERATIONS_FILENAME = "operations.toml"


class PolicyStatus(StrEnum):
    """Lifecycle of an operational policy document."""

    DRAFT = "draft"
    ACTIVE = "active"
    SUPERSEDED = "superseded"


class ProvisioningState(StrEnum):
    """Whether the infrastructure a decision refers to actually exists."""

    UNPROVISIONED = "unprovisioned"
    PROVISIONED = "provisioned"
    DECOMMISSIONED = "decommissioned"


class ReviewDecision(StrEnum):
    """Outcome of a provider-terms review for one subject."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class PublicationTarget(StrEnum):
    """Where canonical result bundles are published.

    ``github_pages`` is a reader-facing view over the same bundles a release carries, not
    a second artifact of record. The receipt, the bundle digest, and the release asset
    remain the evidence; a published page is a rendering of them and is regenerated from
    the bundle rather than edited. It is a distinct value rather than an alias of
    ``github_releases`` because a web page is a materially wider surface than a release
    asset — indexable, cached indefinitely, and quotable out of context — so a policy that
    permits one has not thereby permitted the other.
    """

    GITHUB_RELEASES = "github_releases"
    GITHUB_PAGES = "github_pages"
    PUBLIC_OBJECT_STORE = "public_object_store"
    NONE = "none"


class AccountProcedureStatus(StrEnum):
    """Whether an account reset and recovery process is approved for use."""

    DRAFT = "draft"
    APPROVED = "approved"
    RETIRED = "retired"


class ReferenceVantage(StrictModel):
    """The single network vantage that canonical results are attributed to."""

    vantage_id: Identifier
    country_code: str = Field(min_length=2, max_length=2, pattern=r"^[A-Z]{2}$")
    network_type: str = Field(min_length=1, max_length=100)
    provider: str | None = Field(default=None, min_length=1, max_length=200)
    residential: bool = False
    notes: str | None = Field(default=None, min_length=1, max_length=2000)

    @model_validator(mode="after")
    def reject_placeholder_country(self) -> Self:
        if self.country_code == "ZZ":
            raise ValueError(
                "reference vantage must name a real country; 'ZZ' is the unassigned placeholder"
            )
        return self


class RetentionPolicy(StrictModel):
    """Evidence retention and redaction rules applied before publication."""

    policy_id: Identifier
    raw_retention: str = Field(min_length=1, max_length=200)
    published_retention: str = Field(min_length=1, max_length=200)
    redaction_required: bool = True
    redaction_rules: tuple[str, ...] = ()
    notes: str | None = Field(default=None, min_length=1, max_length=2000)

    @model_validator(mode="after")
    def require_a_rule_when_redaction_is_required(self) -> Self:
        if self.redaction_required and not self.redaction_rules:
            raise ValueError("a policy that requires redaction must name at least one rule")
        return self


class RunnerLane(StrictModel):
    """One self-hosted runner class and its provisioning state."""

    runner_class: RunnerClass
    lane_id: Identifier
    provisioning: ProvisioningState
    hosting: str = Field(min_length=1, max_length=200)
    runner_count: int = Field(default=1, ge=1, le=64)
    notes: str | None = Field(default=None, min_length=1, max_length=2000)


class AccountProcedure(StrictModel):
    """How a synthetic account is created, recovered, and retired."""

    provider: str = Field(min_length=1, max_length=200)
    account_type: str = Field(min_length=1, max_length=200)
    slot_id: Identifier
    status: AccountProcedureStatus
    authentication_method: str = Field(min_length=1, max_length=128)
    recovery_process: str = Field(min_length=1, max_length=4000)
    recovery_owner: str | None = Field(default=None, min_length=1, max_length=200)
    recovery_tested: bool = False
    notes: str | None = Field(default=None, min_length=1, max_length=2000)

    @model_validator(mode="after")
    def require_tested_recovery_before_approval(self) -> Self:
        if self.status is AccountProcedureStatus.APPROVED and not self.recovery_tested:
            raise ValueError("an approved account procedure must record a tested recovery process")
        return self


class TermsReview(StrictModel):
    """A recorded provider-terms review for one subject's automation."""

    subject_id: Identifier
    subject_version: Version
    decision: ReviewDecision
    provider: str = Field(min_length=1, max_length=200)
    terms_uri: str = Field(min_length=1, max_length=2048)
    reviewed_on: date
    reviewed_by: str = Field(min_length=1, max_length=200)
    permitted_actions: tuple[str, ...] = ()
    conditions: tuple[str, ...] = ()
    notes: str | None = Field(default=None, min_length=1, max_length=4000)

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if self.decision is ReviewDecision.APPROVED and not self.permitted_actions:
            raise ValueError("an approved terms review must enumerate the permitted actions")
        if self.decision is ReviewDecision.PENDING and self.permitted_actions:
            raise ValueError("a pending terms review cannot permit actions yet")
        if self.reviewed_on > date.today():
            raise ValueError("a review cannot be dated in the future")
        return self


class PublicationPolicy(StrictModel):
    """Where and how often canonical bundles are published."""

    target: PublicationTarget
    cadence: str = Field(min_length=1, max_length=100)
    append_only: bool = True
    attested: bool = True
    notes: str | None = Field(default=None, min_length=1, max_length=2000)

    @model_validator(mode="after")
    def reject_attesting_an_unpublished_target(self) -> Self:
        if self.target is PublicationTarget.NONE and self.cadence != "never":
            raise ValueError("a disabled publication target must use cadence 'never'")
        return self


class CanaryService(StrictModel):
    """A persistent service a measurement lane depends on."""

    service_id: Identifier
    role: str = Field(min_length=1, max_length=200)
    hosting: str = Field(min_length=1, max_length=200)
    provisioning: ProvisioningState
    pinned_version: str | None = Field(default=None, min_length=1, max_length=128)
    notes: str | None = Field(default=None, min_length=1, max_length=2000)


class OperationsPolicy(StrictModel):
    """The versioned operational contract for canonical measurement."""

    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    operations_id: str = Field(pattern=ID_PATTERN)
    version: Version
    status: PolicyStatus
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4000)
    reference_vantage: ReferenceVantage
    retention: RetentionPolicy
    publication: PublicationPolicy
    runner_lanes: tuple[RunnerLane, ...] = Field(min_length=1)
    account_procedures: tuple[AccountProcedure, ...] = ()
    canary_services: tuple[CanaryService, ...] = ()
    terms_reviews: tuple[TermsReview, ...] = ()

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        lanes = [lane.runner_class for lane in self.runner_lanes]
        if len(lanes) != len(set(lanes)):
            raise ValueError("each runner class may be declared only once")
        procedures = [item.slot_id for item in self.account_procedures]
        if len(procedures) != len(set(procedures)):
            raise ValueError("each account slot may be declared only once")
        services = [service.service_id for service in self.canary_services]
        if len(services) != len(set(services)):
            raise ValueError("each canary service may be declared only once")
        reviews = [(item.subject_id, item.subject_version) for item in self.terms_reviews]
        if len(reviews) != len(set(reviews)):
            raise ValueError("each subject may have only one terms review")
        return self

    def review_for(self, subject_id: str, subject_version: str) -> TermsReview | None:
        """Return the terms review for a subject, if one is recorded."""

        for review in self.terms_reviews:
            if (review.subject_id, review.subject_version) == (subject_id, subject_version):
                return review
        return None


class OperationsError(ValueError):
    """Raised when an operations policy cannot be parsed or is inconsistent."""


class CanonicalGateError(OperationsError):
    """Raised when a canonical run is attempted without the required approvals."""


@dataclass(frozen=True, slots=True)
class OperationsRegistry:
    """The loaded operations policy for a repository root."""

    root: Path
    policy: OperationsPolicy
    path: Path

    @classmethod
    def load(cls, root: Path) -> Self:
        path = root / OPERATIONS_DIRECTORY / OPERATIONS_POLICY_VERSION / OPERATIONS_FILENAME
        try:
            with path.open("rb") as handle:
                document = tomllib.load(handle)
        except FileNotFoundError as error:
            raise OperationsError(
                f"missing operations policy: {path}. Canonical runs require a recorded policy."
            ) from error
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise OperationsError(f"{path}: {error}") from error
        return cls(root=root, policy=OperationsPolicy.model_validate(document), path=path)

    def require_canonical_approval(
        self, subjects: tuple[tuple[str, str], ...]
    ) -> tuple[TermsReview, ...]:
        """Return the approvals that let these subjects run canonically.

        Every subject must have an explicitly approved provider-terms review. A missing
        or pending review is a hard failure rather than a warning, because the
        alternative is discovering the constraint through a terminated account.
        """

        approvals: list[TermsReview] = []
        errors: list[str] = []
        for subject_id, subject_version in subjects:
            reference = f"{subject_id}@{subject_version}"
            review = self.policy.review_for(subject_id, subject_version)
            if review is None:
                errors.append(
                    f"subject {reference} has no recorded provider-terms review in {self.path.name}"
                )
                continue
            if review.decision is not ReviewDecision.APPROVED:
                errors.append(
                    f"subject {reference} has a {review.decision.value} provider-terms review; "
                    "canonical runs require an approved review"
                )
                continue
            approvals.append(review)
        if errors:
            raise CanonicalGateError("\n".join(errors))
        return tuple(approvals)


#: The operations policy version this harness reads. Bump it when the required
#: operational fields change so a stale policy fails loudly instead of silently
#: permitting a run.
OPERATIONS_POLICY_VERSION = "1.0.0"

__all__ = [
    "OPERATIONS_DIRECTORY",
    "OPERATIONS_FILENAME",
    "OPERATIONS_POLICY_VERSION",
    "AccountProcedure",
    "AccountProcedureStatus",
    "CanaryService",
    "CanonicalGateError",
    "OperationsError",
    "OperationsPolicy",
    "OperationsRegistry",
    "PolicyStatus",
    "ProvisioningState",
    "PublicationPolicy",
    "PublicationTarget",
    "ReferenceVantage",
    "RetentionPolicy",
    "ReviewDecision",
    "RunnerLane",
    "TermsReview",
]
