"""Decide whether a run bundle may be offered for publication, and record the offer.

The project holds one invariant above every other: a canonical result exists only if a
GitHub Actions run produced it *and* published it. Planning already refuses a canonical
run whose subjects lack an approved provider-terms review, but planning is too early to
be the only gate. A bundle can be built from a plan written under an older policy, the
policy can be downgraded afterwards, or a bundle can arrive from an artifact that was
never gated at all. Publication therefore re-derives every requirement from the bundle
and the checked-in policy rather than trusting that some earlier step did so.

The gate is fail-closed and reports *every* reason it refuses, not just the first. An
operator turning a lane on should see the full list of outstanding obligations in one
pass instead of discovering them one CI run at a time.

Transport is deliberately not implemented here. The harness decides, stages, and
records; the publishing workflow performs the release upload and attestation. That
split keeps the irreversible, credentialed step in Actions where it can be reviewed,
and keeps this module a pure function of checked-in policy plus a verified bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import uuid7

from privacy_benchmark.harness.analysis import BundleAnalysis
from privacy_benchmark.spec.models import (
    CompletionState,
    EvidenceRecord,
    ExecutionMode,
    GitHubProvenance,
    PublicationReceipt,
    SubjectRef,
    utc_now,
)
from privacy_benchmark.spec.operations import (
    OperationsRegistry,
    PolicyStatus,
    PublicationTarget,
    ReviewDecision,
)
from privacy_benchmark.spec.serialization import (
    read_model_json,
    sha256_bytes,
    write_model_json,
)


class PublicationError(RuntimeError):
    """Raised when a bundle cannot be staged for publication."""


@dataclass(frozen=True, slots=True)
class PublicationDecision:
    """Whether a bundle may be published, and every reason it may not."""

    allowed: bool
    reasons: tuple[str, ...]

    def require(self) -> None:
        if not self.allowed:
            raise PublicationError("bundle is not publishable:\n- " + "\n- ".join(self.reasons))


def _evidence_records(analysis: BundleAnalysis) -> tuple[EvidenceRecord, ...]:
    """Load every evidence record the aggregated bundle carries."""

    return tuple(
        read_model_json(path, EvidenceRecord)
        for path in sorted(analysis.directory.rglob("*.record.json"))
    )


def _bundle_digest(analysis: BundleAnalysis) -> str:
    """Digest the bundle by its checksum manifest, so the receipt pins exact bytes."""

    checksums = analysis.directory / "checksums.sha256"
    if not checksums.is_file():
        raise PublicationError(f"bundle has no checksum manifest: {checksums}")
    return sha256_bytes(checksums.read_bytes())


def evaluate_publication(
    analysis: BundleAnalysis, registry: OperationsRegistry
) -> PublicationDecision:
    """Re-derive every publication requirement from the bundle and the policy."""

    policy = registry.policy
    manifest = analysis.manifest
    plan = manifest.plan
    reasons: list[str] = []

    if policy.status is not PolicyStatus.ACTIVE:
        reasons.append(
            f"operations policy {policy.operations_id}@{policy.version} is "
            f"{policy.status.value}, not active"
        )

    if policy.publication.target is PublicationTarget.NONE:
        reasons.append("publication target is disabled (target = none)")

    if manifest.completion is not CompletionState.COMPLETE:
        reasons.append(
            f"run bundle is {manifest.completion.value}; only a complete bundle may publish"
        )

    # The load-bearing invariant: a bundle that was not produced by a GitHub Actions
    # run is development output, however well-formed it is.
    if plan.execution_mode is not ExecutionMode.GITHUB_ACTIONS:
        reasons.append(
            f"bundle was produced in {plan.execution_mode.value} mode; a canonical "
            "result requires a GitHub Actions run"
        )
    if plan.github is None:
        reasons.append("bundle carries no GitHub Actions provenance")

    for execution in manifest.execution_manifests:
        reference = f"{execution.subject.subject_id}@{execution.subject.subject_version}"
        review = policy.review_for(execution.subject.subject_id, execution.subject.subject_version)
        if review is None:
            reasons.append(f"subject {reference} has no provider-terms review in the policy")
        elif review.decision is not ReviewDecision.APPROVED:
            reasons.append(
                f"subject {reference} has a {review.decision.value} provider-terms review"
            )

    if policy.retention.redaction_required:
        unredacted = sorted(
            record.evidence_id
            for record in _evidence_records(analysis)
            if not record.redaction.applied
        )
        if unredacted:
            shown = ", ".join(unredacted[:5])
            suffix = f" (+{len(unredacted) - 5} more)" if len(unredacted) > 5 else ""
            reasons.append(
                f"retention policy {policy.retention.policy_id} requires redaction but "
                f"{len(unredacted)} evidence record(s) are unredacted: {shown}{suffix}"
            )

    return PublicationDecision(allowed=not reasons, reasons=tuple(reasons))


def stage_publication(
    *,
    analysis: BundleAnalysis,
    registry: OperationsRegistry,
    staging_directory: Path,
) -> PublicationReceipt:
    """Write the append-only receipt recording that a bundle was offered for publication."""

    decision = evaluate_publication(analysis, registry)
    decision.require()

    policy = registry.policy
    plan = analysis.manifest.plan
    github: GitHubProvenance | None = plan.github
    if github is None:  # pragma: no cover - evaluate_publication already refused
        raise PublicationError("bundle carries no GitHub Actions provenance")

    subjects = tuple(
        SubjectRef(
            subject_id=execution.subject.subject_id,
            subject_version=execution.subject.subject_version,
        )
        for execution in analysis.manifest.execution_manifests
    )

    receipt = PublicationReceipt(
        receipt_id=uuid7(),
        published_at=utc_now(),
        target=policy.publication.target.value,
        operations_id=policy.operations_id,
        operations_version=policy.version,
        bundle_id=analysis.manifest.bundle_id,
        bundle_digest=_bundle_digest(analysis),
        plan_id=plan.plan_id,
        suite_id=plan.suite_id,
        suite_version=plan.suite_version,
        github=github,
        subjects=subjects,
        result_count=analysis.manifest.result_count,
        evidence_count=analysis.manifest.evidence_count,
        retention_policy_id=policy.retention.policy_id,
        attested=policy.publication.attested,
    )

    destination = staging_directory / f"{receipt.bundle_id}.receipt.json"
    if destination.exists():
        # append_only publication: an already-published bundle is never re-stamped.
        raise PublicationError(
            f"a receipt for bundle {receipt.bundle_id} already exists at {destination}"
        )

    write_model_json(destination, receipt)
    return receipt


__all__ = [
    "PublicationDecision",
    "PublicationError",
    "evaluate_publication",
    "stage_publication",
]
