"""Versioned domain models for benchmark contracts.

Pydantic models are the source of truth from which the committed JSON Schemas are
generated.  The schemas remain the public, language-neutral contract.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    model_validator,
)

from privacy_benchmark.spec.constants import (
    ID_PATTERN,
    REPOSITORY_PATTERN,
    SCHEMA_VERSION,
    SEMVER_PATTERN,
    SHA256_PATTERN,
)

Identifier = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=ID_PATTERN,
        strip_whitespace=True,
    ),
]
Version = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=SEMVER_PATTERN,
        strip_whitespace=True,
    ),
]
Sha256 = Annotated[
    str,
    StringConstraints(pattern=SHA256_PATTERN, strip_whitespace=True),
]
GitCommitSha = Annotated[
    str,
    StringConstraints(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", strip_whitespace=True),
]


def _as_utc(value: UtcDateTime) -> datetime:
    return value.astimezone(UTC)


UtcDateTime = Annotated[AwareDatetime, AfterValidator(_as_utc)]


class StrictModel(BaseModel):
    """Base model for closed, versioned contracts."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class LifecycleStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class Channel(StrEnum):
    HARNESS = "harness"
    EMAIL = "email"
    WEBMAIL = "webmail"
    CHAT = "chat"
    STATIC = "static"
    DOCUMENTED = "documented"
    HUMAN_REVIEW = "human_review"


class EvidenceClass(StrEnum):
    MEASURED = "measured"
    STATIC = "static"
    DOCUMENTED = "documented"
    HUMAN_REVIEW = "human_review"
    SYNTHETIC = "synthetic"


class EvidenceKind(StrEnum):
    CANARY_EVENT = "canary_event"
    DNS_LOG = "dns_log"
    TLS_METADATA = "tls_metadata"
    PACKET_CAPTURE = "packet_capture"
    BROWSER_TRACE = "browser_trace"
    SCREENSHOT = "screenshot"
    NOTIFICATION_SHADE = "notification_shade"
    APP_LOG = "app_log"
    PAGE_SOURCE = "page_source"
    STATIC_ANALYSIS = "static_analysis"
    POLICY_DOCUMENT = "policy_document"
    AUDIT_DOCUMENT = "audit_document"
    HUMAN_REVIEW = "human_review"
    OTHER = "other"


class ResultStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    NOT_TESTED = "not_tested"


class ExecutionMode(StrEnum):
    GITHUB_ACTIONS = "github_actions"
    LOCAL = "local"


class RunnerClass(StrEnum):
    GITHUB_HOSTED_UBUNTU = "github_hosted_ubuntu"
    SELF_HOSTED_MACOS = "self_hosted_macos"
    SELF_HOSTED_ANDROID = "self_hosted_android"
    SELF_HOSTED_IOS = "self_hosted_ios"
    SELF_HOSTED_REGIONAL = "self_hosted_regional"
    STATIC_HOSTED = "static_hosted"


class CompletionState(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


class RollupOutcome(StrEnum):
    """Stability verdict for one check across all planned repetitions.

    Only :attr:`PASS` and :attr:`FAIL` are decisive product properties.  Every other
    value states that the observed sample does not establish one, which is why the
    longitudinal comparison refuses to order them.
    """

    PASS = "pass"
    FAIL = "fail"
    FLAKY = "flaky"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    INCOMPLETE = "incomplete"


class ComparisonVerdict(StrEnum):
    """Direction of change for one check between two run bundles."""

    NEW = "new"
    REMOVED = "removed"
    IMPROVED = "improved"
    REGRESSED = "regressed"
    UNCHANGED = "unchanged"
    UNORDERABLE = "unorderable"


class ThreatModelRef(StrictModel):
    id: Identifier
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)


class CheckDefinition(StrictModel):
    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    check_id: Identifier
    version: Version
    status: LifecycleStatus = LifecycleStatus.DRAFT
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4000)
    channel: Channel
    evidence_class: EvidenceClass
    threat_models: tuple[ThreatModelRef, ...] = Field(min_length=1)
    runner_classes: tuple[RunnerClass, ...] = Field(min_length=1)
    adapter_id: Identifier
    canonical: bool = True
    timeout_seconds: int = Field(default=1800, ge=30, le=21600)


class ComponentRef(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    version: str | None = Field(default=None, min_length=1, max_length=128)
    build: str | None = Field(default=None, min_length=1, max_length=128)
    package_identifier: str | None = Field(default=None, min_length=1, max_length=512)
    artifact_sha256: Sha256 | None = None
    distribution_channel: str | None = Field(default=None, min_length=1, max_length=128)


class PlatformDefinition(StrictModel):
    os: str = Field(min_length=1, max_length=100)
    version: str | None = Field(default=None, min_length=1, max_length=128)
    build: str | None = Field(default=None, min_length=1, max_length=128)
    architecture: str | None = Field(default=None, min_length=1, max_length=64)
    device_model: str | None = Field(default=None, min_length=1, max_length=200)
    is_emulator: bool = False


class AccountDefinition(StrictModel):
    account_type: str = Field(min_length=1, max_length=200)
    slot_id: Identifier
    synthetic: bool = True
    authentication_method: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def require_synthetic_for_benchmark_accounts(self) -> Self:
        if not self.synthetic:
            raise ValueError("benchmark subject accounts must be marked synthetic")
        return self


class ConfigurationSetting(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    value: str | int | float | bool | None = None
    sensitive: bool = False
    value_redacted: bool = False

    @model_validator(mode="after")
    def protect_sensitive_values(self) -> Self:
        if self.sensitive and self.value is not None:
            raise ValueError("sensitive configuration values must not be stored")
        if self.value_redacted and self.value is not None:
            raise ValueError("redacted configuration values must not also contain a value")
        return self


class SubjectConfiguration(StrictModel):
    profile: str = Field(default="default", min_length=1, max_length=100)
    settings: tuple[ConfigurationSetting, ...] = ()

    @model_validator(mode="after")
    def reject_duplicate_setting_names(self) -> Self:
        names = [setting.name for setting in self.settings]
        if len(names) != len(set(names)):
            raise ValueError("configuration setting names must be unique")
        return self


class NetworkVantage(StrictModel):
    vantage_id: Identifier
    country_code: str = Field(min_length=2, max_length=2, pattern=r"^[A-Z]{2}$")
    network_type: str = Field(min_length=1, max_length=100)
    asn: str | None = Field(default=None, min_length=1, max_length=64)
    public_ip_observed: str | None = None
    proxy: str | None = Field(default=None, min_length=1, max_length=200)
    notes: str | None = Field(default=None, max_length=1000)


class SubjectDefinition(StrictModel):
    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    subject_id: Identifier
    subject_version: Version
    client: ComponentRef
    service: ComponentRef | None = None
    platform: PlatformDefinition
    account: AccountDefinition
    configuration: SubjectConfiguration = Field(default_factory=SubjectConfiguration)
    network_vantage: NetworkVantage
    notes: str | None = Field(default=None, max_length=2000)


class CheckRef(StrictModel):
    check_id: Identifier
    version: Version


class SubjectRef(StrictModel):
    subject_id: Identifier
    subject_version: Version


class GitHubProvenance(StrictModel):
    repository: str = Field(pattern=REPOSITORY_PATTERN)
    workflow: str = Field(min_length=1, max_length=200)
    job: str = Field(min_length=1, max_length=200)
    run_id: int = Field(gt=0)
    run_attempt: int = Field(gt=0)
    commit_sha: GitCommitSha


class RunPlan(StrictModel):
    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    plan_id: UUID
    name: str = Field(min_length=1, max_length=200)
    suite_id: Identifier
    suite_version: Version
    created_at: UtcDateTime
    execution_mode: ExecutionMode
    repetitions: int = Field(default=1, ge=1, le=20)
    checks: tuple[CheckRef, ...] = Field(min_length=1)
    subjects: tuple[SubjectRef, ...] = Field(min_length=1)
    expected_execution_count: int = Field(gt=0)
    github: GitHubProvenance | None = None

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        check_keys = [(ref.check_id, ref.version) for ref in self.checks]
        if len(check_keys) != len(set(check_keys)):
            raise ValueError("run plan checks must be unique")
        subject_keys = [(ref.subject_id, ref.subject_version) for ref in self.subjects]
        if len(subject_keys) != len(set(subject_keys)):
            raise ValueError("run plan subjects must be unique")
        expected = len(self.subjects) * self.repetitions
        if self.expected_execution_count != expected:
            raise ValueError(
                "expected_execution_count must equal subject count multiplied by repetitions"
            )
        if self.execution_mode is ExecutionMode.GITHUB_ACTIONS and self.github is None:
            raise ValueError("GitHub Actions execution mode requires GitHub provenance")
        return self


class CollectorRef(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=128)


class RedactionPolicy(StrictModel):
    policy_id: Identifier
    applied: bool
    raw_retention: str = Field(min_length=1, max_length=200)
    notes: str | None = Field(default=None, max_length=1000)


class EvidenceRecord(StrictModel):
    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    evidence_id: Identifier
    execution_id: UUID
    evidence_class: EvidenceClass
    kind: EvidenceKind
    media_type: str = Field(min_length=1, max_length=200)
    sha256: Sha256
    size_bytes: int = Field(ge=0)
    source_uri: str | None = Field(default=None, min_length=1, max_length=2048)
    collected_at: UtcDateTime
    collector: CollectorRef
    redaction: RedactionPolicy
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class AdapterRef(StrictModel):
    id: Identifier
    version: Version


class ErrorInfo(StrictModel):
    type: str = Field(min_length=1, max_length=300)
    message: str = Field(min_length=1, max_length=4000)
    retryable: bool = False


class CheckResult(StrictModel):
    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    result_id: UUID
    run_id: UUID
    execution_id: UUID
    check: CheckRef
    subject: SubjectRef
    adapter: AdapterRef
    status: ResultStatus
    reason_code: Identifier
    summary: str = Field(min_length=1, max_length=2000)
    started_at: UtcDateTime
    completed_at: UtcDateTime
    evidence_refs: tuple[Identifier, ...] = ()
    details: dict[str, JsonValue] = Field(default_factory=dict)
    error: ErrorInfo | None = None

    @model_validator(mode="after")
    def validate_error_state(self) -> Self:
        if self.status is ResultStatus.ERROR and self.error is None:
            raise ValueError("error results require error details")
        if self.status is not ResultStatus.ERROR and self.error is not None:
            raise ValueError("only error results may include error details")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("evidence references must be unique")
        return self


class ResultFileRef(StrictModel):
    check_id: Identifier
    version: Version
    status: ResultStatus
    path: str = Field(pattern=r"^results/[a-z0-9._-]+\.json$")


class ExecutionManifest(StrictModel):
    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    execution_id: UUID
    run_id: UUID
    plan_id: UUID
    repetition: int = Field(ge=1)
    subject: SubjectDefinition
    execution_mode: ExecutionMode
    github: GitHubProvenance | None = None
    adapter_id: Identifier
    started_at: UtcDateTime
    completed_at: UtcDateTime
    completion: CompletionState
    results: tuple[ResultFileRef, ...]

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if self.execution_mode is ExecutionMode.GITHUB_ACTIONS and self.github is None:
            raise ValueError("GitHub Actions execution mode requires GitHub provenance")
        keys = [(result.check_id, result.version) for result in self.results]
        if len(keys) != len(set(keys)):
            raise ValueError("execution manifest results must be unique")
        return self


class RunBundleManifest(StrictModel):
    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    bundle_id: UUID
    plan: RunPlan
    created_at: UtcDateTime
    completion: CompletionState
    execution_manifests: tuple[ExecutionManifest, ...]
    result_count: int = Field(ge=0)
    evidence_count: int = Field(ge=0)
    missing_subjects: tuple[SubjectRef, ...] = ()

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        if self.result_count != sum(len(item.results) for item in self.execution_manifests):
            raise ValueError("result_count must match execution manifests")
        if self.completion is CompletionState.COMPLETE and self.missing_subjects:
            raise ValueError("complete bundles cannot have missing subjects")
        return self


class PublicationReceipt(StrictModel):
    """Append-only record that one canonical bundle was offered for publication.

    A receipt is not a benchmark result and never carries a finding of its own. It
    records *that* a bundle cleared the operational gate, *which* bundle it was by
    content digest, and under which policy revision, so a later reader can prove the
    bundle was published deliberately rather than reconstructed after the fact. The
    transport itself (release asset upload and attestation) is performed by the
    publishing workflow; the receipt is the harness's own evidence that it offered the
    bundle under a named policy.
    """

    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    receipt_id: UUID
    published_at: UtcDateTime
    target: str = Field(min_length=1, max_length=100)
    operations_id: str = Field(min_length=1, max_length=128)
    operations_version: Version
    bundle_id: UUID
    #: SHA-256 over the bundle's ``checksums.sha256``, so the receipt identifies the
    #: exact bytes that were offered and not merely the bundle's identifier.
    bundle_digest: Sha256
    plan_id: UUID
    suite_id: Identifier
    suite_version: Version
    github: GitHubProvenance
    subjects: tuple[SubjectRef, ...] = Field(min_length=1)
    result_count: int = Field(ge=0)
    evidence_count: int = Field(ge=0)
    retention_policy_id: Identifier
    attested: bool

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        keys = [(ref.subject_id, ref.subject_version) for ref in self.subjects]
        if len(keys) != len(set(keys)):
            raise ValueError("publication receipt subjects must be unique")
        return self


class StatusTally(StrictModel):
    status: ResultStatus
    count: int = Field(ge=1)


class CheckRollup(StrictModel):
    """Repeated-measurement summary for one check against one subject."""

    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    check: CheckRef
    subject: SubjectRef
    outcome: RollupOutcome
    observations: int = Field(ge=0)
    expected_observations: int = Field(gt=0)
    pass_count: int = Field(ge=0)
    fail_count: int = Field(ge=0)
    decisive_count: int = Field(ge=0)
    pass_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    pass_rate_low: float | None = Field(default=None, ge=0.0, le=1.0)
    pass_rate_high: float | None = Field(default=None, ge=0.0, le=1.0)
    statuses: tuple[StatusTally, ...] = ()
    reason_codes: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def validate_rollup(self) -> Self:
        if self.pass_count + self.fail_count != self.decisive_count:
            raise ValueError("decisive_count must equal pass_count plus fail_count")
        if self.decisive_count > self.observations:
            raise ValueError("decisive_count cannot exceed observations")
        if sum(tally.count for tally in self.statuses) != self.observations:
            raise ValueError("status tallies must sum to observations")
        if (self.pass_rate is None) != (self.decisive_count == 0):
            raise ValueError("pass_rate must be absent when no decisive observation exists")
        if self.pass_rate is not None and not math.isclose(
            self.pass_rate,
            self.pass_count / self.decisive_count,
            abs_tol=1e-6,
        ):
            raise ValueError("pass_rate must equal pass_count divided by decisive_count")
        if (self.pass_rate_low is None) != (self.pass_rate is None):
            raise ValueError("confidence bounds must accompany pass_rate")
        if (self.pass_rate_high is None) != (self.pass_rate is None):
            raise ValueError("confidence bounds must accompany pass_rate")
        return self


class SubjectRollup(StrictModel):
    subject: SubjectRef
    #: Carried so a published rollup names the product each column represents without
    #: the reader having to resolve the subject registry. ``client_version`` is held for
    #: the same reason. Both stay ``None`` when no execution supplied a definition.
    client_name: str | None = Field(default=None, min_length=1, max_length=200)
    client_version: str | None = Field(default=None, min_length=1, max_length=128)
    platform: PlatformDefinition | None = None
    checks: tuple[CheckRollup, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_rollups_unique(self) -> Self:
        keys = [(item.check.check_id, item.check.version) for item in self.checks]
        if len(keys) != len(set(keys)):
            raise ValueError("subject rollup checks must be unique")
        return self


class RunRollup(StrictModel):
    """Repetition-level summary of one run bundle.

    A rollup is derived analysis, never a benchmark result.  It summarizes how stable
    each per-check outcome was across the planned repetitions.
    """

    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    rollup_id: UUID
    bundle_id: UUID
    suite_id: Identifier
    suite_version: Version
    plan_id: UUID
    created_at: UtcDateTime
    bundle_created_at: UtcDateTime
    bundle_completion: CompletionState
    repetitions: int = Field(ge=1, le=20)
    subjects: tuple[SubjectRollup, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_rollup(self) -> Self:
        keys = [(item.subject.subject_id, item.subject.subject_version) for item in self.subjects]
        if len(keys) != len(set(keys)):
            raise ValueError("run rollup subjects must be unique")
        for subject in self.subjects:
            for check in subject.checks:
                if check.expected_observations != self.repetitions:
                    raise ValueError("check rollup expectations must match planned repetitions")
        return self


class CheckDelta(StrictModel):
    """Change for one check between a baseline and a candidate bundle."""

    check: CheckRef
    subject: SubjectRef
    verdict: ComparisonVerdict
    baseline_outcome: RollupOutcome | None = None
    candidate_outcome: RollupOutcome | None = None
    baseline_check_version: Version | None = None
    candidate_check_version: Version | None = None
    baseline_subject_version: Version | None = None
    candidate_subject_version: Version | None = None
    baseline_pass_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    candidate_pass_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    version_changed: bool = False


class RunComparison(StrictModel):
    """Longitudinal comparison of two run bundles.

    Verdicts are only ordered when both bundles established a decisive pass or fail.
    A flaky, inconclusive, unsupported, or under-sampled result is reported as
    :attr:`ComparisonVerdict.UNORDERABLE` rather than scored.
    """

    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    comparison_id: UUID
    created_at: UtcDateTime
    baseline_bundle_id: UUID
    candidate_bundle_id: UUID
    baseline_created_at: UtcDateTime
    candidate_created_at: UtcDateTime
    baseline_suite: str = Field(min_length=1, max_length=256)
    candidate_suite: str = Field(min_length=1, max_length=256)
    improved: int = Field(ge=0)
    regressed: int = Field(ge=0)
    unchanged: int = Field(ge=0)
    unorderable: int = Field(ge=0)
    added: int = Field(ge=0)
    removed: int = Field(ge=0)
    deltas: tuple[CheckDelta, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_comparison(self) -> Self:
        if self.baseline_bundle_id == self.candidate_bundle_id:
            raise ValueError("a comparison requires two distinct bundles")
        if self.baseline_created_at > self.candidate_created_at:
            raise ValueError("the baseline bundle cannot be newer than the candidate bundle")
        counted = {
            ComparisonVerdict.IMPROVED: self.improved,
            ComparisonVerdict.REGRESSED: self.regressed,
            ComparisonVerdict.UNCHANGED: self.unchanged,
            ComparisonVerdict.UNORDERABLE: self.unorderable,
            ComparisonVerdict.NEW: self.added,
            ComparisonVerdict.REMOVED: self.removed,
        }
        actual = {verdict: 0 for verdict in counted}
        for delta in self.deltas:
            actual[delta.verdict] += 1
        if actual != counted:
            raise ValueError("verdict counts must match the recorded deltas")
        keys = [(delta.subject.subject_id, delta.check.check_id) for delta in self.deltas]
        if len(keys) != len(set(keys)):
            raise ValueError("each subject and check pair may appear only once")
        return self


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""

    return datetime.now(UTC)


def _subject_observation_model() -> type[StrictModel]:
    from privacy_benchmark.harness.preflight import SubjectObservation

    return SubjectObservation


def schema_model_registry() -> dict[str, type[StrictModel]]:
    """Return public models that have a committed JSON Schema."""

    return {
        "check.schema.json": CheckDefinition,
        "subject.schema.json": SubjectDefinition,
        "run-plan.schema.json": RunPlan,
        "result.schema.json": CheckResult,
        "evidence.schema.json": EvidenceRecord,
        "execution-manifest.schema.json": ExecutionManifest,
        "run-bundle.schema.json": RunBundleManifest,
        "publication-receipt.schema.json": PublicationReceipt,
        "run-rollup.schema.json": RunRollup,
        "run-comparison.schema.json": RunComparison,
        # Imported lazily: the observation contract is declared next to the collectors
        # that produce it, and importing it at module scope would be circular.
        "subject-observation.schema.json": _subject_observation_model(),
    }


def schema_model_dependencies() -> dict[type[StrictModel], set[type[Any]]]:
    """Document direct model dependencies for schema generation tests."""

    return {
        CheckDefinition: {ThreatModelRef},
        SubjectDefinition: {
            ComponentRef,
            PlatformDefinition,
            AccountDefinition,
            SubjectConfiguration,
            NetworkVantage,
        },
        RunPlan: {CheckRef, SubjectRef, GitHubProvenance},
        CheckResult: {CheckRef, SubjectRef, AdapterRef, ErrorInfo},
        EvidenceRecord: {CollectorRef, RedactionPolicy},
        ExecutionManifest: {SubjectDefinition, ResultFileRef, GitHubProvenance},
        RunBundleManifest: {RunPlan, ExecutionManifest, SubjectRef},
        PublicationReceipt: {GitHubProvenance, SubjectRef},
        CheckRollup: {CheckRef, SubjectRef},
        SubjectRollup: {SubjectRef, PlatformDefinition, CheckRollup},
        RunRollup: {SubjectRollup},
        CheckDelta: {CheckRef, SubjectRef},
        RunComparison: {CheckDelta},
    }
