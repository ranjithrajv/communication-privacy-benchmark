"""End-to-end EPT adapter execution through the real harness.

The gateway is mocked at the HTTP boundary, which is exactly the seam the project
controls. Everything below it, the adapter, the execution harness, evidence hashing,
result writing, and manifest finalization, is the production path.

For what happens when a genuine client crosses a real socket, see
``tests/integration/test_live_canary.py``.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from privacy_benchmark.adapters.ept import (
    EptGatewayAdapter,
    EptGatewayClient,
    ObservationChannel,
    ObservationOrigin,
)
from privacy_benchmark.harness.execution import manifest_exit_code, run_execution
from privacy_benchmark.spec.models import (
    CheckDefinition,
    CheckRef,
    CheckResult,
    CompletionState,
    EvidenceRecord,
    ExecutionManifest,
    ResultStatus,
    RunPlan,
    SubjectDefinition,
    SubjectRef,
)
from privacy_benchmark.spec.registry import Registry
from privacy_benchmark.spec.serialization import read_model_json, verify_checksums

DELIVERED = "2026-09-25T12:00:00Z"
FAR_FUTURE = "2099-01-01T00:00:00Z"
MAILBOX = "probe@example.invalid"
CANARY_HOST = "canary.privacy-benchmark.invalid"
#: The adapter polls until the gateway closes the probe window, so the fixture uses a
#: short realistic window rather than an effectively unbounded one.
DEFAULT_WINDOW_SECONDS = 1.0


class FakeGateway:
    """A scripted EPT gateway served over a mocked transport."""

    def __init__(
        self,
        *,
        observations: tuple[dict[str, object], ...] = (),
        delivered: bool = True,
        watchers_healthy: bool = True,
        poll_interval_seconds: float = 0.02,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self.observations = observations
        self.delivered = delivered
        self.watchers_healthy = watchers_healthy
        self.poll_interval_seconds = poll_interval_seconds
        self.window_expires_at = (datetime.now(UTC) + timedelta(seconds=window_seconds)).isoformat()
        self.requests: list[httpx.Request] = []
        self.created_email: str | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["authorization"] == "Bearer test-token"
        if request.method == "POST" and request.url.path == "/v1/tests":
            self.created_email = json.loads(request.content)["email"]
            return httpx.Response(
                200,
                json={
                    "test_id": "test.one",
                    "probe_id": "probe.one",
                    "expires_at": self.window_expires_at,
                },
            )
        if request.method == "GET" and request.url.path == "/v1/tests/test.one/state":
            return httpx.Response(
                200,
                json={
                    "test_id": "test.one",
                    "probe_id": "probe.one",
                    "delivered_at": DELIVERED if self.delivered else None,
                    "watchers_healthy": self.watchers_healthy,
                    "window_expires_at": self.window_expires_at,
                },
            )
        if request.method == "GET" and request.url.path == "/v1/tests/test.one/observations":
            return httpx.Response(
                200, json={"test_id": "test.one", "observations": list(self.observations)}
            )
        return httpx.Response(404)

    def adapter(
        self,
        mailboxes: dict[str, str] | None = None,
        *,
        open_asserted: bool = True,
    ) -> EptGatewayAdapter:
        return EptGatewayAdapter(
            client=EptGatewayClient(
                base_url="https://gateway.invalid",
                token="test-token",
                transport=httpx.MockTransport(self.handler),
            ),
            mailboxes={"slot-0001": MAILBOX} if mailboxes is None else mailboxes,
            poll_interval_seconds=self.poll_interval_seconds,
            open_observer=(lambda context: open_asserted),
        )

    def paths_called(self) -> list[str]:
        return [request.url.path for request in self.requests]


def _observation(
    channel: str = "http",
    *,
    vector: str = "img",
    origin: str = "client",
    remote_host: str = CANARY_HOST,
    probe_id: str = "probe.one",
) -> dict[str, object]:
    return {
        "channel": channel,
        "probe_id": probe_id,
        "vector": vector,
        "origin": origin,
        "remote_host": remote_host,
        "observed_at": "2026-09-25T12:01:05Z",
    }


def _single_check_plan(
    plan: RunPlan, subject: SubjectDefinition, check: CheckDefinition
) -> RunPlan:
    return plan.model_copy(
        update={
            "checks": (CheckRef(check_id=check.check_id, version=check.version),),
            "subjects": (
                SubjectRef(subject_id=subject.subject_id, subject_version=subject.subject_version),
            ),
            "expected_execution_count": 1,
            "repetitions": 1,
        }
    )


def _execute(
    *,
    plan: RunPlan,
    subject: SubjectDefinition,
    check: CheckDefinition,
    adapter: EptGatewayAdapter,
    execution_dir: Path,
) -> tuple[CheckResult, EvidenceRecord | None, ExecutionManifest]:
    outcome = asyncio.run(
        run_execution(
            plan=plan,
            subject=subject,
            checks=(check,),
            adapter=adapter,
            execution_dir=execution_dir,
            repetition=1,
        )
    )
    result = read_model_json(execution_dir / "results" / f"{check.check_id}.json", CheckResult)
    # An error or unsupported result carries no evidence, which is itself the contract.
    evidence = (
        read_model_json(
            execution_dir / "evidence" / f"{result.evidence_refs[0]}.json", EvidenceRecord
        )
        if result.evidence_refs
        else None
    )
    return result, evidence, outcome.manifest


@pytest.fixture
def subject(registry: Registry) -> SubjectDefinition:
    return registry.resolve_subject("fake-client@1.0.0")


@pytest.fixture
def check(registry: Registry) -> CheckDefinition:
    return registry.resolve_check("email.remote-content@1.0.0")


class TestAdjudicationThroughTheHarness:
    def test_a_clean_client_passes_with_hashed_evidence(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        gateway = FakeGateway()
        result, evidence, manifest = _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=check,
            adapter=gateway.adapter(),
            execution_dir=tmp_path / "0001",
        )
        assert result.status is ResultStatus.PASS
        assert result.reason_code == "ept.no-remote-content-observed"
        assert manifest.completion is CompletionState.COMPLETE
        assert manifest_exit_code(manifest) == 0
        assert gateway.created_email == MAILBOX
        assert evidence is not None
        assert evidence.evidence_class.value == "measured"
        assert evidence.redaction.applied is True
        assert len(evidence.sha256) == 64
        assert verify_checksums(tmp_path / "0001") == []

    def test_remote_content_is_a_failure_but_not_a_ci_failure(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        gateway = FakeGateway(observations=(_observation("tls_sni", vector="linkPreconnect"),))
        result, _, manifest = _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=check,
            adapter=gateway.adapter(),
            execution_dir=tmp_path / "0001",
        )
        assert result.status is ResultStatus.FAIL
        assert result.reason_code == "ept.remote-content-detected"
        assert result.details["client_observation_count"] == 1
        # A product fail is a successful measurement, not a CI failure.
        assert manifest.completion is CompletionState.COMPLETE
        assert manifest_exit_code(manifest) == 0

    def test_provider_prefetch_is_recorded_but_never_fails_the_client(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        gateway = FakeGateway(
            observations=(_observation("dns", vector="dnsAnchor", origin="provider"),)
        )
        result, _, _ = _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=check,
            adapter=gateway.adapter(),
            execution_dir=tmp_path / "0001",
        )
        assert result.status is ResultStatus.INCONCLUSIVE
        assert result.reason_code == "ept.provider-prefetch-only"
        assert result.details["provider_observation_count"] == 1
        assert result.details["client_observation_count"] == 0

    @pytest.mark.parametrize(
        ("kwargs", "reason"),
        [
            ({"delivered": False}, "ept.message-not-delivered"),
            ({"watchers_healthy": False}, "ept.watchers-unhealthy"),
        ],
    )
    def test_a_broken_probe_is_inconclusive_never_a_pass(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
        kwargs: dict[str, object],
        reason: str,
    ) -> None:
        result, _, _ = _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=check,
            adapter=FakeGateway(**kwargs).adapter(),  # type: ignore[arg-type]
            execution_dir=tmp_path / "0001",
        )
        assert result.status is ResultStatus.INCONCLUSIVE
        assert result.reason_code == reason

    def test_an_unasserted_open_is_inconclusive_never_a_pass(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        # The single most important property: upstream cannot report an open, so an
        # adapter that was not told the message was opened must not claim a pass.
        result, _, _ = _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=check,
            adapter=FakeGateway().adapter(open_asserted=False),
            execution_dir=tmp_path / "0001",
        )
        assert result.status is ResultStatus.INCONCLUSIVE
        assert result.reason_code == "ept.open-not-asserted"
        assert result.details["open_asserted"] is False

    def test_an_observation_from_another_probe_fails_the_run(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        result, _, manifest = _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=check,
            adapter=FakeGateway(observations=(_observation(probe_id="probe.other"),)).adapter(),
            execution_dir=tmp_path / "0001",
        )
        assert result.status is ResultStatus.ERROR
        assert result.error is not None
        assert result.error.retryable is True
        assert result.evidence_refs == ()
        assert manifest_exit_code(manifest) == 1


class TestProbeCorrelation:
    def test_a_settled_probe_with_no_traffic_polls_once(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        gateway = FakeGateway(poll_interval_seconds=30.0, window_seconds=3600.0)
        _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=check,
            adapter=gateway.adapter(),
            execution_dir=tmp_path / "0001",
        )
        # Once the message is delivered and the watchers are healthy, an empty set is
        # already the answer, so the adapter must not keep polling.
        assert gateway.paths_called().count("/v1/tests/test.one/observations") == 1

    def test_an_unsettled_probe_keeps_polling_until_the_window_closes(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        gateway = FakeGateway(delivered=False, window_seconds=0.5)
        result, _, _ = _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=check,
            adapter=gateway.adapter(),
            execution_dir=tmp_path / "0001",
        )
        assert result.status is ResultStatus.INCONCLUSIVE
        assert result.reason_code == "ept.message-not-delivered"
        assert gateway.paths_called().count("/v1/tests/test.one/observations") > 1


class TestAdapterBoundaries:
    def test_the_mailbox_address_is_never_recorded_in_evidence(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        secret = "secret-probe@example.invalid"
        _, evidence, _ = _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=check,
            adapter=FakeGateway().adapter({"slot-0001": secret}),
            execution_dir=tmp_path / "0001",
        )
        assert evidence is not None
        payload = (
            tmp_path / "0001" / "evidence" / f"{evidence.evidence_id}.payload.json"
        ).read_text()
        assert secret not in payload
        assert json.loads(payload)["account_slot"] == "slot-0001"

    def test_an_unconfigured_account_slot_fails_the_execution(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        # The harness converts an adapter exception into an error result rather than
        # letting it escape, and the message is redacted so a configuration mistake
        # cannot leak the address.
        result, evidence, manifest = _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=check,
            adapter=FakeGateway().adapter({}),
            execution_dir=tmp_path / "0001",
        )
        assert result.status is ResultStatus.ERROR
        assert result.reason_code == "adapter.exception"
        assert result.error is not None
        assert result.error.type == "AdapterError"
        assert "example.invalid" not in result.error.message
        assert evidence is None
        assert manifest_exit_code(manifest) == 1

    def test_an_unsupported_check_is_reported_without_contacting_the_gateway(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        unsupported = CheckDefinition(
            check_id="email.dns-prefetch",
            version="1.0.0",
            title="DNS prefetch",
            description="A check the EPT adapter does not implement.",
            channel="email",
            evidence_class="measured",
            threat_models=check.threat_models,
            runner_classes=("self_hosted_macos",),
            adapter_id="ept",
        )
        gateway = FakeGateway()
        result, _, _ = _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=unsupported,
            adapter=gateway.adapter(),
            execution_dir=tmp_path / "0001",
        )
        assert result.status is ResultStatus.UNSUPPORTED
        assert result.reason_code == "ept.unsupported-check"
        assert gateway.requests == []

    def test_a_gateway_failure_becomes_a_retryable_error_result(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        adapter = EptGatewayAdapter(
            client=EptGatewayClient(
                base_url="https://gateway.invalid",
                token="test-token",
                transport=httpx.MockTransport(lambda request: httpx.Response(503)),
            ),
            mailboxes={"slot-0001": MAILBOX},
            open_observer=lambda context: True,
        )
        result, _, manifest = _execute(
            plan=_single_check_plan(local_plan, subject, check),
            subject=subject,
            check=check,
            adapter=adapter,
            execution_dir=tmp_path / "0001",
        )
        assert result.status is ResultStatus.ERROR
        assert result.error is not None
        assert result.error.retryable is True
        assert manifest_exit_code(manifest) == 1

    def test_an_adapter_without_an_open_observer_carries_no_default_pass(
        self,
    ) -> None:
        adapter = FakeGateway().adapter()
        adapter.open_observer = None
        assert adapter.open_observer is None

    def test_the_adapter_declares_the_checks_it_can_answer(self) -> None:
        adapter = FakeGateway().adapter()
        assert adapter.adapter_id == "ept"
        assert adapter.supported_checks == {"email.remote-content"}

    def test_every_observation_channel_is_a_real_upstream_mechanism(self) -> None:
        # Upstream ships two watchers plus the canary web server. There is no TCP
        # watcher: the preconnect vector is observed through SNI.
        assert set(ObservationChannel) == {"http", "dns", "tls_sni"}
        assert ObservationOrigin.CLIENT.value == "client"
