"""HTTP client and adapter for a private Email Privacy Tester gateway.

The benchmark does not call undocumented EPT routes, read its database, or scrape its
UI. A small private gateway exposes the versioned contract modelled here and translates
to the pinned upstream service, so the harness depends on an API boundary the project
controls rather than on EPT internals.

Adjudication is the delicate part. An empty observation set is the signature of two
very different worlds: a client that blocked every remote fetch, and a message that was
never delivered or never opened. Reporting the first as a ``pass`` would manufacture a
privacy finding out of a broken measurement, so the gateway must positively confirm
delivery, an open signal, and watcher health before an absence is allowed to mean
anything. Anything short of that is ``inconclusive``.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import httpx
from pydantic import BaseModel, ConfigDict, Field, JsonValue

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
    Identifier,
    RedactionPolicy,
    ResultStatus,
    UtcDateTime,
    utc_now,
)
from privacy_benchmark.spec.serialization import json_bytes

#: Environment variables carrying the private gateway address and its token. Both are
#: supplied at run time from a secret store; neither is ever written to a definition.
GATEWAY_URL_VARIABLE = "PT_BENCH_EPT_GATEWAY_URL"
GATEWAY_TOKEN_VARIABLE = "PT_BENCH_EPT_GATEWAY_TOKEN"
#: A JSON object mapping account slot ids to synthetic mailbox addresses.
MAILBOXES_VARIABLE = "PT_BENCH_EPT_MAILBOXES"


class ObservationChannel(StrEnum):
    """A watcher that can observe a client contacting a canary host."""

    HTTP = "http"
    DNS = "dns"
    TLS_SNI = "tls_sni"
    TCP = "tcp"
    MIME = "mime"


#: Observation channels that constitute a remote fetch by the mail client. EPT watches
#: DNS, TLS SNI, and TCP independently of HTTP because a client can leak the fact that
#: a message was opened without ever completing an HTTP request.
REMOTE_FETCH_CHANNELS = frozenset(
    {
        ObservationChannel.HTTP,
        ObservationChannel.DNS,
        ObservationChannel.TLS_SNI,
        ObservationChannel.TCP,
    }
)


class _GatewayModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GatewayTestCreated(_GatewayModel):
    test_id: Identifier
    probe_id: Identifier
    expires_at: UtcDateTime


class GatewayObservation(_GatewayModel):
    """One canary contact reported by a watcher."""

    channel: ObservationChannel
    probe_id: Identifier
    remote_host: str = Field(min_length=1, max_length=253)
    observed_at: UtcDateTime
    resource: str | None = Field(default=None, max_length=2048)
    detail: dict[str, JsonValue] = Field(default_factory=dict)


class GatewayObservations(_GatewayModel):
    test_id: Identifier
    observations: tuple[GatewayObservation, ...] = ()


class GatewayTestState(_GatewayModel):
    """What the gateway knows about the probe window for one test.

    ``delivered_at`` and ``opened_at`` are what separate a client that suppressed
    remote content from a message that never arrived or was never read.
    ``watchers_healthy`` covers the case where every watcher was down, which would
    otherwise look exactly like a clean result.
    """

    test_id: Identifier
    probe_id: Identifier
    delivered_at: UtcDateTime | None = None
    opened_at: UtcDateTime | None = None
    watchers_healthy: bool = False
    window_expires_at: UtcDateTime


class Adjudication(StrEnum):
    """Why the adapter reached the status it did."""

    REMOTE_CONTENT_DETECTED = "ept.remote-content-detected"
    NO_REMOTE_CONTENT_OBSERVED = "ept.no-remote-content-observed"
    MESSAGE_NOT_DELIVERED = "ept.message-not-delivered"
    MESSAGE_NOT_OPENED = "ept.message-not-opened"
    WATCHERS_UNHEALTHY = "ept.watchers-unhealthy"
    UNSUPPORTED_CHECK = "ept.unsupported-check"


class EptGatewayClient:
    """A thin client for the private gateway's versioned contract."""

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout_seconds: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url
        self.token = token
        self.timeout_seconds = timeout_seconds
        self.transport = transport

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=self.timeout_seconds,
            follow_redirects=False,
            transport=self.transport,
        )

    def create_test(self, *, email: str, language: str = "en") -> GatewayTestCreated:
        with self._client() as client:
            response = client.post("/v1/tests", json={"email": email, "language": language})
            response.raise_for_status()
            return GatewayTestCreated.model_validate(response.json())

    def get_state(self, test_id: str) -> GatewayTestState:
        with self._client() as client:
            response = client.get(f"/v1/tests/{test_id}/state")
            response.raise_for_status()
            state = GatewayTestState.model_validate(response.json())
        if state.test_id != test_id:
            raise AdapterError("gateway returned state for the wrong test")
        return state

    def get_observations(self, test_id: str) -> GatewayObservations:
        with self._client() as client:
            response = client.get(f"/v1/tests/{test_id}/observations")
            response.raise_for_status()
            payload = GatewayObservations.model_validate(response.json())
        if payload.test_id != test_id:
            raise AdapterError("gateway returned observations for the wrong test")
        return payload


def adjudicate(
    *,
    state: GatewayTestState,
    observations: tuple[GatewayObservation, ...],
) -> tuple[ResultStatus, Adjudication, str]:
    """Decide a result from gateway state and observations.

    The order matters. Measurement validity is settled before the observation set is
    interpreted, so a broken probe can never be reported as clean client behaviour.
    """

    if state.delivered_at is None:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.MESSAGE_NOT_DELIVERED,
            "The gateway never confirmed delivery, so nothing can be attributed to the client.",
        )
    if not state.watchers_healthy:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.WATCHERS_UNHEALTHY,
            "The canary watchers were not healthy, so an absence of traffic proves nothing.",
        )
    if state.opened_at is None:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.MESSAGE_NOT_OPENED,
            "The message was delivered but no open was observed, so remote-content behavior "
            "was never exercised.",
        )

    foreign = [item for item in observations if item.probe_id != state.probe_id]
    if foreign:
        raise AdapterError(f"gateway returned {len(foreign)} observations for another probe id")

    remote = [item for item in observations if item.channel in REMOTE_FETCH_CHANNELS]
    if remote:
        channels = sorted({item.channel.value for item in remote})
        hosts = sorted({item.remote_host for item in remote})
        return (
            ResultStatus.FAIL,
            Adjudication.REMOTE_CONTENT_DETECTED,
            f"After the message was opened the client contacted {len(remote)} canary endpoints "
            f"over {', '.join(channels)}, disclosing the open to {', '.join(hosts)}.",
        )
    return (
        ResultStatus.PASS,
        Adjudication.NO_REMOTE_CONTENT_OBSERVED,
        "The message was opened with every watcher healthy, and the client made no canary "
        "contact of any kind.",
    )


@dataclass(slots=True)
class EptGatewayAdapter:
    """Runs the email checks a pinned EPT deployment can answer.

    Mailbox addresses are supplied per account slot at construction and are never read
    from a checked-in definition, so a real address cannot reach the repository.
    """

    client: EptGatewayClient
    mailboxes: dict[str, str]
    adapter_id: str = "ept"
    version: str = "1.0.0"
    poll_interval_seconds: float = 5.0
    supported_checks: frozenset[str] = field(
        default_factory=lambda: frozenset({"email.remote-content"})
    )
    redaction_policy_id: str = "evidence-retention-v1"
    raw_retention: str = "30-days-then-delete"

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        if check.check_id not in self.supported_checks:
            return AdapterOutcome(
                status=ResultStatus.UNSUPPORTED,
                reason_code=Adjudication.UNSUPPORTED_CHECK.value,
                summary=(
                    f"The EPT adapter cannot answer {check.check_id}. Supported checks: "
                    f"{', '.join(sorted(self.supported_checks))}."
                ),
                details={"supported": False},
            )

        created = self.client.create_test(email=self._mailbox_for(context))
        state = self.client.get_state(created.test_id)
        observations = await self._await_observations(created.test_id, state, check.timeout_seconds)

        status, reason_code, summary = adjudicate(state=state, observations=observations)
        return AdapterOutcome(
            status=status,
            reason_code=reason_code.value,
            summary=summary,
            details={
                "check_id": check.check_id,
                "probe_id": created.probe_id,
                "test_id": created.test_id,
                "observation_count": len(observations),
                "remote_fetch_count": sum(
                    1 for item in observations if item.channel in REMOTE_FETCH_CHANNELS
                ),
                "delivered": state.delivered_at is not None,
                "opened": state.opened_at is not None,
                "watchers_healthy": state.watchers_healthy,
                "account_slot": context.subject.account.slot_id,
                "adapter": "ept",
            },
            evidence=(
                self._evidence(
                    check=check,
                    context=context,
                    created=created,
                    state=state,
                    observations=observations,
                ),
            ),
        )

    def _mailbox_for(self, context: ExecutionContext) -> str:
        slot_id = context.subject.account.slot_id
        try:
            return self.mailboxes[slot_id]
        except KeyError as error:
            raise AdapterError(
                f"no mailbox is configured for account slot {slot_id}; the adapter takes "
                f"slot-to-address mappings supplied at run time via {MAILBOXES_VARIABLE}"
            ) from error

    async def _await_observations(
        self,
        test_id: str,
        state: GatewayTestState,
        timeout_seconds: int,
    ) -> tuple[GatewayObservation, ...]:
        """Poll until the window closes, the open is seen, or the check times out.

        Polling stops early once the message is open and the watchers are healthy,
        because past that point an empty set is already the answer.
        """

        deadline = min(state.window_expires_at, utc_now() + timedelta(seconds=timeout_seconds))
        while True:
            payload = self.client.get_observations(test_id)
            settled = state.delivered_at is not None and state.opened_at is not None
            if payload.observations or (settled and state.watchers_healthy):
                return payload.observations
            if utc_now() >= deadline:
                return payload.observations
            await asyncio.sleep(self.poll_interval_seconds)
            refreshed = self.client.get_state(test_id)
            if (
                refreshed.delivered_at != state.delivered_at
                or refreshed.opened_at != state.opened_at
                or refreshed.watchers_healthy != state.watchers_healthy
            ):
                state = refreshed

    def _evidence(
        self,
        *,
        check: CheckDefinition,
        context: ExecutionContext,
        created: GatewayTestCreated,
        state: GatewayTestState,
        observations: tuple[GatewayObservation, ...],
    ) -> AdapterEvidence:
        evidence_id = ensure_identifier(
            f"{context.execution_id}.{check.check_id}.ept", field_name="evidence_id"
        )
        payload = json_bytes(
            {
                "check_id": check.check_id,
                "check_version": check.version,
                "execution_id": str(context.execution_id),
                "repetition": context.repetition,
                "subject_id": context.subject.subject_id,
                "subject_version": context.subject.subject_version,
                "account_slot": context.subject.account.slot_id,
                "probe_id": created.probe_id,
                "test_id": created.test_id,
                "probe_window": {
                    "delivered_at": _iso(state.delivered_at),
                    "opened_at": _iso(state.opened_at),
                    "watchers_healthy": state.watchers_healthy,
                    "window_expires_at": _iso(state.window_expires_at),
                },
                "observations": [
                    {
                        "channel": item.channel.value,
                        "remote_host": item.remote_host,
                        "observed_at": _iso(item.observed_at),
                        "resource": item.resource,
                    }
                    for item in observations
                ],
                "synthetic": True,
            }
        )
        return AdapterEvidence(
            evidence_id=evidence_id,
            evidence_class=EvidenceClass.MEASURED,
            kind=EvidenceKind.CANARY_EVENT,
            media_type="application/json",
            payload=payload,
            source_uri=f"ept-gateway://privacy-benchmark/{created.probe_id}",
            redaction=RedactionPolicy(
                policy_id=self.redaction_policy_id,
                applied=True,
                raw_retention=self.raw_retention,
                notes=(
                    "The mailbox address is never recorded. Only the account slot, the "
                    "opaque probe id, and canary hostnames are exported."
                ),
            ),
            metadata={
                "probe_id": created.probe_id,
                "observation_count": len(observations),
                "watchers_healthy": state.watchers_healthy,
            },
        )


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat()


def gateway_config_from_environment(
    environ: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    """Return the gateway base URL and token, or ``None`` when unconfigured."""

    values = os.environ if environ is None else environ
    base_url = values.get(GATEWAY_URL_VARIABLE)
    token = values.get(GATEWAY_TOKEN_VARIABLE)
    if not base_url or not token:
        return None
    return base_url, token


def mailbox_config_from_environment(environ: dict[str, str] | None = None) -> dict[str, str]:
    """Parse the runtime slot-to-address mapping from a JSON environment variable."""

    values = os.environ if environ is None else environ
    raw = values.get(MAILBOXES_VARIABLE)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise AdapterError(
            f"{MAILBOXES_VARIABLE} must be a JSON object mapping account slot ids to "
            "synthetic mailbox addresses"
        ) from error
    if not isinstance(parsed, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in parsed.items()
    ):
        raise AdapterError(
            f"{MAILBOXES_VARIABLE} must be a JSON object of string keys and string values"
        )
    return dict(parsed)
