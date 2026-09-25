"""HTTP client and adapter for a private Email Privacy Tester gateway.

The benchmark does not call undocumented EPT routes, read its database, or scrape its
UI. A small private gateway exposes the versioned contract modelled here and translates
to the pinned upstream service, so the harness depends on an API boundary the project
controls rather than on EPT internals.

Adjudication is the delicate part, and two upstream facts drive its whole shape. Both
are verified against the pinned source in ``infra/ept/UPSTREAM_FINDINGS.md``.

First, an empty observation set is the signature of two very different worlds: a client
that blocked every remote fetch, and a measurement that never exercised the client at
all. So an absence is only allowed to mean anything once the open has been asserted by
the harness and the watchers are known healthy.

Second, an observation is not automatically evidence against the client. EPT's own
documentation warns that provider spam filters prefetch the canary URLs, and those
lookups are recorded identically to a client-initiated fetch. Scoring them as a client
leak would publish a false ``fail`` about the provider, so every observation carries an
origin and only a client-attributed one is scored.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

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
    """The three mechanisms that can actually observe a canary contact upstream.

    EPT ships two watcher processes plus the canary web server. There is no standalone
    TCP watcher: the ``linkPreconnect`` vector is typed ``tcp`` upstream but is observed
    only by the SNI watcher, so preconnect arrives here as :attr:`TLS_SNI`.
    """

    HTTP = "http"
    DNS = "dns"
    TLS_SNI = "tls_sni"


#: Every channel upstream can produce. A contact on any of them is a canary disclosure;
#: what decides whether it indicts the *client* is the observation's origin.
OBSERVATION_CHANNELS = frozenset(ObservationChannel)


class ObservationOrigin(StrEnum):
    """Who initiated a canary contact.

    This distinction is the difference between a finding about a mail client and a
    finding about a mail provider. Upstream cannot make it: a provider spam filter
    prefetching the canary is recorded exactly like a client rendering the message, and
    EPT's own ``dnsAnchor`` text warns that provider resolvers appear "instead of" the
    recipient's address.
    """

    CLIENT = "client"
    PROVIDER = "provider"
    UNKNOWN = "unknown"


#: Origins that can indict the client under test. Anything else is recorded as evidence
#: but never scored as a client disclosure.
CLIENT_ATTRIBUTABLE_ORIGINS = frozenset({ObservationOrigin.CLIENT})


class _GatewayModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GatewayTestCreated(_GatewayModel):
    test_id: Identifier
    probe_id: Identifier
    expires_at: UtcDateTime


class GatewayObservation(_GatewayModel):
    """One canary contact reported by a watcher.

    ``vector`` carries the upstream EPT test name (``img``, ``dnsAnchor``,
    ``linkPreconnect``, …) because a benchmark row is about a specific vector, not a
    channel. ``origin`` is the gateway's attribution of who initiated the contact.
    """

    channel: ObservationChannel
    probe_id: Identifier
    vector: str = Field(min_length=1, max_length=64)
    origin: ObservationOrigin = ObservationOrigin.UNKNOWN
    remote_host: str = Field(min_length=1, max_length=253)
    observed_at: UtcDateTime
    resource: str | None = Field(default=None, max_length=2048)
    detail: dict[str, JsonValue] = Field(default_factory=dict)


class GatewayObservations(_GatewayModel):
    test_id: Identifier
    observations: tuple[GatewayObservation, ...] = ()


class GatewayTestState(_GatewayModel):
    """What the gateway knows about the probe window for one test.

    Deliberately absent: an open signal. Upstream EPT has none. ``Tests.accessed`` is set
    when the test mail is *sent* and again on the first callback, so it is not an
    inbox-delivery or recipient-open confirmation. The open is an interaction the
    harness performs by driving the client, so it is asserted by the caller instead.

    ``delivered_at`` is a *gateway* capability rather than an upstream one: it is
    available only because a self-hosted deployment controls its own SMTP path.
    ``watchers_healthy`` covers every watcher being down, which would otherwise look
    exactly like a clean result.

    ``exercised`` names the upstream vectors this test actually ran. It is the only way
    to tell "the client resolved nothing" from "the test never offered the client
    anything to resolve". A check that depends on a vector absent from this list has not
    been measured, and must not be adjudicated as if it had.
    """

    test_id: Identifier
    probe_id: Identifier
    delivered_at: UtcDateTime | None = None
    watchers_healthy: bool = False
    window_expires_at: UtcDateTime
    exercised: tuple[str, ...] = ()


#: Upstream vectors each check needs the gateway to have actually run, for checks whose
#: validity cannot be established by delivery, open, and watcher health alone.
#:
#: ``email.remote-content`` is deliberately absent: it already has enough to separate a
#: blocked client from an unexercised probe, so requiring a vector name would make it
#: inconclusive against a gateway that has not yet reported them.
#:
#: The names are the upstream EPT test names, which is why this table exists rather than
#: a channel-level requirement: upstream watchers are label-restricted, so "a DNS watcher
#: was up" does not mean "this vector's label was watched".
REQUIRED_EXERCISED: Mapping[str, frozenset[str]] = {
    "email.dns-prefetch": frozenset({"dnsAnchor"}),
    "email.reader-identification": frozenset({"img"}),
}


class Adjudication(StrEnum):
    """Why the adapter reached the status it did."""

    REMOTE_CONTENT_DETECTED = "ept.remote-content-detected"
    NO_REMOTE_CONTENT_OBSERVED = "ept.no-remote-content-observed"
    MESSAGE_NOT_DELIVERED = "ept.message-not-delivered"
    OPEN_NOT_ASSERTED = "ept.open-not-asserted"
    WATCHERS_UNHEALTHY = "ept.watchers-unhealthy"
    PROVIDER_PREFETCH_ONLY = "ept.provider-prefetch-only"
    UNATTRIBUTED_ACTIVITY = "ept.unattributed-activity"
    VECTOR_NOT_EXERCISED = "ept.vector-not-exercised"
    RESOLVER_DISCLOSED = "ept.resolver-disclosed"
    NO_RESOLUTION_OBSERVED = "ept.no-resolution-observed"
    READER_IDENTIFIED = "ept.reader-identified"
    UNSUPPORTED_CHECK = "ept.unsupported-check"


class OpenObserver(Protocol):
    """Asserts that the harness actually opened the message in the client.

    Upstream EPT has no open signal, so this is the only thing standing between an
    unexercised probe and a reported ``pass``. An adapter constructed without one always
    reports ``inconclusive``.
    """

    def __call__(self, context: ExecutionContext) -> bool: ...


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
    open_asserted: bool,
) -> tuple[ResultStatus, Adjudication, str]:
    """Decide a result from gateway state, observations, and the asserted open.

    Measurement validity is settled before the observation set is interpreted, so a
    broken probe can never be reported as clean client behaviour. Attribution is settled
    next, so provider prefetch can never be reported as a client disclosure.
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
    if not open_asserted:
        # Upstream cannot report an open, so the harness must. Without this the result
        # would be a claim about a message nobody was shown.
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.OPEN_NOT_ASSERTED,
            "The message was delivered but no open was asserted by the harness, so "
            "remote-content behavior was never exercised.",
        )

    foreign = [item for item in observations if item.probe_id != state.probe_id]
    if foreign:
        raise AdapterError(f"gateway returned {len(foreign)} observations for another probe id")

    client = [item for item in observations if item.origin in CLIENT_ATTRIBUTABLE_ORIGINS]
    if client:
        vectors = sorted({item.vector for item in client})
        channels = sorted({item.channel.value for item in client})
        return (
            ResultStatus.FAIL,
            Adjudication.REMOTE_CONTENT_DETECTED,
            f"After the message was opened the client itself contacted the canary on "
            f"{', '.join(channels)} for {', '.join(vectors)}, disclosing the open.",
        )

    provider = [item for item in observations if item.origin is ObservationOrigin.PROVIDER]
    if provider and len(provider) == len(observations):
        vectors = sorted({item.vector for item in provider})
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.PROVIDER_PREFETCH_ONLY,
            f"Only provider infrastructure contacted the canary, for {', '.join(vectors)}. "
            "That is a provider behavior and says nothing about the client's own fetching, "
            "so no client result is claimed.",
        )
    if observations:
        # Something contacted the canary and it could not be pinned to the client. That
        # is not evidence the client is clean, so it must not be reported as a pass.
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.UNATTRIBUTED_ACTIVITY,
            "Canary contacts were observed but none could be attributed to the client, so "
            "no client result is claimed.",
        )
    return (
        ResultStatus.PASS,
        Adjudication.NO_REMOTE_CONTENT_OBSERVED,
        "The message was opened with every watcher healthy, and the client made no canary "
        "contact of any kind.",
    )


def _client_observations(
    observations: tuple[GatewayObservation, ...],
) -> list[GatewayObservation]:
    return [item for item in observations if item.origin in CLIENT_ATTRIBUTABLE_ORIGINS]


def adjudicate_dns_prefetch(
    *,
    state: GatewayTestState,
    observations: tuple[GatewayObservation, ...],
    open_asserted: bool,
) -> tuple[ResultStatus, Adjudication, str]:
    """Decide ``email.dns-prefetch``.

    Here the *resolution* is the finding rather than a preliminary to one. A name that
    resolves and is never fetched still hands the canary operator the reader's resolver
    address, which identifies an internet provider and roughly a location, so DNS and
    SNI contacts are decisive in their own right. Folding them into the remote-content
    result would lose the difference between the two adversaries, which is the entire
    reason this check exists separately.
    """

    validity = _settle_validity(state=state, open_asserted=open_asserted)
    if validity is not None:
        return validity

    foreign = [item for item in observations if item.probe_id != state.probe_id]
    if foreign:
        raise AdapterError(f"gateway returned {len(foreign)} observations for another probe id")

    client = _client_observations(observations)
    resolved = [item for item in client if item.channel in RESOLUTION_CHANNELS]
    if resolved:
        channels = sorted({item.channel.value for item in resolved})
        vectors = sorted({item.vector for item in resolved})
        return (
            ResultStatus.FAIL,
            Adjudication.RESOLVER_DISCLOSED,
            f"The client resolved the canary name on {', '.join(channels)} for "
            f"{', '.join(vectors)} without being asked, disclosing the reader's resolver "
            f"to whoever operates the canary.",
        )

    provider = [item for item in observations if item.origin is ObservationOrigin.PROVIDER]
    if provider and len(provider) == len(observations):
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.PROVIDER_PREFETCH_ONLY,
            "Only provider infrastructure resolved the canary name. That discloses the "
            "provider's resolver, not the reader's, so no client result is claimed.",
        )
    if observations:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.UNATTRIBUTED_ACTIVITY,
            "Canary resolutions were observed but none could be attributed to the client, "
            "so no client result is claimed.",
        )
    return (
        ResultStatus.PASS,
        Adjudication.NO_RESOLUTION_OBSERVED,
        "The message was opened with every watcher healthy, and the client did not resolve "
        "the canary name on any channel.",
    )


#: What the canary can attribute a single contact to. Absent keys mean the gateway did
#: not report that field, which is never treated as "not disclosed".
READER_FIELDS = ("source_address", "user_agent")


def adjudicate_reader_identification(
    *,
    state: GatewayTestState,
    observations: tuple[GatewayObservation, ...],
    open_asserted: bool,
) -> tuple[ResultStatus, Adjudication, str]:
    """Decide ``email.reader-identification``.

    This is a question about what one contact reveals rather than whether a contact
    happened, so it is deliberately separate from ``email.remote-content``: a client can
    block every fetch and still hand the canary a source address and a user agent
    through anything that fetches on the user's behalf.

    The verdict is only about *client-attributed* contacts. A provider-side prefetch
    discloses the provider's infrastructure, and reporting that as a reader disclosure
    would be a false finding about the product.
    """

    validity = _settle_validity(state=state, open_asserted=open_asserted)
    if validity is not None:
        return validity

    foreign = [item for item in observations if item.probe_id != state.probe_id]
    if foreign:
        raise AdapterError(f"gateway returned {len(foreign)} observations for another probe id")

    client = _client_observations(observations)
    if not client:
        return (
            ResultStatus.PASS,
            Adjudication.NO_REMOTE_CONTENT_OBSERVED,
            "The client made no canary contact, so the canary learned nothing about the "
            "reader from this test.",
        )

    disclosed = sorted(
        {
            field
            for item in client
            for field in READER_FIELDS
            if item.detail.get(field) not in (None, "")
        }
    )
    if disclosed:
        return (
            ResultStatus.FAIL,
            Adjudication.READER_IDENTIFIED,
            f"A client-attributed canary contact carried {', '.join(disclosed)}, so the "
            f"canary can single out the reader among other addresses.",
        )
    return (
        ResultStatus.PARTIAL,
        Adjudication.UNATTRIBUTED_ACTIVITY,
        "The client contacted the canary but the gateway reported no reader-identifying "
        "field, so what was disclosed cannot be stated. That is not a clean result.",
    )


def _settle_validity(
    *, state: GatewayTestState, open_asserted: bool
) -> tuple[ResultStatus, Adjudication, str] | None:
    """Return an invalid-measurement verdict, or ``None`` when the probe is sound.

    Shared so every per-check adjudication refuses a broken probe identically, rather
    than each one re-deriving the same three guards and eventually disagreeing about one.
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
    if not open_asserted:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.OPEN_NOT_ASSERTED,
            "The message was delivered but no open was asserted by the harness, so "
            "remote-content behavior was never exercised.",
        )
    return None


#: Channels on which a name being resolved is itself the disclosure.
RESOLUTION_CHANNELS = frozenset({ObservationChannel.DNS, ObservationChannel.TLS_SNI})


def _missing_vectors(check_id: str, state: GatewayTestState) -> set[str]:
    """Vectors this check needs that the gateway did not report running."""

    required = REQUIRED_EXERCISED.get(check_id)
    if required is None:
        return set()
    return set(required) - set(state.exercised)


def _adjudicate_check(
    *,
    check_id: str,
    state: GatewayTestState,
    observations: tuple[GatewayObservation, ...],
    open_asserted: bool,
) -> tuple[ResultStatus, Adjudication, str]:
    """Route a check to the adjudication written for its own disclosure."""

    if check_id == "email.dns-prefetch":
        return adjudicate_dns_prefetch(
            state=state, observations=observations, open_asserted=open_asserted
        )
    if check_id == "email.reader-identification":
        return adjudicate_reader_identification(
            state=state, observations=observations, open_asserted=open_asserted
        )
    return adjudicate(state=state, observations=observations, open_asserted=open_asserted)


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
    #: Deliberately left unset by every production caller. Upstream EPT has no open
    #: signal, so no honest observer can be supplied; with none, ``execute_check``
    #: adjudicates with ``open_asserted=False`` and every result is ``inconclusive``.
    #: That is the intended fail-closed behaviour, not an unfinished wiring gap: a
    #: ``pass`` here would be a claim about a message nobody was ever shown. Supply an
    #: observer only once a real open signal exists, never to unblock a run.
    open_observer: OpenObserver | None = None
    supported_checks: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "email.remote-content",
                "email.dns-prefetch",
                "email.reader-identification",
            }
        )
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
        open_asserted = self.open_observer is not None and self.open_observer(context)

        missing = _missing_vectors(check.check_id, state)
        if missing:
            # The test never ran the vector this check measures. Adjudicating the empty
            # observation set here would report a clean client for a probe that offered
            # the client nothing to do.
            return AdapterOutcome(
                status=ResultStatus.INCONCLUSIVE,
                reason_code=Adjudication.VECTOR_NOT_EXERCISED.value,
                summary=(
                    f"The gateway did not report {', '.join(sorted(missing))} as exercised for "
                    f"this test, so {check.check_id} was not measured."
                ),
                details={
                    "check_id": check.check_id,
                    "exercised": ",".join(sorted(state.exercised)),
                    "missing_vectors": ",".join(sorted(missing)),
                },
            )

        status, reason_code, summary = _adjudicate_check(
            check_id=check.check_id,
            state=state,
            observations=observations,
            open_asserted=open_asserted,
        )
        return AdapterOutcome(
            status=status,
            reason_code=reason_code.value,
            summary=summary,
            details={
                "check_id": check.check_id,
                "probe_id": created.probe_id,
                "test_id": created.test_id,
                "observation_count": len(observations),
                "client_observation_count": sum(
                    1 for item in observations if item.origin in CLIENT_ATTRIBUTABLE_ORIGINS
                ),
                "provider_observation_count": sum(
                    1 for item in observations if item.origin is ObservationOrigin.PROVIDER
                ),
                "unattributed_observation_count": sum(
                    1 for item in observations if item.origin is ObservationOrigin.UNKNOWN
                ),
                "vectors": ",".join(sorted({item.vector for item in observations})),
                "delivered": state.delivered_at is not None,
                "open_asserted": open_asserted,
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
                    open_asserted=open_asserted,
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
            if payload.observations or (state.delivered_at is not None and state.watchers_healthy):
                return payload.observations
            if utc_now() >= deadline:
                return payload.observations
            await asyncio.sleep(self.poll_interval_seconds)
            refreshed = self.client.get_state(test_id)
            if (
                refreshed.delivered_at != state.delivered_at
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
        open_asserted: bool,
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
                    "open_asserted": open_asserted,
                    "watchers_healthy": state.watchers_healthy,
                    "window_expires_at": _iso(state.window_expires_at),
                },
                "observations": [
                    {
                        "channel": item.channel.value,
                        "vector": item.vector,
                        "origin": item.origin.value,
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
                "open_asserted": open_asserted,
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
