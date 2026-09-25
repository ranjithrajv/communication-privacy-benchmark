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
    #: The ``Referer`` header exactly as observed, or ``None`` when the request carried
    #: none. A ``None`` here means nothing on its own: only the parent test's
    #: ``referer_captured`` separates "the client sent no Referer" from "this gateway
    #: never looked", and the adjudication refuses to pass without it.
    #:
    #: A declared field rather than a key smuggled through ``detail``, which is an open
    #: map where a key spelled differently is absent rather than wrong, and this is a
    #: load-bearing input. ``extra="forbid"`` means a gateway sending this to an adapter
    #: that does not declare it fails loudly instead of being quietly ignored.
    referrer: str | None = Field(default=None, max_length=2048)
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
    #: Whether this deployment captured the ``Referer`` header on canary contacts.
    #: Declared by the gateway rather than inferred from the observations, because a
    #: gateway that does not capture it produces exactly the same observation set as a
    #: client that leaks nothing, and that difference is the whole measurement. Upstream
    #: cannot supply this at all, so ``False`` is the honest default for every deployment
    #: not changed on purpose, and it is what makes an unpatched gateway report
    #: ``inconclusive`` instead of a clean client.
    referer_captured: bool = False
    #: Hosts this test also exposes as canaries, beyond the tracking host itself. A
    #: ``Referer`` observed on one of these is leakage to a party the reader did not
    #: choose to visit, which is the threat this check exists for; one observed on the
    #: tracking host only discloses the mailbox origin to the canary operator. Both are
    #: real, and collapsing them would misname who learned what.
    third_party_hosts: tuple[str, ...] = ()


#: Upstream vectors each check needs the gateway to have actually run, for checks whose
#: validity cannot be established by delivery, open, and watcher health alone.
#:
#: ``email.remote-content`` is deliberately absent: it already has enough to separate a
#: blocked client from an unexercised probe, so requiring a vector name would make it
#: inconclusive against a gateway that has not yet reported them.
#:
#: The names are the upstream EPT test names, which is why this table exists rather than
#: Upstream vector names, read from ``backend/lib/tests.js`` at ept3 ``c80c093``. These
#: are the exported function names, not the human-facing ``name`` labels, and they are
#: the identifier a gateway reports in ``GatewayObservation.vector``. A wrong name here
#: does not fail loudly: the vector simply never appears in ``state.exercised`` and the
#: check reports ``inconclusive`` forever, so these are pinned rather than derived.
MIME_PART_VECTORS: frozenset[str] = frozenset(
    {
        "calendarAttach",
        "calendarHtml",
        "calendarImage",
        "calendarStyledDescription",
        "messageGlobalImg",
        "rfc822Img",
        "svgBackgroundImg",
        "svgFilterFeImage",
        "svgInlineImage",
        "svgScriptHref",
        "svgUse",
        "svgXxe",
        "vcardPhoto",
    }
)
LIST_UNSUBSCRIBE_VECTORS: frozenset[str] = frozenset({"listUnsubscribe"})
#: Vectors that ask the client to fetch a resource it was not asked to render. Upstream
#: ``dnsImg`` is deliberately absent: its ``img-test`` label is not matched by the DNS
#: watcher's anchor/link regex, so a client that prefetches it would be recorded clean.
BACKGROUND_VECTORS: frozenset[str] = frozenset(
    {
        "background",
        "backgroundImage",
        "borderImage",
        "listStyleImage",
        "svgBackgroundImg",
        "tableBackground",
    }
)

#: a channel-level requirement: upstream watchers are label-restricted, so "a DNS watcher
#: was up" does not mean "this vector's label was watched".
REQUIRED_EXERCISED: Mapping[str, frozenset[str]] = {
    "email.dns-prefetch": frozenset({"dnsAnchor"}),
    "email.reader-identification": frozenset({"img"}),
    "email.mime-remote-part": frozenset(MIME_PART_VECTORS),
    "email.list-unsubscribe-fetch": frozenset(LIST_UNSUBSCRIBE_VECTORS),
    "email.background-fetch": frozenset(BACKGROUND_VECTORS),
    # A Referer can only be observed on a request the client actually made, so this
    # needs a vector the client was offered and ran. `img` is the plainest body vector
    # and is the one `email.remote-content` already uses, so one canary run informs both
    # checks instead of requiring a second probe window.
    "email.referrer-disclosure": frozenset({"img"}),
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
    MIME_PART_DISCLOSED = "ept.mime-part-disclosed"
    NO_MIME_PART_CONTENT_OBSERVED = "ept.no-mime-part-content-observed"
    LIST_UNSUBSCRIBE_DISCLOSED = "ept.list-unsubscribe-disclosed"
    NO_LIST_UNSUBSCRIBE_FETCH_OBSERVED = "ept.no-list-unsubscribe-fetch-observed"
    BACKGROUND_FETCH_DISCLOSED = "ept.background-fetch-disclosed"
    NO_BACKGROUND_FETCH_OBSERVED = "ept.no-background-fetch-observed"
    THIRD_PARTY_REFERRER_DISCLOSED = "ept.third-party-referrer-disclosed"
    REFERRER_DISCLOSED = "ept.referrer-disclosed"
    NO_REFERRER_OBSERVED = "ept.no-referrer-observed"
    REFERER_NOT_CAPTURED = "ept.referrer-not-captured"
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


def _attributed_client_activity(
    *, check_id: str, observations: tuple[GatewayObservation, ...], state: GatewayTestState
) -> list[GatewayObservation]:
    """Client-attributable contacts, rejecting a foreign probe id first.

    A gateway that mixed another test's observations into this one would silently
    manufacture a disclosure for the wrong message, so the probe id is checked before
    any activity is counted.
    """

    foreign = [item for item in observations if item.probe_id != state.probe_id]
    if foreign:
        raise AdapterError(f"gateway returned {len(foreign)} observations for another probe id")
    return _client_observations(observations)


def adjudicate_mime_remote_part(
    *,
    state: GatewayTestState,
    observations: tuple[GatewayObservation, ...],
    open_asserted: bool,
) -> tuple[ResultStatus, Adjudication, str]:
    """Decide ``email.mime-remote-part``.

    Remote references outside the top-level HTML body are a separate disclosure from body
    remote content: a client that blocks body images while rendering a calendar invite or
    an SVG still tells the canary the message was opened. Upstream types every one of
    these vectors ``http``, so a provider-side fetch is indistinguishable here and is
    reported as unattributed rather than scored as a client behaviour.
    """

    validity = _settle_validity(state=state, open_asserted=open_asserted)
    if validity is not None:
        return validity

    client = _attributed_client_activity(
        check_id="email.mime-remote-part", observations=observations, state=state
    )
    hits = sorted({item.vector for item in client if item.vector in MIME_PART_VECTORS})
    if hits:
        return (
            ResultStatus.FAIL,
            Adjudication.MIME_PART_DISCLOSED,
            f"The client fetched remote references from non-body MIME parts "
            f"({', '.join(hits)}), so a client that suppresses body images can still be "
            f"disclosed by a calendar, vCard, SVG, or nested message part.",
        )
    if observations:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.UNATTRIBUTED_ACTIVITY,
            "Non-body canary activity was observed but none could be attributed to the "
            "client, so no client result is claimed.",
        )
    return (
        ResultStatus.PASS,
        Adjudication.NO_MIME_PART_CONTENT_OBSERVED,
        "The message was opened with every watcher healthy, and the client fetched no "
        "remote reference from a calendar, vCard, SVG, or nested message part.",
    )


def adjudicate_list_unsubscribe_fetch(
    *,
    state: GatewayTestState,
    observations: tuple[GatewayObservation, ...],
    open_asserted: bool,
) -> tuple[ResultStatus, Adjudication, str]:
    """Decide ``email.list-unsubscribe-fetch``.

    A ``List-Unsubscribe`` URL is a fetch request authored by the *provider*, not by the
    reader, so a client that honours it automatically discloses that a synthetic message
    reached a mailbox and was processed, with no reader interaction at all.
    """

    validity = _settle_validity(state=state, open_asserted=open_asserted)
    if validity is not None:
        return validity

    client = _attributed_client_activity(
        check_id="email.list-unsubscribe-fetch", observations=observations, state=state
    )
    if [item for item in client if item.vector in LIST_UNSUBSCRIBE_VECTORS]:
        return (
            ResultStatus.FAIL,
            Adjudication.LIST_UNSUBSCRIBE_DISCLOSED,
            "The client fetched the URL supplied in the List-Unsubscribe header without "
            "any reader interaction, disclosing that the message reached a mailbox and "
            "was processed by the client.",
        )
    if observations:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.UNATTRIBUTED_ACTIVITY,
            "Canary activity was observed but none could be attributed to the client, so "
            "no client result is claimed.",
        )
    return (
        ResultStatus.PASS,
        Adjudication.NO_LIST_UNSUBSCRIBE_FETCH_OBSERVED,
        "The message was opened with every watcher healthy, and the client did not fetch "
        "the List-Unsubscribe URL.",
    )


def adjudicate_background_fetch(
    *,
    state: GatewayTestState,
    observations: tuple[GatewayObservation, ...],
    open_asserted: bool,
) -> tuple[ResultStatus, Adjudication, str]:
    """Decide ``email.background-fetch``.

    The absence of an open is the measurement here, not a missing precondition, so the
    shared open guard is deliberately not applied: every other check treats an unopened
    message as unexercised, and applying that rule would make this check report
    ``inconclusive`` for exactly the run it exists to catch. Delivery and watcher health
    are still required, because a contact from an undelivered or unwatched run proves
    nothing.
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

    client = _attributed_client_activity(
        check_id="email.background-fetch", observations=observations, state=state
    )
    if client and not open_asserted:
        vectors = sorted({item.vector for item in client})
        return (
            ResultStatus.FAIL,
            Adjudication.BACKGROUND_FETCH_DISCLOSED,
            f"The client contacted the canary for {', '.join(vectors)} without the message "
            f"ever being opened, so the contact cannot be attributed to a reader action.",
        )
    if client:
        return (
            ResultStatus.PASS,
            Adjudication.NO_BACKGROUND_FETCH_OBSERVED,
            "The canary was contacted only after the message was opened, so no prefetch "
            "before the reader acted is claimed.",
        )
    return (
        ResultStatus.PASS,
        Adjudication.NO_BACKGROUND_FETCH_OBSERVED,
        "The message was delivered with every watcher healthy, and the client made no "
        "canary contact before the message was opened.",
    )


def adjudicate_referrer_disclosure(
    *,
    state: GatewayTestState,
    observations: tuple[GatewayObservation, ...],
    open_asserted: bool,
) -> tuple[ResultStatus, Adjudication, str]:
    """Decide ``email.referrer-disclosure``.

    Two things separate this from every other check that reads the same observations.
    First, a missing ``Referer`` is evidence only if the gateway said it looked: an
    unpatched gateway returns byte-identical observations for a client that leaks a
    mailbox origin and one that leaks nothing, so the capability declaration is consulted
    before any clean verdict is reachable. Second, a ``Referer`` reaching the tracking host
    and one reaching some other host are disclosures to different parties, so the host
    decides which is reported rather than either being called "leakage".

    A clean result is ``partial`` whenever the gateway ran no third-party canary. The
    declared threat is a host the reader did not choose to visit, and a run that watched
    only the tracking host never exercised it, so reporting ``pass`` would claim coverage
    that was not measured.
    """

    validity = _settle_validity(state=state, open_asserted=open_asserted)
    if validity is not None:
        return validity

    if not state.referer_captured:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.REFERER_NOT_CAPTURED,
            "The gateway did not declare that it captured the Referer header, so its "
            "absence cannot be told apart from a gateway that never looked. No client "
            "result is claimed.",
        )

    client = _attributed_client_activity(
        check_id="email.referrer-disclosure", observations=observations, state=state
    )
    third_party = frozenset(state.third_party_hosts)
    leaks = [item for item in client if item.referrer]
    foreign = [item for item in leaks if item.remote_host in third_party]
    if foreign:
        hosts = sorted({item.remote_host for item in foreign})
        return (
            ResultStatus.FAIL,
            Adjudication.THIRD_PARTY_REFERRER_DISCLOSED,
            f"The client sent a Referer header to {', '.join(hosts)}, a host outside the "
            f"message, disclosing the reader's mailbox origin to a party they did not "
            f"choose to visit.",
        )
    if leaks:
        hosts = sorted({item.remote_host for item in leaks})
        return (
            ResultStatus.FAIL,
            Adjudication.REFERRER_DISCLOSED,
            f"The client sent a Referer header to its own canary at {', '.join(hosts)}, "
            f"disclosing the mailbox origin to the canary operator.",
        )
    if observations and not client:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.UNATTRIBUTED_ACTIVITY,
            "Canary activity carried Referer headers, but none could be attributed to the "
            "client, so no client result is claimed.",
        )
    if not third_party:
        return (
            ResultStatus.PARTIAL,
            Adjudication.NO_REFERRER_OBSERVED,
            "The gateway captured the Referer header and the client sent none on any canary "
            "contact, but the test ran no third-party canary host, so leakage to a host the "
            "reader did not choose to visit was not exercised.",
        )
    return (
        ResultStatus.PASS,
        Adjudication.NO_REFERRER_OBSERVED,
        "The gateway captured the Referer header and the client sent none on any canary "
        "contact, including third-party hosts outside the message.",
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
    if check_id == "email.mime-remote-part":
        return adjudicate_mime_remote_part(
            state=state, observations=observations, open_asserted=open_asserted
        )
    if check_id == "email.list-unsubscribe-fetch":
        return adjudicate_list_unsubscribe_fetch(
            state=state, observations=observations, open_asserted=open_asserted
        )
    if check_id == "email.background-fetch":
        return adjudicate_background_fetch(
            state=state, observations=observations, open_asserted=open_asserted
        )
    if check_id == "email.referrer-disclosure":
        return adjudicate_referrer_disclosure(
            state=state, observations=observations, open_asserted=open_asserted
        )
    return adjudicate(state=state, observations=observations, open_asserted=open_asserted)


async def await_observations(
    *,
    client: EptGatewayClient,
    test_id: str,
    state: GatewayTestState,
    timeout_seconds: int,
    poll_interval_seconds: float,
) -> tuple[GatewayObservation, ...]:
    """Poll the gateway until the window closes, the probe settled, or time runs out.

    Module-level so the webmail adapter drives the same window as the desktop clients
    rather than keeping a second copy of the polling that decides when a measurement
    stops. Two copies would eventually disagree about when an empty observation set is
    the answer, and only one of them would be right.
    """

    deadline = min(state.window_expires_at, utc_now() + timedelta(seconds=timeout_seconds))
    while True:
        payload = client.get_observations(test_id)
        if payload.observations or (state.delivered_at is not None and state.watchers_healthy):
            return payload.observations
        if utc_now() >= deadline:
            return payload.observations
        await asyncio.sleep(poll_interval_seconds)
        refreshed = client.get_state(test_id)
        if (
            refreshed.delivered_at != state.delivered_at
            or refreshed.watchers_healthy != state.watchers_healthy
        ):
            state = refreshed


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
                "email.mime-remote-part",
                "email.list-unsubscribe-fetch",
                "email.background-fetch",
                "email.referrer-disclosure",
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

        return await await_observations(
            client=self.client,
            test_id=test_id,
            state=state,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=self.poll_interval_seconds,
        )

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
