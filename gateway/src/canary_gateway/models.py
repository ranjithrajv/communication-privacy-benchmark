"""The gateway's own view of its wire contract.

Written from the contract in ``infra/ept/README.md``, not from the adapter's client models,
so that a drift between the two is a *test failure* rather than a silent agreement. The
adapter and this service are separate distributions on purpose; if they shared models they
could not disagree, and a disagreement is exactly the bug class that produces a clean
result for a client that was never measured.

Every model here is closed (``extra="forbid"``) for the same reason the adapter's gateway
models are: a field sent under a name this service does not declare must fail loudly
instead of being ignored, because on this side an ignored field is a measurement that
silently did not happen.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, JsonValue

ID_PATTERN = r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$"
Identifier = Annotated[str, Field(pattern=ID_PATTERN, max_length=128)]
UtcDateTime = Annotated[datetime, Field(json_schema_extra={"format": "date-time"})]

#: Long enough to cover a client poll interval plus a slow first render, short enough that a
#: forgotten run cannot leave a probe accepting contacts for days.
DEFAULT_WINDOW_SECONDS = 3600


def utc_now() -> datetime:
    return datetime.now(UTC)


class ObservationChannel(StrEnum):
    """The three mechanisms that can observe a canary contact.

    There is no TCP watcher: a preconnect is observed by the SNI watcher, so it arrives
    here as :attr:`TLS_SNI`. Keeping that a property of the channel rather than inventing
    a fourth value is what stops a preconnect from being reported as a distinct mechanism.
    """

    HTTP = "http"
    DNS = "dns"
    TLS_SNI = "tls_sni"


class ObservationOrigin(StrEnum):
    """Who initiated a canary contact.

    The distinction between a client and a provider is the difference between a finding
    about a mail client and a finding about a mail provider, and it cannot be derived here:
    a provider spam filter prefetching the canary looks exactly like a client rendering
    the message. It is recorded by the collector that saw the contact and is never
    guessed from timing.
    """

    CLIENT = "client"
    PROVIDER = "provider"
    UNKNOWN = "unknown"


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CreateTestRequest(ContractModel):
    """Allocate a probe for one synthetic mailbox."""

    email: str = Field(min_length=3, max_length=320)
    language: str = Field(default="en", min_length=2, max_length=8)


class TestCreated(ContractModel):
    test_id: Identifier
    probe_id: Identifier
    expires_at: UtcDateTime


class TestState(ContractModel):
    """What the gateway knows about a probe window.

    ``referer_captured`` is reported as ``True`` because this service does record the
    header, and it is reported per-deployment rather than hardcoded into the adapter for
    the same reason the adapter refuses to pass without it: a service that stopped
    recording the header must not keep claiming that it did.
    """

    test_id: Identifier
    probe_id: Identifier
    delivered_at: UtcDateTime | None = None
    watchers_healthy: bool = False
    window_expires_at: UtcDateTime
    exercised: tuple[str, ...] = ()
    referer_captured: bool = True
    third_party_hosts: tuple[str, ...] = ()


class Observation(ContractModel):
    channel: ObservationChannel
    probe_id: Identifier
    vector: str = Field(min_length=1, max_length=64)
    origin: ObservationOrigin = ObservationOrigin.UNKNOWN
    remote_host: str = Field(min_length=1, max_length=253)
    observed_at: UtcDateTime
    resource: str | None = Field(default=None, max_length=2048)
    #: The ``Referer`` header exactly as received, or ``None`` when the request carried
    #: none. Recorded verbatim rather than normalised: a benchmark row that reports "the
    #: header was present but redacted" cannot be checked by a reader, and this value is
    #: what tells a mailbox origin apart from an unrelated one.
    referrer: str | None = Field(default=None, max_length=2048)
    detail: dict[str, JsonValue] = Field(default_factory=dict)


class ObservationList(ContractModel):
    test_id: Identifier
    observations: tuple[Observation, ...] = ()


class CallbackRequest(ContractModel):
    """A canary contact reported by a collector.

    Collectors are the HTTP callback, the DNS watcher, and the SNI watcher. They are
    authenticated with the same token as the read API, because a collector that can write
    a contact can also invent one, and an invented contact is a failed measurement that
    looks like a disclosure.
    """

    probe_id: Identifier
    vector: str = Field(min_length=1, max_length=64)
    channel: ObservationChannel
    origin: ObservationOrigin = ObservationOrigin.UNKNOWN
    remote_host: str = Field(min_length=1, max_length=253)
    resource: str | None = Field(default=None, max_length=2048)
    referrer: str | None = Field(default=None, max_length=2048)
    detail: dict[str, JsonValue] = Field(default_factory=dict)


class MarkDeliveredRequest(ContractModel):
    """Assert that the canary message reached the synthetic mailbox.

    Supplied by the SMTP delivery path, which this service does not own. It is an explicit
    assertion rather than something inferred from a contact, because a client that
    suppresses all remote content makes no contact at all and would otherwise be
    indistinguishable from a message that never arrived.
    """

    probe_id: Identifier
    delivered_at: UtcDateTime | None = None


class WatcherHeartbeat(ContractModel):
    """A collector reporting that it is running.

    Health is a heartbeat rather than a flag so that a collector which has *stopped* stops
    vouching for the window. A hardcoded ``True`` is the failure this exists to prevent:
    it makes an absence of traffic look like a clean client forever.
    """

    watcher: str = Field(min_length=1, max_length=64)
    observed_at: UtcDateTime


class WatcherHealth(ContractModel):
    watchers: dict[str, UtcDateTime]
    healthy: bool
