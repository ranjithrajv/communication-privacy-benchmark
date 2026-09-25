"""Appium client and adapter for the private chat canary gateway.

The benchmark does not call undocumented Honeymessages routes or drive a real account
from benchmark code paths that are not explicitly audited. A small private gateway
exposes the versioned contract modelled here and translates to the pinned upstream
service, so the harness depends on an API boundary the project controls rather than on
upstream internals. The gateway contract is documented in ``infra/chat/README.md``.

Adjudication carries three chat-specific facts that the email lane does not have.

First, an empty observation set is the signature of two very different worlds: a client
that suppressed link previews, and a measurement that never exercised the client. Chat
makes the second world considerably more likely than email does, because Android
background restrictions can hold a message in the push queue until the device is
unlocked, and each subject fetches previews on a different trigger. An absence is only
allowed to mean anything once delivery, display, and watcher health are all confirmed.

Second, in an end-to-end encrypted conversation the canary URL reaches the reader as
plaintext inside the message body, so the recipient's client fetches it directly from
the canary host rather than through the messaging provider. A client-attributed HTTP
observation is therefore a disclosure of the reader's own act of opening, which is a
stronger and more specific finding than the same observation in mail.

Third, a partial contact is not a pass. A name that resolves but is never fetched means
something was attempted, so reporting it as a clean client would discard a real
observation. It is reported as ``partial`` instead.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from privacy_benchmark.adapters.automation import AutomationStack, collect_automation_stack
from privacy_benchmark.adapters.base import (
    AdapterError,
    AdapterEvidence,
    AdapterOutcome,
    ensure_identifier,
)
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.spec.models import (
    ChatAutomation,
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
GATEWAY_URL_VARIABLE = "PT_BENCH_CHAT_GATEWAY_URL"
GATEWAY_TOKEN_VARIABLE = "PT_BENCH_CHAT_GATEWAY_TOKEN"
#: A JSON object mapping account slot ids to synthetic phone numbers.
NUMBERS_VARIABLE = "PT_BENCH_CHAT_NUMBERS"

#: A conservative E.164 shape. The number is synthetic, but the format is still checked
#: so a mis-mapped slot fails loudly instead of delivering a honey-message to whatever
#: string a secret-store key collision produced.
E164_PATTERN = re.compile(r"^\+[1-9]\d{6,14}$")


class ObservationChannel(StrEnum):
    """The signals a chat canary can observe along the fetch path.

    Honeymessages watches the whole path, and each layer is kept separate because they
    fail independently and mean different things. ``dns`` alone is an attempt, not a
    fetch; ``http`` is the disclosure.
    """

    HTTP = "http"
    DNS = "dns"
    TLS_SNI = "tls_sni"
    WEBSOCKET = "websocket"
    WEBRTC = "webrtc"


#: The channel that constitutes a completed disclosure. Everything else is supporting
#: detail or a partial observation.
DECISIVE_CHANNEL = ObservationChannel.HTTP


class ObservationOrigin(StrEnum):
    """Who initiated a canary contact.

    This is the difference between a finding about a chat client and a finding about a
    messaging provider. WhatsApp performs server-side link handling in some
    configurations, so a provider-attributed fetch of the canary is recorded the same
    way as the reader's own client fetching it.
    """

    CLIENT = "client"
    PROVIDER = "provider"
    UNKNOWN = "unknown"


#: Origins that can indict the client under test. Anything else is recorded as evidence
#: but never scored as a client disclosure.
CLIENT_ATTRIBUTABLE_ORIGINS = frozenset({ObservationOrigin.CLIENT})


class _GatewayModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GatewayMessageCreated(_GatewayModel):
    message_id: Identifier
    probe_id: Identifier
    delivered_at: UtcDateTime | None = None
    expires_at: UtcDateTime


class GatewayObservation(_GatewayModel):
    """One canary contact reported by a watcher.

    ``remote_host`` and ``resource`` are what make a published row checkable by a third
    party: they say which host was contacted and which path carried the request.
    """

    channel: ObservationChannel
    probe_id: Identifier
    origin: ObservationOrigin = ObservationOrigin.UNKNOWN
    remote_host: str = Field(min_length=1, max_length=253)
    observed_at: UtcDateTime
    resource: str | None = Field(default=None, max_length=2048)
    detail: dict[str, JsonValue] = field(default_factory=dict)


class GatewayObservations(_GatewayModel):
    message_id: Identifier
    observations: tuple[GatewayObservation, ...] = ()


class GatewayMessageState(_GatewayModel):
    """What the gateway knows about the probe window for one honey-message.

    ``displayed_at`` is the load-bearing field. A delivered message that the client
    never rendered has not exercised link-preview behaviour, and reporting an empty
    observation set from that state would manufacture a privacy finding out of a
    measurement that never happened. ``watchers_healthy`` covers the case where every
    watcher is down, which would otherwise look exactly like a clean result.
    """

    message_id: Identifier
    probe_id: Identifier
    delivered_at: UtcDateTime | None = None
    displayed_at: UtcDateTime | None = None
    watchers_healthy: bool = False
    window_expires_at: UtcDateTime


class Adjudication(StrEnum):
    """Why the adapter reached the status it did."""

    LINK_PREVIEW_FETCHED = "chat.link-preview-fetched"
    NO_PREVIEW_FETCH_OBSERVED = "chat.no-preview-fetch-observed"
    PARTIAL_CONTACT_ONLY = "chat.partial-contact-only"
    READER_IDENTIFIED = "chat.reader-identified"
    NO_READER_DISCLOSURE_OBSERVED = "chat.no-reader-disclosure-observed"
    MESSAGE_NOT_DELIVERED = "chat.message-not-delivered"
    DISPLAY_NOT_ASSERTED = "chat.display-not-asserted"
    WATCHERS_UNHEALTHY = "chat.watchers-unhealthy"
    PROVIDER_ACTIVITY_ONLY = "chat.provider-activity-only"
    UNATTRIBUTED_ACTIVITY = "chat.unattributed-activity"
    DEVICE_SESSION_UNAVAILABLE = "chat.device-session-unavailable"
    UNSUPPORTED_CHECK = "chat.unsupported-check"


class ChatSession(Protocol):
    """Drives one synthetic chat account on a protected physical device.

    Split out as a protocol so the adapter's logic is testable without an Appium server
    and so the per-app UI work stays isolated from the adjudication that depends on it.
    """

    def deliver(self, number: str) -> None:
        """Ensure the synthetic conversation exists and is ready to receive."""

    def display_honey_message(self) -> bool:
        """Render the conversation and report whether the message was actually shown."""

    def close(self) -> None: ...


class RecipeUnavailable(AdapterError):
    """The subject's recipe could not drive its chat client.

    Raised only for a locator that does not resolve *before* the conversation is open,
    where the recipe is provably the problem. After the open the same symptom is a real
    answer -- the conversation is demonstrably open and the message demonstrably absent --
    so that case is reported as an unasserted display instead, never as this error.
    """


@dataclass(slots=True)
class AppiumChatSession:
    """A minimal Appium-backed session for the protected Android lane.

    Deliberately thin. Everything identical across the three subjects stays here: the
    driver setup, and the order of operations. Everything that differs between them — the
    activity to launch, how the synthetic conversation is addressed, and where the
    honey-message bubble lives — is carried by the subject as a :class:`ChatAutomation`
    recipe rather than written here. That is what makes adding an app a change to a
    checked-in subject instead of a branch of this adapter, and it means the recipe can
    be reviewed without reading a line of driver code.

    No recipe is still the safe state. A session without one raises from ``deliver``
    before a driver is ever opened, because standing up a device to fail afterwards
    wastes the lane and hides the real reason.
    """

    appium_server: str
    package_identifier: str
    device_name: str | None = None
    platform_version: str | None = None
    recipe: ChatAutomation | None = None

    def deliver(self, number: str) -> None:
        # Checked before a driver session is opened: without a recipe the call cannot
        # succeed, and standing up a device session only to fail wastes the lane and
        # hides the real reason.
        if self.recipe is None:
            raise AdapterError(
                f"no verified chat recipe is configured for "
                f"{self.package_identifier}; a session without one cannot assert that "
                f"the message was displayed, so the result would be a fabricated pass"
            )
        session = self._driver()
        try:
            session.implicitly_wait(self.recipe.open_timeout_seconds)
            # Opening the conversation is app-specific and is the reason each subject
            # needs its own recipe; the target is the synthetic number, never a real
            # contact, and the recipe is required to address it by that number.
            self._locate(session, self.recipe.conversation_locator(number)).click()
        except AdapterError:
            raise
        except Exception as error:
            # Before the conversation is open, an unresolvable locator is a broken recipe
            # rather than a measurement. Reporting it as "nothing was displayed" would
            # make a recipe that stopped matching its product look exactly like a client
            # that showed no message, which is the confusion this lane exists to avoid.
            raise RecipeUnavailable(
                f"the chat recipe for {self.package_identifier} could not open the "
                f"synthetic conversation: {error}"
            ) from error
        finally:
            self._quit(session)

    def display_honey_message(self) -> bool:
        if self.recipe is None:
            return False
        session = self._driver()
        try:
            locator = self._locate(session, self.recipe.message_selector)
            return bool(locator.is_displayed())
        except Exception:
            # Any driver failure is an unavailable session, never a clean result.
            return False
        finally:
            self._quit(session)

    @staticmethod
    def _locate(session: Any, locator: str) -> Any:
        """Resolve one Appium locator, preferring an id and falling back to a full one.

        A recipe states a locator the way Appium documents it, which is rarely a bare id.
        Callers that only need an element get the element rather than each of them
        re-implementing the lookup strategy.
        """
        strategy, _, value = locator.partition(":")
        if value and strategy in {"id", "xpath", "accessibility id", "android uiautomator"}:
            return session.find_element(strategy, value)
        return session.find_element("xpath", locator)

    def close(self) -> None:
        return None

    def _driver(self) -> Any:
        try:
            from appium import webdriver
            from appium.options.android import UiAutomator2Options
            from appium.webdriver.common.appiumby import AppiumBy  # noqa: F401
        except ImportError as error:  # pragma: no cover - exercised in minimal installs
            raise AdapterError(
                "Appium-Python-Client is required for the chat lane; install the 'automation' extra"
            ) from error
        capabilities: dict[str, Any] = {
            "platformName": "Android",
            "appium:automationName": "UiAutomator2",
            "appium:appPackage": self.package_identifier,
            "appium:udid": self.device_name,
            "appium:platformVersion": self.platform_version,
        }
        # The launch activity comes from the recipe, so it is the subject's to state
        # rather than the adapter's to guess. Omitted only when there is no recipe at
        # all, which `deliver` already refuses before reaching this point.
        if self.recipe is not None:
            capabilities["appium:appActivity"] = self.recipe.app_activity
        options = UiAutomator2Options().load_capabilities(capabilities)
        return webdriver.Remote(self.appium_server, options=options)

    @staticmethod
    def _quit(session: Any) -> None:
        # A failed teardown must never mask the measurement result.
        with contextlib.suppress(Exception):
            session.quit()


class ChatGatewayClient:
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

    def deliver(self, *, number: str, body_marker: str | None = None) -> GatewayMessageCreated:
        """Deliver a synthetic honey-message to a slot.

        ``body_marker`` places a synthetic token in the message body. Checks that read
        the network never need it, because the canary URL already identifies the
        message. Checks that read a display surface do need it, because they must prove
        that a specific synthetic body reached that surface.
        """

        payload: dict[str, str] = {"number": number}
        if body_marker is not None:
            payload["body_marker"] = body_marker
        with self._client() as client:
            response = client.post("/v1/honey-messages", json=payload)
            response.raise_for_status()
            return GatewayMessageCreated.model_validate(response.json())

    def get_state(self, message_id: str) -> GatewayMessageState:
        with self._client() as client:
            response = client.get(f"/v1/honey-messages/{message_id}/state")
            response.raise_for_status()
            state = GatewayMessageState.model_validate(response.json())
        if state.message_id != message_id:
            raise AdapterError("gateway returned state for the wrong honey-message")
        return state

    def get_observations(self, message_id: str) -> GatewayObservations:
        with self._client() as client:
            response = client.get(f"/v1/honey-messages/{message_id}/observations")
            response.raise_for_status()
            payload = GatewayObservations.model_validate(response.json())
        if payload.message_id != message_id:
            raise AdapterError("gateway returned observations for the wrong honey-message")
        return payload


def adjudicate(
    *,
    state: GatewayMessageState,
    observations: tuple[GatewayObservation, ...],
    display_asserted: bool,
) -> tuple[ResultStatus, Adjudication, str, dict[str, JsonValue]]:
    """Decide a result from gateway state, observations, and the asserted display.

    Measurement validity is settled before the observation set is interpreted, so a
    broken probe can never be reported as clean client behaviour. Attribution is settled
    next, so provider activity can never be reported as a reader disclosure.

    Observations that predate delivery are returned separately in the details rather than
    dropped, because a canary contact that happened before the honey-message was
    delivered cannot have been caused by this client reading it.
    """

    details: dict[str, JsonValue] = {
        "delivered": state.delivered_at is not None,
        "display_asserted": display_asserted,
        "watchers_healthy": state.watchers_healthy,
        "observation_count": len(observations),
    }

    if state.delivered_at is None:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.MESSAGE_NOT_DELIVERED,
            "The gateway never confirmed delivery, so nothing can be attributed to the client.",
            details,
        )
    if not state.watchers_healthy:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.WATCHERS_UNHEALTHY,
            "The canary watchers were not healthy, so an absence of traffic proves nothing.",
            details,
        )
    if not display_asserted:
        # Android background restrictions and per-app preview triggers mean a delivered
        # message is routinely never rendered. Without an asserted display the result
        # would be a claim about a message nobody was shown.
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.DISPLAY_NOT_ASSERTED,
            "The message was delivered but the client never reported rendering it, so "
            "link-preview behavior was never exercised.",
            details,
        )

    foreign = [item for item in observations if item.probe_id != state.probe_id]
    if foreign:
        raise AdapterError(f"gateway returned {len(foreign)} observations for another probe id")

    pre_delivery = tuple(item for item in observations if item.observed_at < state.delivered_at)
    details["pre_delivery_observation_count"] = len(pre_delivery)
    scorable = tuple(item for item in observations if item.observed_at >= state.delivered_at)
    details["scorable_observation_count"] = len(scorable)

    client = [item for item in scorable if item.origin in CLIENT_ATTRIBUTABLE_ORIGINS]
    fetched = [item for item in client if item.channel is DECISIVE_CHANNEL]
    if fetched:
        hosts = sorted({item.remote_host for item in fetched})
        return (
            ResultStatus.FAIL,
            Adjudication.LINK_PREVIEW_FETCHED,
            f"After the message was rendered the client itself fetched the canary on "
            f"{', '.join(hosts)}, disclosing that the conversation was opened.",
            details,
        )
    if client:
        channels = sorted({item.channel.value for item in client})
        return (
            ResultStatus.PARTIAL,
            Adjudication.PARTIAL_CONTACT_ONLY,
            f"The client contacted the canary on {', '.join(channels)} but never completed "
            f"a fetch. Something was attempted, so this is not reported as a clean client.",
            details,
        )

    provider = [item for item in scorable if item.origin is ObservationOrigin.PROVIDER]
    if provider and len(provider) == len(scorable):
        channels = sorted({item.channel.value for item in provider})
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.PROVIDER_ACTIVITY_ONLY,
            f"Only provider infrastructure contacted the canary, on {', '.join(channels)}. "
            "That is a provider behavior and says nothing about the reader's own fetching, "
            "so no client result is claimed.",
            details,
        )
    if scorable:
        # Something contacted the canary and it could not be pinned to the client. That
        # is not evidence the client is clean, so it must not be reported as a pass.
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.UNATTRIBUTED_ACTIVITY,
            "Canary contacts were observed but none could be attributed to the client, so "
            "no client result is claimed.",
            details,
        )
    return (
        ResultStatus.PASS,
        Adjudication.NO_PREVIEW_FETCH_OBSERVED,
        "The message was rendered with every watcher healthy, and the client made no "
        "canary contact of any kind.",
        details,
    )


#: The fields a canary contact must carry before it can single out a reader. A mobile
#: client behind carrier NAT shares an address with many other subscribers, so the source
#: address is only half the disclosure; the user agent is what separates one handset from
#: another on a shared egress. A contact carrying neither reveals that a conversation was
#: opened but not by whom, which is a different and weaker claim than identification.
READER_FIELDS = ("source_address", "user_agent")


def adjudicate_reader_identification(
    *,
    state: GatewayMessageState,
    observations: tuple[GatewayObservation, ...],
    display_asserted: bool,
) -> tuple[ResultStatus, Adjudication, str, dict[str, JsonValue]]:
    """Decide ``chat.reader-identification``.

    This asks what one contact *reveals*, not whether a contact happened, so it is
    deliberately separate from :func:`adjudicate`. A client can suppress every link preview
    and still hand the canary a source address and a user agent through anything that
    fetches on the user's behalf, and conversely a client that fetches on a coarse shared
    address may disclose less than one that resolves a per-account CDN edge. Folding either
    case into the other check would report a fetch as if it were an identification.

    Validity and attribution are settled the same way as for the preview check, and for the
    same reason: a contact that cannot be attributed to the client describes the relay or
    the provider, and reporting it as a reader disclosure would be a false finding about
    the product.
    """

    details: dict[str, JsonValue] = {
        "delivered": state.delivered_at is not None,
        "display_asserted": display_asserted,
        "watchers_healthy": state.watchers_healthy,
        "observation_count": len(observations),
    }

    if state.delivered_at is None:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.MESSAGE_NOT_DELIVERED,
            "The gateway never confirmed delivery, so nothing can be attributed to the client.",
            details,
        )
    if not state.watchers_healthy:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.WATCHERS_UNHEALTHY,
            "The canary watchers were not healthy, so an absence of traffic proves nothing.",
            details,
        )
    if not display_asserted:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.DISPLAY_NOT_ASSERTED,
            "The message was delivered but the client never reported rendering it, so no "
            "contact could have been caused by the reader reading it.",
            details,
        )

    foreign = [item for item in observations if item.probe_id != state.probe_id]
    if foreign:
        raise AdapterError(f"gateway returned {len(foreign)} observations for another probe id")

    pre_delivery = tuple(item for item in observations if item.observed_at < state.delivered_at)
    details["pre_delivery_observation_count"] = len(pre_delivery)
    scorable = tuple(item for item in observations if item.observed_at >= state.delivered_at)
    details["scorable_observation_count"] = len(scorable)

    client = [item for item in scorable if item.origin in CLIENT_ATTRIBUTABLE_ORIGINS]
    if not client:
        provider = [item for item in scorable if item.origin is ObservationOrigin.PROVIDER]
        if provider and len(provider) == len(scorable):
            return (
                ResultStatus.INCONCLUSIVE,
                Adjudication.PROVIDER_ACTIVITY_ONLY,
                "Only provider or relay infrastructure contacted the canary, which "
                "discloses that infrastructure and not the reader, so no client result "
                "is claimed.",
                details,
            )
        if scorable:
            return (
                ResultStatus.INCONCLUSIVE,
                Adjudication.UNATTRIBUTED_ACTIVITY,
                "Canary contacts were observed but none could be attributed to the client, "
                "so nothing is known about what the reader disclosed.",
                details,
            )
        return (
            ResultStatus.PASS,
            Adjudication.NO_READER_DISCLOSURE_OBSERVED,
            "The message was rendered with every watcher healthy, and the client made no "
            "canary contact, so the canary learned nothing about the reader.",
            details,
        )

    disclosed = sorted(
        {
            field
            for item in client
            for field in READER_FIELDS
            if item.detail.get(field) not in (None, "")
        }
    )
    details["disclosed_fields"] = list(disclosed)
    if disclosed:
        return (
            ResultStatus.FAIL,
            Adjudication.READER_IDENTIFIED,
            f"A client-attributed canary contact carried {', '.join(disclosed)}, so the "
            f"canary can single out this reader among other addresses sharing the same "
            f"egress.",
            details,
        )
    # A contact with no identifying field is not a pass. Something was contacted, and the
    # gateway simply did not say what it learned, so the disclosure cannot be stated.
    return (
        ResultStatus.PARTIAL,
        Adjudication.UNATTRIBUTED_ACTIVITY,
        "The client contacted the canary but the gateway reported no reader-identifying "
        "field, so what the canary learned cannot be stated. That is not a clean result.",
        details,
    )


@dataclass(slots=True)
class ChatAppiumAdapter:
    """Runs the chat checks a pinned canary gateway and an Android lane can answer.

    Synthetic numbers are supplied per account slot at construction and are never read
    from a checked-in definition, so a real number cannot reach the repository.
    """

    client: ChatGatewayClient
    numbers: dict[str, str]
    session_factory: Any = None
    adapter_id: str = "chat-appium"
    version: str = "1.0.0"
    poll_interval_seconds: float = 5.0
    #: How long to wait for the client to render the honey-message. Deliberately much
    #: shorter than the check timeout: driving the conversation is a UI interaction with
    #: a small expected latency, whereas the canary window is the long part. Sharing one
    #: bound would let a client stuck behind a background restriction hold the runner for
    #: the whole observation window before reporting ``inconclusive``.
    display_timeout_seconds: int = 120
    supported_checks: frozenset[str] = field(
        default_factory=lambda: frozenset({"chat.link-preview-fetch", "chat.reader-identification"})
    )
    redaction_policy_id: str = "evidence-retention-v1"
    raw_retention: str = "30-days-then-delete"
    automation_stack: AutomationStack | None = None

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        if check.check_id not in self.supported_checks:
            return AdapterOutcome(
                status=ResultStatus.UNSUPPORTED,
                reason_code=Adjudication.UNSUPPORTED_CHECK.value,
                summary=(
                    f"The chat adapter cannot answer {check.check_id}. Supported checks: "
                    f"{', '.join(sorted(self.supported_checks))}."
                ),
                details={"supported": False},
            )

        if self.session_factory is None:
            return AdapterOutcome(
                status=ResultStatus.INCONCLUSIVE,
                reason_code=Adjudication.DEVICE_SESSION_UNAVAILABLE.value,
                summary=(
                    "No Android device session is configured, so link-preview behavior "
                    "could not be exercised on the client at all."
                ),
                details={"check_id": check.check_id, "session": False},
            )

        number = self._number_for(context)
        session = self.session_factory(context)
        display_asserted = False
        created: GatewayMessageCreated | None = None
        try:
            session.deliver(number)
            created = self.client.deliver(number=number)
            display_asserted = await self._await_display(session, check.timeout_seconds)
            state = self.client.get_state(created.message_id)
            observations = await self._await_observations(
                created.message_id, state, check.timeout_seconds
            )
        finally:
            session.close()

        if created is None:  # pragma: no cover - defensive; deliver() raises first
            raise AdapterError("honey-message was never created")

        # The two checks share every precondition and differ only in what they ask of the
        # observation set, so the dispatch is on the check the caller named rather than on
        # a second code path that could drift from the first.
        adjudicate_for = (
            adjudicate_reader_identification
            if check.check_id == "chat.reader-identification"
            else adjudicate
        )
        status, reason_code, summary, details = adjudicate_for(
            state=state, observations=observations, display_asserted=display_asserted
        )
        details.update(
            {
                "check_id": check.check_id,
                "probe_id": created.probe_id,
                "message_id": created.message_id,
                "client_observation_count": sum(
                    1 for item in observations if item.origin in CLIENT_ATTRIBUTABLE_ORIGINS
                ),
                "provider_observation_count": sum(
                    1 for item in observations if item.origin is ObservationOrigin.PROVIDER
                ),
                "channels": ",".join(sorted({item.channel.value for item in observations})),
                "account_slot": context.subject.account.slot_id,
                "adapter": self.adapter_id,
            }
        )
        return AdapterOutcome(
            status=status,
            reason_code=reason_code.value,
            summary=summary,
            details=details,
            evidence=(
                self._evidence(
                    check=check,
                    context=context,
                    created=created,
                    state=state,
                    observations=observations,
                    display_asserted=display_asserted,
                ),
            ),
        )

    def _number_for(self, context: ExecutionContext) -> str:
        slot_id = context.subject.account.slot_id
        try:
            number = self.numbers[slot_id]
        except KeyError as error:
            raise AdapterError(
                f"no synthetic number is configured for account slot {slot_id}; the adapter "
                f"takes slot-to-number mappings supplied at run time via {NUMBERS_VARIABLE}"
            ) from error
        if E164_PATTERN.match(number) is None:
            raise AdapterError(
                f"account slot {slot_id} is not a valid E.164 number; a mis-mapped slot must "
                "fail loudly rather than deliver a honey-message to the wrong account"
            )
        return number

    async def _await_display(self, session: ChatSession, timeout_seconds: int) -> bool:
        """Wait for the client to report rendering the honey-message.

        Bounded by the display timeout rather than the check timeout, so a client held
        behind a background restriction produces an ``inconclusive`` display promptly
        instead of occupying the runner for the whole canary window.
        """

        deadline = utc_now() + timedelta(seconds=min(self.display_timeout_seconds, timeout_seconds))
        while True:
            if session.display_honey_message():
                return True
            if utc_now() >= deadline:
                return False
            await asyncio.sleep(self.poll_interval_seconds)

    async def _await_observations(
        self,
        message_id: str,
        state: GatewayMessageState,
        timeout_seconds: int,
    ) -> tuple[GatewayObservation, ...]:
        """Poll until the window closes, the display is seen, or the check times out.

        Polling stops early once the message is displayed and the watchers are healthy,
        because past that point an empty set is already the answer.
        """

        deadline = min(state.window_expires_at, utc_now() + timedelta(seconds=timeout_seconds))
        while True:
            payload = self.client.get_observations(message_id)
            settled = (
                state.delivered_at is not None
                and state.displayed_at is not None
                and state.watchers_healthy
            )
            if payload.observations or settled:
                return payload.observations
            if utc_now() >= deadline:
                return payload.observations
            await asyncio.sleep(self.poll_interval_seconds)
            refreshed = self.client.get_state(message_id)
            if (
                refreshed.delivered_at != state.delivered_at
                or refreshed.displayed_at != state.displayed_at
                or refreshed.watchers_healthy != state.watchers_healthy
            ):
                state = refreshed

    def _evidence(
        self,
        *,
        check: CheckDefinition,
        context: ExecutionContext,
        created: GatewayMessageCreated,
        state: GatewayMessageState,
        observations: tuple[GatewayObservation, ...],
        display_asserted: bool,
    ) -> AdapterEvidence:
        evidence_id = ensure_identifier(
            f"{context.execution_id}.{check.check_id}.chat", field_name="evidence_id"
        )
        stack = self.automation_stack or collect_automation_stack()
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
                "message_id": created.message_id,
                "probe_window": {
                    "delivered_at": _iso(state.delivered_at),
                    "displayed_at": _iso(state.displayed_at),
                    "display_asserted": display_asserted,
                    "watchers_healthy": state.watchers_healthy,
                    "window_expires_at": _iso(state.window_expires_at),
                },
                "observations": [
                    {
                        "channel": item.channel.value,
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
            source_uri=f"chat-gateway://privacy-benchmark/{created.probe_id}",
            redaction=RedactionPolicy(
                policy_id=self.redaction_policy_id,
                applied=True,
                raw_retention=self.raw_retention,
                notes=(
                    "The synthetic number is never recorded. Only the account slot, the "
                    "opaque probe id, and canary hostnames are exported."
                ),
            ),
            metadata={
                "probe_id": created.probe_id,
                "observation_count": len(observations),
                "watchers_healthy": state.watchers_healthy,
                "display_asserted": display_asserted,
                "appium_python_client": stack.appium_python_client,
                "appium_server": stack.appium_server,
                "android_sdk": stack.android_sdk,
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


def numbers_config_from_environment(environ: dict[str, str] | None = None) -> dict[str, str]:
    """Parse the runtime slot-to-number mapping from a JSON environment variable."""

    values = os.environ if environ is None else environ
    raw = values.get(NUMBERS_VARIABLE)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise AdapterError(
            f"{NUMBERS_VARIABLE} must be a JSON object mapping account slot ids to "
            "synthetic phone numbers"
        ) from error
    if not isinstance(parsed, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in parsed.items()
    ):
        raise AdapterError(
            f"{NUMBERS_VARIABLE} must be a JSON object of string keys and string values"
        )
    return dict(parsed)
