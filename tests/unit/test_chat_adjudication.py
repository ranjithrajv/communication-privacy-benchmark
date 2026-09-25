"""Chat canary adjudication semantics.

Three chat-specific facts drive the module and each has a test that would fail if the
adjudication stopped honouring it.

First, an empty observation set means either "the client suppressed link previews" or
"the conversation was never rendered". Chat makes the second case far more likely than
email does, because Android background restrictions can hold a message in the push
queue and each subject previews on a different trigger.

Second, a partial contact is not a pass. A canary name that resolves but is never
fetched means something was attempted, and reporting that as a clean client would
discard a real observation.

Third, a contact that predates delivery cannot have been caused by the reader, so it
must not be scored against the client even when it is attributed to the client.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from privacy_benchmark.adapters.base import AdapterError
from privacy_benchmark.adapters.chat_appium import (
    CLIENT_ATTRIBUTABLE_ORIGINS,
    Adjudication,
    GatewayMessageState,
    GatewayObservation,
    ObservationChannel,
    ObservationOrigin,
    adjudicate,
    gateway_config_from_environment,
    numbers_config_from_environment,
)

DELIVERED = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
DISPLAYED = datetime(2026, 9, 25, 12, 1, tzinfo=UTC)
EXPIRES = datetime(2026, 9, 25, 13, 0, tzinfo=UTC)
BEFORE_DELIVERY = DELIVERED - timedelta(seconds=30)
CANARY_HOST = "canary.privacy-benchmark.invalid"


def _state(
    *,
    delivered_at: datetime | None = DELIVERED,
    displayed_at: datetime | None = DISPLAYED,
    watchers_healthy: bool = True,
) -> GatewayMessageState:
    return GatewayMessageState(
        message_id="message.one",
        probe_id="probe.one",
        delivered_at=delivered_at,
        displayed_at=displayed_at,
        watchers_healthy=watchers_healthy,
        window_expires_at=EXPIRES,
    )


def _observation(
    channel: ObservationChannel = ObservationChannel.HTTP,
    *,
    origin: ObservationOrigin = ObservationOrigin.CLIENT,
    probe_id: str = "probe.one",
    observed_at: datetime = DISPLAYED,
    host: str = CANARY_HOST,
) -> GatewayObservation:
    return GatewayObservation(
        channel=channel,
        probe_id=probe_id,
        origin=origin,
        remote_host=host,
        observed_at=observed_at,
        resource="/pixel.gif",
    )


def test_client_origins_are_only_the_client() -> None:
    assert frozenset({ObservationOrigin.CLIENT}) == CLIENT_ATTRIBUTABLE_ORIGINS


def test_undelivered_message_claims_nothing() -> None:
    status, reason, _, _ = adjudicate(
        state=_state(delivered_at=None), observations=(), display_asserted=True
    )
    assert status.value == "inconclusive"
    assert reason is Adjudication.MESSAGE_NOT_DELIVERED


def test_unhealthy_watchers_claim_nothing() -> None:
    status, reason, _, _ = adjudicate(
        state=_state(watchers_healthy=False), observations=(), display_asserted=True
    )
    assert status.value == "inconclusive"
    assert reason is Adjudication.WATCHERS_UNHEALTHY


def test_a_message_the_client_never_rendered_claims_nothing() -> None:
    """The chat-specific guard: delivered is not displayed."""

    status, reason, _, _ = adjudicate(
        state=_state(displayed_at=None), observations=(), display_asserted=False
    )
    assert status.value == "inconclusive"
    assert reason is Adjudication.DISPLAY_NOT_ASSERTED


def test_rendered_message_with_no_contact_is_a_pass() -> None:
    status, reason, summary, _ = adjudicate(state=_state(), observations=(), display_asserted=True)
    assert status.value == "pass"
    assert reason is Adjudication.NO_PREVIEW_FETCH_OBSERVED
    assert "no canary contact" in summary


def test_client_http_fetch_fails_and_names_the_host() -> None:
    status, reason, summary, _ = adjudicate(
        state=_state(), observations=(_observation(),), display_asserted=True
    )
    assert status.value == "fail"
    assert reason is Adjudication.LINK_PREVIEW_FETCHED
    assert CANARY_HOST in summary


def test_a_resolved_name_that_is_never_fetched_is_partial_not_a_pass() -> None:
    """DNS-only means something was attempted, so a clean client must not be claimed."""

    status, reason, summary, _ = adjudicate(
        state=_state(),
        observations=(_observation(ObservationChannel.DNS),),
        display_asserted=True,
    )
    assert status.value == "partial"
    assert reason is Adjudication.PARTIAL_CONTACT_ONLY
    assert "dns" in summary


def test_websocket_contact_alone_is_partial() -> None:
    status, reason, _, _ = adjudicate(
        state=_state(),
        observations=(_observation(ObservationChannel.WEBSOCKET),),
        display_asserted=True,
    )
    assert status.value == "partial"
    assert reason is Adjudication.PARTIAL_CONTACT_ONLY


def test_provider_activity_alone_never_claims_a_client_result() -> None:
    status, reason, summary, _ = adjudicate(
        state=_state(),
        observations=(_observation(origin=ObservationOrigin.PROVIDER),),
        display_asserted=True,
    )
    assert status.value == "inconclusive"
    assert reason is Adjudication.PROVIDER_ACTIVITY_ONLY
    assert "provider" in summary


def test_unattributed_activity_never_becomes_a_pass() -> None:
    status, reason, _, _ = adjudicate(
        state=_state(),
        observations=(_observation(origin=ObservationOrigin.UNKNOWN),),
        display_asserted=True,
    )
    assert status.value == "inconclusive"
    assert reason is Adjudication.UNATTRIBUTED_ACTIVITY


def test_a_contact_predating_delivery_is_not_scored_against_the_reader() -> None:
    """The client cannot have fetched a URL it was not yet sent."""

    status, reason, _, details = adjudicate(
        state=_state(),
        observations=(_observation(observed_at=BEFORE_DELIVERY),),
        display_asserted=True,
    )
    assert status.value == "pass"
    assert reason is Adjudication.NO_PREVIEW_FETCH_OBSERVED
    assert details["pre_delivery_observation_count"] == 1
    assert details["scorable_observation_count"] == 0


def test_observations_for_another_probe_are_a_hard_failure() -> None:
    with pytest.raises(AdapterError, match="another probe id"):
        adjudicate(
            state=_state(),
            observations=(_observation(probe_id="probe.other"),),
            display_asserted=True,
        )


def test_validity_is_settled_before_attribution() -> None:
    """A client contact in an invalid measurement is still inconclusive, not a fail."""

    status, reason, _, _ = adjudicate(
        state=_state(watchers_healthy=False),
        observations=(_observation(),),
        display_asserted=True,
    )
    assert status.value == "inconclusive"
    assert reason is Adjudication.WATCHERS_UNHEALTHY


def test_details_report_the_settled_window() -> None:
    _, _, _, details = adjudicate(state=_state(), observations=(), display_asserted=True)
    assert details["delivered"] is True
    assert details["display_asserted"] is True
    assert details["watchers_healthy"] is True
    assert details["observation_count"] == 0


def test_gateway_config_requires_both_url_and_token() -> None:
    assert gateway_config_from_environment({}) is None
    assert gateway_config_from_environment(
        {
            "PT_BENCH_CHAT_GATEWAY_URL": "https://gateway.invalid",
            "PT_BENCH_CHAT_GATEWAY_TOKEN": "token",
        }
    ) == ("https://gateway.invalid", "token")


def test_numbers_config_parses_a_slot_mapping() -> None:
    parsed = numbers_config_from_environment(
        {"PT_BENCH_CHAT_NUMBERS": '{"slot-signal-0001": "+4915100000000"}'}
    )
    assert parsed == {"slot-signal-0001": "+4915100000000"}


def test_numbers_config_rejects_malformed_mappings() -> None:
    with pytest.raises(AdapterError):
        numbers_config_from_environment({"PT_BENCH_CHAT_NUMBERS": "not-json"})
    with pytest.raises(AdapterError):
        numbers_config_from_environment({"PT_BENCH_CHAT_NUMBERS": "[1, 2]"})
