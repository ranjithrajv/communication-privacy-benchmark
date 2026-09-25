"""Tests for ``chat.reader-identification`` adjudication.

The check asks what one canary contact *reveals*, not whether a contact happened, so the
tests are organized around the ways that question gets answered wrongly:

* a relay-side or provider contact is not a reader disclosure, and reporting it as one is
  a false finding about the product;
* a contact with no identifying field is a real contact whose payload the gateway did not
  report, which is ``partial`` and never a pass;
* an unexercised probe -- undelivered, unhealthy watchers, or a message never rendered --
  proves nothing either way, and must not be reported as a clean reader;
* a gateway that mixed another probe's observations in would manufacture a disclosure for
  the wrong conversation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import JsonValue

from privacy_benchmark.adapters.base import AdapterError
from privacy_benchmark.adapters.chat_appium import (
    GatewayMessageState,
    GatewayObservation,
    ObservationChannel,
    ObservationOrigin,
    adjudicate_reader_identification,
)
from privacy_benchmark.spec.models import ResultStatus

DELIVERED = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)
LATER = DELIVERED + timedelta(seconds=30)
EARLIER = DELIVERED - timedelta(seconds=30)
PROBE = "probe-01jq8z7x4m2n3p4q5r6s7t8v9w"
EXPIRES = DELIVERED + timedelta(hours=1)


def _state(**overrides: object) -> GatewayMessageState:
    base: dict[str, object] = {
        "message_id": "msg-1",
        "probe_id": PROBE,
        "delivered_at": DELIVERED,
        "watchers_healthy": True,
        "window_expires_at": EXPIRES,
    }
    base.update(overrides)
    return GatewayMessageState.model_validate(base)


def _contact(
    *,
    origin: ObservationOrigin = ObservationOrigin.CLIENT,
    channel: ObservationChannel = ObservationChannel.HTTP,
    detail: dict[str, JsonValue] | None = None,
    observed_at: datetime = LATER,
    probe_id: str = PROBE,
) -> GatewayObservation:
    return GatewayObservation(
        channel=channel,
        probe_id=probe_id,
        origin=origin,
        remote_host="canary.example.invalid",
        observed_at=observed_at,
        detail=detail or {},
    )


def _adjudicate(
    *,
    state: GatewayMessageState | None = None,
    observations: tuple[GatewayObservation, ...] = (),
    display_asserted: bool = True,
) -> tuple[ResultStatus, str]:
    status, reason, _summary, _details = adjudicate_reader_identification(
        state=state if state is not None else _state(),
        observations=observations,
        display_asserted=display_asserted,
    )
    return status, reason.value


class TestValidityPrecedesInterpretation:
    def test_an_undelivered_message_proves_nothing(self) -> None:
        # Delivered is the gateway's to confirm, and without it there is no client act to
        # attribute a contact to.
        assert _adjudicate(state=_state(delivered_at=None)) == (
            ResultStatus.INCONCLUSIVE,
            "chat.message-not-delivered",
        )

    def test_unhealthy_watchers_prove_nothing(self) -> None:
        assert _adjudicate(state=_state(watchers_healthy=False)) == (
            ResultStatus.INCONCLUSIVE,
            "chat.watchers-unhealthy",
        )

    def test_an_unrendered_message_proves_nothing(self) -> None:
        # Android background restrictions mean a delivered message is routinely never
        # shown. A contact could then not have been caused by the reader reading it.
        assert _adjudicate(display_asserted=False) == (
            ResultStatus.INCONCLUSIVE,
            "chat.display-not-asserted",
        )

    def test_validity_is_settled_before_a_contact_is_read(self) -> None:
        # A contact that would otherwise be a fail must not outrank an unexercised probe:
        # ordering these the other way would report a leak from a message nobody was shown.
        contact = _contact(detail={"source_address": "203.0.113.9"})
        assert _adjudicate(observations=(contact,), display_asserted=False)[1] == (
            "chat.display-not-asserted"
        )


class TestDisclosure:
    def test_a_source_address_identifies_the_reader(self) -> None:
        status, reason = _adjudicate(
            observations=(_contact(detail={"source_address": "203.0.113.9"}),)
        )
        assert (status, reason) == (ResultStatus.FAIL, "chat.reader-identified")

    def test_a_user_agent_alone_identifies_the_reader(self) -> None:
        # Carrier NAT means many subscribers share an egress address, so the user agent is
        # often the only thing separating one handset from another.
        status, reason = _adjudicate(
            observations=(_contact(detail={"user_agent": "Signal-Android/141.0"}),)
        )
        assert (status, reason) == (ResultStatus.FAIL, "chat.reader-identified")

    def test_both_fields_are_reported(self) -> None:
        _status, _reason, _summary, details = adjudicate_reader_identification(
            state=_state(),
            observations=(
                _contact(detail={"source_address": "203.0.113.9", "user_agent": "Signal/141"}),
            ),
            display_asserted=True,
        )
        assert details["disclosed_fields"] == ["source_address", "user_agent"]

    def test_an_empty_field_is_not_a_disclosure(self) -> None:
        # The gateway reporting the key with an empty value is a gateway that saw nothing,
        # not a reader who withheld something.
        assert _adjudicate(observations=(_contact(detail={"source_address": ""}),)) == (
            ResultStatus.PARTIAL,
            "chat.unattributed-activity",
        )

    def test_a_contact_with_no_identifying_field_is_partial_not_pass(self) -> None:
        # Something was contacted and the payload is unstated. Reporting that as a clean
        # reader would turn a missing gateway capability into a privacy result.
        assert _adjudicate(observations=(_contact(detail={"referer": "/x"}),)) == (
            ResultStatus.PARTIAL,
            "chat.unattributed-activity",
        )


class TestAttribution:
    def test_a_relay_contact_is_not_a_reader_disclosure(self) -> None:
        # Signal routes through relays. A relay-side contact identifies the relay.
        status, reason = _adjudicate(
            observations=(
                _contact(
                    origin=ObservationOrigin.PROVIDER,
                    detail={"source_address": "198.51.100.4"},
                ),
            )
        )
        assert (status, reason) == (ResultStatus.INCONCLUSIVE, "chat.provider-activity-only")

    def test_a_client_contact_beats_a_relay_contact(self) -> None:
        # Mixed activity: the client is still on the hook for what it disclosed.
        status, _reason = _adjudicate(
            observations=(
                _contact(
                    origin=ObservationOrigin.PROVIDER,
                    detail={"source_address": "198.51.100.4"},
                ),
                _contact(detail={"user_agent": "Telegram-Android/11.2"}),
            )
        )
        assert status is ResultStatus.FAIL

    def test_unattributable_activity_claims_nothing(self) -> None:
        assert _adjudicate(observations=(_contact(origin=ObservationOrigin.UNKNOWN),)) == (
            ResultStatus.INCONCLUSIVE,
            "chat.unattributed-activity",
        )

    def test_a_pre_delivery_contact_is_not_the_readers_act(self) -> None:
        # A contact before the honey-message was delivered cannot have been caused by
        # this client reading it.
        status, reason = _adjudicate(
            observations=(_contact(detail={"source_address": "203.0.113.9"}, observed_at=EARLIER),)
        )
        assert (status, reason) == (ResultStatus.PASS, "chat.no-reader-disclosure-observed")

    def test_pre_delivery_contacts_are_still_counted(self) -> None:
        # Dropped from the verdict but not from the record, so a lane that suddenly starts
        # producing them is visible rather than invisible.
        _s, _r, _summary, details = adjudicate_reader_identification(
            state=_state(),
            observations=(_contact(observed_at=EARLIER),),
            display_asserted=True,
        )
        assert details["pre_delivery_observation_count"] == 1
        assert details["scorable_observation_count"] == 0


class TestForeignProbes:
    def test_another_probes_observations_are_refused(self) -> None:
        # A gateway that mixed probes in would otherwise manufacture a disclosure for a
        # conversation this reader never opened.
        with pytest.raises(AdapterError, match="another probe id"):
            _adjudicate(
                observations=(_contact(detail={"source_address": "203.0.113.9"}, probe_id="other"),)
            )


class TestNoContact:
    def test_no_contact_at_all_is_a_pass(self) -> None:
        assert _adjudicate() == (ResultStatus.PASS, "chat.no-reader-disclosure-observed")

    def test_the_pass_states_that_the_probe_was_exercised(self) -> None:
        _s, _r, summary, _d = adjudicate_reader_identification(
            state=_state(), observations=(), display_asserted=True
        )
        assert "watcher healthy" in summary
