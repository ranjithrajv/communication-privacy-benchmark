"""EPT gateway adjudication semantics.

The adjudication matrix is the load-bearing part of the adapter. Its most important
property is negative: an unexercised or broken probe must never be reported as a pass.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from privacy_benchmark.adapters.base import AdapterError
from privacy_benchmark.adapters.ept import (
    REMOTE_FETCH_CHANNELS,
    Adjudication,
    GatewayObservation,
    GatewayTestState,
    ObservationChannel,
    adjudicate,
    gateway_config_from_environment,
    mailbox_config_from_environment,
)

DELIVERED = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
OPENED = datetime(2026, 9, 25, 12, 1, tzinfo=UTC)
EXPIRES = datetime(2026, 9, 25, 13, 0, tzinfo=UTC)


def _state(
    *,
    delivered_at: datetime | None = DELIVERED,
    opened_at: datetime | None = OPENED,
    watchers_healthy: bool = True,
) -> GatewayTestState:
    return GatewayTestState(
        test_id="test.one",
        probe_id="probe.one",
        delivered_at=delivered_at,
        opened_at=opened_at,
        watchers_healthy=watchers_healthy,
        window_expires_at=EXPIRES,
    )


def _observation(
    channel: ObservationChannel = ObservationChannel.HTTP,
    *,
    probe_id: str = "probe.one",
    remote_host: str = "canary.example.invalid",
) -> GatewayObservation:
    return GatewayObservation(
        channel=channel,
        probe_id=probe_id,
        remote_host=remote_host,
        observed_at=OPENED + timedelta(seconds=5),
    )


class TestNoFalsePass:
    def test_undelivered_is_inconclusive_not_a_pass(self) -> None:
        status, reason, _ = adjudicate(state=_state(delivered_at=None), observations=())
        assert reason is Adjudication.MESSAGE_NOT_DELIVERED
        assert status.value == "inconclusive"

    def test_unopened_is_inconclusive_not_a_pass(self) -> None:
        status, reason, _ = adjudicate(state=_state(opened_at=None), observations=())
        assert reason is Adjudication.MESSAGE_NOT_OPENED
        assert status.value == "inconclusive"

    def test_unhealthy_watchers_are_inconclusive_not_a_pass(self) -> None:
        status, reason, _ = adjudicate(state=_state(watchers_healthy=False), observations=())
        assert reason is Adjudication.WATCHERS_UNHEALTHY
        assert status.value == "inconclusive"

    def test_delivery_is_checked_before_watcher_health(self) -> None:
        # A probe that never delivered tells us nothing regardless of watcher state.
        status, reason, _ = adjudicate(
            state=_state(delivered_at=None, watchers_healthy=False), observations=()
        )
        assert reason is Adjudication.MESSAGE_NOT_DELIVERED
        assert status.value == "inconclusive"

    def test_watcher_health_is_checked_before_the_open_signal(self) -> None:
        status, reason, _ = adjudicate(
            state=_state(opened_at=None, watchers_healthy=False), observations=()
        )
        assert reason is Adjudication.WATCHERS_UNHEALTHY
        assert status.value == "inconclusive"

    def test_a_fully_healthy_probe_with_no_traffic_is_a_pass(self) -> None:
        status, reason, _ = adjudicate(state=_state(), observations=())
        assert reason is Adjudication.NO_REMOTE_CONTENT_OBSERVED
        assert status.value == "pass"


class TestDetection:
    @pytest.mark.parametrize("channel", sorted(REMOTE_FETCH_CHANNELS))
    def test_every_remote_fetch_channel_is_a_failure(self, channel: ObservationChannel) -> None:
        status, reason, _ = adjudicate(state=_state(), observations=(_observation(channel),))
        assert reason is Adjudication.REMOTE_CONTENT_DETECTED
        assert status.value == "fail"

    def test_a_prefetch_leak_is_detected_without_any_http_request(self) -> None:
        # DNS and SNI can fire before a request completes, so HTTP alone is not enough
        # to claim a client suppressed remote content.
        status, reason, _ = adjudicate(
            state=_state(), observations=(_observation(ObservationChannel.TLS_SNI),)
        )
        assert reason is Adjudication.REMOTE_CONTENT_DETECTED
        assert status.value == "fail"

    def test_the_summary_names_the_channels_and_hosts(self) -> None:
        _, _, summary = adjudicate(
            state=_state(),
            observations=(
                _observation(ObservationChannel.HTTP, remote_host="img.example.invalid"),
                _observation(ObservationChannel.DNS, remote_host="px.example.invalid"),
            ),
        )
        assert "dns" in summary
        assert "http" in summary
        assert "img.example.invalid" in summary
        assert "px.example.invalid" in summary

    def test_a_mime_only_observation_is_not_a_remote_fetch(self) -> None:
        # MIME is an inline part, not a fetch of a remote resource.
        status, _, _ = adjudicate(
            state=_state(), observations=(_observation(ObservationChannel.MIME),)
        )
        assert status.value == "pass"


class TestProbeCorrelation:
    def test_an_observation_from_another_probe_is_rejected(self) -> None:
        with pytest.raises(AdapterError, match="another probe id"):
            adjudicate(state=_state(), observations=(_observation(probe_id="probe.other"),))

    def test_probe_ids_that_differ_only_after_a_valid_batch_still_fail(self) -> None:
        observations = (_observation(), _observation(probe_id="probe.other"))
        with pytest.raises(AdapterError, match="another probe id"):
            adjudicate(state=_state(), observations=observations)


class TestGatewayConfiguration:
    def test_no_configuration_means_no_gateway(self) -> None:
        assert gateway_config_from_environment({}) is None

    def test_a_partial_configuration_is_not_a_gateway(self) -> None:
        assert gateway_config_from_environment({"PT_BENCH_EPT_GATEWAY_URL": "https://x"}) is None
        assert gateway_config_from_environment({"PT_BENCH_EPT_GATEWAY_TOKEN": "t"}) is None

    def test_a_complete_configuration_is_returned(self) -> None:
        config = gateway_config_from_environment(
            {"PT_BENCH_EPT_GATEWAY_URL": "https://gw", "PT_BENCH_EPT_GATEWAY_TOKEN": "t"}
        )
        assert config == ("https://gw", "t")

    def test_an_absent_mailbox_mapping_is_empty(self) -> None:
        assert mailbox_config_from_environment({}) == {}

    def test_a_mailbox_mapping_is_parsed(self) -> None:
        parsed = mailbox_config_from_environment(
            {"PT_BENCH_EPT_MAILBOXES": '{"slot-gmail-0001": "probe@example.invalid"}'}
        )
        assert parsed == {"slot-gmail-0001": "probe@example.invalid"}

    def test_malformed_mailbox_json_is_rejected(self) -> None:
        with pytest.raises(AdapterError, match="must be a JSON object"):
            mailbox_config_from_environment({"PT_BENCH_EPT_MAILBOXES": "not json"})

    def test_a_non_string_mailbox_mapping_is_rejected(self) -> None:
        with pytest.raises(AdapterError, match="string keys and string values"):
            mailbox_config_from_environment({"PT_BENCH_EPT_MAILBOXES": '{"slot": 7}'})

    def test_a_non_object_mailbox_mapping_is_rejected(self) -> None:
        with pytest.raises(AdapterError, match="string keys and string values"):
            mailbox_config_from_environment({"PT_BENCH_EPT_MAILBOXES": "[1, 2]"})
