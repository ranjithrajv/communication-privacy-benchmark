"""Adjudication for the three email checks wired after ``email.reader-identification``.

The vector names asserted here were read from ept3 ``c80c093``
(``backend/lib/tests.js``), not inferred from documentation. A name that does not exist
upstream would make the check report ``inconclusive`` forever, which is safe but
useless, so the names are pinned here as well as in the adapter.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from privacy_benchmark.adapters.base import AdapterError
from privacy_benchmark.adapters.ept import (
    BACKGROUND_VECTORS,
    LIST_UNSUBSCRIBE_VECTORS,
    MIME_PART_VECTORS,
    Adjudication,
    GatewayObservation,
    GatewayTestState,
    ObservationChannel,
    ObservationOrigin,
    ResultStatus,
    adjudicate_background_fetch,
    adjudicate_list_unsubscribe_fetch,
    adjudicate_mime_remote_part,
)

DELIVERED = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
OPENED = datetime(2026, 9, 25, 12, 1, tzinfo=UTC)
EXPIRES = datetime(2026, 9, 25, 13, 0, tzinfo=UTC)
CANARY_HOST = "canary.privacy-benchmark.invalid"


def _state(
    *, delivered_at: datetime | None = DELIVERED, watchers_healthy: bool = True
) -> GatewayTestState:
    return GatewayTestState(
        test_id="test.one",
        probe_id="probe.one",
        delivered_at=delivered_at,
        watchers_healthy=watchers_healthy,
        window_expires_at=EXPIRES,
    )


def _observation(
    *,
    vector: str,
    channel: ObservationChannel = ObservationChannel.HTTP,
    origin: ObservationOrigin = ObservationOrigin.CLIENT,
    probe_id: str = "probe.one",
) -> GatewayObservation:
    return GatewayObservation(
        channel=channel,
        probe_id=probe_id,
        vector=vector,
        origin=origin,
        remote_host=CANARY_HOST,
        observed_at=OPENED + timedelta(seconds=5),
    )


class TestUpstreamVectorNames:
    """The pinned names must stay names the pinned upstream actually exports."""

    @pytest.mark.parametrize("vector", sorted(MIME_PART_VECTORS))
    def test_a_mime_part_vector_is_a_known_upstream_name(self, vector: str) -> None:
        assert vector[0].islower()
        assert vector.isalnum()

    def test_mime_part_covers_every_disclosed_part_type(self) -> None:
        # A calendar, a vCard, an SVG, and a nested message are the four part families
        # the check claims; dropping one would silently narrow the check's scope.
        for family in ("calendar", "vcard", "svg", "rfc822", "messageGlobal"):
            assert any(family in vector for vector in MIME_PART_VECTORS), family

    def test_dns_img_is_excluded_because_upstream_cannot_watch_it(self) -> None:
        # UPSTREAM_FINDINGS: the DNS watcher regex matches only anchor/link labels, so
        # a client that DNS-prefetches `dnsImg` is recorded clean upstream.
        assert "dnsImg" not in BACKGROUND_VECTORS
        assert "dnsImg" not in MIME_PART_VECTORS


class TestMimeRemotePart:
    def _judge(
        self,
        *,
        state: GatewayTestState | None = None,
        observations: tuple[GatewayObservation, ...] = (),
        open_asserted: bool = True,
    ) -> tuple[str, str, str]:
        status, reason, summary = adjudicate_mime_remote_part(
            state=state or _state(), observations=observations, open_asserted=open_asserted
        )
        return status.value, reason.value, summary

    @pytest.mark.parametrize("vector", sorted(MIME_PART_VECTORS))
    def test_every_mime_part_vector_is_a_client_failure(self, vector: str) -> None:
        status, reason, _ = self._judge(observations=(_observation(vector=vector),))
        assert status == ResultStatus.FAIL.value
        assert reason == Adjudication.MIME_PART_DISCLOSED.value

    def test_a_calendar_image_alone_is_still_a_failure(self) -> None:
        # A client that blocks body images but renders an invite is exactly the case
        # this check exists to catch, so the body-only result must not mask it.
        status, reason, _ = self._judge(observations=(_observation(vector="calendarImage"),))
        assert status == ResultStatus.FAIL.value
        assert reason == Adjudication.MIME_PART_DISCLOSED.value

    def test_body_only_traffic_is_not_this_checks_finding(self) -> None:
        status, reason, _ = self._judge(observations=(_observation(vector="img"),))
        assert status == ResultStatus.INCONCLUSIVE.value
        assert reason == Adjudication.UNATTRIBUTED_ACTIVITY.value

    def test_provider_side_traffic_is_never_a_client_result(self) -> None:
        status, reason, _ = self._judge(
            observations=(_observation(vector="svgUse", origin=ObservationOrigin.PROVIDER),)
        )
        assert status == ResultStatus.INCONCLUSIVE.value
        assert reason == Adjudication.UNATTRIBUTED_ACTIVITY.value

    def test_a_silent_run_passes(self) -> None:
        status, reason, _ = self._judge()
        assert status == ResultStatus.PASS.value
        assert reason == Adjudication.NO_MIME_PART_CONTENT_OBSERVED.value

    @pytest.mark.parametrize(
        ("state", "expected"),
        [
            (_state(delivered_at=None), Adjudication.MESSAGE_NOT_DELIVERED),
            (_state(watchers_healthy=False), Adjudication.WATCHERS_UNHEALTHY),
        ],
    )
    def test_a_broken_probe_never_fails_the_client(
        self, state: GatewayTestState, expected: Adjudication
    ) -> None:
        status, reason, _ = self._judge(
            state=state, observations=(_observation(vector="calendarImage"),)
        )
        assert status == ResultStatus.INCONCLUSIVE.value
        assert reason == expected.value

    def test_another_probe_id_is_refused(self) -> None:
        with pytest.raises(AdapterError, match="another probe id"):
            self._judge(observations=(_observation(vector="svgUse", probe_id="probe.other"),))


class TestListUnsubscribeFetch:
    def _judge(
        self,
        *,
        state: GatewayTestState | None = None,
        observations: tuple[GatewayObservation, ...] = (),
        open_asserted: bool = True,
    ) -> tuple[str, str, str]:
        status, reason, summary = adjudicate_list_unsubscribe_fetch(
            state=state or _state(), observations=observations, open_asserted=open_asserted
        )
        return status.value, reason.value, summary

    @pytest.mark.parametrize("vector", sorted(LIST_UNSUBSCRIBE_VECTORS))
    def test_the_header_url_fetch_is_a_failure(self, vector: str) -> None:
        status, reason, _ = self._judge(observations=(_observation(vector=vector),))
        assert status == ResultStatus.FAIL.value
        assert reason == Adjudication.LIST_UNSUBSCRIBE_DISCLOSED.value

    def test_the_summary_says_no_reader_interaction_was_needed(self) -> None:
        _, _, summary = self._judge(observations=(_observation(vector="listUnsubscribe"),))
        assert "without any reader interaction" in summary

    def test_a_silent_run_passes(self) -> None:
        status, reason, _ = self._judge()
        assert status == ResultStatus.PASS.value
        assert reason == Adjudication.NO_LIST_UNSUBSCRIBE_FETCH_OBSERVED.value

    def test_another_vector_is_not_this_checks_finding(self) -> None:
        status, _, _ = self._judge(observations=(_observation(vector="img"),))
        assert status == ResultStatus.INCONCLUSIVE.value

    def test_provider_traffic_is_not_a_client_result(self) -> None:
        status, reason, _ = self._judge(
            observations=(
                _observation(vector="listUnsubscribe", origin=ObservationOrigin.PROVIDER),
            )
        )
        assert status == ResultStatus.INCONCLUSIVE.value
        assert reason == Adjudication.UNATTRIBUTED_ACTIVITY.value


class TestBackgroundFetch:
    def _judge(
        self,
        *,
        state: GatewayTestState | None = None,
        observations: tuple[GatewayObservation, ...] = (),
        open_asserted: bool = True,
    ) -> tuple[str, str, str]:
        status, reason, summary = adjudicate_background_fetch(
            state=state or _state(), observations=observations, open_asserted=open_asserted
        )
        return status.value, reason.value, summary

    @pytest.mark.parametrize("vector", sorted(BACKGROUND_VECTORS))
    def test_a_prefetch_without_an_open_is_a_failure(self, vector: str) -> None:
        # The absence of an open is the measurement here, so the shared open guard must
        # not be applied or this check could never report a failure.
        status, reason, _ = self._judge(
            observations=(_observation(vector=vector),), open_asserted=False
        )
        assert status == ResultStatus.FAIL.value
        assert reason == Adjudication.BACKGROUND_FETCH_DISCLOSED.value

    def test_the_same_traffic_after_an_open_is_not_a_prefetch(self) -> None:
        status, reason, _ = self._judge(
            observations=(_observation(vector="backgroundImage"),), open_asserted=True
        )
        assert status == ResultStatus.PASS.value
        assert reason == Adjudication.NO_BACKGROUND_FETCH_OBSERVED.value

    def test_a_silent_run_passes(self) -> None:
        status, reason, _ = self._judge()
        assert status == ResultStatus.PASS.value
        assert reason == Adjudication.NO_BACKGROUND_FETCH_OBSERVED.value

    def test_undelivered_is_still_inconclusive(self) -> None:
        status, reason, _ = self._judge(
            state=_state(delivered_at=None),
            observations=(_observation(vector="background"),),
            open_asserted=False,
        )
        assert status == ResultStatus.INCONCLUSIVE.value
        assert reason == Adjudication.MESSAGE_NOT_DELIVERED.value

    def test_unhealthy_watchers_are_still_inconclusive(self) -> None:
        status, reason, _ = self._judge(
            state=_state(watchers_healthy=False),
            observations=(_observation(vector="background"),),
            open_asserted=False,
        )
        assert status == ResultStatus.INCONCLUSIVE.value
        assert reason == Adjudication.WATCHERS_UNHEALTHY.value
