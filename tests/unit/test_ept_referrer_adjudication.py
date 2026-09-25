"""Adjudication for ``email.referrer-disclosure``.

The behaviour these tests exist to pin is mostly refusal. A ``Referer`` check is the one
place in the corpus where the *absence* of evidence is worthless unless the gateway says it
looked, because a gateway that never captured the header returns exactly the observations a
clean client would produce. So the capability declaration is asserted before every clean
verdict, and the partial-versus-pass distinction is asserted because collapsing them would
claim coverage of a threat that was never exercised.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from privacy_benchmark.adapters.base import AdapterError
from privacy_benchmark.adapters.ept import (
    Adjudication,
    GatewayObservation,
    GatewayTestState,
    ObservationChannel,
    ObservationOrigin,
    ResultStatus,
    adjudicate_referrer_disclosure,
)

DELIVERED = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
OPENED = datetime(2026, 9, 25, 12, 1, tzinfo=UTC)
EXPIRES = datetime(2026, 9, 25, 13, 0, tzinfo=UTC)
CANARY_HOST = "canary.privacy-benchmark.invalid"
#: A host the reader did not choose to visit: the third party this check exists for.
THIRD_PARTY = "unrelated-newsletter.example.invalid"


def _state(
    *,
    delivered_at: datetime | None = DELIVERED,
    watchers_healthy: bool = True,
    referer_captured: bool = True,
    third_party_hosts: tuple[str, ...] = (THIRD_PARTY,),
) -> GatewayTestState:
    return GatewayTestState(
        test_id="test.one",
        probe_id="probe.one",
        delivered_at=delivered_at,
        watchers_healthy=watchers_healthy,
        window_expires_at=EXPIRES,
        referer_captured=referer_captured,
        third_party_hosts=third_party_hosts,
    )


def _observation(
    *,
    referrer: str | None = None,
    remote_host: str = CANARY_HOST,
    origin: ObservationOrigin = ObservationOrigin.CLIENT,
    channel: ObservationChannel = ObservationChannel.HTTP,
    vector: str = "img",
    probe_id: str = "probe.one",
) -> GatewayObservation:
    return GatewayObservation(
        channel=channel,
        probe_id=probe_id,
        vector=vector,
        origin=origin,
        remote_host=remote_host,
        observed_at=OPENED + timedelta(seconds=5),
        referrer=referrer,
    )


def _judge(
    *,
    state: GatewayTestState | None = None,
    observations: tuple[GatewayObservation, ...] = (),
    open_asserted: bool = True,
) -> tuple[str, str, str]:
    status, reason, summary = adjudicate_referrer_disclosure(
        state=state or _state(), observations=observations, open_asserted=open_asserted
    )
    return status.value, reason.value, summary


class TestTheGatewayMustDeclareItLooked:
    def test_an_unpatched_gateway_is_never_a_clean_client(self) -> None:
        # The whole point of the capability flag: without it these observations are
        # identical to a client's that leaked nothing.
        status, reason, summary = _judge(state=_state(referer_captured=False), observations=())
        assert status == ResultStatus.INCONCLUSIVE.value
        assert reason == Adjudication.REFERER_NOT_CAPTURED.value
        assert "never looked" in summary

    def test_an_unpatched_gateway_is_inconclusive_even_with_traffic(self) -> None:
        # A gateway that does not capture the header cannot be reporting one, so a
        # failure here would be impossible to have come from the header at all.
        status, reason, _ = _judge(
            state=_state(referer_captured=False),
            observations=(_observation(referrer="https://mail.example.invalid/"),),
        )
        assert status == ResultStatus.INCONCLUSIVE.value
        assert reason == Adjudication.REFERER_NOT_CAPTURED.value

    def test_the_capability_is_checked_before_the_noise(self) -> None:
        # An unpatched gateway must not be reported as a client leak for provider
        # prefetch either: the header was never captured, so nothing can be attributed.
        _, reason, _ = _judge(
            state=_state(referer_captured=False),
            observations=(_observation(origin=ObservationOrigin.PROVIDER),),
        )
        assert reason == Adjudication.REFERER_NOT_CAPTURED.value


class TestALeakedRefererIsAFailure:
    def test_a_referer_to_the_canary_discloses_the_mailbox_origin(self) -> None:
        status, reason, _ = _judge(
            observations=(_observation(referrer="https://mail.example.invalid/inbox"),)
        )
        assert status == ResultStatus.FAIL.value
        assert reason == Adjudication.REFERRER_DISCLOSED.value

    def test_a_referer_to_a_third_party_names_the_right_threat(self) -> None:
        # The two are different disclosures to different parties, and reporting them under
        # one code would misname who learned what.
        status, reason, summary = _judge(
            observations=(
                _observation(referrer="https://mail.example.invalid/", remote_host=THIRD_PARTY),
            )
        )
        assert status == ResultStatus.FAIL.value
        assert reason == Adjudication.THIRD_PARTY_REFERRER_DISCLOSED.value
        assert THIRD_PARTY in summary
        assert "did not choose to visit" in summary

    def test_a_third_party_leak_wins_over_a_canary_host_leak(self) -> None:
        # Both occurred; the one naming a party the reader did not choose is the stronger
        # and more specific finding, so it is the one reported.
        _, reason, _ = _judge(
            observations=(
                _observation(referrer="https://mail.example.invalid/"),
                _observation(referrer="https://mail.example.invalid/", remote_host=THIRD_PARTY),
            )
        )
        assert reason == Adjudication.THIRD_PARTY_REFERRER_DISCLOSED.value

    def test_a_referer_on_a_dns_resolution_is_still_a_disclosure(self) -> None:
        # The channel does not change who learns the mailbox origin.
        status, reason, _ = _judge(
            observations=(
                _observation(
                    referrer="https://mail.example.invalid/",
                    channel=ObservationChannel.DNS,
                ),
            )
        )
        assert status == ResultStatus.FAIL.value
        assert reason == Adjudication.REFERRER_DISCLOSED.value

    @pytest.mark.parametrize("origin", [ObservationOrigin.PROVIDER, ObservationOrigin.UNKNOWN])
    def test_a_referer_the_client_did_not_send_is_never_a_client_result(
        self, origin: ObservationOrigin
    ) -> None:
        # The provider's own proxy sending a Referer is a real disclosure, but to the
        # provider. Scoring it against the client would blame the wrong subject.
        status, reason, _ = _judge(
            observations=(_observation(referrer="https://mail.example.invalid/", origin=origin),)
        )
        assert status == ResultStatus.INCONCLUSIVE.value
        assert reason == Adjudication.UNATTRIBUTED_ACTIVITY.value


class TestACleanResultIsScopedToWhatWasWatched:
    def test_no_referer_with_a_third_party_canary_is_a_pass(self) -> None:
        status, reason, _ = _judge(observations=(_observation(),))
        assert status == ResultStatus.PASS.value
        assert reason == Adjudication.NO_REFERRER_OBSERVED.value

    def test_no_referer_without_a_third_party_canary_is_only_partial(self) -> None:
        # The declared threat is a host the reader did not choose to visit. Watching only
        # the tracking host never exercised it, so a pass would claim coverage that was
        # not measured.
        status, reason, summary = _judge(
            state=_state(third_party_hosts=()), observations=(_observation(),)
        )
        assert status == ResultStatus.PARTIAL.value
        assert reason == Adjudication.NO_REFERRER_OBSERVED.value
        assert "not exercised" in summary

    def test_a_silent_run_is_also_only_partial_without_a_third_party_canary(self) -> None:
        status, _, _ = _judge(state=_state(third_party_hosts=()), observations=())
        assert status == ResultStatus.PARTIAL.value

    def test_no_traffic_at_all_is_a_pass_when_the_threat_was_watched(self) -> None:
        status, reason, _ = _judge(observations=())
        assert status == ResultStatus.PASS.value
        assert reason == Adjudication.NO_REFERRER_OBSERVED.value


class TestABrokenProbeIsNeverAClientResult:
    @pytest.mark.parametrize(
        ("state", "open_asserted", "expected"),
        [
            (_state(delivered_at=None), True, Adjudication.MESSAGE_NOT_DELIVERED),
            (_state(watchers_healthy=False), True, Adjudication.WATCHERS_UNHEALTHY),
            (_state(), False, Adjudication.OPEN_NOT_ASSERTED),
        ],
    )
    def test_every_guard_fires_before_any_verdict(
        self, state: GatewayTestState, open_asserted: bool, expected: Adjudication
    ) -> None:
        # Each carries a real Referer, so a guard that ran late would report a failure
        # rather than the inconclusive the broken probe deserves.
        status, reason, _ = _judge(
            state=state,
            open_asserted=open_asserted,
            observations=(_observation(referrer="https://mail.example.invalid/"),),
        )
        assert status == ResultStatus.INCONCLUSIVE.value
        assert reason == expected.value

    def test_another_probe_id_is_refused(self) -> None:
        with pytest.raises(AdapterError, match="another probe id"):
            _judge(observations=(_observation(probe_id="probe.other"),))


class TestTheContractIsFailLoud:
    def test_the_gateway_must_declare_the_field_rather_than_ignore_it(self) -> None:
        # `extra="forbid"` is what makes a gateway that sends `referrer` to an adapter
        # that does not declare it fail loudly. If this ever becomes permissive, a
        # misspelled key would be silently absent and every client would look clean.
        from pydantic import ValidationError

        payload = {
            "channel": "http",
            "probe_id": "probe.one",
            "vector": "img",
            "origin": "client",
            "remote_host": CANARY_HOST,
            "observed_at": "2026-09-25T12:01:05Z",
            "referrer_typo": "https://mail.example.invalid/",
        }
        with pytest.raises(ValidationError):
            GatewayObservation.model_validate(payload)

    def test_the_capability_defaults_to_not_captured(self) -> None:
        # A deployment that says nothing must be treated as one that never looked, or the
        # default would silently manufacture a clean result.
        assert GatewayTestState.model_fields["referer_captured"].default is False

    def test_an_absent_referrer_header_is_none_rather_than_empty(self) -> None:
        assert GatewayObservation.model_fields["referrer"].default is None
