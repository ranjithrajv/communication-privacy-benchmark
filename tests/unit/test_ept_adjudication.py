"""EPT gateway adjudication semantics.

Two upstream facts drive this module, both verified in infra/ept/UPSTREAM_FINDINGS.md.

First, an empty observation set means either "the client blocked everything" or "the
client was never exercised". Nothing may be claimed from it until the open is asserted
and the watchers are healthy.

Second, an observation is not automatically evidence against the *client*: a provider
spam filter prefetching the canary is recorded identically, and scoring that as a client
leak would publish a false ``fail`` about a provider.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import JsonValue, ValidationError

from privacy_benchmark.adapters.base import AdapterError
from privacy_benchmark.adapters.ept import (
    CLIENT_ATTRIBUTABLE_ORIGINS,
    OBSERVATION_CHANNELS,
    REQUIRED_EXERCISED,
    Adjudication,
    GatewayObservation,
    GatewayTestState,
    ObservationChannel,
    ObservationOrigin,
    _missing_vectors,
    adjudicate,
    adjudicate_dns_prefetch,
    adjudicate_reader_identification,
    gateway_config_from_environment,
    mailbox_config_from_environment,
)
from privacy_benchmark.spec.models import ResultStatus

DELIVERED = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
OPENED = datetime(2026, 9, 25, 12, 1, tzinfo=UTC)
EXPIRES = datetime(2026, 9, 25, 13, 0, tzinfo=UTC)
CANARY_HOST = "canary.privacy-benchmark.invalid"


def _state(
    *,
    delivered_at: datetime | None = DELIVERED,
    watchers_healthy: bool = True,
) -> GatewayTestState:
    return GatewayTestState(
        test_id="test.one",
        probe_id="probe.one",
        delivered_at=delivered_at,
        watchers_healthy=watchers_healthy,
        window_expires_at=EXPIRES,
    )


def _observation(
    channel: ObservationChannel = ObservationChannel.HTTP,
    *,
    vector: str = "img",
    origin: ObservationOrigin = ObservationOrigin.CLIENT,
    probe_id: str = "probe.one",
    remote_host: str = CANARY_HOST,
    detail: dict[str, JsonValue] | None = None,
) -> GatewayObservation:
    return GatewayObservation(
        channel=channel,
        probe_id=probe_id,
        vector=vector,
        origin=origin,
        remote_host=remote_host,
        observed_at=OPENED + timedelta(seconds=5),
        detail=detail or {},
    )


def _judge(
    *,
    state: GatewayTestState | None = None,
    observations: tuple[GatewayObservation, ...] = (),
    open_asserted: bool = True,
) -> tuple[str, str, str]:
    status, reason, summary = adjudicate(
        state=state or _state(), observations=observations, open_asserted=open_asserted
    )
    return status.value, reason.value, summary


class TestNoFalsePass:
    def test_undelivered_is_inconclusive(self) -> None:
        status, reason, _ = _judge(state=_state(delivered_at=None))
        assert (status, reason) == ("inconclusive", "ept.message-not-delivered")

    def test_unhealthy_watchers_are_inconclusive(self) -> None:
        status, reason, _ = _judge(state=_state(watchers_healthy=False))
        assert (status, reason) == ("inconclusive", "ept.watchers-unhealthy")

    def test_an_unasserted_open_is_inconclusive(self) -> None:
        # Upstream EPT has no open signal, so the harness must assert it. Without this
        # the result would be a claim about a message nobody was shown.
        status, reason, _ = _judge(open_asserted=False)
        assert (status, reason) == ("inconclusive", "ept.open-not-asserted")

    def test_delivery_is_checked_before_watcher_health(self) -> None:
        _, reason, _ = _judge(state=_state(delivered_at=None, watchers_healthy=False))
        assert reason == "ept.message-not-delivered"

    def test_watcher_health_is_checked_before_the_open(self) -> None:
        _, reason, _ = _judge(state=_state(watchers_healthy=False), open_asserted=False)
        assert reason == "ept.watchers-unhealthy"

    def test_a_fully_valid_probe_with_no_traffic_is_a_pass(self) -> None:
        status, reason, _ = _judge()
        assert (status, reason) == ("pass", "ept.no-remote-content-observed")


class TestClientAttribution:
    @pytest.mark.parametrize("channel", sorted(OBSERVATION_CHANNELS))
    def test_every_channel_a_client_uses_is_a_failure(self, channel: ObservationChannel) -> None:
        status, reason, _ = _judge(observations=(_observation(channel),))
        assert (status, reason) == ("fail", "ept.remote-content-detected")

    def test_a_preconnect_leak_is_caught_through_sni(self) -> None:
        # Upstream types the preconnect vector as "tcp" but only the SNI watcher can
        # observe it, so judging on a "tcp" channel would never fire.
        status, reason, _ = _judge(
            observations=(_observation(ObservationChannel.TLS_SNI, vector="linkPreconnect"),)
        )
        assert (status, reason) == ("fail", "ept.remote-content-detected")
        assert (
            "linkPreconnect"
            in _judge(
                observations=(_observation(ObservationChannel.TLS_SNI, vector="linkPreconnect"),)
            )[2]
        )

    def test_the_summary_names_the_vectors(self) -> None:
        _, _, summary = _judge(
            observations=(
                _observation(ObservationChannel.HTTP, vector="img"),
                _observation(ObservationChannel.DNS, vector="dnsAnchor"),
            )
        )
        assert "img" in summary
        assert "dnsAnchor" in summary


class TestProviderPrefetchIsNotAClientLeak:
    """A provider prefetch looks identical to a client fetch unless attributed."""

    def test_provider_only_activity_never_fails_the_client(self) -> None:
        status, reason, _ = _judge(
            observations=(_observation(ObservationChannel.DNS, origin=ObservationOrigin.PROVIDER),)
        )
        assert (status, reason) == ("inconclusive", "ept.provider-prefetch-only")

    def test_the_provider_summary_says_it_is_not_a_client_result(self) -> None:
        _, _, summary = _judge(
            observations=(_observation(ObservationChannel.DNS, origin=ObservationOrigin.PROVIDER),)
        )
        assert "provider" in summary
        assert "client" in summary

    def test_a_client_contact_still_fails_alongside_provider_prefetch(self) -> None:
        status, reason, _ = _judge(
            observations=(
                _observation(ObservationChannel.DNS, origin=ObservationOrigin.PROVIDER),
                _observation(ObservationChannel.HTTP, origin=ObservationOrigin.CLIENT),
            )
        )
        assert (status, reason) == ("fail", "ept.remote-content-detected")

    def test_unattributed_activity_is_inconclusive(self) -> None:
        status, reason, _ = _judge(observations=(_observation(origin=ObservationOrigin.UNKNOWN),))
        assert (status, reason) == ("inconclusive", "ept.unattributed-activity")

    def test_mixed_provider_and_unattributed_is_inconclusive(self) -> None:
        status, reason, _ = _judge(
            observations=(
                _observation(origin=ObservationOrigin.PROVIDER),
                _observation(origin=ObservationOrigin.UNKNOWN),
            )
        )
        assert (status, reason) == ("inconclusive", "ept.unattributed-activity")

    def test_only_the_client_origin_is_attributable(self) -> None:
        assert frozenset({ObservationOrigin.CLIENT}) == CLIENT_ATTRIBUTABLE_ORIGINS


class TestChannelTaxonomy:
    def test_only_real_upstream_mechanisms_exist(self) -> None:
        # There is no standalone TCP watcher upstream, and no MIME watcher at all.
        assert set(ObservationChannel) == {"http", "dns", "tls_sni"}

    def test_an_unknown_channel_is_rejected(self) -> None:
        # Upstream types the preconnect vector as "tcp", but no TCP watcher exists, so
        # accepting that channel would let a gateway report a signal nothing observes.
        with pytest.raises(ValidationError):
            GatewayObservation.model_validate(
                {
                    "channel": "tcp",
                    "probe_id": "probe.one",
                    "vector": "linkPreconnect",
                    "origin": "client",
                    "remote_host": CANARY_HOST,
                    "observed_at": OPENED.isoformat(),
                }
            )

    def test_a_vector_is_required(self) -> None:
        # A benchmark row is about a specific vector, so the field is mandatory.
        with pytest.raises(ValidationError):
            GatewayObservation.model_validate(
                {
                    "channel": "http",
                    "probe_id": "probe.one",
                    "origin": "client",
                    "remote_host": CANARY_HOST,
                    "observed_at": OPENED.isoformat(),
                }
            )


class TestProbeCorrelation:
    def test_an_observation_from_another_probe_is_rejected(self) -> None:
        with pytest.raises(AdapterError, match="another probe id"):
            _judge(observations=(_observation(probe_id="probe.other"),))

    def test_a_single_foreign_observation_poisons_the_batch(self) -> None:
        with pytest.raises(AdapterError, match="another probe id"):
            _judge(observations=(_observation(), _observation(probe_id="probe.other")))


class TestGatewayConfiguration:
    def test_no_configuration_means_no_gateway(self) -> None:
        assert gateway_config_from_environment({}) is None

    def test_a_partial_configuration_is_not_a_gateway(self) -> None:
        assert gateway_config_from_environment({"PT_BENCH_EPT_GATEWAY_URL": "https://x"}) is None
        assert gateway_config_from_environment({"PT_BENCH_EPT_GATEWAY_TOKEN": "t"}) is None

    def test_a_complete_configuration_is_returned(self) -> None:
        assert gateway_config_from_environment(
            {"PT_BENCH_EPT_GATEWAY_URL": "https://gw", "PT_BENCH_EPT_GATEWAY_TOKEN": "t"}
        ) == ("https://gw", "t")

    def test_an_absent_mailbox_mapping_is_empty(self) -> None:
        assert mailbox_config_from_environment({}) == {}

    def test_a_mailbox_mapping_is_parsed(self) -> None:
        assert mailbox_config_from_environment(
            {"PT_BENCH_EPT_MAILBOXES": '{"slot-gmail-0001": "probe@example.invalid"}'}
        ) == {"slot-gmail-0001": "probe@example.invalid"}

    @pytest.mark.parametrize("raw", ["not json", '{"slot": 7}', "[1, 2]"])
    def test_a_malformed_mailbox_mapping_is_rejected(self, raw: str) -> None:
        with pytest.raises(AdapterError):
            mailbox_config_from_environment({"PT_BENCH_EPT_MAILBOXES": raw})


def test_every_adjudication_has_a_stable_reason_code() -> None:
    for reason in Adjudication:
        assert reason.value.startswith("ept.")


# --- email.dns-prefetch ---------------------------------------------------------
#
# A resolution is the finding here, not a preliminary to one: a name that resolves and
# is never fetched still hands the canary operator the reader's resolver address, which
# identifies an internet provider and roughly a location.


def _dns(*observations: GatewayObservation) -> ResultStatus:
    status, _, _ = adjudicate_dns_prefetch(
        state=_state(), observations=observations, open_asserted=True
    )
    return status


def test_a_client_dns_resolution_is_a_resolver_disclosure() -> None:
    assert _dns(_observation(ObservationChannel.DNS, vector="dnsAnchor")) is ResultStatus.FAIL


def test_a_client_sni_contact_is_a_disclosure_even_without_a_request() -> None:
    status, _, _ = adjudicate_dns_prefetch(
        state=_state(),
        observations=(_observation(ObservationChannel.TLS_SNI, vector="linkPreconnect"),),
        open_asserted=True,
    )
    assert status is ResultStatus.FAIL


def test_resolving_without_fetching_is_a_fail_not_a_partial() -> None:
    """The remote-content ladder calls this preliminary; here it is the whole finding."""

    assert _dns(_observation(ObservationChannel.DNS, vector="dnsAnchor")) is ResultStatus.FAIL


def test_a_provider_resolution_is_never_a_reader_disclosure() -> None:
    status, reason, _ = adjudicate_dns_prefetch(
        state=_state(),
        observations=(_observation(ObservationChannel.DNS, origin=ObservationOrigin.PROVIDER),),
        open_asserted=True,
    )
    assert status is ResultStatus.INCONCLUSIVE
    assert reason is Adjudication.PROVIDER_PREFETCH_ONLY


def test_no_resolution_at_all_is_a_pass() -> None:
    assert _dns() is ResultStatus.PASS


def test_the_dns_result_refuses_an_unwatched_lab() -> None:
    status, reason, _ = adjudicate_dns_prefetch(
        state=_state(watchers_healthy=False), observations=(), open_asserted=True
    )
    assert status is ResultStatus.INCONCLUSIVE
    assert reason is Adjudication.WATCHERS_UNHEALTHY


# --- email.reader-identification ------------------------------------------------


def _identifying(
    origin: ObservationOrigin = ObservationOrigin.CLIENT, **detail: object
) -> GatewayObservation:
    return _observation(origin=origin, detail=dict(detail))


def test_a_contact_carrying_a_source_address_discloses_the_reader() -> None:
    status, reason, _ = adjudicate_reader_identification(
        state=_state(),
        observations=(_identifying(source_address="203.0.113.10"),),
        open_asserted=True,
    )
    assert status is ResultStatus.FAIL
    assert reason is Adjudication.READER_IDENTIFIED


def test_the_reported_reader_fields_are_named_in_the_verdict() -> None:
    _, _, summary = adjudicate_reader_identification(
        state=_state(),
        observations=(_identifying(source_address="203.0.113.10", user_agent="Thunderbird"),),
        open_asserted=True,
    )
    assert "source_address" in summary
    assert "user_agent" in summary


def test_a_client_contact_with_no_identifying_field_is_not_a_clean_result() -> None:
    """Nothing reported is not the same as nothing disclosed, so it is partial."""

    status, _, _ = adjudicate_reader_identification(
        state=_state(), observations=(_identifying(),), open_asserted=True
    )
    assert status is ResultStatus.PARTIAL


def test_no_client_contact_means_nothing_was_learned() -> None:
    status, _, _ = adjudicate_reader_identification(
        state=_state(), observations=(), open_asserted=True
    )
    assert status is ResultStatus.PASS


def test_a_proxied_provider_contact_does_not_identify_the_reader() -> None:
    """A prefetch discloses the provider's address, not the user's, so it is not a fail."""

    status, reason, _ = adjudicate_reader_identification(
        state=_state(),
        observations=(
            _identifying(origin=ObservationOrigin.PROVIDER, source_address="198.51.100.7"),
        ),
        open_asserted=True,
    )
    assert status is not ResultStatus.FAIL
    assert reason is not Adjudication.READER_IDENTIFIED


# --- the required-vector contract ------------------------------------------------


def test_only_checks_that_need_a_vector_name_one() -> None:
    """remote-content is excluded on purpose: its existing guards already suffice."""

    assert "email.remote-content" not in REQUIRED_EXERCISED
    assert REQUIRED_EXERCISED["email.dns-prefetch"] == frozenset({"dnsAnchor"})


@pytest.mark.parametrize(
    ("exercised", "missing"),
    [((), {"dnsAnchor"}), (("img",), {"dnsAnchor"}), (("dnsAnchor",), set())],
)
def test_a_missing_vector_is_what_guards_against_a_fabricated_pass(
    exercised: tuple[str, ...], missing: set[str]
) -> None:
    state = _state()
    object.__setattr__(state, "exercised", exercised)
    assert _missing_vectors("email.dns-prefetch", state) == missing
    assert _missing_vectors("email.remote-content", state) == set()
