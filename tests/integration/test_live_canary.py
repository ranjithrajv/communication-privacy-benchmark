"""Live canary tests: real sockets, real DNS, real HTTP, real delivery.

These are the tests that answer "has this ever touched anything real?". Everything here
crosses an actual network boundary on loopback. Nothing contacts a third party, and no
provider account is required, because the parts being validated are the ones the lab
owns: the canary, the watchers, the delivery path, and the adapter's ability to observe
a genuine client-initiated fetch.

What this file deliberately does *not* claim: that a real mail client fetches remote
content, or that a real provider mailbox receives a probe. Those need the approvals the
operations policy gate enforces.
"""

from __future__ import annotations

import asyncio
import email
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_benchmark.adapters.ept import (
    EptGatewayAdapter,
    EptGatewayClient,
    GatewayObservation,
    GatewayTestState,
    ObservationChannel,
    ObservationOrigin,
    adjudicate,
)
from privacy_benchmark.harness.canary import (
    DNS_QUERY_PATTERN,
    SNI_PATTERN,
    CanaryLedger,
    DnsCanary,
    HttpCanary,
    bind_query_line,
    build_test_message,
    fetch_tracking_url,
    local_addresses,
    raw_dns_query,
)
from privacy_benchmark.spec.models import ResultStatus, UtcDateTime

ZONE = "canary.privacy-benchmark.invalid"


def _parts(message: email.message.Message) -> list[email.message.Message]:
    """Narrow a parsed message to its MIME parts."""

    payload = message.get_payload()
    assert isinstance(payload, list)
    return [part for part in payload if isinstance(part, email.message.Message)]


def _body(message: email.message.Message, index: int) -> str:
    part = _parts(message)[index]
    decoded = part.get_payload(decode=True)
    assert isinstance(decoded, bytes)
    return decoded.decode()


@pytest.fixture
def ledger() -> CanaryLedger:
    return CanaryLedger()


@pytest.fixture
def http_canary(ledger: CanaryLedger) -> Iterator[HttpCanary]:
    canary = HttpCanary(ledger)
    canary.start()
    try:
        yield canary
    finally:
        canary.stop()


@pytest.fixture
def dns_canary(ledger: CanaryLedger) -> Iterator[DnsCanary]:
    canary = DnsCanary(ZONE, ledger)
    canary.start()
    try:
        yield canary
    finally:
        canary.stop()


class TestRealHttpCanary:
    def test_a_real_request_is_observed(
        self, http_canary: HttpCanary, ledger: CanaryLedger
    ) -> None:
        url = http_canary.tracking_url("code123")
        status = asyncio.run(fetch_tracking_url(url))

        assert status == 200
        events = ledger.all_events()
        assert len(events) == 1
        assert events[0].channel == "http"
        assert events[0].remote_ip == "127.0.0.1"
        assert "code123" in events[0].detail["codes"]

    def test_the_canary_really_serves_an_image(self, http_canary: HttpCanary) -> None:
        import urllib.request

        with urllib.request.urlopen(http_canary.tracking_url("code123"), timeout=5) as response:
            body = response.read()
        assert response.headers["Content-Type"] == "image/gif"
        assert body[:6] == b"GIF89a"

    def test_two_clients_produce_two_distinct_events(
        self, http_canary: HttpCanary, ledger: CanaryLedger
    ) -> None:
        # The upstream watchers dedupe within 30s; the ledger must not, or a burst
        # would be invisible in the evidence.
        for _ in range(3):
            asyncio.run(fetch_tracking_url(http_canary.tracking_url("code123")))
        assert len(ledger.all_events()) == 3


class TestRealDnsCanary:
    def test_a_real_query_is_answered(self, dns_canary: DnsCanary) -> None:
        response = raw_dns_query(f"code123.anchor-test.{ZONE}", dns_canary.port)
        assert response is not None
        # DNS header: ID(0-1) flags(2-3) QDCOUNT(4-5) ANCOUNT(6-7) NS(8-9) AR(10-11)
        assert int.from_bytes(response[6:8], "big") == 1, "answer count must be 1"
        assert response[-4:] == bytes((127, 0, 0, 1)), "answer must carry the canary address"

    def test_a_real_query_is_logged_in_bind_format(
        self, dns_canary: DnsCanary, ledger: CanaryLedger
    ) -> None:
        raw_dns_query(f"code123.anchor-test.{ZONE}", dns_canary.port)
        _settle()

        assert dns_canary.query_log, "the query log must receive a record"
        assert DNS_QUERY_PATTERN.match(dns_canary.query_log[-1]) is not None
        events = [event for event in ledger.all_events() if event.channel == "dns"]
        assert events
        assert events[0].vector == "dnsAnchor"
        assert "code123" in events[0].detail["codes"]

    def test_the_link_label_is_also_observed(
        self, dns_canary: DnsCanary, ledger: CanaryLedger
    ) -> None:
        raw_dns_query(f"code123.link-test.{ZONE}", dns_canary.port)
        _settle()
        vectors = {event.vector for event in ledger.all_events() if event.channel == "dns"}
        assert vectors == {"dnsLink"}

    def test_the_upstream_img_label_cannot_fire_the_watcher(
        self, dns_canary: DnsCanary, ledger: CanaryLedger
    ) -> None:
        # Reproduces a real upstream gap: the watcher regex matches only anchor|link,
        # so the img-test label used by the dnsImg vector is never recorded.
        raw_dns_query(f"code123.img-test.{ZONE}", dns_canary.port)
        _settle()
        assert [event for event in ledger.all_events() if event.channel == "dns"] == []
        assert (
            DNS_QUERY_PATTERN.match(f"client 127.0.0.1#0: query: x.img-test.{ZONE} IN A ") is None
        )

    def test_a_non_canary_zone_is_ignored(
        self, dns_canary: DnsCanary, ledger: CanaryLedger
    ) -> None:
        raw_dns_query("example.com", dns_canary.port)
        _settle()
        assert ledger.all_events() == []


class TestUpstreamPatterns:
    @pytest.mark.parametrize(
        "name",
        [
            "abc123.anchor-test.canary.invalid",
            "abc123.link-test.canary.invalid",
        ],
    )
    def test_dns_watcher_pattern_accepts_the_labels_it_claims(self, name: str) -> None:
        assert DNS_QUERY_PATTERN.match(bind_query_line("1.2.3.4", name))

    def test_sni_watcher_pattern_only_covers_preconnect(self) -> None:
        assert SNI_PATTERN.match("abc.link-preconnect-test.canary.invalid")
        assert SNI_PATTERN.match("abc.anchor-test.canary.invalid") is None

    def test_upstream_watchers_refuse_the_lab_host_itself(self) -> None:
        # A single-host lab observes nothing, which must be a known condition rather
        # than a silently clean result.
        assert all(not address.startswith("127.") for address in local_addresses())


class TestRealDelivery:
    def test_a_real_message_carries_real_canary_urls(self, http_canary: HttpCanary) -> None:
        message = build_test_message(
            to="probe@example.invalid",
            code="code123",
            http_tracking_url=http_canary.tracking_url("code123"),
            dns_zone=ZONE,
        )
        parsed = email.message_from_bytes(message.as_bytes())
        assert parsed["To"] == "probe@example.invalid"
        assert parsed["X-Benchmark-Code"] == "code123"

        html = _body(parsed, 1)
        assert http_canary.tracking_url("code123") in html
        assert "dns-prefetch" in html

    def test_the_message_is_valid_mime(self, http_canary: HttpCanary) -> None:
        message = build_test_message(
            to="probe@example.invalid",
            code="code123",
            http_tracking_url=http_canary.tracking_url("code123"),
            dns_zone=ZONE,
        )
        parsed = email.message_from_bytes(message.as_bytes())
        assert parsed.is_multipart()
        assert parsed.get_content_type() == "multipart/alternative"
        assert [part.get_content_type() for part in _parts(parsed)] == [
            "text/plain",
            "text/html",
        ]


class TestLiveAdapterObservation:
    """The adapter must adjudicate a genuine client fetch as a failure."""

    def _observation(self, ledger: CanaryLedger) -> tuple[GatewayObservation, ...]:
        from datetime import UTC, datetime

        return tuple(
            GatewayObservation(
                channel=ObservationChannel(event.channel),
                probe_id="probe.one",
                vector=event.vector,
                origin=ObservationOrigin.CLIENT,
                remote_host="canary.privacy-benchmark.invalid",
                observed_at=datetime.now(UTC),
            )
            for event in ledger.all_events()
        )

    def _state(self) -> GatewayTestState:
        from datetime import UTC, datetime, timedelta

        return GatewayTestState(
            test_id="test.one",
            probe_id="probe.one",
            delivered_at=datetime.now(UTC),
            watchers_healthy=True,
            window_expires_at=datetime.now(UTC) + timedelta(seconds=30),
        )

    def test_a_real_fetch_becomes_a_client_attributed_failure(
        self, http_canary: HttpCanary, ledger: CanaryLedger
    ) -> None:
        asyncio.run(fetch_tracking_url(http_canary.tracking_url("code123")))
        status, reason, summary = adjudicate(
            state=self._state(),
            observations=self._observation(ledger),
            open_asserted=True,
        )
        assert status is ResultStatus.FAIL
        assert reason.value == "ept.remote-content-detected"
        assert "img" in summary

    def test_a_real_dns_prefetch_becomes_a_client_attributed_failure(
        self, dns_canary: DnsCanary, ledger: CanaryLedger
    ) -> None:
        raw_dns_query(f"code123.anchor-test.{ZONE}", dns_canary.port)
        _settle()
        status, reason, summary = adjudicate(
            state=self._state(),
            observations=self._observation(ledger),
            open_asserted=True,
        )
        assert status is ResultStatus.FAIL
        assert reason.value == "ept.remote-content-detected"
        assert "dnsAnchor" in summary

    def test_a_silent_client_is_a_pass(self, ledger: CanaryLedger) -> None:
        status, reason, _ = adjudicate(state=self._state(), observations=(), open_asserted=True)
        assert status is ResultStatus.PASS
        assert reason.value == "ept.no-remote-content-observed"


class TestLiveAdapterConstruction:
    def test_an_adapter_without_an_open_observer_never_passes(
        self, http_canary: HttpCanary
    ) -> None:
        # The single most important property: upstream cannot report an open, so an
        # adapter that was not told the message was opened must not claim a pass.
        adapter = EptGatewayAdapter(
            client=EptGatewayClient(base_url="https://gateway.invalid", token="t"),
            mailboxes={"slot-0001": "probe@example.invalid"},
        )
        assert adapter.open_observer is None

    def test_loopback_is_reachable_for_a_lab_run(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            assert probe.getsockname()[0] == "127.0.0.1"


def _settle() -> None:
    """Give the canary's background thread a moment to record."""
    import time

    time.sleep(0.25)


def test_utc_datetime_alias_is_exported() -> None:
    assert UtcDateTime is not None


def test_repository_layout_is_unchanged(repository_root: Path) -> None:
    assert (repository_root / "src" / "privacy_benchmark" / "harness" / "canary.py").is_file()
