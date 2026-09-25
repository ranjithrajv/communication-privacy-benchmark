"""Contract conformance: the real adapter client against the real gateway service.

This is the test that earns its keep. The adapter and this service are separate
distributions with separately written models, so they *can* disagree — and when they do,
the failure mode is a measurement that silently did not happen, not an exception. Every
test here runs the benchmark's own ``EptGatewayClient`` against the actual application, so
a renamed field or a changed default is caught here rather than on a measurement runner.

The gateway is exercised in-process through its ASGI interface; no socket, no database, no
token from the environment.
"""

from __future__ import annotations

import httpx
import pytest
from privacy_benchmark.adapters.ept import (
    EptGatewayAdapter,
    EptGatewayClient,
    ObservationChannel,
    ObservationOrigin,
)

from asgi import SyncASGITransport
from canary_gateway.app import Settings, create_app
from canary_gateway.models import CallbackRequest
from canary_gateway.store import InMemoryObservationStore

TOKEN = "contract-token"
SLOT = "slot-0001"
MAILBOX = "probe@mail.example.invalid"
CANARY_HOST = "canary.privacy-benchmark.invalid"
THIRD_PARTY = "unrelated-newsletter.example.invalid"


def _client(app, **kwargs) -> EptGatewayClient:
    return EptGatewayClient(
        base_url="https://gateway.invalid",
        token=TOKEN,
        transport=SyncASGITransport(app),
        **kwargs,
    )


@pytest.fixture
def store() -> InMemoryObservationStore:
    # A one-second window keeps the poll loop bounded while still allowing delivery to be
    # marked, so the contract paths are exercised without a slow test.
    return InMemoryObservationStore(third_party_hosts=(THIRD_PARTY,))


@pytest.fixture
def app(store: InMemoryObservationStore):
    settings = Settings(token=TOKEN, third_party_hosts=(THIRD_PARTY,), window_seconds=30)
    return create_app(store=store, settings=settings)


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


def _http(app, token: str | None = None) -> httpx.Client:
    """An in-process client for the routes the gateway client does not cover.

    ``httpx.get`` and friends do not accept a transport, so every direct call goes
    through a client built here rather than repeating the construction.
    """
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return httpx.Client(
        base_url="https://gateway.invalid", transport=SyncASGITransport(app), headers=headers
    )


def _healthy(store: InMemoryObservationStore) -> None:
    for name in store.required_watchers:
        store.heartbeat(_beat(name))


def _beat(name: str):
    from canary_gateway.models import WatcherHeartbeat, utc_now

    return WatcherHeartbeat(watcher=name, observed_at=utc_now())


class TestTheReadContract:
    def test_create_state_and_observations_round_trip(self, app, store) -> None:
        client = _client(app)
        created = client.create_test(email=MAILBOX)
        assert created.test_id
        assert created.probe_id

        _healthy(store)
        state = client.get_state(created.test_id)
        assert state.probe_id == created.probe_id
        assert state.watchers_healthy
        # Delivery is not inferred from anything: an unwatched, unopened probe says so.
        assert state.delivered_at is None

        assert client.get_observations(created.test_id).observations == ()

    def test_the_service_declares_the_referer_capability_it_keeps(self, app, store) -> None:
        # The adapter refuses to report a clean client without this. A service that
        # recorded no header but declared it did would manufacture clean results.
        client = _client(app)
        created = client.create_test(email=MAILBOX)
        _healthy(store)
        state = client.get_state(created.test_id)
        assert state.referer_captured
        assert state.third_party_hosts == (THIRD_PARTY,)

    def test_a_contact_comes_back_with_its_referrer_intact(self, app, store) -> None:
        client = _client(app)
        created = client.create_test(email=MAILBOX)
        store.record(
            CallbackRequest(
                probe_id=created.probe_id,
                vector="img",
                channel=ObservationChannel.HTTP,
                origin=ObservationOrigin.CLIENT,
                remote_host=CANARY_HOST,
                referrer="https://mail.example.invalid/inbox",
            )
        )
        observations = client.get_observations(created.test_id).observations
        assert len(observations) == 1
        assert observations[0].referrer == "https://mail.example.invalid/inbox"
        assert observations[0].vector == "img"
        assert observations[0].origin is ObservationOrigin.CLIENT

    def test_a_contact_with_no_referrer_is_none_not_empty(self, app, store) -> None:
        # An empty string would be read as a header that was present and blank, which is a
        # different claim from "the request carried none".
        client = _client(app)
        created = client.create_test(email=MAILBOX)
        store.record(
            CallbackRequest(
                probe_id=created.probe_id,
                vector="cssBackgroundImage",
                channel=ObservationChannel.HTTP,
                origin=ObservationOrigin.CLIENT,
                remote_host=CANARY_HOST,
            )
        )
        assert client.get_observations(created.test_id).observations[0].referrer is None

    def test_exercised_vectors_reflect_what_actually_ran(self, app, store) -> None:
        # A required-vector guard can only work if the gateway reports the vectors it
        # offered, including ones that drew no contact.
        client = _client(app)
        created = client.create_test(email=MAILBOX)
        store.mark_exercised(created.probe_id, frozenset({"img", "calendarImage"}))
        assert client.get_state(created.test_id).exercised == ("calendarImage", "img")

    def test_an_unknown_test_id_is_a_404_not_an_empty_result(self, app) -> None:
        client = _client(app)
        with pytest.raises(httpx.HTTPStatusError) as raised:
            client.get_state("test-does-not-exist")
        assert raised.value.response.status_code == 404


class TestAuthentication:
    def test_a_missing_token_is_refused(self, app) -> None:
        with _http(app) as http:
            response = http.get("/v1/watchers/health")
        assert response.status_code == 401

    def test_a_wrong_token_is_refused(self, app) -> None:
        with _http(app, token="wrong") as http:
            response = http.get("/v1/watchers/health")
        assert response.status_code == 401

    def test_an_unauthenticated_contact_cannot_invent_a_measurement(self, app, store) -> None:
        # This is the write path, so a token that only guarded reads would let anyone
        # fabricate a disclosure. The probe comes from this service's own store so the
        # assertion is that nothing was recorded against a probe that really exists.
        created = store.create(mailbox=MAILBOX, window_seconds=30)
        with _http(app) as http:
            response = http.post(
                "/v1/contacts",
                json={
                    "probe_id": created.probe_id,
                    "vector": "img",
                    "channel": "http",
                    "origin": "client",
                    "remote_host": CANARY_HOST,
                },
            )
        assert response.status_code == 401
        assert store.observations(created.test_id) == ()


class TestWatcherHealthIsEarned:
    def test_a_service_with_no_collectors_is_unhealthy(self, app) -> None:
        # The default must be unhealthy. Anything else turns an unwatched window into a
        # reported clean client, which is the worst available failure.
        client = _client(app)
        created = client.create_test(email=MAILBOX)
        assert client.get_state(created.test_id).watchers_healthy is False

    def test_health_requires_every_collector_not_just_one(self, app, store) -> None:
        client = _client(app)
        created = client.create_test(email=MAILBOX)
        store.heartbeat(_beat("http"))
        store.heartbeat(_beat("dns"))
        # SNI is still silent, so the window is not covered.
        assert client.get_state(created.test_id).watchers_healthy is False
        _healthy(store)
        assert client.get_state(created.test_id).watchers_healthy is True

    def test_a_stale_heartbeat_stops_counting(self, app, store) -> None:
        from datetime import timedelta

        from canary_gateway.models import utc_now

        client = _client(app)
        created = client.create_test(email=MAILBOX)
        for name in store.required_watchers:
            store.heartbeat(
                _beat(name).__class__(watcher=name, observed_at=utc_now() - timedelta(hours=1))
            )
        # A collector that has stopped must stop vouching for the window.
        assert client.get_state(created.test_id).watchers_healthy is False


class TestDeliveryIsAssertedNotInferred:
    def test_delivery_is_absent_until_the_mail_path_says_otherwise(self, app, store) -> None:
        client = _client(app)
        created = client.create_test(email=MAILBOX)
        _healthy(store)
        assert client.get_state(created.test_id).delivered_at is None
        with _http(app, token=TOKEN) as http:
            http.post("/v1/tests/delivered", json={"probe_id": created.probe_id})
        assert client.get_state(created.test_id).delivered_at is not None

    def test_delivery_is_independent_of_any_contact(self, app, store) -> None:
        # A client that suppresses everything makes no contact. Inferring delivery from a
        # contact would report that client as undelivered and lose the real result.
        client = _client(app)
        created = client.create_test(email=MAILBOX)
        store.mark_delivered(created.probe_id, None)
        assert client.get_state(created.test_id).delivered_at is not None
        assert client.get_observations(created.test_id).observations == ()


class ScriptedStore(InMemoryObservationStore):
    """A store that plays the whole collector pipeline when a probe is allocated.

    The adapter allocates its own probe, so a test cannot pre-record a contact against a
    probe it made itself. Scripting the delivery path, the watcher heartbeats, the vectors
    the canary offered, and the contacts that came back -- at the moment of allocation -- is
    what lets the adapter's own ``create_test`` see a window that looks like a real one.
    """

    def __init__(
        self,
        *,
        contacts: tuple[CallbackRequest, ...] = (),
        delivered: bool = True,
        third_party_hosts: tuple[str, ...] = (),
    ) -> None:
        super().__init__(third_party_hosts=third_party_hosts)
        self._scripted_contacts = contacts
        self._delivered = delivered

    def create(self, *, mailbox: str, window_seconds: int = 30):
        created = super().create(mailbox=mailbox, window_seconds=2)
        for name in self.required_watchers:
            self.heartbeat(_beat(name))
        if self._delivered:
            self.mark_delivered(created.probe_id, None)
        self.mark_exercised(created.probe_id, frozenset({"img"}))
        for contact in self._scripted_contacts:
            self.record(contact.model_copy(update={"probe_id": created.probe_id}))
        return created


def _adapter(app, *, open_asserted: bool | None):
    return EptGatewayAdapter(
        client=_client(app),
        mailboxes={SLOT: MAILBOX},
        poll_interval_seconds=0.01,
        open_observer=None if open_asserted is None else (lambda context: open_asserted),
    )


def _service(store: ScriptedStore, *, third_party_hosts: tuple[str, ...] = ()):
    return create_app(
        store=store,
        settings=Settings(token=TOKEN, window_seconds=2, third_party_hosts=third_party_hosts),
    )


def _leak(host: str) -> CallbackRequest:
    return CallbackRequest(
        probe_id="placeholder",
        vector="img",
        channel=ObservationChannel.HTTP,
        origin=ObservationOrigin.CLIENT,
        remote_host=host,
        referrer="https://mail.example.invalid/inbox",
    )


class TestTheAdapterRunsAgainstThisService:
    """The real adapter, the real client, the real service, one scripted pipeline."""

    def test_a_probe_the_client_never_opened_is_inconclusive(self) -> None:
        # Nothing displayed the message, so remote-content behaviour was never exercised
        # and no clean result may be claimed -- whatever the canary did or did not record.
        app = _service(ScriptedStore())
        check = _check()
        outcome = _run(_adapter(app, open_asserted=None), check, _context(check))
        assert outcome.status.value == "inconclusive"
        assert outcome.reason_code == "ept.open-not-asserted"

    def test_an_opened_probe_with_no_contact_passes(self) -> None:
        # The full pipeline ran, every watcher was healthy, and the canary saw nothing.
        app = _service(ScriptedStore())
        check = _check()
        outcome = _run(_adapter(app, open_asserted=True), check, _context(check))
        assert outcome.status.value == "pass"
        assert outcome.reason_code == "ept.no-remote-content-observed"
        assert outcome.details["delivered"] is True
        assert outcome.details["watchers_healthy"] is True

    def test_a_client_contact_becomes_a_failure(self) -> None:
        app = _service(ScriptedStore(contacts=(_leak(CANARY_HOST),)))
        check = _check()
        outcome = _run(_adapter(app, open_asserted=True), check, _context(check))
        assert outcome.status.value == "fail"
        assert outcome.reason_code == "ept.remote-content-detected"

    def test_a_third_party_referrer_survives_the_round_trip(self) -> None:
        # The case the gateway contract change was made for: a Referer reaching a host
        # outside the message, recorded verbatim by the service and adjudicated as a
        # disclosure to a party the reader did not choose to visit.
        app = _service(
            ScriptedStore(contacts=(_leak(THIRD_PARTY),), third_party_hosts=(THIRD_PARTY,)),
            third_party_hosts=(THIRD_PARTY,),
        )
        check = _check(check_id="email.referrer-disclosure")
        outcome = _run(_adapter(app, open_asserted=True), check, _context(check))
        assert outcome.status.value == "fail"
        assert outcome.reason_code == "ept.third-party-referrer-disclosed"

    def test_a_provider_contact_is_never_a_client_failure(self) -> None:
        contact = _leak(CANARY_HOST).model_copy(update={"origin": ObservationOrigin.PROVIDER})
        app = _service(ScriptedStore(contacts=(contact,)))
        check = _check()
        outcome = _run(_adapter(app, open_asserted=True), check, _context(check))
        assert outcome.status.value == "inconclusive"
        assert outcome.reason_code == "ept.provider-prefetch-only"

    def test_an_undelivered_probe_is_never_a_client_verdict(self) -> None:
        app = _service(ScriptedStore(delivered=False))
        check = _check()
        outcome = _run(_adapter(app, open_asserted=True), check, _context(check))
        assert outcome.status.value == "inconclusive"
        assert outcome.reason_code == "ept.message-not-delivered"


def _check(check_id: str = "email.remote-content"):
    from privacy_benchmark.spec.models import CheckDefinition

    return CheckDefinition(
        check_id=check_id,
        version="1.0.0",
        title="Contract conformance",
        description="A check used only to drive the adapter in these tests.",
        channel="email",
        evidence_class="measured",
        threat_models=(
            {
                "id": "mailbox.content-disclosure",
                "title": "Content disclosure",
                "description": "The canary learns the message was opened.",
            },
        ),
        runner_classes=("self_hosted_macos",),
        adapter_id="ept",
    )


def _context(check):
    from datetime import UTC, datetime
    from typing import Any, cast
    from uuid import uuid7

    from privacy_benchmark.harness.context import ExecutionContext
    from privacy_benchmark.spec.models import (
        AccountDefinition,
        ComponentRef,
        NetworkVantage,
        PlatformDefinition,
        SubjectConfiguration,
        SubjectDefinition,
    )

    subject = SubjectDefinition(
        subject_id="contract-subject",
        subject_version="1.0.0",
        client=ComponentRef(name="Test client"),
        service=ComponentRef(name="Example Mail"),
        platform=PlatformDefinition(os="macOS", architecture="x86_64", is_emulator=False),
        account=AccountDefinition(
            account_type="consumer", slot_id=SLOT, authentication_method="oauth2"
        ),
        configuration=SubjectConfiguration(),
        network_vantage=NetworkVantage(
            vantage_id="vantage-one", country_code="DE", network_type="residential"
        ),
    )
    from pathlib import Path

    return ExecutionContext(
        # The adapter never reads the plan, and a real one requires a suite that names a
        # provisioned subject. Casting is honest here; building a fake suite to satisfy a
        # type checker would not be.
        plan=cast("Any", None),
        subject=subject,
        checks=(check,),
        execution_id=uuid7(),
        execution_dir=Path("/tmp"),
        adapter_id="ept",
        repetition=1,
        started_at=datetime.now(UTC),
    )


def _run(adapter, check, context):
    import asyncio

    return asyncio.run(adapter.execute_check(check, context))
