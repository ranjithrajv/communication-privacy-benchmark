"""End-to-end webmail adapter execution through the real harness.

The canary gateway is mocked at the HTTP boundary, exactly as in ``test_ept_adapter``:
that is the seam this project owns. Everything below it -- the adapter, the readiness
gates, and the shared adjudication -- is the production path. No browser is launched;
``WebmailSession`` is a protocol precisely so the reasoning that decides a verdict can be
tested without one.

The gateway and the fake session write to one shared event log, because the ordering
between them is the part most worth pinning and the part a per-object assertion would
miss: a webmail message arrives asynchronously, so driving the browser before delivery
is confirmed would report a client that refused to open a message that had not arrived.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid7

import httpx

from privacy_benchmark.adapters.ept import EptGatewayClient
from privacy_benchmark.adapters.webmail_playwright import (
    WebmailCredentials,
    WebmailPlaywrightAdapter,
    browser_lane_available,
    webmail_credentials_from_environment,
)
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.spec.models import (
    AccountDefinition,
    CheckDefinition,
    ComponentRef,
    NetworkVantage,
    PlatformDefinition,
    ResultStatus,
    RunPlan,
    SubjectConfiguration,
    SubjectDefinition,
    WebmailAutomation,
)

DELIVERED = "2026-09-25T12:00:00Z"
CANARY_HOST = "canary.privacy-benchmark.invalid"
SLOT = "slot-webmail-0001"
ENTRY_URL = "https://mail.example.invalid/index.php"

RECIPE = {
    "entry_url": ENTRY_URL,
    "user_field": "input[name='user']",
    "password_field": "input[name='pass']",
    "submit_field": "button[type='submit']",
    "message_row": "tr.message",
    "message_open": "tr.message a.subject",
    "message_body": "div#message-body",
    "ready_marker": "div#message-list",
}


class FakeGateway:
    """A scripted EPT gateway served over a mocked transport, sharing one event log."""

    def __init__(
        self,
        log: list[str],
        *,
        observations: tuple[dict[str, object], ...] = (),
        delivered: bool = True,
        watchers_healthy: bool = True,
        poll_interval_seconds: float = 0.02,
        window_seconds: float = 1.0,
    ) -> None:
        self.log = log
        self.observations = observations
        self.delivered = delivered
        self.watchers_healthy = watchers_healthy
        self.poll_interval_seconds = poll_interval_seconds
        self.window_expires_at = (datetime.now(UTC) + timedelta(seconds=window_seconds)).isoformat()

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer test-token"
        if request.method == "POST" and request.url.path == "/v1/tests":
            self.log.append("gateway:create")
            return httpx.Response(
                200,
                json={
                    "test_id": "test.one",
                    "probe_id": "probe.one",
                    "expires_at": self.window_expires_at,
                },
            )
        if request.method == "GET" and request.url.path == "/v1/tests/test.one/state":
            self.log.append("gateway:state")
            return httpx.Response(
                200,
                json={
                    "test_id": "test.one",
                    "probe_id": "probe.one",
                    "delivered_at": DELIVERED if self.delivered else None,
                    "watchers_healthy": self.watchers_healthy,
                    "window_expires_at": self.window_expires_at,
                    "exercised": ["img", "cssBackgroundImage"],
                },
            )
        if request.method == "GET" and request.url.path == "/v1/tests/test.one/observations":
            self.log.append("gateway:observations")
            return httpx.Response(
                200, json={"test_id": "test.one", "observations": list(self.observations)}
            )
        return httpx.Response(404)


class FakeSession:
    """A scripted browser. Records what it was asked to do and in what order."""

    def __init__(self, log: list[str], *, opened: bool = True) -> None:
        self.log = log
        self.opened = opened
        self.closed = False

    def __call__(self, **_: object) -> FakeSession:
        return self

    async def log_in(self) -> None:
        self.log.append("session:log_in")

    async def open_message(self) -> bool:
        self.log.append("session:open")
        return self.opened

    async def close(self) -> None:
        self.log.append("session:close")
        self.closed = True


def _observation(
    *, vector: str = "img", origin: str = "client", probe_id: str = "probe.one"
) -> dict[str, object]:
    return {
        "channel": "http",
        "probe_id": probe_id,
        "vector": vector,
        "origin": origin,
        "remote_host": CANARY_HOST,
        "observed_at": "2026-09-25T12:01:05Z",
    }


def _check() -> CheckDefinition:
    return CheckDefinition(
        check_id="webmail.remote-content",
        version="1.0.0",
        title="Remote content on open",
        description="A webmail check the adapter answers.",
        channel="webmail",
        evidence_class="measured",
        threat_models=(
            {
                "id": "webmail.read-disclosure",
                "title": "Read disclosure",
                "description": "The canary learns the message was opened.",
            },
        ),
        runner_classes=("self_hosted_regional",),
        adapter_id="webmail-playwright",
    )


def _subject(*, with_recipe: bool = True) -> SubjectDefinition:
    return SubjectDefinition(
        subject_id="roundcube-webmail-consumer",
        subject_version="1.0.0",
        client=ComponentRef(name="Chromium"),
        service=ComponentRef(name="Example Mail"),
        platform=PlatformDefinition(os="Linux", architecture="x86_64", is_emulator=False),
        account=AccountDefinition(
            account_type="consumer-webmail",
            slot_id=SLOT,
            authentication_method="password",
        ),
        configuration=SubjectConfiguration(),
        network_vantage=NetworkVantage(
            vantage_id="webmail-lane-unselected",
            country_code="DE",
            network_type="residential-unselected",
        ),
        webmail=WebmailAutomation(**RECIPE) if with_recipe else None,
    )


def _context(
    plan: RunPlan, subject: SubjectDefinition, check: CheckDefinition, tmp_path: Path
) -> ExecutionContext:
    return ExecutionContext(
        plan=plan,
        subject=subject,
        checks=(check,),
        execution_id=uuid7(),
        execution_dir=tmp_path,
        adapter_id="webmail-playwright",
        repetition=1,
        started_at=datetime.now(UTC),
    )


def _adapter(gateway: FakeGateway, session: object | None) -> WebmailPlaywrightAdapter:
    return WebmailPlaywrightAdapter(
        client=EptGatewayClient(
            base_url="https://gateway.invalid",
            token="test-token",
            transport=httpx.MockTransport(gateway.handler),
        ),
        credentials={SLOT: WebmailCredentials(username="probe", password="synthetic")},
        session_factory=session,
        poll_interval_seconds=gateway.poll_interval_seconds,
    )


def _run(
    *,
    plan: RunPlan,
    tmp_path: Path,
    gateway: FakeGateway,
    session: object | None,
    subject: SubjectDefinition | None = None,
    check: CheckDefinition | None = None,
):
    the_subject = subject or _subject()
    the_check = check or _check()
    adapter = _adapter(gateway, session)
    context = _context(plan, the_subject, the_check, tmp_path)
    return asyncio.run(adapter.execute_check(the_check, context)), adapter


class TestTheLaneMustExist:
    def test_no_session_factory_is_unexercised_not_a_pass(self, local_plan, tmp_path) -> None:
        log: list[str] = []
        outcome, _ = _run(
            plan=local_plan, tmp_path=tmp_path, gateway=FakeGateway(log), session=None
        )
        assert outcome.status is ResultStatus.INCONCLUSIVE
        assert outcome.reason_code == "webmail.lane-unavailable"
        # A missing lane must not touch the gateway: nothing was measured, and creating a
        # probe would leave a canary test open that nobody will ever collect.
        assert log == []

    def test_the_lane_flag_alone_does_not_enable_a_browser(self) -> None:
        assert browser_lane_available({}) is False
        assert browser_lane_available({"PRIVACY_BENCHMARK_BROWSER_LANE": ""}) is False
        assert browser_lane_available({"PRIVACY_BENCHMARK_BROWSER_LANE": "0"}) is False
        assert browser_lane_available({"PRIVACY_BENCHMARK_BROWSER_LANE": "1"}) is True


class TestTheSubjectMustBeDrivable:
    def test_a_subject_without_a_recipe_is_unexercised(self, local_plan, tmp_path) -> None:
        log: list[str] = []
        outcome, _ = _run(
            plan=local_plan,
            tmp_path=tmp_path,
            gateway=FakeGateway(log),
            session=FakeSession(log),
            subject=_subject(with_recipe=False),
        )
        assert outcome.status is ResultStatus.INCONCLUSIVE
        assert outcome.reason_code == "webmail.recipe-missing"
        assert log == []

    def test_missing_credentials_are_unexercised(self, local_plan, tmp_path) -> None:
        log: list[str] = []
        gateway = FakeGateway(log)
        adapter = WebmailPlaywrightAdapter(
            client=EptGatewayClient(
                base_url="https://gateway.invalid",
                token="test-token",
                transport=httpx.MockTransport(gateway.handler),
            ),
            session_factory=FakeSession(log),
        )
        context = _context(local_plan, _subject(), _check(), tmp_path)
        outcome = asyncio.run(adapter.execute_check(_check(), context))
        assert outcome.status is ResultStatus.INCONCLUSIVE
        assert outcome.reason_code == "webmail.credentials-missing"
        assert log == []


class TestMeasurementOrdering:
    def test_delivery_is_confirmed_before_the_browser_is_driven(self, local_plan, tmp_path) -> None:
        log: list[str] = []
        outcome, _ = _run(
            plan=local_plan,
            tmp_path=tmp_path,
            gateway=FakeGateway(log),
            session=FakeSession(log),
        )
        assert outcome.status is ResultStatus.PASS
        assert log.index("gateway:state") < log.index("session:log_in")
        assert log.index("session:log_in") < log.index("session:open")

    def test_an_undelivered_probe_is_inconclusive_and_the_browser_is_never_driven(
        self, local_plan, tmp_path
    ) -> None:
        log: list[str] = []
        outcome, _ = _run(
            plan=local_plan,
            tmp_path=tmp_path,
            gateway=FakeGateway(log, delivered=False),
            session=FakeSession(log),
        )
        assert outcome.status is ResultStatus.INCONCLUSIVE
        assert outcome.reason_code == "ept.message-not-delivered"
        assert "session:open" not in log

    def test_the_browser_is_closed_even_when_the_open_fails(self, local_plan, tmp_path) -> None:
        log: list[str] = []
        session = FakeSession(log, opened=False)
        outcome, _ = _run(
            plan=local_plan, tmp_path=tmp_path, gateway=FakeGateway(log), session=session
        )
        assert outcome.status is ResultStatus.INCONCLUSIVE
        assert outcome.reason_code == "ept.open-not-asserted"
        assert session.closed is True


class TestWhatTheCanaryObserved:
    def test_a_client_fetch_is_a_failure(self, local_plan, tmp_path) -> None:
        log: list[str] = []
        outcome, _ = _run(
            plan=local_plan,
            tmp_path=tmp_path,
            gateway=FakeGateway(log, observations=(_observation(vector="cssBackgroundImage"),)),
            session=FakeSession(log),
        )
        assert outcome.status is ResultStatus.FAIL
        assert outcome.reason_code == "ept.remote-content-detected"
        assert outcome.details["observation_count"] == 1
        assert outcome.details["client_observation_count"] == 1
        assert outcome.details["open_asserted"] is True

    def test_a_provider_fetch_is_never_a_client_result(self, local_plan, tmp_path) -> None:
        log: list[str] = []
        outcome, _ = _run(
            plan=local_plan,
            tmp_path=tmp_path,
            gateway=FakeGateway(log, observations=(_observation(vector="img", origin="provider"),)),
            session=FakeSession(log),
        )
        assert outcome.status is ResultStatus.INCONCLUSIVE
        assert outcome.reason_code == "ept.provider-prefetch-only"
        assert outcome.details["provider_observation_count"] == 1

    def test_unhealthy_watchers_cannot_report_a_clean_product(self, local_plan, tmp_path) -> None:
        log: list[str] = []
        outcome, _ = _run(
            plan=local_plan,
            tmp_path=tmp_path,
            gateway=FakeGateway(log, watchers_healthy=False),
            session=FakeSession(log),
        )
        assert outcome.status is ResultStatus.INCONCLUSIVE
        assert outcome.reason_code == "ept.watchers-unhealthy"

    def test_a_silent_run_passes_and_records_the_entry_host(self, local_plan, tmp_path) -> None:
        log: list[str] = []
        outcome, _ = _run(
            plan=local_plan, tmp_path=tmp_path, gateway=FakeGateway(log), session=FakeSession(log)
        )
        assert outcome.status is ResultStatus.PASS
        assert outcome.details["entry_url_host"] == "mail.example.invalid"
        assert outcome.details["account_slot"] == SLOT
        # The published row must carry the vantage, not the recipe.
        assert "user_field" not in json.dumps(outcome.details)

    def test_an_unsupported_check_names_what_the_adapter_answers(
        self, local_plan, tmp_path
    ) -> None:
        log: list[str] = []
        check = _check().model_copy(update={"check_id": "webmail.not-a-check"})
        outcome, _ = _run(
            plan=local_plan,
            tmp_path=tmp_path,
            gateway=FakeGateway(log),
            session=FakeSession(log),
            check=check,
        )
        assert outcome.status is ResultStatus.UNSUPPORTED
        assert outcome.reason_code == "webmail.unsupported-check"
        assert log == []


class TestCredentialsFromEnvironment:
    def test_both_halves_are_required(self) -> None:
        env = {
            "PRIVACY_BENCHMARK_WEBMAIL_slot-webmail-0001_USERNAME": "probe",
            "PRIVACY_BENCHMARK_WEBMAIL_slot-webmail-0001_PASSWORD": "synthetic",
        }
        creds = webmail_credentials_from_environment(env)
        assert creds[SLOT].username == "probe"
        assert creds[SLOT].password == "synthetic"

    def test_a_password_without_a_username_is_not_an_account(self) -> None:
        env = {"PRIVACY_BENCHMARK_WEBMAIL_slot-webmail-0001_PASSWORD": "synthetic"}
        assert webmail_credentials_from_environment(env) == {}

    def test_an_empty_value_is_not_an_account(self) -> None:
        env = {
            "PRIVACY_BENCHMARK_WEBMAIL_slot-webmail-0001_USERNAME": "",
            "PRIVACY_BENCHMARK_WEBMAIL_slot-webmail-0001_PASSWORD": "synthetic",
        }
        assert webmail_credentials_from_environment(env) == {}

    def test_unrelated_variables_are_ignored(self) -> None:
        env = {"HOME": "/root", "PRIVACY_BENCHMARK_EMAIL_TOKEN": "x"}
        assert webmail_credentials_from_environment(env) == {}
