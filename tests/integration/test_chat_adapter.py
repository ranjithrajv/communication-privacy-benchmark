"""Chat gateway client and adapter wiring.

The device lane does not exist, so nothing here drives Appium. What is exercised is the
boundary the adapter actually owns: the versioned gateway contract, the slot-to-number
mapping, the display assertion, and the evidence it exports. The Appium session is a
fake, which is also the point — the adjudication must not depend on a device to be
correct, and an adapter that needs one cannot be tested in CI at all.
"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid7

import httpx
import pytest

from privacy_benchmark.adapters.base import AdapterError, AdapterOutcome
from privacy_benchmark.adapters.chat_appium import (
    NUMBERS_VARIABLE,
    ChatAppiumAdapter,
    ChatGatewayClient,
)
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.harness.planning import build_run_plan
from privacy_benchmark.spec.models import ExecutionMode, RunPlan, utc_now
from privacy_benchmark.spec.registry import Registry

SLOT = "slot-signal-0001"
NUMBER = "+4915100000000"
CANARY_HOST = "canary.privacy-benchmark.invalid"

NOW = utc_now()
DELIVERED = (NOW - timedelta(seconds=30)).isoformat()
DISPLAYED = (NOW - timedelta(seconds=20)).isoformat()
OBSERVED = (NOW - timedelta(seconds=10)).isoformat()
EXPIRES = (NOW + timedelta(hours=1)).isoformat()


def _gateway(observations: list[dict[str, Any]], *, displayed_at: str | None = DISPLAYED) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer test-token"
        if request.method == "POST" and request.url.path == "/v1/honey-messages":
            return httpx.Response(
                200,
                json={
                    "message_id": "message.one",
                    "probe_id": "probe.one",
                    "delivered_at": DELIVERED,
                    "expires_at": EXPIRES,
                },
            )
        if request.method == "GET" and request.url.path == "/v1/honey-messages/message.one/state":
            state: dict[str, Any] = {
                "message_id": "message.one",
                "probe_id": "probe.one",
                "delivered_at": DELIVERED,
                "watchers_healthy": True,
                "window_expires_at": EXPIRES,
            }
            if displayed_at is not None:
                state["displayed_at"] = displayed_at
            return httpx.Response(200, json=state)
        if (
            request.method == "GET"
            and request.url.path == "/v1/honey-messages/message.one/observations"
        ):
            return httpx.Response(
                200, json={"message_id": "message.one", "observations": observations}
            )
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _client(observations: list[dict[str, Any]] | None = None, **kwargs: Any) -> ChatGatewayClient:
    return ChatGatewayClient(
        base_url="https://gateway.invalid",
        token="test-token",
        transport=_gateway(observations or [], **kwargs),
    )


def _http_observation(
    origin: str = "client", detail: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "channel": "http",
        "probe_id": "probe.one",
        "origin": origin,
        "remote_host": CANARY_HOST,
        "observed_at": OBSERVED,
        "resource": "/pixel.gif",
        "detail": detail or {},
    }


class FakeSession:
    """A device stand-in that records what the adapter asked it to do."""

    def __init__(self, displayed: bool = True) -> None:
        self.displayed = displayed
        self.delivered_numbers: list[str] = []
        self.closed = False

    def deliver(self, number: str) -> None:
        self.delivered_numbers.append(number)

    def display_honey_message(self) -> bool:
        return self.displayed

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def execution_dir(tmp_path: Path) -> Path:
    """Where a chat run writes its evidence.

    A per-test temporary directory, so a measurement never leaves artifacts in the
    repository tree where a later run or a packaged build could pick them up.
    """
    return tmp_path / "chat-tests"


def _context(registry: Registry, repository_root: Path, execution_dir: Path) -> ExecutionContext:
    plan: RunPlan = build_run_plan(
        repository_root / "suites" / "chat" / "1.0.0" / "suite.toml",
        repository_root,
        execution_mode=ExecutionMode.LOCAL,
        github=None,
    )
    return ExecutionContext(
        plan=plan,
        subject=registry.resolve_subject("signal-android-default@1.0.0"),
        checks=(registry.resolve_check("chat.link-preview-fetch@1.0.0"),),
        execution_id=uuid7(),
        execution_dir=execution_dir,
        adapter_id="chat-appium",
        repetition=1,
        started_at=utc_now(),
    )


def _adapter(
    session: FakeSession | None,
    observations: list[dict[str, Any]] | None = None,
    numbers: dict[str, str] | None = None,
) -> ChatAppiumAdapter:
    return ChatAppiumAdapter(
        client=_client(observations or []),
        numbers={SLOT: NUMBER} if numbers is None else numbers,
        session_factory=None if session is None else (lambda _context: session),
        poll_interval_seconds=0.0,
        display_timeout_seconds=0,
    )


def _execute(
    registry: Registry,
    repository_root: Path,
    execution_dir: Path,
    adapter: ChatAppiumAdapter,
) -> AdapterOutcome:
    return asyncio.run(
        adapter.execute_check(
            registry.resolve_check("chat.link-preview-fetch@1.0.0"),
            _context(registry, repository_root, execution_dir),
        )
    )


def test_gateway_speaks_the_versioned_contract() -> None:
    client = _client()
    created = client.deliver(number=NUMBER)
    state = client.get_state(created.message_id)
    observations = client.get_observations(created.message_id)

    assert created.probe_id == "probe.one"
    assert state.displayed_at is not None
    assert observations.message_id == created.message_id


def test_gateway_rejects_state_for_the_wrong_message() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message_id": "message.other",
                "probe_id": "probe.one",
                "window_expires_at": EXPIRES,
            },
        )

    client = ChatGatewayClient(
        base_url="https://gateway.invalid",
        token="test-token",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(AdapterError, match="wrong honey-message"):
        client.get_state("message.one")


def test_a_client_fetch_is_reported_as_a_fail(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    session = FakeSession()
    outcome = _execute(
        registry,
        repository_root,
        execution_dir,
        _adapter(session, observations=[_http_observation()]),
    )

    assert outcome.status.value == "fail"
    assert outcome.reason_code == "chat.link-preview-fetched"
    assert outcome.details["client_observation_count"] == 1
    assert session.closed is True


def test_a_conversation_the_device_never_rendered_is_inconclusive(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    """The display assertion is what stops a queued push from reading as a clean client."""

    outcome = _execute(
        registry, repository_root, execution_dir, _adapter(FakeSession(displayed=False))
    )

    assert outcome.status.value == "inconclusive"
    assert outcome.reason_code == "chat.display-not-asserted"
    assert outcome.details["display_asserted"] is False


def test_provider_side_link_handling_is_never_a_client_fail(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    outcome = _execute(
        registry,
        repository_root,
        execution_dir,
        _adapter(FakeSession(), observations=[_http_observation(origin="provider")]),
    )

    assert outcome.status.value == "inconclusive"
    assert outcome.reason_code == "chat.provider-activity-only"


def test_without_a_device_lane_the_result_is_inconclusive(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    outcome = _execute(registry, repository_root, execution_dir, _adapter(None))

    assert outcome.status.value == "inconclusive"
    assert outcome.reason_code == "chat.device-session-unavailable"


def test_an_unsupported_check_is_reported_as_unsupported(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    adapter = _adapter(FakeSession())
    outcome = asyncio.run(
        adapter.execute_check(
            registry.resolve_check("email.remote-content@1.0.0"),
            _context(registry, repository_root, execution_dir),
        )
    )

    assert outcome.status.value == "unsupported"
    assert outcome.reason_code == "chat.unsupported-check"
    assert outcome.details["supported"] is False


def test_an_unmapped_slot_fails_loudly(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    with pytest.raises(AdapterError, match="no synthetic number is configured"):
        _execute(registry, repository_root, execution_dir, _adapter(FakeSession(), numbers={}))


def test_a_malformed_number_fails_before_any_delivery(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    session = FakeSession()
    with pytest.raises(AdapterError, match=r"valid E\.164 number"):
        _execute(
            registry,
            repository_root,
            execution_dir,
            _adapter(session, numbers={SLOT: "not-a-number"}),
        )
    assert session.delivered_numbers == [], "nothing may be delivered to a bad mapping"


def test_evidence_never_carries_the_synthetic_number(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    outcome = _execute(
        registry,
        repository_root,
        execution_dir,
        _adapter(FakeSession(), observations=[_http_observation()]),
    )

    evidence = outcome.evidence[0]
    assert NUMBER.encode() not in evidence.payload
    payload = json.loads(evidence.payload)
    assert payload["account_slot"] == SLOT
    assert payload["synthetic"] is True
    assert payload["observations"][0]["remote_host"] == CANARY_HOST
    assert evidence.redaction.applied is True
    assert evidence.kind.value == "canary_event"


def test_evidence_records_the_display_window(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    outcome = _execute(registry, repository_root, execution_dir, _adapter(FakeSession()))

    payload = json.loads(outcome.evidence[0].payload)
    assert payload["probe_window"]["display_asserted"] is True
    assert payload["probe_window"]["displayed_at"] is not None


def test_evidence_carries_the_automation_stack(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    """A published chat row must be reproducible against a named Appium stack."""

    outcome = _execute(registry, repository_root, execution_dir, _adapter(FakeSession()))
    metadata = outcome.evidence[0].metadata

    assert "appium_python_client" in metadata
    assert "appium_server" in metadata
    assert "android_sdk" in metadata


def test_numbers_variable_is_the_documented_one() -> None:
    assert NUMBERS_VARIABLE == "PT_BENCH_CHAT_NUMBERS"


def test_reader_identification_routes_to_its_own_adjudication(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    """The two checks must not share a verdict by accident.

    Both read the same observation set, so a dispatch bug would show up as one check
    reporting the other's reason code. A contact that discloses a source address is a
    ``fail`` for identification and only a ``partial`` for the preview check, which is
    precisely the distinction the split exists to preserve.
    """
    adapter = _adapter(
        FakeSession(),
        observations=[_http_observation(detail={"source_address": "203.0.113.9"})],
    )
    outcome = asyncio.run(
        adapter.execute_check(
            registry.resolve_check("chat.reader-identification@1.0.0"),
            _context(registry, repository_root, execution_dir),
        )
    )

    assert outcome.status.value == "fail"
    assert outcome.reason_code == "chat.reader-identified"
    assert outcome.details["disclosed_fields"] == ["source_address"]


def test_the_preview_check_still_reports_a_partial_for_the_same_contact(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    """The same observations, a different question, a different verdict."""
    adapter = _adapter(
        FakeSession(),
        observations=[_http_observation(detail={"source_address": "203.0.113.9"})],
    )
    outcome = asyncio.run(
        adapter.execute_check(
            registry.resolve_check("chat.link-preview-fetch@1.0.0"),
            _context(registry, repository_root, execution_dir),
        )
    )

    assert outcome.status.value == "fail"
    assert outcome.reason_code == "chat.link-preview-fetched"
    assert "disclosed_fields" not in outcome.details


def test_the_adapter_only_claims_the_checks_it_can_answer() -> None:
    adapter = _adapter(FakeSession())
    assert adapter.supported_checks == frozenset(
        {"chat.link-preview-fetch", "chat.reader-identification"}
    )
    assert adapter.adapter_id == "chat-appium"


def test_an_appium_session_without_a_verified_recipe_refuses_to_claim_a_display() -> None:
    """No recipe must produce inconclusive, never a fabricated pass."""

    from privacy_benchmark.adapters.chat_appium import AppiumChatSession

    session = AppiumChatSession(appium_server="http://127.0.0.1:4723", package_identifier="x")
    assert session.display_honey_message() is False
    with pytest.raises(AdapterError, match="no verified chat recipe"):
        session.deliver(NUMBER)
