"""Adapter boundary contract tests."""

from __future__ import annotations

import platform

import httpx
import pytest

from privacy_benchmark.adapters.automation import collect_automation_stack
from privacy_benchmark.adapters.ept import EptGatewayClient


def test_automation_stack_records_the_running_interpreter(monkeypatch: pytest.MonkeyPatch) -> None:
    # Provenance is attributed to the run, so the recorded interpreter must be the one
    # actually executing rather than a fixture value the test supplied.
    monkeypatch.setenv("ANDROID_HOME", "/opt/android-sdk-fixture")
    stack = collect_automation_stack()

    assert stack.python == platform.python_version()
    assert stack.platform == platform.platform()
    assert stack.android_sdk == "/opt/android-sdk-fixture"


def test_automation_stack_reports_no_sdk_when_the_runner_exports_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A measurement must never claim a toolchain it did not run on, so an undetermined
    # field stays None instead of being filled with a placeholder.
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)

    assert collect_automation_stack().android_sdk is None


def test_ept_gateway_uses_versioned_authenticated_endpoints() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer test-token"
        if request.method == "POST" and request.url.path == "/v1/tests":
            return httpx.Response(
                200,
                json={
                    "test_id": "test.one",
                    "probe_id": "probe.one",
                    "expires_at": "2026-09-25T16:00:00Z",
                },
            )
        if request.method == "GET" and request.url.path == "/v1/tests/test.one/observations":
            return httpx.Response(200, json={"test_id": "test.one", "observations": []})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    client = EptGatewayClient(
        base_url="https://gateway.invalid",
        token="test-token",
        transport=transport,
    )
    created = client.create_test(email="synthetic@example.invalid")
    observations = client.get_observations(created.test_id)

    assert created.probe_id == "probe.one"
    assert observations.test_id == created.test_id
