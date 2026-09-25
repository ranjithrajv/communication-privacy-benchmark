"""Adapter boundary contract tests."""

from __future__ import annotations

import httpx

from privacy_benchmark.adapters.automation import collect_automation_stack
from privacy_benchmark.adapters.ept import EptGatewayClient


def test_automation_stack_records_optional_client_versions() -> None:
    stack = collect_automation_stack(
        appium_server="3.7.0",
        appium_driver="fixture",
        node="24.21.0",
    )
    assert stack.appium_server == "3.7.0"
    assert stack.appium_driver == "fixture"
    assert stack.python.count(".") == 2
    assert stack.playwright is not None
    assert stack.appium_python_client is not None


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
