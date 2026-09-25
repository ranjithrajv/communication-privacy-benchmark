"""HTTP client for a future authenticated EPT gateway.

The benchmark does not call undocumented EPT routes directly.  A small private gateway
should expose this versioned contract and translate to the pinned upstream service.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from pydantic import BaseModel, ConfigDict, JsonValue

from privacy_benchmark.spec.models import Identifier, UtcDateTime


class GatewayTestCreated(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    test_id: Identifier
    probe_id: Identifier
    expires_at: UtcDateTime


class GatewayObservations(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    test_id: Identifier
    observations: tuple[dict[str, JsonValue], ...] = ()


@dataclass(frozen=True, slots=True)
class EptGatewayClient:
    base_url: str
    token: str
    timeout_seconds: float = 30.0
    transport: httpx.BaseTransport | None = None

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=self.timeout_seconds,
            follow_redirects=False,
            transport=self.transport,
        )

    def create_test(self, *, email: str, language: str = "en") -> GatewayTestCreated:
        with self._client() as client:
            response = client.post("/v1/tests", json={"email": email, "language": language})
            response.raise_for_status()
            return GatewayTestCreated.model_validate(response.json())

    def get_observations(self, test_id: str) -> GatewayObservations:
        with self._client() as client:
            response = client.get(f"/v1/tests/{test_id}/observations")
            response.raise_for_status()
            payload = GatewayObservations.model_validate(response.json())
        if payload.test_id != test_id:
            raise ValueError("gateway returned observations for the wrong test")
        return payload
