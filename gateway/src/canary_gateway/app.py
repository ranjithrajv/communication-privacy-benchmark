"""The canary gateway's HTTP surface.

Implements the three routes in ``infra/ept/README.md`` plus the write path the collectors
use. Three things here are deliberate and are the reason this service is worth building
rather than proxying to upstream:

* **Watcher health is a heartbeat, never a flag.** ``watchers_healthy`` is computed from
  whether every required collector has checked in recently. A service that hardcoded it
  would turn every unwatched window into a reported clean client, which is the single
  worst failure available to this benchmark.
* **The ``Referer`` header is recorded verbatim.** The adapter refuses to report a clean
  client unless the gateway declares it captured, so the declaration here is a promise
  this code has to keep.
* **Contacts for an unknown or expired probe are refused.** An observation nobody
  allocated is not evidence about anything.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status

from canary_gateway.models import (
    DEFAULT_WINDOW_SECONDS,
    CallbackRequest,
    CreateTestRequest,
    MarkDeliveredRequest,
    ObservationList,
    TestCreated,
    TestState,
    WatcherHealth,
    WatcherHeartbeat,
    utc_now,
)
from canary_gateway.store import (
    InMemoryObservationStore,
    ObservationStore,
    ProbeExpired,
    UnknownProbe,
)


@dataclass(slots=True)
class Settings:
    """Run-time configuration. No secret is ever read from a checked-in file."""

    token: str
    third_party_hosts: tuple[str, ...] = ()
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    #: The collectors a complete observation set needs. Overridable so a deployment can
    #: add a collector without a code change, but never to an empty set: an empty set
    #: would make every window trivially healthy.
    required_watchers: frozenset[str] = frozenset({"http", "dns", "sni"})

    @classmethod
    def from_environment(cls, environ: dict[str, str] | None = None) -> Settings:
        env = os.environ if environ is None else environ
        token = env.get("CANARY_GATEWAY_TOKEN", "")
        if not token:
            # Refusing to start is the correct behaviour: a gateway with no token would
            # accept an invented contact from anyone, and an invented contact is a failed
            # measurement that looks like a disclosure.
            raise RuntimeError("CANARY_GATEWAY_TOKEN must be set")
        hosts = env.get("CANARY_GATEWAY_THIRD_PARTY_HOSTS", "")
        watchers = env.get("CANARY_GATEWAY_REQUIRED_WATCHERS", "http,dns,sni")
        required = frozenset(part.strip() for part in watchers.split(",") if part.strip())
        if not required:
            raise RuntimeError("CANARY_GATEWAY_REQUIRED_WATCHERS must name at least one watcher")
        return cls(
            token=token,
            third_party_hosts=tuple(h.strip() for h in hosts.split(",") if h.strip()),
            required_watchers=required,
        )


def _unauthorised() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="a valid bearer token is required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def create_app(
    store: ObservationStore | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    """Build the service.

    Both dependencies are injectable so the contract tests can run the real application
    against a real store without a socket, a token from the environment, or a database.
    """
    resolved_settings = settings or Settings.from_environment()
    # A store is configured where it is built. The app does not reach in and widen its
    # watcher set afterwards, because a health verdict that depends on a mutation made
    # after construction is a verdict nobody can point at.
    resolved_store: ObservationStore = store or InMemoryObservationStore(
        third_party_hosts=resolved_settings.third_party_hosts,
        required_watchers=resolved_settings.required_watchers,
    )

    app = FastAPI(
        title="Privacy benchmark canary gateway",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
    )
    app.state.store = resolved_store
    app.state.settings = resolved_settings

    def authenticate(authorization: Annotated[str | None, Header()] = None) -> None:
        if not authorization or not authorization.startswith("Bearer "):
            raise _unauthorised()
        if authorization.removeprefix("Bearer ").strip() != resolved_settings.token:
            raise _unauthorised()

    auth = [Depends(authenticate)]

    def probe_or_404(test_id: str) -> None:
        try:
            resolved_store.get(test_id)
        except UnknownProbe as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="unknown test id"
            ) from error

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/watchers/health", response_model=WatcherHealth, dependencies=auth)
    def watchers_health() -> WatcherHealth:
        return WatcherHealth(
            watchers=resolved_store.heartbeats(), healthy=resolved_store.watchers_healthy()
        )

    @app.post("/v1/watchers/heartbeat", dependencies=auth)
    def watcher_heartbeat(beat: WatcherHeartbeat) -> dict[str, str]:
        resolved_store.heartbeat(beat)
        return {"status": "recorded"}

    @app.post("/v1/tests", response_model=TestCreated, status_code=201, dependencies=auth)
    def create_test(body: CreateTestRequest) -> TestCreated:
        return resolved_store.create(
            mailbox=body.email, window_seconds=resolved_settings.window_seconds
        )

    @app.get("/v1/tests/{test_id}/state", response_model=TestState, dependencies=auth)
    def test_state(test_id: str) -> TestState:
        probe_or_404(test_id)
        return resolved_store.state(test_id)

    @app.get("/v1/tests/{test_id}/observations", response_model=ObservationList, dependencies=auth)
    def test_observations(test_id: str) -> ObservationList:
        probe_or_404(test_id)
        return ObservationList(
            test_id=test_id, observations=tuple(resolved_store.observations(test_id))
        )

    @app.post("/v1/contacts", status_code=201, dependencies=auth)
    def record_contact(body: CallbackRequest) -> dict[str, str]:
        try:
            observation = resolved_store.record(body)
        except UnknownProbe as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="unknown probe id"
            ) from error
        except ProbeExpired as error:
            # 409 rather than 202: the contact is real but outside the measurement, and a
            # collector that treats it as accepted would under-report what it saw.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="probe window has closed"
            ) from error
        return {"status": "recorded", "vector": observation.vector}

    @app.post("/v1/tests/delivered", dependencies=auth)
    def mark_delivered(body: MarkDeliveredRequest) -> dict[str, str]:
        try:
            resolved_store.mark_delivered(body.probe_id, body.delivered_at)
        except UnknownProbe as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="unknown probe id"
            ) from error
        return {"status": "recorded"}

    return app


@dataclass(slots=True)
class CanaryRoutes:
    """The canary-facing routes a real browser hits, mounted beside the API.

    Kept separate from the API because these are the only routes reachable without a
    token: a reader of the message has no token, and the canary URLs must work for them.
    They can only *add* an observation for a probe that was already allocated, so being
    unauthenticated cannot manufacture a measurement.
    """

    store: ObservationStore
    settings: Settings
    app: FastAPI = field(default_factory=lambda: FastAPI(docs_url=None, redoc_url=None))

    def mount(self) -> FastAPI:
        @self.app.get("/canary/{probe_id}/{vector}", include_in_schema=False)
        def canary_contact(
            probe_id: str,
            vector: str,
            referer: Annotated[str | None, Header()] = None,
            user_agent: Annotated[str | None, Header()] = None,
        ) -> dict[str, str]:
            self.store.record(
                CallbackRequest(
                    probe_id=probe_id,
                    vector=vector,
                    channel="http",  # type: ignore[arg-type]
                    # A contact from the reader's own browser is client-attributable; the
                    # provider's prefetcher is recorded by the mail path instead, which is
                    # the only place that can tell the two apart.
                    origin="client",  # type: ignore[arg-type]
                    remote_host="canary.invalid",
                    referrer=referer,
                    detail={"user_agent": user_agent} if user_agent else {},
                )
            )
            return {"status": "ok"}

        return self.app


def iter_probes(store: ObservationStore) -> Iterator[str]:
    """Every allocated probe id, for diagnostics and expiry sweeps."""
    yield from getattr(store, "_by_probe", {})


__all__ = [
    "CanaryRoutes",
    "Settings",
    "create_app",
    "iter_probes",
    "utc_now",
]
