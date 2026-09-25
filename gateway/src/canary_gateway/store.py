"""Observation storage behind a narrow interface.

The store is a :class:`Protocol` rather than a concrete database so the service can be
exercised end to end without PostgreSQL, and so the persistent deployment is a
substitution rather than a rewrite. The decision record allows PostgreSQL with SQLAlchemy
Core for the deployed service; it does not require it in the first increment, and adding
it before anything can call the service would be a dependency with no user.

The in-memory implementation is not a mock. It enforces the same invariants the persistent
one must, because those invariants are what make a result trustworthy: a contact for an
unknown or expired probe is refused rather than stored, and a probe's observations are
returned only for that probe.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from canary_gateway.models import (
    DEFAULT_WINDOW_SECONDS,
    CallbackRequest,
    Observation,
    ObservationOrigin,
    TestCreated,
    TestState,
    WatcherHeartbeat,
    utc_now,
)


class StoreError(Exception):
    """The store refused an operation. Carries a reason the API can map to a status."""


class UnknownProbe(StoreError):
    """The probe id is not one this service allocated."""


class ProbeExpired(StoreError):
    """The probe's window has closed, so it can no longer accept contacts."""


@dataclass(slots=True)
class Probe:
    test_id: str
    probe_id: str
    mailbox: str
    window_expires_at: datetime
    delivered_at: datetime | None = None
    exercised: frozenset[str] = frozenset()
    referer_captured: bool = True
    third_party_hosts: tuple[str, ...] = ()
    observations: list[Observation] = field(default_factory=list)


class ObservationStore(Protocol):
    """What the API needs from persistence, and nothing more.

    Declared with the read shapes the routes return rather than the rows they are built
    from, so a store that has to reshape on the way out is free to. Every member here is
    called by the API; adding one that nothing calls would make this an aspiration rather
    than a contract.
    """

    required_watchers: frozenset[str]

    def create(self, *, mailbox: str, window_seconds: int = ...) -> TestCreated: ...

    def get(self, test_id: str) -> Probe: ...

    def state(self, test_id: str) -> TestState: ...

    def observations(self, test_id: str) -> tuple[Observation, ...]: ...

    def record(self, contact: CallbackRequest) -> Observation: ...

    def mark_delivered(self, probe_id: str, delivered_at: datetime | None) -> None: ...

    def mark_exercised(self, probe_id: str, vectors: frozenset[str]) -> None: ...

    def heartbeat(self, beat: WatcherHeartbeat) -> None: ...

    def heartbeats(self) -> dict[str, datetime]: ...

    def watchers_healthy(self) -> bool: ...


class InMemoryObservationStore:
    """The reference implementation, and the one the contract tests run against.

    A watcher is considered healthy only while it has checked in within
    ``watcher_grace``. Nothing here can report healthy without a recorded heartbeat, so a
    freshly started service reports unhealthy until its collectors announce themselves —
    which is the correct default, because an unwatched window must not read as a clean
    client.
    """

    def __init__(
        self,
        *,
        third_party_hosts: tuple[str, ...] = (),
        required_watchers: frozenset[str] = frozenset({"http", "dns", "sni"}),
        watcher_grace: timedelta = timedelta(seconds=90),
    ) -> None:
        self._by_test: dict[str, Probe] = {}
        self._by_probe: dict[str, Probe] = {}
        self._heartbeats: dict[str, datetime] = {}
        self._third_party_hosts = third_party_hosts
        # Held as an instance attribute so a deployment can widen the set without a code
        # change, and so nothing else has to reach in and mutate it after construction.
        self.required_watchers = required_watchers
        self.watcher_grace = watcher_grace

    def create(self, *, mailbox: str, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> TestCreated:
        test_id = f"test-{secrets.token_hex(6)}"
        probe_id = f"probe-{secrets.token_hex(6)}"
        expires = utc_now() + timedelta(seconds=window_seconds)
        probe = Probe(
            test_id=test_id,
            probe_id=probe_id,
            mailbox=mailbox,
            window_expires_at=expires,
            referer_captured=True,
            third_party_hosts=self._third_party_hosts,
        )
        self._by_test[test_id] = probe
        self._by_probe[probe_id] = probe
        return TestCreated(test_id=test_id, probe_id=probe_id, expires_at=expires)

    def get(self, test_id: str) -> Probe:
        probe = self._by_test.get(test_id)
        if probe is None:
            raise UnknownProbe(test_id)
        return probe

    def record(self, contact: CallbackRequest) -> Observation:
        probe = self._by_probe.get(contact.probe_id)
        if probe is None:
            raise UnknownProbe(contact.probe_id)
        if utc_now() > probe.window_expires_at:
            # Refused rather than stored: a contact arriving after the window is outside
            # the measurement, and keeping it would let a late fetch change a verdict the
            # harness has already read.
            raise ProbeExpired(contact.probe_id)
        observation = Observation(
            channel=contact.channel,
            probe_id=contact.probe_id,
            vector=contact.vector,
            origin=contact.origin,
            remote_host=contact.remote_host,
            observed_at=utc_now(),
            resource=contact.resource,
            referrer=contact.referrer,
            detail=contact.detail,
        )
        probe.observations.append(observation)
        probe.exercised = probe.exercised | {contact.vector}
        return observation

    def mark_delivered(self, probe_id: str, delivered_at: datetime | None) -> None:
        probe = self._by_probe.get(probe_id)
        if probe is None:
            raise UnknownProbe(probe_id)
        probe.delivered_at = delivered_at or utc_now()

    def heartbeat(self, beat: WatcherHeartbeat) -> None:
        self._heartbeats[beat.watcher] = beat.observed_at

    def heartbeats(self) -> dict[str, datetime]:
        return dict(self._heartbeats)

    def watchers_healthy(self) -> bool:
        cutoff = utc_now() - self.watcher_grace
        return all(
            name in self._heartbeats and self._heartbeats[name] >= cutoff
            for name in self.required_watchers
        )

    def state(self, test_id: str) -> TestState:
        probe = self.get(test_id)
        return TestState(
            test_id=probe.test_id,
            probe_id=probe.probe_id,
            delivered_at=probe.delivered_at,
            watchers_healthy=self.watchers_healthy(),
            window_expires_at=probe.window_expires_at,
            exercised=tuple(sorted(probe.exercised)),
            referer_captured=probe.referer_captured,
            third_party_hosts=probe.third_party_hosts,
        )

    def observations(self, test_id: str) -> tuple[Observation, ...]:
        return tuple(self.get(test_id).observations)

    def mark_exercised(self, probe_id: str, vectors: frozenset[str]) -> None:
        """Record vectors the canary actually ran, independently of any contact.

        A vector that ran but was never contacted is exactly the case a required-vector
        guard exists for, and it can only be known from the message-sending path.
        """
        probe = self._by_probe.get(probe_id)
        if probe is None:
            raise UnknownProbe(probe_id)
        probe.exercised = probe.exercised | vectors


__all__ = [
    "InMemoryObservationStore",
    "ObservationOrigin",
    "ObservationStore",
    "Probe",
    "ProbeExpired",
    "StoreError",
    "UnknownProbe",
]
