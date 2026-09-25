"""Chat notification adapter wiring.

The verdict ladder and the dump parser are owned by their own unit tests, so nothing
here re-asserts them. This file exists only for what the adapter adds on top: reading
the declared privacy level out of the subject, turning a device into evidence of the
right kind, and refusing to run without a device or a package to attribute to.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid7

import pytest

from privacy_benchmark.adapters.base import AdapterError
from privacy_benchmark.adapters.chat_notification import (
    AppState,
    ChatNotificationAdapter,
    PostedNotification,
    ShadeReading,
)
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.harness.planning import build_run_plan
from privacy_benchmark.spec.models import ExecutionMode, RunPlan, utc_now
from privacy_benchmark.spec.registry import Registry

SLOT = "slot-signal-0001"
NUMBER = "+4915100000000"
PACKAGE = "org.thoughtcrime.securesms"

DUE = AppState(notification_permission=True, app_running=True, screen_locked=True, dnd_active=False)


class FakeShade:
    """A device stand-in that records what the adapter asked it to do.

    It returns readings; it does not decide anything. The verdict for each reading is
    owned by the adjudication tests.
    """

    def __init__(self, reading: ShadeReading) -> None:
        self.reading = reading
        self.prepared = 0
        self.restored = 0
        self.reads = 0

    def prepare(self) -> AppState:
        self.prepared += 1
        return self.reading.state

    def read(self) -> ShadeReading:
        self.reads += 1
        return self.reading

    def restore(self) -> None:
        self.restored += 1


class RecordingGateway:
    """Captures the delivery so the marker can be asserted end to end."""

    def __init__(self) -> None:
        self.deliveries: list[dict[str, Any]] = []

    def deliver(self, *, number: str, body_marker: str | None = None) -> Any:
        self.deliveries.append({"number": number, "body_marker": body_marker})
        return object()


@pytest.fixture
def execution_dir(tmp_path: Path) -> Path:
    """Where a chat run writes its evidence.

    A per-test temporary directory, so a measurement never leaves artifacts in the
    repository tree where a later run or a packaged build could pick them up.
    """
    return tmp_path / "notify-tests"


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
        checks=(registry.resolve_check("chat.notification-preview@1.0.0"),),
        execution_id=uuid7(),
        execution_dir=execution_dir,
        adapter_id="chat-notification",
        repetition=1,
        started_at=utc_now(),
    )


def _adapter(shade: ShadeReading | None) -> tuple[ChatNotificationAdapter, RecordingGateway]:
    gateway = RecordingGateway()
    adapter = ChatNotificationAdapter(
        gateway=gateway,
        numbers={SLOT: NUMBER},
        shade=None if shade is None else FakeShade(shade),
        shade_poll_interval_seconds=0.0,
        shade_read_attempts=2,
    )
    return adapter, gateway


def _exposed(marker: str) -> ShadeReading:
    return ShadeReading(
        readable=True,
        state=DUE,
        notifications=(
            PostedNotification(package_identifier=PACKAGE, title="Lab Contact", text=marker),
        ),
    )


def _run(
    registry: Registry, repository_root: Path, execution_dir: Path, shade: ShadeReading | None
) -> Any:
    adapter, _ = _adapter(shade)
    return asyncio.run(
        adapter.execute_check(
            registry.resolve_check("chat.notification-preview@1.0.0"),
            _context(registry, repository_root, execution_dir),
        )
    )


def _check(registry: Registry) -> Any:
    return registry.resolve_check("chat.notification-preview@1.0.0")


def test_evidence_is_a_notification_shade_and_carries_the_marker(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    """A published row must be traceable to the marker that proves this exact body."""

    gateway = RecordingGateway()
    adapter = ChatNotificationAdapter(
        gateway=gateway,
        numbers={SLOT: NUMBER},
        shade=None,
        shade_poll_interval_seconds=0.0,
    )

    # A shade stand-in that echoes back whatever marker was delivered, which is what a
    # real client does: the marker arrives in the body and comes back out in the text.
    class EchoShade(FakeShade):
        def read(self) -> ShadeReading:
            marker = gateway.deliveries[-1]["body_marker"]
            return ShadeReading(
                readable=True,
                state=DUE,
                notifications=(
                    PostedNotification(
                        package_identifier=PACKAGE, title="Lab Contact", text=marker
                    ),
                ),
            )

    adapter.shade = EchoShade(ShadeReading(readable=False, state=DUE))
    outcome = asyncio.run(
        adapter.execute_check(
            registry.resolve_check("chat.notification-preview@1.0.0"),
            _context(registry, repository_root, execution_dir),
        )
    )

    evidence = outcome.evidence[0]
    assert evidence.kind.value == "notification_shade"
    payload = json.loads(evidence.payload)
    assert payload["marker"] == gateway.deliveries[-1]["body_marker"]
    assert payload["synthetic"] is True
    assert payload["shade"]["notification_due"] is True


def test_evidence_never_carries_the_synthetic_number(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    adapter, _ = _adapter(ShadeReading(readable=False, state=DUE))
    outcome = asyncio.run(
        adapter.execute_check(_check(registry), _context(registry, repository_root, execution_dir))
    )
    assert NUMBER.encode() not in outcome.evidence[0].payload
    assert json.loads(outcome.evidence[0].payload)["account_slot"] == SLOT


def test_the_delivery_carries_the_marker_the_check_looks_for(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    adapter, gateway = _adapter(ShadeReading(readable=False, state=DUE))
    asyncio.run(
        adapter.execute_check(_check(registry), _context(registry, repository_root, execution_dir))
    )
    assert len(gateway.deliveries) == 1
    assert gateway.deliveries[0]["number"] == NUMBER
    assert gateway.deliveries[0]["body_marker"] is not None


def test_the_device_is_restored_even_when_the_read_fails(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    """A lane left locked is a broken lane, so teardown must not depend on success."""

    class FailingShade(FakeShade):
        def read(self) -> ShadeReading:
            raise AdapterError("adb died")

    broken = FailingShade(ShadeReading(readable=False, state=DUE))
    adapter, _ = _adapter(None)
    adapter.shade = broken
    with pytest.raises(AdapterError):
        asyncio.run(
            adapter.execute_check(
                _check(registry), _context(registry, repository_root, execution_dir)
            )
        )
    assert broken.restored == 1


def test_without_a_device_the_result_is_inconclusive(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    outcome = _run(registry, repository_root, execution_dir, None)
    assert outcome.status.value == "inconclusive"
    assert outcome.reason_code == "chat.device-unavailable"


def test_an_unsupported_check_is_reported_as_unsupported(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    adapter, _ = _adapter(ShadeReading(readable=False, state=DUE))
    outcome = asyncio.run(
        adapter.execute_check(
            registry.resolve_check("chat.link-preview-fetch@1.0.0"),
            _context(registry, repository_root, execution_dir),
        )
    )
    assert outcome.status.value == "unsupported"
    assert outcome.details["supported"] is False


def test_the_declared_privacy_level_comes_from_the_subject(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    subject = registry.resolve_subject("signal-android-default@1.0.0")
    declared = {s.name: s.value for s in subject.configuration.settings}
    assert declared["notification_privacy"] == "content"


def test_an_unmapped_slot_fails_before_the_device_is_touched(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    gateway = RecordingGateway()
    fake = FakeShade(ShadeReading(readable=False, state=DUE))
    adapter = ChatNotificationAdapter(
        gateway=gateway,
        numbers={},
        shade=fake,
        shade_poll_interval_seconds=0.0,
    )
    with pytest.raises(AdapterError, match="no synthetic number is configured"):
        asyncio.run(
            adapter.execute_check(
                _check(registry), _context(registry, repository_root, execution_dir)
            )
        )
    assert fake.prepared == 0, "the device must not be touched for an unmapped slot"
    assert gateway.deliveries == []


def test_a_subject_without_a_package_cannot_be_attributed(
    registry: Registry, repository_root: Path, execution_dir: Path
) -> None:
    """Without a package there is no way to say which build leaked the body."""

    context = _context(registry, repository_root, execution_dir)
    stripped = context.subject.model_copy(
        update={"client": context.subject.client.model_copy(update={"package_identifier": None})}
    )
    adapter, _ = _adapter(ShadeReading(readable=False, state=DUE))
    with pytest.raises(AdapterError, match="no package_identifier"):
        asyncio.run(adapter.execute_check(_check(registry), replace(context, subject=stripped)))
