"""Probing whether a real device's notification dump can be read.

The parser is written against a documented shape rather than a captured one, so the
failure this protects against is quiet: an unrecognized dump yields no records, which
without a probe would look like a device that posts no notifications and would be
adjudicated as a clean client.

The probe is allowed to fail, and must fail loudly instead.
"""

from __future__ import annotations

import pytest

from privacy_benchmark.adapters.base import AdapterError
from privacy_benchmark.adapters.chat_notification import (
    AdbNotificationShade,
    parse_dumpsys_notifications,
    probe_shade,
)

DUMP = """Current Notification Manager state:
  Records:
  NotificationRecord(0xa1b2: pkg=org.thoughtcrime.securesms user=UserHandle{0} id=17 \
tag=null key=0|org.thoughtcrime.securesms|0|None|10123:null:null)
    extras={
      android.title=String (Lab Contact)
      android.text=String (hello)
    }
"""


class StubShade:
    """An adb stand-in serving a scripted dump."""

    def __init__(self, output: str | None) -> None:
        self.output = output

    def _run(self, *args: str) -> str:
        if self.output is None:
            raise AdapterError("adb unavailable")
        return self.output

    def _state(self) -> object:
        from privacy_benchmark.adapters.chat_notification import AppState

        return AppState(
            notification_permission=True, app_running=True, screen_locked=True, dnd_active=False
        )


def test_a_readable_dump_reports_what_the_parser_saw() -> None:
    probe = probe_shade(StubShade(DUMP))  # type: ignore[arg-type]

    assert probe.readable is True
    assert probe.usable is True
    assert probe.record_count == 1
    assert probe.packages == ("org.thoughtcrime.securesms",)
    assert probe.title_extras == 1
    assert probe.text_extras == 1


def test_an_unrecognized_dump_is_reported_as_unreadable() -> None:
    """The quiet failure: no records must never read as a device with nothing to say."""

    probe = probe_shade(StubShade("Notification manager state: 3 listeners\n"))  # type: ignore[arg-type]

    assert probe.readable is False
    assert probe.usable is False
    assert "no recognizable NotificationRecord" in (probe.detail or "")


def test_a_dump_with_no_string_extras_is_not_usable() -> None:
    """Records without text cannot separate a preview from an empty notification."""

    bare = (
        "NotificationRecord(0x99: pkg=com.whatsapp user=UserHandle{0} id=8 tag=null)\n"
        "    extras={\n    }\n"
    )
    parsed = parse_dumpsys_notifications(bare)
    assert len(parsed) == 1, "the record is kept; it simply carries nothing readable"

    probe = probe_shade(StubShade(bare))  # type: ignore[arg-type]
    assert probe.readable is True
    assert probe.usable is False, "no extras means the check could only ever report pass"


def test_an_unreachable_device_is_reported_rather_than_raised() -> None:
    probe = probe_shade(StubShade(None))  # type: ignore[arg-type]

    assert probe.readable is False
    assert probe.usable is False
    assert "adb unavailable" in (probe.detail or "")


def test_the_probe_names_the_gap_it_exists_to_close() -> None:
    """The message must say the parser is unverified, so an operator does not debug the app."""

    probe = probe_shade(StubShade("nothing here"))  # type: ignore[arg-type]
    assert "not a captured one" in (probe.detail or "")
    assert "rather than that the device posts no notifications" in (probe.detail or "")


def test_the_probe_takes_no_device_action() -> None:
    """It must be safe on an unprovisioned lane: read-only, no lock, no delivery."""

    recorded: list[tuple[str, ...]] = []

    class Recording(StubShade):
        def _run(self, *args: str) -> str:
            recorded.append(args)
            return DUMP

    probe_shade(Recording(DUMP))  # type: ignore[arg-type]
    assert recorded == [("shell", "dumpsys", "notification", "--noredact")]


def test_the_shade_reads_a_device_it_owns() -> None:
    shade = AdbNotificationShade(serial="emulator-5554", package_identifier="com.whatsapp")
    assert shade.serial == "emulator-5554"
    assert shade.package_identifier == "com.whatsapp"
    with pytest.raises(AdapterError):
        shade._run("shell", "definitely-not-an-adb-subcommand")
