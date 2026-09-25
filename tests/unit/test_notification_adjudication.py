"""Adjudication of the lock-screen notification surface.

The whole contract is one asymmetry: an empty shade is not evidence. It is the signature
of a client that posts no preview and of a device that was never going to receive one,
so it may only be read as a pass once the shade was readable *and* a notification was
due. Every case below exists to protect that ordering, and a test that only asserted the
happy-path verdicts would not notice it being broken.
"""

from __future__ import annotations

import pytest

from privacy_benchmark.adapters.base import AdapterError
from privacy_benchmark.adapters.chat_notification import (
    AppState,
    NotificationPrivacy,
    PostedNotification,
    ShadeReading,
    adjudicate,
    new_marker,
)

MARKER = "zed-4f9a2b1c-plinth"
PACKAGE = "org.thoughtcrime.securesms"


def _due() -> AppState:
    return AppState(
        notification_permission=True, app_running=True, screen_locked=True, dnd_active=False
    )


def _reading(*notifications: PostedNotification, state: AppState | None = None) -> ShadeReading:
    return ShadeReading(readable=True, state=state or _due(), notifications=tuple(notifications))


def _posted(*, title: str = "Lab Contact", text: str = "") -> PostedNotification:
    return PostedNotification(package_identifier=PACKAGE, title=title, text=text)


def _verdict(
    reading: ShadeReading,
    *,
    declared: NotificationPrivacy = NotificationPrivacy.CONTENT,
    marker: str = MARKER,
) -> str:
    status, _, _, _ = adjudicate(reading=reading, marker=marker, declared=declared)
    return status.value


def _reason(
    reading: ShadeReading,
    *,
    declared: NotificationPrivacy = NotificationPrivacy.CONTENT,
    marker: str = MARKER,
) -> str:
    _, reason, _, _ = adjudicate(reading=reading, marker=marker, declared=declared)
    return reason.value


# --- validity guards, which must be settled before the observation set is read ---


def test_an_unreadable_shade_is_never_a_clean_client() -> None:
    reading = ShadeReading(readable=False, state=_due(), detail="unrecognized dump")
    assert _verdict(reading) == "inconclusive"
    assert _reason(reading) == "chat.shade-unreadable"


@pytest.mark.parametrize(
    "state",
    [
        AppState(notification_permission=False, app_running=True, screen_locked=True),
        AppState(notification_permission=True, app_running=False, screen_locked=True),
        AppState(notification_permission=True, app_running=True, screen_locked=False),
        AppState(
            notification_permission=True, app_running=True, screen_locked=True, dnd_active=True
        ),
    ],
    ids=["no-permission", "not-running", "screen-unlocked", "do-not-disturb"],
)
def test_an_absent_notification_is_uninterpretable_unless_one_was_due(state: AppState) -> None:
    """The guard that stops a force-stopped app from reading as a private client."""

    assert not state.notification_due
    reading = ShadeReading(readable=True, state=state, notifications=())
    assert _verdict(reading) == "inconclusive"
    assert _reason(reading) == "chat.notification-not-due"


def test_a_due_notification_with_nothing_posted_is_a_pass() -> None:
    reading = _reading()
    assert _verdict(reading) == "pass"
    assert _reason(reading) == "chat.no-notification-posted"


# --- the disclosure ladder, only reachable once validity is settled ---


def test_the_message_body_in_a_notification_is_a_disclosure() -> None:
    reading = _reading(_posted(text=f"{MARKER} please confirm"))
    assert _verdict(reading) == "fail"
    assert _reason(reading) == "chat.preview-discloses-content"


def test_a_body_ignoring_a_declared_none_is_reported_as_its_own_finding() -> None:
    """A weak default and an ignored setting are different problems for the user."""

    reading = _reading(_posted(text=MARKER))
    assert _verdict(reading, declared=NotificationPrivacy.NONE) == "fail"
    assert _reason(reading, declared=NotificationPrivacy.NONE) == "chat.setting-not-honoured"


def test_a_notification_naming_only_the_correspondent_is_partial() -> None:
    """Content withheld, but who the reader is talking to is still exposed."""

    reading = _reading(_posted(title="Lab Contact"))
    assert _verdict(reading) == "partial"
    assert _reason(reading) == "chat.preview-identifies-correspondent"


def test_a_notification_with_no_readable_text_is_a_pass() -> None:
    reading = _reading(_posted(title="", text=""))
    assert _verdict(reading) == "pass"
    assert _reason(reading) == "chat.no-preview-content"


def test_a_marker_surfaced_under_another_package_is_still_a_disclosure() -> None:
    """The only route for honey-message text into another app's notification is the
    messaging client publishing it, so the shade is judged as a whole. Both threat
    models are about the shade, not about one package's row.
    """

    reading = _reading(
        PostedNotification(package_identifier="com.android.systemui", title="", text=MARKER)
    )
    assert _verdict(reading) == "fail"
    assert _reason(reading) == "chat.preview-discloses-content"


@pytest.mark.parametrize(
    "marker", ["not-a-marker", "", "zed-plinth"], ids=["words", "empty", "short"]
)
def test_a_marker_that_cannot_be_matched_never_reads_as_nothing_exposed(marker: str) -> None:
    with pytest.raises(AdapterError, match="well-formed synthetic marker"):
        adjudicate(
            reading=_reading(_posted(text="something")),
            marker=marker,
            declared=NotificationPrivacy.CONTENT,
        )


def test_details_carry_the_preconditions_the_verdict_rests_on() -> None:
    _, _, _, details = adjudicate(
        reading=_reading(_posted(text=MARKER)),
        marker=MARKER,
        declared=NotificationPrivacy.CONTENT,
    )
    assert details["notification_due"] is True
    assert details["declared_notification_privacy"] == "content"
    assert details["shade_readable"] is True
    assert details["exposed_by"] == PACKAGE


def test_markers_are_unique_per_delivery() -> None:
    """Two runs must not be able to satisfy each other's marker."""

    assert len({new_marker(), new_marker(), new_marker()}) == 3


def test_a_generated_marker_is_recognised_as_one() -> None:
    marker = new_marker()
    reading = _reading(_posted(text=marker))
    assert _verdict(reading, marker=marker) == "fail"
