"""Reads what a chat client exposes on the Android lock screen.

This is a display-surface measurement, not a network one. Nothing here observes a
canary URL, so the usual canary guard does not apply: an empty reading is *not* evidence
of a clean client. The app may have had no notification permission, may have been
force-stopped, or may never have been shown the message at all, and every one of those
looks identical to "this client shows no preview" unless the app's state is positively
confirmed first.

That is why :class:`AppState` exists and why it is checked before the observation set is
interpreted. A notification is only ever read as a disclosure once the harness has
established that a notification was due, and an unreadable shade is never read as a
clean one.

The second delicate point is attribution. Reading a notification proves what the client
placed in it; it does not prove who saw it. A full body preview is a real exposure
because the platform hands that text to every bound notification listener, not only to
the person holding the device, so the two threat models this check carries are separated
by *how much* was exposed rather than by who was assumed to be looking.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from privacy_benchmark.adapters.base import (
    AdapterError,
    AdapterEvidence,
    AdapterOutcome,
    ensure_identifier,
)
from privacy_benchmark.adapters.chat_appium import (
    numbers_config_from_environment,
)
from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.spec.models import (
    CheckDefinition,
    EvidenceClass,
    EvidenceKind,
    RedactionPolicy,
    ResultStatus,
    UtcDateTime,
)
from privacy_benchmark.spec.serialization import json_bytes

#: The appium-side gateway variables are reused, because delivery of the honey-message
#: is the same operation for every chat check; only the observation differs.
NUMBERS_VARIABLE = "PT_BENCH_CHAT_NUMBERS"


class NotificationPrivacy(StrEnum):
    """How much of a message a client is expected to put in a notification.

    One vocabulary across all three chat subjects on purpose. Each app names this
    setting differently in its own UI, so subjects declare this normalized level and a
    published row compares like with like instead of comparing three vendor labels.
    """

    CONTENT = "content"
    SENDER_ONLY = "sender_only"
    NONE = "none"


class AppState(BaseModel):
    """What the device was doing, established before the shade is read.

    Every field here is a precondition for interpreting an absence. The combined
    :attr:`notification_due` answer is what turns "no notification found" from an
    uninterpretable silence into a measurement.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    notification_permission: bool = False
    app_running: bool = False
    screen_locked: bool = False
    dnd_active: bool = False

    @property
    def notification_due(self) -> bool:
        """Whether a compliant client would have had to post a notification.

        Screen lock is required because a foreground app legitimately shows no
        notification, and do-not-disturb suppresses them on the platform rather than
        through a client choice.
        """

        return (
            self.notification_permission
            and self.app_running
            and (self.screen_locked and not self.dnd_active)
        )


class PostedNotification(BaseModel):
    """One notification the subject's app had posted when the shade was read."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    package_identifier: str = Field(min_length=1, max_length=512)
    title: str = ""
    text: str = ""
    posted_at: UtcDateTime | None = None

    @property
    def exposes_marker(self) -> bool:
        return bool(MARKER_PATTERN.search(f"{self.title}\n{self.text}"))


class ShadeReading(BaseModel):
    """One read of the notification shade.

    ``readable`` is explicit because an unparseable ``dumpsys`` dump and a shade with
    nothing in it produce nearly identical text. Collapsing them would let a changed
    platform format report itself as a clean client.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    readable: bool
    state: AppState
    notifications: tuple[PostedNotification, ...] = ()
    detail: str | None = Field(default=None, max_length=2000)

    def for_package(self, package_identifier: str) -> tuple[PostedNotification, ...]:
        return tuple(
            item for item in self.notifications if item.package_identifier == package_identifier
        )


class Adjudication(StrEnum):
    """Why the adapter reached the status it did."""

    PREVIEW_DISCLOSES_CONTENT = "chat.preview-discloses-content"
    PREVIEW_IDENTIFIES_CORRESPONDENT = "chat.preview-identifies-correspondent"
    NO_NOTIFICATION_POSTED = "chat.no-notification-posted"
    NO_PREVIEW_CONTENT = "chat.no-preview-content"
    SETTING_NOT_HONOURED = "chat.setting-not-honoured"
    SHADE_UNREADABLE = "chat.shade-unreadable"
    NOTIFICATION_NOT_DUE = "chat.notification-not-due"
    DEVICE_UNAVAILABLE = "chat.device-unavailable"
    UNSUPPORTED_CHECK = "chat.unsupported-check"


#: The marker is a synthetic, per-run token. It is the whole point of the measurement:
#: it is what proves a specific synthetic message body reached the notification.
MARKER_PATTERN = re.compile(r"\bzed-([a-z0-9]{4,12})-plinth\b")

_RECORD_START = re.compile(r"^[^)\n]*?\bpkg=(?P<pkg>[A-Za-z0-9_.]+)")
_TITLE = re.compile(r"android\.title=String \((?P<value>[^)]*)\)")
_TEXT = re.compile(r"android\.text=String \((?P<value>[^)]*)\)")
_POST_NOTIFICATIONS = re.compile(r"POST_NOTIFICATIONS: granted=(?P<granted>\w+)")
_KEYGUARD_LOCKED = re.compile(r"mDreamingLockscreen=true")


def new_marker() -> str:
    """Return a fresh synthetic marker for one delivery."""

    return f"zed-{os.urandom(4).hex()}-plinth"


def parse_dumpsys_notifications(output: str) -> tuple[PostedNotification, ...]:
    """Extract posted notifications from ``dumpsys notification --noredact`` output.

    The platform output is a flat dump of many record types, so this deliberately
    reads only the ``NotificationRecord`` entries and only the two string extras that
    carry what a person would see. Records without those extras are kept with empty
    text rather than dropped: an app that posts a notification with no readable body is
    a real observation, and silently discarding it would turn it into an absence.

    Unrecognizable input yields an empty tuple. The caller treats an empty result as an
    unreadable shade rather than an empty shade, so a platform format change surfaces
    as ``inconclusive`` and not as a clean client.
    """

    notifications: list[PostedNotification] = []
    if "NotificationRecord(" not in output:
        return ()

    # Splitting on the record delimiter bounds each chunk to exactly one record, so a
    # later record's extras can never be attributed to an earlier one.
    for chunk in output.split("NotificationRecord(")[1:]:
        package = _RECORD_START.search(chunk)
        if package is None:
            continue
        title = _TITLE.search(chunk)
        text = _TEXT.search(chunk)
        notifications.append(
            PostedNotification(
                package_identifier=package.group("pkg"),
                title=title.group("value") if title else "",
                text=text.group("value") if text else "",
            )
        )
    return tuple(notifications)


class GatewayDelivery(Protocol):
    """Delivers a synthetic honey-message to an account slot.

    Split from the concrete HTTP client because delivery is the only part of the canary
    gateway this check needs. Depending on the narrow operation keeps the surface that
    sends synthetic messages to real numbers in one obvious place.
    """

    def deliver(self, *, number: str, body_marker: str | None = None) -> Any: ...


class NotificationShadeReader(Protocol):
    """Observes the on-device notification surface.

    A protocol rather than a concrete class so the adjudication can be tested without a
    device, while :class:`AdbNotificationShade` remains the real implementation the
    adapter uses in production.
    """

    def prepare(self) -> AppState:
        """Lock the screen and clear the shade, then report the app's postable state."""

    def read(self) -> ShadeReading:
        """Read the shade and the app state again, after delivery."""

    def restore(self) -> None: ...


@dataclass(slots=True)
class AdbNotificationShade:
    """Reads the notification shade over ``adb`` on the protected Android lane.

    ``dumpsys notification`` is used rather than a UI-automation dump because the shade
    is not inspectable by the automation layer while the screen is locked, which is the
    only state in which this check is meaningful.

    The output format is platform-version specific. That is why
    :func:`parse_dumpsys_notifications` returns nothing for input it does not
    recognize and the adapter reports ``inconclusive``: a format change must not be
    able to turn itself into a passing privacy result.
    """

    serial: str
    package_identifier: str
    adb_binary: str = "adb"
    read_timeout_seconds: float = 30.0

    def prepare(self) -> AppState:
        self._run("input", "keyevent", "KEYCODE_SLEEP")
        self._run("service", "call", "notification", "cancel_all_notifications")
        return self._state()

    def read(self) -> ShadeReading:
        state = self._state()
        try:
            output = self._run("shell", "dumpsys", "notification", "--noredact")
        except AdapterError as error:
            return ShadeReading(readable=False, state=state, detail=str(error)[:2000])

        notifications = parse_dumpsys_notifications(output)
        if not notifications:
            return ShadeReading(
                readable=False,
                state=state,
                detail=(
                    "dumpsys output contained no recognizable NotificationRecord entries; "
                    "the platform format is unverified rather than the shade being empty"
                ),
            )
        return ShadeReading(readable=True, state=state, notifications=notifications)

    def restore(self) -> None:
        with contextlib.suppress(AdapterError):
            self._run("input", "keyevent", "KEYCODE_WAKEUP")

    def _state(self) -> AppState:
        """Read the preconditions that make an absence interpretable.

        Every probe fails closed. A precondition that cannot be read is reported as not
        satisfied, which sends the check to ``inconclusive`` rather than to a pass, so a
        platform change can never quietly manufacture a clean client.
        """

        return AppState(
            notification_permission=self._notification_permission(),
            app_running=self._has_output("shell", "pidof", self.package_identifier),
            screen_locked=self._lock_keyguard(),
            dnd_active=self._raw("shell", "settings", "get", "global", "zen_mode")
            in {"1", "2", "3"},
        )

    def _notification_permission(self) -> bool:
        """Whether the app may post notifications at all.

        The grant line is required. If it is absent the answer is ``False`` rather than
        ``True``: on pre-Android-13 devices the permission is install-time, but a missing
        line is equally consistent with a ``dumpsys`` format this adapter does not
        understand, and guessing "granted" in that case would report a notification as
        due when nothing could have posted one.
        """

        match = _POST_NOTIFICATIONS.search(
            self._raw("shell", "dumpsys", "package", self.package_identifier)
        )
        return match is not None and match.group("granted") == "true"

    def _lock_keyguard(self) -> bool:
        """Whether the keyguard is engaged, rather than assuming the sleep key worked."""

        return _KEYGUARD_LOCKED.search(self._raw("shell", "dumpsys", "window")) is not None

    def _raw(self, *args: str) -> str:
        try:
            return self._run(*args).strip()
        except AdapterError:
            return ""

    def _has_output(self, *args: str) -> bool:
        return bool(self._raw(*args))

    def _run(self, *args: str) -> str:
        command = [self.adb_binary]
        if self.serial:
            command += ["-s", self.serial]
        command += list(args)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.read_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise AdapterError(f"adb {' '.join(args)} failed: {error}") from error
        if completed.returncode != 0:
            raise AdapterError(
                f"adb {' '.join(args)} exited {completed.returncode}: "
                f"{completed.stderr.strip()[:400]}"
            )
        return completed.stdout


def adjudicate(
    *,
    reading: ShadeReading,
    marker: str,
    declared: NotificationPrivacy,
) -> tuple[ResultStatus, Adjudication, str, dict[str, JsonValue]]:
    """Decide a result from one shade reading, the marker, and the declared setting.

    Validity is settled before the observation set is interpreted, so a broken or
    unexpected measurement can never be reported as a client that leaks nothing.
    """

    details: dict[str, JsonValue] = {
        "marker": marker,
        "declared_notification_privacy": declared.value,
        "shade_readable": reading.readable,
        "notification_due": reading.state.notification_due,
        "screen_locked": reading.state.screen_locked,
        "notification_permission": reading.state.notification_permission,
        "dnd_active": reading.state.dnd_active,
        "posted_total": len(reading.notifications),
    }

    if not reading.readable:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.SHADE_UNREADABLE,
            "The notification shade could not be read, so an empty reading says nothing "
            "about what the client exposes.",
            details,
        )
    if not reading.state.notification_due:
        return (
            ResultStatus.INCONCLUSIVE,
            Adjudication.NOTIFICATION_NOT_DUE,
            "The client was not in a state in which it had to post a notification, so an "
            "absent notification is a device state rather than a client choice.",
            details,
        )

    return _interpret(reading=reading, marker=marker, declared=declared, details=details)


def _interpret(
    *,
    reading: ShadeReading,
    marker: str,
    declared: NotificationPrivacy,
    details: dict[str, JsonValue],
) -> tuple[ResultStatus, Adjudication, str, dict[str, JsonValue]]:
    posted = reading.notifications
    matched = MARKER_PATTERN.search(marker)
    if matched is None:
        raise AdapterError(f"the delivery marker is not a well-formed synthetic marker: {marker}")
    token = matched.group(0)

    if not posted:
        # The absence is interpretable here and only here: the shade was readable and a
        # notification was due, so a compliant client genuinely posted nothing.
        return (
            ResultStatus.PASS,
            Adjudication.NO_NOTIFICATION_POSTED,
            "A notification was due and the shade was readable, and the client posted no "
            "notification at all.",
            details,
        )

    exposed = [item for item in posted if token in f"{item.title}\n{item.text}"]
    if exposed:
        details["exposed_by"] = ",".join(sorted({item.package_identifier for item in exposed}))
        if declared is NotificationPrivacy.NONE:
            # A different failure from a weak default: the user asked for nothing and the
            # client ignored that, which is a correctness problem as well as a disclosure.
            return (
                ResultStatus.FAIL,
                Adjudication.SETTING_NOT_HONOURED,
                "The subject declares that no message content reaches notifications, but the "
                "synthetic message body was readable in the shade, so the setting is not "
                "being applied.",
                details,
            )
        return (
            ResultStatus.FAIL,
            Adjudication.PREVIEW_DISCLOSES_CONTENT,
            "The synthetic message body was readable in the notification, which is exposed to "
            "anyone glancing at the device and to every bound notification listener.",
            details,
        )

    identifying = [item for item in posted if item.title.strip() or item.text.strip()]
    if identifying:
        # Content withheld but the correspondent is not: a partial row, because the
        # remaining text still names who the reader is talking to.
        return (
            ResultStatus.PARTIAL,
            Adjudication.PREVIEW_IDENTIFIES_CORRESPONDENT,
            "The message body was withheld, but the notification still names the "
            "conversation, so the correspondent is disclosed without the content.",
            details,
        )
    return (
        ResultStatus.PASS,
        Adjudication.NO_PREVIEW_CONTENT,
        "A notification was due and posted, and it carried neither the message body nor a "
        "conversation name.",
        details,
    )


@dataclass(slots=True)
class ChatNotificationAdapter:
    """Runs the chat notification checks the Android lane can answer.

    Delivery is reused from the canary gateway because sending a synthetic message is
    the same operation for every chat check. Only the observation differs: this adapter
    never looks at network traffic.
    """

    gateway: GatewayDelivery
    numbers: dict[str, str]
    shade: NotificationShadeReader | None = None
    adapter_id: str = "chat-notification"
    version: str = "1.0.0"
    supported_checks: frozenset[str] = field(
        default_factory=lambda: frozenset({"chat.notification-preview"})
    )
    redaction_policy_id: str = "evidence-retention-v1"
    raw_retention: str = "30-days-then-delete"
    #: How long to keep re-reading the shade while a notification is in flight, and how
    #: often. Notification arrival is a device-speed question rather than a network one,
    #: so these are much shorter than the canary observation window.
    shade_poll_interval_seconds: float = 5.0
    shade_read_attempts: int = 6

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome:
        if check.check_id not in self.supported_checks:
            return AdapterOutcome(
                status=ResultStatus.UNSUPPORTED,
                reason_code=Adjudication.UNSUPPORTED_CHECK.value,
                summary=(
                    f"The chat notification adapter cannot answer {check.check_id}. "
                    f"Supported checks: {', '.join(sorted(self.supported_checks))}."
                ),
                details={"supported": False},
            )
        if self.shade is None:
            return AdapterOutcome(
                status=ResultStatus.INCONCLUSIVE,
                reason_code=Adjudication.DEVICE_UNAVAILABLE.value,
                summary=(
                    "No Android device is attached, so the notification surface could not "
                    "be observed at all."
                ),
                details={"check_id": check.check_id, "device": False},
            )

        number = self._number_for(context)
        declared = _declared_privacy(context)
        package = context.subject.client.package_identifier
        if package is None:
            raise AdapterError(
                f"subject {context.subject.subject_id} declares no package_identifier, so the "
                "notification surface cannot be attributed to a specific client build"
            )

        marker = new_marker()
        reading = ShadeReading(readable=False, state=AppState())
        try:
            self.shade.prepare()
            await self._deliver(number, marker)
            reading = await self._await_notification(package, marker)
        finally:
            self.shade.restore()

        status, reason_code, summary, details = adjudicate(
            reading=reading, marker=marker, declared=declared
        )
        details.update(
            {
                "check_id": check.check_id,
                "package_identifier": package,
                "account_slot": context.subject.account.slot_id,
                "adapter": self.adapter_id,
            }
        )
        return AdapterOutcome(
            status=status,
            reason_code=reason_code.value,
            summary=summary,
            details=details,
            evidence=(
                self._evidence(
                    check=check,
                    context=context,
                    reading=reading,
                    marker=marker,
                    declared=declared,
                ),
            ),
        )

    def _number_for(self, context: ExecutionContext) -> str:
        slot_id = context.subject.account.slot_id
        try:
            return self.numbers[slot_id]
        except KeyError as error:
            raise AdapterError(
                f"no synthetic number is configured for account slot {slot_id}; the adapter "
                f"takes slot-to-number mappings supplied at run time via {NUMBERS_VARIABLE}"
            ) from error

    async def _deliver(self, number: str, marker: str) -> None:
        """Deliver the honey-message carrying the marker.

        The marker travels in the message body. The gateway owns the actual send, so
        this only has to hand over the body and let the gateway report whether it was
        accepted; an unaccepted delivery means the shade is about to be read for a
        message that was never sent.
        """

        self.gateway.deliver(number=number, body_marker=marker)

    async def _await_notification(self, package: str, marker: str) -> ShadeReading:
        """Poll the shade until the marker appears or the attempts are exhausted.

        Returning the last reading either way matters: an exhausted poll that found
        nothing still has to be adjudicated, because "nothing appeared" and "the shade
        was never readable" are different results.
        """

        del package  # attribution is by marker: the shade is judged as a whole
        assert self.shade is not None  # narrowed by the caller
        reading = self.shade.read()
        token = MARKER_PATTERN.search(marker)
        for _ in range(max(self.shade_read_attempts, 1) - 1):
            if token is not None and any(
                token.group(0) in f"{item.title}\n{item.text}" for item in reading.notifications
            ):
                return reading
            if not reading.readable:
                return reading
            await asyncio.sleep(self.shade_poll_interval_seconds)
            reading = self.shade.read()
        return reading

    def _evidence(
        self,
        *,
        check: CheckDefinition,
        context: ExecutionContext,
        reading: ShadeReading,
        marker: str,
        declared: NotificationPrivacy,
    ) -> AdapterEvidence:
        evidence_id = ensure_identifier(
            f"{context.execution_id}.{check.check_id}.notify", field_name="evidence_id"
        )
        payload = json_bytes(
            {
                "check_id": check.check_id,
                "check_version": check.version,
                "execution_id": str(context.execution_id),
                "repetition": context.repetition,
                "subject_id": context.subject.subject_id,
                "subject_version": context.subject.subject_version,
                "account_slot": context.subject.account.slot_id,
                "marker": marker,
                "declared_notification_privacy": declared.value,
                "shade": {
                    "readable": reading.readable,
                    "detail": reading.detail,
                    "state": reading.state.model_dump(mode="json"),
                    "notification_due": reading.state.notification_due,
                },
                "notifications": [
                    {
                        "package_identifier": item.package_identifier,
                        "title": item.title,
                        "text": item.text,
                        "posted_at": _iso(item.posted_at),
                    }
                    for item in reading.notifications
                ],
                "synthetic": True,
            }
        )
        return AdapterEvidence(
            evidence_id=evidence_id,
            evidence_class=EvidenceClass.MEASURED,
            kind=EvidenceKind.NOTIFICATION_SHADE,
            media_type="application/json",
            payload=payload,
            source_uri=f"android-shade://privacy-benchmark/{context.subject.subject_id}",
            redaction=RedactionPolicy(
                policy_id=self.redaction_policy_id,
                applied=True,
                raw_retention=self.raw_retention,
                notes=(
                    "Only the subject's own notifications are read, and only the synthetic "
                    "marker body. The synthetic number is never recorded."
                ),
            ),
            metadata={
                "marker": marker,
                "shade_readable": reading.readable,
                "notification_due": reading.state.notification_due,
                "posted_total": len(reading.notifications),
            },
        )


def _declared_privacy(context: ExecutionContext) -> NotificationPrivacy:
    """Read the privacy level the subject declares, defaulting to nothing when absent.

    A subject that omits the setting is treated as declaring no expectation, so a
    disclosure is still reported rather than being excused by a missing declaration.
    """

    for setting in context.subject.configuration.settings:
        if setting.name == "notification_privacy" and isinstance(setting.value, str):
            try:
                return NotificationPrivacy(setting.value)
            except ValueError as error:
                raise AdapterError(
                    f"subject {context.subject.subject_id} declares an unknown "
                    f"notification_privacy level: {setting.value}"
                ) from error
    return NotificationPrivacy.NONE


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat()


__all__ = [
    "AdbNotificationShade",
    "Adjudication",
    "AppState",
    "ChatNotificationAdapter",
    "GatewayDelivery",
    "NotificationPrivacy",
    "NotificationShadeReader",
    "PostedNotification",
    "ShadeReading",
    "adjudicate",
    "new_marker",
    "numbers_config_from_environment",
    "parse_dumpsys_notifications",
]
