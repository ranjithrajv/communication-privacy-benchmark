"""Parsing of the Android notification dump.

The single most damaging failure here is record bleed: ``dumpsys notification`` is one
flat text blob, and if a record's ``extras`` are attributed to the wrong package then
one app's notification can report a disclosure for a different app, or hide one. The
isolation cases below are the reason this contract has its own owner.

The sample is **hand-built from the documented shape** of ``dumpsys notification
--noredact``, not captured from a device. It pins the parsing logic, not the platform.
Verifying the format against a real build is an outstanding gate and is why the check
stays ``draft``; the adapter treats unrecognizable output as an unreadable shade rather
than an empty one, so a format change surfaces as ``inconclusive`` instead of a pass.
"""

from __future__ import annotations

from privacy_benchmark.adapters.chat_notification import (
    MARKER_PATTERN,
    parse_dumpsys_notifications,
)

MARKER = "zed-4f9a2b1c-plinth"

#: Two records, the second with no text extra, in the documented dump shape.
TWO_RECORDS = (
    """Current Notification Manager state:
  Records:
  NotificationRecord(0xa1b2c3: pkg=org.thoughtcrime.securesms user=UserHandle{0} id=17 \
tag=null key=0|org.thoughtcrime.securesms|0|None|10123:null:null)
    pkg=org.thoughtcrime.securesms
    opPkg=org.thoughtcrime.securesms
    extras={
      android.title=String (Lab Contact)
      android.text=String ("""
    + MARKER
    + """ please confirm)
    }
  NotificationRecord(0xd4e5f6: pkg=com.android.systemui user=UserHandle{0} id=3 tag=null \
key=0|com.android.systemui|0|None|10123:null:null)
    extras={
      android.title=String (Battery)
    }
"""
)

#: A record whose extras carry no readable strings at all.
BARE_RECORD = """  NotificationRecord(0x99aa: pkg=com.whatsapp user=UserHandle{0} id=8 tag=null \
key=0|com.whatsapp|0|None|10123:null:null)
    pkg=com.whatsapp
    flags=0x0
"""


def test_each_record_yields_its_own_package_and_text() -> None:
    parsed = parse_dumpsys_notifications(TWO_RECORDS)
    assert [item.package_identifier for item in parsed] == [
        "org.thoughtcrime.securesms",
        "com.android.systemui",
    ]
    assert parsed[0].title == "Lab Contact"
    assert parsed[0].text == f"{MARKER} please confirm"


#: The same two records with the marker-bearing one second, so bleed would be visible
#: in the other direction too.
TWO_RECORDS_REVERSED = (
    """Current Notification Manager state:
  Records:
  NotificationRecord(0xd4e5f6: pkg=com.android.systemui user=UserHandle{0} id=3 tag=null \
key=0|com.android.systemui|0|None|10123:null:null)
    extras={
      android.title=String (Battery)
    }
  NotificationRecord(0xa1b2c3: pkg=org.thoughtcrime.securesms user=UserHandle{0} id=17 \
tag=null key=0|org.thoughtcrime.securesms|0|None|10123:null:null)
    extras={
      android.title=String (Lab Contact)
      android.text=String ("""
    + MARKER
    + """ please confirm)
    }
"""
)


def test_a_later_record_never_donates_its_text_to_an_earlier_one() -> None:
    by_package = {
        item.package_identifier: item for item in parse_dumpsys_notifications(TWO_RECORDS)
    }
    assert by_package["org.thoughtcrime.securesms"].text == f"{MARKER} please confirm"
    assert by_package["com.android.systemui"].text == ""


def test_an_earlier_record_never_donates_its_text_to_a_later_one() -> None:
    """Bleed in the other direction: the marker must not reach the preceding record."""

    by_package = {
        item.package_identifier: item for item in parse_dumpsys_notifications(TWO_RECORDS_REVERSED)
    }
    assert by_package["com.android.systemui"].text == ""
    assert by_package["com.android.systemui"].title == "Battery"
    assert by_package["org.thoughtcrime.securesms"].text == f"{MARKER} please confirm"


def test_a_record_with_no_readable_extras_is_kept_rather_than_dropped() -> None:
    """An app posting a notification with no body is an observation, not an absence."""

    parsed = parse_dumpsys_notifications(BARE_RECORD)
    assert len(parsed) == 1
    assert parsed[0].package_identifier == "com.whatsapp"
    assert parsed[0].title == ""
    assert parsed[0].text == ""


def test_the_marker_is_recognised_only_in_the_record_that_carries_it() -> None:
    parsed = parse_dumpsys_notifications(TWO_RECORDS)
    assert [item.exposes_marker for item in parsed] == [True, False]


def test_output_without_any_notification_record_parses_to_nothing() -> None:
    assert parse_dumpsys_notifications("Notification manager state: 3 listeners\n") == ()


def test_an_empty_dump_parses_to_nothing() -> None:
    assert parse_dumpsys_notifications("") == ()


def test_the_marker_pattern_only_accepts_a_well_formed_synthetic_token() -> None:
    assert MARKER_PATTERN.search(MARKER) is not None
    assert MARKER_PATTERN.search("zed-ab-plinth") is None
    assert MARKER_PATTERN.search("please confirm") is None
