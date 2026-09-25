"""Tests for the chat automation recipe carried by a subject.

The recipe is the thing that decides what the harness will actually drive on a device,
so these tests are mostly about the ways a wrong recipe could quietly produce a clean
result. Every assertion here corresponds to a way that could go wrong:

* a recipe that cannot address the synthetic conversation would open whatever thread
  happened to be on screen, and the canary would record a fetch against a conversation
  nobody entered;
* a recipe with no client package has nothing to launch and nothing to filter, so the run
  could only ever report an unavailable device;
* a subject carrying both recipes would describe two different products at once.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from privacy_benchmark.spec.models import (
    ChatAutomation,
    ComponentRef,
    PlatformDefinition,
    SubjectDefinition,
)

RECIPE: dict[str, object] = {
    "app_activity": "org.thoughtcrime.securesms.gui.MainActivity",
    "conversation_selector": '//android.widget.TextView[@text="{number}"]',
    "message_selector": "id:conversation_row",
    "message_body_selector": "id:message_body",
}

PACKAGE = "org.thoughtcrime.securesms"


def _recipe(**overrides: object) -> ChatAutomation:
    return ChatAutomation.model_validate({**RECIPE, **overrides})


def _subject(**overrides: object) -> SubjectDefinition:
    base: dict[str, object] = {
        "subject_id": "signal-android-default",
        "subject_version": "1.0.0",
        "client": ComponentRef(name="Signal Android", package_identifier=PACKAGE),
        "platform": PlatformDefinition(os="Android", architecture="arm64-v8a"),
        "account": {
            "account_type": "synthetic-mobile-number",
            "slot_id": "slot-signal-0001",
            "authentication_method": "phone_number_sms",
        },
        "network_vantage": {
            "vantage_id": "chat-lane-unselected",
            "country_code": "DE",
            "network_type": "residential-unselected",
        },
    }
    base.update(overrides)
    return SubjectDefinition.model_validate(base)


class TestChatAutomationRecipe:
    def test_a_recipe_round_trips(self) -> None:
        assert _recipe().app_activity.endswith("MainActivity")

    def test_the_conversation_must_be_addressed_by_number(self) -> None:
        # The load-bearing invariant. Without the placeholder the harness opens whatever
        # is in view, and the observation belongs to a thread the reader never entered.
        with pytest.raises(ValidationError, match="number"):
            _recipe(conversation_selector="id:conversation_list")

    def test_the_conversation_locator_carries_the_synthetic_number(self) -> None:
        number = "+4915112345678"
        locator = _recipe().conversation_locator(number)
        assert number in locator
        assert "{number}" not in locator

    def test_the_body_must_not_be_the_bubble(self) -> None:
        # Otherwise "the bubble rendered" and "the body rendered" are one observation, and
        # the check cannot tell a truncated preview from a whole one.
        with pytest.raises(ValidationError, match="message_body_selector"):
            _recipe(message_body_selector="id:conversation_row")

    def test_the_body_is_optional(self) -> None:
        assert _recipe(message_body_selector=None).message_body_selector is None

    def test_timeouts_are_bounded(self) -> None:
        with pytest.raises(ValidationError):
            _recipe(open_timeout_seconds=0)
        with pytest.raises(ValidationError):
            _recipe(display_timeout_seconds=10_000)

    def test_an_unexpected_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _recipe(message_selector_typo="id:row")


class TestRecipeOnASubject:
    def test_a_subject_may_carry_a_recipe(self) -> None:
        assert _subject(chat=_recipe()).chat is not None

    def test_a_subject_needs_no_recipe(self) -> None:
        # A native client subject with no automation is legitimate, and is the only state
        # the checked-in chat subjects are in today.
        assert _subject().chat is None

    def test_a_chat_recipe_needs_a_package_to_launch(self) -> None:
        # The Appium session launches by package and the shade reader filters by it.
        with pytest.raises(ValidationError, match="client package"):
            _subject(
                chat=_recipe(),
                client=ComponentRef(name="Signal Android"),
            )

    def test_a_subject_cannot_carry_two_recipes(self) -> None:
        webmail = {
            "entry_url": "https://mail.example.invalid/",
            "user_field": "#user",
            "password_field": "#pass",
            "submit_field": "#submit",
            "message_row": "#row",
            "message_open": "#open",
            "message_body": "#body",
            "ready_marker": "#ready",
        }
        with pytest.raises(ValidationError, match="not both"):
            _subject(chat=_recipe(), webmail=webmail, service={"name": "Example"})

    def test_the_two_recipes_are_independent_fields(self) -> None:
        # Renaming the webmail field to `webmail` is what makes this assertable: a
        # subject that drives a browser and a subject that drives an installed client are
        # different things, and the field names now say which.
        subject = _subject(chat=_recipe())
        assert subject.webmail is None
        assert subject.chat is not None
