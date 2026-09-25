"""The webmail recipe, and the adapter ids the checked-in checks are allowed to name.

The provider is deliberately not compiled into the adapter, so a recipe is the only thing
that tells the harness which product it is driving. That makes the recipe a load-bearing
measurement input rather than configuration, and these tests treat it as one: a recipe
that cannot drive a message, or that would put a synthetic password on the wire in clear,
is rejected at load time instead of at run time.
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass

import pytest
from pydantic import ValidationError

from privacy_benchmark.adapters.chat_appium import ChatAppiumAdapter
from privacy_benchmark.adapters.chat_notification import ChatNotificationAdapter
from privacy_benchmark.adapters.ept import EptGatewayAdapter
from privacy_benchmark.adapters.fake import FakeAdapter
from privacy_benchmark.adapters.webmail_playwright import WebmailPlaywrightAdapter
from privacy_benchmark.spec.models import (
    AccountDefinition,
    ComponentRef,
    NetworkVantage,
    PlatformDefinition,
    SubjectConfiguration,
    SubjectDefinition,
    WebmailAutomation,
)

VALID = {
    "entry_url": "https://mail.example.invalid/index.php",
    "user_field": "input[name='user']",
    "password_field": "input[name='pass']",
    "submit_field": "button[type='submit']",
    "message_row": "tr.message",
    "message_open": "tr.message a.subject",
    "message_body": "div#message-body",
    "ready_marker": "div#message-list",
}

ADAPTER_CLASSES = (
    FakeAdapter,
    EptGatewayAdapter,
    ChatAppiumAdapter,
    ChatNotificationAdapter,
    WebmailPlaywrightAdapter,
)


def _adapter_ids() -> set[str]:
    """Every adapter id a real adapter class answers to.

    Read from the declared default rather than by instantiating, so a test never needs a
    gateway client or a device. Handles both shapes the adapters use: a dataclass field
    (where a slots dataclass has already removed the class attribute) and a plain class
    attribute.
    """

    ids: set[str] = set()
    for cls in ADAPTER_CLASSES:
        for spec in fields(cls) if is_dataclass(cls) else ():
            if spec.name == "adapter_id" and isinstance(spec.default, str):
                ids.add(spec.default)
        declared = getattr(cls, "adapter_id", None)
        if isinstance(declared, str):
            ids.add(declared)
    return ids


class TestTheRecipe:
    def test_a_complete_recipe_loads(self) -> None:
        recipe = WebmailAutomation.model_validate(VALID)
        assert recipe.entry_url.startswith("https://")
        assert recipe.sign_out_field is None

    def test_plain_http_is_refused_because_credentials_ride_on_that_request(self) -> None:
        # The harness types a synthetic password into this origin. Over plain http any
        # network observer reads it, and the subject would no longer be faithful to the
        # product a reader actually uses.
        with pytest.raises(ValidationError, match="entry_url"):
            WebmailAutomation.model_validate({**VALID, "entry_url": "http://mail.example.invalid"})

    @pytest.mark.parametrize(
        "entry_url",
        [
            "https://",
            "not-a-url",
            "ftp://mail.example.invalid",
            "https://mail.example.invalid/ with spaces",
        ],
    )
    def test_a_non_https_entry_point_is_refused(self, entry_url: str) -> None:
        with pytest.raises(ValidationError, match="entry_url"):
            WebmailAutomation.model_validate({**VALID, "entry_url": entry_url})

    def test_the_row_and_open_selectors_must_differ(self) -> None:
        # If they were the same element the harness could not tell "the list never
        # loaded" from "the message opened", which is the one thing the open asserts.
        with pytest.raises(ValidationError, match="must be different selectors"):
            WebmailAutomation.model_validate({**VALID, "message_open": VALID["message_row"]})

    def test_the_body_must_not_be_the_open_control(self) -> None:
        with pytest.raises(ValidationError, match="message_body"):
            WebmailAutomation.model_validate({**VALID, "message_body": VALID["message_open"]})

    @pytest.mark.parametrize("field_name", ["user_field", "message_row", "ready_marker"])
    def test_a_blank_selector_is_refused(self, field_name: str) -> None:
        with pytest.raises(ValidationError, match=field_name):
            WebmailAutomation.model_validate({**VALID, field_name: "   "})

    @pytest.mark.parametrize("timeout", [0, 4, 601, -1])
    def test_a_timeout_outside_the_bounds_is_refused(self, timeout: int) -> None:
        # A zero or negative timeout would report an unrendered message instantly, which
        # is indistinguishable from a product that refused to render it.
        with pytest.raises(ValidationError):
            WebmailAutomation.model_validate({**VALID, "login_timeout_seconds": timeout})


class TestTheSubjectCarriesTheRecipe:
    def _base(self) -> SubjectDefinition:
        return SubjectDefinition(
            subject_id="webmail-subject",
            subject_version="1.0.0",
            client=ComponentRef(name="Chromium"),
            service=ComponentRef(name="Example Mail"),
            platform=PlatformDefinition(os="Linux", architecture="x86_64", is_emulator=False),
            account=AccountDefinition(
                account_type="consumer-webmail",
                slot_id="slot-0001",
                authentication_method="password",
            ),
            configuration=SubjectConfiguration(),
            network_vantage=NetworkVantage(
                vantage_id="vantage-one", country_code="DE", network_type="residential"
            ),
            automation=WebmailAutomation.model_validate(VALID),
        )

    def _subject(self, **overrides: object) -> SubjectDefinition:
        return self._base().model_copy(update=overrides)

    def test_a_subject_may_carry_a_recipe(self) -> None:
        assert self._subject().automation is not None

    def test_a_subject_may_omit_one(self) -> None:
        # Native clients have nothing to drive, so the recipe is optional. Only a subject
        # that claims to have one is held to the webmail rules.
        assert self._subject(automation=None).automation is None

    def test_a_recipe_without_a_named_service_is_refused(self) -> None:
        # A comparison row is meaningless without knowing which service it is, and a
        # recipe with an empty provider column would silently never be distinguishable
        # from another provider's row. Built through ``model_validate`` rather than
        # ``model_copy`` because the latter bypasses validation by design, so it could
        # not demonstrate that the rule actually fires.
        payload = self._base().model_dump(mode="json", exclude={"service"})
        with pytest.raises(ValidationError, match="must name its service"):
            SubjectDefinition.model_validate(payload)

    def test_the_recipe_is_frozen(self) -> None:
        recipe = self._subject().automation
        assert recipe is not None
        attribute = "entry_url"
        with pytest.raises(ValidationError):
            setattr(recipe, attribute, "https://elsewhere.invalid")


class TestEveryCheckNamesARealAdapter:
    def test_no_check_points_at_an_adapter_that_does_not_exist(self, registry) -> None:
        # A misspelled adapter id would otherwise survive every build and only surface as
        # an unresolvable adapter during a measurement, on a lane that is expensive to
        # run and currently unprovisioned. ``unimplemented`` is the one declared
        # placeholder and is checked separately, so a typo is still caught.
        real = _adapter_ids() | {"unimplemented"}
        assert real, "no adapter ids were discovered"
        for (check_id, version), check in registry.checks.items():
            assert check.adapter_id in real, (
                f"{check_id}@{version} names adapter {check.adapter_id!r}, "
                f"which is not one of {sorted(real)}"
            )

    def test_the_sentinel_is_named_rather_than_typo_adjacent(self, registry) -> None:
        # Guarding the guard: if this list ever grows a near-miss entry, a typo of that
        # name would pass silently. Nothing in the tree declares it.
        assert "unimplemented" not in _adapter_ids()

    def test_the_webmail_check_is_wired_to_the_webmail_adapter(self, registry) -> None:
        check = registry.resolve_check("webmail.remote-content@1.0.0")
        assert check.adapter_id == "webmail-playwright"
        assert check.channel == "webmail"

    def test_the_webmail_check_is_draft_and_has_no_suite(self, registry) -> None:
        # There is no webmail subject because the provider is unselected, and a suite
        # cannot be declared without one. A placeholder subject would make the pipeline
        # look complete while measuring nothing.
        check = registry.resolve_check("webmail.remote-content@1.0.0")
        assert check.status.value == "draft"
        assert not any(
            "webmail.remote-content" in reference
            for suite in registry.suites.values()
            for reference in suite.checks
        )
