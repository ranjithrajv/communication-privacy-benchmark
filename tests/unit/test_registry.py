"""Registry definition tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from privacy_benchmark.spec.operations import OperationsRegistry
from privacy_benchmark.spec.registry import Registry, RegistryValidationError, parse_reference

#: The email disclosure families. Each has a distinct adversary and a distinct control,
#: which is why they are separate checks rather than one aggregate: a client that blocks
#: body images while rendering a calendar invite is invisible to a body-only test.
EMAIL_CHECKS = {
    "email.background-fetch",
    "email.dns-prefetch",
    "email.list-unsubscribe-fetch",
    "email.mime-remote-part",
    "email.reader-identification",
    "email.referrer-disclosure",
    "email.remote-content",
}


def test_checked_in_registry_is_valid(registry: Registry) -> None:
    """Every declared family is registered, and the harness fixture exists.

    The email set is asserted exactly because this repository owns it. The chat set is
    derived from the chat suite instead, so that lane can grow its checks without an
    unrelated inventory here failing; a suite referencing a check that is not registered
    is already caught by registry validation.
    """

    chat_checks = {
        (check_id, version)
        for check_id, version in (
            parse_reference(reference) for reference in registry.resolve_suite("chat@1.0.0").checks
        )
    }
    assert set(registry.checks) == {
        ("harness.smoke", "1.0.0"),
        *((check_id, "1.0.0") for check_id in sorted(EMAIL_CHECKS)),
        *chat_checks,
        *WEBMAIL_CHECKS,
    }
    assert ("fake-client", "1.0.0") in registry.subjects
    assert ("smoke", "1.0.0") in registry.suites


#: Listed literally rather than derived from a suite, unlike the chat set above, and that
#: asymmetry is the point: there is no webmail suite because a suite must name at least
#: one subject and a subject *is* a provider. Naming the provider is still an open
#: decision, so the check is registered and the suite is not. If a provider is chosen this
#: becomes derived like the chat set, and this constant disappears.
WEBMAIL_CHECKS = {("webmail.remote-content", "1.0.0")}


EMAIL_SUBJECTS = {
    "apple-mail-gmail-consumer",
    "thunderbird-gmail-consumer",
}


def test_the_email_check_has_an_adapter_but_stays_draft(registry: Registry) -> None:
    """The adapter exists; the lane does not, so the check is still not runnable."""

    check = registry.resolve_check("email.remote-content@1.0.0")
    assert check.status.value == "draft"
    assert check.adapter_id == "ept"
    assert check.canonical is True
    assert [runner.value for runner in check.runner_classes] == [
        "self_hosted_macos",
        "self_hosted_android",
    ]


def test_the_email_suite_is_draft_until_the_gateway_is_pinned(registry: Registry) -> None:
    suite = registry.resolve_suite("email@1.0.0")
    assert suite.status.value == "draft"
    assert {parse_reference(ref)[0] for ref in suite.checks} == EMAIL_CHECKS
    assert {parse_reference(ref)[0] for ref in suite.subjects} == EMAIL_SUBJECTS


def test_every_email_check_declares_the_adversary_it_measures(registry: Registry) -> None:
    """A check with no threat model cannot be read as a privacy claim."""

    for check_id in sorted(EMAIL_CHECKS):
        check = registry.resolve_check(f"{check_id}@1.0.0")
        assert check.channel.value == "email", check_id
        assert check.evidence_class.value == "measured", check_id
        assert len(check.threat_models) >= 1, check_id
        assert all(model.id and model.title and model.description for model in check.threat_models)


def test_a_check_without_an_adapter_says_what_it_is_waiting_for(registry: Registry) -> None:
    """The corpus is declared ahead of the adapters, and says so per check.

    A check still on the unimplemented adapter must name the capability it is waiting
    for rather than implying a measurement exists. The three with an adapter still say
    so too, because an adapter is not a lane: each names the gateway-side capability
    that has to exist before it can report a product result.
    """

    for check_id in EMAIL_CHECKS:
        check = registry.resolve_check(f"{check_id}@1.0.0")
        description = check.description.lower()
        if check.adapter_id == "unimplemented":
            assert "unimplemented because" in description, (
                f"{check_id} has no adapter and must state what it is waiting for"
            )
        else:
            assert check.adapter_id == "ept"
            assert "adapter answers this check" in description, (
                f"{check_id} has an adapter and must state the remaining gate"
            )
        assert check.status.value == "draft", check_id


def test_no_email_check_is_active_while_the_lane_is_unprovisioned(registry: Registry) -> None:
    assert all(
        registry.resolve_check(f"{check_id}@1.0.0").status.value == "draft"
        for check_id in EMAIL_CHECKS
    )


def test_the_email_suite_repeats_enough_to_detect_flakiness(registry: Registry) -> None:
    assert registry.resolve_suite("email@1.0.0").repetitions >= 3


def test_email_subjects_share_one_account_so_the_client_is_the_variable(
    registry: Registry,
) -> None:
    slots = {
        subject_id: registry.resolve_subject(f"{subject_id}@1.0.0").account.slot_id
        for subject_id in EMAIL_SUBJECTS
    }
    assert len(set(slots.values())) == 1, "a shared slot is what makes the rows comparable"

    vantages = {
        registry.resolve_subject(f"{subject_id}@1.0.0").network_vantage.vantage_id
        for subject_id in EMAIL_SUBJECTS
    }
    assert len(vantages) == 1, "a differing vantage would confound the client comparison"


def test_email_subjects_declare_the_remote_content_setting_under_test(
    registry: Registry,
) -> None:
    settings = {
        subject_id: {
            setting.name: setting.value
            for setting in registry.resolve_subject(f"{subject_id}@1.0.0").configuration.settings
        }
        for subject_id in EMAIL_SUBJECTS
    }
    # The two clients must differ in the setting the check actually measures,
    # otherwise the comparison says nothing.
    assert settings["apple-mail-gmail-consumer"]["load_remote_content"] == "ask_per_message"
    assert settings["thunderbird-gmail-consumer"]["load_remote_content"] == "never"


def test_email_subjects_use_only_synthetic_accounts(registry: Registry) -> None:
    for subject_id in EMAIL_SUBJECTS:
        account = registry.resolve_subject(f"{subject_id}@1.0.0").account
        assert account.synthetic is True
        assert account.authentication_method == "oauth2_with_app_password"


def test_email_subjects_do_not_pin_runtime_derived_identity(registry: Registry) -> None:
    for subject_id in EMAIL_SUBJECTS:
        subject = registry.resolve_subject(f"{subject_id}@1.0.0")
        assert subject.client.version is None
        assert subject.client.build is None
        assert subject.client.artifact_sha256 is None
        assert subject.platform.device_model is None
        assert subject.platform.version is None


CHAT_SUBJECTS = {
    "signal-android-default",
    "whatsapp-android-default",
    "telegram-android-default",
}


@pytest.fixture
def operations(repository_root: Path) -> OperationsRegistry:
    return OperationsRegistry.load(repository_root)


def test_chat_subjects_declare_their_measured_lane(registry: Registry) -> None:
    for subject_id in CHAT_SUBJECTS:
        subject = registry.resolve_subject(f"{subject_id}@1.0.0")
        assert subject.platform.os == "Android"
        assert subject.platform.is_emulator is False
        assert subject.account.synthetic is True
        assert subject.account.authentication_method == "phone_number_sms"
        assert subject.configuration.profile == "default"


def measured_subject_keys(registry: Registry) -> list[tuple[str, str]]:
    """Subjects that appear in a product lane, as opposed to the harness fixture.

    The fake client is only ever driven by the harness smoke suite, and its
    ``country_code`` is deliberately the unassigned placeholder because it is a loopback
    CI fixture rather than a measurement vantage. Every subject that will actually be
    published must come from the reference vantage instead.
    """

    keys: set[tuple[str, str]] = set()
    for suite in registry.suites.values():
        if all(registry.resolve_check(ref).channel.value == "harness" for ref in suite.checks):
            continue
        keys.update(parse_reference(ref) for ref in suite.subjects)
    return sorted(keys)


def test_every_measured_subject_uses_the_reference_vantage_country(
    registry: Registry,
    operations: OperationsRegistry,
) -> None:
    """A subject on a different country than the reference vantage is not comparable.

    A chat row and an email row only mean something together if both were measured from
    the same region, so the country is pinned to the policy rather than chosen per
    subject. spec/operations.py enforces this for the reference vantage; NetworkVantage
    carries no such guard, so a subject could otherwise validate while naming no
    country.
    """

    reference = operations.policy.reference_vantage.country_code
    for subject_id, subject_version in measured_subject_keys(registry):
        vantage = registry.subjects[(subject_id, subject_version)].network_vantage
        assert vantage.country_code == reference, (
            f"{subject_id}@{subject_version} measures from {vantage.country_code} but the "
            f"reference vantage is {reference}"
        )
        assert vantage.country_code != "ZZ", (
            f"{subject_id}@{subject_version} uses the unassigned 'ZZ' placeholder"
        )


def test_chat_subjects_do_not_pin_runtime_derived_identity(registry: Registry) -> None:
    """App version, build, and artifact hash are captured at measurement time."""

    for subject_id in CHAT_SUBJECTS:
        subject = registry.resolve_subject(f"{subject_id}@1.0.0")
        assert subject.client.version is None
        assert subject.client.build is None
        assert subject.client.artifact_sha256 is None
        assert subject.platform.device_model is None
        assert subject.platform.version is None


def test_chat_subjects_declare_the_privacy_relevant_configuration(registry: Registry) -> None:
    for subject_id in CHAT_SUBJECTS:
        settings = {
            setting.name: setting.value
            for setting in registry.resolve_subject(f"{subject_id}@1.0.0").configuration.settings
        }
        assert settings["link_previews"] == "enabled"
        assert settings["read_receipts"] == "enabled"


def test_every_chat_subject_declares_the_notification_privacy_the_check_reads(
    registry: Registry,
) -> None:
    """The check adjudicates against a declared level, so a subject must carry one.

    Without it the adapter falls back to expecting no content, which would report a
    default-on preview as a setting the client ignored.
    """

    for subject_id in CHAT_SUBJECTS:
        settings = {
            setting.name: setting.value
            for setting in registry.resolve_subject(f"{subject_id}@1.0.0").configuration.settings
        }
        assert settings["notification_privacy"] in {"content", "sender_only", "none"}


def test_chat_suite_is_draft_until_the_device_lane_exists(registry: Registry) -> None:
    suite = registry.resolve_suite("chat@1.0.0")
    assert suite.status.value == "draft"
    assert suite.checks == (
        "chat.link-preview-fetch@1.0.0",
        "chat.notification-preview@1.0.0",
        "chat.reader-identification@1.0.0",
    )
    assert {parse_reference(ref)[0] for ref in suite.subjects} == CHAT_SUBJECTS


def test_the_notification_check_measures_a_display_surface_not_a_network_one(
    registry: Registry,
) -> None:
    """A lock-screen preview leaks without any canary contact, so the adapter differs."""

    check = registry.resolve_check("chat.notification-preview@1.0.0")
    assert check.channel.value == "chat"
    assert check.evidence_class.value == "measured"
    assert check.adapter_id == "chat-notification"
    assert check.adapter_id != registry.resolve_check("chat.link-preview-fetch@1.0.0").adapter_id
    assert check.status.value == "draft"
    assert {model.id for model in check.threat_models} == {
        "device.observer-disclosure",
        "notification.listener-disclosure",
    }


def test_chat_check_targets_the_android_device_lane(registry: Registry) -> None:
    check = registry.resolve_check("chat.link-preview-fetch@1.0.0")
    assert check.status.value == "draft"
    assert check.channel.value == "chat"
    assert check.evidence_class.value == "measured"
    assert check.adapter_id == "chat-appium"
    assert [runner.value for runner in check.runner_classes] == ["self_hosted_android"]


@pytest.mark.parametrize("reference", ["missing-version", "too@many@parts", "@1.0.0", "id@"])
def test_invalid_definition_references_are_rejected(reference: str) -> None:
    with pytest.raises(RegistryValidationError):
        parse_reference(reference)
