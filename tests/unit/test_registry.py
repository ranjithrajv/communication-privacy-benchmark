"""Registry definition tests."""

from __future__ import annotations

import pytest

from privacy_benchmark.spec.registry import Registry, RegistryValidationError, parse_reference


def test_checked_in_registry_is_valid(registry: Registry) -> None:
    assert set(registry.checks) == {
        ("chat.link-preview-fetch", "1.0.0"),
        ("email.remote-content", "1.0.0"),
        ("harness.smoke", "1.0.0"),
    }
    assert ("fake-client", "1.0.0") in registry.subjects
    assert ("smoke", "1.0.0") in registry.suites


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
    assert suite.checks == ("email.remote-content@1.0.0",)
    assert {parse_reference(ref)[0] for ref in suite.subjects} == EMAIL_SUBJECTS


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


def test_chat_subjects_declare_their_measured_lane(registry: Registry) -> None:
    for subject_id in CHAT_SUBJECTS:
        subject = registry.resolve_subject(f"{subject_id}@1.0.0")
        assert subject.platform.os == "Android"
        assert subject.platform.is_emulator is False
        assert subject.account.synthetic is True
        assert subject.account.authentication_method == "phone_number_sms"
        assert subject.configuration.profile == "default"
        assert subject.network_vantage.country_code == "ZZ"


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


def test_chat_suite_is_draft_until_the_device_lane_exists(registry: Registry) -> None:
    suite = registry.resolve_suite("chat@1.0.0")
    assert suite.status.value == "draft"
    assert suite.checks == ("chat.link-preview-fetch@1.0.0",)
    assert {parse_reference(ref)[0] for ref in suite.subjects} == CHAT_SUBJECTS


def test_chat_check_targets_the_android_device_lane(registry: Registry) -> None:
    check = registry.resolve_check("chat.link-preview-fetch@1.0.0")
    assert check.status.value == "draft"
    assert check.channel.value == "chat"
    assert check.evidence_class.value == "measured"
    assert check.adapter_id == "unimplemented"
    assert [runner.value for runner in check.runner_classes] == ["self_hosted_android"]


@pytest.mark.parametrize("reference", ["missing-version", "too@many@parts", "@1.0.0", "id@"])
def test_invalid_definition_references_are_rejected(reference: str) -> None:
    with pytest.raises(RegistryValidationError):
        parse_reference(reference)
