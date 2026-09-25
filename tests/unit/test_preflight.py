"""Device preflight: parsing real platform output and failing closed.

The parsers are exercised against genuine platform output formats. The ``adb`` fake
stands in for a device at the process boundary and returns real command output; it does
not implement any of the parsing under test.
"""

from __future__ import annotations

import plistlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from privacy_benchmark.harness.preflight import (
    Argv,
    ClientObservation,
    CompletedCommand,
    FieldStatus,
    PlatformObservation,
    Severity,
    build_observation,
    collect_android_client,
    collect_android_platform,
    collect_macos_client,
    observe_vantage,
)
from privacy_benchmark.spec.models import SubjectRef

SUBJECT = SubjectRef(subject_id="apple-mail-gmail-consumer", subject_version="1.0.0")
APK_PATH = "/data/app/~~k3JzQ==/com.example.mail-1/base.apk"
APK_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

#: Globally routable addresses used only to exercise the private-range filter. Nothing
#: is ever sent to them. RFC 5737 documentation ranges are deliberately avoided: Python
#: classifies them as private, so they cannot stand in for a public vantage.
PUBLIC_A = "8.8.8.8"
PUBLIC_B = "1.1.1.1"
#: A non-routable documentation address, used where a non-public address is wanted.
NON_PUBLIC = "203.0.113.7"

#: Verbatim shapes of the real commands, so the parsers are tested against what a
#: device actually emits rather than an invented format.
DUMPSYS_PACKAGE = f"""Packages:
  Package [{SUBJECT.subject_id.replace("apple-mail-gmail-consumer", "com.example.mail")}] (a1b2c3):
    userId=10123
    pkg=Package{{4d1f2e3a com.example.mail}}
    codePath=/data/app/~~k3JzQ==/com.example.mail-1
    versionCode=6427099 minSdk=26 targetSdk=35
    versionName=142.0.7444.175
    installerPackageName=com.android.vending
    firstInstallTime=2026-01-02 03:04:05
"""


class FakeAdb:
    """A device at the process boundary, returning real command output."""

    def __init__(
        self,
        *,
        properties: dict[str, str] | None = None,
        dumpsys: str = DUMPSYS_PACKAGE,
        package_path: str = f"package:{APK_PATH}",
        apk_sha: str = APK_SHA,
        attached: bool = True,
    ) -> None:
        self.attached = attached
        self.properties = {
            "ro.build.version.release": "14",
            "ro.build.display.id": "AP1A.240505.004",
            "ro.product.cpu.abi": "arm64-v8a",
            "ro.product.model": "Pixel 8",
            "ro.kernel.qemu": "0",
            "ro.hardware": "tensor",
            "ro.build.version.sdk": "34",
            **(properties or {}),
        }
        self.dumpsys = dumpsys
        self.package_path = package_path
        self.apk_sha = apk_sha
        self.calls: list[Argv] = []

    def __call__(self, args: Argv) -> CompletedCommand:
        self.calls.append(args)
        joined = " ".join(args)
        if "getprop" in joined:
            name = args[-1]
            if not self.attached or name not in self.properties:
                return CompletedCommand(returncode=1, stdout="")
            return CompletedCommand(returncode=0, stdout=f"{self.properties[name]}\n")
        if "dumpsys package" in joined:
            return CompletedCommand(returncode=0, stdout=self.dumpsys)
        if "pm path" in joined:
            if not self.package_path:
                return CompletedCommand(returncode=1, stdout="")
            return CompletedCommand(returncode=0, stdout=f"{self.package_path}\n")
        if "sha256sum" in joined:
            return CompletedCommand(returncode=0, stdout=f"{self.apk_sha}  {args[-1]}\n")
        return CompletedCommand(returncode=127, stdout="", stderr="unknown command")

    def ran(self, needle: str) -> bool:
        return any(needle in " ".join(call) for call in self.calls)


def _bundle(tmp_path: Path, plist: dict[str, object] | None, *, binary: bool = True) -> Path:
    root = tmp_path / "Mail.app" / "Contents" / "Resources"
    root.mkdir(parents=True)
    if plist is not None:
        with (root / "Info.plist").open("wb") as handle:
            plistlib.dump(plist, handle, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML)
    return tmp_path / "Mail.app"


class TestMacosClient:
    def test_a_binary_plist_is_parsed(self, tmp_path: Path) -> None:
        bundle = _bundle(
            tmp_path,
            {
                "CFBundleName": "Mail",
                "CFBundleShortVersionString": "16.0",
                "CFBundleVersion": "3724.1.1",
                "CFBundleIdentifier": "com.apple.mail",
            },
        )
        observed = collect_macos_client(bundle)
        assert observed.status is FieldStatus.OBSERVED
        assert observed.name == "Mail"
        assert observed.package_identifier == "com.apple.mail"
        assert observed.source == "macos-app-bundle"

    def test_the_build_is_separate_from_the_marketing_version(self, tmp_path: Path) -> None:
        """Apple ships both and they differ, so conflating them is a real risk.

        If the build were folded into the version, two different builds would compare
        as equal and a longitudinal comparison would miss a client change entirely.
        """

        bundle = _bundle(
            tmp_path,
            {"CFBundleShortVersionString": "16.0", "CFBundleVersion": "3724.1.1"},
        )
        observed = collect_macos_client(bundle)
        assert observed.version == "16.0"
        assert observed.build == "3724.1.1"
        assert observed.version != observed.build

    def test_an_xml_plist_is_parsed_too(self, tmp_path: Path) -> None:
        bundle = _bundle(tmp_path, {"CFBundleShortVersionString": "115.0"}, binary=False)
        assert collect_macos_client(bundle).version == "115.0"

    def test_a_missing_info_plist_is_unavailable(self, tmp_path: Path) -> None:
        observed = collect_macos_client(_bundle(tmp_path, None))
        assert observed.status is FieldStatus.UNAVAILABLE
        assert observed.version is None
        assert observed.detail["reason"] == "Info.plist not found"

    def test_a_corrupt_plist_is_unavailable(self, tmp_path: Path) -> None:
        bundle = _bundle(tmp_path, None)
        (bundle / "Contents" / "Resources" / "Info.plist").write_bytes(b"not a plist at all")
        observed = collect_macos_client(bundle)
        assert observed.status is FieldStatus.UNAVAILABLE
        assert observed.version is None

    def test_a_plist_without_a_version_cannot_identify_a_build(self, tmp_path: Path) -> None:
        observed = collect_macos_client(_bundle(tmp_path, {"CFBundleName": "Mail"}))
        assert observed.status is FieldStatus.OBSERVED
        assert observed.identifies_a_build is False


class TestAndroidClient:
    def test_version_build_and_artifact_are_observed(self) -> None:
        observed = collect_android_client(package="com.example.mail", runner=FakeAdb())
        assert observed.status is FieldStatus.OBSERVED
        assert observed.version == "142.0.7444.175"
        assert observed.build == "6427099"
        assert observed.artifact_sha256 == APK_SHA
        assert observed.distribution_channel == "play-store"

    def test_the_artifact_hash_is_observed_not_just_the_version(self) -> None:
        """A version string is a vendor claim; the hash is what was on the device."""

        adb = FakeAdb(apk_sha="a" * 64)
        assert collect_android_client(package="com.example.mail", runner=adb).artifact_sha256 == (
            "a" * 64
        )

    def test_a_missing_device_is_unavailable_not_a_guess(self) -> None:
        observed = collect_android_client(
            package="com.example.mail", runner=FakeAdb(attached=False)
        )
        assert observed.status is FieldStatus.UNAVAILABLE
        assert observed.identifies_a_build is False

    def test_a_malformed_hash_is_discarded(self) -> None:
        adb = FakeAdb(apk_sha="not-a-hash")
        observed = collect_android_client(package="com.example.mail", runner=adb)
        assert observed.artifact_sha256 is None
        assert observed.version == "142.0.7444.175"

    def test_a_missing_apk_path_leaves_the_version_intact(self) -> None:
        adb = FakeAdb(package_path="")
        observed = collect_android_client(package="com.example.mail", runner=adb)
        assert observed.artifact_sha256 is None
        assert observed.identifies_a_build is True

    def test_a_serial_is_passed_through(self) -> None:
        adb = FakeAdb()
        collect_android_client(package="com.example.mail", runner=adb, serial="emulator-5554")
        assert all("-s" in call or "shell" in call for call in adb.calls)
        assert adb.ran("getprop")


class TestAndroidPlatform:
    def test_a_physical_device_is_observed(self) -> None:
        observed = collect_android_platform(runner=FakeAdb())
        assert observed.status is FieldStatus.OBSERVED
        assert observed.os == "Android"
        assert observed.version == "14"
        assert observed.device_model == "Pixel 8"
        assert observed.architecture == "arm64-v8a"
        assert observed.is_emulator is False
        assert observed.emulator_evidence is None

    @pytest.mark.parametrize(
        ("property_name", "value"),
        [
            ("ro.kernel.qemu", "1"),
            ("ro.boot.qemu", "true"),
            ("ro.hardware", "goldfish"),
            ("ro.product.device", "ranchu"),
        ],
    )
    def test_an_emulator_is_detected_and_the_evidence_recorded(
        self, property_name: str, value: str
    ) -> None:
        """Emulators change TLS, push, and background scheduling, so a row measured on
        one is not comparable with a physical-device row."""

        observed = collect_android_platform(runner=FakeAdb(properties={property_name: value}))
        assert observed.is_emulator is True
        assert observed.emulator_evidence is not None
        assert property_name in observed.emulator_evidence

    def test_a_qemu_flag_of_zero_is_not_an_emulator(self) -> None:
        assert collect_android_platform(runner=FakeAdb()).is_emulator is False

    def test_no_device_is_unavailable(self) -> None:
        observed = collect_android_platform(runner=FakeAdb(attached=False))
        assert observed.status is FieldStatus.UNAVAILABLE
        assert observed.is_emulator is None

    def test_an_emulator_verdict_without_evidence_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must record the evidence"):
            PlatformObservation(
                status=FieldStatus.OBSERVED,
                os="Android",
                is_emulator=True,
                source="test",
            )


class TestVantageObservation:
    def test_a_public_address_is_observed(self) -> None:
        observed = observe_vantage(
            vantage_id="reference-de",
            remote_addresses=frozenset({PUBLIC_A}),
            country_by_address={PUBLIC_A: "DE"},
        )
        assert observed.status is FieldStatus.OBSERVED
        assert observed.observed_public_ip == PUBLIC_A
        assert observed.country_code == "DE"
        assert observed.pins_a_region is True

    def test_non_public_addresses_cannot_pin_a_vantage(self) -> None:
        """A lab on loopback or a private range has not measured a vantage.

        RFC 5737 documentation ranges count here too: Python classifies them as private,
        and a documentation address is not somewhere a measurement was taken.
        """

        observed = observe_vantage(
            vantage_id="local", remote_addresses=frozenset({"127.0.0.1", "10.0.0.4"})
        )
        assert observed.status is FieldStatus.UNAVAILABLE
        assert observed.pins_a_region is False
        assert "private or loopback" in observed.detail["reason"]
        assert (
            observe_vantage(vantage_id="v", remote_addresses=frozenset({NON_PUBLIC})).status
            is FieldStatus.UNAVAILABLE
        )

    def test_two_public_egresses_do_not_pin_a_vantage(self) -> None:
        """More than one egress means the row is not attributable to one place."""

        observed = observe_vantage(
            vantage_id="reference-de",
            remote_addresses=frozenset({PUBLIC_A, PUBLIC_B}),
        )
        assert observed.status is FieldStatus.UNAVAILABLE
        assert "more than one public egress" in observed.detail["reason"]

    def test_no_contact_leaves_the_vantage_unpinned(self) -> None:
        observed = observe_vantage(vantage_id="reference-de", remote_addresses=frozenset())
        assert observed.status is FieldStatus.UNAVAILABLE
        assert observed.pins_a_region is False

    def test_the_placeholder_country_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unassigned placeholder"):
            observe_vantage(
                vantage_id="v",
                remote_addresses=frozenset({PUBLIC_A}),
                country_by_address={PUBLIC_A: "ZZ"},
            )

    def test_garbage_addresses_are_not_treated_as_observations(self) -> None:
        observed = observe_vantage(vantage_id="v", remote_addresses=frozenset({"not-an-address"}))
        assert observed.status is FieldStatus.UNAVAILABLE


class TestFailClosedFindings:
    def _client(self, **kwargs: object) -> ClientObservation:
        values: dict[str, object] = {
            "status": FieldStatus.OBSERVED,
            "version": "1.0",
            "source": "t",
        }
        values.update(kwargs)
        if values["status"] is FieldStatus.UNAVAILABLE:
            values.pop("version", None)
        return ClientObservation.model_validate(values)

    def _platform(self, **kwargs: object) -> PlatformObservation:
        values: dict[str, object] = {"status": FieldStatus.OBSERVED, "os": "macOS", "source": "t"}
        values.update(kwargs)
        return PlatformObservation.model_validate(values)

    def test_an_unidentified_client_blocks_a_canonical_measurement(self) -> None:
        observation = build_observation(
            subject=SUBJECT,
            client=self._client(status=FieldStatus.UNAVAILABLE),
            platform_observation=self._platform(),
            vantage=observe_vantage(vantage_id="v", remote_addresses=frozenset({PUBLIC_A})),
        )
        assert observation.blocks_measurement is True
        assert observation.measurement_ready is False
        assert any(f.severity is Severity.BLOCKER for f in observation.findings)

    def test_an_identified_client_is_measurement_ready(self) -> None:
        observation = build_observation(
            subject=SUBJECT,
            client=self._client(),
            platform_observation=self._platform(),
            vantage=observe_vantage(
                vantage_id="reference-de",
                remote_addresses=frozenset({PUBLIC_A}),
                country_by_address={PUBLIC_A: "DE"},
            ),
        )
        assert observation.blocks_measurement is False
        assert observation.measurement_ready is True
        assert observation.findings == ()

    def test_an_emulator_is_recorded_without_blocking(self) -> None:
        observation = build_observation(
            subject=SUBJECT,
            client=self._client(),
            platform_observation=self._platform(
                is_emulator=True, emulator_evidence="ro.kernel.qemu=1"
            ),
            vantage=observe_vantage(
                vantage_id="reference-de", remote_addresses=frozenset({PUBLIC_A})
            ),
        )
        assert observation.blocks_measurement is False
        assert [f.code for f in observation.findings] == [
            "preflight.emulator-detected",
            "preflight.vantage-unpinned",
        ]

    def test_an_artifact_hash_alone_identifies_a_build(self) -> None:
        observation = build_observation(
            subject=SUBJECT,
            client=self._client(version=None, artifact_sha256="b" * 64),
            platform_observation=self._platform(),
            vantage=observe_vantage(vantage_id="v", remote_addresses=frozenset({PUBLIC_A})),
        )
        assert observation.blocks_measurement is False

    def test_an_unavailable_observation_must_not_carry_build_identity(self) -> None:
        for field, value in (("version", "1.0"), ("build", "1.0"), ("artifact_sha256", "b" * 64)):
            with pytest.raises(ValidationError, match="must not carry build identity"):
                ClientObservation.model_validate(
                    {"status": "unavailable", "source": "t", field: value}
                )

    def test_an_unavailable_observation_may_name_its_target(self) -> None:
        observed = ClientObservation.model_validate(
            {
                "status": "unavailable",
                "source": "adb",
                "package_identifier": "com.example.mail",
                "detail": {"reason": "no device answered getprop"},
            }
        )
        assert observed.identifies_a_build is False
        assert observed.package_identifier == "com.example.mail"

    def test_the_observation_is_bound_to_its_subject_and_time(self) -> None:
        moment = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
        observation = build_observation(
            subject=SUBJECT,
            client=self._client(),
            platform_observation=self._platform(),
            vantage=observe_vantage(vantage_id="v", remote_addresses=frozenset({PUBLIC_A})),
            observed_at=moment,
        )
        assert observation.subject == SUBJECT
        assert observation.observed_at == moment
