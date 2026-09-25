"""Observe the runtime identity of a subject before a check measures it.

A checked-in subject declares the parts of a configuration the lab controls and
deliberately leaves the runtime-derived facts unset: app version, build, artifact hash,
device model, OS build, and measurement region. That is the right default, because a
definition must never assert a version that was not observed. But it leaves a gap: if
nothing records what was actually measured, a result cannot be attributed to a build and
a longitudinal comparison cannot tell a product change from a measurement change.

This module closes that gap. It produces a :class:`SubjectObservation`, binding a subject
reference to what was really observed at run time.

The one property that matters most is that it **fails closed**. An observation that
cannot establish client identity is reported as unavailable and carries a blocking
finding, because a measurement that cannot be attributed to a build must not be allowed
to look like a clean one.

The vantage's public address is observed from the canary's own connection records rather
than an external IP echo service. The lab already sees the source address of every
canary contact, so asking a third party where we are would add an unnecessary external
dependency and an unnecessary disclosure.
"""

from __future__ import annotations

import platform
import plistlib
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid7

from privacy_benchmark.spec.models import (
    ClientObservation,
    FieldStatus,
    Finding,
    PlatformObservation,
    Severity,
    SubjectObservation,
    SubjectRef,
    UtcDateTime,
    VantageObservation,
    utc_now,
)

Argv = tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CompletedCommand:
    returncode: int
    stdout: str
    stderr: str = ""


#: Runs a command and returns its result. Injected so collectors can be exercised against
#: captured device output without a physical device, and so the process boundary stays in
#: one place.
CommandRunner = Callable[[Argv], CompletedCommand]


def subprocess_runner(timeout: float = 30.0) -> CommandRunner:
    """A runner backed by the real ``subprocess`` module."""

    def run(args: Argv) -> CompletedCommand:
        try:
            completed = subprocess.run(
                list(args),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return CompletedCommand(returncode=127, stdout="", stderr=str(error))
        return CompletedCommand(
            returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr
        )

    return run


# --------------------------------------------------------------------------- macOS


_MACOS_VERSION_KEYS = ("CFBundleShortVersionString", "CFBundleVersion")
_INFO_PLIST = "Info.plist"


def _as_text(value: object) -> str | None:
    """Coerce a plist value to text, treating anything else as absent."""

    return value.strip() or None if isinstance(value, str) else None


def _first_present(plist: dict[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        text = _as_text(plist.get(key))
        if text is not None:
            return text
    return None


def _second_present(plist: dict[str, object], keys: tuple[str, ...]) -> str | None:
    """The build identifier, which is the key after the marketing version.

    Apple ships both, and they differ, so conflating them would make two different
    builds compare as equal.
    """

    found = [text for key in keys if (text := _as_text(plist.get(key))) is not None]
    return found[1] if len(found) > 1 else None


def collect_macos_client(bundle: Path) -> ClientObservation:
    """Read a real macOS application bundle's Info.plist.

    ``plistlib`` parses both the XML and binary plist formats, so this needs no
    subprocess and no ``defaults`` invocation.
    """

    plist_path = bundle / "Contents" / "Resources" / _INFO_PLIST
    if not plist_path.is_file():
        plist_path = bundle / "Contents" / _INFO_PLIST
    if not plist_path.is_file():
        return ClientObservation(
            status=FieldStatus.UNAVAILABLE,
            source="macos-app-bundle",
            detail={"bundle": str(bundle), "reason": "Info.plist not found"},
        )
    try:
        with plist_path.open("rb") as handle:
            plist = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as error:
        return ClientObservation(
            status=FieldStatus.UNAVAILABLE,
            source="macos-app-bundle",
            detail={"bundle": str(bundle), "reason": type(error).__name__},
        )
    if not isinstance(plist, dict):
        return ClientObservation(
            status=FieldStatus.UNAVAILABLE,
            source="macos-app-bundle",
            detail={"bundle": str(bundle), "reason": "Info.plist is not a dictionary"},
        )
    identifier = plist.get("CFBundleIdentifier")
    return ClientObservation(
        status=FieldStatus.OBSERVED,
        name=_as_text(plist.get("CFBundleName")),
        version=_first_present(plist, _MACOS_VERSION_KEYS),
        build=_second_present(plist, _MACOS_VERSION_KEYS),
        package_identifier=_as_text(identifier) if isinstance(identifier, str) else None,
        distribution_channel=_as_text(plist.get("CFBundlePackageType")),
        source="macos-app-bundle",
        detail={"bundle": str(bundle), "info_plist": str(plist_path)},
    )


def collect_macos_platform() -> PlatformObservation:
    """Observe the local macOS build without shelling out."""

    release, _, _ = platform.mac_ver()
    uname = platform.uname()
    if not release:
        return PlatformObservation(
            status=FieldStatus.UNAVAILABLE,
            os="macOS",
            source="python-platform",
            detail={"reason": "platform.mac_ver() returned no release"},
        )
    return PlatformObservation(
        status=FieldStatus.OBSERVED,
        os="macOS",
        version=release,
        build=_as_text(uname.version) or None,
        architecture=uname.machine or None,
        device_model=_apple_silicon_model(),
        is_emulator=False,
        source="python-platform",
    )


def _apple_silicon_model(runner: CommandRunner | None = None) -> str | None:
    """Read the Apple silicon model identifier, which Python does not expose."""

    if runner is None and not shutil.which("sysctl"):
        return None
    run = runner or subprocess_runner()
    result = run(("sysctl", "-n", "hw.model"))
    if result.returncode != 0:
        return None
    model = result.stdout.strip()
    return model or None


# --------------------------------------------------------------------------- Android

_ADB = "adb"


def adb_prefix(serial: str | None = None) -> tuple[str, ...]:
    return (_ADB, *(("-s", serial) if serial else ()), "shell")


def _prop(runner: CommandRunner, prefix: tuple[str, ...], name: str) -> str | None:
    result = runner((*prefix, "getprop", name))
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


_VERSION_NAME = re.compile(r"versionName=(?P<value>\S+)")
_VERSION_CODE = re.compile(r"versionCode=(?P<value>\d+)")


def collect_android_client(
    *,
    package: str,
    runner: CommandRunner | None = None,
    serial: str | None = None,
    adb_path: str = _ADB,
) -> ClientObservation:
    """Observe a real installed Android package over adb."""

    run = runner or subprocess_runner()
    prefix = (adb_path, *(("-s", serial) if serial else ()), "shell")
    if _prop(run, prefix, "ro.build.version.sdk") is None:
        return ClientObservation(
            status=FieldStatus.UNAVAILABLE,
            package_identifier=package,
            source="adb",
            detail={"reason": "no device answered getprop", "package": package},
        )

    dump = run((*prefix, "dumpsys", "package", package))
    name = _VERSION_NAME.search(dump.stdout)
    code = _VERSION_CODE.search(dump.stdout)
    artifact = _apk_sha256(run, prefix, package, adb_path, serial)

    return ClientObservation(
        status=FieldStatus.OBSERVED,
        version=name.group("value") if name else None,
        build=code.group("value") if code else None,
        package_identifier=package,
        artifact_sha256=artifact,
        distribution_channel=_installed_channel(dump.stdout),
        source="adb",
        detail={"serial": serial or "default", "package": package},
    )


_APK_PATH = re.compile(r"package:(?P<path>\S+)")


def _apk_sha256(
    run: CommandRunner,
    prefix: tuple[str, ...],
    package: str,
    adb_path: str,
    serial: str | None,
) -> str | None:
    """Hash the installed APK so a result names the exact artifact, not just a version.

    A version string is a claim by the vendor's release process; the hash is the thing
    that was actually on the device.
    """

    located = run((*prefix, "pm", "path", package))
    match = _APK_PATH.search(located.stdout)
    if match is None:
        return None
    remote = match.group("path")
    digest = run(("adb", *(("-s", serial) if serial else ()), "shell", "sha256sum", remote))
    if digest.returncode != 0:
        return None
    candidate = digest.stdout.split(maxsplit=1)[0].strip().lower()
    return candidate if re.fullmatch(r"[0-9a-f]{64}", candidate) else None


_INSTALLER = re.compile(r"installerPackageName=(?P<value>\S+)")
_CHANNEL_BY_INSTALLER = {
    "com.android.vending": "play-store",
    "com.google.android.packageinstaller": "sideloaded",
}


def _installed_channel(dumpsys: str) -> str | None:
    match = _INSTALLER.search(dumpsys)
    if match is None:
        return None
    return _CHANNEL_BY_INSTALLER.get(match.group("value"))


_EMULATOR_HARDWARE = ("goldfish", "ranchu", "vbox", "cutf_cvm", "cuttlefish")
_EMULATOR_PROPERTIES = ("ro.kernel.qemu", "ro.boot.qemu", "ro.hardware", "ro.product.device")


def collect_android_platform(
    *, runner: CommandRunner | None = None, serial: str | None = None, adb_path: str = _ADB
) -> PlatformObservation:
    """Observe a real Android device over adb, including emulator detection.

    Emulator detection matters for scientific validity rather than tidiness: emulators
    change TLS, push, and background scheduling behavior, which is exactly what the chat
    checks measure.
    """

    run = runner or subprocess_runner()
    prefix = (adb_path, *(("-s", serial) if serial else ()), "shell")
    release = _prop(run, prefix, "ro.build.version.release")
    if release is None:
        return PlatformObservation(
            status=FieldStatus.UNAVAILABLE,
            os="Android",
            source="adb",
            detail={"reason": "no device answered getprop"},
        )

    evidence: list[str] = []
    for name in _EMULATOR_PROPERTIES:
        value = _prop(run, prefix, name)
        if value is None:
            continue
        qemu_flag = name in {"ro.kernel.qemu", "ro.boot.qemu"} and value.strip() in {
            "1",
            "true",
        }
        hardware_hint = name in {"ro.hardware", "ro.product.device"} and any(
            token in value.lower() for token in _EMULATOR_HARDWARE
        )
        if qemu_flag or hardware_hint:
            evidence.append(f"{name}={value.strip()}")

    return PlatformObservation(
        status=FieldStatus.OBSERVED,
        os="Android",
        version=release,
        build=_prop(run, prefix, "ro.build.display.id"),
        architecture=_prop(run, prefix, "ro.product.cpu.abi"),
        device_model=_prop(run, prefix, "ro.product.model"),
        is_emulator=bool(evidence),
        emulator_evidence="; ".join(evidence) or None,
        source="adb",
        detail={"serial": serial or "default"},
    )


# --------------------------------------------------------------------------- vantage

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")


def observe_vantage(
    *,
    vantage_id: str | None,
    remote_addresses: frozenset[str],
    country_by_address: Mapping[str, str] | None = None,
    asn_by_address: Mapping[str, str] | None = None,
) -> VantageObservation:
    """Derive the vantage from the addresses the canary actually saw.

    The lab already records the source address of every canary contact, so the vantage
    is observed rather than guessed, and no third party is asked where we are.
    """

    if not remote_addresses:
        return VantageObservation(
            status=FieldStatus.UNAVAILABLE,
            vantage_id=vantage_id,
            source="canary-observations",
            detail={"reason": "no canary contact recorded a source address"},
        )

    public = sorted(
        address
        for address in remote_addresses
        if not _is_private(address) and _looks_like_an_address(address)
    )
    if not public:
        return VantageObservation(
            status=FieldStatus.UNAVAILABLE,
            vantage_id=vantage_id,
            source="canary-observations",
            detail={
                "reason": "every observed address was private or loopback",
                "observed": ",".join(sorted(remote_addresses)),
            },
        )
    if len(public) > 1:
        # More than one egress means the row is not attributable to a single vantage.
        return VantageObservation(
            status=FieldStatus.UNAVAILABLE,
            vantage_id=vantage_id,
            observed_public_ip=public[0],
            source="canary-observations",
            detail={
                "reason": "more than one public egress address was observed",
                "observed": ",".join(public),
            },
        )

    address = public[0]
    return VantageObservation(
        status=FieldStatus.OBSERVED,
        vantage_id=vantage_id,
        observed_public_ip=address,
        country_code=(country_by_address or {}).get(address),
        asn=(asn_by_address or {}).get(address),
        source="canary-observations",
        detail={"observed_addresses": str(len(remote_addresses))},
    )


def _looks_like_an_address(value: str) -> bool:
    return bool(_IPV4.fullmatch(value) or _IPV6.fullmatch(value))


def _is_private(address: str) -> bool:
    import ipaddress

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True
    return (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


# --------------------------------------------------------------------------- assembly


def build_observation(
    *,
    subject: SubjectRef,
    client: ClientObservation,
    platform_observation: PlatformObservation,
    vantage: VantageObservation,
    observed_at: UtcDateTime | None = None,
) -> SubjectObservation:
    """Assemble an observation and derive its findings.

    Findings are derived rather than supplied so a caller cannot forget one, and so the
    blocking conditions are the same everywhere.
    """

    findings: list[Finding] = []
    if not client.identifies_a_build:
        findings.append(
            Finding(
                code="preflight.client-identity-unavailable",
                severity=Severity.BLOCKER,
                message=(
                    "The client could not be identified to a version or artifact hash, so a "
                    "result could not be attributed to a build and must not be published."
                ),
            )
        )
    if platform_observation.is_emulator:
        findings.append(
            Finding(
                code="preflight.emulator-detected",
                severity=Severity.INFO,
                message=(
                    "The runner reports an emulator. Emulators change TLS, push, and "
                    "background scheduling behavior, so the row is not comparable with a "
                    "physical-device row."
                ),
            )
        )
    if not vantage.pins_a_region:
        findings.append(
            Finding(
                code="preflight.vantage-unpinned",
                severity=Severity.INFO,
                message=(
                    "The measurement vantage could not be pinned to a country, so the row "
                    "is not comparable across runs."
                ),
            )
        )

    return SubjectObservation(
        observation_id=uuid7(),
        subject=subject,
        observed_at=observed_at or utc_now(),
        client=client,
        platform=platform_observation,
        vantage=vantage,
        findings=tuple(findings),
    )


__all__ = [
    "CompletedCommand",
    "FieldStatus",
    "Finding",
    "PlatformObservation",
    "Severity",
    "SubjectObservation",
    "VantageObservation",
    "adb_prefix",
    "build_observation",
    "collect_android_client",
    "collect_android_platform",
    "collect_macos_client",
    "collect_macos_platform",
    "observe_vantage",
    "subprocess_runner",
]
