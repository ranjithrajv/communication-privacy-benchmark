"""Automation stack provenance shared by browser and mobile adapters."""

from __future__ import annotations

import os
import platform
from importlib.metadata import PackageNotFoundError, version

from pydantic import BaseModel, ConfigDict


class AutomationStack(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    python: str
    platform: str
    playwright: str | None = None
    appium_python_client: str | None = None
    #: Only known when the caller injects a stack describing the session it built; the
    #: harness cannot discover the server URL an already-constructed session used.
    appium_server: str | None = None
    android_sdk: str | None = None


def _package_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def _first_environment_value(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def collect_automation_stack() -> AutomationStack:
    """Collect the toolchain provenance recorded beside every measurement.

    Only provenance the run can actually prove is recorded: a version resolved from the
    installed distribution, or a path the runner exports. Anything undetermined stays
    ``None`` rather than being guessed, so published evidence never claims a toolchain
    the measurement did not actually run on.
    """

    return AutomationStack.model_validate(
        {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "playwright": _package_version("playwright"),
            "appium_python_client": _package_version("Appium-Python-Client"),
            "android_sdk": _first_environment_value("ANDROID_HOME", "ANDROID_SDK_ROOT"),
        }
    )
