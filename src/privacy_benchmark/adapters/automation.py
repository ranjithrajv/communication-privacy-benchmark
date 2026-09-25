"""Automation stack provenance shared by browser and mobile adapters."""

from __future__ import annotations

import platform
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from pydantic import BaseModel, ConfigDict


class AutomationStack(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)

    python: str
    platform: str
    playwright: str | None = None
    appium_python_client: str | None = None
    appium_server: str | None = None
    appium_driver: str | None = None
    node: str | None = None
    android_sdk: str | None = None
    jdk: str | None = None
    xcode: str | None = None
    macos: str | None = None


def _package_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def collect_automation_stack(**overrides: Any) -> AutomationStack:
    values: dict[str, Any] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "playwright": _package_version("playwright"),
        "appium_python_client": _package_version("Appium-Python-Client"),
    }
    values.update(overrides)
    return AutomationStack.model_validate(values)
