"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from privacy_benchmark.harness.planning import build_run_plan
from privacy_benchmark.spec.models import ExecutionMode, RunPlan
from privacy_benchmark.spec.registry import Registry

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repository_root() -> Path:
    return REPOSITORY_ROOT


@pytest.fixture
def registry(repository_root: Path) -> Registry:
    return Registry.load(repository_root)


@pytest.fixture
def local_plan(repository_root: Path) -> RunPlan:
    return build_run_plan(
        repository_root / "suites" / "smoke" / "1.0.0" / "suite.toml",
        repository_root,
        execution_mode=ExecutionMode.LOCAL,
        github=None,
    )
