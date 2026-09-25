"""Run planning and GitHub provenance tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from privacy_benchmark.harness.planning import (
    build_run_plan,
    github_provenance_from_environment,
    resolve_execution_mode,
)
from privacy_benchmark.spec.models import ExecutionMode

GITHUB_ENVIRONMENT = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_REPOSITORY": "owner/repository",
    "GITHUB_WORKFLOW": "Adapter smoke",
    "GITHUB_JOB": "smoke",
    "GITHUB_RUN_ID": "12345",
    "GITHUB_RUN_ATTEMPT": "2",
    "GITHUB_SHA": "a" * 40,
}


def test_github_environment_produces_provenance() -> None:
    provenance = github_provenance_from_environment(GITHUB_ENVIRONMENT)
    assert provenance is not None
    assert provenance.run_attempt == 2
    assert provenance.commit_sha == "a" * 40


def test_github_actions_is_detected() -> None:
    mode = resolve_execution_mode(environ=GITHUB_ENVIRONMENT)
    assert mode is ExecutionMode.GITHUB_ACTIONS


def test_github_mode_cannot_be_selected_outside_actions() -> None:
    with pytest.raises(ValueError, match="only available inside GitHub Actions"):
        resolve_execution_mode(ExecutionMode.GITHUB_ACTIONS, environ={})


def test_github_mode_plan_contains_provenance(repository_root: Path) -> None:
    provenance = github_provenance_from_environment(GITHUB_ENVIRONMENT)
    plan = build_run_plan(
        repository_root / "suites" / "smoke" / "1.0.0" / "suite.toml",
        repository_root,
        execution_mode=ExecutionMode.GITHUB_ACTIONS,
        github=provenance,
    )
    assert plan.execution_mode is ExecutionMode.GITHUB_ACTIONS
    assert plan.github is not None
    assert plan.github.run_id == 12345
