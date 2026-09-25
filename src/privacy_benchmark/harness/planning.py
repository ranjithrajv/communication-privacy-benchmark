"""Create deterministic run plans from checked-in suite definitions."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid7

from privacy_benchmark.spec.models import (
    CheckRef,
    ExecutionMode,
    GitHubProvenance,
    RunPlan,
    SubjectRef,
    utc_now,
)
from privacy_benchmark.spec.registry import Registry, parse_reference


def github_provenance_from_environment(
    environ: dict[str, str] | None = None,
) -> GitHubProvenance | None:
    values = os.environ if environ is None else environ
    required = (
        "GITHUB_REPOSITORY",
        "GITHUB_WORKFLOW",
        "GITHUB_JOB",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_SHA",
    )
    if not all(values.get(name) for name in required):
        return None
    return GitHubProvenance(
        repository=values["GITHUB_REPOSITORY"],
        workflow=values["GITHUB_WORKFLOW"],
        job=values["GITHUB_JOB"],
        run_id=int(values["GITHUB_RUN_ID"]),
        run_attempt=int(values["GITHUB_RUN_ATTEMPT"]),
        commit_sha=values["GITHUB_SHA"],
    )


def resolve_execution_mode(
    requested: ExecutionMode | None = None,
    *,
    environ: dict[str, str] | None = None,
) -> ExecutionMode:
    values = os.environ if environ is None else environ
    if requested is None:
        return (
            ExecutionMode.GITHUB_ACTIONS
            if values.get("GITHUB_ACTIONS") == "true"
            else ExecutionMode.LOCAL
        )
    if requested is ExecutionMode.GITHUB_ACTIONS and values.get("GITHUB_ACTIONS") != "true":
        raise ValueError("github_actions execution mode is only available inside GitHub Actions")
    return requested


def build_run_plan(
    suite_path: Path,
    root: Path,
    *,
    execution_mode: ExecutionMode,
    github: GitHubProvenance | None,
) -> RunPlan:
    suite_ref = f"{suite_path.parent.parent.name}@{suite_path.parent.name}"
    parse_reference(suite_ref)
    registry = Registry.load(root)
    suite = registry.resolve_suite(suite_ref)
    checks = tuple(
        CheckRef(check_id=identifier, version=version)
        for identifier, version in (parse_reference(reference) for reference in suite.checks)
    )
    subjects = tuple(
        SubjectRef(subject_id=identifier, subject_version=version)
        for identifier, version in (parse_reference(reference) for reference in suite.subjects)
    )
    return RunPlan(
        plan_id=uuid7(),
        name=f"{suite.suite_id}@{suite.version}",
        suite_id=suite.suite_id,
        suite_version=suite.version,
        created_at=utc_now(),
        execution_mode=execution_mode,
        repetitions=suite.repetitions,
        checks=checks,
        subjects=subjects,
        expected_execution_count=len(subjects) * suite.repetitions,
        github=github,
    )
