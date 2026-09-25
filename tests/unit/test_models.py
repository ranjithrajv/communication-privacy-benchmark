"""Contract model tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid7

import pytest
from pydantic import ValidationError

from privacy_benchmark.spec.models import (
    CheckRef,
    CheckResult,
    ConfigurationSetting,
    ErrorInfo,
    ExecutionMode,
    GitHubProvenance,
    ResultStatus,
    RunPlan,
    SubjectRef,
)


def test_sensitive_configuration_cannot_store_a_value() -> None:
    with pytest.raises(ValidationError, match="sensitive configuration"):
        ConfigurationSetting(name="api-token", value="secret", sensitive=True)


def test_github_mode_requires_provenance() -> None:
    with pytest.raises(ValidationError, match="requires GitHub provenance"):
        RunPlan(
            plan_id=uuid7(),
            name="invalid",
            suite_id="smoke",
            suite_version="1.0.0",
            created_at=datetime.now(UTC),
            execution_mode=ExecutionMode.GITHUB_ACTIONS,
            repetitions=1,
            checks=(CheckRef(check_id="harness.smoke", version="1.0.0"),),
            subjects=(SubjectRef(subject_id="fake-client", subject_version="1.0.0"),),
            expected_execution_count=1,
        )


def test_error_result_requires_error_details() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="error results require"):
        CheckResult(
            result_id=uuid7(),
            run_id=uuid7(),
            execution_id=uuid7(),
            check=CheckRef(check_id="harness.smoke", version="1.0.0"),
            subject=SubjectRef(subject_id="fake-client", subject_version="1.0.0"),
            adapter={"id": "fake", "version": "1.0.0"},
            status=ResultStatus.ERROR,
            reason_code="adapter.exception",
            summary="Failed",
            started_at=now,
            completed_at=now,
        )


def test_error_result_round_trips() -> None:
    now = datetime.now(UTC)
    result = CheckResult(
        result_id=uuid7(),
        run_id=uuid7(),
        execution_id=uuid7(),
        check=CheckRef(check_id="harness.smoke", version="1.0.0"),
        subject=SubjectRef(subject_id="fake-client", subject_version="1.0.0"),
        adapter={"id": "fake", "version": "1.0.0"},
        status=ResultStatus.ERROR,
        reason_code="adapter.exception",
        summary="Failed",
        started_at=now,
        completed_at=now,
        error=ErrorInfo(type="RuntimeError", message="Redacted"),
    )
    assert CheckResult.model_validate_json(result.model_dump_json()) == result


def test_github_provenance_pattern() -> None:
    with pytest.raises(ValidationError):
        GitHubProvenance(
            repository="not-a-repository",
            workflow="CI",
            job="test",
            run_id=1,
            run_attempt=1,
            commit_sha="0" * 40,
        )


@pytest.mark.parametrize("commit_sha", ["0" * 40, "a" * 64])
def test_github_provenance_accepts_git_commit_digests(commit_sha: str) -> None:
    provenance = GitHubProvenance(
        repository="owner/repository",
        workflow="CI",
        job="test",
        run_id=1,
        run_attempt=1,
        commit_sha=commit_sha,
    )
    assert provenance.commit_sha == commit_sha
