"""CLI end-to-end tests."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from privacy_benchmark.cli.main import main

GITHUB_ENVIRONMENT = {
    "GITHUB_REPOSITORY": "owner/repository",
    "GITHUB_WORKFLOW": "Email benchmark",
    "GITHUB_JOB": "measure",
    "GITHUB_RUN_ID": "12345",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_SHA": "a" * 40,
}


def test_registry_and_schema_commands(repository_root: Path) -> None:
    runner = CliRunner()
    registry_result = runner.invoke(main, ["registry", "validate", "--root", str(repository_root)])
    assert registry_result.exit_code == 0, registry_result.output
    assert json.loads(registry_result.output)["valid"] is True

    schema_result = runner.invoke(
        main,
        [
            "schemas",
            "export",
            "--output-dir",
            str(repository_root / "schemas" / "v1alpha1"),
            "--check",
        ],
    )
    assert schema_result.exit_code == 0, schema_result.output


def test_operations_validate_reports_blocked_subjects(repository_root: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["operations", "validate", "--root", str(repository_root)])
    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["valid"] is True
    assert payload["publication_target"] == "github_releases"
    blocked = {item["subject"] for item in payload["canonical_blocked_subjects"]}
    assert blocked == {
        "apple-mail-gmail-consumer@1.0.0",
        "thunderbird-gmail-consumer@1.0.0",
        "signal-android-default@1.0.0",
        "whatsapp-android-default@1.0.0",
        "telegram-android-default@1.0.0",
    }
    # Every real subject is blocked; only the account-free fixture is approved.
    assert payload["review_decisions"] == {"approved": 1, "pending": 5}
    assert payload["unprovisioned_infrastructure"]


def test_operations_validate_reports_a_missing_policy(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["operations", "validate", "--root", str(tmp_path)])
    assert result.exit_code == 1
    assert "missing operations policy" in result.output


def test_plan_refuses_an_unapproved_canonical_chat_run(repository_root: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "plan",
            "--root",
            str(repository_root),
            "--suite",
            str(repository_root / "suites" / "chat" / "1.0.0" / "suite.toml"),
            "--output",
            str(repository_root / "build" / "chat-plan.json"),
            "--mode",
            "github_actions",
        ],
        env={"GITHUB_ACTIONS": "true", **GITHUB_ENVIRONMENT},
    )
    assert result.exit_code == 1
    assert "pending provider-terms review" in result.output


def test_plan_allows_an_unapproved_run_when_deliberately_overridden(
    tmp_path: Path, repository_root: Path
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "plan",
            "--root",
            str(repository_root),
            "--suite",
            str(repository_root / "suites" / "chat" / "1.0.0" / "suite.toml"),
            "--output",
            str(tmp_path / "chat-plan.json"),
            "--mode",
            "github_actions",
            "--allow-unapproved-subjects",
        ],
        env={"GITHUB_ACTIONS": "true", **GITHUB_ENVIRONMENT},
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["mode"] == "github_actions"


def test_preflight_blocks_when_the_client_cannot_be_identified(
    tmp_path: Path, repository_root: Path
) -> None:
    """A measurement that cannot be attributed to a build must not look ready."""

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "preflight",
            "--root",
            str(repository_root),
            "--subject",
            "fake-client@1.0.0",
            "--output",
            str(tmp_path / "observation.json"),
        ],
    )
    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["measurement_ready"] is False
    assert any(finding["severity"] == "blocker" for finding in payload["findings"])


def test_preflight_reads_a_real_macos_bundle(tmp_path: Path, repository_root: Path) -> None:
    import plistlib

    bundle = tmp_path / "Mail.app" / "Contents" / "Resources"
    bundle.mkdir(parents=True)
    with (bundle / "Info.plist").open("wb") as handle:
        plistlib.dump(
            {
                "CFBundleName": "Mail",
                "CFBundleShortVersionString": "16.0",
                "CFBundleVersion": "3724.1.1",
                "CFBundleIdentifier": "com.apple.mail",
            },
            handle,
            fmt=plistlib.FMT_BINARY,
        )
    runner = CliRunner()
    output = tmp_path / "observation.json"
    result = runner.invoke(
        main,
        [
            "preflight",
            "--root",
            str(repository_root),
            "--subject",
            "apple-mail-gmail-consumer@1.0.0",
            "--app-bundle",
            str(tmp_path / "Mail.app"),
            "--vantage-id",
            "reference-de",
            "--observed-address",
            "8.8.8.8",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["client"]["version"] == "16.0"
    assert payload["client"]["build"] == "3724.1.1"
    assert payload["measurement_ready"] is True

    validation = runner.invoke(
        main,
        ["schemas", "validate", "--kind", "subject-observation", str(output)],
    )
    assert validation.exit_code == 0, validation.output


def test_preflight_refuses_a_macos_subject_without_a_bundle(
    tmp_path: Path, repository_root: Path
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "preflight",
            "--root",
            str(repository_root),
            "--subject",
            "thunderbird-gmail-consumer@1.0.0",
            "--output",
            str(tmp_path / "observation.json"),
        ],
    )
    assert result.exit_code == 1
    assert "needs --app-bundle" in result.output


def test_full_local_smoke_flow(tmp_path: Path, repository_root: Path) -> None:
    runner = CliRunner()
    plan_path = tmp_path / "plan.json"
    executions = tmp_path / "executions"
    bundle = tmp_path / "bundle"

    plan_result = runner.invoke(
        main,
        [
            "plan",
            "--root",
            str(repository_root),
            "--suite",
            str(repository_root / "suites" / "smoke" / "1.0.0" / "suite.toml"),
            "--output",
            str(plan_path),
        ],
    )
    assert plan_result.exit_code == 0, plan_result.output

    execute_result = runner.invoke(
        main,
        [
            "execute",
            "--root",
            str(repository_root),
            "--plan",
            str(plan_path),
            "--subject",
            "fake-client",
            "--output-dir",
            str(executions),
        ],
    )
    assert execute_result.exit_code == 0, execute_result.output

    finalize_result = runner.invoke(
        main,
        [
            "finalize",
            "--plan",
            str(plan_path),
            "--execution-dir",
            str(executions / "fake-client" / "0001"),
        ],
    )
    assert finalize_result.exit_code == 0, finalize_result.output

    aggregate_result = runner.invoke(
        main,
        [
            "aggregate",
            "--plan",
            str(plan_path),
            "--executions",
            str(executions),
            "--output",
            str(bundle),
        ],
    )
    assert aggregate_result.exit_code == 0, aggregate_result.output
    assert json.loads(aggregate_result.output)["completion"] == "complete"

    validate_result = runner.invoke(
        main,
        [
            "schemas",
            "validate",
            "--kind",
            "run-bundle",
            str(bundle / "manifest.json"),
        ],
    )
    assert validate_result.exit_code == 0, validate_result.output
