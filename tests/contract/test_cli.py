"""CLI end-to-end tests."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from privacy_benchmark.cli.main import main


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
