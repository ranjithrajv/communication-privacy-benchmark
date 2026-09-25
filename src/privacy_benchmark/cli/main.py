"""Click entry point for the benchmark harness."""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import click

from privacy_benchmark.adapters.base import AdapterRegistry
from privacy_benchmark.adapters.fake import FakeAdapter
from privacy_benchmark.harness.aggregation import aggregate_run
from privacy_benchmark.harness.analysis import (
    summarize_rollup,
    write_comparison,
    write_rollup,
)
from privacy_benchmark.harness.execution import (
    ExecutionOutcome,
    finalize_execution,
    manifest_exit_code,
    run_execution,
)
from privacy_benchmark.harness.planning import (
    build_run_plan,
    github_provenance_from_environment,
    resolve_execution_mode,
)
from privacy_benchmark.spec.constants import PACKAGE_VERSION
from privacy_benchmark.spec.models import CompletionState, ExecutionMode, RunPlan
from privacy_benchmark.spec.registry import Registry
from privacy_benchmark.spec.schemas import export_schemas, validate_document
from privacy_benchmark.spec.serialization import read_model_json, write_model_json


def _emit_json(value: object) -> None:
    click.echo(json.dumps(value, indent=2, sort_keys=True))


def _adapter_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(FakeAdapter())
    return registry


def _load_plan(path: Path) -> RunPlan:
    return read_model_json(path, RunPlan)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(PACKAGE_VERSION, prog_name="pt-bench")
def main() -> None:
    """Run and inspect the communication privacy benchmark harness."""


@main.group()
def registry() -> None:
    """Validate checked-in benchmark definitions."""


@registry.command("validate")
@click.option(
    "--root",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path(),
    show_default=True,
)
def registry_validate(root: Path) -> None:
    """Validate all check, subject, and suite definitions."""

    try:
        loaded = Registry.load(root)
    except Exception as error:
        raise click.ClickException(str(error)) from error
    _emit_json(
        {
            "valid": True,
            "checks": len(loaded.checks),
            "subjects": len(loaded.subjects),
            "suites": len(loaded.suites),
        }
    )


@main.group("schemas")
def schemas() -> None:
    """Export and validate public JSON Schemas."""


@schemas.command("export")
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("schemas/v1alpha1"),
    show_default=True,
)
@click.option("--check", is_flag=True, help="Fail instead of writing when schemas drift.")
def schemas_export(output_dir: Path, *, check: bool) -> None:
    """Generate public schemas from the Pydantic contract models."""

    try:
        errors = export_schemas(output_dir, check=check)
    except Exception as error:
        raise click.ClickException(str(error)) from error
    if errors:
        raise click.ClickException("\n".join(errors))
    _emit_json({"valid": True, "checked": check, "output_dir": str(output_dir)})


@schemas.command("validate")
@click.argument(
    "paths",
    nargs=-1,
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
)
@click.option(
    "--kind",
    type=click.Choice(
        [
            "check",
            "subject",
            "run-plan",
            "result",
            "evidence",
            "execution-manifest",
            "run-bundle",
            "run-rollup",
            "run-comparison",
        ]
    ),
    required=True,
)
def schemas_validate(paths: tuple[Path, ...], *, kind: str) -> None:
    """Validate documents against a selected public contract."""

    if not paths:
        raise click.UsageError("provide at least one document path")
    validated: list[str] = []
    for path in paths:
        try:
            validate_document(path, kind)
        except Exception as error:
            raise click.ClickException(f"{path}: {error}") from error
        validated.append(str(path))
    _emit_json({"valid": True, "kind": kind, "documents": validated})


@main.command("plan")
@click.option(
    "--suite",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    required=True,
)
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
)
@click.option(
    "--root",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path(),
    show_default=True,
)
@click.option(
    "--mode",
    type=click.Choice([mode.value for mode in ExecutionMode]),
    default=None,
    help="Defaults to github_actions inside Actions and local elsewhere.",
)
def plan_command(*, suite: Path, output: Path, root: Path, mode: str | None) -> None:
    """Create a run plan from a checked-in suite."""

    try:
        execution_mode = resolve_execution_mode(ExecutionMode(mode) if mode is not None else None)
        github = github_provenance_from_environment()
        plan = build_run_plan(
            suite,
            root,
            execution_mode=execution_mode,
            github=github,
        )
        write_model_json(output, plan)
    except Exception as error:
        raise click.ClickException(str(error)) from error
    _emit_json({"plan": str(output), "plan_id": str(plan.plan_id), "mode": plan.execution_mode})


@main.command("execute")
@click.option(
    "--plan",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    required=True,
)
@click.option("--subject", required=True, help="Subject ID from the run plan.")
@click.option("--adapter", default="fake", show_default=True)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path, file_okay=False),
    required=True,
)
@click.option(
    "--root",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path(),
    show_default=True,
)
@click.option("--repetition", type=click.IntRange(1, 20), default=1, show_default=True)
@click.option("--force", is_flag=True, help="Replace an existing repetition directory.")
def execute_command(
    *,
    plan: Path,
    subject: str,
    adapter: str,
    output_dir: Path,
    root: Path,
    repetition: int,
    force: bool,
) -> None:
    """Execute all planned checks for one subject repetition."""

    try:
        run_plan = _load_plan(plan)
        definitions = Registry.load(root)
        subjects = [ref for ref in run_plan.subjects if ref.subject_id == subject]
        if len(subjects) != 1:
            raise ValueError(f"subject must identify exactly one planned subject: {subject}")
        subject_definition = definitions.resolve_subject(
            f"{subjects[0].subject_id}@{subjects[0].subject_version}"
        )
        checks = tuple(
            definitions.resolve_check(f"{ref.check_id}@{ref.version}") for ref in run_plan.checks
        )
        adapter_instance = _adapter_registry().get(adapter)
        execution_dir = output_dir / subject / f"{repetition:04d}"
        if execution_dir.exists() and any(execution_dir.iterdir()):
            if not force:
                raise ValueError(f"execution directory is not empty: {execution_dir}")
            shutil.rmtree(execution_dir)
        outcome = asyncio.run(
            run_execution(
                plan=run_plan,
                subject=subject_definition,
                checks=checks,
                adapter=adapter_instance,
                execution_dir=execution_dir,
                repetition=repetition,
            )
        )
    except Exception as error:
        raise click.ClickException(str(error)) from error
    _emit_execution_outcome(outcome)


@main.command("finalize")
@click.option(
    "--plan",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    required=True,
)
@click.option(
    "--execution-dir",
    type=click.Path(path_type=Path, file_okay=False, exists=True),
    required=True,
)
def finalize_command(*, plan: Path, execution_dir: Path) -> None:
    """Fill missing check results as errors and rewrite the manifest."""

    try:
        run_plan = _load_plan(plan)
        manifest = finalize_execution(execution_dir=execution_dir, plan=run_plan)
    except Exception as error:
        raise click.ClickException(str(error)) from error
    _emit_json(
        {
            "execution_dir": str(execution_dir),
            "manifest": manifest.model_dump(mode="json"),
            "exit_code": manifest_exit_code(manifest),
        }
    )
    if manifest_exit_code(manifest) != 0:
        raise click.exceptions.Exit(1)


@main.command("aggregate")
@click.option(
    "--plan",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    required=True,
)
@click.option(
    "--executions",
    type=click.Path(path_type=Path, file_okay=False, exists=True),
    required=True,
)
@click.option(
    "--output",
    type=click.Path(path_type=Path, file_okay=False),
    required=True,
)
@click.option("--force", is_flag=True, help="Replace an existing output bundle.")
def aggregate_command(*, plan: Path, executions: Path, output: Path, force: bool) -> None:
    """Validate and aggregate finalized executions into a run bundle."""

    try:
        run_plan = _load_plan(plan)
        outcome = aggregate_run(
            plan=run_plan,
            executions_root=executions,
            output_dir=output,
            force=force,
        )
    except Exception as error:
        raise click.ClickException(str(error)) from error
    _emit_json(
        {
            "output": str(output),
            "bundle_id": str(outcome.manifest.bundle_id),
            "completion": outcome.manifest.completion,
            "results": outcome.manifest.result_count,
            "evidence": outcome.evidence_count,
        }
    )
    if outcome.manifest.completion.value != "complete":
        raise click.exceptions.Exit(2)


@main.command("rollup")
@click.option(
    "--bundle",
    type=click.Path(path_type=Path, file_okay=False, exists=True),
    required=True,
    help="A run bundle produced by 'pt-bench aggregate'.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Where to write the rollup. Must be outside the bundle.",
)
def rollup_command(*, bundle: Path, output: Path) -> None:
    """Summarize how stable each per-check outcome was across repetitions."""

    try:
        rollup = write_rollup(bundle, output)
    except Exception as error:
        raise click.ClickException(str(error)) from error
    _emit_json(
        {
            "output": str(output),
            "rollup_id": str(rollup.rollup_id),
            "bundle_id": str(rollup.bundle_id),
            "bundle_completion": rollup.bundle_completion,
            "repetitions": rollup.repetitions,
            "outcomes": summarize_rollup(rollup),
        }
    )
    if rollup.bundle_completion is not CompletionState.COMPLETE:
        raise click.exceptions.Exit(2)


@main.command("compare")
@click.option(
    "--baseline",
    type=click.Path(path_type=Path, file_okay=False, exists=True),
    required=True,
    help="The earlier run bundle.",
)
@click.option(
    "--candidate",
    type=click.Path(path_type=Path, file_okay=False, exists=True),
    required=True,
    help="The later run bundle.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Where to write the comparison. Must be outside both bundles.",
)
@click.option(
    "--fail-on-regression",
    is_flag=True,
    help="Exit non-zero when any check regressed.",
)
def compare_command(
    *, baseline: Path, candidate: Path, output: Path, fail_on_regression: bool
) -> None:
    """Report per-check change between two run bundles without scoring them."""

    try:
        comparison = write_comparison(
            baseline_directory=baseline,
            candidate_directory=candidate,
            output=output,
        )
    except Exception as error:
        raise click.ClickException(str(error)) from error
    _emit_json(
        {
            "output": str(output),
            "comparison_id": str(comparison.comparison_id),
            "baseline_bundle_id": str(comparison.baseline_bundle_id),
            "candidate_bundle_id": str(comparison.candidate_bundle_id),
            "baseline_suite": comparison.baseline_suite,
            "candidate_suite": comparison.candidate_suite,
            "improved": comparison.improved,
            "regressed": comparison.regressed,
            "unchanged": comparison.unchanged,
            "unorderable": comparison.unorderable,
            "added": comparison.added,
            "removed": comparison.removed,
        }
    )
    if fail_on_regression and comparison.regressed:
        raise click.exceptions.Exit(1)


def _emit_execution_outcome(outcome: ExecutionOutcome) -> None:
    payload: dict[str, Any] = {
        "execution_dir": str(outcome.execution_dir),
        "manifest": outcome.manifest.model_dump(mode="json"),
        "exit_code": outcome.exit_code,
    }
    _emit_json(payload)
    if outcome.exit_code != 0:
        raise click.exceptions.Exit(outcome.exit_code)


if __name__ == "__main__":
    sys.exit(main())
