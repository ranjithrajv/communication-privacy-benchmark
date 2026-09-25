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
from privacy_benchmark.adapters.ept import (
    EptGatewayAdapter,
    EptGatewayClient,
    gateway_config_from_environment,
    mailbox_config_from_environment,
)
from privacy_benchmark.adapters.fake import FakeAdapter
from privacy_benchmark.harness.aggregation import aggregate_run
from privacy_benchmark.harness.analysis import (
    load_bundle,
    render_rollup_matrix,
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
from privacy_benchmark.harness.preflight import (
    ClientObservation,
    FieldStatus,
    PlatformObservation,
    build_observation,
    collect_android_client,
    collect_android_platform,
    collect_macos_client,
    collect_macos_platform,
    observe_vantage,
)
from privacy_benchmark.harness.publishing import evaluate_publication, stage_publication
from privacy_benchmark.spec.constants import PACKAGE_VERSION
from privacy_benchmark.spec.models import (
    CompletionState,
    ExecutionMode,
    RunPlan,
    SubjectDefinition,
    SubjectRef,
)
from privacy_benchmark.spec.operations import (
    OperationsRegistry,
    ProvisioningState,
    ReviewDecision,
)
from privacy_benchmark.spec.registry import Registry
from privacy_benchmark.spec.schemas import export_schemas, validate_document
from privacy_benchmark.spec.serialization import read_model_json, write_model_json


def _emit_json(value: object) -> None:
    click.echo(json.dumps(value, indent=2, sort_keys=True))


def _adapter_registry() -> AdapterRegistry:
    """Build the adapter registry.

    The EPT adapter is registered only when a private gateway is configured, so a
    checkout with no gateway credentials cannot accidentally address a real deployment.
    """

    registry = AdapterRegistry()
    registry.register(FakeAdapter())
    gateway = gateway_config_from_environment()
    if gateway is not None:
        base_url, token = gateway
        registry.register(
            EptGatewayAdapter(
                client=EptGatewayClient(base_url=base_url, token=token),
                mailboxes=mailbox_config_from_environment(),
            )
        )
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


@main.command("preflight")
@click.option(
    "--subject",
    required=True,
    help="Subject ID@version from the registry.",
)
@click.option(
    "--root",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path(),
    show_default=True,
)
@click.option(
    "--app-bundle",
    type=click.Path(path_type=Path, file_okay=False, exists=True),
    default=None,
    help="Path to a macOS application bundle, for Apple Mail and Thunderbird subjects.",
)
@click.option(
    "--adb-serial",
    default=None,
    help="adb device serial. Required for an Android subject.",
)
@click.option(
    "--vantage-id",
    default=None,
    help="Vantage label to record alongside the observed addresses.",
)
@click.option(
    "--observed-address",
    type=str,
    multiple=True,
    help="A source address the canary saw. Repeatable.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Where to write the subject observation.",
)
@click.option(
    "--allow-blocked",
    is_flag=True,
    help="Exit zero even when the observation blocks a canonical measurement.",
)
def preflight_command(
    *,
    subject: str,
    root: Path,
    app_bundle: Path | None,
    adb_serial: str | None,
    vantage_id: str | None,
    observed_address: tuple[str, ...],
    output: Path,
    allow_blocked: bool,
) -> None:
    """Observe the runtime identity a measurement will be attributed to."""

    try:
        definition = Registry.load(root).resolve_subject(subject)
        platform_observation, client = _observe_platform(
            definition, app_bundle=app_bundle, adb_serial=adb_serial
        )
        vantage = observe_vantage(
            vantage_id=vantage_id,
            remote_addresses=frozenset(observed_address),
        )
        observation = build_observation(
            subject=SubjectRef(
                subject_id=definition.subject_id, subject_version=definition.subject_version
            ),
            client=client,
            platform_observation=platform_observation,
            vantage=vantage,
        )
        write_model_json(output, observation)
    except Exception as error:
        raise click.ClickException(str(error)) from error
    _emit_json(
        {
            "output": str(output),
            "observation_id": str(observation.observation_id),
            "subject": subject,
            "client": observation.client.model_dump(mode="json"),
            "platform": observation.platform.model_dump(mode="json"),
            "vantage": observation.vantage.model_dump(mode="json"),
            "findings": [finding.model_dump(mode="json") for finding in observation.findings],
            "measurement_ready": observation.measurement_ready,
        }
    )
    if observation.blocks_measurement and not allow_blocked:
        raise click.exceptions.Exit(2)


def _observe_platform(
    definition: SubjectDefinition,
    *,
    app_bundle: Path | None,
    adb_serial: str | None,
) -> tuple[PlatformObservation, ClientObservation]:
    """Dispatch to the collector matching the subject's declared operating system."""

    operating_system = definition.platform.os
    if operating_system == "macOS":
        if app_bundle is None:
            raise click.ClickException(
                "a macOS subject needs --app-bundle pointing at the installed application"
            )
        return collect_macos_platform(), collect_macos_client(app_bundle)
    if operating_system == "Android":
        package = definition.client.package_identifier
        if not package:
            raise click.ClickException(
                f"subject {definition.subject_id} declares no package identifier to observe"
            )
        return (
            collect_android_platform(serial=adb_serial),
            collect_android_client(package=package, serial=adb_serial),
        )
    return (
        PlatformObservation(
            status=FieldStatus.UNAVAILABLE,
            os=operating_system,
            source="none",
            detail={"reason": f"no collector for {operating_system}"},
        ),
        ClientObservation(
            status=FieldStatus.UNAVAILABLE,
            source="none",
            detail={"reason": f"no collector for {operating_system}"},
        ),
    )


@main.command("publish")
@click.option(
    "--bundle",
    type=click.Path(path_type=Path, file_okay=False, exists=True),
    required=True,
    help="A complete run bundle produced by 'pt-bench aggregate'.",
)
@click.option(
    "--staging",
    type=click.Path(path_type=Path, file_okay=False),
    required=True,
    help="Where to write the publication receipt. Must be outside the bundle.",
)
@click.option(
    "--root",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path(),
    show_default=True,
)
def publish_command(*, bundle: Path, staging: Path, root: Path) -> None:
    """Re-check a run bundle against the operational policy and record its publication.

    Publication is fail-closed. Every unmet requirement is reported at once, so a
    blocked lane lists all of its outstanding obligations instead of one per run. The
    receipt is written only when the bundle clears the gate; the workflow that
    follows performs the release upload and attestation.
    """

    try:
        analysis = load_bundle(bundle)
        registry = OperationsRegistry.load(root)
        decision = evaluate_publication(analysis, registry)
        if not decision.allowed:
            _emit_json(
                {
                    "published": False,
                    "bundle_id": str(analysis.manifest.bundle_id),
                    "reasons": list(decision.reasons),
                }
            )
            raise click.exceptions.Exit(2)
        receipt = stage_publication(
            analysis=analysis,
            registry=registry,
            staging_directory=staging,
        )
    except click.exceptions.Exit:
        raise
    except Exception as error:
        raise click.ClickException(str(error)) from error

    _emit_json(
        {
            "published": True,
            "target": receipt.target,
            "receipt": str(staging / f"{receipt.bundle_id}.receipt.json"),
            "receipt_id": str(receipt.receipt_id),
            "bundle_id": str(receipt.bundle_id),
            "bundle_digest": receipt.bundle_digest,
            "attested": receipt.attested,
            "run": {
                "repository": receipt.github.repository,
                "run_id": receipt.github.run_id,
                "run_attempt": receipt.github.run_attempt,
            },
        }
    )


@main.group("operations")
def operations() -> None:
    """Inspect the checked-in operational policy that gates canonical runs."""


@operations.command("validate")
@click.option(
    "--root",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path(),
    show_default=True,
)
def operations_validate(root: Path) -> None:
    """Validate the operations policy and report canonical readiness per subject."""

    try:
        loaded = OperationsRegistry.load(root)
    except Exception as error:
        raise click.ClickException(str(error)) from error

    policy = loaded.policy
    decisions: dict[str, int] = {}
    unmeasured: list[dict[str, str]] = []
    for review in policy.terms_reviews:
        decisions[review.decision.value] = decisions.get(review.decision.value, 0) + 1
        if review.decision is not ReviewDecision.APPROVED:
            unmeasured.append(
                {
                    "subject": f"{review.subject_id}@{review.subject_version}",
                    "provider": review.provider,
                    "decision": review.decision.value,
                }
            )
    unprovisioned = sorted(
        {
            lane.runner_class.value
            for lane in policy.runner_lanes
            if lane.provisioning is not ProvisioningState.PROVISIONED
        }
        | {
            service.service_id
            for service in policy.canary_services
            if service.provisioning is not ProvisioningState.PROVISIONED
        }
    )
    _emit_json(
        {
            "valid": True,
            "policy": str(loaded.path.relative_to(root)),
            "operations_version": policy.version,
            "status": policy.status,
            "reference_vantage": policy.reference_vantage.vantage_id,
            "publication_target": policy.publication.target,
            "runner_lanes": len(policy.runner_lanes),
            "account_procedures": len(policy.account_procedures),
            "canary_services": len(policy.canary_services),
            "terms_reviews": len(policy.terms_reviews),
            "review_decisions": decisions,
            "canonical_blocked_subjects": unmeasured,
            "unprovisioned_infrastructure": unprovisioned,
        }
    )
    if unmeasured or unprovisioned:
        raise click.exceptions.Exit(2)


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
            "subject-observation",
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
@click.option(
    "--allow-unapproved-subjects",
    is_flag=True,
    help="Plan a GitHub Actions run without approved provider-terms reviews.",
)
def plan_command(
    *, suite: Path, output: Path, root: Path, mode: str | None, allow_unapproved_subjects: bool
) -> None:
    """Create a run plan from a checked-in suite."""

    try:
        execution_mode = resolve_execution_mode(ExecutionMode(mode) if mode is not None else None)
        github = github_provenance_from_environment()
        plan = build_run_plan(
            suite,
            root,
            execution_mode=execution_mode,
            github=github,
            require_canonical_approval=not allow_unapproved_subjects,
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
@click.option(
    "--table",
    "as_table",
    is_flag=True,
    help="Print a check-by-subject matrix instead of the JSON summary.",
)
def rollup_command(*, bundle: Path, output: Path, as_table: bool) -> None:
    """Summarize how stable each per-check outcome was across repetitions."""

    try:
        rollup = write_rollup(bundle, output)
    except Exception as error:
        raise click.ClickException(str(error)) from error
    if as_table:
        click.echo(render_rollup_matrix(rollup))
    else:
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
