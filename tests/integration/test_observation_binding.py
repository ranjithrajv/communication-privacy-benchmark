"""The preflight observation must reach the run record, not sit beside it.

Preflight is only worth running if the result can be attributed to the build it was
measured on. A subject definition deliberately leaves app version, build, and artifact
hash unset, so the observation on the manifest is the only record of which build a row
belongs to.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from privacy_benchmark.adapters.fake import FakeAdapter
from privacy_benchmark.harness.aggregation import aggregate_run
from privacy_benchmark.harness.analysis import load_bundle, rollup_bundle
from privacy_benchmark.harness.execution import (
    ExecutionOutcome,
    finalize_execution,
    run_execution,
)
from privacy_benchmark.harness.preflight import (
    build_observation,
    observe_vantage,
)
from privacy_benchmark.spec.models import (
    CheckDefinition,
    ClientObservation,
    CompletionState,
    ExecutionManifest,
    FieldStatus,
    PlatformObservation,
    RunPlan,
    SubjectDefinition,
    SubjectObservation,
    SubjectRef,
)
from privacy_benchmark.spec.registry import Registry
from privacy_benchmark.spec.serialization import read_model_json, verify_checksums, write_checksums

PUBLIC_ADDRESS = "8.8.8.8"


def _observation(subject: SubjectDefinition, *, version: str = "16.0") -> SubjectObservation:
    return build_observation(
        subject=SubjectRef(subject_id=subject.subject_id, subject_version=subject.subject_version),
        client=ClientObservation(
            status=FieldStatus.OBSERVED,
            name="Mail",
            version=version,
            package_identifier="com.apple.mail",
            source="macos-app-bundle",
        ),
        platform_observation=PlatformObservation(
            status=FieldStatus.OBSERVED, os="macOS", version="15.3", source="python-platform"
        ),
        vantage=observe_vantage(
            vantage_id="reference-de",
            remote_addresses=frozenset({PUBLIC_ADDRESS}),
            country_by_address={PUBLIC_ADDRESS: "DE"},
        ),
    )


def _execute(
    *,
    plan: RunPlan,
    subject: SubjectDefinition,
    check: CheckDefinition,
    execution_dir: Path,
    observation: SubjectObservation | None,
) -> ExecutionOutcome:
    return asyncio.run(
        run_execution(
            plan=plan,
            subject=subject,
            checks=(check,),
            adapter=FakeAdapter(),
            execution_dir=execution_dir,
            repetition=1,
            observation=observation,
        )
    )


@pytest.fixture
def subject(registry: Registry) -> SubjectDefinition:
    return registry.resolve_subject("fake-client@1.0.0")


@pytest.fixture
def check(registry: Registry) -> CheckDefinition:
    return registry.resolve_check("harness.smoke@1.0.0")


class TestObservationReachesTheManifest:
    def test_the_manifest_records_the_observed_build(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        outcome = _execute(
            plan=local_plan,
            subject=subject,
            check=check,
            execution_dir=tmp_path / "0001",
            observation=_observation(subject),
        )
        manifest = outcome.manifest
        assert manifest.observation is not None
        assert manifest.observation.client.version == "16.0"
        assert manifest.observation.client.package_identifier == "com.apple.mail"
        assert manifest.observation.vantage.country_code == "DE"
        assert manifest.observation.measurement_ready is True

    def test_a_pinned_definition_stays_untouched_by_the_observation(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        registry: Registry,
        check: CheckDefinition,
    ) -> None:
        """The observation supplies the version; the definition must stay silent.

        A real subject declares no app version, so if the observation were folded back
        into it a definition would end up asserting a build it never verified.
        """

        real = registry.resolve_subject("apple-mail-gmail-consumer@1.0.0")
        assert real.client.version is None
        _execute(
            plan=local_plan,
            subject=real,
            check=check,
            execution_dir=tmp_path / "0001",
            observation=_observation(real),
        )
        manifest = read_model_json(tmp_path / "0001" / "manifest.json", ExecutionManifest)
        assert manifest.subject.client.version is None
        assert manifest.observation is not None
        assert manifest.observation.client.version == "16.0"

    def test_the_observation_is_inside_the_checksummed_execution(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        _execute(
            plan=local_plan,
            subject=subject,
            check=check,
            execution_dir=tmp_path / "0001",
            observation=_observation(subject),
        )
        assert (tmp_path / "0001" / "subject-observation.json").is_file()
        # Covered by the same seal as the evidence, so it cannot be swapped afterwards.
        assert verify_checksums(tmp_path / "0001") == []

    def test_a_tampered_observation_fails_the_execution_seal(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        _execute(
            plan=local_plan,
            subject=subject,
            check=check,
            execution_dir=tmp_path / "0001",
            observation=_observation(subject),
        )
        path = tmp_path / "0001" / "subject-observation.json"
        path.write_text(path.read_text().replace('"16.0"', '"99.9"'))
        assert verify_checksums(tmp_path / "0001") != []

    def test_a_run_without_preflight_records_no_observation(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        outcome = _execute(
            plan=local_plan,
            subject=subject,
            check=check,
            execution_dir=tmp_path / "0001",
            observation=None,
        )
        assert outcome.manifest.observation is None
        assert not (tmp_path / "0001" / "subject-observation.json").exists()


class TestObservationSurvivesFinalize:
    def test_a_standalone_finalize_keeps_the_observation(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        """The finalize command re-derives the manifest from disk, so it must not drop
        the observation that the execution wrote."""

        _execute(
            plan=local_plan,
            subject=subject,
            check=check,
            execution_dir=tmp_path / "0001",
            observation=_observation(subject, version="16.0"),
        )
        manifest = finalize_execution(execution_dir=tmp_path / "0001", plan=local_plan)
        assert manifest.observation is not None
        assert manifest.observation.client.version == "16.0"
        assert manifest.completion is CompletionState.COMPLETE
        assert verify_checksums(tmp_path / "0001") == []

    def test_a_failed_finalize_still_reports_the_observation(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        _execute(
            plan=local_plan,
            subject=subject,
            check=check,
            execution_dir=tmp_path / "0001",
            observation=_observation(subject),
        )
        (tmp_path / "0001" / "results" / "harness.smoke.json").unlink()
        write_checksums(tmp_path / "0001")
        manifest = finalize_execution(execution_dir=tmp_path / "0001", plan=local_plan)
        assert manifest.observation is not None


class TestObservationSurvivesAggregation:
    def test_the_bundle_carries_the_observation(
        self,
        tmp_path: Path,
        local_plan: RunPlan,
        subject: SubjectDefinition,
        check: CheckDefinition,
    ) -> None:
        _execute(
            plan=local_plan,
            subject=subject,
            check=check,
            execution_dir=tmp_path / "executions" / "fake-client" / "0001",
            observation=_observation(subject),
        )
        outcome = aggregate_run(
            plan=local_plan,
            executions_root=tmp_path / "executions",
            output_dir=tmp_path / "bundle",
        )
        assert outcome.manifest.execution_manifests[0].observation is not None
        # A derived view must not lose it either.
        rollup = rollup_bundle(load_bundle(outcome.output_dir))
        assert rollup.bundle_id == outcome.manifest.bundle_id
