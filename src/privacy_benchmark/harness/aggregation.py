"""Validate, copy, and aggregate finalized execution bundles."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid7

from privacy_benchmark.spec.models import (
    CheckResult,
    CompletionState,
    EvidenceRecord,
    ExecutionManifest,
    RunBundleManifest,
    RunPlan,
    SubjectRef,
    utc_now,
)
from privacy_benchmark.spec.serialization import (
    read_model_json,
    sha256_bytes,
    verify_checksums,
    write_checksums,
    write_model_json,
)


class AggregationError(RuntimeError):
    """Raised when execution bundles cannot be safely aggregated."""


@dataclass(frozen=True, slots=True)
class AggregationOutcome:
    output_dir: Path
    manifest: RunBundleManifest
    evidence_count: int


def aggregate_run(
    *,
    plan: RunPlan,
    executions_root: Path,
    output_dir: Path,
    force: bool = False,
) -> AggregationOutcome:
    manifest_paths = sorted(executions_root.rglob("manifest.json"))
    if not manifest_paths:
        raise AggregationError(f"no execution manifests found under {executions_root}")
    if output_dir.exists() and any(output_dir.iterdir()):
        if not force:
            raise AggregationError(f"output directory is not empty: {output_dir}")
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    manifests: list[ExecutionManifest] = []
    result_count = 0
    evidence_ids: set[str] = set()
    evidence_count = 0
    positions: set[tuple[str, str, int]] = set()

    for manifest_path in manifest_paths:
        execution_dir = manifest_path.parent
        checksum_errors = verify_checksums(execution_dir)
        if checksum_errors:
            raise AggregationError(
                f"invalid execution bundle {execution_dir}: " + "; ".join(checksum_errors)
            )
        manifest = read_model_json(manifest_path, ExecutionManifest)
        if manifest.plan_id != plan.plan_id or manifest.run_id != plan.plan_id:
            raise AggregationError(f"execution {manifest.execution_id} belongs to another plan")
        subject_key = (manifest.subject.subject_id, manifest.subject.subject_version)
        if subject_key not in {
            (subject.subject_id, subject.subject_version) for subject in plan.subjects
        }:
            raise AggregationError(f"execution {manifest.execution_id} uses an unplanned subject")

        # The repetition axis is what makes a pass rate mean anything, so a position
        # must be claimed by exactly one execution. Without this, two executions
        # claiming the same repetition would overwrite each other's results while
        # result_count still counted both, producing a bundle that reports complete for
        # a repetition that was never measured.
        position = (*subject_key, manifest.repetition)
        if position in positions:
            raise AggregationError(
                f"repetition {manifest.repetition} of subject "
                f"{manifest.subject.subject_id}@{manifest.subject.subject_version} is "
                "claimed by more than one execution"
            )
        if not 1 <= manifest.repetition <= plan.repetitions:
            raise AggregationError(
                f"execution {manifest.execution_id} claims repetition "
                f"{manifest.repetition} outside the planned 1..{plan.repetitions}"
            )
        # Together these two guards bound the manifest count to
        # len(plan.subjects) * plan.repetitions, which is exactly
        # plan.expected_execution_count, so no separate count check is needed.
        positions.add(position)

        relative_base = Path(manifest.subject.subject_id) / f"{manifest.repetition:04d}"
        for result_ref in manifest.results:
            source_result = execution_dir / result_ref.path
            result = read_model_json(source_result, CheckResult)
            if result.execution_id != manifest.execution_id:
                raise AggregationError(f"result {result.result_id} has the wrong execution id")
            destination = output_dir / "results" / relative_base / f"{result.check.check_id}.json"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_result, destination)
            result_count += 1

            for evidence_id in result.evidence_refs:
                if evidence_id in evidence_ids:
                    raise AggregationError(
                        f"duplicate evidence id across executions: {evidence_id}"
                    )
                record_path = execution_dir / "evidence" / f"{evidence_id}.json"
                record = read_model_json(record_path, EvidenceRecord)
                if record.execution_id != manifest.execution_id:
                    raise AggregationError(f"evidence {evidence_id} has the wrong execution id")
                payload_paths = sorted(
                    path
                    for path in (execution_dir / "evidence").glob(f"{evidence_id}.payload*")
                    if path.is_file()
                )
                if len(payload_paths) != 1:
                    raise AggregationError(
                        f"evidence {evidence_id} must have exactly one payload file"
                    )
                payload = payload_paths[0].read_bytes()
                if sha256_bytes(payload) != record.sha256:
                    raise AggregationError(f"evidence {evidence_id} checksum does not match record")
                if len(payload) != record.size_bytes:
                    raise AggregationError(f"evidence {evidence_id} size does not match record")
                evidence_destination = (
                    output_dir / "evidence" / relative_base / payload_paths[0].name
                )
                evidence_destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(payload_paths[0], evidence_destination)
                shutil.copy2(
                    record_path,
                    output_dir / "evidence" / relative_base / f"{evidence_id}.record.json",
                )
                evidence_ids.add(evidence_id)
                evidence_count += 1

        manifests.append(manifest)

    subject_counts = {
        (manifest.subject.subject_id, manifest.subject.subject_version): 0 for manifest in manifests
    }
    for manifest in manifests:
        key = (manifest.subject.subject_id, manifest.subject.subject_version)
        subject_counts[key] += 1

    missing_subjects = tuple(
        SubjectRef(subject_id=subject_id, subject_version=subject_version)
        for (subject_id, subject_version), count in subject_counts.items()
        if count < plan.repetitions
    )
    planned_subject_keys = {
        (subject.subject_id, subject.subject_version) for subject in plan.subjects
    }
    missing_subjects = tuple(
        [
            *missing_subjects,
            *(
                SubjectRef(subject_id=subject_id, subject_version=subject_version)
                for subject_id, subject_version in sorted(
                    planned_subject_keys - set(subject_counts)
                )
            ),
        ]
    )
    duplicate_subjects = len(manifests) != len({manifest.execution_id for manifest in manifests})
    if duplicate_subjects:
        raise AggregationError("duplicate execution manifests found")

    completion = (
        CompletionState.INCOMPLETE
        if missing_subjects or len(manifests) < plan.expected_execution_count
        else CompletionState.COMPLETE
    )
    bundle_manifest = RunBundleManifest(
        bundle_id=uuid7(),
        plan=plan,
        created_at=utc_now(),
        completion=completion,
        execution_manifests=tuple(manifests),
        result_count=result_count,
        evidence_count=evidence_count,
        missing_subjects=missing_subjects,
    )
    write_model_json(output_dir / "manifest.json", bundle_manifest)
    write_checksums(output_dir)
    return AggregationOutcome(
        output_dir=output_dir,
        manifest=bundle_manifest,
        evidence_count=evidence_count,
    )
