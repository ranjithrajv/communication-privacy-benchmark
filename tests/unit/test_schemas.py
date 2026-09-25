"""Public schema generation and validation tests."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from privacy_benchmark.spec.schemas import export_schemas, generate_schemas


def test_every_generated_schema_is_valid_draft_2020_12() -> None:
    for filename, schema in generate_schemas().items():
        Draft202012Validator.check_schema(schema)
        assert schema["$id"].endswith(":1alpha1"), filename


def test_committed_schemas_have_no_drift(tmp_path: Path, repository_root: Path) -> None:
    export_schemas(tmp_path, check=False)
    for generated in tmp_path.glob("*.json"):
        committed = repository_root / "schemas" / "v1alpha1" / generated.name
        assert generated.read_bytes() == committed.read_bytes()


def test_committed_schema_registry_is_current(repository_root: Path) -> None:
    errors = export_schemas(repository_root / "schemas" / "v1alpha1", check=True)
    assert errors == []


def test_schema_files_are_deterministic(tmp_path: Path) -> None:
    export_schemas(tmp_path, check=False)
    first = {path.name: path.read_bytes() for path in tmp_path.glob("*.json")}
    export_schemas(tmp_path, check=False)
    second = {path.name: path.read_bytes() for path in tmp_path.glob("*.json")}
    assert first == second
    assert json.loads(next(iter(first.values())))["$schema"].endswith("2020-12/schema")
