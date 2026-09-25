"""Generate and validate committed public JSON Schemas."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from privacy_benchmark.spec.constants import JSON_SCHEMA_DIALECT, SCHEMA_VERSION
from privacy_benchmark.spec.models import schema_model_registry
from privacy_benchmark.spec.serialization import write_bytes_atomic


def generate_schemas() -> dict[str, dict[str, Any]]:
    """Generate the public schema registry from the Pydantic models."""

    generated: dict[str, dict[str, Any]] = {}
    for filename, model_type in schema_model_registry().items():
        schema = model_type.model_json_schema(by_alias=True, mode="validation")
        schema["$schema"] = JSON_SCHEMA_DIALECT
        schema.setdefault(
            "$id",
            f"urn:communication-privacy-benchmark:schema:{filename.removesuffix('.schema.json')}:{SCHEMA_VERSION}",
        )
        schema["title"] = model_type.__name__
        generated[filename] = schema
    return generated


def _schema_bytes(schema: dict[str, Any]) -> bytes:
    return (json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def export_schemas(output_dir: Path, *, check: bool = False) -> list[str]:
    """Export schemas, or return drift errors when ``check`` is true."""

    drift_errors: list[str] = []
    for filename, schema in generate_schemas().items():
        path = output_dir / filename
        payload = _schema_bytes(schema)
        if check:
            if not path.is_file():
                drift_errors.append(f"missing schema: {path}")
            elif path.read_bytes() != payload:
                drift_errors.append(f"schema drift: {path}")
        else:
            write_bytes_atomic(path, payload)
    return drift_errors


def validate_document(path: Path, kind: str) -> BaseModel:
    """Validate a public document against one registered contract kind."""

    try:
        from jsonschema import Draft202012Validator
    except ImportError as error:  # pragma: no cover - exercised only in minimal installs
        raise RuntimeError(
            "jsonschema is required for schema validation; install the project dependencies"
        ) from error

    registry = schema_model_registry()
    selected = {
        "check": registry["check.schema.json"],
        "subject": registry["subject.schema.json"],
        "run-plan": registry["run-plan.schema.json"],
        "result": registry["result.schema.json"],
        "evidence": registry["evidence.schema.json"],
        "execution-manifest": registry["execution-manifest.schema.json"],
        "run-bundle": registry["run-bundle.schema.json"],
    }.get(kind)
    if selected is None:
        raise ValueError(f"unknown schema kind: {kind}")

    schema_filename = next(name for name, model in registry.items() if model is selected)
    schema = generate_schemas()[schema_filename]
    document = json.loads(path.read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
    return selected.model_validate(document)
