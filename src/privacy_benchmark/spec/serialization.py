"""Deterministic JSON serialization and checksum helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel


def json_bytes(value: object) -> bytes:
    """Serialize a value as deterministic, newline-terminated JSON."""

    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"{payload}\n".encode()


def model_json_bytes(model: BaseModel) -> bytes:
    return json_bytes(model.model_dump(mode="json"))


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_bytes_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_bytes(payload)
    temporary_path.replace(path)


def write_model_json[ModelT: BaseModel](path: Path, model: ModelT) -> bytes:
    payload = model_json_bytes(model)
    write_bytes_atomic(path, payload)
    return payload


def read_model_json[ModelT: BaseModel](path: Path, model_type: type[ModelT]) -> ModelT:
    return model_type.model_validate_json(path.read_bytes())


def write_checksums(root: Path, relative_paths: list[Path] | None = None) -> Path:
    """Write SHA-256 checksums for files under root, excluding the checksum file."""

    if relative_paths is None:
        relative_paths = [path for path in root.rglob("*") if path.is_file()]
    filtered = [
        path for path in relative_paths if path.name != "checksums.sha256" and path.is_file()
    ]
    filtered.sort(key=lambda path: path.relative_to(root).as_posix())
    lines = [
        f"{sha256_bytes(path.read_bytes())}  {path.relative_to(root).as_posix()}"
        for path in filtered
    ]
    checksum_path = root / "checksums.sha256"
    write_bytes_atomic(checksum_path, ("\n".join(lines) + "\n").encode())
    return checksum_path


def verify_checksums(root: Path) -> list[str]:
    """Verify checksums and return a list of human-readable errors."""

    checksum_path = root / "checksums.sha256"
    if not checksum_path.is_file():
        return [f"missing checksum file: {checksum_path}"]

    errors: list[str] = []
    expected_paths: set[str] = set()
    for line_number, line in enumerate(checksum_path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            expected_hash, relative_path = line.split("  ", maxsplit=1)
        except ValueError:
            errors.append(f"{checksum_path}:{line_number}: malformed checksum line")
            continue
        expected_paths.add(relative_path)
        path = root / relative_path
        if not path.is_file():
            errors.append(f"missing file: {relative_path}")
            continue
        actual_hash = sha256_bytes(path.read_bytes())
        if actual_hash != expected_hash:
            errors.append(
                f"checksum mismatch: {relative_path}: expected {expected_hash}, got {actual_hash}"
            )

    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "checksums.sha256"
    }
    errors.extend(
        f"unlisted file: {extra_path}" for extra_path in sorted(actual_paths - expected_paths)
    )
    return errors
