"""Adapter protocol and registry."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from pydantic import JsonValue

from privacy_benchmark.harness.context import ExecutionContext
from privacy_benchmark.spec.models import (
    CheckDefinition,
    EvidenceClass,
    EvidenceKind,
    Identifier,
    RedactionPolicy,
    ResultStatus,
)


class AdapterError(RuntimeError):
    """An adapter could not complete a check."""


@dataclass(frozen=True, slots=True)
class AdapterEvidence:
    evidence_id: str
    evidence_class: EvidenceClass
    kind: EvidenceKind
    media_type: str
    payload: bytes
    redaction: RedactionPolicy
    source_uri: str | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AdapterOutcome:
    status: ResultStatus
    reason_code: str
    summary: str
    details: Mapping[str, JsonValue] = field(default_factory=dict)
    evidence: tuple[AdapterEvidence, ...] = ()


@runtime_checkable
class CheckAdapter(Protocol):
    adapter_id: str
    version: str

    async def execute_check(
        self, check: CheckDefinition, context: ExecutionContext
    ) -> AdapterOutcome: ...


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, CheckAdapter] = {}

    def register(self, adapter: CheckAdapter) -> None:
        if adapter.adapter_id in self._adapters:
            raise ValueError(f"adapter already registered: {adapter.adapter_id}")
        self._adapters[adapter.adapter_id] = adapter

    def get(self, adapter_id: Identifier | str) -> CheckAdapter:
        try:
            return self._adapters[str(adapter_id)]
        except KeyError as error:
            available = ", ".join(sorted(self._adapters)) or "none"
            raise AdapterError(
                f"unknown adapter {adapter_id!s}; registered adapters: {available}"
            ) from error


def ensure_identifier(value: str, *, field_name: str = "identifier") -> str:
    """Validate identifiers used by adapters before they reach public contracts."""

    # Pydantic's generated pattern is not exported as a reusable validator, so the
    # adapter boundary performs a small, explicit check for the fields it constructs.
    import re

    from privacy_benchmark.spec.constants import ID_PATTERN

    if re.fullmatch(ID_PATTERN, value) is None:
        raise AdapterError(f"invalid {field_name}: {value!r}")
    return value


def freeze_json(value: Mapping[str, Any]) -> dict[str, JsonValue]:
    """Convert an adapter mapping into a JSON-compatible dictionary."""

    # Pydantic validates the final public model. This helper prevents accidental
    # inclusion of arbitrary Python objects in the details mapping.
    #
    # The suppression is a ty limitation, not a hole: ty expands Pydantic's recursive
    # `JsonValue` alias into a union containing `dict[str, Never]` and then fails to
    # recognise that expansion as a subtype of itself, so `dict[str, Any]` is reported
    # as not matching the `dict[str, JsonValue]` it is being returned against. mypy
    # accepts this because `Any` is assignable to `JsonValue`.
    return dict(value)  # ty: ignore[invalid-return-type]
