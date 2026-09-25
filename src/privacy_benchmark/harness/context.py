"""Execution context shared by benchmark adapters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import UUID

from privacy_benchmark.spec.models import CheckDefinition, RunPlan, SubjectDefinition


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    plan: RunPlan
    subject: SubjectDefinition
    checks: tuple[CheckDefinition, ...]
    execution_id: UUID
    execution_dir: Path
    adapter_id: str
    repetition: int
    started_at: datetime
