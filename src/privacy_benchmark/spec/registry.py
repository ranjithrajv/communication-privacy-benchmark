"""Load and validate checked-in check, subject, and suite definitions."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field

from privacy_benchmark.spec.constants import ID_PATTERN, SCHEMA_VERSION, SEMVER_PATTERN
from privacy_benchmark.spec.models import (
    CheckDefinition,
    LifecycleStatus,
    SubjectDefinition,
)


class DefinitionError(ValueError):
    """Raised when a definition file cannot be parsed."""


class RegistryValidationError(ValueError):
    """Raised when the registry violates a cross-file invariant."""


class SuiteDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: Literal["1alpha1"] = SCHEMA_VERSION
    suite_id: str = Field(pattern=ID_PATTERN)
    version: str = Field(pattern=SEMVER_PATTERN)
    status: LifecycleStatus = LifecycleStatus.ACTIVE
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4000)
    checks: tuple[str, ...] = Field(min_length=1)
    subjects: tuple[str, ...] = Field(min_length=1)
    repetitions: int = Field(default=1, ge=1, le=20)


@dataclass(frozen=True, slots=True)
class Registry:
    root: Path
    checks: dict[tuple[str, str], CheckDefinition] = field(default_factory=dict)
    subjects: dict[tuple[str, str], SubjectDefinition] = field(default_factory=dict)
    suites: dict[tuple[str, str], SuiteDefinition] = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path) -> Self:
        checks: dict[tuple[str, str], CheckDefinition] = {}
        subjects: dict[tuple[str, str], SubjectDefinition] = {}
        suites: dict[tuple[str, str], SuiteDefinition] = {}

        for path in sorted(root.glob("checks/*/*/*/check.toml")):
            check = CheckDefinition.model_validate(_read_toml(path))
            _validate_definition_path(path, root, "checks", check.check_id, check.version)
            checks[(check.check_id, check.version)] = check

        for path in sorted(root.glob("subjects/*/*/subject.toml")):
            subject = SubjectDefinition.model_validate(_read_toml(path))
            _validate_definition_path(
                path, root, "subjects", subject.subject_id, subject.subject_version
            )
            subjects[(subject.subject_id, subject.subject_version)] = subject

        for path in sorted(root.glob("suites/*/*/suite.toml")):
            suite = SuiteDefinition.model_validate(_read_toml(path))
            _validate_definition_path(path, root, "suites", suite.suite_id, suite.version)
            suites[(suite.suite_id, suite.version)] = suite

        registry = cls(root=root, checks=checks, subjects=subjects, suites=suites)
        registry.validate()
        return registry

    def validate(self) -> None:
        errors: list[str] = []

        active_suite_checks: set[tuple[str, str]] = set()
        for suite_key, suite in self.suites.items():
            if suite.status is not LifecycleStatus.ACTIVE:
                continue
            for reference in suite.checks:
                try:
                    check_key = parse_reference(reference)
                    check = self.checks[check_key]
                except (RegistryValidationError, KeyError) as error:
                    errors.append(f"suite {suite_key[0]}@{suite_key[1]}: {error}")
                    continue
                active_suite_checks.add(check_key)
                if check.status is not LifecycleStatus.ACTIVE:
                    errors.append(
                        f"suite {suite_key[0]}@{suite_key[1]} references "
                        f"non-active check {reference}"
                    )
                if check.canonical and check.adapter_id in {"fake", "unimplemented"}:
                    errors.append(
                        f"check {check.check_id}@{check.version} is canonical but uses "
                        f"non-production adapter {check.adapter_id}"
                    )
            for reference in suite.subjects:
                try:
                    self.subjects[parse_reference(reference)]
                except (RegistryValidationError, KeyError) as error:
                    errors.append(f"suite {suite_key[0]}@{suite_key[1]}: {error}")

        for check_key, check in self.checks.items():
            if (
                check.status is LifecycleStatus.ACTIVE
                and check.canonical
                and check_key not in active_suite_checks
            ):
                errors.append(
                    f"active canonical check {check_key[0]}@{check_key[1]} is not in a suite"
                )

        if errors:
            raise RegistryValidationError("\n".join(errors))

    def resolve_check(self, reference: str) -> CheckDefinition:
        return self.checks[parse_reference(reference)]

    def resolve_subject(self, reference: str) -> SubjectDefinition:
        return self.subjects[parse_reference(reference)]

    def resolve_suite(self, reference: str) -> SuiteDefinition:
        return self.suites[parse_reference(reference)]


def parse_reference(reference: str) -> tuple[str, str]:
    if reference.count("@") != 1:
        raise RegistryValidationError(f"definition reference must be id@version: {reference}")
    identifier, version = reference.split("@", maxsplit=1)
    if not identifier or not version:
        raise RegistryValidationError(f"definition reference must be id@version: {reference}")
    return identifier, version


def _read_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            # `tomllib.load` hands back `dict[str, Any]`. Binding it to the type this
            # function promises keeps the guarantee visible to callers: the returned
            # table holds `object`, not `Any`, so reading a key still needs a real type.
            value: dict[str, object] = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise DefinitionError(f"{path}: {error}") from error
    if not isinstance(value, dict):
        raise DefinitionError(f"{path}: top-level TOML value must be a table")
    return value


def _validate_definition_path(
    path: Path,
    root: Path,
    directory: str,
    identifier: str,
    version: str,
) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise DefinitionError(f"{path}: definition is outside repository root") from error
    expected_parts = 5 if directory == "checks" else 4
    if len(relative.parts) != expected_parts:
        raise DefinitionError(f"{path}: unexpected definition directory depth")
    identity_index = 2 if directory == "checks" else 1
    actual_identifier = relative.parts[identity_index]
    if directory == "checks":
        actual_identifier = f"{relative.parts[1]}.{actual_identifier}"
    actual_version = relative.parts[identity_index + 1]
    if actual_identifier != identifier or actual_version != version:
        raise DefinitionError(
            f"{path}: path identity {actual_identifier}@{actual_version} does not match "
            f"{identifier}@{version}"
        )
