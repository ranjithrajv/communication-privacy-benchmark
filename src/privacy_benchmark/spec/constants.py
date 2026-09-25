"""Public contract constants for the benchmark."""

from __future__ import annotations

from typing import Final

PACKAGE_VERSION: Final = "0.1.0"
SCHEMA_VERSION: Final = "1alpha1"
JSON_SCHEMA_DIALECT: Final = "https://json-schema.org/draft/2020-12/schema"

ID_PATTERN: Final = r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$"
SEMVER_PATTERN: Final = (
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SHA256_PATTERN: Final = r"^[0-9a-f]{64}$"
REPOSITORY_PATTERN: Final = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
