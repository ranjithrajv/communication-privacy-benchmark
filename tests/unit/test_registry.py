"""Registry definition tests."""

from __future__ import annotations

import pytest

from privacy_benchmark.spec.registry import Registry, RegistryValidationError, parse_reference


def test_checked_in_registry_is_valid(registry: Registry) -> None:
    assert set(registry.checks) == {
        ("email.remote-content", "1.0.0"),
        ("harness.smoke", "1.0.0"),
    }
    assert ("fake-client", "1.0.0") in registry.subjects
    assert ("smoke", "1.0.0") in registry.suites


def test_draft_product_check_is_not_canonical_yet(registry: Registry) -> None:
    check = registry.resolve_check("email.remote-content@1.0.0")
    assert check.status.value == "draft"
    assert check.adapter_id == "unimplemented"


@pytest.mark.parametrize("reference", ["missing-version", "too@many@parts", "@1.0.0", "id@"])
def test_invalid_definition_references_are_rejected(reference: str) -> None:
    with pytest.raises(RegistryValidationError):
        parse_reference(reference)
