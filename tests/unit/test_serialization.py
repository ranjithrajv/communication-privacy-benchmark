"""Property-based serialization tests."""

from __future__ import annotations

import json

from hypothesis import given
from hypothesis import strategies as st

from privacy_benchmark.spec.serialization import json_bytes, sha256_bytes

json_scalars = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(10**12), max_value=10**12)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=200),
    lambda children: (
        st.lists(children, max_size=20)
        | st.dictionaries(st.text(min_size=1, max_size=40), children, max_size=20)
    ),
    max_leaves=50,
)


@given(json_scalars)
def test_json_serialization_is_deterministic(value: object) -> None:
    first = json_bytes(value)
    second = json_bytes(value)
    assert first == second
    assert first.endswith(b"\n")
    assert json.loads(first) == value


@given(json_scalars)
def test_hashing_is_deterministic(value: object) -> None:
    payload = json_bytes(value)
    assert sha256_bytes(payload) == sha256_bytes(payload)


def test_hashing_matches_the_published_sha256_vectors() -> None:
    # Evidence integrity is verified against a checksum recomputed from the same bytes by
    # a reader outside this codebase, so the digest has to be real SHA-256 rather than any
    # stable string. A length or self-consistency check would pass a wrong algorithm.
    assert sha256_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert (
        sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
