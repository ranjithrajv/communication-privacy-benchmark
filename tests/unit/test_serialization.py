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
    assert len(sha256_bytes(payload)) == 64
