"""Mapping from ABI field types to Python type annotations."""

from __future__ import annotations

from ..types import FieldType

_SCALAR_TO_PY = {
    "u64": "int",
    "u128": "int",
    "bool": "bool",
    # Field elements, hashes, and addresses travel as 0x-prefixed hex strings.
    "fp": "str",
    "bytes32": "str",
    "address": "str",
}


def field_type_to_py(field_type: FieldType) -> str:
    """Return the Python annotation for an ABI field type."""
    if field_type.is_array:
        assert field_type.kind is not None  # guaranteed by FieldType validation
        return f"tuple[{field_type_to_py(field_type.kind)}, ...]"
    return _SCALAR_TO_PY[field_type.type]
