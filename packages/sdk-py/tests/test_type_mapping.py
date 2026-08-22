import pytest

from zerostyl_sdk import FieldType, field_type_to_py


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("u64", "int"),
        ("u128", "int"),
        ("bool", "bool"),
        ("fp", "str"),
        ("bytes32", "str"),
        ("address", "str"),
    ],
)
def test_scalar_mappings(tag, expected):
    assert field_type_to_py(FieldType(type=tag)) == expected


def test_array_mapping():
    t = FieldType(type="array", kind=FieldType(type="fp"), len=32)
    assert field_type_to_py(t) == "tuple[str, ...]"


def test_nested_array_mapping():
    inner = FieldType(type="array", kind=FieldType(type="u64"), len=4)
    outer = FieldType(type="array", kind=inner, len=2)
    assert field_type_to_py(outer) == "tuple[tuple[int, ...], ...]"
