import json

from zerostyl_sdk import generate_bindings, parse_abi_schema
from zerostyl_sdk.codegen.generator import HEADER


def abi(witness_fields=None, public_fields=None, name="deposit"):
    witness_fields = witness_fields if witness_fields is not None else [
        {"name": "amount", "kind": {"type": "fp"}, "visibility": "private"}
    ]
    public_fields = public_fields if public_fields is not None else [
        {"name": "amount_commitment", "kind": {"type": "fp"}}
    ]
    return parse_abi_schema(
        json.dumps(
            {
                "abi_version": 1,
                "circuit": {
                    "name": name,
                    "version": "1.0.0",
                    "description": "test",
                    "default_k": 10,
                    "num_public_inputs": len(public_fields),
                    "num_private_witnesses": len(witness_fields),
                },
                "witness": {"fields": witness_fields},
                "public_inputs": {"fields": public_fields},
                "proof": {"format_version": 1, "proving_system": "halo2_kzg"},
            }
        )
    )


def test_generated_module_is_valid_python():
    code = generate_bindings(abi())
    compile(code, "<generated>", "exec")


def test_header_and_const_present():
    code = generate_bindings(abi())
    assert code.startswith(HEADER)
    assert 'DEPOSIT_CIRCUIT: Final = {' in code
    assert '"name": \'deposit\'' in code or "\"name\": 'deposit'" in code
    assert '"default_k": 10' in code


def test_dataclasses_have_typed_fields():
    code = generate_bindings(abi())
    assert "@dataclass(frozen=True)" in code
    assert "class DepositWitness:" in code
    assert "    amount: str" in code
    assert "class DepositPublicInputs:" in code
    assert "    amount_commitment: str" in code


def test_array_fields_map_to_tuples():
    code = generate_bindings(
        abi(
            witness_fields=[
                {
                    "name": "siblings",
                    "kind": {"type": "array", "kind": {"type": "fp"}, "len": 32},
                    "visibility": "private",
                }
            ]
        )
    )
    assert "    siblings: tuple[str, ...]" in code


def test_empty_schemas_generate_pass_dataclasses():
    code = generate_bindings(abi(witness_fields=[], public_fields=[]))
    compile(code, "<generated>", "exec")
    assert "class DepositWitness:\n    pass" in code
    assert "class DepositPublicInputs:\n    pass" in code


def test_multi_segment_name_pascal_cased():
    code = generate_bindings(abi(name="private_vote_tally"))
    assert "class PrivateVoteTallyWitness:" in code
    assert "PRIVATE_VOTE_TALLY_CIRCUIT: Final = {" in code


def test_python_keyword_field_names_are_sanitized():
    # `from` is a valid Rust identifier but a Python keyword; the generated
    # dataclass must stay importable.
    code = generate_bindings(
        abi(
            witness_fields=[
                {"name": "from", "kind": {"type": "address"}, "visibility": "private"},
                {"name": "amount", "kind": {"type": "u64"}, "visibility": "private"},
            ]
        )
    )
    compile(code, "<generated>", "exec")
    assert "    from_: str" in code
    assert "    amount: int" in code
