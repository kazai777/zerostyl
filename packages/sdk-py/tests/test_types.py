import json

import pytest

from zerostyl_sdk import ABI_VERSION, FieldType, parse_abi_schema


def sample_abi() -> dict:
    return {
        "abi_version": ABI_VERSION,
        "circuit": {
            "name": "deposit",
            "version": "1.0.0",
            "description": "test circuit",
            "default_k": 10,
            "num_public_inputs": 1,
            "num_private_witnesses": 2,
        },
        "witness": {
            "fields": [
                {"name": "amount", "kind": {"type": "fp"}, "visibility": "private"},
                {"name": "amount_nonce", "kind": {"type": "fp"}, "visibility": "private"},
            ]
        },
        "public_inputs": {
            "fields": [{"name": "amount_commitment", "kind": {"type": "fp"}}]
        },
        "proof": {"format_version": 1, "proving_system": "halo2_kzg"},
    }


def test_parses_valid_schema():
    abi = parse_abi_schema(json.dumps(sample_abi()))
    assert abi.abi_version == ABI_VERSION
    assert abi.circuit.name == "deposit"
    assert abi.witness.fields[0].name == "amount"
    assert abi.public_inputs.fields[0].kind.type == "fp"
    assert abi.proof.proving_system == "halo2_kzg"
    assert abi.on_chain is None


def test_parses_nested_array_field_type():
    data = sample_abi()
    data["witness"]["fields"][0]["kind"] = {
        "type": "array",
        "kind": {"type": "fp"},
        "len": 32,
    }
    abi = parse_abi_schema(json.dumps(data))
    kind = abi.witness.fields[0].kind
    assert kind.is_array
    assert kind.len == 32
    assert kind.kind == FieldType(type="fp")


def test_parses_on_chain_binding():
    data = sample_abi()
    data["on_chain"] = {"chain_id": 421614, "contract_address": "0x" + "aa" * 20}
    abi = parse_abi_schema(json.dumps(data))
    assert abi.on_chain is not None
    assert abi.on_chain.chain_id == 421614


@pytest.mark.parametrize(
    "system", ["halo2_ipa", "halo2_kzg_groth16_wrap", "halo2_kzg", "stark_fri"]
)
def test_accepts_all_proving_systems(system):
    data = sample_abi()
    data["proof"]["proving_system"] = system
    assert parse_abi_schema(json.dumps(data)).proof.proving_system == system


def test_rejects_unknown_proving_system():
    data = sample_abi()
    data["proof"]["proving_system"] = "groth16"
    with pytest.raises(ValueError, match="unknown proving system"):
        parse_abi_schema(json.dumps(data))


def test_rejects_wrong_abi_version():
    data = sample_abi()
    data["abi_version"] = 99
    with pytest.raises(ValueError, match="unsupported abi_version"):
        parse_abi_schema(json.dumps(data))


def test_rejects_public_input_count_mismatch():
    data = sample_abi()
    data["circuit"]["num_public_inputs"] = 5
    with pytest.raises(ValueError, match="num_public_inputs"):
        parse_abi_schema(json.dumps(data))


def test_rejects_witness_count_mismatch():
    data = sample_abi()
    data["circuit"]["num_private_witnesses"] = 5
    with pytest.raises(ValueError, match="num_private_witnesses"):
        parse_abi_schema(json.dumps(data))


def sample_abi_with_public_witness() -> dict:
    """Two private witnesses plus one public one (a comparison operand the contract supplies).

    The public field stays in ``witness.fields`` — the prover still has to assign its cell — but
    only the private ones count towards ``num_private_witnesses``.
    """
    data = sample_abi()
    data["circuit"]["num_public_inputs"] = 2
    data["witness"]["fields"].append(
        {"name": "threshold", "kind": {"type": "u64"}, "visibility": "public"}
    )
    data["public_inputs"]["fields"].append({"name": "threshold", "kind": {"type": "u64"}})
    return data


def test_accepts_public_witness_field_not_counted_as_private():
    abi = parse_abi_schema(json.dumps(sample_abi_with_public_witness()))
    assert len(abi.witness.fields) == 3
    assert abi.circuit.num_private_witnesses == 2


def test_rejects_private_count_below_the_number_of_private_fields():
    data = sample_abi_with_public_witness()
    data["circuit"]["num_private_witnesses"] = 1
    with pytest.raises(ValueError, match="num_private_witnesses"):
        parse_abi_schema(json.dumps(data))


def test_rejects_private_count_that_includes_the_public_field():
    data = sample_abi_with_public_witness()
    data["circuit"]["num_private_witnesses"] = 3
    with pytest.raises(ValueError, match="num_private_witnesses"):
        parse_abi_schema(json.dumps(data))


def test_rejects_malformed_json():
    with pytest.raises(ValueError, match="not valid JSON"):
        parse_abi_schema("{not json")


def test_array_field_missing_kind_or_len_raises_value_error():
    data = sample_abi()
    data["witness"]["fields"][0]["kind"] = {"type": "array", "kind": {"type": "fp"}}  # no len
    with pytest.raises(ValueError, match="requires `kind` and `len`"):
        parse_abi_schema(json.dumps(data))


def test_rejects_unknown_field_type_tag():
    data = sample_abi()
    data["witness"]["fields"][0]["kind"] = {"type": "u256"}
    with pytest.raises(ValueError, match="unknown field type tag"):
        parse_abi_schema(json.dumps(data))


def test_rejects_unknown_visibility():
    data = sample_abi()
    data["witness"]["fields"][0]["visibility"] = "hidden"
    with pytest.raises(ValueError, match="unknown visibility"):
        parse_abi_schema(json.dumps(data))


def test_field_type_validates_array_shape():
    with pytest.raises(ValueError, match="requires `kind` and `len`"):
        FieldType(type="array")
    with pytest.raises(ValueError, match="takes no"):
        FieldType(type="fp", len=3)
