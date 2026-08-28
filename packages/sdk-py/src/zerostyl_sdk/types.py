"""Typed mirror of the ZeroStyl ABI schema (``abi.json``).

The dataclasses here map 1:1 onto the Rust ``zerostyl_circuits::abi::AbiSchema``
(and the TypeScript ``@zerostyl/sdk-ts`` types): circuit metadata, private
witness fields, public inputs, and proof metadata.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

ABI_VERSION = 1

_SCALAR_TAGS = frozenset({"u64", "u128", "bool", "bytes32", "address", "fp"})
_PROVING_SYSTEMS = frozenset(
    {"halo2_ipa", "halo2_kzg_groth16_wrap", "halo2_kzg", "stark_fri"}
)
_VISIBILITIES = frozenset({"private", "public"})


@dataclass(frozen=True)
class FieldType:
    """A field's wire type: a scalar tag, or ``array`` with ``kind``/``len``."""

    type: str
    kind: FieldType | None = None
    len: int | None = None

    def __post_init__(self) -> None:
        if self.type == "array":
            if self.kind is None or self.len is None:
                raise ValueError("array field type requires `kind` and `len`")
        elif self.type in _SCALAR_TAGS:
            if self.kind is not None or self.len is not None:
                raise ValueError(f"scalar field type `{self.type}` takes no `kind`/`len`")
        else:
            raise ValueError(f"unknown field type tag `{self.type}`")

    @property
    def is_array(self) -> bool:
        return self.type == "array"


@dataclass(frozen=True)
class WitnessField:
    name: str
    kind: FieldType
    visibility: str
    description: str | None = None

    def __post_init__(self) -> None:
        if self.visibility not in _VISIBILITIES:
            raise ValueError(f"unknown visibility `{self.visibility}`")


@dataclass(frozen=True)
class WitnessSchema:
    fields: tuple[WitnessField, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class PublicInputField:
    name: str
    kind: FieldType
    description: str | None = None


@dataclass(frozen=True)
class PublicInputsSchema:
    fields: tuple[PublicInputField, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CircuitMetadata:
    name: str
    version: str
    description: str
    default_k: int
    num_public_inputs: int
    num_private_witnesses: int


@dataclass(frozen=True)
class ProofMetadata:
    format_version: int
    proving_system: str
    approx_size_bytes: int | None = None

    def __post_init__(self) -> None:
        if self.proving_system not in _PROVING_SYSTEMS:
            raise ValueError(f"unknown proving system `{self.proving_system}`")


@dataclass(frozen=True)
class OnChainBinding:
    chain_id: int
    contract_address: str


@dataclass(frozen=True)
class AbiSchema:
    abi_version: int
    circuit: CircuitMetadata
    witness: WitnessSchema
    public_inputs: PublicInputsSchema
    proof: ProofMetadata
    on_chain: OnChainBinding | None = None


def _parse_field_type(data: Any) -> FieldType:
    if not isinstance(data, dict):
        raise ValueError(f"field type must be an object, got {type(data).__name__}")
    tag = data.get("type")
    if tag == "array":
        if "kind" not in data or "len" not in data:
            raise ValueError("array field type requires `kind` and `len`")
        return FieldType(type="array", kind=_parse_field_type(data["kind"]), len=int(data["len"]))
    if not isinstance(tag, str):
        raise ValueError("field type object is missing its `type` tag")
    return FieldType(type=tag)


def _require(data: dict[str, Any], key: str, context: str) -> Any:
    if key not in data:
        raise ValueError(f"missing `{key}` in {context}")
    return data[key]


def parse_abi_schema(json_str: str) -> AbiSchema:
    """Parse and validate an ``abi.json`` document.

    Raises ``ValueError`` on malformed JSON, unknown enum values, an
    unsupported ``abi_version``, or count mismatches between the circuit
    metadata and the field lists.
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"abi.json is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("abi.json must be a JSON object")

    abi_version = int(_require(data, "abi_version", "abi.json"))
    if abi_version != ABI_VERSION:
        raise ValueError(
            f"unsupported abi_version {abi_version} (this SDK supports {ABI_VERSION})"
        )

    circuit_data = _require(data, "circuit", "abi.json")
    circuit = CircuitMetadata(
        name=str(_require(circuit_data, "name", "circuit")),
        version=str(_require(circuit_data, "version", "circuit")),
        description=str(_require(circuit_data, "description", "circuit")),
        default_k=int(_require(circuit_data, "default_k", "circuit")),
        num_public_inputs=int(_require(circuit_data, "num_public_inputs", "circuit")),
        num_private_witnesses=int(_require(circuit_data, "num_private_witnesses", "circuit")),
    )

    witness = WitnessSchema(
        fields=tuple(
            WitnessField(
                name=str(_require(f, "name", "witness field")),
                kind=_parse_field_type(_require(f, "kind", "witness field")),
                visibility=str(_require(f, "visibility", "witness field")),
                description=f.get("description"),
            )
            for f in _require(data, "witness", "abi.json")["fields"]
        )
    )

    public_inputs = PublicInputsSchema(
        fields=tuple(
            PublicInputField(
                name=str(_require(f, "name", "public input field")),
                kind=_parse_field_type(_require(f, "kind", "public input field")),
                description=f.get("description"),
            )
            for f in _require(data, "public_inputs", "abi.json")["fields"]
        )
    )

    proof_data = _require(data, "proof", "abi.json")
    proof = ProofMetadata(
        format_version=int(_require(proof_data, "format_version", "proof")),
        proving_system=str(_require(proof_data, "proving_system", "proof")),
        approx_size_bytes=proof_data.get("approx_size_bytes"),
    )

    on_chain = None
    if data.get("on_chain") is not None:
        oc = data["on_chain"]
        on_chain = OnChainBinding(
            chain_id=int(_require(oc, "chain_id", "on_chain")),
            contract_address=str(_require(oc, "contract_address", "on_chain")),
        )

    if circuit.num_public_inputs != len(public_inputs.fields):
        raise ValueError(
            f"circuit.num_public_inputs ({circuit.num_public_inputs}) does not match "
            f"public_inputs.fields length ({len(public_inputs.fields)})"
        )
    # `witness.fields` also carries the public inputs the prover has to assign (a comparison
    # operand taken from a contract argument, for instance), so the count is over the private
    # fields only — not over the whole list.
    private_witnesses = sum(1 for f in witness.fields if f.visibility == "private")
    if circuit.num_private_witnesses != private_witnesses:
        raise ValueError(
            f"circuit.num_private_witnesses ({circuit.num_private_witnesses}) does not match "
            f"the number of private witness.fields ({private_witnesses})"
        )

    return AbiSchema(
        abi_version=abi_version,
        circuit=circuit,
        witness=witness,
        public_inputs=public_inputs,
        proof=proof,
        on_chain=on_chain,
    )
