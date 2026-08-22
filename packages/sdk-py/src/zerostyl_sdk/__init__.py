"""Python SDK for the ZeroStyl zk toolkit on Arbitrum Stylus.

Parses the exporter's ``abi.json`` documents into typed dataclasses and
generates typed Python bindings (mirroring ``@zerostyl/sdk-ts``).
"""

from .codegen.generator import generate_bindings
from .codegen.type_mapping import field_type_to_py
from .types import (
    ABI_VERSION,
    AbiSchema,
    CircuitMetadata,
    FieldType,
    OnChainBinding,
    ProofMetadata,
    PublicInputField,
    PublicInputsSchema,
    WitnessField,
    WitnessSchema,
    parse_abi_schema,
)

__version__ = "0.1.0"

__all__ = [
    "ABI_VERSION",
    "AbiSchema",
    "CircuitMetadata",
    "FieldType",
    "OnChainBinding",
    "ProofMetadata",
    "PublicInputField",
    "PublicInputsSchema",
    "WitnessField",
    "WitnessSchema",
    "__version__",
    "field_type_to_py",
    "generate_bindings",
    "parse_abi_schema",
]
