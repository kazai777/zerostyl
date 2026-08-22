# zerostyl-sdk (Python)

Python SDK for the [ZeroStyl](https://github.com/kazai777/zerostyl) zk toolkit on
Arbitrum Stylus. Parses the exporter's `abi.json` documents into typed dataclasses and
generates typed Python bindings — the same scope as `@zerostyl/sdk-ts`, in Python.

Pure Python, zero runtime dependencies, Python ≥ 3.10.

## Install (from the repo)

```bash
cd packages/sdk-py
python -m pip install ".[dev]"
```

## Usage

```python
from pathlib import Path
from zerostyl_sdk import parse_abi_schema, generate_bindings

abi = parse_abi_schema(Path("abi.json").read_text())
print(abi.circuit.name, abi.circuit.num_public_inputs)

bindings = generate_bindings(abi)   # a Python module as a string
Path("deposit_bindings.py").write_text(bindings)
```

CLI (equivalent of the TS SDK's `zerostyl-sdk generate`):

```bash
# after `pip install` (see above), either form works:
zerostyl-sdk-py generate --abi ../../examples/zk_private_demo/abi.json --out bindings.py
python -m zerostyl_sdk generate --abi ../../examples/zk_private_demo/abi.json
```

Generated output for the demo circuit:

```python
DEPOSIT_CIRCUIT: Final = {
    "name": "deposit",
    ...
}

@dataclass(frozen=True)
class DepositWitness:
    collateral: str
    collateral_nonce: str
    threshold: str

@dataclass(frozen=True)
class DepositPublicInputs:
    collateral_commitment: str
```

Type mapping: `u64`/`u128` → `int`, `bool` → `bool`, `fp`/`bytes32`/`address` → `str`
(`0x`-prefixed hex), arrays → `tuple[..., ...]`.

## Tests

```bash
python -m pytest
ruff check src tests
```

The snapshot test locks the generated bindings for
`examples/zk_private_demo/abi.json`; regenerate with
`REGEN_SDK_PY_SNAPSHOTS=1 python -m pytest`.

## Scope and future work

Codegen only — proof generation from Python (bindings to the Rust prover) and on-chain
submission helpers are future work, mirroring the TypeScript SDK's roadmap. The package
is not yet published to PyPI.

## License

MIT — see the repository's [LICENSE](../../LICENSE).
