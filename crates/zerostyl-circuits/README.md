# zerostyl-circuits

Core circuit abstractions for the [ZeroStyl](https://github.com/kazai777/zerostyl) zk toolkit on
Arbitrum Stylus: the `CircuitDescriptor` trait, the witness / public-input schema types, the
`AbiSchema` (`abi.json`) document, a proof envelope, and a circuit `Registry`.

The `CircuitDescriptor` trait is deliberately backend-agnostic — it takes and returns JSON strings
and byte slices and never names a curve type — so the CLI, debugger, exporter, and SDKs consume
every circuit the same way, and a future proving backend can implement it unchanged.

## What it provides

- **`CircuitDescriptor`** — `prove` / `verify` / `mock_prove` / `inspect`, plus schema accessors.
- **`AbiSchema`** and the schema types (`WitnessSchema`, `PublicInputsSchema`, `FieldType`, …) —
  the language-neutral `abi.json` contract shared with the SDK generators.
- **`Registry`** and the `register_circuit!` macro.
- **`CanonicalProof`** — the proof wire envelope (magic + circuit id + version).

This crate has no halo2 dependency; halo2 lives in the circuit implementations that depend on it.

## License

MIT — see [LICENSE](../../LICENSE).
