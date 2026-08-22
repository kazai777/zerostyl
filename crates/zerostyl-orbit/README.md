# zerostyl-orbit

Orbit zk-Adapter for the [ZeroStyl](https://github.com/kazai777/zerostyl) toolkit: per-chain
configuration profiles and deployability analysis for Arbitrum and Arbitrum Orbit chains.

It answers, for a given chain and a given compiled WASM artifact, the question the rest of the
toolkit only states in prose: **is this deployable here, and can this proving system be verified
on-chain?**

## What it provides

- **`ChainProfile`** — a chain's size limits, gas/ink model, and available precompiles. Built-ins
  for `arbitrum-one`, `arbitrum-nova`, `arbitrum-sepolia`, plus a customizable `my-orbit-chain`
  template; custom Orbit chains load from a TOML file.
- **`assess`** — size an artifact against a chain's caps (compressed on-chain code + decompressed
  WASM) → a `DeployabilityReport` with per-limit margins.
- **`assess_verification`** — does a chain expose the precompiles a
  `zerostyl_circuits::ProvingSystem` needs on-chain? (KZG and the Groth16 wrap reduce to a BN254
  pairing at `0x08`; STARK/FRI needs none; IPA has no BN254 path.)
- Chain-parameter **constants** (`EIP170_MAX_CODE_SIZE`, `STYLUS_ARBOS60_MAX_WASM_SIZE`,
  `INK_PER_GAS`, …) — previously scattered across doc comments, now one source of truth.

## CLI

```bash
# List built-in chains and their WASM budgets
zerostyl-orbit list

# Show a profile (built-in name or path to a .toml)
zerostyl-orbit show --chain arbitrum-sepolia

# Is this artifact deployable on one chain? (+ optional on-chain-verify precompile check)
zerostyl-orbit check --chain arbitrum-sepolia --wasm my_contract.wasm --proving-system halo2_kzg

# Check one artifact across every built-in chain at once
zerostyl-orbit matrix --wasm my_contract.wasm --proving-system halo2_kzg

# Scaffold a custom Orbit chain profile to edit
zerostyl-orbit init --output my-orbit-chain.toml
```

Example: the reference `zerostyl-verifier` (~91 KB Brotli) is reported **NOT deployable** on the
standard 24 KB chains — it fits the compressed cap only on a custom Orbit chain raised to 96 KB,
and still overflows the 256 KB decompressed cap — while confirming the BN254 pairing precompile is
available on all of them. That is the size blocker, quantified per chain.

## Custom chain profile (TOML)

```toml
name = "my-orbit-chain"
chain_id = 123456
arbos_version = 60

[limits]
max_code_size = 98304       # compressed on-chain code cap (bytes); 96 KB max on a custom chain
max_wasm_size = 262144      # decompressed WASM cap (bytes)
max_init_code_size = 196608

[gas]
ink_per_gas = 10000
# ink_price_wei = 100       # optional; chain-owner configurable

[precompiles]
bn256_pairing = true        # set false to model a chain that removed 0x08
```

## Scope

Analysis and configuration only — **no RPC, signing, or deployment**. Use `cargo-stylus` to deploy;
the Brotli size here approximates it closely but is not byte-identical, so treat it as indicative.
Built-in `chain_id`/ArbOS values reflect published chain parameters that may change over time —
override them with a TOML profile when needed.

## License

MIT — see the repository's [LICENSE](../../LICENSE).
