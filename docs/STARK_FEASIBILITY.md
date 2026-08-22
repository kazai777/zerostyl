# zk-STARKs feasibility study

**Status:** research / forward-looking. This document evaluates whether ZeroStyl should adopt a
zk-STARK proving backend, what it would buy, what it would cost, and a recommended path. It is a
decision aid, not a commitment to migrate.

## 1. Why ask the question

ZeroStyl proves with **halo2 using a KZG polynomial commitment on BN254** (PSE fork). Two properties
of that choice motivate looking at STARKs:

1. **Trusted setup.** KZG needs a structured reference string (SRS). ZeroStyl currently derives its
   SRS deterministically from a fixed seed (`DEV_SRS_SEED`) — a reproducible *development* setup,
   explicitly **not** a secure Powers-of-Tau ceremony. A production deployment would need a real
   ceremony, whose toxic waste is a standing trust assumption. STARKs are **transparent**: no setup,
   no toxic waste.
2. **Post-quantum security.** KZG (and a Groth16 wrap) rest on elliptic-curve pairings and the
   discrete-log assumption, which Shor's algorithm breaks on a sufficiently large quantum computer.
   STARKs rest only on collision-resistant hashes, which are not known to be broken by quantum
   attacks (Grover gives at most a square-root speed-up, absorbed by a modest security-parameter
   bump). STARKs are the standard answer to "post-quantum zero-knowledge".

Both are real, but neither is an *immediate* operational problem for a testnet toolkit. The purpose
here is to know the trade precisely before it becomes one.

## 2. What a STARK is (relevant to this decision)

A zk-STARK proves execution of an **AIR** (algebraic intermediate representation) using **FRI**
(Fast Reed–Solomon Interactive Oracle Proof of Proximity) over a small prime field, with all
commitments built from Merkle trees of hash digests. The consequences that matter here:

- **Transparent** — no SRS, no trusted setup.
- **Hash-based** — verification is a large number of hash evaluations and Merkle-path checks; it
  uses **no elliptic-curve operations and no pairing**.
- **Small fields** — modern STARK stacks run over 31–64-bit fields (Goldilocks, BabyBear,
  Mersenne31) chosen for prover speed, *not* over the 254-bit BN254 scalar field ZeroStyl's halo2
  circuits use.
- **Larger proofs** — FRI trades proof size for transparency and speed.

## 3. Quantitative comparison

Figures are order-of-magnitude from public benchmarks (2024–2025) and ZeroStyl's own measurements;
exact numbers depend heavily on circuit size and parameters.

| Property | halo2-KZG (current) | Groth16 (wrap target) | zk-STARK (FRI) |
|---|---|---|---|
| Trusted setup | Universal (KZG SRS) | Per-circuit CRS | **None (transparent)** |
| Post-quantum | No | No | **Yes** |
| Proof size | ~2.7 KB (measured: `state_mask` = 2720 B) | ~128–256 B | **~45–576 KB** (Winterfell ~63 KB, Plonky2/RISC0 ~250 KB, Plonky3 ~576 KB) |
| Verifier cost (EVM) | ~500k gas class | **~250k gas** | **~2.5M gas** class (native) |
| On-chain verifier code | ~91.5 KB compressed (halo2 SHPLONK + BN254) | small (uses precompiles) | large (hash/FRI heavy) |
| Precompile dependency | BN254 `0x06/0x07/0x08` | BN254 `0x06/0x07/0x08` | **none** (hash-only) |
| Field | BN254 scalar (254-bit) | BN254 | small field (31–64-bit) |

Two facts stand out for ZeroStyl specifically:

- The current halo2 proof is **~2.7 KB**; a STARK proof for comparable statements is **one to two
  orders of magnitude larger**. For a privacy transaction whose proof is posted or relayed, that is
  a real bandwidth/calldata cost.
- A **native** STARK on-chain verifier is *larger and more gas-hungry* than the halo2 one, not
  smaller. STARKs do **not** solve ZeroStyl's core deployment blocker (the halo2 verifier is
  ~91.5 KB vs the 24 KB Stylus limit — see [`CONTRACTS.md`](../contracts/CONTRACTS.md) and
  [`STARK` handling in `zerostyl-orbit`](../crates/zerostyl-orbit)). If anything they make on-chain
  verification harder.

## 4. On-chain reality on Arbitrum Stylus

Arbitrum Stylus caps a deployed contract at **24 KB Brotli-compressed** (up to 96 KB on a custom
Orbit chain) and **128 KB decompressed** (256 KB at ArbOS ≥ 60). ZeroStyl's `zerostyl-orbit` crate
turns these into a concrete deployability check.

- A **native STARK verifier** is a large, hash-intensive program. Arbitrum exposes `keccak256` as a
  host I/O, which helps, but a full FRI verifier (many queries × Merkle paths × field arithmetic in
  a small field emulated inside the contract) is well over the 24 KB budget — the same size problem
  as halo2, arguably worse. So a *native, end-to-end post-quantum* on-chain verifier is **not
  feasible on Stylus under current size and gas budgets** — and, notably, that is a property of the budget, not of
  ZeroStyl.
- The pragmatic on-chain pattern used across the ecosystem (RISC Zero, Plonky2→circom, SP1) is to
  **wrap** the large transparent proof in a small **Groth16** SNARK and verify *that* on-chain via
  the BN254 pairing precompile (`0x08`, which Arbitrum supports). ZeroStyl already anticipates this:
  the `ProvingSystem::Halo2KzgGroth16Wrap` variant and `zerostyl-orbit`'s precompile check exist for
  exactly this path.
- **Caveat that matters:** wrapping a STARK in Groth16 for cheap on-chain verification **re-introduces
  a trusted setup and forfeits post-quantum security at the wrap layer**. You keep transparency and
  PQ for the *proving* pipeline, but the on-chain verification is once again pairing-based. True
  end-to-end post-quantum *and* on-chain verification is not achievable within current Stylus size
  and gas budgets by any known construction.

## 5. What migration would cost ZeroStyl

Switching proving backends is not a configuration flip; it is a stack change.

- **Circuit rewrite.** ZeroStyl's gadgets (`zerostyl-gadgets`: Poseidon commitment, bit-decomposition
  range, comparison, Merkle) are halo2 **PLONKish** chips over BN254. A STARK backend expresses
  constraints as an **AIR** over a small field. The gadgets and the `#[zk_private]` codegen that
  emits them would be rewritten, not ported.
- **Field change.** Witness encoding, the Poseidon parameters, and every `Fr`-based helper assume the
  BN254 scalar field. A STARK stack uses Goldilocks/BabyBear/Mersenne31 — different Poseidon
  constants, different range-check strategy (lookups vs bit decomposition), different serialization.
- **Prover stack.** Candidate Rust backends: **Plonky3** (fastest FRI prover, powers SP1; the most
  active), **Winterfell** (simplest to learn, smaller proofs ~63 KB), **RISC Zero** (a zkVM, not a
  circuit DSL). Each is a substantial dependency with its own proof format and recursion story.
- **The seam that already exists.** ZeroStyl's `CircuitDescriptor` trait (`zerostyl-circuits`) was
  deliberately designed backend-agnostic — it takes/returns JSON strings and byte slices and **never
  names `halo2curves` or `Fr`** in its signatures. A STARK circuit could implement the same trait, so
  the CLI, SDK, exporter ABI, and dashboard would keep working unchanged above it. The
  `ProvingSystem::StarkFri` enum variant is a placeholder reserved for this. That trait is the single
  point that makes a future backend swap tractable rather than a full-toolkit rewrite.

## 6. Recommendation

**Do not migrate to STARKs in the near term.** For ZeroStyl's current goal — privacy circuits on
Arbitrum Stylus with the smallest possible on-chain footprint — halo2-KZG on BN254 is the better fit:
smaller proofs, and the only realistic on-chain-verification path (a Groth16 wrap over the BN254
precompiles) is pairing-based regardless of the proving backend, so STARKs' transparency/PQ
advantages are lost precisely at the on-chain layer where the size blocker lives.

Concretely, in priority order:

1. **Short term — pursue the Groth16 wrap for on-chain verification**, keeping halo2-KZG for proving.
   This is what actually unblocks on-chain SNARK verification within the 24 KB Stylus budget (via the
   `0x08` precompile), and `zerostyl-orbit` already models its feasibility per chain. It does not
   deliver post-quantum security, which is an accepted trade for a BN254 EVM-aligned toolkit.
2. **Address the trusted-setup concern independently of STARKs** by replacing `DEV_SRS_SEED` with SRS
   from a real Powers-of-Tau ceremony before any mainnet use. This removes the most concrete of the
   two motivations without a backend change.
3. **Long term — keep the STARK door open behind the `CircuitDescriptor` seam.** If post-quantum
   proving becomes a requirement, add a **Plonky3** backend as an alternative descriptor
   implementation (proving PQ, wrapping in Groth16 for on-chain), rather than replacing halo2. Revisit
   a *native* on-chain STARK verifier only if Stylus size/gas budgets rise materially or a STARK
   precompile lands — neither of which is on the near-term horizon.

The honest bottom line: STARKs give transparency and post-quantum security for the *proving*
pipeline, at the cost of much larger proofs and a verifier that is harder, not easier, to fit
on-chain. They are a credible long-term option gated behind a backend abstraction ZeroStyl already
has — not a current fix for either the size blocker or a shipped requirement.

## References

- Comparative analyses of zk-SNARKs vs zk-STARKs (proof size, verifier cost, trusted setup,
  post-quantum): QuillAudits, Hacken, Cyfrin (2024–2025); arXiv:2512.10020.
- FRI/STARK proving-system landscape and on-chain viability (Plonky2/Plonky3, Winterfell, RISC Zero,
  recursion, Groth16 wrap): "An Opinionated Overview of ZK Tooling and Proof Systems".
- On-chain STARK verification measurement: eprint 2025/1741 (L1 on-chain STARK+PQC verification).
- ZeroStyl-specific size constraints: [`contracts/CONTRACTS.md`](../contracts/CONTRACTS.md),
  [`crates/zerostyl-orbit`](../crates/zerostyl-orbit), [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md).
