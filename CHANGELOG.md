# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Versioning policy

ZeroStyl is **pre-1.0**. While the major version is `0`, a minor bump (`0.1 → 0.2`) may include
breaking changes and a patch bump (`0.1.0 → 0.1.1`) is reserved for backward-compatible fixes, per
SemVer's pre-release clause. The API will stabilize under `1.0.0` once the toolkit's surface is
settled. All workspace crates share a single version, declared once in the root `Cargo.toml`
`[workspace.package]`.

## [Unreleased]

## [0.1.1] — 2026-08-23

Documentation-only republish of the JavaScript and Python SDKs (`@zerostyl/sdk-ts` on npm,
`zerostyl-sdk` on PyPI). The Rust crates are unchanged and remain at `0.1.0` on crates.io.

### Fixed
- SDK READMEs: corrected the install instructions to reflect the published packages
  (`npm install @zerostyl/sdk-ts`, `pip install zerostyl-sdk`) and removed the stale "not yet
  published" notes.

## [0.1.0] — 2026-08-23

First published release. Crates on crates.io: `zerostyl-runtime`, `zerostyl-circuits`,
`zerostyl-orbit`, `zerostyl-sdk`. SDKs: `@zerostyl/sdk-ts` (npm), `zerostyl-sdk` (PyPI).

### Added
- `zerostyl-orbit` — per-chain size/gas/precompile profiles and deployability analysis for Arbitrum
  Orbit chains, with a `list`/`show`/`check`/`matrix`/`init` CLI.
- Real ABI transformation in `zerostyl-exporter`: the generated contract now ships a host trait,
  a per-commitment nullifier, `public_inputs()`, the standardized event constants, and a reference
  Stylus embedding (replacing the previous `todo!()` stub).
- `zerostyl-sdk` (Rust): circuit registry client, `WitnessBuilder`, prove/verify, ABI loading, and
  the canonical proof envelope.
- TypeScript (`@zerostyl/sdk-ts`) and Python (`zerostyl-sdk`) SDKs: typed-bindings codegen from
  `abi.json`.
- `zerostyl-runtime`: `no_std` runtime with the standardized `ZeroStylPrivacyTransaction` event and
  `BytecodeFingerprint`.
- `docs/STARK_FEASIBILITY.md` — zk-STARK feasibility study.

### Changed
- Migrated the proof system from halo2-IPA (Pasta) to halo2-KZG (BN254, PSE fork).
- Extracted circuit gadgets into the `no_std` `zerostyl-gadgets` crate.
- Moved `AbiSchema` into `zerostyl-circuits` so SDK crates consume it without the exporter.
- Centralized shared dependency versions in `[workspace.dependencies]` and unified `thiserror` to
  version 2 across all crates.
- Unified per-crate `version`/`edition`/`license`/`repository` to inherit from `[workspace.package]`.

### Fixed
- **Circuit soundness (critical):** exporter-generated circuits now load each private value into a
  single cell reused (via `copy_advice`) across the commitment, range, and comparison gadgets, and
  range-check both comparison operands — closing a witness-decoupling / field-wraparound forgery.
- Range-check soundness in `zerostyl-gadgets` (`acc_init` pinned to zero).
- Generated contract `verify_proof` now fails closed by default; nullifiers are keyed per-commitment
  (no replay via re-proving).
- Circuit `k` estimation accounts for the added comparison range checks.
- KZG params cache filename includes the SRS seed, preventing reuse of a stale/foreign SRS.

<!--
Release checklist (per version):
  1. Move [Unreleased] items under a new [x.y.z] heading with the date.
  2. Bump `version` in the root Cargo.toml [workspace.package].
  3. Commit, then tag:  git tag -a vX.Y.Z -m "vX.Y.Z"  &&  git push origin vX.Y.Z
  4. Publish crates in dependency order (see docs / release-plz.toml).
-->
