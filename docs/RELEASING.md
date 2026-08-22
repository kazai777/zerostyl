# Releasing

ZeroStyl is a single-version workspace: every crate shares the version declared once in the root
`Cargo.toml` under `[workspace.package]`. This document is the release checklist and the current
publishability status.

## Versioning

- Pre-1.0: a **minor** bump (`0.1 → 0.2`) may break the API; a **patch** bump is backward-compatible
  only. See the policy note in [`CHANGELOG.md`](../CHANGELOG.md).
- All crates move together (one version, one git tag).

## Bump + tag a release

With [`cargo-release`](https://github.com/crate-ci/cargo-release) (config in `release.toml`):

```bash
cargo release minor --execute      # bumps [workspace.package] version, updates CHANGELOG, commits
git tag -a v0.2.0 -m "v0.2.0"      # release.toml keeps push/publish OFF; tag and push manually
git push origin main --tags
```

Or manually: edit `version` in the root `Cargo.toml`, move the `CHANGELOG.md` `[Unreleased]` items
under a dated `[x.y.z]` heading, commit, then `git tag`.

## Publishing to crates.io

> Publishing is **irreversible** — a version can only be *yanked*, never replaced. Always
> `cargo publish -p <crate> --dry-run` first.

### Publishable today (halo2-free)

These crates have no halo2 dependency and can be published now, **in dependency order**:

```bash
cargo publish -p zerostyl-runtime      # no internal deps
cargo publish -p zerostyl-circuits     # no internal deps
cargo publish -p zerostyl-orbit        # depends on: zerostyl-circuits
cargo publish -p zerostyl-sdk          # depends on: zerostyl-circuits, zerostyl-runtime
```

Before publishing, convert the internal `path` dependencies to `path` + `version` so the published
manifests point at crates.io (cargo uses the path locally and the version on crates.io):

```toml
zerostyl-circuits = { path = "../zerostyl-circuits", version = "0.1.0" }
```

Path-only `dev-dependencies` (e.g. `zk_private_demo`) are dropped from the published package
automatically.

### Blocked (do not publish yet)

- **halo2-dependent crates** — `zerostyl-gadgets`, `zerostyl-compiler`, `zerostyl-verifier`,
  `zerostyl-cli`. The workspace pins `halo2_proofs` to the PSE fork via a `[patch.crates-io]` git
  source. That patch does **not** travel with a published crate: the crate would declare
  `halo2_proofs = "=0.3.0"`, which on crates.io is the *Zcash* upstream (IPA-Pasta) — a different
  codebase — so downstream builds would fail. These stay git-only until the fork dependency is
  resolved (switch to a crates.io-published KZG-BN254 fork, or vendor + rename the fork).
- **example-path-dependent crates** — `zerostyl-exporter`, `zerostyl-debugger` depend on the demo
  crates under `examples/` (which are `publish = false`). They stay git-only until the circuits are
  factored out of `examples/`.

## npm / PyPI

Independent of the crates.io blockers:

- **npm** — `pnpm --filter @zerostyl/sdk-ts build && npm publish` (from `packages/sdk-ts`).
- **PyPI** — `python -m build && twine upload dist/*` (from `packages/sdk-py`).
