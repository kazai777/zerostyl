# Releasing

ZeroStyl is a single-version workspace: every crate shares the version declared once in the root
`Cargo.toml` under `[workspace.package]`. This document describes the release process and which
crates are publishable to crates.io.

## Versioning

- Pre-1.0: a **minor** bump (`0.1 → 0.2`) may break the API; a **patch** bump is backward-compatible
  only. See the policy note in [`CHANGELOG.md`](../CHANGELOG.md).
- All crates move together (one version, one git tag).

## Bump and tag a release

With [`cargo-release`](https://github.com/crate-ci/cargo-release) (config in `release.toml`):

```bash
cargo release minor --execute      # bumps [workspace.package] version, updates CHANGELOG, commits
git tag -a v0.2.0 -m "v0.2.0"      # release.toml leaves push/publish off; tag and push explicitly
git push origin main --tags
```

Without the tool: edit `version` in the root `Cargo.toml`, move the `CHANGELOG.md` `[Unreleased]`
items under a dated `[x.y.z]` heading, commit, then `git tag`.

## Publishing to crates.io

A published version cannot be replaced, only *yanked*. Run `cargo publish -p <crate> --dry-run`
before each real publish.

### Crates without a halo2 dependency

These crates carry no halo2 dependency and are published in dependency order:

```bash
cargo publish -p zerostyl-runtime      # no internal deps
cargo publish -p zerostyl-circuits     # no internal deps
cargo publish -p zerostyl-orbit        # depends on: zerostyl-circuits
cargo publish -p zerostyl-sdk          # depends on: zerostyl-circuits, zerostyl-runtime
```

Each internal `path` dependency must carry a `version` alongside the path, so the published
manifest resolves against crates.io (cargo uses the path locally and the version when published):

```toml
zerostyl-circuits = { path = "../zerostyl-circuits", version = "0.1.0" }
```

Path-only `dev-dependencies` (such as `zk_private_demo`) are omitted from the published package
automatically.

### Crates not publishable to crates.io

- **halo2-dependent crates** — `zerostyl-gadgets`, `zerostyl-compiler`, `zerostyl-verifier`,
  `zerostyl-cli`. The workspace pins `halo2_proofs` to the PSE fork via a `[patch.crates-io]` git
  source. That patch does not travel with a published crate: the crate would declare
  `halo2_proofs = "=0.3.0"`, which on crates.io is the Zcash upstream (IPA-Pasta) — a different
  codebase — so downstream builds would fail. Publishing them requires either switching to a
  crates.io-published KZG-BN254 fork or vendoring the fork under a distinct name.
- **example-path-dependent crates** — `zerostyl-exporter` and `zerostyl-debugger` depend on the
  demo crates under `examples/` (declared `publish = false`). Publishing them requires factoring
  the circuits out of `examples/` into publishable crates.

## npm and PyPI

The JavaScript and Python SDKs are independent of the crates.io constraints above:

- **npm** — from `packages/sdk-ts`: `pnpm build && npm publish`.
- **PyPI** — from `packages/sdk-py`: `python -m build && twine upload dist/*`.
