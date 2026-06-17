# Task 1.1: Workspace scaffolding + CI — Report

## Status: DONE_WITH_CONCERNS

## What was implemented

Created a Cargo workspace with four crate members (`vault-core`, `vault-server`, `vault-cli`, `vault-wasm`), pinned the Rust toolchain, added `.gitignore` for Rust artifacts, and set up a GitHub Actions CI workflow that runs fmt/clippy/test/audit. The `vault-core` stub exposes a `version()` function with a passing unit test.

## Files created

| Path | Purpose |
|------|---------|
| `.gitignore` | Excludes `/target`, `.rs.bk`, `Cargo.lock.bak`, `*.swp`, `.DS_Store` |
| `rust-toolchain.toml` | Pins toolchain to `stable` (see Concerns) |
| `Cargo.toml` | Workspace manifest with members and shared deps |
| `Cargo.lock` | Resolved dependency lockfile (committed) |
| `crates/vault-core/Cargo.toml` | `vault-core` package inheriting workspace settings + deps |
| `crates/vault-core/src/lib.rs` | Stub library with `version()` + test |
| `crates/vault-server/Cargo.toml` + `src/lib.rs` | Empty stub to satisfy workspace member |
| `crates/vault-cli/Cargo.toml` + `src/lib.rs` | Empty stub to satisfy workspace member |
| `crates/vault-wasm/Cargo.toml` + `src/lib.rs` | Empty stub to satisfy workspace member |
| `.github/workflows/ci.yml` | CI: fmt-check, clippy, test, audit |

The `vault-server` / `vault-cli` / `vault-wasm` crates are minimal placeholders (`// stub` lib.rs, no dependencies) added so the workspace listed in the brief can resolve. They will be filled in by later tasks.

## Verification

```
$ cargo --version
cargo 1.96.0 (ac68faa20 2026-05-25)

$ cargo test -p vault-core
running 1 test
test tests::version_is_non_empty ... ok
test result: ok. 1 passed; 0 failed; 0 ignored

$ cargo fmt --all -- --check
(exit 0, no output)
```

## TDD Evidence

### RED — test fails when impl is removed

Temporarily replaced `env!("CARGO_PKG_VERSION")` with `""` and ran the test:

```
$ cargo test -p vault-core
running 1 test
test tests::version_is_non_empty ... FAILED

failures:
---- tests::version_is_non_empty stdout ----
thread 'tests::version_is_non_empty' panicked at crates/vault-core/src/lib.rs:12:33:
assertion failed: !version().is_empty()

test result: FAILED. 0 passed; 1 failed; 0 ignored
```

### GREEN — test passes with original impl

```
$ cargo test -p vault-core
running 1 test
test tests::version_is_non_empty ... ok
test result: ok. 1 passed; 0 failed; 0 ignored
```

## Concerns / Deviations from the Brief

1. **Toolchain bumped from `1.78.0` to `stable`.** With the current crates.io registry (as of 2026-06-17), several transitive dependencies require Cargo features (`edition2024`) that are not available in Rust 1.78. Specifically:
   - `blake3 1.8.5` (auto-resolved from `^1.5.3`) requires `cpufeatures ^0.3.0`, which itself uses `edition2024`.
   - `url 2.5.x` resolves to `idna_adapter 1.2.x`, also `edition2024`.

   Patching every transitive dep to old versions was not viable (Cargo still tries to evaluate newer versions from the index). I changed `rust-toolchain.toml` to `channel = "stable"` and updated CI to match. The `rust-version` field in `Cargo.toml` remains `"1.78"` (the MSRV statement) but the project will only build with a recent stable toolchain. The plan author should decide whether to:
   - Accept the bump to stable, or
   - Vendor dependencies and lock the registry, or
   - Pin more transitive packages (likely incomplete).

2. **Stub crates for `vault-server`, `vault-cli`, `vault-wasm`.** The brief's workspace manifest lists four members but only specifies `vault-core` content. To make the workspace build, I added minimal `// stub` lib.rs and empty `Cargo.toml` for the other three. These will be replaced by their respective tasks.

3. **Rust was not installed on this system.** Installed via `rustup` with the `stable` toolchain (1.96.0). If the host running CI uses `dtolnay/rust-toolchain@v1` with `toolchain: stable` (as configured), it will fetch a recent Rust automatically.

4. **CI `cargo audit` step.** The CI workflow includes `cargo audit`, which requires `cargo-audit` to be installed. The step uses `|| true` on install so CI doesn't fail on transient install issues, but the audit itself can fail on advisories. This matches the brief verbatim.

## Self-review

- All files from the brief's file list are present.
- No extra feature work was added.
- `cargo test -p vault-core` passes (1/1).
- `cargo fmt --all -- --check` exits clean.
- Commit message is clean: `chore: workspace + vault-core stub + CI`.

## Commit

```
9f109b2 chore: workspace + vault-core stub + CI
13 files changed, 1186 insertions(+)
```
