### Task 1.1: Workspace scaffolding + CI

**Files:**
- Create: `Cargo.toml`
- Create: `.gitignore`
- Create: `rust-toolchain.toml`
- Create: `.github/workflows/ci.yml`

**Step 1.1.1: Init git + .gitignore**

```bash
cd /home/gtx/Documents/mypass
git init
```

Create `.gitignore`:
```
/target
**/*.rs.bk
Cargo.lock.bak
*.swp
.DS_Store
```

**Step 1.1.2: Pin toolchain**

Create `rust-toolchain.toml`:
```toml
[toolchain]
channel = "1.78.0"
components = ["rustfmt", "clippy"]
```

**Step 1.1.3: Workspace manifest**

Create `Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = [
    "crates/vault-core",
    "crates/vault-server",
    "crates/vault-cli",
    "crates/vault-wasm",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
rust-version = "1.78"

[workspace.dependencies]
# Use 1.78-compatible versions; pin exact.
serde = { version = "1.0.203", features = ["derive"] }
serde_json = "1.0.117"
thiserror = "1.0.61"
anyhow = "1.0.86"
tracing = "0.1.40"
tracing-subscriber = { version = "0.3.18", features = ["env-filter"] }
zeroize = { version = "1.8.1", features = ["zeroize_derive"] }
subtle = "2.6.1"
chacha20poly1305 = "0.10.1"
argon2 = "0.5.3"
blake3 = "1.5.3"
hkdf = "0.12.4"
sha2 = "0.10.8"
base64 = "0.22.1"
rand = "0.8.5"
getrandom = "0.2.15"
url = "2.5.0"
chrono = { version = "0.4.38", features = ["serde"] }
```

**Step 1.1.4: Empty vault-core stub**

Create `crates/vault-core/Cargo.toml`:
```toml
[package]
name = "vault-core"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
zeroize.workspace = true
subtle.workspace = true
chacha20poly1305.workspace = true
argon2.workspace = true
blake3.workspace = true
hkdf.workspace = true
sha2.workspace = true
base64.workspace = true
rand.workspace = true
getrandom.workspace = true
url.workspace = true
chrono.workspace = true
```

Create `crates/vault-core/src/lib.rs`:
```rust
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! E2E encryption core for mypass vault.

/// Returns the library version.
pub fn version() -> &'static str { env!("CARGO_PKG_VERSION") }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_is_non_empty() { assert!(!version().is_empty()); }
}
```

**Step 1.1.5: CI**

Create `.github/workflows/ci.yml`:
```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@v1
        with:
          toolchain: 1.78.0
          components: rustfmt, clippy
      - run: cargo fmt --all -- --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test --all --no-fail-fast
      - run: cargo install --locked cargo-audit || true
      - run: cargo audit
```

**Step 1.1.6: Verify and commit**

Run:
```bash
cargo --version
cargo test -p vault-core
cargo fmt --all
git add -A
git commit -m "chore: workspace + vault-core stub + CI"
```

Expected: tests pass, commit succeeds.

---

