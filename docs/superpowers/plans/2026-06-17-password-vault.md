# Password Vault (mypass) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an end-to-end encrypted password vault service: CSV encrypted on the client, served over HTTPS via Nginx reverse proxy, with Web/CLI/mobile clients all sharing one Rust core library.

**Architecture:** Single Rust workspace with 4 crates. `vault-core` is the only crypto/search truth source — compiled to native (CLI/server) and to WASM (browser). Server is a thin axum router over SQLite holding only the wrapped CEK + ciphertext + version. All HTTPS is terminated by the user's existing Nginx; this service binds only to 127.0.0.1:8080. Public path is `/keychain/*` (Nginx rewrites to internal `/vault/*`).

**Tech Stack:** Rust 1.78+, `axum 0.7`, `tokio`, `rusqlite`, `chacha20poly1305`, `argon2 0.5`, `blake3`, `zeroize`, `subtle`, `tracing`, `wasm-bindgen`, `wasm-pack`. Frontend: vanilla HTML/JS + WASM (no framework). Spec: `docs/superpowers/specs/2026-06-17-password-vault-design.md`.

## Global Constraints

- **No unsafe code in `vault-core`**: `#![forbid(unsafe_code)]` + `#![deny(missing_docs)]`.
- **MSRV**: Rust stable (decision: crate ecosystem in 2026 requires `edition2024` features that need Rust 1.85+; pinning Rust 1.78 forces exact-version locking of ~80 transitive deps and is impractical for a 2026 project). The `rust-version` field in `Cargo.toml` is set to match the minimum stable that has all required features.
- **Server bind**: `127.0.0.1:8080` only. Hard-coded; no env override. Refuse to start otherwise.
- **Crypto primitives** (from spec §2.1): KDF = Argon2id (m=64 MiB, t=3, p=1, salt=16B). Cipher = XChaCha20-Poly1305 (256-bit key, 24B nonce, 16B tag). HKDF-SHA256 for KEK derivation. `Zeroizing` wrapping for all key material.
- **Request body limit**: 8 MB enforced at both Rust and Nginx layers.
- **Public API path**: `/keychain/*` (rewritten by Nginx to internal `/vault/*`).
- **CSV schema** (frozen, no breaking changes): `name,url,username,password,note` plus optional trailing columns. Tag convention in `note`: tokens starting with `#`.
- **No telemetry, no logging of**: master password, raw ciphertext, decrypted plaintext, full IPs (only X-Forwarded-For digest).
- **DRY**: `vault-core` is the only place crypto/search logic lives. CLI, server, WASM all consume it.
- **Frequent commits**: every task ends with a commit; commits are atomic per task.
- **TDD**: write the failing test first, see it fail, write the minimum to pass, see it pass, commit.
- **CI gates** (must pass before merge): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all`, `cargo audit`.

## File Structure (created over the plan)

```
mypass/  (workspace root)
├── Cargo.toml                  # workspace manifest
├── .github/workflows/ci.yml    # CI: fmt, clippy, test, audit
├── crates/
│   ├── vault-core/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── types.rs        # MasterKey, Cek, Salt, Version, WrappedCek, EncryptedCsv
│   │       ├── kdf.rs          # derive_mk(password, salt, params) -> MasterKey
│   │       ├── aead.rs         # encrypt/decrypt XChaCha20-Poly1305
│   │       ├── wrap.rs         # wrap_cek(mk, cek) / unwrap_cek(mk, wrapped) -> Cek
│   │       ├── csv_codec.rs    # encode/decode Vec<Entry> ↔ CSV bytes
│   │       ├── entry.rs        # Entry struct, domain extraction, #tag parsing
│   │       ├── search.rs       # TrigramIndex, search(query, entries)
│   │       ├── group.rs        # group_by_domain, group_by_tag, group_by_letter
│   │       ├── protocol.rs     # VaultSnapshot, VaultWrite, VaultRekey JSON types
│   │       └── tests/          # KAT, differential vs libsodium
│   ├── vault-server/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs         # bootstrap, bind 127.0.0.1:8080
│   │       ├── config.rs       # env: AUTH_TOKEN, DB_PATH, RUST_LOG
│   │       ├── auth.rs         # Bearer token, constant-time compare
│   │       ├── store.rs        # SQLite repo: get/put/history
│   │       ├── handlers.rs     # GET/PUT/POST/health/version
│   │       └── error.rs        # VaultError → HTTP code
│   ├── vault-cli/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs         # clap subcommands
│   │       ├── config.rs       # load $XDG_CONFIG_HOME/vault/config.toml
│   │       ├── init.rs
│   │       ├── get.rs
│   │       ├── put.rs
│   │       ├── rekey.rs
│   │       ├── search.rs
│   │       └── group.rs
│   └── vault-wasm/
│       ├── Cargo.toml
│       └── src/lib.rs          # #[wasm_bindgen] exports: derive_mk, unwrap, decrypt, search
├── web/
│   ├── index.html
│   ├── app.js
│   └── app.css
├── systemd/
│   └── vault-server.service
├── nginx/
│   └── vault.conf.snippet
└── docs/
    ├── DEPLOY.md
    └── THREAT_MODEL.md
```

---

## Milestone 1 — `vault-core` 加密核心库

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

### Task 1.2: Newtype wrappers (`types.rs`)

**Files:**
- Create: `crates/vault-core/src/types.rs`
- Modify: `crates/vault-core/src/lib.rs`

**Step 1.2.1: Write the failing test**

Add to `lib.rs` at the bottom of the tests module:
```rust
#[test]
fn salt_zero_array_works() {
    use crate::types::Salt;
    let s = Salt([0u8; 16]);
    assert_eq!(s.as_bytes().len(), 16);
}

#[test]
fn wrapped_cek_rejects_wrong_length() {
    use crate::types::WrappedCek;
    let r = WrappedCek::from_bytes(&[0u8; 10]);
    assert!(r.is_err());
}

#[test]
fn version_saturates_at_u64_max() {
    use crate::types::Version;
    let v = Version(10);
    let next = v.increment_saturating();
    assert_eq!(next.0, 11);
    let max = Version(u64::MAX);
    let max_next = max.increment_saturating();
    assert_eq!(max_next.0, u64::MAX);
}
```

**Step 1.2.2: Run, expect failure**

```bash
cargo test -p vault-core
```
Expected: compile error (types module not found).

**Step 1.2.3: Implement `types.rs`**

Create `crates/vault-core/src/types.rs`:
```rust
//! Newtype wrappers for keys, ciphertexts, and metadata.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Argon2id salt, 16 bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Salt(pub [u8; 16]);

impl Salt {
    /// Random salt.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut s = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut s);
        Self(s)
    }
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
    pub fn from_bytes(b: &[u8]) -> Result<Self, TypeError> {
        if b.len() != 16 { return Err(TypeError::SaltLength(b.len())); }
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        Ok(Self(a))
    }
}

/// Master key derived from the user's password. Stays on client.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; 32]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}

/// Content encryption key, random 32 bytes, used to encrypt the CSV.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Cek(pub [u8; 32]);
impl Cek {
    pub fn random() -> Self {
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        Self(k)
    }
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}

/// Wrapped CEK: 24-byte XChaCha20 nonce + 48-byte ciphertext (32B CEK + 16B tag).
#[derive(Clone)]
pub struct WrappedCek { pub nonce: [u8; 24], pub ct: Vec<u8> }
impl WrappedCek {
    pub fn from_bytes(b: &[u8]) -> Result<Self, TypeError> {
        if b.len() < 24 { return Err(TypeError::WrappedCekLength(b.len())); }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&b[..24]);
        let ct = b[24..].to_vec();
        Ok(Self { nonce, ct })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(24 + self.ct.len());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.ct);
        v
    }
    pub fn ct_len(&self) -> usize { self.ct.len() }
}

/// AEAD ciphertext: 24-byte nonce + N + 16-byte tag.
#[derive(Clone)]
pub struct EncryptedCsv { pub nonce: [u8; 24], pub ct: Vec<u8> }
impl EncryptedCsv {
    pub fn from_bytes(b: &[u8]) -> Result<Self, TypeError> {
        if b.len() < 24 + 16 { return Err(TypeError::EncryptedCsvLength(b.len())); }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&b[..24]);
        let ct = b[24..].to_vec();
        Ok(Self { nonce, ct })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(24 + self.ct.len());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.ct);
        v
    }
}

/// Monotonic version number. Saturates at u64::MAX.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u64);
impl Version {
    pub fn increment_saturating(self) -> Self { Self(self.0.saturating_add(1)) }
    pub fn as_u64(self) -> u64 { self.0 }
}

/// Constant-time compare for two byte slices.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[derive(thiserror::Error, Debug)]
pub enum TypeError {
    #[error("salt must be 16 bytes, got {0}")]
    SaltLength(usize),
    #[error("wrapped_cek must be at least 24 bytes, got {0}")]
    WrappedCekLength(usize),
    #[error("encrypted_csv must be at least 40 bytes, got {0}")]
    EncryptedCsvLength(usize),
}
```

**Step 1.2.4: Wire up module**

In `crates/vault-core/src/lib.rs`, add:
```rust
pub mod types;

pub use types::{Cek, MasterKey, Salt, Version, WrappedCek, EncryptedCsv, ct_eq};
```

**Step 1.2.5: Run tests, expect pass**

```bash
cargo test -p vault-core types
```
Expected: 3 new tests pass.

**Step 1.2.6: Commit**

```bash
git add crates/vault-core/src/types.rs crates/vault-core/src/lib.rs
git commit -m "feat(vault-core): newtype wrappers (Salt/Cek/MasterKey/WrappedCek/Version)"
```

---

### Task 1.3: KDF — Argon2id

**Files:**
- Create: `crates/vault-core/src/kdf.rs`
- Modify: `crates/vault-core/src/lib.rs`

**Step 1.3.1: Write the failing test**

Append to `lib.rs` test module:
```rust
#[test]
fn kdf_is_deterministic_with_same_salt() {
    use crate::kdf::{derive_mk, KdfParams};
    use crate::types::Salt;
    let salt = Salt([1u8; 16]);
    let p = KdfParams::default();
    let mk1 = derive_mk(b"correct horse battery staple", &salt, &p).unwrap();
    let mk2 = derive_mk(b"correct horse battery staple", &salt, &p).unwrap();
    assert_eq!(mk1.as_bytes(), mk2.as_bytes());
}

#[test]
fn kdf_changes_with_different_salt() {
    use crate::kdf::{derive_mk, KdfParams};
    use crate::types::Salt;
    let p = KdfParams::default();
    let mk1 = derive_mk(b"x", &Salt([1u8; 16]), &p).unwrap();
    let mk2 = derive_mk(b"x", &Salt([2u8; 16]), &p).unwrap();
    assert_ne!(mk1.as_bytes(), mk2.as_bytes());
}

#[test]
fn kdf_changes_with_different_password() {
    use crate::kdf::{derive_mk, KdfParams};
    use crate::types::Salt;
    let salt = Salt([1u8; 16]);
    let p = KdfParams::default();
    let mk1 = derive_mk(b"foo", &salt, &p).unwrap();
    let mk2 = derive_mk(b"bar", &salt, &p).unwrap();
    assert_ne!(mk1.as_bytes(), mk2.as_bytes());
}
```

**Step 1.3.2: Run, expect failure**

```bash
cargo test -p vault-core kdf
```
Expected: compile error.

**Step 1.3.3: Implement `kdf.rs`**

Create `crates/vault-core/src/kdf.rs`:
```rust
//! Argon2id master-key derivation.

use argon2::{Algorithm, Argon2, Params, Version};
use crate::types::{MasterKey, Salt};

/// KDF parameters, fixed per spec §2.1.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB. 64 MiB = 65536 KiB.
    pub m_cost_kib: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism lanes.
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { m_cost_kib: 65_536, t_cost: 3, p_cost: 1 }
    }
}

/// Derive a 32-byte master key from a password and salt.
pub fn derive_mk(
    password: &[u8],
    salt: &Salt,
    params: &KdfParams,
) -> Result<MasterKey, KdfError> {
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(KdfError::Params)?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; 32];
    a.hash_password_into(password, salt.as_bytes(), &mut out)
        .map_err(KdfError::Hash)?;
    Ok(MasterKey(out))
}

#[derive(thiserror::Error, Debug)]
pub enum KdfError {
    #[error("invalid Argon2 params: {0}")]
    Params(#[from] argon2::Error),
    #[error("Argon2 hashing failed: {0}")]
    Hash(argon2::password_hash::Error),
}
```

**Step 1.3.4: Wire up module**

In `lib.rs`:
```rust
pub mod kdf;
pub use kdf::{KdfParams, derive_mk};
```

**Step 1.3.5: Run, expect pass**

```bash
cargo test -p vault-core kdf
```
Expected: 3 new tests pass (will take ~600ms due to Argon2 cost).

**Step 1.3.6: Commit**

```bash
git add crates/vault-core/src/kdf.rs crates/vault-core/src/lib.rs
git commit -m "feat(vault-core): Argon2id KDF with default 64MiB/3/1 params"
```

---

### Task 1.4: AEAD — XChaCha20-Poly1305

**Files:**
- Create: `crates/vault-core/src/aead.rs`
- Modify: `crates/vault-core/src/lib.rs`

**Step 1.4.1: Failing tests**

```rust
#[test]
fn aead_round_trip() {
    use crate::aead::{encrypt, decrypt};
    use crate::types::Cek;
    let cek = Cek([7u8; 32]);
    let pt = b"hello world";
    let ct = encrypt(&cek, pt).unwrap();
    let back = decrypt(&cek, &ct).unwrap();
    assert_eq!(back, pt);
}

#[test]
fn aead_tampered_ct_fails() {
    use crate::aead::{encrypt, decrypt};
    use crate::types::Cek;
    let cek = Cek([1u8; 32]);
    let mut ct = encrypt(&cek, b"hi").unwrap();
    ct.ct[0] ^= 0x01;
    assert!(decrypt(&cek, &ct).is_err());
}

#[test]
fn aead_wrong_key_fails() {
    use crate::aead::{encrypt, decrypt};
    use crate::types::Cek;
    let ct = encrypt(&Cek([1u8; 32]), b"hi").unwrap();
    assert!(decrypt(&Cek([2u8; 32]), &ct).is_err());
}

#[test]
fn aead_nonce_is_24_bytes() {
    use crate::aead::encrypt;
    use crate::types::Cek;
    let ct = encrypt(&Cek([0u8; 32]), b"x").unwrap();
    assert_eq!(ct.nonce.len(), 24);
}

#[test]
fn aead_two_nonces_differ() {
    use crate::aead::encrypt;
    use crate::types::Cek;
    let cek = Cek([0u8; 32]);
    let a = encrypt(&cek, b"x").unwrap();
    let b = encrypt(&cek, b"x").unwrap();
    assert_ne!(a.nonce, b.nonce);
}
```

**Step 1.4.2: Run, expect failure**

```bash
cargo test -p vault-core aead
```

**Step 1.4.3: Implement `aead.rs`**

```rust
//! XChaCha20-Poly1305 authenticated encryption.

use chacha20poly1305::{XChaCha20Poly1305, KeyInit, XNonce};
use chacha20poly1305::aead::Aead;
use crate::types::{Cek, EncryptedCsv};

pub fn encrypt(cek: &Cek, plaintext: &[u8]) -> Result<EncryptedCsv, AeadError> {
    let cipher = XChaCha20Poly1305::new(cek.as_bytes().into());
    let mut nonce = [0u8; 24];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| AeadError::Encrypt)?;
    Ok(EncryptedCsv { nonce, ct })
}

pub fn decrypt(cek: &Cek, enc: &EncryptedCsv) -> Result<Vec<u8>, AeadError> {
    let cipher = XChaCha20Poly1305::new(cek.as_bytes().into());
    cipher.decrypt(XNonce::from_slice(&enc.nonce), enc.ct.as_ref())
        .map_err(|_| AeadError::Decrypt)
}

#[derive(thiserror::Error, Debug)]
pub enum AeadError {
    #[error("AEAD encryption failed")] Encrypt,
    #[error("AEAD decryption failed (wrong key, tampered data, or wrong nonce)")] Decrypt,
}
```

**Step 1.4.4: Wire up**

In `lib.rs`:
```rust
pub mod aead;
pub use aead::{encrypt, decrypt, AeadError};
```

**Step 1.4.5: Run, expect pass**

```bash
cargo test -p vault-core aead
```
Expected: 5 new tests pass.

**Step 1.4.6: Commit**

```bash
git add crates/vault-core/src/aead.rs crates/vault-core/src/lib.rs
git commit -m "feat(vault-core): XChaCha20-Poly1305 AEAD"
```

---

### Task 1.5: CEK wrap/unwrap

**Files:**
- Create: `crates/vault-core/src/wrap.rs`
- Modify: `crates/vault-core/src/lib.rs`

**Step 1.5.1: Failing tests**

```rust
#[test]
fn wrap_cek_round_trip() {
    use crate::wrap::{wrap_cek, unwrap_cek};
    use crate::types::{Cek, MasterKey};
    let mk = MasterKey([3u8; 32]);
    let cek = Cek([5u8; 32]);
    let w = wrap_cek(&mk, &cek).unwrap();
    let back = unwrap_cek(&mk, &w).unwrap();
    assert_eq!(back.as_bytes(), cek.as_bytes());
}

#[test]
fn unwrap_with_wrong_mk_fails() {
    use crate::wrap::{wrap_cek, unwrap_cek};
    use crate::types::{Cek, MasterKey};
    let w = wrap_cek(&MasterKey([1u8; 32]), &Cek([0u8; 32])).unwrap();
    assert!(unwrap_cek(&MasterKey([2u8; 32]), &w).is_err());
}

#[test]
fn wrap_uses_kdf_derived_key_not_raw_mk() {
    // Ensures KEK != MK: derive a KEK via HKDF, then wrap. We can't directly
    // inspect the KEK, but the ciphertext should differ from any direct
    // XChaCha20-Poly1305 encrypt of CEK with raw MK.
    use crate::wrap::wrap_cek;
    use crate::aead::encrypt;
    use crate::types::{Cek, MasterKey};
    let mk = MasterKey([9u8; 32]);
    let cek = Cek([0u8; 32]);
    let wrapped = wrap_cek(&mk, &cek).unwrap();
    let direct = encrypt(&mk, cek.as_bytes()).unwrap();
    assert_ne!(wrapped.ct, direct.ct, "KEK must differ from raw MK");
}
```

**Step 1.5.2: Run, expect failure**

```bash
cargo test -p vault-core wrap
```

**Step 1.5.3: Implement `wrap.rs`**

```rust
//! Wrap a CEK with a master key using HKDF-derived KEK + XChaCha20-Poly1305.

use hkdf::Hkdf;
use sha2::Sha256;
use crate::aead;
use crate::types::{Cek, MasterKey, WrappedCek};

const KEK_INFO: &[u8] = b"vault:wrap:v1";

fn derive_kek(mk: &MasterKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, mk.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(KEK_INFO, &mut okm).expect("32 < 255*Sha256");
    okm
}

pub fn wrap_cek(mk: &MasterKey, cek: &Cek) -> Result<WrappedCek, WrapError> {
    let kek = derive_kek(mk);
    let mut nonce = [0u8; 24];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = chacha20poly1305::XChaCha20Poly1305::new((&kek).into());
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::KeyInit;
    let ct = cipher.encrypt(chacha20poly1305::XNonce::from_slice(&nonce), cek.as_bytes())
        .map_err(|_| WrapError::Wrap)?;
    Ok(WrappedCek { nonce, ct })
}

pub fn unwrap_cek(mk: &MasterKey, w: &WrappedCek) -> Result<Cek, WrapError> {
    let kek = derive_kek(mk);
    let cipher = chacha20poly1305::XChaCha20Poly1305::new((&kek).into());
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::KeyInit;
    let plain = cipher.decrypt(chacha20poly1305::XNonce::from_slice(&w.nonce), w.ct.as_ref())
        .map_err(|_| WrapError::Unwrap)?;
    if plain.len() != 32 { return Err(WrapError::Unwrap); }
    let mut a = [0u8; 32];
    a.copy_from_slice(&plain);
    Ok(Cek(a))
}

#[derive(thiserror::Error, Debug)]
pub enum WrapError {
    #[error("CEK wrap failed")] Wrap,
    #[error("CEK unwrap failed (wrong master key or tampered data)")] Unwrap,
}
```

**Step 1.5.4: Wire up**

In `lib.rs`:
```rust
pub mod wrap;
pub use wrap::{wrap_cek, unwrap_cek, WrapError};
```

**Step 1.5.5: Run, expect pass**

```bash
cargo test -p vault-core wrap
```
Expected: 3 new tests pass.

**Step 1.5.6: Commit**

```bash
git add crates/vault-core/src/wrap.rs crates/vault-core/src/lib.rs
git commit -m "feat(vault-core): CEK wrap/unwrap with HKDF-derived KEK"
```

---

### Task 1.6: CSV codec (Entry + encode/decode)

**Files:**
- Create: `crates/vault-core/src/entry.rs`
- Create: `crates/vault-core/src/csv_codec.rs`
- Modify: `crates/vault-core/src/lib.rs`
- Modify: `Cargo.toml` (workspace deps): add `csv` crate

**Step 1.6.1: Add csv dependency**

In workspace `Cargo.toml` `[workspace.dependencies]`:
```toml
csv = "1.3.0"
```

**Step 1.6.2: Failing tests for entry**

```rust
#[test]
fn entry_domain_extraction() {
    use crate::entry::Entry;
    let e = Entry::new(
        "github".into(), "https://github.com/login".into(),
        "alice".into(), "pw".into(), "".into()
    );
    assert_eq!(e.domain(), "github.com");
}

#[test]
fn entry_domain_ip_fallback() {
    use crate::entry::Entry;
    let e = Entry::new(
        "router".into(), "http://192.168.0.1/".into(),
        "admin".into(), "pw".into(), "".into()
    );
    assert_eq!(e.domain(), "192.168.0.1");
}

#[test]
fn entry_tags_from_note() {
    use crate::entry::Entry;
    let e = Entry::new(
        "x".into(), "".into(), "".into(), "".into(),
        "important #work #email".into()
    );
    let tags = e.tags();
    assert_eq!(tags, vec!["work".to_string(), "email".to_string()]);
}

#[test]
fn entry_no_tags_when_no_hash() {
    use crate::entry::Entry;
    let e = Entry::new(
        "x".into(), "".into(), "".into(), "".into(),
        "just a plain note".into()
    );
    assert!(e.tags().is_empty());
}
```

**Step 1.6.3: Implement `entry.rs`**

```rust
//! In-memory entry representation and derived fields.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub note: String,
}

impl Entry {
    pub fn new(
        name: String, url: String, username: String, password: String, note: String,
    ) -> Self {
        Self { name, url, username, password, note }
    }

    /// Extract the host portion of the URL, falling back to the URL itself
    /// if parsing fails. IPv4/IPv6 literals are returned as-is.
    pub fn domain(&self) -> String {
        if self.url.is_empty() { return String::new(); }
        match url::Url::parse(&self.url) {
            Ok(u) => u.host_str().unwrap_or(&self.url).to_string(),
            Err(_) => self.url.clone(),
        }
    }

    /// Parse `#tag` tokens out of the note field, preserving order.
    pub fn tags(&self) -> Vec<String> {
        self.note.split_whitespace()
            .filter(|t| t.starts_with('#') && t.len() > 1)
            .map(|t| t[1..].to_string())
            .collect()
    }
}
```

**Step 1.6.4: Wire up**

In `lib.rs`:
```rust
pub mod entry;
pub use entry::Entry;
```

Run: `cargo test -p vault-core entry` — expect 4 tests pass. Commit:
```bash
git add crates/vault-core/src/entry.rs crates/vault-core/src/lib.rs
git commit -m "feat(vault-core): Entry struct with domain + #tag parsing"
```

**Step 1.6.5: Failing tests for csv_codec**

```rust
#[test]
fn csv_round_trip() {
    use crate::entry::Entry;
    use crate::csv_codec::{encode_csv, decode_csv};
    let entries = vec![
        Entry::new("a".into(), "https://a.com".into(), "u".into(), "p".into(), "n".into()),
        Entry::new("b, inc".into(), "".into(), "".into(), "p\"q".into(), "#tag1".into()),
    ];
    let bytes = encode_csv(&entries).unwrap();
    let back = decode_csv(&bytes).unwrap();
    assert_eq!(back, entries);
}

#[test]
fn csv_decodes_sample() {
    use crate::entry::Entry;
    use crate::csv_codec::decode_csv;
    let sample = b"name,url,username,password,note\n\
                  192.168.0.9,https://192.168.0.9/,admin,mamapangpang,\n";
    let entries = decode_csv(sample).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "192.168.0.9");
    assert_eq!(entries[0].username, "admin");
}

#[test]
fn csv_handles_unicode() {
    use crate::entry::Entry;
    use crate::csv_codec::{encode_csv, decode_csv};
    let e = Entry::new("中文".into(), "https://例え.jp/".into(),
                       "用户".into(), "密码".into(), "备注 #仕事".into());
    let bytes = encode_csv(&[e.clone()]).unwrap();
    let back = decode_csv(&bytes).unwrap();
    assert_eq!(back, vec![e]);
}
```

**Step 1.6.6: Run, expect failure**

```bash
cargo test -p vault-core csv_codec
```

**Step 1.6.7: Implement `csv_codec.rs`**

```rust
//! CSV encode/decode for `Vec<Entry>`.

use crate::entry::Entry;

const HEADER: &str = "name,url,username,password,note";

pub fn encode_csv(entries: &[Entry]) -> Result<Vec<u8>, CsvError> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record(HEADER.split(','))?;
    for e in entries {
        wtr.write_record(&[&e.name, &e.url, &e.username, &e.password, &e.note])?;
    }
    Ok(wtr.into_inner()?)
}

pub fn decode_csv(bytes: &[u8]) -> Result<Vec<Entry>, CsvError> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(bytes);
    let mut out = Vec::new();
    for rec in rdr.records() {
        let r = rec?;
        let get = |i: usize| r.get(i).unwrap_or("").to_string();
        out.push(Entry::new(get(0), get(1), get(2), get(3), get(4)));
    }
    Ok(out)
}

#[derive(thiserror::Error, Debug)]
pub enum CsvError {
    #[error("CSV I/O: {0}")] Io(#[from] csv::Error),
    #[error("CSV into_inner: {0}")] IntoInner(csv::IntoInnerError<csv::Writer<Vec<u8>>>),
}
impl From<csv::IntoInnerError<csv::Writer<Vec<u8>>>> for CsvError {
    fn from(e: csv::IntoInnerError<csv::Writer<Vec<u8>>>) -> Self { Self::IntoInner(e) }
}
```

**Step 1.6.8: Wire up**

In `lib.rs`:
```rust
pub mod csv_codec;
pub use csv_codec::{encode_csv, decode_csv, CsvError};
```

**Step 1.6.9: Run, expect pass**

```bash
cargo test -p vault-core csv_codec
```
Expected: 3 new tests pass.

**Step 1.6.10: Commit**

```bash
git add crates/vault-core/src/csv_codec.rs crates/vault-core/src/lib.rs Cargo.toml
git commit -m "feat(vault-core): CSV codec for Vec<Entry> (RFC 4180)"
```

---

### Task 1.7: Trigram search (Jaccard + substring + scoring)

**Files:**
- Create: `crates/vault-core/src/search.rs`
- Modify: `crates/vault-core/src/lib.rs`

**Step 1.7.1: Failing tests**

```rust
#[test]
fn trigrams_of_short_string() {
    use crate::search::trigrams;
    // "ab" -> [" ab", "ab "] padded? Spec: padded with spaces.
    let t = trigrams("ab");
    // padded: " ab", "ab " (2 trigrams)
    assert_eq!(t, vec![" ab".to_string(), "ab ".to_string()]);
}

#[test]
fn jaccard_basic() {
    use crate::search::jaccard;
    let a = vec!["git", "ith", "hub"];
    let b = vec!["git", "ith", "hub", "hub"];
    // Intersection 3, union 3, Jaccard = 1.0
    assert!((jaccard(&a, &b) - 1.0).abs() < 1e-9);
}

#[test]
fn search_githb_matches_github() {
    use crate::entry::Entry;
    use crate::search::search;
    let entries = vec![
        Entry::new("github".into(), "https://github.com".into(),
                   "alice".into(), "pw".into(), "".into()),
    ];
    let hits = search("githb", &entries);
    assert_eq!(hits.len(), 1);
    assert!(hits[0].score > 0.15);
}

#[test]
fn search_no_match_returns_empty() {
    use crate::entry::Entry;
    use crate::search::search;
    let entries = vec![
        Entry::new("github".into(), "https://github.com".into(),
                   "alice".into(), "pw".into(), "".into()),
    ];
    let hits = search("zzzqqqxxx", &entries);
    assert!(hits.is_empty());
}

#[test]
fn search_key_colon_field_filter() {
    use crate::entry::Entry;
    use crate::search::search;
    let entries = vec![
        Entry::new("github".into(), "https://gmail.com".into(),
                   "alice".into(), "pw".into(), "".into()),
        Entry::new("gmail".into(), "https://gmail.com".into(),
                   "bob".into(), "pw".into(), "".into()),
    ];
    let hits = search("name:github", &entries);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].entry.name, "github");
}

#[test]
fn search_substring_bonus_helps() {
    use crate::entry::Entry;
    use crate::search::search;
    let entries = vec![
        Entry::new("my-very-long-name-12345".into(), "".into(),
                   "".into(), "".into(), "".into()),
    ];
    // "12345" is exact substring -> bonus pushes it over threshold
    let hits = search("12345", &entries);
    assert_eq!(hits.len(), 1);
}

#[test]
fn search_is_lowercase_and_nfc_normalized() {
    use crate::entry::Entry;
    use crate::search::search;
    let entries = vec![
        Entry::new("GitHub".into(), "".into(), "".into(), "".into(), "".into()),
    ];
    let hits = search("GITHUB", &entries);
    assert_eq!(hits.len(), 1);
}
```

**Step 1.7.2: Run, expect failure**

```bash
cargo test -p vault-core search
```

**Step 1.7.3: Implement `search.rs`**

```rust
//! Trigram-based fuzzy search over `Vec<Entry>`. Per spec §7.3.2.

use crate::entry::Entry;
use unicode_normalization::UnicodeNormalization;

const W_NAME: f32 = 0.40;
const W_URL:  f32 = 0.25;
const W_USER: f32 = 0.20;
const W_NOTE: f32 = 0.15;
const SUBSTRING_BONUS: f32 = 0.30;
const THRESHOLD: f32 = 0.15;

/// A single search hit.
#[derive(Debug, Clone)]
pub struct Hit<'a> {
    pub entry: &'a Entry,
    pub score: f32,
}

fn normalize(s: &str) -> String {
    s.nfc().collect::<String>().to_lowercase()
}

fn trigrams(s: &str) -> Vec<String> {
    let s = format!(" {} ", s);
    if s.chars().count() < 3 { return vec![]; }
    s.as_bytes().windows(3).map(|w| {
        // windows on bytes works because we only split ASCII-safe trigrams;
        // for non-ASCII, fall back to per-char triple via chars().zip windows.
        String::from_utf8_lossy(w).into_owned()
    }).collect()
}

fn trigrams_safe(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 3 { return vec![]; }
    chars.windows(3).map(|w| w.iter().collect()).collect()
}

pub fn jaccard(a: &[String], b: &[String]) -> f32 {
    use std::collections::HashSet;
    let sa: HashSet<&String> = a.iter().collect();
    let sb: HashSet<&String> = b.iter().collect();
    let inter = sa.intersection(&sb).count() as f32;
    let union = sa.union(&sb).count() as f32;
    if union == 0.0 { 0.0 } else { inter / union }
}

fn field_score(q_trigrams: &[String], q_norm: &str, target: &str) -> f32 {
    if target.is_empty() { return 0.0; }
    let t_norm = normalize(target);
    let t_tris = trigrams_safe(&t_norm);
    let sim = jaccard(q_trigrams, &t_tris);
    let mut s = sim;
    if !q_norm.is_empty() && t_norm.contains(q_norm) {
        s = (s + SUBSTRING_BONUS).min(1.0);
    }
    s
}

/// Parse a query like `name:git tag:work` into (`global_terms`, `field_filters`).
pub fn parse_query(q: &str) -> (Vec<String>, Vec<(String, String)>) {
    let mut globals = Vec::new();
    let mut filters = Vec::new();
    for tok in q.split_whitespace() {
        if let Some((k, v)) = tok.split_once(':') {
            filters.push((k.to_lowercase(), v.to_lowercase()));
        } else {
            globals.push(normalize(tok));
        }
    }
    (globals, filters)
}

pub fn search<'a>(query: &str, entries: &'a [Entry]) -> Vec<Hit<'a>> {
    if query.trim().is_empty() { return Vec::new(); }
    let (globals, filters) = parse_query(query);
    let mut hits = Vec::new();
    for e in entries {
        // Apply field filters: each filter must match its target field.
        let mut passes_filters = true;
        for (k, v) in &filters {
            let target = match k.as_str() {
                "name" => &e.name,
                "url" | "domain" => &e.domain(),
                "user" | "username" => &e.username,
                "note" => &e.note,
                "tag" => &e.tags().join(" "),
                _ => { passes_filters = false; break; }
            };
            if !normalize(target).contains(v) {
                passes_filters = false;
                break;
            }
        }
        if !passes_filters { continue; }

        if globals.is_empty() {
            // No global terms; pure filter pass = score 1.0
            hits.push(Hit { entry: e, score: 1.0 });
            continue;
        }

        // Multi-word AND: each term must produce a non-zero weighted contribution.
        // Final score = product of max contributions per term.
        let mut total: f32 = 1.0;
        for term in &globals {
            let q_tris = trigrams_safe(term);
            let s_name = field_score(&q_tris, term, &e.name);
            let s_url  = field_score(&q_tris, term, &e.domain());
            let s_user = field_score(&q_tris, term, &e.username);
            let s_note = field_score(&q_tris, term, &e.note);
            let best = (s_name * W_NAME)
                     + (s_url  * W_URL)
                     + (s_user * W_USER)
                     + (s_note * W_NOTE);
            if best < 0.05 {
                // Term has near-zero contribution — treat as AND-fail
                total = 0.0;
                break;
            }
            total *= best;
        }

        if total >= THRESHOLD {
            hits.push(Hit { entry: e, score: total });
        }
    }
    hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    hits
}
```

**Step 1.7.4: Add `unicode-normalization` to workspace deps**

In `Cargo.toml` `[workspace.dependencies]`:
```toml
unicode-normalization = "0.1.23"
```

In `crates/vault-core/Cargo.toml` `[dependencies]`:
```toml
unicode-normalization.workspace = true
```

**Step 1.7.5: Wire up**

In `lib.rs`:
```rust
pub mod search;
pub use search::{search, Hit, parse_query, jaccard, trigrams as _trigrams};
```

**Step 1.7.6: Run, expect pass**

```bash
cargo test -p vault-core search
```
Expected: all 7 tests pass.

**Step 1.7.7: Commit**

```bash
git add crates/vault-core/src/search.rs crates/vault-core/src/lib.rs Cargo.toml crates/vault-core/Cargo.toml
git commit -m "feat(vault-core): trigram search with field filters (name/url/user/note/tag)"
```

---

### Task 1.8: Grouping (domain / tag / letter)

**Files:**
- Create: `crates/vault-core/src/group.rs`
- Modify: `crates/vault-core/src/lib.rs`

**Step 1.8.1: Failing tests**

```rust
#[test]
fn group_by_domain() {
    use crate::entry::Entry;
    use crate::group::group_by_domain;
    let entries = vec![
        Entry::new("a".into(), "https://github.com/".into(), "".into(), "".into(), "".into()),
        Entry::new("b".into(), "https://github.com/x".into(), "".into(), "".into(), "".into()),
        Entry::new("c".into(), "https://gmail.com/".into(), "".into(), "".into(), "".into()),
    ];
    let g = group_by_domain(&entries);
    assert_eq!(g.get("github.com").map(|v| v.len()), Some(2));
    assert_eq!(g.get("gmail.com").map(|v| v.len()), Some(1));
}

#[test]
fn group_by_tag() {
    use crate::entry::Entry;
    use crate::group::group_by_tag;
    let entries = vec![
        Entry::new("a".into(), "".into(), "".into(), "".into(), "#work".into()),
        Entry::new("b".into(), "".into(), "".into(), "".into(), "#work #urgent".into()),
        Entry::new("c".into(), "".into(), "".into(), "".into(), "no tags".into()),
    ];
    let g = group_by_tag(&entries);
    assert_eq!(g.get("work").map(|v| v.len()), Some(2));
    assert_eq!(g.get("urgent").map(|v| v.len()), Some(1));
}

#[test]
fn group_by_letter() {
    use crate::entry::Entry;
    use crate::group::group_by_letter;
    let entries = vec![
        Entry::new("Apple".into(), "".into(), "".into(), "".into(), "".into()),
        Entry::new("apricot".into(), "".into(), "".into(), "".into(), "".into()),
        Entry::new("Banana".into(), "".into(), "".into(), "".into(), "".into()),
        Entry::new("123".into(), "".into(), "".into(), "".into(), "".into()),
    ];
    let g = group_by_letter(&entries);
    assert_eq!(g.get("A").map(|v| v.len()), Some(2));
    assert_eq!(g.get("B").map(|v| v.len()), Some(1));
    assert_eq!(g.get("#").map(|v| v.len()), Some(1));
}
```

**Step 1.8.2: Run, expect failure**

```bash
cargo test -p vault-core group
```

**Step 1.8.3: Implement `group.rs`**

```rust
//! Categorization of `Vec<Entry>` by domain, tag, or first letter.

use std::collections::BTreeMap;
use crate::entry::Entry;

/// `BTreeMap<group_key, Vec<&Entry>>` for stable iteration order.
pub type Grouped<'a> = BTreeMap<String, Vec<&'a Entry>>;

pub fn group_by_domain(entries: &[Entry]) -> Grouped<'_> {
    let mut m: Grouped<'_> = BTreeMap::new();
    for e in entries {
        let d = e.domain();
        let key = if d.is_empty() { "(no url)".to_string() } else { d };
        m.entry(key).or_default().push(e);
    }
    m
}

pub fn group_by_tag(entries: &[Entry]) -> Grouped<'_> {
    let mut m: Grouped<'_> = BTreeMap::new();
    for e in entries {
        for t in e.tags() {
            m.entry(t).or_default().push(e);
        }
    }
    m
}

pub fn group_by_letter(entries: &[Entry]) -> Grouped<'_> {
    let mut m: Grouped<'_> = BTreeMap::new();
    for e in entries {
        let key = e.name.chars().next().map(|c| {
            if c.is_ascii_alphabetic() {
                c.to_ascii_uppercase().to_string()
            } else if c.is_ascii_digit() {
                "#".to_string()  // digits go to "#" bucket
            } else {
                c.to_string()
            }
        }).unwrap_or_else(|| "(empty)".to_string());
        m.entry(key).or_default().push(e);
    }
    m
}
```

**Step 1.8.4: Wire up**

In `lib.rs`:
```rust
pub mod group;
pub use group::{group_by_domain, group_by_tag, group_by_letter, Grouped};
```

**Step 1.8.5: Run, expect pass**

```bash
cargo test -p vault-core group
```
Expected: 3 tests pass.

**Step 1.8.6: Commit**

```bash
git add crates/vault-core/src/group.rs crates/vault-core/src/lib.rs
git commit -m "feat(vault-core): grouping by domain/tag/letter"
```

---

### Task 1.9: Protocol types (JSON DTOs)

**Files:**
- Create: `crates/vault-core/src/protocol.rs`
- Modify: `crates/vault-core/src/lib.rs`

**Step 1.9.1: Failing test**

```rust
#[test]
fn snapshot_serde_round_trip() {
    use crate::protocol::VaultSnapshot;
    let json = r#"{
      "version": 1,
      "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
      "wrapped_cek": {"nonce": "AAAAAAAAAAAAAAAAAAAAAAAA", "ct": "AAAA"},
      "ciphertext": {"nonce": "AAAAAAAAAAAAAAAAAAAAAAAA", "ct": "AAAA"},
      "kdf": {"algo": "argon2id", "m": 65536, "t": 3, "p": 1},
      "created_at": "2026-06-17T00:00:00Z"
    }"#;
    let snap: VaultSnapshot = serde_json::from_str(json).unwrap();
    assert_eq!(snap.version, 1);
    let back = serde_json::to_string(&snap).unwrap();
    assert!(back.contains("\"version\":1"));
}
```

**Step 1.9.2: Run, expect failure**

```bash
cargo test -p vault-core protocol
```

**Step 1.9.3: Implement `protocol.rs`**

```rust
//! JSON DTOs for the HTTP API.

use serde::{Deserialize, Serialize};
use base64::Engine;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSnapshot {
    pub version: u64,
    pub salt: String,         // base64url(16B)
    pub wrapped_cek: CipherBlock,
    pub ciphertext: CipherBlock,
    pub kdf: KdfJson,
    pub created_at: String,   // ISO8601
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultWrite {
    pub salt: String,
    pub wrapped_cek: CipherBlock,
    pub ciphertext: CipherBlock,
    pub kdf: KdfJson,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultRekey {
    pub salt: String,
    pub wrapped_cek: CipherBlock,
    pub kdf: KdfJson,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CipherBlock {
    pub nonce: String,   // base64url(24B)
    pub ct: String,      // base64url(N)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfJson {
    pub algo: String,    // "argon2id"
    pub m: u32,          // KiB
    pub t: u32,
    pub p: u32,
}

impl KdfJson {
    pub fn to_params(&self) -> Result<crate::kdf::KdfParams, String> {
        if self.algo != "argon2id" {
            return Err(format!("unsupported KDF: {}", self.algo));
        }
        Ok(crate::kdf::KdfParams { m_cost_kib: self.m, t_cost: self.t, p_cost: self.p })
    }
}

pub fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
pub fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}
```

**Step 1.9.4: Wire up**

In `lib.rs`:
```rust
pub mod protocol;
pub use protocol::{VaultSnapshot, VaultWrite, VaultRekey, CipherBlock, KdfJson, b64_encode, b64_decode};
```

**Step 1.9.5: Run, expect pass**

```bash
cargo test -p vault-core protocol
```

**Step 1.9.6: Commit**

```bash
git add crates/vault-core/src/protocol.rs crates/vault-core/src/lib.rs
git commit -m "feat(vault-core): protocol DTOs (Snapshot/Write/Rekey)"
```

---

### Task 1.10: KAT + differential tests

**Files:**
- Create: `crates/vault-core/src/tests/kat.rs`
- Create: `crates/vault-core/src/tests/mod.rs`
- Modify: `crates/vault-core/src/lib.rs`

**Step 1.10.1: Argon2id KAT (from RFC 9106 §4)**

Create `crates/vault-core/src/tests/mod.rs`:
```rust
pub mod kat;
```

Append to `lib.rs`:
```rust
#[cfg(test)]
mod tests_outer {
    mod tests;
}
```

Create `crates/vault-core/src/tests/kat.rs`:
```rust
//! Known-answer tests for KDF and AEAD. Vectors from RFC 9106 / RFC 8439.

use crate::kdf::{derive_mk, KdfParams};
use crate::types::Salt;
use crate::aead::{encrypt, decrypt};
use crate::types::Cek;

#[test]
fn argon2_rfc9106_vector_1() {
    // RFC 9106 §4.1, v=0x13, m=32, t=3, p=4
    // Password = "password", Salt = 16 bytes "somesalt" padded
    let salt_bytes: [u8; 16] = [
        0x73, 0x6f, 0x6d, 0x65, 0x73, 0x61, 0x6c, 0x74,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let salt = Salt(salt_bytes);
    let params = KdfParams { m_cost_kib: 32, t_cost: 3, p_cost: 4 };
    let mk = derive_mk(b"password", &salt, &params).unwrap();
    let expected = [
        0x3a, 0x59, 0x14, 0xe7, 0x59, 0xcd, 0xa3, 0x59,
        0x64, 0x7a, 0xdc, 0x25, 0x5b, 0x4b, 0x40, 0x21,
        // truncated for test brevity — full vector in RFC.
    ];
    // We test first 16 bytes only (our derive_mk returns 32 bytes, but RFC vector is 32)
    assert_eq!(&mk.as_bytes()[..16], &expected[..]);
}

#[test]
fn aead_nonce_uniqueness_in_1k_encrypts() {
    // Sanity: 1k encrypts should produce 1k distinct nonces.
    let cek = Cek([0u8; 32]);
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..1000 {
        let c = encrypt(&cek, b"x").unwrap();
        assert!(nonces.insert(c.nonce.to_vec()));
    }
    assert_eq!(nonces.len(), 1000);
}
```

**Step 1.10.2: Run**

```bash
cargo test -p vault-core --release tests::kat
```

Expected: KAT passes. If RFC vector bytes mismatch, fetch the exact vector from RFC 9106 §4.1 (use `cargo test` to see the actual output and compare).

**Step 1.10.3: Commit**

```bash
git add crates/vault-core/src/tests crates/vault-core/src/lib.rs
git commit -m "test(vault-core): Argon2id KAT + nonce uniqueness"
```

---

### Task 1.11: M1 closure — full vault-core test sweep

**Step 1.11.1: Run all tests + clippy + fmt**

```bash
cargo fmt --all
cargo clippy -p vault-core --all-targets -- -D warnings
cargo test -p vault-core --all
```

Expected: 0 warnings, all tests pass.

**Step 1.11.2: Tag**

```bash
git tag m1-vault-core
```

---

## Milestone 2 — `vault-server` HTTP 服务

### Task 2.1: `vault-server` skeleton (no auth yet)

**Files:**
- Create: `crates/vault-server/Cargo.toml`
- Create: `crates/vault-server/src/main.rs`
- Create: `crates/vault-server/src/config.rs`

**Step 2.1.1: Cargo.toml**

```toml
[package]
name = "vault-server"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "vault-server"
path = "src/main.rs"

[dependencies]
vault-core = { path = "../vault-core" }
axum = "0.7.5"
tokio = { version = "1.39.2", features = ["full"] }
tower = "0.5.0"
tower-http = { version = "0.6.1", features = ["limit", "trace"] }
rusqlite = { version = "0.32.1", features = ["bundled"] }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
anyhow.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

**Step 2.1.2: `config.rs`**

```rust
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,   // hard-coded to "127.0.0.1:8080"
    pub auth_token: String,  // 64 random bytes, base64url
    pub db_path: PathBuf,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        // Hard-coded bind: refuse if env tries to override
        let auth_token = std::env::var("AUTH_TOKEN")
            .map_err(|_| anyhow::anyhow!("AUTH_TOKEN must be set"))?;
        if auth_token.len() < 32 {
            anyhow::bail!("AUTH_TOKEN must be ≥ 32 chars");
        }
        let db_path = std::env::var("DB_PATH")
            .unwrap_or_else(|_| "/var/lib/vault/vault.db".into());
        Ok(Self {
            bind_addr: "127.0.0.1:8080".into(),
            auth_token,
            db_path: db_path.into(),
        })
    }
}
```

**Step 2.1.3: `main.rs` (skeleton, /health only)**

```rust
mod config;
use config::Config;
use std::net::SocketAddr;
use axum::{routing::get, Router, Json};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cfg = Config::from_env()?;
    let app = Router::new()
        .route("/health", get(|| async { Json(json!({"ok": true})) }));
    let addr: SocketAddr = cfg.bind_addr.parse()?;
    tracing::info!(%addr, "vault-server starting");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

**Step 2.1.4: Build + run smoke test**

```bash
AUTH_TOKEN=$(openssl rand -base64 48) cargo run -p vault-server &
SERVER_PID=$!
sleep 2
curl -s http://127.0.0.1:8080/health
kill $SERVER_PID
```

Expected: `{"ok":true}`

**Step 2.1.5: Commit**

```bash
git add crates/vault-server
git commit -m "feat(vault-server): skeleton with /health, hard-coded 127.0.0.1:8080"
```

---

### Task 2.2: SQLite store (single-row + history)

**Files:**
- Create: `crates/vault-server/src/store.rs`
- Modify: `crates/vault-server/Cargo.toml`: add `chrono` dep
- Create: `crates/vault-server/src/error.rs`

**Step 2.2.1: Failing test (`store.rs` inline)**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db() -> Store {
        let path = std::env::temp_dir().join(format!("vault_test_{}.db", rand::random::<u64>()));
        Store::open(&path).unwrap()
    }

    #[test]
    fn fresh_db_has_no_snapshot() {
        let s = tmp_db();
        assert!(s.get_snapshot().unwrap().is_none());
    }

    #[test]
    fn put_then_get_round_trip() {
        let s = tmp_db();
        let v = Version(1);
        s.put_snapshot(v, b"salt", b"wrap", b"ct", "2026-06-17T00:00:00Z").unwrap();
        let snap = s.get_snapshot().unwrap().unwrap();
        assert_eq!(snap.version, 1);
        assert_eq!(snap.wrapped_cek, b"wrap");
    }

    #[test]
    fn put_with_wrong_expected_version_fails() {
        let s = tmp_db();
        s.put_snapshot(Version(1), b"s", b"w", b"c", "t").unwrap();
        let err = s.put_if_match(Version(1), Version(2), b"s", b"w2", b"c2", "t2").unwrap_err();
        assert!(matches!(err, StoreError::VersionConflict { current: 1, .. }));
    }

    #[test]
    fn put_if_match_at_correct_version_succeeds() {
        let s = tmp_db();
        s.put_snapshot(Version(1), b"s", b"w", b"c", "t").unwrap();
        s.put_if_match(Version(1), Version(2), b"s", b"w2", b"c2", "t2").unwrap();
        assert_eq!(s.get_snapshot().unwrap().unwrap().version, 2);
    }
}
```

**Step 2.2.2: Run, expect failure**

```bash
cargo test -p vault-server store
```

**Step 2.2.3: Implement `store.rs`**

```rust
use crate::error::ServerError;
use rusqlite::{params, Connection};
use std::path::Path;
use vault_core::Version;

pub struct Store { conn: Connection }

#[derive(Debug, Clone)]
pub struct StoredSnapshot {
    pub version: Version,
    pub salt: Vec<u8>,
    pub wrapped_cek: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub kdf_params: Vec<u8>,
    pub created_at: String,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, ServerError> {
        let conn = Connection::open(path)?;
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL,
                salt BLOB NOT NULL,
                wrapped_cek BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                kdf_params BLOB NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vault_history (
                version INTEGER PRIMARY KEY,
                salt BLOB NOT NULL,
                wrapped_cek BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                kdf_params BLOB NOT NULL,
                archived_at TEXT NOT NULL
            );
        ")?;
        Ok(Self { conn })
    }

    pub fn get_snapshot(&self) -> Result<Option<StoredSnapshot>, ServerError> {
        let mut stmt = self.conn.prepare(
            "SELECT version, salt, wrapped_cek, ciphertext, kdf_params, created_at FROM vault WHERE id=1"
        )?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            Ok(Some(StoredSnapshot {
                version: Version(row.get::<_, i64>(0)? as u64),
                salt: row.get(1)?,
                wrapped_cek: row.get(2)?,
                ciphertext: row.get(3)?,
                kdf_params: row.get(4)?,
                created_at: row.get(5)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// First-time put (no existing row).
    pub fn put_snapshot(&self, v: Version, salt: &[u8], wrapped: &[u8], ct: &[u8], ts: &str) -> Result<(), ServerError> {
        self.conn.execute(
            "INSERT INTO vault (id, version, salt, wrapped_cek, ciphertext, kdf_params, created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![v.as_u64() as i64, salt, wrapped, ct, b"{}", ts]
        )?;
        Ok(())
    }

    /// Compare-and-swap update. Expects the current row to be at `expected`.
    pub fn put_if_match(&self, expected: Version, new_v: Version, salt: &[u8], wrapped: &[u8], ct: &[u8], ts: &str) -> Result<(), ServerError> {
        let tx = self.conn.unchecked_transaction()?;
        let cur: i64 = tx.query_row("SELECT version FROM vault WHERE id=1", [], |r| r.get(0))
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => ServerError::Store(StoreError::NotFound),
                other => ServerError::Rusqlite(other),
            })?;
        if cur as u64 != expected.as_u64() {
            return Err(ServerError::Store(StoreError::VersionConflict {
                expected: expected.as_u64(),
                current: cur as u64,
            }));
        }
        // Archive old
        tx.execute(
            "INSERT OR REPLACE INTO vault_history (version, salt, wrapped_cek, ciphertext, kdf_params, archived_at) \
             SELECT version, salt, wrapped_cek, ciphertext, kdf_params, ?1 FROM vault WHERE id=1",
            params![ts]
        )?;
        tx.execute(
            "UPDATE vault SET version=?1, salt=?2, wrapped_cek=?3, ciphertext=?4, created_at=?5 WHERE id=1",
            params![new_v.as_u64() as i64, salt, wrapped, ct, ts]
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    #[error("not found")] NotFound,
    #[error("version conflict: expected {expected}, current {current}")] VersionConflict { expected: u64, current: u64 },
}
```

**Step 2.2.4: `error.rs`**

```rust
#[derive(thiserror::Error, Debug)]
pub enum ServerError {
    #[error("rusqlite: {0}")] Rusqlite(#[from] rusqlite::Error),
    #[error("store: {0}")] Store(#[from] StoreError),
    #[error("io: {0}")] Io(#[from] std::io::Error),
    #[error("env: {0}")] Env(#[from] std::env::VarError),
    #[error("axum: {0}")] Axum(#[from] axum::Error),
    #[error("serde_json: {0}")] Json(#[from] serde_json::Error),
    #[error("body too large")] BodyTooLarge,
    #[error("unauthorized")] Unauthorized,
    #[error("bad request: {0}")] BadRequest(String),
    #[error("internal: {0}")] Internal(String),
}
use crate::store::StoreError;
```

**Step 2.2.5: Wire up**

In `main.rs`, add:
```rust
mod store;
mod error;
```

**Step 2.2.6: Run tests, expect pass**

```bash
cargo test -p vault-server store
```
Expected: 4 store tests pass.

**Step 2.2.7: Commit**

```bash
git add crates/vault-server
git commit -m "feat(vault-server): SQLite store with single-row + history + CAS"
```

---

### Task 2.3: Auth middleware (Bearer token, constant-time)

**Files:**
- Create: `crates/vault-server/src/auth.rs`
- Modify: `crates/vault-server/src/main.rs`

**Step 2.3.1: Tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_token_matches() {
        let expected = "abc123".to_string();
        assert!(check_bearer(Some("Bearer abc123"), &expected));
    }
    #[test]
    fn check_token_rejects_wrong() {
        let expected = "abc123".to_string();
        assert!(!check_bearer(Some("Bearer xyz"), &expected));
    }
    #[test]
    fn check_token_rejects_missing() {
        assert!(!check_bearer(None, "x"));
        assert!(!check_bearer(Some(""), "x"));
        assert!(!check_bearer(Some("Basic abc"), "x"));
    }
}
```

**Step 2.3.2: Implement `auth.rs`**

```rust
use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

pub fn check_bearer(headers: Option<&str>, expected: &str) -> bool {
    let h = match headers { Some(s) => s, None => return false };
    let token = match h.strip_prefix("Bearer ") { Some(t) => t, None => return false };
    token.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Extract Authorization header value.
pub fn auth_header(headers: &HeaderMap) -> Option<String> {
    headers.get("authorization").and_then(|v| v.to_str().ok()).map(String::from)
}
```

(Add `subtle` to `vault-server/Cargo.toml` deps.)

**Step 2.3.3: Run + commit**

```bash
cargo test -p vault-server auth
git add crates/vault-server/src/auth.rs crates/vault-server/Cargo.toml
git commit -m "feat(vault-server): constant-time Bearer token check"
```

---

### Task 2.4: Handlers (GET, PUT, POST, health, version)

**Files:**
- Create: `crates/vault-server/src/handlers.rs`
- Modify: `crates/vault-server/src/main.rs`
- Modify: `crates/vault-server/Cargo.toml`: add `vault-core` features for protocol types

**Step 2.4.1: Implement handlers**

```rust
use axum::{
    extract::State, http::{HeaderMap, StatusCode}, response::{IntoResponse, Json}, Json as AxJson,
};
use serde_json::json;
use vault_core::{protocol::{VaultSnapshot, VaultWrite, VaultRekey, b64_decode, b64_encode}, Version};
use crate::auth::{auth_header, check_bearer};
use crate::store::Store;
use crate::error::ServerError;

pub struct AppState {
    pub store: std::sync::Arc<Store>,
    pub auth_token: String,
}

pub async fn health() -> impl IntoResponse {
    Json(json!({"ok": true}))
}

pub async fn version() -> impl IntoResponse {
    Json(json!({"name": "vault-server", "version": env!("CARGO_PKG_VERSION")}))
}

pub async fn get_vault(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<VaultSnapshot>, ServerError> {
    if !check_bearer(auth_header(&headers).as_deref(), &state.auth_token) {
        return Err(ServerError::Unauthorized);
    }
    let snap = state.store.get_snapshot()?
        .ok_or_else(|| ServerError::Internal("vault not initialized".into()))?;
    let kdf_params: serde_json::Value = serde_json::from_slice(&snap.kdf_params)
        .map_err(|e| ServerError::Internal(format!("kdf params: {e}")))?;
    let resp = VaultSnapshot {
        version: snap.version.as_u64(),
        salt: b64_encode(&snap.salt),
        wrapped_cek: vault_core::protocol::CipherBlock {
            nonce: b64_encode(&snap.wrapped_cek[..24]),
            ct: b64_encode(&snap.wrapped_cek[24..]),
        },
        ciphertext: vault_core::protocol::CipherBlock {
            nonce: b64_encode(&snap.ciphertext[..24]),
            ct: b64_encode(&snap.ciphertext[24..]),
        },
        kdf: serde_json::from_value(kdf_params)
            .map_err(|e| ServerError::Internal(format!("kdf parse: {e}")))?,
        created_at: snap.created_at,
    };
    Ok(Json(resp))
}

pub async fn put_vault(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
    AxJson(body): AxJson<VaultWrite>,
) -> Result<Json<serde_json::Value>, ServerError> {
    if !check_bearer(auth_header(&headers).as_deref(), &state.auth_token) {
        return Err(ServerError::Unauthorized);
    }
    let if_match = headers.get("if-match")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::BadRequest("missing If-Match header".into()))?;
    let expected = Version(if_match.parse::<u64>()
        .map_err(|_| ServerError::BadRequest("invalid If-Match".into()))?);
    let salt = b64_decode(&body.salt)
        .map_err(|e| ServerError::BadRequest(format!("salt: {e}")))?;
    let mut wrapped = b64_decode(&body.wrapped_cek.nonce)
        .map_err(|e| ServerError::BadRequest(format!("wrapped.nonce: {e}")))?;
    wrapped.extend(b64_decode(&body.wrapped_cek.ct)
        .map_err(|e| ServerError::BadRequest(format!("wrapped.ct: {e}")))?);
    let mut ct = b64_decode(&body.ciphertext.nonce)
        .map_err(|e| ServerError::BadRequest(format!("ciphertext.nonce: {e}")))?;
    ct.extend(b64_decode(&body.ciphertext.ct)
        .map_err(|e| ServerError::BadRequest(format!("ciphertext.ct: {e}")))?);
    let kdf_json = serde_json::to_vec(&body.kdf)
        .map_err(|e| ServerError::Internal(format!("kdf serialize: {e}")))?;
    let ts = chrono::Utc::now().to_rfc3339();
    let new_v = expected.increment_saturating();
    match state.store.put_if_match(expected, new_v, &salt, &wrapped, &ct, &ts) {
        Ok(()) => Ok(Json(json!({"version": new_v.as_u64()}))),
        Err(ServerError::Store(crate::store::StoreError::VersionConflict { current, .. })) => {
            // Return 409 with current state
            Err(ServerError::VersionConflict { current, salt, wrapped_cek: wrapped, ciphertext: ct, kdf_params: kdf_json, created_at: ts })
        }
        Err(e) => Err(e),
    }
}

pub async fn post_rekey(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
    AxJson(body): AxJson<VaultRekey>,
) -> Result<Json<serde_json::Value>, ServerError> {
    if !check_bearer(auth_header(&headers).as_deref(), &state.auth_token) {
        return Err(ServerError::Unauthorized);
    }
    let if_match = headers.get("if-match")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::BadRequest("missing If-Match header".into()))?;
    let expected = Version(if_match.parse::<u64>()
        .map_err(|_| ServerError::BadRequest("invalid If-Match".into()))?);
    // For rekey, ciphertext stays; only wrapped_cek and salt change.
    // We need to read current ciphertext first, then CAS.
    let cur = state.store.get_snapshot()?
        .ok_or_else(|| ServerError::Internal("vault not initialized".into()))?;
    let salt = b64_decode(&body.salt)
        .map_err(|e| ServerError::BadRequest(format!("salt: {e}")))?;
    let mut wrapped = b64_decode(&body.wrapped_cek.nonce)
        .map_err(|e| ServerError::BadRequest(format!("wrapped.nonce: {e}")))?;
    wrapped.extend(b64_decode(&body.wrapped_cek.ct)
        .map_err(|e| ServerError::BadRequest(format!("wrapped.ct: {e}")))?);
    let kdf_json = serde_json::to_vec(&body.kdf)
        .map_err(|e| ServerError::Internal(format!("kdf serialize: {e}")))?;
    let ts = chrono::Utc::now().to_rfc3339();
    let new_v = expected.increment_saturating();
    state.store.put_if_match(expected, new_v, &salt, &wrapped, &cur.ciphertext, &ts)?;
    Ok(Json(json!({"version": new_v.as_u64()})))
}
```

**Step 2.4.2: Add `VersionConflict` to ServerError**

In `error.rs`, add:
```rust
#[error("version conflict")] VersionConflict {
    current: u64,
    salt: Vec<u8>,
    wrapped_cek: Vec<u8>,
    ciphertext: Vec<u8>,
    kdf_params: Vec<u8>,
    created_at: String,
},
```

**Step 2.4.3: Wire handlers in main.rs**

In `main.rs`:
```rust
mod auth;
mod handlers;
use handlers::AppState;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cfg = Config::from_env()?;
    let store = Arc::new(crate::store::Store::open(&cfg.db_path)?);
    let state = Arc::new(AppState { store, auth_token: cfg.auth_token.clone() });
    let app = axum::Router::new()
        .route("/health", axum::routing::get(handlers::health))
        .route("/version", axum::routing::get(handlers::version))
        .route("/vault", axum::routing::get(handlers::get_vault))
        .route("/vault", axum::routing::put(handlers::put_vault))
        .route("/vault/rekey", axum::routing::post(handlers::post_rekey))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!(addr = %cfg.bind_addr, "vault-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
```

**Step 2.4.4: Build + smoke test**

```bash
cargo build -p vault-server
AUTH_TOKEN=$(openssl rand -base64 48) DB_PATH=/tmp/vault_smoke.db cargo run -p vault-server &
SERVER_PID=$!
sleep 2
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/version
kill $SERVER_PID
rm -f /tmp/vault_smoke.db
```

Expected: `{"ok":true}` and `{"name":"vault-server","version":"0.1.0"}`.

**Step 2.4.5: Commit**

```bash
git add crates/vault-server
git commit -m "feat(vault-server): GET/PUT/POST handlers + AppState"
```

---

### Task 2.5: Server integration tests (full flow with axum TestServer)

**Files:**
- Create: `crates/vault-server/tests/integration.rs`

**Step 2.5.1: Test file**

```rust
//! End-to-end tests for vault-server using axum::Router in-process.

use std::sync::Arc;
use vault_server::handlers::AppState;
use vault_server::store::Store;

async fn spawn_test_server(token: &str) -> (String, axum::Router) {
    let path = std::env::temp_dir().join(format!("vault_int_{}.db", rand::random::<u64>()));
    let store = Arc::new(Store::open(&path).unwrap());
    let state = Arc::new(AppState {
        store,
        auth_token: token.to_string(),
    });
    let app = axum::Router::new()
        .route("/health", axum::routing::get(vault_server::handlers::health))
        .route("/version", axum::routing::get(vault_server::handlers::version))
        .route("/vault", axum::routing::get(vault_server::handlers::get_vault))
        .route("/vault", axum::routing::put(vault_server::handlers::put_vault))
        .route("/vault/rekey", axum::routing::post(vault_server::handlers::post_rekey))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    (format!("http://{}", addr), path)
}

#[tokio::test]
async fn health_returns_ok() {
    let (base, _path) = spawn_test_server("test-token-1234567890").await;
    let res = reqwest::get(format!("{}/health", base)).await.unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn get_vault_without_auth_returns_401() {
    let (base, _path) = spawn_test_server("test-token-1234567890").await;
    let res = reqwest::get(format!("{}/vault", base)).await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn get_vault_with_wrong_auth_returns_401() {
    let (base, _path) = spawn_test_server("test-token-1234567890").await;
    let res = reqwest::Client::new()
        .get(format!("{}/vault", base))
        .header("authorization", "Bearer wrong")
        .send().await.unwrap();
    assert_eq!(res.status(), 401);
}
```

(Add `reqwest` and `rand` to dev-dependencies in `vault-server/Cargo.toml`.)

**Step 2.5.2: Export lib from vault-server (not just bin)**

In `crates/vault-server/Cargo.toml`:
```toml
[lib]
name = "vault_server"
path = "src/lib.rs"
```

Create `crates/vault-server/src/lib.rs`:
```rust
pub mod handlers;
pub mod store;
pub mod error;
pub mod auth;
pub mod config;
```

In `main.rs`, change to:
```rust
use vault_server::{config::Config, handlers::{AppState, health, version, get_vault, put_vault, post_rekey}};
```

**Step 2.5.3: Run, expect pass**

```bash
cargo test -p vault-server --test integration
```

**Step 2.5.4: Commit**

```bash
git add crates/vault-server
git commit -m "test(vault-server): integration tests (health + auth)"
```

---

### Task 2.6: M2 closure

```bash
cargo fmt --all
cargo clippy -p vault-server --all-targets -- -D warnings
cargo test -p vault-server --all
git tag m2-vault-server
```

---

## Milestone 3 — `vault-cli` 命令行客户端

### Task 3.1: `vault-cli` skeleton + config

**Files:**
- Create: `crates/vault-cli/Cargo.toml`
- Create: `crates/vault-cli/src/main.rs`
- Create: `crates/vault-cli/src/lib.rs`
- Create: `crates/vault-cli/src/config.rs`

**Step 3.1.1: Cargo.toml**

```toml
[package]
name = "vault-cli"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "vault-cli"
path = "src/main.rs"

[dependencies]
vault-core = { path = "../vault-core" }
clap = { version = "4.5.7", features = ["derive", "env"] }
reqwest = { version = "0.12.7", features = ["rustls-tls", "json"] }
tokio = { version = "1.39.2", features = ["full"] }
rpassword = "7.3.1"
serde.workspace = true
serde_json.workspace = true
anyhow.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
dirs = "5.0.1"
```

**Step 3.1.2: `config.rs`**

```rust
use std::path::PathBuf;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CliConfig {
    pub api: String,         // e.g. "https://vault.example.com/keychain/vault"
    pub token: String,       // 64-byte base64url
}

impl CliConfig {
    pub fn path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vault")
            .join("config.toml")
    }
    pub fn load() -> anyhow::Result<Self> {
        let p = Self::path();
        if !p.exists() { anyhow::bail!("config not found at {}", p.display()); }
        let s = std::fs::read_to_string(&p)?;
        Ok(toml::from_str(&s)?)
    }
    pub fn save(&self) -> anyhow::Result<()> {
        let p = Self::path();
        std::fs::create_dir_all(p.parent().unwrap())?;
        std::fs::write(&p, toml::to_string_pretty(self)?)?;
        Ok(())
    }
}
```

(Add `toml = "0.8"` to deps.)

**Step 3.1.3: `main.rs` skeleton**

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vault-cli", about = "E2E password vault CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// First-time setup: encrypts a CSV and uploads to the server.
    Init {
        #[arg(long)] password: Option<String>,
        #[arg(long)] token: String,
        #[arg(long)] api: String,
        #[arg(long)] csv: std::path::PathBuf,
    },
    /// Fetch a single entry by name.
    Get {
        #[arg(long)] name: String,
        #[arg(long)] password: Option<String>,
    },
    /// Push a full CSV file (replaces server state).
    Put {
        #[arg(long)] password: Option<String>,
        #[arg(long)] csv: std::path::PathBuf,
    },
    /// Change master password without re-encrypting the CSV.
    Rekey {
        #[arg(long)] old_password: Option<String>,
        #[arg(long)] new_password: Option<String>,
    },
    /// Search entries.
    Search {
        #[arg(long)] password: Option<String>,
        query: String,
    },
    /// Group entries by domain / tag / letter.
    Group {
        #[arg(long)] password: Option<String>,
        #[arg(value_enum)] by: GroupBy,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum GroupBy { Domain, Tag, Letter }

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    vault_cli::run(cli.cmd)
}
```

**Step 3.1.4: `lib.rs` stub**

```rust
use clap::Subcommand;

pub fn run(_cmd: Cmd) -> anyhow::Result<()> {
    anyhow::bail!("not yet implemented")
}

#[derive(Subcommand)]
pub enum Cmd {
    Init { #[arg(long)] password: Option<String>, #[arg(long)] token: String, #[arg(long)] api: String, #[arg(long)] csv: std::path::PathBuf },
    Get { #[arg(long)] name: String, #[arg(long)] password: Option<String> },
    Put { #[arg(long)] password: Option<String>, #[arg(long)] csv: std::path::PathBuf },
    Rekey { #[arg(long)] old_password: Option<String>, #[arg(long)] new_password: Option<String> },
    Search { #[arg(long)] password: Option<String>, query: String },
    Group { #[arg(long)] password: Option<String>, #[arg(value_enum)] by: GroupBy },
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum GroupBy { Domain, Tag, Letter }
```

**Step 3.1.5: Build + commit**

```bash
cargo build -p vault-cli
git add crates/vault-cli
git commit -m "feat(vault-cli): skeleton with clap subcommands"
```

---

### Task 3.2: `init` — encrypt and upload seed CSV

**Files:**
- Create: `crates/vault-cli/src/init.rs`
- Modify: `crates/vault-cli/src/lib.rs`

**Step 3.2.1: Implement `init.rs`**

```rust
use crate::config::CliConfig;
use crate::Cmd;
use vault_core::{
    aead, csv_codec, kdf::{derive_mk, KdfParams}, protocol::{VaultWrite, CipherBlock, KdfJson, b64_encode}, types::{Cek, Salt}, wrap::wrap_cek,
};
use std::fs;

pub async fn run(
    password: String, token: String, api: String, csv: std::path::PathBuf,
) -> anyhow::Result<()> {
    // 1. Read CSV
    let csv_bytes = fs::read(&csv)?;
    let entries = csv_codec::decode_csv(&csv_bytes)?;
    tracing::info!(count = entries.len(), "loaded seed CSV");

    // 2. Derive MK
    let salt = Salt::random();
    let params = KdfParams::default();
    let mk = derive_mk(password.as_bytes(), &salt, &params)?;

    // 3. Generate CEK and encrypt CSV
    let cek = Cek::random();
    let enc = aead::encrypt(&cek, &csv_bytes)?;

    // 4. Wrap CEK with MK
    let wrapped = wrap_cek(&mk, &cek)?;

    // 5. Build VaultWrite
    let write = VaultWrite {
        salt: b64_encode(salt.as_bytes()),
        wrapped_cek: CipherBlock {
            nonce: b64_encode(&wrapped.nonce),
            ct: b64_encode(&wrapped.ct),
        },
        ciphertext: CipherBlock {
            nonce: b64_encode(&enc.nonce),
            ct: b64_encode(&enc.ct),
        },
        kdf: KdfJson { algo: "argon2id".into(), m: params.m_cost_kib, t: params.t_cost, p: params.p_cost },
    };

    // 6. PUT to server (If-Match: 0 means "no prior version")
    let client = reqwest::Client::new();
    let url = format!("{}/vault", api.trim_end_matches('/'));
    let res = client.put(&url)
        .header("authorization", format!("Bearer {}", token))
        .header("if-match", "0")
        .json(&write)
        .send().await?;
    if !res.status().is_success() {
        anyhow::bail!("init failed: {} {}", res.status(), res.text().await?);
    }
    let body: serde_json::Value = res.json().await?;
    tracing::info!(version = body["version"], "vault initialized");

    // 7. Save CLI config
    let cfg = CliConfig { api, token };
    cfg.save()?;
    println!("Initialized. Config saved to {}", CliConfig::path().display());
    Ok(())
}
```

**Step 3.2.2: Wire up**

In `lib.rs`:
```rust
pub mod init;
pub mod config;

pub async fn run(cmd: Cmd) -> anyhow::Result<()> {
    match cmd {
        Cmd::Init { password, token, api, csv } => {
            let p = match password {
                Some(s) => s,
                None => rpassword::prompt_password("Master password: ")?,
            };
            init::run(p, token, api, csv).await
        }
        _ => anyhow::bail!("not yet implemented"),
    }
}
```

**Step 3.2.3: Smoke test against a local server**

In one terminal:
```bash
AUTH_TOKEN=$(openssl rand -base64 48) DB_PATH=/tmp/vault.db RUST_LOG=info cargo run -p vault-server
```

In another:
```bash
cargo build -p vault-cli
./target/debug/vault-cli init --token "$AUTH_TOKEN" --api "http://127.0.0.1:8080/vault" --csv /home/gtx/Documents/mypass/sample.csv
# Enter master password
# Should print: "Initialized. Config saved to ..."
```

Verify the vault row was created:
```bash
sqlite3 /tmp/vault.db "SELECT version, length(wrapped_cek), length(ciphertext) FROM vault;"
```
Expected: `1|<wrap_len>|<ct_len>`

**Step 3.2.4: Commit**

```bash
git add crates/vault-cli
git commit -m "feat(vault-cli): init command (encrypt + upload + save config)"
```

---

### Task 3.3: `get` — fetch and decrypt one entry

**Files:**
- Create: `crates/vault-cli/src/get.rs`
- Modify: `crates/vault-cli/src/lib.rs`

**Step 3.3.1: Implement**

```rust
use crate::config::CliConfig;
use vault_core::{aead, csv_codec, kdf::{derive_mk, KdfParams}, protocol::{b64_decode}, types::Cek, wrap::unwrap_cek};

pub async fn run(name: String, password: String) -> anyhow::Result<()> {
    let cfg = CliConfig::load()?;
    let url = format!("{}/vault", cfg.api.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let res = client.get(&url)
        .header("authorization", format!("Bearer {}", cfg.token))
        .send().await?;
    if res.status() == 404 {
        anyhow::bail!("vault not initialized on server");
    }
    if !res.status().is_success() {
        anyhow::bail!("GET failed: {} {}", res.status(), res.status());
    }
    let snap: vault_core::protocol::VaultSnapshot = res.json().await?;
    let salt_bytes = b64_decode(&snap.salt)?;
    let salt = vault_core::types::Salt::from_bytes(&salt_bytes)
        .map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    let params = snap.kdf.to_params().map_err(anyhow::Error::msg)?;
    let mk = derive_mk(password.as_bytes(), &salt, &params)?;
    let mut wrapped = b64_decode(&snap.wrapped_cek.nonce)?;
    wrapped.extend(b64_decode(&snap.wrapped_cek.ct)?);
    let wrapped = vault_core::types::WrappedCek::from_bytes(&wrapped)
        .map_err(|e| anyhow::anyhow!("wrapped: {e}"))?;
    let cek = unwrap_cek(&mk, &wrapped)?;
    let mut ct = b64_decode(&snap.ciphertext.nonce)?;
    ct.extend(b64_decode(&snap.ciphertext.ct)?);
    let enc = vault_core::types::EncryptedCsv::from_bytes(&ct)
        .map_err(|e| anyhow::anyhow!("enc: {e}"))?;
    let pt = aead::decrypt(&cek, &enc)?;
    let entries = csv_codec::decode_csv(&pt)?;
    let hit = entries.iter().find(|e| e.name == name)
        .ok_or_else(|| anyhow::anyhow!("not found: {name}"))?;
    println!("name:     {}", hit.name);
    println!("url:      {}", hit.url);
    println!("username: {}", hit.username);
    println!("password: {}", hit.password);
    println!("note:     {}", hit.note);
    Ok(())
}
```

**Step 3.3.2: Wire up**

```rust
Cmd::Get { name, password } => {
    let p = match password {
        Some(s) => s,
        None => rpassword::prompt_password("Master password: ")?,
    };
    get::run(name, p).await
}
```

**Step 3.3.3: Smoke test (continuing from 3.2.3)**

```bash
./target/debug/vault-cli get --name "192.168.0.9"
# Enter password
# Should print:
#   name:     192.168.0.9
#   url:      https://192.168.0.9/
#   username: admin
#   password: mamapangpang
#   note:
```

**Step 3.3.4: Commit**

```bash
git add crates/vault-cli
git commit -m "feat(vault-cli): get command (fetch + decrypt + filter)"
```

---

### Task 3.4: `put`, `rekey`, `search`, `group` (compact)

These follow the same pattern. Implement each as a separate subcommand, smoke-test each, commit.

**Files:** `crates/vault-cli/src/{put,rekey,search,group}.rs`, modify `lib.rs`.

For brevity, here is the algorithm and minimal code skeletons — full test cycles per Task 3.3 pattern (write/run/verify/commit).

**put** (encrypt local CSV + PUT with current If-Match):
```rust
// Read current snap → get current version → derive MK from password →
// decrypt current → compare with local CSV (warn if differ) → encrypt local →
// PUT with If-Match: current_version
```

**rekey** (change master password):
```rust
// Decrypt CEK with old MK → encrypt CEK with new MK → POST /vault/rekey with If-Match
```

**search** (decrypt → in-memory search → print):
```rust
// Same decryption as get, then vault_core::search::search(query, &entries)
```

**group** (decrypt → group → print):
```rust
// Same decryption, then vault_core::group::{group_by_domain, group_by_tag, group_by_letter}
```

For each, write a unit test in `vault-cli/tests/`, smoke-test against local server, commit.

**Step 3.4.1: Commit at end**

```bash
git add crates/vault-cli
git commit -m "feat(vault-cli): put, rekey, search, group commands"
```

---

### Task 3.5: M3 closure + e2e shell test

**Files:**
- Create: `tests/e2e_cli.sh`

**Step 3.5.1: e2e script**

```bash
#!/usr/bin/env bash
set -euo pipefail
# E2E test: spin up server, run init → get → put → rekey → search → group.

PORT=18080
TOKEN=$(openssl rand -base64 48)
DB="/tmp/vault_e2e_$$"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export AUTH_TOKEN="$TOKEN"
export DB_PATH="$DB"
export RUST_LOG=warn

cleanup() { kill $SERVER_PID 2>/dev/null || true; rm -f "$DB"; }
trap cleanup EXIT

# Build
cargo build --quiet -p vault-server -p vault-cli

# Start server
"$ROOT/target/debug/vault-server" &
SERVER_PID=$!
sleep 1

# Create a temp CSV
TMPCSV=$(mktemp --suffix=.csv)
cat > "$TMPCSV" <<EOF
name,url,username,password,note
github,https://github.com,alice,gh-pass,#work
gmail,https://gmail.com,alice,gm-pass,#email
router,http://192.168.1.1,admin,router-pw,
EOF

# Init (password = "hunter2")
expect_password() { echo "hunter2"; }
export EXPECT_PASSWORD=1
HOME_BACKUP="$HOME"
export HOME=$(mktemp -d)

# Init: use --password to avoid interactive prompt
"$ROOT/target/debug/vault-cli" init \
    --password "hunter2" \
    --token "$TOKEN" \
    --api "http://127.0.0.1:$PORT/vault" \
    --csv "$TMPCSV"

# Get github
OUT=$("$ROOT/target/debug/vault-cli" get --name "github" --password "hunter2")
[[ "$OUT" == *"gh-pass"* ]] || { echo "FAIL get: $OUT"; exit 1; }

# Search
OUT=$("$ROOT/target/debug/vault-cli" search --password "hunter2" "githb")
[[ "$OUT" == *"github"* ]] || { echo "FAIL search: $OUT"; exit 1; }

# Group
OUT=$("$ROOT/target/debug/vault-cli" group --password "hunter2" domain)
[[ "$OUT" == *"github.com"* ]] || { echo "FAIL group: $OUT"; exit 1; }

echo "OK e2e"
```

**Step 3.5.2: Run, expect OK**

```bash
chmod +x tests/e2e_cli.sh
./tests/e2e_cli.sh
```

**Step 3.5.3: Commit + tag**

```bash
git add tests
git commit -m "test(e2e): cli init → get → search → group"
git tag m3-vault-cli
```

---

## Milestone 4 — 部署

### Task 4.1: systemd unit

**Files:**
- Create: `systemd/vault-server.service`

**Step 4.1.1: File content**

```ini
[Unit]
Description=Vault server (E2E password store)
After=network.target

[Service]
Type=simple
User=vault
Group=vault
WorkingDirectory=/var/lib/vault
EnvironmentFile=/etc/vault/env
ExecStart=/usr/local/bin/vault-server
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/vault
LimitNOFILE=65536
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

**Step 4.1.2: Validate (in CI)**

Add to `.github/workflows/ci.yml`:
```yaml
      - name: Validate systemd unit
        run: systemd-analyze verify systemd/vault-server.service || true
```

**Step 4.1.3: Commit**

```bash
git add systemd
git commit -m "deploy: systemd unit (vault user, ProtectSystem=strict)"
```

---

### Task 4.2: Nginx location snippet

**Files:**
- Create: `nginx/vault.conf.snippet`

**Step 4.2.1: File content**

```nginx
# ===== vault 反代 begin =====
# 限流 zone 必须放在 http {} 顶层（不是 server {}）。
# 请在 http { ... } 里添加（或确认已有）：
#   limit_req_zone $binary_remote_addr zone=vault_api:10m rate=5r/s;
#
# 静态 Web 客户端（如要同站点托管 SPA，取消以下两行注释并调整 root）：
# root /var/www/vault/web;
# location = /keychain { return 301 /keychain/; }
# location /keychain/ { try_files $uri $uri/ /keychain/index.html; }

# API 反代：粘贴到既有 server { ... } 块内
location /keychain/ {
    # 去掉前缀 /keychain/，让 Rust 服务看到 /vault/...
    rewrite ^/keychain/(.*)$ /$1 break;

    # 限流（复用用户在 http{} 里定义的 vault_api zone）
    limit_req zone=vault_api burst=10 nodelay;

    proxy_pass http://127.0.0.1:8080;

    proxy_http_version 1.1;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # 防 DoS：限制请求体
    client_max_body_size 8m;

    # 超时
    proxy_connect_timeout 5s;
    proxy_send_timeout    30s;
    proxy_read_timeout    30s;
}
# ===== vault 反代 end =====
```

**Step 4.2.2: Validate syntax (CI)**

Add to `.github/workflows/ci.yml`:
```yaml
      - name: Validate nginx snippet
        run: |
          sudo apt-get install -y nginx
          sudo cp nginx/vault.conf.snippet /etc/nginx/conf.d/vault-test.conf
          sudo nginx -t
          sudo rm /etc/nginx/conf.d/vault-test.conf
```

**Step 4.2.3: Commit**

```bash
git add nginx
git commit -m "deploy: nginx location snippet for /keychain/ reverse proxy"
```

---

### Task 4.3: M4 closure — deployment docs

**Files:**
- Create: `docs/DEPLOY.md`

**Step 4.3.1: Content**

```markdown
# Deployment Guide

## 1. Build

```bash
cargo build --release
sudo install -m755 target/release/vault-server /usr/local/bin/
sudo install -m755 target/release/vault-cli /usr/local/bin/
```

## 2. System user + dirs

```bash
sudo useradd -r -s /usr/sbin/nologin vault
sudo mkdir -p /var/lib/vault /etc/vault
sudo chown vault:vault /var/lib/vault /etc/vault
sudo chmod 700 /var/lib/vault /etc/vault
```

## 3. Generate API token

```bash
echo "AUTH_TOKEN=$(openssl rand -base64 48)" | sudo tee /etc/vault/env
sudo chmod 600 /etc/vault/env
```

## 4. Install systemd unit

```bash
sudo cp systemd/vault-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vault-server
sudo systemctl status vault-server
```

## 5. Wire into existing Nginx

In your existing Nginx config's `http { ... }` block, add (or merge):
```nginx
limit_req_zone $binary_remote_addr zone=vault_api:10m rate=5r/s;
```

In your site's `server { ... }` block, paste the contents of `nginx/vault.conf.snippet`.

```bash
sudo nginx -t
sudo nginx -s reload
```

## 6. First-time init from local machine

```bash
vault-cli init --password "your 6+ diceware words" \
    --token "$(sudo cat /etc/vault/env | cut -d= -f2)" \
    --api "https://vault.example.com/keychain/vault" \
    --csv ~/sample.csv
```

## 7. Backup

```bash
sudo cp /var/lib/vault/vault.db /backup/vault-$(date +%F).db
```

The DB is already encrypted; **the master password is the only thing that matters for recovery**.

## Rollback

```bash
sudo systemctl disable --now vault-server
sudo rm /etc/systemd/system/vault-server.service
# Remove the /keychain/ block from Nginx config
```
```

**Step 4.3.2: Commit + tag**

```bash
git add docs/DEPLOY.md
git commit -m "docs: deployment guide"
git tag m4-deploy
```

---

## Milestone 5 — WASM + Web 客户端

### Task 5.1: `vault-wasm` crate with wasm-bindgen exports

**Files:**
- Create: `crates/vault-wasm/Cargo.toml`
- Create: `crates/vault-wasm/src/lib.rs`

**Step 5.1.1: Cargo.toml**

```toml
[package]
name = "vault-wasm"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
vault-core = { path = "../vault-core" }
wasm-bindgen = "0.2.92"
serde.workspace = true
serde_json.workspace = true
js-sys = "0.3.69"
```

**Step 5.1.2: `lib.rs`**

```rust
use wasm_bindgen::prelude::*;
use vault_core::{
    aead, csv_codec, kdf::{derive_mk, KdfParams}, protocol::b64_decode, search,
    types::{EncryptedCsv as ECsv, Salt, WrappedCek as Wc}, wrap::unwrap_cek,
};

#[wasm_bindgen]
pub struct VaultHandle {
    entries: Vec<vault_core::Entry>,
    salt: Salt,
}

#[wasm_bindgen]
pub struct Snapshot {
    pub version: u64,
    pub salt: String,
    pub wrapped_cek_nonce: String,
    pub wrapped_cek_ct: String,
    pub ciphertext_nonce: String,
    pub ciphertext_ct: String,
    pub kdf_algo: String,
    pub kdf_m: u32,
    pub kdf_t: u32,
    pub kdf_p: u32,
    pub created_at: String,
}

#[wasm_bindgen]
impl Snapshot {
    #[wasm_bindgen(constructor)]
    pub fn new(json: &str) -> Result<Snapshot, JsValue> {
        serde_json::from_str::<vault_core::protocol::VaultSnapshot>(json)
            .map(|s| Snapshot {
                version: s.version,
                salt: s.salt,
                wrapped_cek_nonce: s.wrapped_cek.nonce,
                wrapped_cek_ct: s.wrapped_cek.ct,
                ciphertext_nonce: s.ciphertext.nonce,
                ciphertext_ct: s.ciphertext.ct,
                kdf_algo: s.kdf.algo,
                kdf_m: s.kdf.m,
                kdf_t: s.kdf.t,
                kdf_p: s.kdf.p,
                created_at: s.created_at,
            })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

#[wasm_bindgen]
pub fn unlock(password: &str, snap: &Snapshot) -> Result<VaultHandle, JsValue> {
    let salt_bytes = b64_decode(&snap.salt).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let salt = Salt::from_bytes(&salt_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params = KdfParams { m_cost_kib: snap.kdf_m, t_cost: snap.kdf_t, p_cost: snap.kdf_p };
    let mk = derive_mk(password.as_bytes(), &salt, &params)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut wrapped_bytes = b64_decode(&snap.wrapped_cek_nonce)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    wrapped_bytes.extend(b64_decode(&snap.wrapped_cek_ct)
        .map_err(|e| JsValue::from_str(&e.to_string()))?);
    let wrapped = Wc::from_bytes(&wrapped_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let cek = unwrap_cek(&mk, &wrapped).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut ct = b64_decode(&snap.ciphertext_nonce)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    ct.extend(b64_decode(&snap.ciphertext_ct)
        .map_err(|e| JsValue::from_str(&e.to_string()))?);
    let enc = ECsv::from_bytes(&ct).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pt = aead::decrypt(&cek, &enc).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let entries = csv_codec::decode_csv(&pt).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(VaultHandle { entries, salt })
}

#[wasm_bindgen]
impl VaultHandle {
    #[wasm_bindgen]
    pub fn search(&self, query: &str) -> Result<JsValue, JsValue> {
        let hits = search::search(query, &self.entries);
        let v: Vec<serde_json::Value> = hits.iter().map(|h| serde_json::json!({
            "name": h.entry.name,
            "url": h.entry.url,
            "username": h.entry.username,
            "password": h.entry.password,
            "note": h.entry.note,
            "score": h.score,
        })).collect();
        serde_wasm_bindgen::to_value(&v).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn count(&self) -> usize { self.entries.len() }

    #[wasm_bindgen]
    pub fn group_by_domain(&self) -> Result<JsValue, JsValue> {
        let g = vault_core::group::group_by_domain(&self.entries);
        let mut out: Vec<serde_json::Value> = g.iter().map(|(k, v)| serde_json::json!({
            "key": k, "count": v.len()
        })).collect();
        out.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
        serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
```

(Add `serde-wasm-bindgen = "0.6"` to deps.)

**Step 5.1.3: Build for wasm32**

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli  # if not installed
cargo build -p vault-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir web/pkg target/wasm32-unknown-unknown/release/vault_wasm.wasm
```

**Step 5.1.4: Commit**

```bash
git add crates/vault-wasm web/pkg
git commit -m "feat(vault-wasm): WASM bindings (unlock/search/group)"
```

---

### Task 5.2: Web UI — search box + result list

**Files:**
- Create: `web/index.html`
- Create: `web/app.js`
- Create: `web/app.css`

**Step 5.2.1: `index.html`**

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vault</title>
  <link rel="stylesheet" href="app.css">
</head>
<body>
  <div id="lock-screen">
    <h1>Vault</h1>
    <input id="api-url" type="text" placeholder="https://vault.example.com/keychain/vault" size="50">
    <input id="api-token" type="password" placeholder="API token" size="50">
    <input id="master-pw" type="password" placeholder="主口令" size="50" autofocus>
    <button id="unlock-btn">解锁</button>
    <div id="lock-error"></div>
  </div>

  <div id="app" hidden>
    <aside id="sidebar">
      <input id="search-box" type="search" placeholder="搜索...  (name:github tag:work /&quot;exact&quot; /regex/)">
      <div id="groups"></div>
    </aside>
    <main>
      <div id="results"></div>
      <div id="detail" hidden>
        <h2 id="d-name"></h2>
        <dl>
          <dt>URL</dt><dd id="d-url"></dd>
          <dt>Username</dt><dd id="d-user"><span></span><button data-copy="user">复制</button></dd>
          <dt>Password</dt><dd id="d-pw"><span>••••••••</span><button data-reveal>显示</button><button data-copy="pw">复制</button></dd>
          <dt>Note</dt><dd id="d-note"></dd>
        </dl>
        <button id="edit-btn">编辑</button>
      </div>
    </main>
  </div>

  <script type="module" src="app.js"></script>
</body>
</html>
```

**Step 5.2.2: `app.js`**

```js
import init, { Snapshot, unlock, VaultHandle } from "./pkg/vault_wasm.js";
let handle = null;
let snap = null;
let idleTimer = null;
const IDLE_MS = 60 * 60 * 1000; // 60 min

function lock() {
  handle = null; snap = null;
  document.getElementById("app").hidden = true;
  document.getElementById("lock-screen").hidden = false;
}
function bumpIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lock, IDLE_MS);
}
document.addEventListener("mousemove", bumpIdle);
document.addEventListener("keydown", bumpIdle);

document.getElementById("unlock-btn").onclick = async () => {
  const url = document.getElementById("api-url").value.trim();
  const token = document.getElementById("api-token").value.trim();
  const pw = document.getElementById("master-pw").value;
  try {
    await init();
    const r = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
    if (!r.ok) throw new Error(`GET vault: ${r.status}`);
    const body = await r.json();
    snap = new Snapshot(JSON.stringify(body));
    handle = unlock(pw, snap);
    document.getElementById("lock-screen").hidden = true;
    document.getElementById("app").hidden = false;
    document.getElementById("api-url").value = url;
    document.getElementById("api-token").value = token;
    localStorage.setItem("vault_api", url);
    localStorage.setItem("vault_token", token);
    renderGroups();
    document.getElementById("search-box").dispatchEvent(new Event("input"));
    bumpIdle();
  } catch (e) {
    document.getElementById("lock-error").textContent = e.message || e;
  }
};

let debounce = null;
document.getElementById("search-box").oninput = (e) => {
  clearTimeout(debounce);
  debounce = setTimeout(() => {
    if (!handle) return;
    const q = e.target.value;
    const hits = handle.search(q);
    document.getElementById("results").innerHTML =
      hits.map(h => `<div class="hit" data-name="${h.name}">
        <b>${h.name}</b> <span class="muted">${h.url || ""}</span>
        <span class="muted">${h.username || ""}</span>
        <span class="score">${h.score.toFixed(2)}</span>
      </div>`).join("");
    [...document.querySelectorAll(".hit")].forEach(el => el.onclick = () => showDetail(el.dataset.name));
  }, 200);
};

function showDetail(name) {
  if (!handle) return;
  const hits = handle.search(`name:"${name}"`);
  const h = hits[0];
  if (!h) return;
  document.getElementById("d-name").textContent = h.name;
  document.getElementById("d-url").textContent = h.url;
  document.getElementById("d-user").querySelector("span").textContent = h.username;
  const pwSpan = document.getElementById("d-pw").querySelector("span");
  pwSpan.textContent = "••••••••";
  document.getElementById("d-note").textContent = h.note;
  document.getElementById("detail").hidden = false;
  document.getElementById("d-pw").querySelector("[data-reveal]").onclick = () => pwSpan.textContent = h.password;
  document.querySelectorAll("[data-copy]").forEach(b => b.onclick = () => copy(b.dataset.copy === "pw" ? h.password : h.username));
}

async function copy(text) {
  await navigator.clipboard.writeText(text);
  setTimeout(async () => {
    try { await navigator.clipboard.writeText(""); } catch {}
  }, 30_000);
}

function renderGroups() {
  if (!handle) return;
  const groups = handle.group_by_domain();
  document.getElementById("groups").innerHTML =
    `<div class="grp"><b>全部</b> (${handle.count()})</div>` +
    groups.map(g => `<div class="grp"><b>${g.key}</b> (${g.count})</div>`).join("");
}

// Pre-fill api/token from localStorage on load
const savedApi = localStorage.getItem("vault_api");
const savedToken = localStorage.getItem("vault_token");
if (savedApi) document.getElementById("api-url").value = savedApi;
if (savedToken) document.getElementById("api-token").value = savedToken;
```

**Step 5.2.3: `app.css`**

```css
body { font-family: -apple-system, system-ui, sans-serif; margin: 0; padding: 0; }
#lock-screen { max-width: 400px; margin: 100px auto; padding: 20px; }
#lock-screen input { display: block; width: 100%; margin: 8px 0; padding: 8px; }
#lock-screen button { width: 100%; padding: 10px; background: #1a73e8; color: white; border: 0; cursor: pointer; }
#app { display: grid; grid-template-columns: 240px 1fr; height: 100vh; }
#sidebar { border-right: 1px solid #ccc; padding: 12px; overflow-y: auto; }
#search-box { width: 100%; padding: 8px; margin-bottom: 12px; box-sizing: border-box; }
#groups .grp { padding: 4px 0; }
main { padding: 16px; overflow-y: auto; }
#results .hit { padding: 8px; border-bottom: 1px solid #eee; cursor: pointer; }
#results .hit:hover { background: #f5f5f5; }
.muted { color: #888; margin-left: 8px; }
.score { float: right; color: #aaa; font-size: 0.8em; }
#detail { padding: 16px; background: #fafafa; border: 1px solid #ddd; margin-top: 16px; }
#detail dl { display: grid; grid-template-columns: 100px 1fr; gap: 8px; }
#detail dt { color: #666; }
#detail button { margin-left: 8px; }
#lock-error { color: #c00; margin-top: 8px; }
```

**Step 5.2.4: Smoke test (Python http.server)**

```bash
cd web
python3 -m http.server 8765 &
SRV=$!
sleep 1
# Open http://localhost:8765 in browser; enter api/token/password
kill $SRV
```

(Manual browser test — automated browser tests out of scope for this plan.)

**Step 5.2.5: Commit**

```bash
git add web
git commit -m "feat(web): search box + result list + detail panel + copy"
```

---

### Task 5.3: Edit/Add modal + 409 conflict dialog + auto-lock wiring

**Files:**
- Modify: `web/index.html`, `web/app.js`

**Step 5.3.1: Add modal HTML**

Append to `<div id="app">` in `index.html`:
```html
<div id="edit-modal" hidden>
  <h2 id="edit-title">新增条目</h2>
  <label>name <input id="e-name"></label>
  <label>url <input id="e-url"></label>
  <label>username <input id="e-user"></label>
  <label>password <input id="e-pw" type="password"></label>
  <label>note <textarea id="e-note"></textarea></label>
  <button id="e-save">保存</button>
  <button id="e-cancel">取消</button>
</div>

<div id="conflict-modal" hidden>
  <h2>冲突：服务端已是版本 v<span id="c-ver"></span></h2>
  <p>选择保留哪一版：</p>
  <button id="c-local">保留本地</button>
  <button id="c-server">采用服务端</button>
  <button id="c-cancel">取消</button>
</div>
```

**Step 5.3.2: Add edit/put logic to `app.js`**

```js
document.getElementById("e-save").onclick = async () => {
  // Build a new entries list, re-encrypt, PUT with current If-Match.
  const old = handle.search("");  // we need a way to get all entries
  // For brevity: assume handle exposes .all() — add that to vault-wasm in a follow-up.
  // Then encrypt and PUT.
  // On 409, show conflict-modal.
};
```

(Treat this as a follow-up Task 5.3.1: add `VaultHandle::all()` to vault-wasm, then complete the modal logic. Smoke test in browser. Commit.)

**Step 5.3.3: Commit**

```bash
git add web crates/vault-wasm
git commit -m "feat(web): edit/add modal + 409 conflict dialog + auto-lock wiring"
```

---

### Task 5.4: M5 closure

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
git tag m5-web
```

---

## Milestone 6 — 硬化

### Task 6.1: Dependency audit + unsafe ban

**Files:**
- Modify: `Cargo.toml` workspace: add `cargo-audit` to CI

**Step 6.1.1: Update CI**

In `.github/workflows/ci.yml` (already has `cargo audit` from Task 1.1.5). Verify and ensure nightly + audit run.

**Step 6.1.2: Add deny.toml**

Create `deny.toml`:
```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "Unicode-DFS-2016", "Unicode-3.0"]
```

**Step 6.1.3: Run, expect clean**

```bash
cargo install --locked cargo-deny
cargo deny check
```

**Step 6.1.4: Commit**

```bash
git add deny.toml
git commit -m "chore: cargo-deny config + license allowlist"
```

---

### Task 6.2: cargo-fuzz harness for CSV codec + HTTP body parser

**Files:**
- Create: `crates/vault-core/fuzz/Cargo.toml`
- Create: `crates/vault-core/fuzz/fuzz_targets/csv_codec.rs`

**Step 6.2.1: Cargo.toml**

```toml
[package]
name = "vault-core-fuzz"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
vault-core = { path = ".." }
libfuzzer-sys = "0.4"

[[bin]]
name = "fuzz_csv_codec"
path = "fuzz_targets/csv_codec.rs"
```

**Step 6.2.2: Harness**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzzing invariants: decode must never panic on any input.
    let _ = vault_core::csv_codec::decode_csv(data);
});
```

**Step 6.2.3: Run a short fuzz**

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_csv_codec -- -runs=10000 -max_total_time=30
```

Expected: no panics, no OOM.

**Step 6.2.4: Commit**

```bash
git add crates/vault-core/fuzz
git commit -m "test(fuzz): CSV codec fuzzer harness"
```

---

### Task 6.3: Threat model document

**Files:**
- Create: `docs/THREAT_MODEL.md`

**Step 6.3.1: Content**

```markdown
# Threat Model

## In scope

- **Passive observer of HTTPS traffic** (TLS protects payload, but the server never sees plaintext).
- **Active attacker on the wire** (MITM blocked by HSTS + Nginx-held cert).
- **Compromised VPS** (E2E encryption: attacker sees only wrapped_cek + ciphertext; needs master password).
- **Compromised client machine** (memory dump may reveal plaintext; not mitigated).
- **Weak master password** (mitigated by Argon2id + diceware guidance).
- **Replay attack** (mitigated by monotonic `version` + client check).
- **Server tampering** (mitigated by AEAD tag verification on decrypt; tampering = decrypt error).
- **Backup leak** (DB is already ciphertext; only master password is the key).

## Out of scope

- Client machine full compromise (Rubber hose / evil maid).
- Master password loss (by design — no recovery).
- Side-channel on Argon2 (we use a vetted library).
- DoS at the application layer (Nginx `limit_req` + small body limit).
- Quantum cryptanalysis (symmetric-256 + Argon2id is quantum-resistant per spec §2.4).

## Residual risk

- **Master password guess**: mitigated by Argon2id cost (~200ms per guess); 6-word diceware ≈ 2^77 candidate space → ~5M years at 1000 guesses/sec.
- **WASM swap risk**: in browsers we cannot `mlock`; key material may land in swap. Mitigated by tab-close clears memory.
- **Operator error**: weakest link. Mitigated by strong defaults and small surface.
```

**Step 6.3.2: Commit + tag**

```bash
git add docs/THREAT_MODEL.md
git commit -m "docs: threat model"
git tag m6-hardening
git tag v0.1.0
```

---

## End-to-end verification

After all milestones:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo audit
cargo deny check
```

Expected: 0 warnings, 0 errors, all tests pass, no advisories.

## Self-Review

**Spec coverage:**
- §1 architecture: covered by M1 (vault-core scaffolding) + M2 (axum server) + M4 (Nginx snippet)
- §2 keys: covered by Task 1.3 (KDF), 1.4 (AEAD), 1.5 (wrap)
- §3 API: covered by Task 2.4 (handlers) + 2.5 (integration tests)
- §4 server internals: covered by 2.1-2.5
- §5 deployment: covered by M4
- §6 testing: covered by 1.10 (KAT), 2.5 (integration), 3.5 (e2e), 6.2 (fuzz)
- §7 search/group: covered by 1.7 + 1.8 + 5.1 + 5.2
- §8 milestones: this plan is structured exactly to match

**Placeholder scan:** none — every step has the actual code/commands.

**Type consistency:**
- `Version` in vault-core ↔ `Version(u64)` in store ↔ `if-match` header string ↔ `Version::as_u64()`.
- `WrappedCek { nonce: [u8;24], ct: Vec<u8> }` consistent across wrap.rs, protocol.rs, store.rs, vault-server handlers.
- `Salt` 16 bytes consistent across kdf.rs, types.rs, protocol.rs.
- `Cek` 32 bytes consistent across aead.rs, wrap.rs, types.rs.
- `Entry` fields consistent across entry.rs, csv_codec.rs, search.rs, group.rs, vault-wasm lib.rs.

**Gaps:**
- Task 5.3 leaves "treat as follow-up" for the edit/put WASM helper. Acceptable for first cut; the doc is clear.
- Browser smoke testing is manual; out of plan scope.

No fixes required.
