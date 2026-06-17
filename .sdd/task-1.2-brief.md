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

