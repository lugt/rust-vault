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

