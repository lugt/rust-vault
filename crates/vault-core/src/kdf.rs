//! Argon2id master-key derivation.

use crate::types::{MasterKey, Salt};
use argon2::{Algorithm, Argon2, Params, Version};

/// KDF parameters, fixed per spec §2.1.
///
/// `m_cost_kib` is in **Kibibytes** (65536 = 64 MiB).
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
        Self {
            m_cost_kib: 65_536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Derive a 32-byte master key from a password and salt.
pub fn derive_mk(password: &[u8], salt: &Salt, params: &KdfParams) -> Result<MasterKey, KdfError> {
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e: argon2::Error| KdfError::Params(e.to_string()))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; 32];
    a.hash_password_into(password, salt.as_bytes(), &mut out)
        .map_err(|e: argon2::Error| KdfError::Hash(e.to_string()))?;
    Ok(MasterKey(out))
}

/// Errors from KDF operations.
#[derive(thiserror::Error, Debug)]
pub enum KdfError {
    /// Invalid Argon2 parameters.
    #[error("invalid Argon2 params: {0}")]
    Params(String),
    /// Argon2 hashing itself failed.
    #[error("Argon2 hashing failed: {0}")]
    Hash(String),
}
