//! JSON DTOs for the HTTP API. All binary blobs are base64url-encoded.

use base64::Engine;
use serde::{Deserialize, Serialize};

/// A full snapshot of the encrypted vault, returned by `GET /vault`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSnapshot {
    /// Monotonic version number.
    pub version: u64,
    /// Argon2id salt (16 bytes, base64url).
    pub salt: String,
    /// Wrapped CEK (24B nonce + N+16B ciphertext, split into two fields).
    pub wrapped_cek: CipherBlock,
    /// Encrypted CSV (24B nonce + N+16B ciphertext, split into two fields).
    pub ciphertext: CipherBlock,
    /// KDF parameters used to derive the master key.
    pub kdf: KdfJson,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
}

/// Body for `PUT /vault` — replaces the current snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultWrite {
    /// New salt.
    pub salt: String,
    /// New wrapped CEK.
    pub wrapped_cek: CipherBlock,
    /// New ciphertext.
    pub ciphertext: CipherBlock,
    /// KDF parameters.
    pub kdf: KdfJson,
}

/// Body for `POST /vault/rekey` — re-wraps the CEK without changing ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultRekey {
    /// New salt (re-derived from new master password).
    pub salt: String,
    /// New wrapped CEK (under new master key).
    pub wrapped_cek: CipherBlock,
    /// New KDF parameters.
    pub kdf: KdfJson,
}

/// A nonce + ciphertext block, base64url-encoded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CipherBlock {
    /// 24-byte nonce, base64url.
    pub nonce: String,
    /// Variable-length ciphertext (including AEAD tag), base64url.
    pub ct: String,
}

/// KDF parameters, sent over the wire.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfJson {
    /// Algorithm name. Always `"argon2id"` in this version.
    pub algo: String,
    /// Memory cost in KiB (matches `KdfParams::m_cost_kib`).
    pub m: u32,
    /// Time cost (iterations).
    pub t: u32,
    /// Parallelism lanes.
    pub p: u32,
}

impl KdfJson {
    /// Convert to the in-process `KdfParams`. Returns an error if the algorithm
    /// is unsupported.
    pub fn to_params(&self) -> Result<crate::kdf::KdfParams, String> {
        if self.algo != "argon2id" {
            return Err(format!("unsupported KDF: {}", self.algo));
        }
        Ok(crate::kdf::KdfParams {
            m_cost_kib: self.m,
            t_cost: self.t,
            p_cost: self.p,
        })
    }
}

/// Base64url-no-pad encode a byte slice.
pub fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Base64url-no-pad decode a string.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}
