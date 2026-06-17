//! Wrap a CEK with a master key using HKDF-derived KEK + XChaCha20-Poly1305.

use crate::types::{Cek, MasterKey, WrappedCek};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF info string for KEK derivation. Versioned so we can rotate later.
const KEK_INFO: &[u8] = b"vault:wrap:v1";

/// Derive a 32-byte KEK from the master key via HKDF-SHA256.
fn derive_kek(mk: &MasterKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, mk.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(KEK_INFO, &mut okm).expect("32 < 255*Sha256");
    okm
}

/// Wrap a CEK under a master key. Produces a fresh 24-byte nonce.
pub fn wrap_cek(mk: &MasterKey, cek: &Cek) -> Result<WrappedCek, WrapError> {
    let kek = derive_kek(mk);
    let mut nonce = [0u8; 24];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&kek).into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), cek.as_bytes())
        .map_err(|_| WrapError::Wrap)?;
    Ok(WrappedCek { nonce, ct })
}

/// Unwrap a CEK using the master key. Returns an error if the master key is
/// wrong or the wrapped blob was tampered with.
pub fn unwrap_cek(mk: &MasterKey, w: &WrappedCek) -> Result<Cek, WrapError> {
    let kek = derive_kek(mk);
    let cipher = XChaCha20Poly1305::new((&kek).into());
    let plain = cipher
        .decrypt(XNonce::from_slice(&w.nonce), w.ct.as_ref())
        .map_err(|_| WrapError::Unwrap)?;
    if plain.len() != 32 {
        return Err(WrapError::Unwrap);
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&plain);
    Ok(Cek(a))
}

/// Errors from wrap/unwrap operations.
#[derive(thiserror::Error, Debug)]
pub enum WrapError {
    /// CEK wrap failed.
    #[error("CEK wrap failed")]
    Wrap,
    /// CEK unwrap failed (wrong master key or tampered data).
    #[error("CEK unwrap failed (wrong master key or tampered data)")]
    Unwrap,
}
