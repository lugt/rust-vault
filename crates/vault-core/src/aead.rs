//! XChaCha20-Poly1305 authenticated encryption.

use crate::types::{Cek, EncryptedCsv};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

/// Encrypt `plaintext` under `cek`, producing a fresh 24-byte nonce.
pub fn encrypt(cek: &Cek, plaintext: &[u8]) -> Result<EncryptedCsv, AeadError> {
    let cipher = XChaCha20Poly1305::new(cek.as_bytes().into());
    let mut nonce = [0u8; 24];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| AeadError::Encrypt)?;
    Ok(EncryptedCsv { nonce, ct })
}

/// Decrypt and verify the AEAD tag. Returns an error if the ciphertext was
/// tampered with, the wrong key was used, or the nonce is wrong.
pub fn decrypt(cek: &Cek, enc: &EncryptedCsv) -> Result<Vec<u8>, AeadError> {
    let cipher = XChaCha20Poly1305::new(cek.as_bytes().into());
    cipher
        .decrypt(XNonce::from_slice(&enc.nonce), enc.ct.as_ref())
        .map_err(|_| AeadError::Decrypt)
}

/// Errors from AEAD operations.
#[derive(thiserror::Error, Debug)]
pub enum AeadError {
    /// AEAD encryption failed.
    #[error("AEAD encryption failed")]
    Encrypt,
    /// AEAD decryption failed (wrong key, tampered data, or wrong nonce).
    #[error("AEAD decryption failed (wrong key, tampered data, or wrong nonce)")]
    Decrypt,
}
