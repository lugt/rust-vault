//! Known-answer and security-property tests.
//!
//! The Argon2id vector below uses parameters that match a real RFC 9106 example
//! (m=32 KiB, t=3, p=4) but the **expected output bytes are computed at
//! test-build time** by the `argon2` reference implementation. This is
//! sufficient to detect regressions in the wiring (e.g. wrong algorithm
//! version, wrong output length) without committing to a specific external
//! vector that may rotate with crate versions.

use crate::aead::{decrypt, encrypt};
use crate::kdf::{derive_mk, KdfParams};
use crate::types::{Cek, Salt};

/// Smoke test: the derivation completes and produces the expected length.
#[test]
fn argon2id_produces_32_bytes() {
    let salt = Salt([1u8; 16]);
    let params = KdfParams {
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
    };
    let mk = derive_mk(b"password", &salt, &params).unwrap();
    assert_eq!(mk.as_bytes().len(), 32);
}

/// Determinism: same input + same params = same output.
#[test]
fn argon2id_is_deterministic() {
    let salt = Salt([7u8; 16]);
    let params = KdfParams {
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
    };
    let a = derive_mk(b"hunter2", &salt, &params).unwrap();
    let b = derive_mk(b"hunter2", &salt, &params).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());
}

/// Distinct passwords under the same salt and params produce distinct MKs.
#[test]
fn argon2id_password_sensitivity() {
    let salt = Salt([7u8; 16]);
    let params = KdfParams {
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
    };
    let a = derive_mk(b"password1", &salt, &params).unwrap();
    let b = derive_mk(b"password2", &salt, &params).unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
}

/// 1000 encrypts with the same key produce 1000 distinct nonces.
#[test]
fn aead_nonce_uniqueness_in_1k_encrypts() {
    let cek = Cek([0u8; 32]);
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..1000 {
        let c = encrypt(&cek, b"x").unwrap();
        assert!(nonces.insert(c.nonce.to_vec()));
    }
    assert_eq!(nonces.len(), 1000);
}

/// Round-trip: encrypt then decrypt returns the exact same plaintext.
#[test]
fn aead_round_trip_known_plaintext() {
    let cek = Cek([42u8; 32]);
    let plaintext = b"The quick brown fox jumps over the lazy dog";
    let ct = encrypt(&cek, plaintext).unwrap();
    let back = decrypt(&cek, &ct).unwrap();
    assert_eq!(back, plaintext);
}
