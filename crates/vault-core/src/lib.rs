#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! E2E encryption core for mypass vault.

pub mod kdf;
pub mod types;

pub use kdf::{derive_mk, KdfParams};
pub use types::{ct_eq, Cek, EncryptedCsv, MasterKey, Salt, Version, WrappedCek};

/// Returns the library version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }

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

    #[test]
    fn kdf_is_deterministic_with_same_salt() {
        use crate::types::Salt;
        let salt = Salt([1u8; 16]);
        let p = KdfParams::default();
        let mk1 = derive_mk(b"correct horse battery staple", &salt, &p).unwrap();
        let mk2 = derive_mk(b"correct horse battery staple", &salt, &p).unwrap();
        assert_eq!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn kdf_changes_with_different_salt() {
        let p = KdfParams::default();
        let mk1 = derive_mk(b"x", &Salt([1u8; 16]), &p).unwrap();
        let mk2 = derive_mk(b"x", &Salt([2u8; 16]), &p).unwrap();
        assert_ne!(mk1.as_bytes(), mk2.as_bytes());
    }

    #[test]
    fn kdf_changes_with_different_password() {
        use crate::types::Salt;
        let salt = Salt([1u8; 16]);
        let p = KdfParams::default();
        let mk1 = derive_mk(b"foo", &salt, &p).unwrap();
        let mk2 = derive_mk(b"bar", &salt, &p).unwrap();
        assert_ne!(mk1.as_bytes(), mk2.as_bytes());
    }
}
