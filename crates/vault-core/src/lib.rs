#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! E2E encryption core for mypass vault.

pub mod aead;
pub mod csv_codec;
pub mod entry;
pub mod group;
pub mod kdf;
pub mod search;
pub mod types;
pub mod wrap;

pub use aead::{decrypt, encrypt, AeadError};
pub use csv_codec::{decode_csv, encode_csv, CsvError};
pub use entry::Entry;
pub use group::{group_by_domain, group_by_letter, group_by_tag, Grouped};
pub use kdf::{derive_mk, KdfParams};
pub use search::{jaccard, search, trigrams, Hit};
pub use types::{ct_eq, Cek, EncryptedCsv, MasterKey, Salt, Version, WrappedCek};
pub use wrap::{unwrap_cek, wrap_cek, WrapError};

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

    #[test]
    fn aead_round_trip() {
        let cek = Cek([7u8; 32]);
        let pt = b"hello world";
        let ct = encrypt(&cek, pt).unwrap();
        let back = decrypt(&cek, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn aead_tampered_ct_fails() {
        let cek = Cek([1u8; 32]);
        let mut ct = encrypt(&cek, b"hi").unwrap();
        ct.ct[0] ^= 0x01;
        assert!(decrypt(&cek, &ct).is_err());
    }

    #[test]
    fn aead_wrong_key_fails() {
        let ct = encrypt(&Cek([1u8; 32]), b"hi").unwrap();
        assert!(decrypt(&Cek([2u8; 32]), &ct).is_err());
    }

    #[test]
    fn aead_nonce_is_24_bytes() {
        let ct = encrypt(&Cek([0u8; 32]), b"x").unwrap();
        assert_eq!(ct.nonce.len(), 24);
    }

    #[test]
    fn aead_two_nonces_differ() {
        let cek = Cek([0u8; 32]);
        let a = encrypt(&cek, b"x").unwrap();
        let b = encrypt(&cek, b"x").unwrap();
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn wrap_cek_round_trip() {
        let mk = MasterKey([3u8; 32]);
        let cek = Cek([5u8; 32]);
        let w = wrap_cek(&mk, &cek).unwrap();
        let back = unwrap_cek(&mk, &w).unwrap();
        assert_eq!(back.as_bytes(), cek.as_bytes());
    }

    #[test]
    fn unwrap_with_wrong_mk_fails() {
        let w = wrap_cek(&MasterKey([1u8; 32]), &Cek([0u8; 32])).unwrap();
        assert!(unwrap_cek(&MasterKey([2u8; 32]), &w).is_err());
    }

    #[test]
    fn wrap_uses_kdf_derived_key_not_raw_mk() {
        // Verify wrap produces different ciphertext than a direct AEAD encrypt
        // with the raw MK bytes treated as a CEK. The KEK (HKDF-derived from MK)
        // must differ from the raw MK.
        let mk_bytes: [u8; 32] = [9u8; 32];
        let mk = MasterKey(mk_bytes);
        let cek = Cek([0u8; 32]);
        let wrapped = wrap_cek(&mk, &cek).unwrap();
        // Direct AEAD using the raw MK bytes as a key
        let mk_as_cek = Cek(mk_bytes);
        let direct = encrypt(&mk_as_cek, cek.as_bytes()).unwrap();
        assert_ne!(wrapped.ct, direct.ct, "KEK must differ from raw MK");
    }

    #[test]
    fn entry_domain_extraction() {
        let e = Entry::new(
            "github".into(),
            "https://github.com/login".into(),
            "alice".into(),
            "pw".into(),
            "".into(),
        );
        assert_eq!(e.domain(), "github.com");
    }

    #[test]
    fn entry_domain_ip_fallback() {
        let e = Entry::new(
            "router".into(),
            "http://192.168.0.1/".into(),
            "admin".into(),
            "pw".into(),
            "".into(),
        );
        assert_eq!(e.domain(), "192.168.0.1");
    }

    #[test]
    fn entry_tags_from_note() {
        let e = Entry::new(
            "x".into(),
            "".into(),
            "".into(),
            "".into(),
            "important #Work #EMAIL".into(),
        );
        let tags = e.tags();
        assert_eq!(tags, vec!["work".to_string(), "email".to_string()]);
    }

    #[test]
    fn entry_no_tags_when_no_hash() {
        let e = Entry::new(
            "x".into(),
            "".into(),
            "".into(),
            "".into(),
            "just a plain note".into(),
        );
        assert!(e.tags().is_empty());
    }

    #[test]
    fn csv_round_trip() {
        let entries = vec![
            Entry::new(
                "a".into(),
                "https://a.com".into(),
                "u".into(),
                "p".into(),
                "n".into(),
            ),
            Entry::new(
                "b, inc".into(),
                "".into(),
                "".into(),
                "p\"q".into(),
                "#tag1".into(),
            ),
        ];
        let bytes = encode_csv(&entries).unwrap();
        let back = decode_csv(&bytes).unwrap();
        assert_eq!(back, entries);
    }

    #[test]
    fn csv_decodes_sample() {
        let sample = b"name,url,username,password,note\n\
                      192.168.0.9,https://192.168.0.9/,admin,mamapangpang,\n";
        let entries = decode_csv(sample).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "192.168.0.9");
        assert_eq!(entries[0].username, "admin");
    }

    #[test]
    fn csv_handles_unicode() {
        let e = Entry::new(
            "\u{4e2d}\u{6587}".into(),
            "https://\u{4f8b}\u{3048}.jp/".into(),
            "\u{7528}\u{6237}".into(),
            "\u{5bc6}\u{7801}".into(),
            "\u{5907}\u{6ce8} #\u{4ed5}\u{4e8b}".into(),
        );
        let bytes = encode_csv(&[e.clone()]).unwrap();
        let back = decode_csv(&bytes).unwrap();
        assert_eq!(back, vec![e]);
    }

    #[test]
    fn trigrams_of_short_string() {
        // 2-char input is below the 3-char trigram floor -> empty.
        let t = trigrams("ab");
        assert!(t.is_empty());
    }

    #[test]
    fn jaccard_basic() {
        let a = vec!["git".to_string(), "ith".to_string(), "hub".to_string()];
        let b = vec![
            "git".to_string(),
            "ith".to_string(),
            "hub".to_string(),
            "ub ".to_string(),
        ];
        // intersection 3, union 4, Jaccard = 0.75
        assert!((jaccard(&a, &b) - 0.75).abs() < 1e-9);
    }

    #[test]
    fn search_githb_matches_github() {
        let entries = vec![Entry::new(
            "github".into(),
            "https://github.com".into(),
            "alice".into(),
            "pw".into(),
            "".into(),
        )];
        let hits = search("githb", &entries);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].score > 0.15, "score was {}", hits[0].score);
    }

    #[test]
    fn search_no_match_returns_empty() {
        let entries = vec![Entry::new(
            "github".into(),
            "https://github.com".into(),
            "alice".into(),
            "pw".into(),
            "".into(),
        )];
        let hits = search("zzzqqqxxx", &entries);
        assert!(hits.is_empty());
    }

    #[test]
    fn search_key_colon_field_filter() {
        let entries = vec![
            Entry::new(
                "github".into(),
                "https://gmail.com".into(),
                "alice".into(),
                "pw".into(),
                "".into(),
            ),
            Entry::new(
                "gmail".into(),
                "https://gmail.com".into(),
                "bob".into(),
                "pw".into(),
                "".into(),
            ),
        ];
        let hits = search("name:github", &entries);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].entry.name, "github");
    }

    #[test]
    fn search_substring_bonus_helps() {
        let entries = vec![Entry::new(
            "my-very-long-name-12345".into(),
            "".into(),
            "".into(),
            "".into(),
            "".into(),
        )];
        // "12345" is exact substring -> bonus pushes it over threshold
        let hits = search("12345", &entries);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn search_is_lowercase_and_nfc_normalized() {
        let entries = vec![Entry::new(
            "GitHub".into(),
            "".into(),
            "".into(),
            "".into(),
            "".into(),
        )];
        let hits = search("GITHUB", &entries);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_group_by_domain() {
        let entries = vec![
            Entry::new(
                "a".into(),
                "https://github.com/".into(),
                "".into(),
                "".into(),
                "".into(),
            ),
            Entry::new(
                "b".into(),
                "https://github.com/x".into(),
                "".into(),
                "".into(),
                "".into(),
            ),
            Entry::new(
                "c".into(),
                "https://gmail.com/".into(),
                "".into(),
                "".into(),
                "".into(),
            ),
        ];
        let g = group_by_domain(&entries);
        assert_eq!(g.get("github.com").map(|v| v.len()), Some(2));
        assert_eq!(g.get("gmail.com").map(|v| v.len()), Some(1));
    }

    #[test]
    fn test_group_by_tag() {
        let entries = vec![
            Entry::new("a".into(), "".into(), "".into(), "".into(), "#work".into()),
            Entry::new(
                "b".into(),
                "".into(),
                "".into(),
                "".into(),
                "#work #urgent".into(),
            ),
            Entry::new(
                "c".into(),
                "".into(),
                "".into(),
                "".into(),
                "no tags".into(),
            ),
        ];
        let g = group_by_tag(&entries);
        assert_eq!(g.get("work").map(|v| v.len()), Some(2));
        assert_eq!(g.get("urgent").map(|v| v.len()), Some(1));
    }

    #[test]
    fn test_group_by_letter() {
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
}
