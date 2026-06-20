//! WASM bindings for the vault core. Exposes `unlock` + `search` + `group`
//! + `put_entries` + `rekey` to JavaScript.

use vault_core::{
    aead, csv_codec,
    kdf::{derive_mk, KdfParams},
    protocol::{b64_decode, b64_encode, CipherBlock, KdfJson, VaultRekey, VaultWrite},
    types::{Cek, EncryptedCsv, Salt, WrappedCek},
    wrap::{unwrap_cek, wrap_cek},
};
use wasm_bindgen::prelude::*;

/// Holds the decrypted, in-memory list of entries.
#[wasm_bindgen]
pub struct VaultHandle {
    entries: Vec<vault_core::Entry>,
    /// Kept around so the JS side can call `put_entries` without re-deriving.
    pub(crate) current_password: String,
    /// Decrypted CEK so rekey + put don't have to re-decrypt the snapshot.
    pub(crate) current_cek: Option<Cek>,
}

impl VaultHandle {
    fn cek(&self) -> Result<&Cek, String> {
        self.current_cek
            .as_ref()
            .ok_or_else(|| "vault not unlocked yet".to_string())
    }
}

/// Decrypts a snapshot and returns a handle to the in-memory vault.
#[wasm_bindgen]
pub fn unlock(password: &str, snapshot_json: &str) -> Result<VaultHandle, JsValue> {
    let snap: vault_core::protocol::VaultSnapshot = serde_json::from_str(snapshot_json)
        .map_err(|e| JsValue::from_str(&format!("parse: {e}")))?;

    let salt_bytes =
        b64_decode(&snap.salt).map_err(|e| JsValue::from_str(&format!("salt: {e}")))?;
    let salt =
        Salt::from_bytes(&salt_bytes).map_err(|e| JsValue::from_str(&format!("salt: {e}")))?;
    let params = KdfParams {
        m_cost_kib: snap.kdf.m,
        t_cost: snap.kdf.t,
        p_cost: snap.kdf.p,
    };
    let mk = derive_mk(password.as_bytes(), &salt, &params)
        .map_err(|e| JsValue::from_str(&format!("kdf: {e}")))?;

    let mut wrapped_bytes = b64_decode(&snap.wrapped_cek.nonce)
        .map_err(|e| JsValue::from_str(&format!("w.nonce: {e}")))?;
    wrapped_bytes.extend(
        b64_decode(&snap.wrapped_cek.ct).map_err(|e| JsValue::from_str(&format!("w.ct: {e}")))?,
    );
    let wrapped = WrappedCek::from_bytes(&wrapped_bytes)
        .map_err(|e| JsValue::from_str(&format!("wrapped: {e}")))?;
    let cek = unwrap_cek(&mk, &wrapped).map_err(|e| JsValue::from_str(&format!("unwrap: {e}")))?;

    let mut ct_bytes = b64_decode(&snap.ciphertext.nonce)
        .map_err(|e| JsValue::from_str(&format!("c.nonce: {e}")))?;
    ct_bytes.extend(
        b64_decode(&snap.ciphertext.ct).map_err(|e| JsValue::from_str(&format!("c.ct: {e}")))?,
    );
    let enc =
        EncryptedCsv::from_bytes(&ct_bytes).map_err(|e| JsValue::from_str(&format!("enc: {e}")))?;
    let pt = aead::decrypt(&cek, &enc).map_err(|e| JsValue::from_str(&format!("decrypt: {e}")))?;
    let entries =
        csv_codec::decode_csv(&pt).map_err(|e| JsValue::from_str(&format!("csv: {e}")))?;

    Ok(VaultHandle {
        entries,
        current_password: password.to_string(),
        current_cek: Some(cek),
    })
}

#[wasm_bindgen]
impl VaultHandle {
    /// Number of decrypted entries.
    #[wasm_bindgen]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the decrypted entries as a JSON string.
    #[wasm_bindgen]
    pub fn all(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.entries).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Replace the in-memory entry list with the given JSON array, returning
    /// the new (in-memory) count. Does NOT encrypt or send to the server.
    /// Call `put_entries` to persist.
    #[wasm_bindgen]
    pub fn set_entries(&mut self, json: JsValue) -> Result<usize, JsValue> {
        let arr: Vec<serde_json::Value> = serde_wasm_bindgen::from_value(json)
            .map_err(|e| JsValue::from_str(&format!("parse: {e}")))?;
        let mut new_entries = Vec::with_capacity(arr.len());
        for v in arr {
            new_entries.push(json_to_entry(&v)?);
        }
        self.entries = new_entries;
        Ok(self.entries.len())
    }

    /// Search with a query string. Returns hits (with score field) as a JSON string.
    /// Empty query returns ALL entries with score 1.0.
    #[wasm_bindgen]
    pub fn search(&self, query: &str) -> Result<String, JsValue> {
        if query.trim().is_empty() {
            let v: Vec<serde_json::Value> = self
                .entries
                .iter()
                .map(|e| {
                    let mut j = serde_json::to_value(e)
                        .unwrap_or_else(|_| serde_json::Value::Object(Default::default()));
                    j.as_object_mut()
                        .unwrap()
                        .insert("score".into(), serde_json::json!(1.0_f32));
                    j
                })
                .collect();
            return serde_json::to_string(&v).map_err(|e| JsValue::from_str(&e.to_string()));
        }
        let hits = vault_core::search::search(query, &self.entries);
        let v: Vec<serde_json::Value> = hits
            .iter()
            .map(|h| {
                let mut j = serde_json::to_value(h.entry)
                    .unwrap_or_else(|_| serde_json::Value::Object(Default::default()));
                j.as_object_mut()
                    .unwrap()
                    .insert("score".into(), serde_json::json!(h.score));
                j
            })
            .collect();
        serde_json::to_string(&v).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Group by domain. Returns `[{key, count}, ...]` sorted by count desc.
    #[wasm_bindgen]
    pub fn group_by_domain(&self) -> Result<JsValue, JsValue> {
        let g = vault_core::group::group_by_domain(&self.entries);
        let mut v: Vec<serde_json::Value> = g
            .iter()
            .map(|(k, vs)| serde_json::json!({ "key": k, "count": vs.len() }))
            .collect();
        v.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
        serde_wasm_bindgen::to_value(&v).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Group by tag. Returns `[{key, count}, ...]`.
    #[wasm_bindgen]
    pub fn group_by_tag(&self) -> Result<JsValue, JsValue> {
        let g = vault_core::group::group_by_tag(&self.entries);
        let mut v: Vec<serde_json::Value> = g
            .iter()
            .map(|(k, vs)| serde_json::json!({ "key": k, "count": vs.len() }))
            .collect();
        v.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
        serde_wasm_bindgen::to_value(&v).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Group by first letter of name.
    #[wasm_bindgen]
    pub fn group_by_letter(&self) -> Result<JsValue, JsValue> {
        let g = vault_core::group::group_by_letter(&self.entries);
        let v: Vec<serde_json::Value> = g
            .iter()
            .map(|(k, vs)| serde_json::json!({ "key": k, "count": vs.len() }))
            .collect();
        serde_wasm_bindgen::to_value(&v).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Encrypt the current in-memory entries to a `VaultWrite` JSON. The
    /// caller (JS) then PUTs this to `/vault` with the matching `If-Match`.
    #[wasm_bindgen]
    pub fn put_entries(&self) -> Result<String, JsValue> {
        let csv = csv_codec::encode_csv(&self.entries)
            .map_err(|e| JsValue::from_str(&format!("encode: {e}")))?;
        let cek = self.cek().map_err(|e| JsValue::from_str(&e))?;
        let enc =
            aead::encrypt(cek, &csv).map_err(|e| JsValue::from_str(&format!("encrypt: {e}")))?;

        let salt = Salt::random();
        let params = KdfParams::default();
        let mk = derive_mk(self.current_password.as_bytes(), &salt, &params)
            .map_err(|e| JsValue::from_str(&format!("kdf: {e}")))?;
        let wrapped = wrap_cek(&mk, &cek).map_err(|e| JsValue::from_str(&format!("wrap: {e}")))?;

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
            kdf: KdfJson {
                algo: "argon2id".into(),
                m: params.m_cost_kib,
                t: params.t_cost,
                p: params.p_cost,
            },
        };
        serde_json::to_string(&write).map_err(|e| JsValue::from_str(&format!("serialize: {e}")))
    }

    /// Re-wrap the CEK under a new master password. Returns a `VaultRekey`
    /// JSON. The caller (JS) then POSTs to `/vault/rekey`. The new password
    /// becomes the active password for subsequent puts.
    #[wasm_bindgen]
    pub fn rekey(&mut self, new_password: &str) -> Result<String, JsValue> {
        let cek = self.cek().map_err(|e| JsValue::from_str(&e))?;
        let new_salt = Salt::random();
        let new_params = KdfParams::default();
        let new_mk = derive_mk(new_password.as_bytes(), &new_salt, &new_params)
            .map_err(|e| JsValue::from_str(&format!("kdf: {e}")))?;
        let new_wrapped =
            wrap_cek(&new_mk, cek).map_err(|e| JsValue::from_str(&format!("wrap: {e}")))?;

        let body = VaultRekey {
            salt: b64_encode(new_salt.as_bytes()),
            wrapped_cek: CipherBlock {
                nonce: b64_encode(&new_wrapped.nonce),
                ct: b64_encode(&new_wrapped.ct),
            },
            kdf: KdfJson {
                algo: "argon2id".into(),
                m: new_params.m_cost_kib,
                t: new_params.t_cost,
                p: new_params.p_cost,
            },
        };
        self.current_password = new_password.to_string();
        serde_json::to_string(&body).map_err(|e| JsValue::from_str(&format!("serialize: {e}")))
    }
}

fn json_to_entry(v: &serde_json::Value) -> Result<vault_core::Entry, JsValue> {
    Ok(vault_core::Entry {
        name: v["name"].as_str().unwrap_or("").to_string(),
        url: v["url"].as_str().unwrap_or("").to_string(),
        username: v["username"].as_str().unwrap_or("").to_string(),
        password: v["password"].as_str().unwrap_or("").to_string(),
        note: v["note"].as_str().unwrap_or("").to_string(),
    })
}
