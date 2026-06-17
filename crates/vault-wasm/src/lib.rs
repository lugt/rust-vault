//! WASM bindings for the vault core. Exposes `unlock` + `search` + `group`
//! to JavaScript.

use vault_core::{
    aead, csv_codec,
    kdf::{derive_mk, KdfParams},
    protocol::b64_decode,
    types::{EncryptedCsv, Salt, WrappedCek},
    wrap::unwrap_cek,
};
use wasm_bindgen::prelude::*;

/// Holds the decrypted, in-memory list of entries.
#[wasm_bindgen]
pub struct VaultHandle {
    entries: Vec<vault_core::Entry>,
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

    Ok(VaultHandle { entries })
}

#[wasm_bindgen]
impl VaultHandle {
    /// Number of decrypted entries.
    #[wasm_bindgen]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Returns the decrypted entries as a JSON array (name/url/username only).
    #[wasm_bindgen]
    pub fn all(&self) -> Result<JsValue, JsValue> {
        let v: Vec<serde_json::Value> = self
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "name": e.name,
                    "url": e.url,
                    "username": e.username,
                    "password": e.password,
                    "note": e.note,
                })
            })
            .collect();
        serde_wasm_bindgen::to_value(&v).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Search with a query string. Returns hits sorted by score desc.
    #[wasm_bindgen]
    pub fn search(&self, query: &str) -> Result<JsValue, JsValue> {
        let hits = vault_core::search::search(query, &self.entries);
        let v: Vec<serde_json::Value> = hits
            .iter()
            .map(|h| {
                serde_json::json!({
                    "name": h.entry.name,
                    "url": h.entry.url,
                    "username": h.entry.username,
                    "password": h.entry.password,
                    "note": h.entry.note,
                    "score": h.score,
                })
            })
            .collect();
        serde_wasm_bindgen::to_value(&v).map_err(|e| JsValue::from_str(&e.to_string()))
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
}
