//! HTTP handlers for `/vault`, `/health`, `/version`.

use crate::auth::{auth_header, check_bearer};
use crate::error::ServerError;
use crate::store::Store;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Mutex};
use vault_core::protocol::{
    b64_decode, b64_encode, CipherBlock, KdfJson, VaultRekey, VaultSnapshot, VaultWrite,
};
use vault_core::Version;

/// Shared state injected into every handler.
pub struct AppState {
    /// Underlying SQLite store, behind a std::sync::Mutex because rusqlite's
    /// Connection is !Send. Each request takes the lock for the duration of
    /// its short query.
    pub store: Arc<Mutex<Store>>,
    /// Expected API token (must match `Authorization: Bearer <token>`).
    pub auth_token: String,
}

/// `GET /health` — always 200 if the process is alive.
pub async fn health() -> impl IntoResponse {
    Json(json!({ "ok": true }))
}

/// `GET /version` — service identity.
pub async fn version() -> impl IntoResponse {
    Json(json!({
        "name": "vault-server",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// `GET /vault` — return the current snapshot.
pub async fn get_vault(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<VaultSnapshot>, ServerError> {
    if !check_bearer(auth_header(&headers).as_deref(), &state.auth_token) {
        return Err(ServerError::Unauthorized);
    }
    let snap = state
        .store
        .lock()
        .map_err(|e| ServerError::Internal(format!("store lock poisoned: {e}")))?
        .get_snapshot()?
        .ok_or_else(|| ServerError::Internal("vault not initialized".into()))?;
    let kdf_params: serde_json::Value = serde_json::from_slice(&snap.kdf_params)
        .map_err(|e| ServerError::Internal(format!("kdf params parse: {e}")))?;
    let kdf: KdfJson = serde_json::from_value(kdf_params)
        .map_err(|e| ServerError::Internal(format!("kdf struct: {e}")))?;

    let wrapped = split_nonce_ct(&snap.wrapped_cek)
        .ok_or_else(|| ServerError::Internal("wrapped_cek too short".into()))?;
    let ct = split_nonce_ct(&snap.ciphertext)
        .ok_or_else(|| ServerError::Internal("ciphertext too short".into()))?;
    let salt = if snap.salt.len() == 16 {
        snap.salt
    } else {
        return Err(ServerError::Internal("salt length".into()));
    };

    Ok(Json(VaultSnapshot {
        version: snap.version.as_u64(),
        salt: b64_encode(&salt),
        wrapped_cek: CipherBlock {
            nonce: b64_encode(&wrapped.0),
            ct: b64_encode(&wrapped.1),
        },
        ciphertext: CipherBlock {
            nonce: b64_encode(&ct.0),
            ct: b64_encode(&ct.1),
        },
        kdf,
        created_at: snap.created_at,
    }))
}

/// Split a buffer into (24-byte nonce, rest).
fn split_nonce_ct(b: &[u8]) -> Option<([u8; 24], Vec<u8>)> {
    if b.len() < 24 {
        return None;
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&b[..24]);
    Some((nonce, b[24..].to_vec()))
}

/// `PUT /vault` — replace the snapshot, requires matching `If-Match: <v>`.
pub async fn put_vault(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<VaultWrite>,
) -> Result<Json<serde_json::Value>, ServerError> {
    if !check_bearer(auth_header(&headers).as_deref(), &state.auth_token) {
        return Err(ServerError::Unauthorized);
    }
    let if_match = headers
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::BadRequest("missing If-Match header".into()))?;
    let expected = if_match
        .parse::<u64>()
        .map_err(|_| ServerError::BadRequest("invalid If-Match".into()))?;
    let expected = Version(expected);

    let salt = b64_decode(&body.salt).map_err(|e| ServerError::BadRequest(format!("salt: {e}")))?;
    let wrapped = join_nonce_ct(&body.wrapped_cek.nonce, &body.wrapped_cek.ct)
        .map_err(|e| ServerError::BadRequest(format!("wrapped_cek: {e}")))?;
    let ct = join_nonce_ct(&body.ciphertext.nonce, &body.ciphertext.ct)
        .map_err(|e| ServerError::BadRequest(format!("ciphertext: {e}")))?;
    let kdf_params =
        serde_json::to_vec(&body.kdf).map_err(|e| ServerError::Internal(format!("kdf: {e}")))?;
    let ts = chrono::Utc::now().to_rfc3339();
    let new_v = expected.increment_saturating();

    let store = state
        .store
        .lock()
        .map_err(|e| ServerError::Internal(format!("store lock poisoned: {e}")))?;
    // If-Match: 0 with no existing snapshot = first-time put.
    if expected.as_u64() == 0 && store.get_snapshot()?.is_none() {
        store.put_snapshot(new_v, &salt, &wrapped, &ct, &kdf_params, &ts)?;
        return Ok(Json(json!({ "version": new_v.as_u64() })));
    }
    let res = store.put_if_match(expected, new_v, &salt, &wrapped, &ct, &kdf_params, &ts);
    drop(store);
    match res {
        Ok(()) => Ok(Json(json!({ "version": new_v.as_u64() }))),
        Err(ServerError::Store(crate::store::StoreError::VersionConflict { current, .. })) => {
            Err(ServerError::VersionConflict {
                current,
                salt,
                wrapped_cek: wrapped,
                ciphertext: ct,
                kdf_params,
                created_at: ts,
            })
        }
        Err(e) => Err(e),
    }
}

/// `POST /vault/rekey` — re-wrap the CEK under a new master key, without
/// re-encrypting the CSV. The ciphertext blob is preserved.
pub async fn post_rekey(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<VaultRekey>,
) -> Result<Json<serde_json::Value>, ServerError> {
    if !check_bearer(auth_header(&headers).as_deref(), &state.auth_token) {
        return Err(ServerError::Unauthorized);
    }
    let if_match = headers
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::BadRequest("missing If-Match header".into()))?;
    let expected = if_match
        .parse::<u64>()
        .map_err(|_| ServerError::BadRequest("invalid If-Match".into()))?;
    let expected = Version(expected);

    let cur = state
        .store
        .lock()
        .map_err(|e| ServerError::Internal(format!("store lock poisoned: {e}")))?
        .get_snapshot()?
        .ok_or_else(|| ServerError::Internal("vault not initialized".into()))?;

    let salt = b64_decode(&body.salt).map_err(|e| ServerError::BadRequest(format!("salt: {e}")))?;
    let wrapped = join_nonce_ct(&body.wrapped_cek.nonce, &body.wrapped_cek.ct)
        .map_err(|e| ServerError::BadRequest(format!("wrapped_cek: {e}")))?;
    let kdf_params =
        serde_json::to_vec(&body.kdf).map_err(|e| ServerError::Internal(format!("kdf: {e}")))?;
    let ts = chrono::Utc::now().to_rfc3339();
    let new_v = expected.increment_saturating();

    state
        .store
        .lock()
        .map_err(|e| ServerError::Internal(format!("store lock poisoned: {e}")))?
        .put_if_match(
            expected,
            new_v,
            &salt,
            &wrapped,
            &cur.ciphertext,
            &kdf_params,
            &ts,
        )?;
    Ok(Json(json!({ "version": new_v.as_u64() })))
}

/// `GET /vault/history` — list archived versions (metadata only).
pub async fn get_history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ServerError> {
    if !check_bearer(auth_header(&headers).as_deref(), &state.auth_token) {
        return Err(ServerError::Unauthorized);
    }
    let store = state
        .store
        .lock()
        .map_err(|e| ServerError::Internal(format!("store lock poisoned: {e}")))?;
    let current = store.get_snapshot()?.map(|s| s.version.as_u64());
    let history = store.list_history()?;
    drop(store);

    let items: Vec<serde_json::Value> = history
        .into_iter()
        .map(|h| {
            json!({
                "version": h.version.as_u64(),
                "archived_at": h.archived_at,
            })
        })
        .collect();
    Ok(Json(json!({
        "current_version": current,
        "history": items,
    })))
}

/// `POST /vault/clear` — archive current snapshot to history and empty the vault.
pub async fn post_clear(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<axum::http::StatusCode, ServerError> {
    if !check_bearer(auth_header(&headers).as_deref(), &state.auth_token) {
        return Err(ServerError::Unauthorized);
    }
    let ts = chrono::Utc::now().to_rfc3339();
    state
        .store
        .lock()
        .map_err(|e| ServerError::Internal(format!("store lock poisoned: {e}")))?
        .clear_current(&ts)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct RecoverRequest {
    pub from_version: u64,
}

/// `POST /vault/recover` — restore an archived version as the new current.
/// The restored snapshot is still encrypted with the OLD master password.
pub async fn post_recover(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RecoverRequest>,
) -> Result<Json<serde_json::Value>, ServerError> {
    if !check_bearer(auth_header(&headers).as_deref(), &state.auth_token) {
        return Err(ServerError::Unauthorized);
    }
    let from = Version(body.from_version);
    let store = state
        .store
        .lock()
        .map_err(|e| ServerError::Internal(format!("store lock poisoned: {e}")))?;
    // If there's a current snapshot, bump past it; otherwise use from+1.
    let new_v = match store.get_snapshot()? {
        Some(cur) => cur.version.increment_saturating(),
        None => from.increment_saturating(),
    };
    let ts = chrono::Utc::now().to_rfc3339();
    store.restore_from_history(from, new_v, &ts)?;
    Ok(Json(json!({ "version": new_v.as_u64() })))
}

/// Combine a base64url nonce + base64url ct into the wire-format buffer.
fn join_nonce_ct(nonce_b64: &str, ct_b64: &str) -> Result<Vec<u8>, String> {
    let nonce = b64_decode(nonce_b64).map_err(|e| e.to_string())?;
    let ct = b64_decode(ct_b64).map_err(|e| e.to_string())?;
    if nonce.len() != 24 {
        return Err(format!("nonce must be 24 bytes, got {}", nonce.len()));
    }
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}
