//! Server error type. Each variant maps to an HTTP status code.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use vault_core::protocol::{b64_encode, CipherBlock};

#[derive(thiserror::Error, Debug)]
pub enum ServerError {
    /// Underlying SQLite error.
    #[error("rusqlite: {0}")]
    Rusqlite(#[from] rusqlite::Error),

    /// Store-level error (e.g. version conflict, not found).
    #[error("store: {0}")]
    Store(#[from] StoreError),

    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Environment variable missing or invalid.
    #[error("env: {0}")]
    Env(#[from] std::env::VarError),

    /// Body too large.
    #[error("body too large")]
    BodyTooLarge,

    /// Unauthorized (missing or wrong Bearer token).
    #[error("unauthorized")]
    Unauthorized,

    /// Bad request (malformed body, missing header, etc.).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Internal error. The cause is logged; only a generic message is returned.
    #[error("internal: {0}")]
    Internal(String),

    /// Version conflict (CAS failure). Carries the current server state so
    /// the client can decide how to merge.
    #[error("version conflict")]
    VersionConflict(Box<VersionConflictData>),
}

/// Payload for the `VersionConflict` error variant. Boxed to keep
/// `ServerError` small on the stack.
#[derive(Debug)]
pub struct VersionConflictData {
    pub current: u64,
    pub salt: Vec<u8>,
    pub wrapped_cek: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub kdf_params: Vec<u8>,
    pub created_at: String,
}

use crate::store::StoreError;

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        match self {
            ServerError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized" })),
            )
                .into_response(),
            ServerError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
            }
            ServerError::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({ "error": "body too large" })),
            )
                .into_response(),
            ServerError::VersionConflict(data) => {
                let VersionConflictData {
                    current,
                    salt,
                    wrapped_cek,
                    ciphertext,
                    kdf_params,
                    created_at,
                } = *data;
                let (nonce_w, ct_w) = match split_nonce(&wrapped_cek) {
                    Some(p) => p,
                    None => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": "wrapped_cek corrupt" })),
                        )
                            .into_response();
                    }
                };
                let (nonce_c, ct_c) = match split_nonce(&ciphertext) {
                    Some(p) => p,
                    None => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": "ciphertext corrupt" })),
                        )
                            .into_response();
                    }
                };
                let kdf: serde_json::Value =
                    serde_json::from_slice(&kdf_params).unwrap_or(json!({}));
                let body = json!({
                    "error": "version conflict",
                    "current_version": current,
                    "current_salt": b64_encode(&salt),
                    "current_wrapped_cek": CipherBlock {
                        nonce: b64_encode(&nonce_w),
                        ct: b64_encode(&ct_w),
                    },
                    "current_ciphertext": CipherBlock {
                        nonce: b64_encode(&nonce_c),
                        ct: b64_encode(&ct_c),
                    },
                    "current_kdf": kdf,
                    "current_created_at": created_at,
                });
                (StatusCode::CONFLICT, Json(body)).into_response()
            }
            ServerError::Store(StoreError::NotFound) => {
                (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response()
            }
            // Internal errors: log details, return generic 500.
            other => {
                tracing::error!(error = %other, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "internal server error" })),
                )
                    .into_response()
            }
        }
    }
}

fn split_nonce(b: &[u8]) -> Option<([u8; 24], Vec<u8>)> {
    if b.len() < 24 {
        return None;
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&b[..24]);
    Some((nonce, b[24..].to_vec()))
}
