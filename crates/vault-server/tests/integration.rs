//! End-to-end tests for the HTTP API.

use base64::Engine;
use std::sync::{Arc, Mutex};
use vault_server::config::Config;
use vault_server::handlers::{get_vault, health, post_rekey, put_vault, version, AppState};
use vault_server::store::Store;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

async fn spawn_test_server(token: &str) -> (String, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!(
        "vault_int_{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
    let state = Arc::new(AppState {
        store,
        auth_token: token.to_string(),
    });
    let app = axum::Router::new()
        .route("/health", axum::routing::get(health))
        .route("/version", axum::routing::get(version))
        .route("/vault", axum::routing::get(get_vault).put(put_vault))
        .route("/vault/rekey", axum::routing::post(post_rekey))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{}", addr), path)
}

#[tokio::test]
async fn health_returns_ok() {
    let (base, _path) = spawn_test_server("test-token-1234567890-abcdefghij").await;
    let res = reqwest::get(format!("{}/health", base)).await.unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn get_vault_without_auth_returns_401() {
    let (base, _path) = spawn_test_server("test-token-1234567890-abcdefghij").await;
    let res = reqwest::get(format!("{}/vault", base)).await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn get_vault_with_wrong_auth_returns_401() {
    let (base, _path) = spawn_test_server("test-token-1234567890-abcdefghij").await;
    let res = reqwest::Client::new()
        .get(format!("{}/vault", base))
        .header("authorization", "Bearer wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn put_then_get_round_trip() {
    let (base, _path) = spawn_test_server("test-token-1234567890-abcdefghij").await;
    let client = reqwest::Client::new();
    let auth = "Bearer test-token-1234567890-abcdefghij";

    // First-time put (If-Match: 0)
    let body = serde_json::json!({
        "salt": b64(&[0xAAu8; 16]),
        "wrapped_cek": {"nonce": b64(&[0xBBu8; 24]), "ct": b64(&[0xCCu8; 48])},
        "ciphertext": {"nonce": b64(&[0xDDu8; 24]), "ct": b64(&[0xEEu8; 64])},
        "kdf": {"algo": "argon2id", "m": 65536, "t": 3, "p": 1}
    });
    let res = client
        .put(format!("{}/vault", base))
        .header("authorization", auth)
        .header("if-match", "0")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "PUT failed: {:?}", res.text().await);

    // Get
    let res = client
        .get(format!("{}/vault", base))
        .header("authorization", auth)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let snap: serde_json::Value = res.json().await.unwrap();
    assert_eq!(snap["version"], 1);
}

#[tokio::test]
async fn put_with_stale_if_match_returns_409() {
    let (base, _path) = spawn_test_server("test-token-1234567890-abcdefghij").await;
    let client = reqwest::Client::new();
    let auth = "Bearer test-token-1234567890-abcdefghij";
    let body = serde_json::json!({
        "salt": b64(&[0xAAu8; 16]),
        "wrapped_cek": {"nonce": b64(&[0xBBu8; 24]), "ct": b64(&[0xCCu8; 48])},
        "ciphertext": {"nonce": b64(&[0xDDu8; 24]), "ct": b64(&[0xEEu8; 64])},
        "kdf": {"algo": "argon2id", "m": 65536, "t": 3, "p": 1}
    });
    // First put: version 0 -> 1
    let res = client
        .put(format!("{}/vault", base))
        .header("authorization", auth)
        .header("if-match", "0")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    // Second put with stale If-Match: 0 -> 409
    let res = client
        .put(format!("{}/vault", base))
        .header("authorization", auth)
        .header("if-match", "0")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 409);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["current_version"], 1);
}

// Suppress unused-import warning for Config (kept for future use in tests).
#[allow(dead_code)]
fn _config_used() -> Config {
    Config {
        bind_addr: "127.0.0.1:0".into(),
        auth_token: "x".into(),
        db_path: std::path::PathBuf::from("/tmp/x"),
    }
}
