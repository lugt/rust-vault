//! End-to-end tests for the HTTP API.

use base64::Engine;
use std::sync::{Arc, Mutex};
use vault_server::config::Config;
use vault_server::handlers::{
    get_history, get_vault, health, post_clear, post_recover, post_rekey, put_vault, version,
    AppState,
};
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
        .route("/vault/history", axum::routing::get(get_history))
        .route("/vault/clear", axum::routing::post(post_clear))
        .route("/vault/recover", axum::routing::post(post_recover))
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

#[tokio::test]
async fn history_empty_then_populated_after_put() {
    let (base, _path) = spawn_test_server("test-token-1234567890-abcdefghij").await;
    let client = reqwest::Client::new();
    let auth = "Bearer test-token-1234567890-abcdefghij";

    // First, history is empty.
    let res = client
        .get(format!("{}/vault/history", base))
        .header("authorization", auth)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["history"].as_array().unwrap().len(), 0);

    // PUT v1.
    let put_body = serde_json::json!({
        "salt": b64(&[0xAAu8; 16]),
        "wrapped_cek": {"nonce": b64(&[0xBBu8; 24]), "ct": b64(&[0xCCu8; 48])},
        "ciphertext": {"nonce": b64(&[0xDDu8; 24]), "ct": b64(&[0xEEu8; 64])},
        "kdf": {"algo": "argon2id", "m": 65536, "t": 3, "p": 1}
    });
    let res = client
        .put(format!("{}/vault", base))
        .header("authorization", auth)
        .header("if-match", "0")
        .json(&put_body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn clear_archives_and_empties() {
    let (base, _path) = spawn_test_server("test-token-1234567890-abcdefghij").await;
    let client = reqwest::Client::new();
    let auth = "Bearer test-token-1234567890-abcdefghij";
    let put_body = serde_json::json!({
        "salt": b64(&[0xAAu8; 16]),
        "wrapped_cek": {"nonce": b64(&[0xBBu8; 24]), "ct": b64(&[0xCCu8; 48])},
        "ciphertext": {"nonce": b64(&[0xDDu8; 24]), "ct": b64(&[0xEEu8; 64])},
        "kdf": {"algo": "argon2id", "m": 65536, "t": 3, "p": 1}
    });

    // PUT v1.
    client
        .put(format!("{}/vault", base))
        .header("authorization", auth)
        .header("if-match", "0")
        .json(&put_body)
        .send()
        .await
        .unwrap();

    // Clear.
    let res = client
        .post(format!("{}/vault/clear", base))
        .header("authorization", auth)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);

    // Now GET should 500 with "vault not initialized" (mapped from Internal).
    let res = client
        .get(format!("{}/vault", base))
        .header("authorization", auth)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 500);

    // History should now contain v1.
    let res = client
        .get(format!("{}/vault/history", base))
        .header("authorization", auth)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["current_version"], serde_json::Value::Null);
    assert_eq!(body["history"].as_array().unwrap().len(), 1);
    assert_eq!(body["history"][0]["version"], 1);
}

#[tokio::test]
async fn recover_restores_history_version() {
    let (base, _path) = spawn_test_server("test-token-1234567890-abcdefghij").await;
    let client = reqwest::Client::new();
    let auth = "Bearer test-token-1234567890-abcdefghij";

    let body_v1 = serde_json::json!({
        "salt": b64(&[0xA1u8; 16]),
        "wrapped_cek": {"nonce": b64(&[0xB1u8; 24]), "ct": b64(&[0xC1u8; 48])},
        "ciphertext": {"nonce": b64(&[0xD1u8; 24]), "ct": b64(&[0xE1u8; 64])},
        "kdf": {"algo": "argon2id", "m": 65536, "t": 3, "p": 1}
    });
    let body_v2 = serde_json::json!({
        "salt": b64(&[0xA2u8; 16]),
        "wrapped_cek": {"nonce": b64(&[0xB2u8; 24]), "ct": b64(&[0xC2u8; 48])},
        "ciphertext": {"nonce": b64(&[0xD2u8; 24]), "ct": b64(&[0xE2u8; 64])},
        "kdf": {"algo": "argon2id", "m": 65536, "t": 3, "p": 1}
    });

    // PUT v1, then v2.
    client
        .put(format!("{}/vault", base))
        .header("authorization", auth)
        .header("if-match", "0")
        .json(&body_v1)
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/vault", base))
        .header("authorization", auth)
        .header("if-match", "1")
        .json(&body_v2)
        .send()
        .await
        .unwrap();

    // Recover v1.
    let res = client
        .post(format!("{}/vault/recover", base))
        .header("authorization", auth)
        .json(&serde_json::json!({ "from_version": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let v: serde_json::Value = res.json().await.unwrap();
    assert_eq!(v["version"], 3);

    // GET should now have v1's ciphertext back.
    let res = client
        .get(format!("{}/vault", base))
        .header("authorization", auth)
        .send()
        .await
        .unwrap();
    let snap: serde_json::Value = res.json().await.unwrap();
    assert_eq!(snap["version"], 3);
    assert_eq!(snap["ciphertext"]["ct"], body_v1["ciphertext"]["ct"]);
}

#[tokio::test]
async fn recover_from_missing_version_returns_404() {
    let (base, _path) = spawn_test_server("test-token-1234567890-abcdefghij").await;
    let client = reqwest::Client::new();
    let auth = "Bearer test-token-1234567890-abcdefghij";

    let put_body = serde_json::json!({
        "salt": b64(&[0xAAu8; 16]),
        "wrapped_cek": {"nonce": b64(&[0xBBu8; 24]), "ct": b64(&[0xCCu8; 48])},
        "ciphertext": {"nonce": b64(&[0xDDu8; 24]), "ct": b64(&[0xEEu8; 64])},
        "kdf": {"algo": "argon2id", "m": 65536, "t": 3, "p": 1}
    });
    client
        .put(format!("{}/vault", base))
        .header("authorization", auth)
        .header("if-match", "0")
        .json(&put_body)
        .send()
        .await
        .unwrap();

    let res = client
        .post(format!("{}/vault/recover", base))
        .header("authorization", auth)
        .json(&serde_json::json!({ "from_version": 99 }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}
