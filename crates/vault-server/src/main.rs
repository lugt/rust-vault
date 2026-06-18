//! `vault-server` binary entry point.

use axum::routing::{get, post};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use vault_server::config::Config;
use vault_server::handlers::{
    get_history, get_vault, health, post_clear, post_recover, post_rekey, put_vault, version,
    AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cfg = Config::from_env()?;
    let store = Arc::new(std::sync::Mutex::new(vault_server::store::Store::open(
        &cfg.db_path,
    )?));
    let state = Arc::new(AppState {
        store,
        auth_token: cfg.auth_token.clone(),
    });
    // Permissive CORS: the API is bearer-protected, so an open CORS policy
    // does not weaken security. It just lets the web UI talk to the API
    // even when served from a different origin (e.g. local file://).
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    let app = axum::Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/vault", get(get_vault).put(put_vault))
        .route("/vault/rekey", post(post_rekey))
        .route("/vault/history", get(get_history))
        .route("/vault/clear", post(post_clear))
        .route("/vault/recover", post(post_recover))
        .layer(cors)
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!(addr = %cfg.bind_addr, "vault-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
