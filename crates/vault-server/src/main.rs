//! `vault-server` binary entry point.

use axum::routing::{get, post};
use std::sync::Arc;
use vault_server::config::Config;
use vault_server::handlers::{get_vault, health, post_rekey, put_vault, version, AppState};

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
    let app = axum::Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/vault", get(get_vault).put(put_vault))
        .route("/vault/rekey", post(post_rekey))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    tracing::info!(addr = %cfg.bind_addr, "vault-server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
