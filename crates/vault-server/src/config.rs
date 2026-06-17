//! Server configuration loaded from environment variables.

use std::path::PathBuf;

/// Server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Bind address. Always `127.0.0.1:8080` (hard-coded; env cannot override).
    pub bind_addr: String,
    /// API token for Bearer auth. Required.
    pub auth_token: String,
    /// Path to the SQLite database file.
    pub db_path: PathBuf,
}

impl Config {
    /// Load configuration from the environment.
    pub fn from_env() -> anyhow::Result<Self> {
        let auth_token =
            std::env::var("AUTH_TOKEN").map_err(|_| anyhow::anyhow!("AUTH_TOKEN must be set"))?;
        if auth_token.len() < 32 {
            anyhow::bail!("AUTH_TOKEN must be at least 32 chars");
        }
        let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "/var/lib/vault/vault.db".into());
        Ok(Self {
            // Hard-coded: refuse to bind to anything other than loopback.
            bind_addr: "127.0.0.1:8080".into(),
            auth_token,
            db_path: db_path.into(),
        })
    }
}
