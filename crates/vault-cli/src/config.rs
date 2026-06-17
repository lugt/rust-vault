//! CLI configuration persistence.

use std::path::PathBuf;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CliConfig {
    /// API endpoint, e.g. `https://vault.example.com/keychain/vault`.
    pub api: String,
    /// API token (Bearer).
    pub token: String,
}

impl CliConfig {
    /// Path to the config file: `$XDG_CONFIG_HOME/vault/config.toml`.
    pub fn path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vault")
            .join("config.toml")
    }

    /// Load from disk; returns an error if missing.
    pub fn load() -> anyhow::Result<Self> {
        let p = Self::path();
        if !p.exists() {
            anyhow::bail!("config not found at {}", p.display());
        }
        let s = std::fs::read_to_string(&p)?;
        Ok(toml::from_str(&s)?)
    }

    /// Save to disk, creating parent directories.
    pub fn save(&self) -> anyhow::Result<()> {
        let p = Self::path();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&p, toml::to_string_pretty(self)?)?;
        // 0600 — config contains an API token.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&p, perms)?;
        }
        Ok(())
    }
}
