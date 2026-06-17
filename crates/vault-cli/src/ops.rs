//! Operation implementations: `init`, `get`, `put`, `rekey`, `search`, `group`.

use crate::config::CliConfig;
use anyhow::{anyhow, Context};
use std::path::Path;
use vault_core::protocol::{
    b64_decode, b64_encode, CipherBlock, KdfJson, VaultRekey, VaultSnapshot, VaultWrite,
};
use vault_core::{
    aead, csv_codec,
    kdf::{derive_mk, KdfParams},
    types::{Cek, Salt, WrappedCek as Wc},
    wrap::{unwrap_cek, wrap_cek},
    Version,
};

/// Prompt for a master password (hidden).
pub fn prompt_password(prompt: &str) -> anyhow::Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}

/// Build a `reqwest::Client` with a generous timeout.
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("client build")
}

/// GET the current snapshot (decoded).
pub async fn fetch_snapshot(api: &str, token: &str) -> anyhow::Result<VaultSnapshot> {
    let res = client()
        .get(api)
        .header("authorization", format!("Bearer {}", token))
        .send()
        .await
        .with_context(|| format!("GET {}", api))?;
    if res.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!("vault not initialized on server");
    }
    if !res.status().is_success() {
        anyhow::bail!("GET failed: {} {}", res.status(), res.text().await?);
    }
    Ok(res.json().await?)
}

/// Decrypt the snapshot, returning the entries and the salt for re-encrypt.
pub fn decrypt_snapshot(
    snap: &VaultSnapshot,
    password: &str,
) -> anyhow::Result<(Vec<vault_core::Entry>, Salt, KdfParams)> {
    let salt_bytes = b64_decode(&snap.salt).context("salt b64")?;
    let salt = Salt::from_bytes(&salt_bytes).map_err(|e| anyhow!("salt: {e}"))?;
    let params = snap.kdf.to_params().map_err(anyhow::Error::msg)?;
    let mk = derive_mk(password.as_bytes(), &salt, &params).context("derive_mk")?;

    let mut wrapped_bytes = b64_decode(&snap.wrapped_cek.nonce).context("wrapped.nonce b64")?;
    wrapped_bytes.extend(b64_decode(&snap.wrapped_cek.ct).context("wrapped.ct b64")?);
    let wrapped = Wc::from_bytes(&wrapped_bytes).map_err(|e| anyhow!("wrapped: {e}"))?;
    let cek = unwrap_cek(&mk, &wrapped).context("unwrap_cek")?;

    let mut ct_bytes = b64_decode(&snap.ciphertext.nonce).context("ciphertext.nonce b64")?;
    ct_bytes.extend(b64_decode(&snap.ciphertext.ct).context("ciphertext.ct b64")?);
    let enc =
        vault_core::types::EncryptedCsv::from_bytes(&ct_bytes).map_err(|e| anyhow!("enc: {e}"))?;
    let pt = aead::decrypt(&cek, &enc).context("aead decrypt")?;
    let entries = csv_codec::decode_csv(&pt).context("decode_csv")?;
    Ok((entries, salt, params))
}

/// Initialize a new vault from a CSV file.
pub async fn run_init(
    password: String,
    token: String,
    api: String,
    csv: &Path,
) -> anyhow::Result<()> {
    let csv_bytes = std::fs::read(csv).with_context(|| format!("read {}", csv.display()))?;
    let _entries = csv_codec::decode_csv(&csv_bytes).context("parse seed CSV")?;
    tracing::info!(file = %csv.display(), bytes = csv_bytes.len(), "loaded seed CSV");

    let salt = Salt::random();
    let params = KdfParams::default();
    let mk = derive_mk(password.as_bytes(), &salt, &params).context("derive_mk")?;

    let cek = Cek::random();
    let enc = aead::encrypt(&cek, &csv_bytes).context("aead encrypt")?;
    let wrapped = wrap_cek(&mk, &cek).context("wrap_cek")?;

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

    let res = client()
        .put(api.trim_end_matches('/'))
        .header("authorization", format!("Bearer {}", token))
        .header("if-match", "0")
        .json(&write)
        .send()
        .await?;
    if !res.status().is_success() {
        anyhow::bail!("PUT failed: {} {}", res.status(), res.text().await?);
    }
    let body: serde_json::Value = res.json().await?;
    tracing::info!(version = %body["version"], "vault initialized");

    let cfg = CliConfig {
        api: api.trim_end_matches('/').to_string(),
        token,
    };
    cfg.save().context("save CLI config")?;
    println!(
        "Initialized. Config saved to {}",
        CliConfig::path().display()
    );
    Ok(())
}

/// Fetch a single entry by name.
pub async fn run_get(name: String, password: String) -> anyhow::Result<()> {
    let cfg = CliConfig::load().context("load CLI config (run `vault-cli init` first)")?;
    let snap = fetch_snapshot(&cfg.api, &cfg.token).await?;
    let (entries, _salt, _params) = decrypt_snapshot(&snap, &password)?;

    let hit = entries
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| anyhow!("not found: {name}"))?;
    println!("name:     {}", hit.name);
    println!("url:      {}", hit.url);
    println!("username: {}", hit.username);
    println!("password: {}", hit.password);
    println!("note:     {}", hit.note);
    Ok(())
}

/// Push a full CSV (encrypted) to the server.
pub async fn run_put(password: String, csv: &Path) -> anyhow::Result<()> {
    let cfg = CliConfig::load()?;
    let snap = fetch_snapshot(&cfg.api, &cfg.token).await?;
    let current_version = snap.version;
    let (entries, _salt, _params) = decrypt_snapshot(&snap, &password)?;
    tracing::info!(count = entries.len(), "current vault size");

    let csv_bytes = std::fs::read(csv).with_context(|| format!("read {}", csv.display()))?;
    let new_entries = csv_codec::decode_csv(&csv_bytes).context("parse CSV")?;
    tracing::info!(file = %csv.display(), new_count = new_entries.len(), "loaded new CSV");

    let salt = Salt::random();
    let params = KdfParams::default();
    let mk = derive_mk(password.as_bytes(), &salt, &params).context("derive_mk")?;
    let cek = Cek::random();
    let enc = aead::encrypt(&cek, &csv_bytes).context("aead encrypt")?;
    let wrapped = wrap_cek(&mk, &cek).context("wrap_cek")?;

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

    let res = client()
        .put(&cfg.api)
        .header("authorization", format!("Bearer {}", cfg.token))
        .header("if-match", current_version.to_string())
        .json(&write)
        .send()
        .await?;
    if res.status() == reqwest::StatusCode::CONFLICT {
        anyhow::bail!(
            "version conflict: server has moved past v{current_version}; re-fetch and retry"
        );
    }
    if !res.status().is_success() {
        anyhow::bail!("PUT failed: {} {}", res.status(), res.text().await?);
    }
    let body: serde_json::Value = res.json().await?;
    println!("Wrote v{} (was v{})", body["version"], current_version);
    Ok(())
}

/// Search entries in-memory after decryption.
pub async fn run_search(password: String, query: String) -> anyhow::Result<()> {
    let cfg = CliConfig::load()?;
    let snap = fetch_snapshot(&cfg.api, &cfg.token).await?;
    let (entries, _salt, _params) = decrypt_snapshot(&snap, &password)?;
    let hits = vault_core::search::search(&query, &entries);
    if hits.is_empty() {
        println!("(no matches)");
    }
    for h in hits {
        println!(
            "{:.3}  {}  {}  {}",
            h.score, h.entry.name, h.entry.url, h.entry.username
        );
    }
    Ok(())
}

/// Group entries by domain, tag, or first letter.
pub async fn run_group(password: String, by: &str) -> anyhow::Result<()> {
    let cfg = CliConfig::load()?;
    let snap = fetch_snapshot(&cfg.api, &cfg.token).await?;
    let (entries, _salt, _params) = decrypt_snapshot(&snap, &password)?;
    let grouped = match by {
        "domain" => vault_core::group::group_by_domain(&entries),
        "tag" => vault_core::group::group_by_tag(&entries),
        "letter" => vault_core::group::group_by_letter(&entries),
        _ => anyhow::bail!("unknown group-by: {by}"),
    };
    for (k, v) in &grouped {
        println!("{}  ({})", k, v.len());
    }
    Ok(())
}

/// Rekey: change the master password without re-encrypting the CSV.
pub async fn run_rekey(old_password: String, new_password: String) -> anyhow::Result<()> {
    let cfg = CliConfig::load()?;
    let snap = fetch_snapshot(&cfg.api, &cfg.token).await?;
    let current_version = snap.version;
    let (_entries, _salt, _params) = decrypt_snapshot(&snap, &old_password)?;

    let new_salt = Salt::random();
    let new_params = KdfParams::default();
    let new_mk =
        derive_mk(new_password.as_bytes(), &new_salt, &new_params).context("derive_mk new")?;

    // We need the CEK to re-wrap. Easiest: do a full decrypt+re-encrypt round-trip
    // off the OLD password into a local var, then wrap with the new password.
    // But we already threw away the CEK after decrypt. So re-fetch the snapshot
    // and re-decrypt.
    let snap = fetch_snapshot(&cfg.api, &cfg.token).await?;
    let (_entries, _salt, old_params) = decrypt_snapshot(&snap, &old_password)?;
    let mut wrapped_bytes = b64_decode(&snap.wrapped_cek.nonce)?;
    wrapped_bytes.extend(b64_decode(&snap.wrapped_cek.ct)?);
    let wrapped = Wc::from_bytes(&wrapped_bytes).map_err(|e| anyhow!("wrapped: {e}"))?;
    let old_mk = derive_mk(old_password.as_bytes(), &_salt, &old_params)?;
    let cek = unwrap_cek(&old_mk, &wrapped)?;
    let _ = Version(current_version); // currently unused after re-wrap
    let new_wrapped = wrap_cek(&new_mk, &cek)?;

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

    let res = client()
        .post(format!("{}/rekey", cfg.api))
        .header("authorization", format!("Bearer {}", cfg.token))
        .header("if-match", current_version.to_string())
        .json(&body)
        .send()
        .await?;
    if res.status() == reqwest::StatusCode::CONFLICT {
        anyhow::bail!("version conflict: server has moved past v{current_version}");
    }
    if !res.status().is_success() {
        anyhow::bail!(
            "POST /vault/rekey failed: {} {}",
            res.status(),
            res.text().await?
        );
    }
    let v: serde_json::Value = res.json().await?;
    println!("Rekeyed to v{}.", v["version"]);
    Ok(())
}
