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

/// Decrypt the snapshot, returning the entries, salt, KDF params, and the
/// decrypted CEK (so callers like `add`/`update` can re-encrypt with the
/// same CEK instead of minting a new one).
pub fn decrypt_snapshot(
    snap: &VaultSnapshot,
    password: &str,
) -> anyhow::Result<(Vec<vault_core::Entry>, Salt, KdfParams, Cek)> {
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
    Ok((entries, salt, params, cek))
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
    let (entries, _salt, _params, _cek) = decrypt_snapshot(&snap, &password)?;

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
    let (entries, _salt, _params, _cek) = decrypt_snapshot(&snap, &password)?;
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
    let (entries, _salt, _params, _cek) = decrypt_snapshot(&snap, &password)?;
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
    let (entries, _salt, _params, _cek) = decrypt_snapshot(&snap, &password)?;
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
    let (_entries, _salt, _params, _cek) = decrypt_snapshot(&snap, &old_password)?;

    let new_salt = Salt::random();
    let new_params = KdfParams::default();
    let new_mk =
        derive_mk(new_password.as_bytes(), &new_salt, &new_params).context("derive_mk new")?;

    // We need the CEK to re-wrap. Easiest: do a full decrypt+re-encrypt round-trip
    // off the OLD password into a local var, then wrap with the new password.
    // But we already threw away the CEK after decrypt. So re-fetch the snapshot
    // and re-decrypt.
    let snap = fetch_snapshot(&cfg.api, &cfg.token).await?;
    let (_entries, _salt, old_params, _cek) = decrypt_snapshot(&snap, &old_password)?;
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

/// GET `/vault/history` — print all archived versions + current version.
pub async fn run_history() -> anyhow::Result<()> {
    let cfg = CliConfig::load()?;
    let res = client()
        .get(format!("{}/history", cfg.api))
        .header("authorization", format!("Bearer {}", cfg.token))
        .send()
        .await?;
    if !res.status().is_success() {
        anyhow::bail!("GET history failed: {} {}", res.status(), res.text().await?);
    }
    let body: serde_json::Value = res.json().await?;
    match &body["current_version"] {
        serde_json::Value::Null => println!("current: (empty)"),
        serde_json::Value::Number(n) => println!("current: v{}", n),
        _ => {}
    }
    let arr = body["history"].as_array().cloned().unwrap_or_default();
    if arr.is_empty() {
        println!("history: (none)");
    } else {
        println!("history:");
        for h in arr {
            println!("  v{}  archived_at={}", h["version"], h["archived_at"]);
        }
    }
    Ok(())
}

/// POST `/vault/clear` — archive current + empty vault.
pub async fn run_clear(force: bool) -> anyhow::Result<()> {
    let cfg = CliConfig::load()?;
    if !force {
        eprint!("This will wipe the current vault (kept in history). Continue? [y/N] ");
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        if !s.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }
    let res = client()
        .post(format!("{}/clear", cfg.api))
        .header("authorization", format!("Bearer {}", cfg.token))
        .send()
        .await?;
    if !res.status().is_success() {
        anyhow::bail!("POST clear failed: {} {}", res.status(), res.text().await?);
    }
    println!("Cleared. Current snapshot archived to history.");
    Ok(())
}

/// POST `/vault/recover` — restore an archived version as the new current.
pub async fn run_recover(from_version: u64) -> anyhow::Result<()> {
    let cfg = CliConfig::load()?;
    let res = client()
        .post(format!("{}/recover", cfg.api))
        .header("authorization", format!("Bearer {}", cfg.token))
        .json(&serde_json::json!({ "from_version": from_version }))
        .send()
        .await?;
    if !res.status().is_success() {
        anyhow::bail!(
            "POST recover failed: {} {}",
            res.status(),
            res.text().await?
        );
    }
    let v: serde_json::Value = res.json().await?;
    println!("Recovered as v{}.", v["version"]);
    Ok(())
}

// ---------------------------------------------------------------------------
// list / add / update / delete — single-entry CRUD over the same CAS protocol.
// Master password is NEVER accepted on the command line: it comes from
// `--password-file` (first line of a file) or an interactive hidden prompt.
// ---------------------------------------------------------------------------

/// Read the master password from a file (first line, trailing CR/LF stripped)
/// or, if no file given, an interactive hidden prompt.
pub fn read_master_password(password_file: Option<&Path>) -> anyhow::Result<String> {
    match password_file {
        Some(p) => {
            let s = std::fs::read_to_string(p)
                .with_context(|| format!("read password file {}", p.display()))?;
            Ok(s.trim_end_matches(|c| c == '\r' || c == '\n').to_string())
        }
        None => prompt_password("Master password: "),
    }
}

/// A decrypted vault ready for in-memory editing.
struct Unlocked {
    version: u64,
    entries: Vec<vault_core::Entry>,
    cek: Cek,
}

/// Fetch + decrypt, keeping the CEK so edits can re-encrypt with the same key.
async fn fetch_unlock(api: &str, token: &str, password: &str) -> anyhow::Result<Unlocked> {
    let snap = fetch_snapshot(api, token).await?;
    let (entries, _salt, _params, cek) = decrypt_snapshot(&snap, password)?;
    Ok(Unlocked {
        version: snap.version,
        entries,
        cek,
    })
}

/// Re-encrypt `entries` with the existing CEK and PUT them with If-Match.
/// The CEK is re-wrapped under the same master password with a fresh salt.
/// Returns the new server version.
async fn push_entries(
    api: &str,
    token: &str,
    version: u64,
    cek: &Cek,
    password: &str,
    entries: &[vault_core::Entry],
) -> anyhow::Result<u64> {
    let csv = csv_codec::encode_csv(entries).context("encode_csv")?;
    let enc = aead::encrypt(cek, &csv).context("aead encrypt")?;

    let salt = Salt::random();
    let params = KdfParams::default();
    let mk = derive_mk(password.as_bytes(), &salt, &params).context("derive_mk")?;
    let wrapped = wrap_cek(&mk, cek).context("wrap_cek")?;

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
        .header("if-match", version.to_string())
        .json(&write)
        .send()
        .await?;
    if res.status() == reqwest::StatusCode::CONFLICT {
        anyhow::bail!("version conflict: server moved past v{version}; re-fetch and retry");
    }
    if !res.status().is_success() {
        anyhow::bail!("PUT failed: {} {}", res.status(), res.text().await?);
    }
    let body: serde_json::Value = res.json().await?;
    Ok(body["version"].as_u64().unwrap_or(0))
}

/// Prompt for a text field on stderr with an optional default (shown in
/// brackets; empty input keeps the default). Visible input — do NOT use for
/// passwords.
fn read_field(label: &str, default: &str) -> anyhow::Result<String> {
    use std::io::Write;
    eprint!("{label}");
    if !default.is_empty() {
        eprint!(" [{default}]");
    }
    eprint!(": ");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let s = s.trim_end_matches(|c| c == '\r' || c == '\n').to_string();
    if s.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(s)
    }
}

/// Prompt for a hidden field. If `keep_default` is true, an empty input keeps
/// `default` (used by `update` to leave the entry password unchanged).
fn read_hidden(label: &str, default: &str, keep_default: bool) -> anyhow::Result<String> {
    let hint = if keep_default { " (enter to keep current)" } else { "" };
    let s = prompt_password(&format!("{label}{hint}: "))?;
    if s.is_empty() && keep_default {
        Ok(default.to_string())
    } else {
        Ok(s)
    }
}

/// `vault-cli list` — decrypt and print every entry.
pub async fn run_list(password: String, show_password: bool) -> anyhow::Result<()> {
    let cfg = CliConfig::load().context("load CLI config (run `vault-cli init` first)")?;
    let unlocked = fetch_unlock(&cfg.api, &cfg.token, &password).await?;

    if unlocked.entries.is_empty() {
        println!("(vault is empty)");
        return Ok(());
    }
    println!("{} entries (v{}):", unlocked.entries.len(), unlocked.version);
    println!("{:-<4}  {:-<30}  {:-<30}  {}", "#", "name", "url", "username");
    for (i, e) in unlocked.entries.iter().enumerate() {
        println!(
            "{:>3}  {:<30}  {:<30}  {}",
            i + 1,
            truncate(&e.name, 30),
            truncate(&e.url, 30),
            e.username,
        );
        if show_password {
            println!("      password: {}", e.password);
            if !e.note.is_empty() {
                println!("      note:     {}", e.note);
            }
        }
    }
    if !show_password {
        eprintln!("(use --show-password to reveal passwords/notes)");
    }
    Ok(())
}

/// `vault-cli add` — interactively (or via flags) create one entry, append,
/// and PUT. The entry's own password is always a hidden prompt.
pub async fn run_add(
    password: String,
    name: Option<String>,
    url: Option<String>,
    username: Option<String>,
    note: Option<String>,
) -> anyhow::Result<()> {
    let cfg = CliConfig::load()?;
    let mut unlocked = fetch_unlock(&cfg.api, &cfg.token, &password).await?;

    let name = match name {
        Some(s) => s,
        None => loop {
            let s = read_field("name", "")?;
            if !s.is_empty() {
                break s;
            }
            eprintln!("name is required");
        },
    };
    if unlocked.entries.iter().any(|e| e.name == name) {
        anyhow::bail!("an entry named {name:?} already exists; use `update` instead");
    }
    let url = match url {
        Some(s) => s,
        None => read_field("url", "")?,
    };
    let username = match username {
        Some(s) => s,
        None => read_field("username", "")?,
    };
    let entry_password = read_hidden("password", "", false)?;
    let note = match note {
        Some(s) => s,
        None => read_field("note", "")?,
    };

    unlocked.entries.push(vault_core::Entry {
        name,
        url,
        username,
        password: entry_password,
        note,
    });
    let new_v = push_entries(
        &cfg.api,
        &cfg.token,
        unlocked.version,
        &unlocked.cek,
        &password,
        &unlocked.entries,
    )
    .await?;
    println!("Added. Vault now at v{new_v} ({} entries).", unlocked.entries.len());
    Ok(())
}

/// `vault-cli update --name X` — edit one entry's fields, then PUT. Fields
/// passed on the command line are set directly; others prompt with the old
/// value as the default (empty input keeps it).
pub async fn run_update(
    password: String,
    name: String,
    url: Option<String>,
    username: Option<String>,
    note: Option<String>,
) -> anyhow::Result<()> {
    let cfg = CliConfig::load()?;
    let mut unlocked = fetch_unlock(&cfg.api, &cfg.token, &password).await?;

    let idx = unlocked
        .entries
        .iter()
        .position(|e| e.name == name)
        .ok_or_else(|| anyhow!("not found: {name}"))?;
    let old = unlocked.entries[idx].clone();

    let new_name = read_field("name", &old.name)?;
    if new_name != old.name && unlocked.entries.iter().any(|e| e.name == new_name) {
        anyhow::bail!("an entry named {new_name:?} already exists");
    }
    let new_url = match url {
        Some(s) => s,
        None => read_field("url", &old.url)?,
    };
    let new_username = match username {
        Some(s) => s,
        None => read_field("username", &old.username)?,
    };
    let new_password = read_hidden("password", &old.password, true)?;
    let new_note = match note {
        Some(s) => s,
        None => read_field("note", &old.note)?,
    };

    unlocked.entries[idx] = vault_core::Entry {
        name: new_name,
        url: new_url,
        username: new_username,
        password: new_password,
        note: new_note,
    };
    let new_v = push_entries(
        &cfg.api,
        &cfg.token,
        unlocked.version,
        &unlocked.cek,
        &password,
        &unlocked.entries,
    )
    .await?;
    println!("Updated {name:?}. Vault now at v{new_v}.");
    Ok(())
}

/// `vault-cli delete --name X` — remove one entry and PUT.
pub async fn run_delete(password: String, name: String) -> anyhow::Result<()> {
    let cfg = CliConfig::load()?;
    let mut unlocked = fetch_unlock(&cfg.api, &cfg.token, &password).await?;

    let before = unlocked.entries.len();
    unlocked.entries.retain(|e| e.name != name);
    if unlocked.entries.len() == before {
        anyhow::bail!("not found: {name}");
    }
    let new_v = push_entries(
        &cfg.api,
        &cfg.token,
        unlocked.version,
        &unlocked.cek,
        &password,
        &unlocked.entries,
    )
    .await?;
    println!(
        "Deleted {name:?}. Vault now at v{new_v} ({} entries).",
        unlocked.entries.len()
    );
    Ok(())
}

/// Truncate a string to `max` chars, appending `…` if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}
