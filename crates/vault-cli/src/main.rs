//! `vault-cli` binary entry point.

use clap::Parser;
use vault_cli::cli::{Cli, Cmd, GroupBy};
use vault_cli::ops;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Init {
            password,
            token,
            api,
            csv,
        } => {
            let pw = match password {
                Some(s) => s,
                None => ops::prompt_password("Master password: ")?,
            };
            ops::run_init(pw, token, api, &csv).await
        }
        Cmd::Get { name, password } => {
            let pw = match password {
                Some(s) => s,
                None => ops::prompt_password("Master password: ")?,
            };
            ops::run_get(name, pw).await
        }
        Cmd::Search { password, query } => {
            let pw = match password {
                Some(s) => s,
                None => ops::prompt_password("Master password: ")?,
            };
            ops::run_search(pw, query).await
        }
        Cmd::Put { password, csv } => {
            let pw = match password {
                Some(s) => s,
                None => ops::prompt_password("Master password: ")?,
            };
            ops::run_put(pw, &csv).await
        }
        Cmd::Rekey {
            old_password,
            new_password,
        } => {
            let old = match old_password {
                Some(s) => s,
                None => ops::prompt_password("Old master password: ")?,
            };
            let new = match new_password {
                Some(s) => s,
                None => {
                    let first = ops::prompt_password("New master password: ")?;
                    let second = ops::prompt_password("Confirm new master password: ")?;
                    if first != second {
                        anyhow::bail!("passwords do not match");
                    }
                    first
                }
            };
            ops::run_rekey(old, new).await
        }
        Cmd::Group { password, by } => {
            let pw = match password {
                Some(s) => s,
                None => ops::prompt_password("Master password: ")?,
            };
            let s = match by {
                GroupBy::Domain => "domain",
                GroupBy::Tag => "tag",
                GroupBy::Letter => "letter",
            };
            ops::run_group(pw, s).await
        }
        Cmd::History => ops::run_history().await,
        Cmd::Clear { force } => ops::run_clear(force).await,
        Cmd::Recover { from_version } => ops::run_recover(from_version).await,
    }
}
