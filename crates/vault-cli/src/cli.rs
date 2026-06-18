//! CLI command definitions.

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "vault-cli", about = "E2E password vault CLI", version)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// First-time setup: encrypt a CSV and upload to the server.
    Init {
        /// Master password (omit to be prompted).
        #[arg(long)]
        password: Option<String>,
        /// API token.
        #[arg(long)]
        token: String,
        /// API endpoint, e.g. `https://vault.example.com/keychain/vault`.
        #[arg(long)]
        api: String,
        /// Path to the seed CSV file.
        #[arg(long)]
        csv: std::path::PathBuf,
    },
    /// Fetch a single entry by name.
    Get {
        /// Entry name to look up.
        #[arg(long)]
        name: String,
        /// Master password (omit to be prompted).
        #[arg(long)]
        password: Option<String>,
    },
    /// Search entries.
    Search {
        /// Master password (omit to be prompted).
        #[arg(long)]
        password: Option<String>,
        /// Query string.
        query: String,
    },
    /// Push a full CSV file (replaces server state).
    Put {
        /// Master password (omit to be prompted).
        #[arg(long)]
        password: Option<String>,
        /// Path to the CSV file.
        #[arg(long)]
        csv: std::path::PathBuf,
    },
    /// Rekey: change the master password without re-encrypting the CSV.
    Rekey {
        /// Old master password.
        #[arg(long)]
        old_password: Option<String>,
        /// New master password.
        #[arg(long)]
        new_password: Option<String>,
    },
    /// Group entries by domain, tag, or first letter.
    Group {
        /// Master password (omit to be prompted).
        #[arg(long)]
        password: Option<String>,
        /// Grouping axis.
        #[arg(value_enum)]
        by: GroupBy,
    },
    /// List archived versions on the server.
    History,
    /// Wipe the current vault; the current snapshot is archived to history.
    /// The next `init` will re-create the vault. (Destructive.)
    Clear {
        /// Skip the confirmation prompt.
        #[arg(long)]
        force: bool,
    },
    /// Restore an archived version as the new current. The restored snapshot
    /// is still encrypted with the OLD master password.
    Recover {
        /// Version number from history to restore.
        #[arg(long)]
        from_version: u64,
    },
}

/// Axis for the `group` command.
#[derive(ValueEnum, Clone, Debug)]
pub enum GroupBy {
    Domain,
    Tag,
    Letter,
}
