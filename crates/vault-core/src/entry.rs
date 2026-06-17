//! In-memory entry representation and derived fields.

use serde::{Deserialize, Serialize};

/// A single vault entry (one row of the CSV).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Display name, e.g. "github".
    pub name: String,
    /// URL the entry is for.
    pub url: String,
    /// Login username.
    pub username: String,
    /// Login password.
    pub password: String,
    /// Free-form note. May contain `#tag` tokens for filtering.
    pub note: String,
}

impl Entry {
    /// Construct a new entry.
    pub fn new(
        name: String,
        url: String,
        username: String,
        password: String,
        note: String,
    ) -> Self {
        Self {
            name,
            url,
            username,
            password,
            note,
        }
    }

    /// Extract the host portion of the URL, falling back to the URL itself
    /// if parsing fails. IPv4/IPv6 literals are returned as-is.
    pub fn domain(&self) -> String {
        if self.url.is_empty() {
            return String::new();
        }
        match url::Url::parse(&self.url) {
            Ok(u) => u.host_str().unwrap_or(&self.url).to_string(),
            Err(_) => self.url.clone(),
        }
    }

    /// Parse `#tag` tokens out of the note field, preserving order.
    /// Tokens are lowercased so callers can compare consistently.
    pub fn tags(&self) -> Vec<String> {
        self.note
            .split_whitespace()
            .filter(|t| t.starts_with('#') && t.len() > 1)
            .map(|t| t[1..].to_lowercase())
            .collect()
    }
}
