//! SQLite-backed vault store: single current row + history of recent snapshots.

use crate::error::ServerError;
use rusqlite::{params, Connection};
use std::path::Path;
use vault_core::Version;

/// A snapshot retrieved from the database.
#[derive(Debug, Clone)]
pub struct StoredSnapshot {
    /// Monotonic version.
    pub version: Version,
    /// 16-byte Argon2 salt.
    pub salt: Vec<u8>,
    /// Wrapped CEK: 24-byte nonce || ciphertext.
    pub wrapped_cek: Vec<u8>,
    /// Encrypted CSV: 24-byte nonce || ciphertext.
    pub ciphertext: Vec<u8>,
    /// KDF params (JSON-encoded).
    pub kdf_params: Vec<u8>,
    /// ISO-8601 timestamp.
    pub created_at: String,
}

/// Metadata about an archived version in `vault_history`.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    /// Version number archived.
    pub version: Version,
    /// When the snapshot was archived (moved to history).
    pub archived_at: String,
}

/// Wrapper around the SQLite connection.
pub struct Store {
    conn: Connection,
}

/// Store-level errors.
#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    /// No row exists (first-time put).
    #[error("not found")]
    NotFound,
    /// CAS mismatch: the row is at `current`, not `expected`.
    #[error("version conflict: expected {expected}, current {current}")]
    VersionConflict {
        /// Caller's expected version.
        expected: u64,
        /// Current server version.
        current: u64,
    },
}

impl Store {
    /// Open (or create) a SQLite database at `path` and ensure the schema exists.
    pub fn open(path: &Path) -> Result<Self, ServerError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL,
                salt BLOB NOT NULL,
                wrapped_cek BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                kdf_params BLOB NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vault_history (
                version INTEGER PRIMARY KEY,
                salt BLOB NOT NULL,
                wrapped_cek BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                kdf_params BLOB NOT NULL,
                archived_at TEXT NOT NULL
            );
            ",
        )?;
        Ok(Self { conn })
    }

    /// Get the current snapshot, if any.
    pub fn get_snapshot(&self) -> Result<Option<StoredSnapshot>, ServerError> {
        let mut stmt = self.conn.prepare(
            "SELECT version, salt, wrapped_cek, ciphertext, kdf_params, created_at
             FROM vault WHERE id = 1",
        )?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            Ok(Some(StoredSnapshot {
                version: Version(row.get::<_, i64>(0)? as u64),
                salt: row.get(1)?,
                wrapped_cek: row.get(2)?,
                ciphertext: row.get(3)?,
                kdf_params: row.get(4)?,
                created_at: row.get(5)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// First-time put: create the row. Fails if a row already exists.
    pub fn put_snapshot(
        &self,
        v: Version,
        salt: &[u8],
        wrapped: &[u8],
        ct: &[u8],
        kdf_params: &[u8],
        ts: &str,
    ) -> Result<(), ServerError> {
        self.conn.execute(
            "INSERT INTO vault (id, version, salt, wrapped_cek, ciphertext, kdf_params, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![v.as_u64() as i64, salt, wrapped, ct, kdf_params, ts],
        )?;
        Ok(())
    }

    /// Compare-and-swap update. The current row must be at `expected`;
    /// the new version is `new_v`. Archives the old row to `vault_history`.
    pub fn put_if_match(
        &self,
        expected: Version,
        new_v: Version,
        salt: &[u8],
        wrapped: &[u8],
        ct: &[u8],
        kdf_params: &[u8],
        ts: &str,
    ) -> Result<(), ServerError> {
        let tx = self.conn.unchecked_transaction()?;
        let cur: i64 = tx
            .query_row("SELECT version FROM vault WHERE id = 1", [], |r| r.get(0))
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => ServerError::Store(StoreError::NotFound),
                other => ServerError::Rusqlite(other),
            })?;
        if cur as u64 != expected.as_u64() {
            return Err(ServerError::Store(StoreError::VersionConflict {
                expected: expected.as_u64(),
                current: cur as u64,
            }));
        }
        // Archive the old row.
        tx.execute(
            "INSERT OR REPLACE INTO vault_history
                (version, salt, wrapped_cek, ciphertext, kdf_params, archived_at)
             SELECT version, salt, wrapped_cek, ciphertext, kdf_params, ?1
             FROM vault WHERE id = 1",
            params![ts],
        )?;
        // Overwrite the current row.
        tx.execute(
            "UPDATE vault
                SET version = ?1, salt = ?2, wrapped_cek = ?3,
                    ciphertext = ?4, kdf_params = ?5, created_at = ?6
              WHERE id = 1",
            params![new_v.as_u64() as i64, salt, wrapped, ct, kdf_params, ts],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// List all archived snapshots, newest first.
    pub fn list_history(&self) -> Result<Vec<HistoryEntry>, ServerError> {
        let mut stmt = self
            .conn
            .prepare("SELECT version, archived_at FROM vault_history ORDER BY archived_at DESC")?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(HistoryEntry {
                version: Version(row.get::<_, i64>(0)? as u64),
                archived_at: row.get(1)?,
            });
        }
        Ok(out)
    }

    /// Archive the current snapshot to `vault_history`, then delete the
    /// current row. After this, `get_snapshot()` returns `None` and the next
    /// PUT must use `If-Match: 0` (init-style).
    pub fn clear_current(&self, ts: &str) -> Result<(), ServerError> {
        let tx = self.conn.unchecked_transaction()?;
        // Move the current row into history, preserving the version.
        tx.execute(
            "INSERT OR REPLACE INTO vault_history
                (version, salt, wrapped_cek, ciphertext, kdf_params, archived_at)
             SELECT version, salt, wrapped_cek, ciphertext, kdf_params, ?1
             FROM vault WHERE id = 1",
            params![ts],
        )?;
        // Delete the current row.
        tx.execute("DELETE FROM vault WHERE id = 1", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Restore an archived version as the new current. Copies the snapshot
    /// bytes from `vault_history[version]` to `vault` with `new_version`.
    /// The version is bumped to `new_version` (typically current+1) so
    /// subsequent PUTs use the new version as the If-Match value.
    pub fn restore_from_history(
        &self,
        from_version: Version,
        new_version: Version,
        ts: &str,
    ) -> Result<(), ServerError> {
        let tx = self.conn.unchecked_transaction()?;
        // Make sure the requested history row exists.
        let exists: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM vault_history WHERE version = ?1",
                params![from_version.as_u64() as i64],
                |r| r.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => ServerError::Store(StoreError::NotFound),
                other => ServerError::Rusqlite(other),
            })?;
        if exists == 0 {
            return Err(ServerError::Store(StoreError::NotFound));
        }
        // Archive whatever is current right now (so the recover is itself
        // a history event and can be undone).
        tx.execute(
            "INSERT OR REPLACE INTO vault_history
                (version, salt, wrapped_cek, ciphertext, kdf_params, archived_at)
             SELECT version, salt, wrapped_cek, ciphertext, kdf_params, ?1
             FROM vault WHERE id = 1",
            params![ts],
        )?;
        // Copy the requested history row into current with the new version.
        tx.execute(
            "INSERT OR REPLACE INTO vault
                (id, version, salt, wrapped_cek, ciphertext, kdf_params, created_at)
             SELECT 1, ?1, salt, wrapped_cek, ciphertext, kdf_params, ?2
             FROM vault_history WHERE version = ?3",
            params![
                new_version.as_u64() as i64,
                ts,
                from_version.as_u64() as i64
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db() -> Store {
        let path = std::env::temp_dir().join(format!(
            "vault_store_test_{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Store::open(&path).unwrap()
    }

    #[test]
    fn fresh_db_has_no_snapshot() {
        let s = tmp_db();
        assert!(s.get_snapshot().unwrap().is_none());
    }

    #[test]
    fn put_then_get_round_trip() {
        let s = tmp_db();
        s.put_snapshot(Version(1), b"salt16", b"wrap", b"ct", b"{}", "t")
            .unwrap();
        let snap = s.get_snapshot().unwrap().unwrap();
        assert_eq!(snap.version, Version(1));
        assert_eq!(snap.wrapped_cek, b"wrap");
        assert_eq!(snap.ciphertext, b"ct");
    }

    #[test]
    fn put_if_match_at_correct_version_succeeds() {
        let s = tmp_db();
        s.put_snapshot(Version(1), b"s", b"w", b"c", b"{}", "t1")
            .unwrap();
        s.put_if_match(Version(1), Version(2), b"s", b"w2", b"c2", b"{}", "t2")
            .unwrap();
        assert_eq!(s.get_snapshot().unwrap().unwrap().version, Version(2));
    }

    #[test]
    fn put_if_match_at_wrong_version_fails() {
        let s = tmp_db();
        s.put_snapshot(Version(1), b"s", b"w", b"c", b"{}", "t")
            .unwrap();
        let err = s
            .put_if_match(Version(99), Version(100), b"s", b"w2", b"c2", b"{}", "t2")
            .unwrap_err();
        assert!(matches!(
            err,
            ServerError::Store(StoreError::VersionConflict { .. })
        ));
    }

    #[test]
    fn list_history_initially_empty() {
        let s = tmp_db();
        assert!(s.list_history().unwrap().is_empty());
    }

    #[test]
    fn clear_archives_and_empties_current() {
        let s = tmp_db();
        s.put_snapshot(Version(1), b"s", b"w", b"c", b"{}", "t1")
            .unwrap();
        s.put_if_match(Version(1), Version(2), b"s", b"w2", b"c2", b"{}", "t2")
            .unwrap();
        // After 2 PUTs, history contains v1, current is v2.
        let hist = s.list_history().unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].version, Version(1));

        s.clear_current("t3").unwrap();
        assert!(s.get_snapshot().unwrap().is_none());
        // History now contains v1 and v2 (the latter just added by clear).
        let hist = s.list_history().unwrap();
        assert_eq!(hist.len(), 2);
    }

    #[test]
    fn restore_from_history_makes_old_version_current() {
        let s = tmp_db();
        s.put_snapshot(Version(1), b"s", b"w1", b"c1", b"{}", "t1")
            .unwrap();
        s.put_if_match(Version(1), Version(2), b"s", b"w2", b"c2", b"{}", "t2")
            .unwrap();
        // Restore v1 as new v3.
        s.restore_from_history(Version(1), Version(3), "t3")
            .unwrap();
        let cur = s.get_snapshot().unwrap().unwrap();
        assert_eq!(cur.version, Version(3));
        assert_eq!(cur.wrapped_cek, b"w1");
        assert_eq!(cur.ciphertext, b"c1");
    }

    #[test]
    fn restore_from_unknown_version_fails() {
        let s = tmp_db();
        s.put_snapshot(Version(1), b"s", b"w", b"c", b"{}", "t1")
            .unwrap();
        let err = s
            .restore_from_history(Version(99), Version(2), "t2")
            .unwrap_err();
        assert!(matches!(err, ServerError::Store(StoreError::NotFound)));
    }
}
