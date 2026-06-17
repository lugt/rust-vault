//! CSV encode/decode for `Vec<Entry>`.
//!
//! Uses the standard `csv` crate (RFC 4180). The header is fixed at
//! `name,url,username,password,note`.

use crate::entry::Entry;

/// CSV header row.
const HEADER: &str = "name,url,username,password,note";

/// Encode entries to CSV bytes (UTF-8).
pub fn encode_csv(entries: &[Entry]) -> Result<Vec<u8>, CsvError> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record(HEADER.split(','))?;
    for e in entries {
        wtr.write_record(&[&e.name, &e.url, &e.username, &e.password, &e.note])?;
    }
    Ok(wtr.into_inner()?)
}

/// Decode CSV bytes into entries. Missing trailing columns become empty strings.
pub fn decode_csv(bytes: &[u8]) -> Result<Vec<Entry>, CsvError> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(bytes);
    let mut out = Vec::new();
    for rec in rdr.records() {
        let r = rec?;
        let get = |i: usize| r.get(i).unwrap_or("").to_string();
        out.push(Entry::new(get(0), get(1), get(2), get(3), get(4)));
    }
    Ok(out)
}

/// Errors from CSV encode/decode.
#[derive(thiserror::Error, Debug)]
pub enum CsvError {
    /// I/O or parsing error from the `csv` crate.
    #[error("CSV I/O: {0}")]
    Io(#[from] csv::Error),
    /// Failed to extract the inner writer.
    #[error("CSV into_inner: {0}")]
    IntoInner(csv::IntoInnerError<csv::Writer<Vec<u8>>>),
}

impl From<csv::IntoInnerError<csv::Writer<Vec<u8>>>> for CsvError {
    fn from(e: csv::IntoInnerError<csv::Writer<Vec<u8>>>) -> Self {
        Self::IntoInner(e)
    }
}
