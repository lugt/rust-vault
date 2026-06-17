//! Categorization of `Vec<Entry>` by domain, tag, or first letter.

use crate::entry::Entry;
use std::collections::BTreeMap;

/// `BTreeMap<group_key, Vec<&Entry>>` for stable iteration order.
pub type Grouped<'a> = BTreeMap<String, Vec<&'a Entry>>;

/// Group entries by their URL domain. Empty URLs fall into `(no url)`.
pub fn group_by_domain(entries: &[Entry]) -> Grouped<'_> {
    let mut m: Grouped<'_> = BTreeMap::new();
    for e in entries {
        let d = e.domain();
        let key = if d.is_empty() {
            "(no url)".to_string()
        } else {
            d
        };
        m.entry(key).or_default().push(e);
    }
    m
}

/// Group entries by each `#tag` found in their note. Entries with no tags
/// are not represented in the output.
pub fn group_by_tag(entries: &[Entry]) -> Grouped<'_> {
    let mut m: Grouped<'_> = BTreeMap::new();
    for e in entries {
        for t in e.tags() {
            m.entry(t).or_default().push(e);
        }
    }
    m
}

/// Group entries by the first character of their name. ASCII letters go into
/// their uppercase bucket, ASCII digits into `#`, anything else into its own
/// single-char bucket. Empty names go into `(empty)`.
pub fn group_by_letter(entries: &[Entry]) -> Grouped<'_> {
    let mut m: Grouped<'_> = BTreeMap::new();
    for e in entries {
        let key = e
            .name
            .chars()
            .next()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    c.to_ascii_uppercase().to_string()
                } else if c.is_ascii_digit() {
                    "#".to_string()
                } else {
                    c.to_string()
                }
            })
            .unwrap_or_else(|| "(empty)".to_string());
        m.entry(key).or_default().push(e);
    }
    m
}
