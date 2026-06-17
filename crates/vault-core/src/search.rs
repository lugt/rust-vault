//! Trigram-based fuzzy search over `Vec<Entry>`. Per spec §7.3.2.
//!
//! Scoring is field-weighted (name 0.40 / url 0.25 / user 0.20 / note 0.15)
//! with a substring-match bonus. Multi-word queries are AND-combined via
//! product of per-term contributions; any term below the per-term floor
//! drops the entry entirely.

use crate::entry::Entry;
use std::collections::HashSet;
use unicode_normalization::UnicodeNormalization;

/// Weight for the `name` field.
const W_NAME: f32 = 0.40;
/// Weight for the `url`/`domain` field.
const W_URL: f32 = 0.25;
/// Weight for the `username` field.
const W_USER: f32 = 0.20;
/// Weight for the `note` field.
const W_NOTE: f32 = 0.15;
/// Bonus added when the normalized query is a substring of the normalized target.
const SUBSTRING_BONUS: f32 = 0.30;
/// Minimum total score for a hit to be returned.
const THRESHOLD: f32 = 0.15;
/// Per-term contribution below which the term is treated as a miss (for AND).
const PER_TERM_FLOOR: f32 = 0.05;

/// A single search hit.
#[derive(Debug, Clone)]
pub struct Hit<'a> {
    /// Reference to the matched entry.
    pub entry: &'a Entry,
    /// Computed relevance score.
    pub score: f32,
}

/// Lowercase + Unicode NFC normalize a string.
fn normalize(s: &str) -> String {
    s.nfc().collect::<String>().to_lowercase()
}

/// Build character-level trigrams (Unicode-safe, never splits a codepoint).
/// Returns empty vec for inputs shorter than 3 characters.
pub fn trigrams(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 3 {
        return Vec::new();
    }
    chars.windows(3).map(|w| w.iter().collect()).collect()
}

/// Jaccard similarity over two trigram sets.
pub fn jaccard(a: &[String], b: &[String]) -> f32 {
    let sa: HashSet<&String> = a.iter().collect();
    let sb: HashSet<&String> = b.iter().collect();
    let inter = sa.intersection(&sb).count() as f32;
    let union = sa.union(&sb).count() as f32;
    if union == 0.0 {
        0.0
    } else {
        inter / union
    }
}

/// Score a single field against a normalized query.
fn field_score(q_trigrams: &[String], q_norm: &str, target: &str) -> f32 {
    if target.is_empty() {
        return 0.0;
    }
    let t_norm = normalize(target);
    let t_tris = trigrams(&t_norm);
    let sim = jaccard(q_trigrams, &t_tris);
    let mut s = sim;
    if !q_norm.is_empty() && t_norm.contains(q_norm) {
        s = (s + SUBSTRING_BONUS).min(1.0);
    }
    s
}

/// Parse a query like `name:git tag:work` into (global terms, field filters).
/// Tokens are lowercased; global terms are NFC-normalized.
pub fn parse_query(q: &str) -> (Vec<String>, Vec<(String, String)>) {
    let mut globals = Vec::new();
    let mut filters = Vec::new();
    for tok in q.split_whitespace() {
        if let Some((k, v)) = tok.split_once(':') {
            filters.push((k.to_lowercase(), v.to_lowercase()));
        } else {
            globals.push(normalize(tok));
        }
    }
    (globals, filters)
}

/// Search entries with a query string. Returns hits sorted by score desc.
pub fn search<'a>(query: &str, entries: &'a [Entry]) -> Vec<Hit<'a>> {
    if query.trim().is_empty() {
        return Vec::new();
    }
    let (globals, filters) = parse_query(query);
    let mut hits = Vec::new();
    for e in entries {
        // Apply field filters first.
        let mut passes_filters = true;
        for (k, v) in &filters {
            let target = match k.as_str() {
                "name" => &e.name,
                "url" | "domain" => &e.domain(),
                "user" | "username" => &e.username,
                "note" => &e.note,
                "tag" => &e.tags().join(" "),
                _ => {
                    passes_filters = false;
                    break;
                }
            };
            if !normalize(target).contains(v) {
                passes_filters = false;
                break;
            }
        }
        if !passes_filters {
            continue;
        }

        if globals.is_empty() {
            // Pure filter pass: every entry that matches gets score 1.0.
            hits.push(Hit {
                entry: e,
                score: 1.0,
            });
            continue;
        }

        // Multi-word AND: product of per-term weighted contributions.
        // A term with contribution < PER_TERM_FLOOR kills the entry.
        let mut total: f32 = 1.0;
        for term in &globals {
            let q_tris = trigrams(term);
            let s_name = field_score(&q_tris, term, &e.name);
            let s_url = field_score(&q_tris, term, &e.domain());
            let s_user = field_score(&q_tris, term, &e.username);
            let s_note = field_score(&q_tris, term, &e.note);
            let best = (s_name * W_NAME) + (s_url * W_URL) + (s_user * W_USER) + (s_note * W_NOTE);
            if best < PER_TERM_FLOOR {
                total = 0.0;
                break;
            }
            total *= best;
        }

        if total >= THRESHOLD {
            hits.push(Hit {
                entry: e,
                score: total,
            });
        }
    }
    hits.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hits
}
