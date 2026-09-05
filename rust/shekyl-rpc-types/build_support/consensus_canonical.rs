// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The canonical form of `config/consensus_constants.json`, and its digest.
//!
//! `docs/design/CLIENT_VERSION_CONSTANTS_VALIDATION.md` §3.3 (`VC-D3`) pins
//! the rules; this file is their one definition. It is included by
//! `build.rs` (to emit [`CONSENSUS_CONSTANTS_DIGEST`] at build time) and by
//! `src/consensus_digest.rs`'s tests (to pin the rules against a synthetic
//! KAT and against the live file), so the generator and its oracle cannot
//! disagree about what the rules are.
//!
//! The rules, in the order they apply:
//!
//! 1. parse as JSON; the document must be an object;
//! 2. drop every key that begins with `_` (the file's prose);
//! 3. every remaining value must be a non-negative JSON integer — anything
//!    else is an error naming the key, so the simplicity of step 5 is
//!    enforced rather than assumed;
//! 4. sort the remaining keys bytewise ascending;
//! 5. emit the header line [`CANONICAL_HEADER`] + LF, then per key
//!    `<key><SP><decimal><LF>` — no sign, no leading zeros, no separators;
//! 6. the digest is SHA-256 over those UTF-8 bytes, as 64 lowercase hex chars.
//!
//! The digest is a **label, not a protocol hash**: it authenticates nothing
//! (§1 of the design). The header line is the canonical form's version;
//! changing any rule above bumps `v1`.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// First line of the canonical form; the domain tag and the form's version.
pub const CANONICAL_HEADER: &str = "shekyl-consensus-constants-canonical-v1";

/// Why a document has no canonical form. Every variant names enough to fix
/// the file; the build fails on any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// The text is not JSON.
    Json(String),
    /// The JSON is not an object at the top level.
    NotAnObject,
    /// A non-`_` key holds something other than an integer.
    NotAnInteger {
        /// The offending key.
        key: String,
        /// What was found instead.
        found: &'static str,
    },
    /// A non-`_` key holds a negative integer.
    Negative {
        /// The offending key.
        key: String,
    },
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "consensus_constants.json is not valid JSON: {e}"),
            Self::NotAnObject => write!(f, "consensus_constants.json is not a JSON object"),
            Self::NotAnInteger { key, found } => write!(
                f,
                "consensus_constants.json key {key:?} holds {found}; every non-underscore \
                 value must be a non-negative integer (the canonical form, \
                 CLIENT_VERSION_CONSTANTS_VALIDATION.md §3.3, admits nothing else — a \
                 non-integer constant reopens VC-D3, it does not sneak past it)"
            ),
            Self::Negative { key } => write!(
                f,
                "consensus_constants.json key {key:?} is negative; the canonical form admits \
                 only non-negative integers"
            ),
        }
    }
}

fn kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// The canonical form of `json` (rules 1–5 above), or why it has none.
pub fn canonical_form(json: &str) -> Result<String, CanonicalError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| CanonicalError::Json(e.to_string()))?;
    let map = value.as_object().ok_or(CanonicalError::NotAnObject)?;

    let mut keys: Vec<&String> = map.keys().filter(|k| !k.starts_with('_')).collect();
    keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let mut out = String::with_capacity(64 * (keys.len() + 1));
    out.push_str(CANONICAL_HEADER);
    out.push('\n');
    for key in keys {
        let value = &map[key.as_str()];
        let serde_json::Value::Number(number) = value else {
            return Err(CanonicalError::NotAnInteger {
                key: key.clone(),
                found: kind(value),
            });
        };
        match number.as_u64() {
            Some(integer) => {
                // `Display` for u64 is decimal, unsigned, no leading zeros.
                writeln!(out, "{key} {integer}").expect("String::write_fmt is infallible");
            }
            None if number.is_i64() => return Err(CanonicalError::Negative { key: key.clone() }),
            None => {
                return Err(CanonicalError::NotAnInteger {
                    key: key.clone(),
                    found: "a non-integer number",
                })
            }
        }
    }
    Ok(out)
}

/// Rule 6: SHA-256 of the canonical bytes, as 64 lowercase hex characters.
pub fn digest_hex(canonical: &str) -> String {
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(hex, "{byte:02x}").expect("String::write_fmt is infallible");
    }
    hex
}
