// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The canonical form of the integer constant authorities under `config/`,
//! and its digest.
//!
//! `docs/design/CLIENT_VERSION_CONSTANTS_VALIDATION.md` §3.3 (`VC-D3`) pins
//! the per-file rules and `VC-D12` the file set; this file is their one
//! definition. It is included by `build.rs` (to emit
//! [`CONSENSUS_CONSTANTS_DIGEST`] at build time) and by
//! `src/consensus_digest.rs`'s tests (to pin the rules against a synthetic
//! KAT and against the live files), so the generator and its oracle cannot
//! disagree about what the rules are.
//!
//! The rules, in the order they apply:
//!
//! 1. the header line [`CANONICAL_HEADER`] + LF — the domain tag and the
//!    form's version (`v2`: two files with section lines; `v1` was
//!    `consensus_constants.json` alone);
//! 2. then, per file in the fixed order [`CANONICAL_FILES`], a section line
//!    `= <path>` + LF, followed by the file's lines:
//! 3. parse as JSON; the document must be an object;
//! 4. drop every key that begins with `_` (the file's prose);
//! 5. every remaining value must be a non-negative JSON integer — anything
//!    else is an error naming the file and key, so the simplicity of step 7
//!    is enforced rather than assumed;
//! 6. sort the remaining keys bytewise ascending;
//! 7. emit `<key><SP><decimal><LF>` per key — no sign, no leading zeros, no
//!    separators;
//! 8. the digest is SHA-256 over all of those UTF-8 bytes, as 64 lowercase
//!    hex chars.
//!
//! The digest is a **label, not a protocol hash**: it authenticates nothing
//! (§1 of the design). It is a **change detector, not a freeze**: a value
//! the file itself marks provisional (the D2 escalation numbers, under a
//! GF-7 freeze ceremony) still moves the digest, and the re-pin is how the
//! ceremony becomes visible, not a gate against it (`VC-D12`). Changing any
//! rule above bumps the header's version.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// First line of the canonical form; the domain tag and the form's version.
pub const CANONICAL_HEADER: &str = "shekyl-consensus-constants-canonical-v2";

/// The files the digest covers, in canonical order, as paths from the
/// repository root. Both integer authorities under `config/` (`VC-D12`);
/// the per-network `genesis_recipients.*.json` are not constants files and
/// are covered by the genesis-hash axis instead.
pub const CANONICAL_FILES: [&str; 2] = [
    "config/consensus_constants.json",
    "config/economics_params.json",
];

/// Why a document has no canonical form. Every variant names enough to fix
/// the file; the build fails on any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// The text is not JSON.
    Json {
        /// The offending file.
        file: String,
        /// The parser's message.
        message: String,
    },
    /// The JSON is not an object at the top level.
    NotAnObject {
        /// The offending file.
        file: String,
    },
    /// A non-`_` key holds something other than an integer.
    NotAnInteger {
        /// The offending file.
        file: String,
        /// The offending key.
        key: String,
        /// What was found instead.
        found: &'static str,
    },
    /// A non-`_` key holds a negative integer.
    Negative {
        /// The offending file.
        file: String,
        /// The offending key.
        key: String,
    },
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json { file, message } => write!(f, "{file} is not valid JSON: {message}"),
            Self::NotAnObject { file } => write!(f, "{file} is not a JSON object"),
            Self::NotAnInteger { file, key, found } => write!(
                f,
                "{file} key {key:?} holds {found}; every non-underscore value must be a \
                 non-negative integer (the canonical form, \
                 CLIENT_VERSION_CONSTANTS_VALIDATION.md §3.3, admits nothing else — a \
                 non-integer constant reopens VC-D3, it does not sneak past it)"
            ),
            Self::Negative { file, key } => write!(
                f,
                "{file} key {key:?} is negative; the canonical form admits only \
                 non-negative integers"
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

/// Rules 3–7 for one file, appended to `out` (the caller has already
/// written the section line).
fn append_file(out: &mut String, file: &str, json: &str) -> Result<(), CanonicalError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| CanonicalError::Json {
            file: file.to_owned(),
            message: e.to_string(),
        })?;
    let map = value
        .as_object()
        .ok_or_else(|| CanonicalError::NotAnObject {
            file: file.to_owned(),
        })?;

    let mut keys: Vec<&String> = map.keys().filter(|k| !k.starts_with('_')).collect();
    keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    for key in keys {
        let value = &map[key.as_str()];
        let serde_json::Value::Number(number) = value else {
            return Err(CanonicalError::NotAnInteger {
                file: file.to_owned(),
                key: key.clone(),
                found: kind(value),
            });
        };
        match number.as_u64() {
            Some(integer) => {
                // `Display` for u64 is decimal, unsigned, no leading zeros.
                writeln!(out, "{key} {integer}").expect("String::write_fmt is infallible");
            }
            None if number.is_i64() => {
                return Err(CanonicalError::Negative {
                    file: file.to_owned(),
                    key: key.clone(),
                })
            }
            None => {
                return Err(CanonicalError::NotAnInteger {
                    file: file.to_owned(),
                    key: key.clone(),
                    found: "a non-integer number",
                })
            }
        }
    }
    Ok(())
}

/// The canonical form of `files` — `(path, contents)` pairs in the order
/// given, which the caller takes from [`CANONICAL_FILES`] — or why there is
/// none.
pub fn canonical_form(files: &[(&str, &str)]) -> Result<String, CanonicalError> {
    let mut out = String::with_capacity(4096);
    out.push_str(CANONICAL_HEADER);
    out.push('\n');
    for (file, json) in files {
        writeln!(out, "= {file}").expect("String::write_fmt is infallible");
        append_file(&mut out, file, json)?;
    }
    Ok(out)
}

/// Rule 8: SHA-256 of the canonical bytes, as 64 lowercase hex characters.
pub fn digest_hex(canonical: &str) -> String {
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(hex, "{byte:02x}").expect("String::write_fmt is infallible");
    }
    hex
}
