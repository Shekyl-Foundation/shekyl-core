// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Error taxonomy for the prefs crate, including the per-field
//! rejection messages for Bucket-3 CLI-only override names.
//!
//! Every variant carries enough structured detail that a caller can
//! pattern-match on the specific failure ([`PrefsError::Bucket3Field`]
//! in particular) without re-parsing the human-readable string. The
//! `Display` impls are engineered to be documentation-as-diagnostic
//! per rule `82-failure-mode-ux.mdc`: a user who pastes the error
//! message into a search bar should find the prescriptive answer on
//! the first page.
//!
//! # Bucket-3 rejection
//!
//! `max_reorg_depth`, `skip_to_height`, and `refresh_from_block_height`
//! are the three Bucket-3 fields per
//! [`docs/WALLET_PREFS.md §3.3`](../../docs/WALLET_PREFS.md). When the
//! TOML body contains one of those top-level keys, the parser
//! rejects the file with a per-field message that names the
//! equivalent CLI flag. The rejection fires **before** the generic
//! `deny_unknown_fields` catch-all so the error the user sees is the
//! helpful one, not the structural one.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Enumeration of Bucket-3 fields whose presence in `prefs.toml`
/// triggers a specialized rejection. Kept as an enum (not a raw
/// string) so callers can exhaustively match and so the CLI flag
/// equivalent table lives in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket3Field {
    /// `max_reorg_depth` — runtime-only reorg-depth override.
    MaxReorgDepth,
    /// `skip_to_height` — one-shot scanner starting height.
    SkipToHeight,
    /// `refresh_from_block_height` — one-shot refresh cursor.
    RefreshFromBlockHeight,
}

impl Bucket3Field {
    /// The TOML field name as it would appear in a tampered prefs
    /// file.
    pub fn field_name(self) -> &'static str {
        match self {
            Self::MaxReorgDepth => "max_reorg_depth",
            Self::SkipToHeight => "skip_to_height",
            Self::RefreshFromBlockHeight => "refresh_from_block_height",
        }
    }

    /// The `shekyl-cli` flag a user should reach for instead.
    pub fn cli_flag(self) -> &'static str {
        match self {
            Self::MaxReorgDepth => "--max-reorg-depth",
            Self::SkipToHeight => "--skip-to-height",
            Self::RefreshFromBlockHeight => "--refresh-from-block-height",
        }
    }

    /// Recognise a TOML key as a Bucket-3 name. Returns `None` if the
    /// key is a legitimate Layer-2 field (or garbage, which falls
    /// through to the generic `deny_unknown_fields` rejection).
    pub fn from_toml_key(key: &str) -> Option<Self> {
        match key {
            "max_reorg_depth" => Some(Self::MaxReorgDepth),
            "skip_to_height" => Some(Self::SkipToHeight),
            "refresh_from_block_height" => Some(Self::RefreshFromBlockHeight),
            _ => None,
        }
    }
}

/// Error type for all prefs-crate surface APIs. Not marked
/// `#[non_exhaustive]` intentionally: additional variants land in
/// minor-version bumps and are a behavior change reviewers must
/// notice.
#[derive(Debug, Error)]
pub enum PrefsError {
    /// A Bucket-3 field name was found in `prefs.toml`. The message
    /// points the user at the CLI flag they almost certainly meant.
    /// This error is **tamper-equivalent**: `load_prefs` treats it as
    /// "TOML parse failure" per §5 and quarantines the file.
    #[error(
        "prefs.toml contains `{field}`, which is not a persistent preference. \
         Advanced chain-related overrides are runtime-only.\n\n\
         Use:\n    shekyl-cli {flag} N <command>\n\n\
         See docs/WALLET_PREFS.md §3.3 for the preference/override distinction."
    )]
    Bucket3Field {
        /// The field name as it appeared in the TOML body.
        field: &'static str,
        /// The equivalent `shekyl-cli` flag.
        flag: &'static str,
    },

    /// The TOML body exceeded the crate-level size cap. Real prefs
    /// files are sub-kilobyte; a multi-kilobyte body is either a
    /// malicious payload meant to tax the parser or a log blob
    /// written to the wrong path.
    #[error(
        "prefs.toml exceeds the {limit} byte cap ({actual} bytes read). \
         Real preferences files are far smaller; this file is being \
         quarantined as a tamper event."
    )]
    OversizeToml { limit: usize, actual: u64 },

    /// Parsing the TOML body failed for a reason other than a
    /// Bucket-3 collision: unknown field, missing value, syntactic
    /// error, wrong type, etc. Wraps the underlying `toml` error for
    /// diagnostics.
    #[error("failed to parse prefs.toml: {0}")]
    TomlParse(String),

    /// Serializing the prefs into TOML failed. Should never happen
    /// for the typed schema this crate ships — included for
    /// completeness and to surface a clear diagnostic if a future
    /// schema change introduces a non-serializable field.
    #[error("failed to serialize prefs.toml: {0}")]
    TomlSerialize(String),

    /// HMAC verification of `prefs.toml.hmac` against the TOML body
    /// failed. Treated as a tamper event; the caller's load path
    /// quarantines both files.
    #[error("HMAC verification failed for {path:?}")]
    HmacMismatch { path: PathBuf },

    /// The on-disk HMAC file was not exactly 32 bytes. Same policy as
    /// a mismatch: quarantine.
    #[error("HMAC file {path:?} has invalid length ({actual}; expected 32)")]
    HmacWrongLength { path: PathBuf, actual: u64 },

    /// Filesystem I/O error. Quarantine and atomic-write helpers
    /// surface their underlying `io::Error` through this variant; the
    /// `source()` chain points to the concrete errno where possible.
    #[error("prefs I/O error: {0}")]
    Io(#[from] io::Error),
}

impl PrefsError {
    /// Construct the Bucket-3 variant for a given field.
    pub fn bucket3(f: Bucket3Field) -> Self {
        Self::Bucket3Field {
            field: f.field_name(),
            flag: f.cli_flag(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket3_names_and_flags_match_spec() {
        // These assertions pin the user-visible contract. Breaking
        // any of them is a behavior change that must update
        // docs/WALLET_PREFS.md §3.3 in the same commit.
        assert_eq!(Bucket3Field::MaxReorgDepth.cli_flag(), "--max-reorg-depth");
        assert_eq!(Bucket3Field::SkipToHeight.cli_flag(), "--skip-to-height");
        assert_eq!(
            Bucket3Field::RefreshFromBlockHeight.cli_flag(),
            "--refresh-from-block-height"
        );
    }

    #[test]
    fn bucket3_error_text_mentions_cli_flag_and_spec() {
        let e = PrefsError::bucket3(Bucket3Field::MaxReorgDepth);
        let s = format!("{e}");
        assert!(s.contains("--max-reorg-depth"), "{s}");
        assert!(s.contains("docs/WALLET_PREFS.md"), "{s}");
    }

    #[test]
    fn bucket3_from_toml_key_covers_all_variants() {
        for f in [
            Bucket3Field::MaxReorgDepth,
            Bucket3Field::SkipToHeight,
            Bucket3Field::RefreshFromBlockHeight,
        ] {
            assert_eq!(Bucket3Field::from_toml_key(f.field_name()), Some(f));
        }
        assert_eq!(Bucket3Field::from_toml_key("default_decimal_point"), None);
    }
}
