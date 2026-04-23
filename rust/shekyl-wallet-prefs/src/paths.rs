// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Companion-path derivation for `.prefs.toml` and `.prefs.toml.hmac`.
//!
//! A Shekyl v1 wallet cluster shares a single base name `P`:
//!
//! ```text
//! <P>.wallet            — state file (ledger, sync state, …)
//! <P>.wallet.keys       — seed/capability file
//! <P>.prefs.toml        — TOML body for the plaintext prefs layer
//! <P>.prefs.toml.hmac   — 32-byte HMAC-SHA256 over the body
//! ```
//!
//! The input to both helpers in this module is the **state-file path**
//! `<P>.wallet` — the same argument callers pass to
//! [`shekyl_wallet_file`]'s orchestrator APIs. The helpers strip the
//! trailing `.wallet` extension once, then append the prefs suffix.
//! A base path without `.wallet` is treated as the stem directly, so
//! tests and one-off scripts do not have to synthesize a fake
//! extension.
//!
//! # The derivation rule, spelled out
//!
//! ```text
//! state  = "/tmp/alice.wallet"
//! stem   = "/tmp/alice"            (strip trailing ".wallet")
//! prefs  = stem + ".prefs.toml"    = "/tmp/alice.prefs.toml"
//! hmac   = stem + ".prefs.toml.hmac" = "/tmp/alice.prefs.toml.hmac"
//! ```
//!
//! When `state` does not end in `.wallet` (e.g. test fixtures), the
//! suffix is appended directly:
//!
//! ```text
//! state  = "/tmp/x"
//! prefs  = "/tmp/x.prefs.toml"
//! hmac   = "/tmp/x.prefs.toml.hmac"
//! ```
//!
//! This mirrors the symmetry in [`shekyl_wallet_file::paths`]: the
//! user picks one path and every companion path is a deterministic
//! function of it.
//!
//! # What this module does not do
//!
//! It does not touch the filesystem. Purely path manipulation.
//!
//! [`shekyl_wallet_file`]: https://docs.rs/shekyl-wallet-file
//! [`shekyl_wallet_file::paths`]: https://docs.rs/shekyl-wallet-file

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Trailing extension on the wallet state-file path. Stripped (if
/// present) before appending the prefs suffix so that the prefs files
/// sit at the stem, matching the `WALLET_PREFS.md §4.1` filename
/// examples.
pub const WALLET_STATE_SUFFIX: &str = ".wallet";

/// Suffix appended to the base stem for the TOML prefs body.
pub const PREFS_TOML_SUFFIX: &str = ".prefs.toml";

/// Suffix appended to the base stem for the HMAC companion file.
pub const PREFS_HMAC_SUFFIX: &str = ".prefs.toml.hmac";

/// Strip a single trailing `".wallet"` from `base`, if present.
/// Returns the stem as an [`OsString`] so Windows paths with
/// non-UTF-8 segments survive the round-trip unchanged.
fn strip_wallet_suffix(base: &Path) -> OsString {
    // Detecting ".wallet" is a pure-byte operation on the OsStr; we
    // could use `Path::extension` but that would also match bases
    // like `foo.wallet.tmp` where the last extension is `.tmp`. The
    // contract is "strip exactly .wallet from the end, once".
    let os = base.as_os_str().to_owned();
    let bytes = os.as_encoded_bytes();
    let suf = WALLET_STATE_SUFFIX.as_bytes();
    if bytes.len() >= suf.len() && &bytes[bytes.len() - suf.len()..] == suf {
        // Safe: we only trim whole-UTF-8 bytes (".wallet" is pure ASCII).
        // SAFETY: removing ASCII bytes preserves the OsString's encoding
        // contract; we never split a UTF-16 surrogate or an OsStr boundary.
        let trimmed = &bytes[..bytes.len() - suf.len()];
        unsafe { OsString::from_encoded_bytes_unchecked(trimmed.to_vec()) }
    } else {
        os
    }
}

/// Derive the `.prefs.toml` path for a wallet whose state file is at
/// `base` (e.g. `/tmp/alice.wallet`).
///
/// # Examples
///
/// ```
/// use shekyl_wallet_prefs::paths::prefs_toml_path_from;
/// use std::path::Path;
/// assert_eq!(
///     prefs_toml_path_from(Path::new("/tmp/alice.wallet")),
///     Path::new("/tmp/alice.prefs.toml"),
/// );
/// assert_eq!(
///     prefs_toml_path_from(Path::new("/tmp/bare")),
///     Path::new("/tmp/bare.prefs.toml"),
/// );
/// ```
pub fn prefs_toml_path_from(base: &Path) -> PathBuf {
    let mut stem = strip_wallet_suffix(base);
    stem.push(PREFS_TOML_SUFFIX);
    PathBuf::from(stem)
}

/// Derive the `.prefs.toml.hmac` path. Same rule as
/// [`prefs_toml_path_from`] but with the HMAC suffix.
///
/// # Examples
///
/// ```
/// use shekyl_wallet_prefs::paths::prefs_hmac_path_from;
/// use std::path::Path;
/// assert_eq!(
///     prefs_hmac_path_from(Path::new("/tmp/alice.wallet")),
///     Path::new("/tmp/alice.prefs.toml.hmac"),
/// );
/// ```
pub fn prefs_hmac_path_from(base: &Path) -> PathBuf {
    let mut stem = strip_wallet_suffix(base);
    stem.push(PREFS_HMAC_SUFFIX);
    PathBuf::from(stem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_trailing_wallet_exactly_once() {
        assert_eq!(
            prefs_toml_path_from(Path::new("/tmp/a.wallet")),
            Path::new("/tmp/a.prefs.toml"),
        );
        // Only the trailing ".wallet" is stripped; embedded ones stay.
        assert_eq!(
            prefs_toml_path_from(Path::new("/tmp/.wallet-backup.wallet")),
            Path::new("/tmp/.wallet-backup.prefs.toml"),
        );
    }

    #[test]
    fn no_wallet_suffix_is_suffix_append_only() {
        assert_eq!(
            prefs_toml_path_from(Path::new("/tmp/primary")),
            Path::new("/tmp/primary.prefs.toml"),
        );
        assert_eq!(
            prefs_hmac_path_from(Path::new("/tmp/primary")),
            Path::new("/tmp/primary.prefs.toml.hmac"),
        );
    }

    #[test]
    fn toml_and_hmac_live_in_same_dir() {
        let base = Path::new("/home/alice/w/main.wallet");
        let toml = prefs_toml_path_from(base);
        let hmac = prefs_hmac_path_from(base);
        assert_eq!(toml.parent(), hmac.parent());
    }

    #[test]
    fn does_not_touch_case_variants_of_suffix() {
        // We strip literal bytes `.wallet`; a base ending in `.WALLET`
        // is left alone. Avoids an unintended platform-specific
        // case-fold on case-insensitive filesystems.
        assert_eq!(
            prefs_toml_path_from(Path::new("/tmp/alice.WALLET")),
            Path::new("/tmp/alice.WALLET.prefs.toml"),
        );
    }
}
