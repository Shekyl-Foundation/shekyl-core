// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Companion-path helpers for the two-file wallet envelope.
//!
//! A Shekyl v1 wallet is always a pair of files sharing a base name:
//!
//! ```text
//! <base>.wallet.keys    ← the seed/capability file; written once at
//!                         creation, and again only on password rotation
//!                         or restore. Carries identity + settings.
//! <base>
//!   .wallet             ← the state file; rewritten on every auto-save.
//!                         Carries the ledger, bookkeeping, tx-meta, and
//!                         sync-state blocks inside a SWSP-framed
//!                         postcard payload.
//! ```
//!
//! Every orchestrator entry point takes a single `base` path and this
//! module derives both companion paths from it. Centralizing the rule
//! prevents the "some call sites use `.wallet.keys`, some use
//! `_keys.wallet`, some forget the dot" drift we saw in the Monero-
//! lineage codebase.
//!
//! # The derivation rule
//!
//! - `keys_path_from(base) = base + ".keys"`
//! - `state_path_from(base) = base`
//!
//! In other words, the user picks the `.wallet` path (the one they
//! actually want to `File → Open…` against), and the keys file is
//! always `<that>.keys`. Example:
//!
//! ```text
//! base               = /home/alice/wallets/primary.wallet
//! keys_path_from(..) = /home/alice/wallets/primary.wallet.keys
//! state_path_from(..)= /home/alice/wallets/primary.wallet
//! ```
//!
//! This matches the legacy Monero convention (`wallet` + `wallet.keys`)
//! so users migrating from pre-V3 builds have one less thing to
//! learn; the migration discontinuity is in the file *format*, not in
//! the file *naming*.
//!
//! # What this module does not do
//!
//! It does not touch the filesystem. All functions are pure path
//! manipulation.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Extension suffix appended to the user-provided base path to derive
/// the keys-file path. Appended as raw bytes, not via `set_extension`,
/// so a base like `primary.wallet` becomes `primary.wallet.keys`
/// (rather than `primary.keys`, which `set_extension` would produce).
pub const KEYS_FILE_SUFFIX: &str = ".keys";

/// Derive the `.wallet.keys` companion path from a user-provided base.
/// The base is treated as the `.wallet` path; we append `".keys"` to
/// the full path including any extensions the user specified.
///
/// # Examples
///
/// ```
/// use shekyl_engine_file::paths::keys_path_from;
/// use std::path::Path;
/// assert_eq!(
///     keys_path_from(Path::new("/tmp/primary.wallet")),
///     Path::new("/tmp/primary.wallet.keys"),
/// );
/// // A base with no extension still works:
/// assert_eq!(
///     keys_path_from(Path::new("/tmp/primary")),
///     Path::new("/tmp/primary.keys"),
/// );
/// ```
pub fn keys_path_from(base: &Path) -> PathBuf {
    let mut os: OsString = base.as_os_str().to_owned();
    os.push(KEYS_FILE_SUFFIX);
    PathBuf::from(os)
}

/// Derive the `.wallet` (state-file) path. Currently the identity
/// function; wrapped for symmetry with [`keys_path_from`] and to give
/// us a single change point if the naming rule ever evolves.
pub fn state_path_from(base: &Path) -> PathBuf {
    base.to_path_buf()
}

/// Extension suffix appended to the user-provided base path to derive
/// the FCMP++ curve-tree store path (CT-5). Appended as raw bytes (same
/// rule as [`KEYS_FILE_SUFFIX`]) so a base like `primary.wallet` becomes
/// `primary.wallet.curvetree`, keeping the store a visible sibling of the
/// `.wallet` / `.wallet.keys` pair rather than a hidden cache elsewhere.
pub const CURVE_TREE_STORE_SUFFIX: &str = ".curvetree";

/// Derive the curve-tree store path from a user-provided base, per the
/// CT-5 engine-wiring design (`docs/design/CT5_ENGINE_WIRING.md` §3.1):
/// the `redb`-backed `shekyl_curve_tree::LeafStore` lives **beside the
/// wallet files**, sharing their base name. The base is the `.wallet`
/// path; we append [`CURVE_TREE_STORE_SUFFIX`] to the full path including
/// any extensions, exactly as [`keys_path_from`] does.
///
/// # Examples
///
/// ```
/// use shekyl_engine_file::paths::curve_tree_store_path_from;
/// use std::path::Path;
/// assert_eq!(
///     curve_tree_store_path_from(Path::new("/tmp/primary.wallet")),
///     Path::new("/tmp/primary.wallet.curvetree"),
/// );
/// ```
pub fn curve_tree_store_path_from(base: &Path) -> PathBuf {
    let mut os: OsString = base.as_os_str().to_owned();
    os.push(CURVE_TREE_STORE_SUFFIX);
    PathBuf::from(os)
}

/// Extension suffix appended to the base path to derive the `P`-isolated
/// archival-scan state path (2d-1 SP-5). Appended as raw bytes (same rule as
/// [`KEYS_FILE_SUFFIX`]) so a base like `primary.wallet` becomes
/// `primary.wallet.pscan` — a visible sibling of the `.wallet` / `.wallet.keys`
/// pair, structurally separate from the principal ledger (the firewall keeps the
/// `P` scan state out of the principal state file).
pub const PSCAN_STATE_SUFFIX: &str = ".pscan";

/// Derive the `.wallet.pscan` `P`-scan state path from a user-provided base, the
/// same way [`keys_path_from`] / [`curve_tree_store_path_from`] do (append to the
/// full base, not `set_extension`).
///
/// # Examples
///
/// ```
/// use shekyl_engine_file::paths::pscan_state_path_from;
/// use std::path::Path;
/// assert_eq!(
///     pscan_state_path_from(Path::new("/tmp/primary.wallet")),
///     Path::new("/tmp/primary.wallet.pscan"),
/// );
/// ```
pub fn pscan_state_path_from(base: &Path) -> PathBuf {
    let mut os: OsString = base.as_os_str().to_owned();
    os.push(PSCAN_STATE_SUFFIX);
    PathBuf::from(os)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_path_appends_suffix() {
        assert_eq!(
            keys_path_from(Path::new("/tmp/a.wallet")),
            Path::new("/tmp/a.wallet.keys"),
        );
    }

    #[test]
    fn keys_path_is_not_set_extension() {
        // set_extension would drop ".wallet" and give us "/tmp/a.keys";
        // we want to preserve it.
        let got = keys_path_from(Path::new("/tmp/a.wallet"));
        assert_ne!(got, Path::new("/tmp/a.keys"));
    }

    #[test]
    fn keys_path_on_extensionless_base() {
        assert_eq!(
            keys_path_from(Path::new("/tmp/primary")),
            Path::new("/tmp/primary.keys"),
        );
    }

    #[test]
    fn state_path_is_identity() {
        let p = Path::new("/tmp/a.wallet");
        assert_eq!(state_path_from(p), p);
    }

    #[test]
    fn keys_and_state_paths_are_siblings() {
        let base = Path::new("/home/alice/wallets/x.wallet");
        let k = keys_path_from(base);
        let s = state_path_from(base);
        assert_eq!(k.parent(), s.parent());
    }

    #[test]
    fn curve_tree_path_appends_suffix() {
        assert_eq!(
            curve_tree_store_path_from(Path::new("/tmp/a.wallet")),
            Path::new("/tmp/a.wallet.curvetree"),
        );
    }

    #[test]
    fn curve_tree_path_is_not_set_extension() {
        // set_extension would drop ".wallet" and give "/tmp/a.curvetree";
        // we preserve the full base, as for the keys file.
        let got = curve_tree_store_path_from(Path::new("/tmp/a.wallet"));
        assert_ne!(got, Path::new("/tmp/a.curvetree"));
    }

    #[test]
    fn curve_tree_store_is_sibling_of_wallet_files() {
        let base = Path::new("/home/alice/wallets/x.wallet");
        let k = keys_path_from(base);
        let s = state_path_from(base);
        let c = curve_tree_store_path_from(base);
        assert_eq!(c.parent(), s.parent());
        assert_eq!(c.parent(), k.parent());
    }
}
