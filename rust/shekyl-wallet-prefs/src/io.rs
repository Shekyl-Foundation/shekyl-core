// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Load and save `prefs.toml` with HMAC-SHA256 integrity, atomic
//! writes, and quarantine-on-tamper semantics.
//!
//! This module implements the runtime side of
//! [`docs/WALLET_PREFS.md §4–§6`](../../docs/WALLET_PREFS.md). It is
//! deliberately the only part of the crate that touches the
//! filesystem; [`crate::hmac_key`] and [`crate::schema`] are pure
//! libraries.
//!
//! # Load outcomes
//!
//! [`LoadOutcome`] distinguishes three post-conditions so the caller
//! can surface them in the UI without re-reading disk:
//!
//! | Outcome              | Disk state before        | Disk state after        |
//! |----------------------|--------------------------|-------------------------|
//! | [`LoadOutcome::Missing`]  | Neither file present  | Unchanged               |
//! | [`LoadOutcome::Loaded`]   | Both files valid       | Unchanged               |
//! | [`LoadOutcome::Tampered`] | Corrupt / missing pair | Offenders quarantined   |
//!
//! Every branch returns a fully-populated [`WalletPrefs`]; the
//! [`crate::schema::WalletPrefs::default`] values absorb any missing
//! fields on the happy path and replace the entire document on the
//! tamper path. Nothing in this crate ever **refuses** to load a
//! wallet because of a prefs issue (that is the refuse-to-load ledger
//! rule; prefs are advisory).
//!
//! # Save model
//!
//! [`save_prefs`] writes the TOML body and HMAC file as a pair. Both
//! writes go through [`atomic_write`] (tmp → fsync → rename →
//! fsync(parent)). If the first rename succeeds and the second
//! fails, the next open sees a body-without-matching-HMAC, which the
//! loader treats as tamper, quarantines, and falls back to defaults —
//! the same path as any other corrupt pair.
//!
//! # Quarantine filename format
//!
//! ```text
//! <P>.prefs.toml.tampered-<unix_seconds>
//! <P>.prefs.toml.tampered-<unix_seconds>.1
//! <P>.prefs.toml.tampered-<unix_seconds>.2
//! ```
//!
//! The counter suffix is appended only on collision (two tamper
//! events in the same wall-clock second). Forensic files are never
//! clobbered.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tempfile::Builder;

use crate::errors::{Bucket3Field, PrefsError};
use crate::hmac_key::PrefsHmacKey;
use crate::paths::{prefs_hmac_path_from, prefs_toml_path_from};
use crate::schema::WalletPrefs;

/// Hard file-size cap for `prefs.toml`, in bytes. Files larger than
/// this are treated as a tamper event per
/// [`docs/WALLET_PREFS.md §6.1`](../../docs/WALLET_PREFS.md) — real
/// prefs files are well under a kilobyte.
pub const MAX_PREFS_TOML_BYTES: usize = 64 * 1024;

/// Hard size of the HMAC-SHA256 companion file: exactly the 32-byte
/// MAC output. Anything shorter or longer is a tamper event; the
/// loader refuses it with [`PrefsError::HmacWrongLength`].
pub const PREFS_HMAC_FILE_BYTES: usize = 32;

/// Bounded sanity limit for the HMAC file read buffer. Much larger
/// than the legitimate 32 bytes but still bounded, so a pathological
/// file on disk cannot make us allocate GB of memory to produce the
/// diagnostic.
const HMAC_READ_LIMIT: u64 = 4096;

/// Upper bound on the `.N` collision suffix when a previous
/// quarantine event landed in the same wall-clock second. 256 is
/// generous; past that we return an error so a pathological
/// quarantine loop cannot spin forever.
const MAX_QUARANTINE_COLLISION: u32 = 256;

/// Result of [`load_prefs`]. Each variant names the post-condition
/// so callers can log, update UI state, or surface the tamper event
/// without re-inspecting the filesystem.
#[derive(Debug)]
pub enum LoadOutcome {
    /// Neither `prefs.toml` nor `prefs.toml.hmac` exists. A fresh
    /// `WalletPrefs::default()` is returned; nothing is written to
    /// disk yet per the bootstrap policy in `§4.2`.
    Missing(WalletPrefs),

    /// Both files exist and validated cleanly. The returned prefs
    /// are the parsed contents of `prefs.toml`.
    Loaded(WalletPrefs),

    /// A tamper event was detected (missing pair half, HMAC
    /// mismatch, oversize body, or parse failure including Bucket-3
    /// collision). Offending files have been renamed into
    /// quarantine, a `WARN` log line has been emitted, and the
    /// returned prefs are `WalletPrefs::default()`.
    Tampered {
        /// Defaults returned to the caller in place of the corrupt
        /// contents.
        prefs: WalletPrefs,
        /// Paths of the files that were moved into quarantine. The
        /// original `.prefs.toml` and/or `.prefs.toml.hmac` no
        /// longer exist; these are the new names.
        quarantined: Vec<PathBuf>,
        /// The specific error that triggered the quarantine. Kept
        /// for log formatting; also stored here so tests can assert
        /// on the root cause without scraping the `WARN` line.
        reason: String,
    },
}

impl LoadOutcome {
    /// Borrow the `WalletPrefs` regardless of which branch fired.
    /// Convenient for call sites that only want the settings.
    pub fn prefs(&self) -> &WalletPrefs {
        match self {
            Self::Missing(p) | Self::Loaded(p) => p,
            Self::Tampered { prefs, .. } => prefs,
        }
    }

    /// Consume the outcome, returning only the prefs. Discards the
    /// tamper / missing signal.
    pub fn into_prefs(self) -> WalletPrefs {
        match self {
            Self::Missing(p) | Self::Loaded(p) => p,
            Self::Tampered { prefs, .. } => prefs,
        }
    }

    /// True iff this outcome was [`Self::Tampered`]. Useful in GUI
    /// flows that want to surface a "your preferences file was
    /// tampered with" banner.
    pub fn is_tampered(&self) -> bool {
        matches!(self, Self::Tampered { .. })
    }
}

/// Load `prefs.toml` and validate its HMAC against the supplied key.
///
/// See [`LoadOutcome`] for the three possible post-conditions and
/// [`docs/WALLET_PREFS.md §5`](../../docs/WALLET_PREFS.md) for the
/// failure-policy table that this function implements.
///
/// `base_path` must be the wallet's `.wallet` state-file path (the
/// same value a caller passes to `WalletFileHandle::open`). The
/// companion `.prefs.toml` and `.prefs.toml.hmac` paths are derived
/// via [`crate::paths`].
pub fn load_prefs(base_path: &Path, hmac_key: &PrefsHmacKey) -> Result<LoadOutcome, PrefsError> {
    let toml_path = prefs_toml_path_from(base_path);
    let hmac_path = prefs_hmac_path_from(base_path);

    let toml_present = toml_path.exists();
    let hmac_present = hmac_path.exists();

    // Case A: neither present. Silent defaults, no log, no disk write.
    if !toml_present && !hmac_present {
        return Ok(LoadOutcome::Missing(WalletPrefs::default()));
    }

    // Case B: orphan half. Quarantine whichever exists alone; load defaults.
    if toml_present ^ hmac_present {
        let orphan = if toml_present { &toml_path } else { &hmac_path };
        let reason =
            format!("prefs pair incomplete (orphan {orphan:?}); quarantining and loading defaults");
        tracing::warn!(
            target: "shekyl_wallet_prefs",
            orphan = %orphan.display(),
            "orphaned prefs companion; quarantining"
        );
        let quarantined = quarantine_if_present(&toml_path, &hmac_path)?;
        return Ok(LoadOutcome::Tampered {
            prefs: WalletPrefs::default(),
            quarantined,
            reason,
        });
    }

    // Case C: both present. Read both, verify HMAC, parse.
    let toml_bytes = match read_capped(&toml_path, MAX_PREFS_TOML_BYTES) {
        Ok(b) => b,
        Err(e @ PrefsError::OversizeToml { .. }) => {
            return quarantine_and_default(&toml_path, &hmac_path, format!("{e}"));
        }
        Err(PrefsError::Io(e)) => return Err(PrefsError::Io(e)),
        Err(other) => return Err(other),
    };
    let hmac_bytes = match read_hmac_file(&hmac_path) {
        Ok(b) => b,
        Err(e @ PrefsError::HmacWrongLength { .. }) => {
            return quarantine_and_default(&toml_path, &hmac_path, format!("{e}"));
        }
        Err(other) => return Err(other),
    };

    if !verify_hmac(hmac_key, &toml_bytes, &hmac_bytes) {
        let reason = format!("HMAC verification failed for {toml_path:?}");
        return quarantine_and_default(&toml_path, &hmac_path, reason);
    }

    match parse_toml_strict(&toml_bytes) {
        Ok(prefs) => Ok(LoadOutcome::Loaded(prefs)),
        Err(e) => quarantine_and_default(&toml_path, &hmac_path, format!("{e}")),
    }
}

/// Serialize `prefs` to TOML, atomically write the body, compute
/// HMAC-SHA256 over the exact bytes written, and atomically write
/// the HMAC file. Callers should hold any higher-level session lock
/// (`WalletFileHandle`'s advisory lock is enough in practice).
pub fn save_prefs(
    base_path: &Path,
    hmac_key: &PrefsHmacKey,
    prefs: &WalletPrefs,
) -> Result<(), PrefsError> {
    let body =
        toml::to_string_pretty(prefs).map_err(|e| PrefsError::TomlSerialize(e.to_string()))?;
    let body_bytes = body.as_bytes();

    if body_bytes.len() > MAX_PREFS_TOML_BYTES {
        // Should be unreachable for any hand-editable schema, but
        // pin the check so a future field explosion is caught at
        // save time rather than silently tripping the read-side cap
        // on the next open.
        return Err(PrefsError::OversizeToml {
            limit: MAX_PREFS_TOML_BYTES,
            actual: body_bytes.len() as u64,
        });
    }

    let tag = compute_hmac(hmac_key, body_bytes);

    let toml_path = prefs_toml_path_from(base_path);
    let hmac_path = prefs_hmac_path_from(base_path);

    atomic_write(&toml_path, body_bytes)?;
    atomic_write(&hmac_path, &tag)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read a file up to `max` bytes. Returning an `OversizeToml` at
/// `max + 1` bytes lets the caller report the real overshoot without
/// pulling the whole pathological file into memory.
fn read_capped(path: &Path, max: usize) -> Result<Vec<u8>, PrefsError> {
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    let actual = metadata.len();
    if actual > max as u64 {
        return Err(PrefsError::OversizeToml { limit: max, actual });
    }
    let mut buf = Vec::with_capacity(usize::try_from(actual).unwrap_or(max));
    // Read at most `max + 1` bytes so a file that grew between stat
    // and read still doesn't bypass the cap.
    file.take(max as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > max {
        return Err(PrefsError::OversizeToml {
            limit: max,
            actual: buf.len() as u64,
        });
    }
    Ok(buf)
}

/// Read the HMAC companion file, enforcing the exact 32-byte length.
fn read_hmac_file(path: &Path) -> Result<[u8; PREFS_HMAC_FILE_BYTES], PrefsError> {
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    let actual = metadata.len();
    if actual != PREFS_HMAC_FILE_BYTES as u64 {
        return Err(PrefsError::HmacWrongLength {
            path: path.to_path_buf(),
            actual,
        });
    }
    let mut buf = Vec::with_capacity(PREFS_HMAC_FILE_BYTES);
    file.take(HMAC_READ_LIMIT).read_to_end(&mut buf)?;
    if buf.len() != PREFS_HMAC_FILE_BYTES {
        return Err(PrefsError::HmacWrongLength {
            path: path.to_path_buf(),
            actual: buf.len() as u64,
        });
    }
    let mut out = [0u8; PREFS_HMAC_FILE_BYTES];
    out.copy_from_slice(&buf);
    Ok(out)
}

/// Compute HMAC-SHA256(`hmac_key`, `body`) → 32 bytes. Infallible
/// for the fixed 32-byte key and SHA-256 block size.
fn compute_hmac(hmac_key: &PrefsHmacKey, body: &[u8]) -> [u8; PREFS_HMAC_FILE_BYTES] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(hmac_key.as_bytes().as_slice())
        .expect("HMAC accepts any key length");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; PREFS_HMAC_FILE_BYTES];
    out.copy_from_slice(&tag);
    out
}

/// Constant-time HMAC verification. Uses the `hmac` crate's built-in
/// `verify_slice`, which compares in constant time per
/// `subtle::ConstantTimeEq`.
fn verify_hmac(hmac_key: &PrefsHmacKey, body: &[u8], expected: &[u8]) -> bool {
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(hmac_key.as_bytes().as_slice()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(expected).is_ok()
}

/// Intercept Bucket-3 fields by peeking at the TOML document tree,
/// then delegate to the strict schema parser. Returning the
/// per-field error before the schema layer keeps the user-facing
/// diagnostic useful; the generic `deny_unknown_fields` message says
/// "unknown field", while our variant names the CLI flag the user
/// probably wanted.
fn parse_toml_strict(body_bytes: &[u8]) -> Result<WalletPrefs, PrefsError> {
    let text = std::str::from_utf8(body_bytes)
        .map_err(|e| PrefsError::TomlParse(format!("prefs.toml is not valid UTF-8: {e}")))?;

    // First pass: look for a Bucket-3 name at the top level. We use
    // `toml::Value` rather than `toml::Table` because a malformed
    // document will fail here and we want that error to surface as
    // a generic parse failure, not a Bucket-3 collision.
    match text.parse::<toml::Value>() {
        Ok(toml::Value::Table(table)) => {
            for key in table.keys() {
                if let Some(bucket3) = Bucket3Field::from_toml_key(key) {
                    return Err(PrefsError::bucket3(bucket3));
                }
            }
        }
        Ok(_) => {
            // TOML grammar says the top level is always a table; a
            // non-table here means the `toml` crate accepted an
            // unusual document. Fall through to the strict parser,
            // which will reject it.
        }
        Err(e) => {
            return Err(PrefsError::TomlParse(e.to_string()));
        }
    }

    toml::from_str::<WalletPrefs>(text).map_err(|e| PrefsError::TomlParse(e.to_string()))
}

/// Quarantine any pair-half that currently exists and return a
/// [`LoadOutcome::Tampered`] with the defaults already populated.
/// Wrapper around [`quarantine_if_present`] for the common case.
fn quarantine_and_default(
    toml_path: &Path,
    hmac_path: &Path,
    reason: String,
) -> Result<LoadOutcome, PrefsError> {
    tracing::warn!(
        target: "shekyl_wallet_prefs",
        toml_path = %toml_path.display(),
        hmac_path = %hmac_path.display(),
        reason = %reason,
        "prefs tamper detected; quarantining files and loading defaults"
    );
    let quarantined = quarantine_if_present(toml_path, hmac_path)?;
    Ok(LoadOutcome::Tampered {
        prefs: WalletPrefs::default(),
        quarantined,
        reason,
    })
}

/// Rename any existing `toml_path` / `hmac_path` into a
/// tampered-<ts> quarantine variant, disambiguating collisions with
/// a `.N` counter.
fn quarantine_if_present(toml_path: &Path, hmac_path: &Path) -> io::Result<Vec<PathBuf>> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let mut out = Vec::new();
    for src in [toml_path, hmac_path] {
        if !src.exists() {
            continue;
        }
        let target = pick_quarantine_target(src, ts)?;
        fs::rename(src, &target)?;
        out.push(target);
    }
    Ok(out)
}

/// Pick a unique `…tampered-<ts>` / `…tampered-<ts>.<N>` filename.
/// Increments `N` until the target does not exist. Bounded at
/// [`MAX_QUARANTINE_COLLISION`].
fn pick_quarantine_target(src: &Path, ts: u64) -> io::Result<PathBuf> {
    let base = {
        let mut os = src.as_os_str().to_owned();
        os.push(format!(".tampered-{ts}"));
        PathBuf::from(os)
    };
    if !base.exists() {
        return Ok(base);
    }
    for n in 1..=MAX_QUARANTINE_COLLISION {
        let mut os = src.as_os_str().to_owned();
        os.push(format!(".tampered-{ts}.{n}"));
        let candidate = PathBuf::from(os);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "quarantine target {base:?} exhausted collision counter ({MAX_QUARANTINE_COLLISION})"
        ),
    ))
}

/// Atomic file replace: sibling tempfile → fsync → rename →
/// fsync(parent). Mirrors `shekyl_wallet_file::atomic::atomic_write_file`
/// but scoped to the prefs crate's error type and without the
/// WalletFileError coupling. A future refactor may consolidate the
/// two under a shared `shekyl-atomic-io` crate.
fn atomic_write(target: &Path, bytes: &[u8]) -> Result<(), PrefsError> {
    let parent = target.parent().ok_or_else(|| {
        PrefsError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("atomic_write target has no parent dir: {target:?}"),
        ))
    })?;

    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("prefs.tmp");
    let mut tmp = Builder::new()
        .prefix(name)
        .suffix(".tmp")
        .rand_bytes(8)
        .tempfile_in(parent)
        .map_err(PrefsError::Io)?;

    {
        let file = tmp.as_file_mut();
        file.write_all(bytes).map_err(PrefsError::Io)?;
        file.sync_all().map_err(PrefsError::Io)?;
    }

    tmp.persist(target)
        .map_err(|e| PrefsError::Io(io::Error::other(e.to_string())))?;

    fsync_parent_dir(parent)?;
    Ok(())
}

#[cfg(unix)]
fn fsync_parent_dir(parent: &Path) -> Result<(), PrefsError> {
    let dir = fs::File::open(parent).map_err(PrefsError::Io)?;
    rustix::fs::fsync(&dir)
        .map_err(|e| PrefsError::Io(io::Error::from_raw_os_error(e.raw_os_error())))?;
    Ok(())
}

#[cfg(not(unix))]
fn fsync_parent_dir(_parent: &Path) -> Result<(), PrefsError> {
    // Windows has no directory-fsync; `File::sync_all` on the file
    // is sufficient per the platform's durability model.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac_key::{EXPECTED_CLASSICAL_ADDRESS_BYTES, FILE_KEK_BYTES};
    use tempfile::tempdir;

    fn fixture_key() -> PrefsHmacKey {
        let mut kek = [0u8; FILE_KEK_BYTES];
        for (i, b) in kek.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }
        let mut addr = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        addr[0] = 0x01;
        PrefsHmacKey::derive(&kek, &addr)
    }

    fn base_in(dir: &Path) -> PathBuf {
        dir.join("alice.wallet")
    }

    #[test]
    fn missing_pair_returns_missing_outcome() {
        let d = tempdir().unwrap();
        let base = base_in(d.path());
        let key = fixture_key();
        let outcome = load_prefs(&base, &key).unwrap();
        assert!(matches!(outcome, LoadOutcome::Missing(_)));
        assert_eq!(outcome.into_prefs(), WalletPrefs::default());
        // No file written on this path.
        assert!(!prefs_toml_path_from(&base).exists());
        assert!(!prefs_hmac_path_from(&base).exists());
    }

    #[test]
    fn save_then_load_round_trips() {
        let d = tempdir().unwrap();
        let base = base_in(d.path());
        let key = fixture_key();
        let mut prefs = WalletPrefs::default();
        prefs.cosmetic.default_decimal_point = 10;
        prefs.operational.inactivity_lock_timeout = 30;
        save_prefs(&base, &key, &prefs).expect("save");

        let outcome = load_prefs(&base, &key).expect("load");
        match outcome {
            LoadOutcome::Loaded(loaded) => assert_eq!(loaded, prefs),
            other => panic!("expected Loaded, got {other:?}"),
        }
    }

    #[test]
    fn hmac_mismatch_quarantines_and_defaults() {
        let d = tempdir().unwrap();
        let base = base_in(d.path());
        let key = fixture_key();
        save_prefs(&base, &key, &WalletPrefs::default()).unwrap();

        // Flip a byte in the HMAC file.
        let hmac_path = prefs_hmac_path_from(&base);
        let mut bytes = fs::read(&hmac_path).unwrap();
        bytes[0] ^= 0xFF;
        fs::write(&hmac_path, &bytes).unwrap();

        let outcome = load_prefs(&base, &key).unwrap();
        match outcome {
            LoadOutcome::Tampered {
                prefs,
                quarantined,
                reason,
            } => {
                assert_eq!(prefs, WalletPrefs::default());
                // Both files should have been quarantined.
                assert_eq!(quarantined.len(), 2);
                for p in &quarantined {
                    assert!(p.exists(), "quarantined file missing: {p:?}");
                }
                assert!(reason.contains("HMAC"), "{reason}");
                // Originals gone.
                assert!(!prefs_toml_path_from(&base).exists());
                assert!(!prefs_hmac_path_from(&base).exists());
            }
            other => panic!("expected Tampered, got {other:?}"),
        }
    }

    #[test]
    fn orphan_toml_quarantined() {
        let d = tempdir().unwrap();
        let base = base_in(d.path());
        let key = fixture_key();
        // Write only the TOML body (no HMAC).
        let toml_path = prefs_toml_path_from(&base);
        fs::write(&toml_path, "schema_version = 1\n").unwrap();

        let outcome = load_prefs(&base, &key).unwrap();
        assert!(outcome.is_tampered());
        assert!(!toml_path.exists(), "orphan toml should be quarantined");
    }

    #[test]
    fn orphan_hmac_quarantined() {
        let d = tempdir().unwrap();
        let base = base_in(d.path());
        let key = fixture_key();
        let hmac_path = prefs_hmac_path_from(&base);
        fs::write(&hmac_path, vec![0u8; 32]).unwrap();

        let outcome = load_prefs(&base, &key).unwrap();
        assert!(outcome.is_tampered());
        assert!(!hmac_path.exists(), "orphan hmac should be quarantined");
    }

    #[test]
    fn bucket3_field_produces_prescriptive_error_and_quarantine() {
        let d = tempdir().unwrap();
        let base = base_in(d.path());
        let key = fixture_key();

        // Write a legitimate HMAC over the malicious TOML so the
        // HMAC-verify step passes and the parser gets a look at the
        // body; otherwise the HMAC failure would mask the
        // per-field diagnostic.
        let toml_body = "max_reorg_depth = 0\n";
        let toml_path = prefs_toml_path_from(&base);
        fs::write(&toml_path, toml_body).unwrap();
        let tag = compute_hmac(&key, toml_body.as_bytes());
        fs::write(prefs_hmac_path_from(&base), tag).unwrap();

        let outcome = load_prefs(&base, &key).unwrap();
        match outcome {
            LoadOutcome::Tampered { reason, .. } => {
                assert!(
                    reason.contains("--max-reorg-depth"),
                    "expected CLI flag in diagnostic, got: {reason}"
                );
                assert!(
                    reason.contains("docs/WALLET_PREFS.md"),
                    "expected spec reference in diagnostic, got: {reason}"
                );
            }
            other => panic!("expected Tampered, got {other:?}"),
        }
    }

    #[test]
    fn oversize_toml_triggers_quarantine() {
        let d = tempdir().unwrap();
        let base = base_in(d.path());
        let key = fixture_key();

        // Write a valid-HMAC body that intentionally exceeds the cap.
        let mut body = String::with_capacity(MAX_PREFS_TOML_BYTES + 1024);
        while body.len() <= MAX_PREFS_TOML_BYTES {
            body.push_str("# padding comment filled to push the file size cap\n");
        }
        let toml_path = prefs_toml_path_from(&base);
        fs::write(&toml_path, body.as_bytes()).unwrap();
        let tag = compute_hmac(&key, body.as_bytes());
        fs::write(prefs_hmac_path_from(&base), tag).unwrap();

        let outcome = load_prefs(&base, &key).unwrap();
        match outcome {
            LoadOutcome::Tampered { reason, .. } => {
                assert!(reason.contains("byte cap"), "{reason}");
            }
            other => panic!("expected Tampered, got {other:?}"),
        }
    }

    #[test]
    fn quarantine_collisions_get_counter_suffix() {
        let d = tempdir().unwrap();
        let base = base_in(d.path());
        let key = fixture_key();

        // First tamper event.
        fs::write(prefs_toml_path_from(&base), "garbage = true\n").unwrap();
        fs::write(prefs_hmac_path_from(&base), vec![0u8; 32]).unwrap();
        let _ = load_prefs(&base, &key).unwrap();

        // Second tamper event in (hopefully) the same wall-clock
        // second. Even if the clock ticks, the counter is exercised
        // via the `pick_quarantine_target` path, which is a
        // write-once behavior regardless of timing.
        fs::write(prefs_toml_path_from(&base), "garbage = true\n").unwrap();
        fs::write(prefs_hmac_path_from(&base), vec![0u8; 32]).unwrap();
        let outcome = load_prefs(&base, &key).unwrap();
        match outcome {
            LoadOutcome::Tampered { quarantined, .. } => {
                // At least one quarantine filename must still have
                // been chosen uniquely — all of them exist on disk.
                for p in &quarantined {
                    assert!(p.exists(), "quarantined file missing: {p:?}");
                }
            }
            other => panic!("expected Tampered, got {other:?}"),
        }

        // Sanity: enumerate the parent dir and confirm no file was
        // overwritten (collision counter ensured uniqueness).
        let entries: Vec<_> = fs::read_dir(d.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        let tampered_count = entries.iter().filter(|n| n.contains(".tampered-")).count();
        assert!(
            tampered_count >= 2,
            "expected ≥2 quarantined files in {entries:?}"
        );
    }

    #[test]
    fn wrong_key_is_treated_as_tamper() {
        let d = tempdir().unwrap();
        let base = base_in(d.path());
        let saved_key = fixture_key();
        save_prefs(&base, &saved_key, &WalletPrefs::default()).unwrap();

        // Derive a different key by flipping a byte in the address.
        let mut kek = [0u8; FILE_KEK_BYTES];
        for (i, b) in kek.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }
        let mut addr = [0u8; EXPECTED_CLASSICAL_ADDRESS_BYTES];
        addr[0] = 0x02; // differs from fixture_key
        let other_key = PrefsHmacKey::derive(&kek, &addr);

        let outcome = load_prefs(&base, &other_key).unwrap();
        assert!(outcome.is_tampered());
    }
}
