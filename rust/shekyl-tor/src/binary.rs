// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Discover the wallet's `tor` binary and **verify it against a hash pin** before
//! it is handed to the launcher (SP-T0c, design doc DQ-T0.5).
//!
//! The 2d-2 firewall rests on *our* tor: a swapped or tampered `tor` binary
//! defeats every downstream guarantee, so trusting the binary is a **mission #1
//! precondition**, not a convenience. This module is the runtime half of that
//! trust; it pairs with a pin-time obligation recorded in
//! [`docs/RELEASE_CHECKLIST.md`](../../../docs/RELEASE_CHECKLIST.md) (the
//! operational step-by-step lives there, not here — one procedure, one home).
//!
//! **Two verifications, doing different jobs — do not conflate them:**
//!
//! - *Pin-time* (a maintainer, per the release checklist): the Tor Expert Bundle
//!   is GPG-verified against the Tor Browser Developers signing key
//!   ([`TOR_SIGNING_KEY_FPR`]) and the **extracted binary's** SHA-256 recorded as
//!   the pin. That is where the signing key — the durable pin — is enforced.
//! - *Runtime* (this module, every launch): a bare extracted binary carries no
//!   attached signature, so the gate is necessarily **SHA-256 of the discovered
//!   binary == the pinned hash → hand out a [`VerifiedTorBinary`], else refuse**.
//!
//! The gate is **structural, not conventional**: [`discover_and_verify`] /
//! [`discover_and_verify_at`] are the *only* producers of [`VerifiedTorBinary`],
//! and `ManagedTor::tor_binary` accepts nothing else — a spawn path cannot skip
//! verification because it cannot obtain the type without it (the same
//! make-bad-states-unrepresentable shape as SP-T0a's `ServerVerified`). The one
//! bypass is the loudly-named, `#[cfg(test)]`-only
//! `VerifiedTorBinary::unchecked_for_test`.
//!
//! **Scope boundary — what the pin does and does not defend (read before
//! extending):** the pin defends against *at-rest* tampering — a bad download, a
//! supply-chain swap, a binary replaced before launch. Verification hashes the
//! file and the launcher later `exec`s **by path**, which re-opens the file: an
//! attacker who can write the binary's directory *in the check-to-exec window*
//! can still swap it (classic TOCTOU). Such an attacker can usually tamper the
//! wallet itself, so the residual is narrow — but it is a boundary, not zero.
//! Load-bearing consequence: the production binary must live in a
//! wallet-controlled, non-world-writable directory (the beside-the-wallet
//! install layout gives this; the `PATH` fallback is the *widest* window and is
//! a bring-your-own-tor / dev convenience, not the intended production path).
//! Reopening criterion (rule 21): if the threat model ever includes a local
//! attacker with in-window write access to the tor directory, close the window
//! with fd-based exec (verify the fd, `fexecve` the same fd) instead of
//! re-litigating path-based checks.
//!
//! On failure surfaces: unlike `ControlError::Spawn` — which deliberately
//! carries **no path** because the actor's errors can flow into logs long after
//! setup — these errors are *pre-launch, operator-facing setup diagnostics*
//! (rule 82), and a tor install path is operator-supplied configuration, not
//! persona-linked forensic data (no circuit ID, target, or SOCKS username), so
//! the offending path and cause are carried. That asymmetry is deliberate; if
//! you change one side, reconcile the other.

use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The Tor Browser Developers OpenPGP key the Expert Bundle is verified against
/// **at pin time** (see `docs/RELEASE_CHECKLIST.md`, which cross-references this
/// constant by name). The durable pin is *this key*, not any single hash: a
/// version bump re-verifies the new bundle's signature against this fingerprint,
/// then records the new binary hash. Advisory at runtime — no code path checks a
/// signature here (a bare extracted binary has none); the runtime gate is the
/// per-target [`TorPin::sha256`].
pub const TOR_SIGNING_KEY_FPR: &str = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290";

/// A pinned Tor release for one build target: the versions (provenance for the
/// checklist — not used at runtime) and the SHA-256 of the **extracted `tor`
/// binary** (the runtime gate).
#[derive(Debug, Clone, Copy)]
pub struct TorPin {
    /// Tor Expert Bundle version the binary was extracted from.
    pub bundle_version: &'static str,
    /// The `tor` version inside that bundle.
    pub tor_version: &'static str,
    /// SHA-256 of the extracted `tor` binary for the current target.
    pub sha256: [u8; 32],
}

/// The pin for the current build target, or `None` where no binary has been
/// pinned yet. A `None` target cannot launch a *managed* tor (discovery hard-
/// refuses) — `TorLaunch::Attached` to an externally-run tor still works, and a
/// new target is enabled by pinning it (checklist + a `cfg` arm here), never by
/// relaxing the gate.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const CURRENT_PIN: Option<TorPin> = Some(TorPin {
    bundle_version: "15.0.17",
    tor_version: "0.4.9.11",
    // Recorded 2026-07-01 via the RELEASE_CHECKLIST "Bundled Tor pin" procedure
    // (download → GPG-verify → extract → hash); the checklist step is the
    // provenance record, this constant is the runtime gate.
    sha256: hex_literal::hex!("660a8c54d0c9341f85f0a7f827b6bde640e7db14dfde44d3856979d4ee6d16fb"),
});
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
const CURRENT_PIN: Option<TorPin> = None;

/// The `tor` executable's file name on this platform. (The Windows arm is
/// unreachable until a Windows pin exists — `CURRENT_PIN` is `None` there — but
/// a platform-correct filename constant is not a rule-21 flexibility lever, and
/// un-`cfg`-ing it would plant a silently wrong `"tor"` on the exact extension
/// path the pin design names.)
#[cfg(windows)]
const TOR_EXE_NAME: &str = "tor.exe";
#[cfg(not(windows))]
const TOR_EXE_NAME: &str = "tor";

/// A tor binary path that **passed the hash-pin gate** — the only currency
/// `ManagedTor::tor_binary` accepts. The field is private and the only
/// production constructors are [`discover_and_verify`] /
/// [`discover_and_verify_at`], so holding one *is* the proof of verification
/// (the SP-T0a `ServerVerified` pattern: you cannot reach the spawn without the
/// witness). `Debug`/the carried path are non-forensic here (see the module doc
/// on failure surfaces).
///
/// The path inside is **canonicalized at verification time**, so the bytes
/// hashed and the path later spawned name the same file — a bare or relative
/// candidate (an empty `PATH` entry, `SHEKYL_TOR_BINARY=./tor`) cannot verify
/// one file and exec another via cwd changes or the OS `exec` `PATH` search.
#[derive(Debug, Clone)]
pub struct VerifiedTorBinary(PathBuf);

impl VerifiedTorBinary {
    /// The verified, canonical path — for the spawn site.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// **Test-only bypass** of the hash gate, for lifecycle tests that inject an
    /// arbitrary (unpinned) tor — e.g. SP-T0b-2's offline child. Deliberately
    /// loud and greppable: every use is a declared exception to the gate.
    #[cfg(test)]
    pub(crate) fn unchecked_for_test(path: PathBuf) -> Self {
        Self(path)
    }
}

/// Why the wallet's `tor` binary could not be produced. These are **pre-launch
/// setup/config failures an operator diagnoses** — so unlike the actor's
/// content-free `ControlError::Spawn` (whose messages can flow into long-lived
/// logs), they carry the offending path and cause (rule 82). A tor install path
/// is operator-supplied configuration, not persona-linked forensic data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorBinaryError {
    /// This build target has no recorded pin, so a managed tor cannot be trusted
    /// or launched here. (Attach to an externally-run tor instead, or pin this
    /// target.)
    Unpinned,
    /// No `tor` binary was found via the override / beside-the-wallet / `PATH`
    /// search.
    NotFound,
    /// The candidate exists but is not a regular file (a directory, FIFO, or
    /// device) — refused before it is opened, so a FIFO cannot hang discovery.
    NotAFile(PathBuf),
    /// The candidate is a regular file but not executable — it would pass the
    /// hash yet fail at spawn with an error tor never gets to log. (Unix-only
    /// check; other platforms surface the spawn failure instead.)
    NotExecutable(PathBuf),
    /// The candidate could not be read; carries the [`std::io::ErrorKind`] so
    /// permission-denied, vanished, and I/O-error are distinguishable.
    Io {
        /// The path that failed.
        path: PathBuf,
        /// Why it failed.
        kind: std::io::ErrorKind,
    },
    /// The candidate's SHA-256 does not match the pin. **The common cause is
    /// benign**: a system tor (a distro build can never hash-match the pinned
    /// Expert Bundle), a stale install, or a mistyped pin bump — tampering is
    /// the rare case. Both digests are carried (they are public values) so the
    /// operator can see *what* was found vs. expected.
    HashMismatch {
        /// The path that was hashed.
        path: PathBuf,
        /// The pinned digest.
        expected: [u8; 32],
        /// The digest actually computed.
        actual: [u8; 32],
    },
}

/// Format a digest as lowercase hex (both pin and computed digests are public;
/// printing them is diagnosability, not leakage).
fn fmt_hex(f: &mut std::fmt::Formatter<'_>, bytes: &[u8; 32]) -> std::fmt::Result {
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

impl std::fmt::Display for TorBinaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unpinned => write!(
                f,
                "no pinned tor for this build target (managed tor unavailable; attach instead)"
            ),
            Self::NotFound => write!(
                f,
                "no tor binary found (set SHEKYL_TOR_BINARY, install beside the wallet, or add to PATH)"
            ),
            Self::NotAFile(p) => {
                write!(f, "tor binary candidate is not a regular file: {}", p.display())
            }
            Self::NotExecutable(p) => {
                write!(f, "tor binary is not executable (lost exec bit?): {}", p.display())
            }
            Self::Io { path, kind } => {
                write!(f, "could not read tor binary for verification ({kind}): {}", path.display())
            }
            Self::HashMismatch { path, expected, actual } => {
                write!(
                    f,
                    "tor binary does not match the pinned Expert Bundle build (a system tor or \
                     stale install will not match; reinstall the bundled tor or point \
                     SHEKYL_TOR_BINARY at it): {} — expected sha256 ",
                    path.display()
                )?;
                fmt_hex(f, expected)?;
                write!(f, ", found ")?;
                fmt_hex(f, actual)
            }
        }
    }
}

impl std::error::Error for TorBinaryError {}

/// Discover the wallet's `tor` binary and verify it against the pinned SHA-256,
/// returning a [`VerifiedTorBinary`] only if it matches.
///
/// Exactly **one** candidate is chosen, in this order, and it is the one verified:
///   1. the `SHEKYL_TOR_BINARY` env override (an operator/packager naming a
///      specific binary — still hash-gated; the override changes *where* we look,
///      never *whether* we verify; a set-but-empty value is treated as unset),
///   2. a `tor` next to the running wallet executable (the bundled install
///      layout — the intended production path; note `std::env::current_exe` is
///      best-effort by its own docs, and if it errors this tier is skipped),
///   3. `tor` on `PATH` (bring-your-own-tor / dev convenience — the widest
///      TOCTOU surface, see the module doc's scope boundary).
///
/// There is deliberately **no fall-through on a verification failure**: one
/// candidate is selected and its failure is terminal, so a tampered bundled
/// binary can never silently defer to a different tor. (Fall-through on
/// *absence* is how the tiers advance — a missing beside-the-wallet binary means
/// `PATH` is consulted — so deleting the bundled tor relocates discovery; the
/// relocated candidate is still hash-gated.) Mission #1: an unpinned tor defeats
/// the firewall, so "refuse to launch" is the only safe outcome.
///
/// For a caller-supplied path (a settings file), use [`discover_and_verify_at`]
/// — never route configuration through the env var.
///
/// This performs blocking file I/O (hashing a ~3.6 MB binary once at setup);
/// call it before entering the actor's async hot path — from async code, wrap it
/// in `tokio::task::spawn_blocking`.
pub fn discover_and_verify() -> Result<VerifiedTorBinary, TorBinaryError> {
    let pin = CURRENT_PIN.ok_or(TorBinaryError::Unpinned)?;
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let path = candidate_from(
        std::env::var_os("SHEKYL_TOR_BINARY"),
        exe_dir.as_deref(),
        std::env::var_os("PATH"),
    )
    .ok_or(TorBinaryError::NotFound)?;
    verify_candidate(&path, &pin.sha256)
}

/// Verify a **caller-supplied** tor path (e.g. from the wallet's settings file)
/// against the pin — the same gate as [`discover_and_verify`], minus discovery.
/// This is the sanctioned route for configuration: never plumb a config value
/// through the `SHEKYL_TOR_BINARY` env var (process-global, race-prone).
pub fn discover_and_verify_at(path: &Path) -> Result<VerifiedTorBinary, TorBinaryError> {
    let pin = CURRENT_PIN.ok_or(TorBinaryError::Unpinned)?;
    verify_candidate(path, &pin.sha256)
}

/// Select the single `tor` candidate from explicit inputs — the pure core of
/// discovery, separated from the process globals (env, `current_exe`) so the
/// precedence rules are unit-testable without racing the parallel test harness
/// over `std::env`.
///
/// Precedence: a non-empty override wins unconditionally (an explicit choice is
/// never bypassed by a fall-through — even if the file does not exist, so a typo
/// surfaces as *its* error, not a silent fallback); else a binary beside the
/// wallet if present; else the first **launchable** (regular, executable) `tor`
/// on `PATH` — matching the shell's own lookup, so a mode-0644 stray cannot
/// shadow the tor that `exec` would actually run.
fn candidate_from(
    override_var: Option<OsString>,
    exe_dir: Option<&Path>,
    path_var: Option<OsString>,
) -> Option<PathBuf> {
    if let Some(p) = override_var {
        // A set-but-empty override means unset (`SHEKYL_TOR_BINARY= wallet`, an
        // unexpanded variable in a wrapper script) — fall through to discovery
        // rather than "verifying" the empty path.
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    if let Some(beside) = exe_dir.map(|dir| dir.join(TOR_EXE_NAME)) {
        if beside.is_file() {
            return Some(beside);
        }
    }
    let path = path_var?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(TOR_EXE_NAME))
        .find(|c| c.is_file() && is_executable(c))
}

/// Does the path carry any execute bit? (Unix). `exec` skips non-executable
/// `PATH` entries that a bare `is_file()` accepts — discovery must agree with
/// `exec` about which file will actually run.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}
#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

/// The gate itself: canonicalize the candidate (so the hashed file and the
/// spawned path cannot diverge via relative paths, cwd changes, or the OS
/// `exec` `PATH` search), refuse non-regular / non-executable files with a
/// curated error, hash, and compare to `pin`. Returns the witness type on
/// success. Takes the pin as a parameter so the gate itself is KAT-testable
/// against arbitrary pins.
fn verify_candidate(path: &Path, pin: &[u8; 32]) -> Result<VerifiedTorBinary, TorBinaryError> {
    let canonical = std::fs::canonicalize(path).map_err(|e| TorBinaryError::Io {
        path: path.to_owned(),
        kind: e.kind(),
    })?;
    let meta = std::fs::metadata(&canonical).map_err(|e| TorBinaryError::Io {
        path: canonical.clone(),
        kind: e.kind(),
    })?;
    // Refuse non-regular files *before* opening: a FIFO would block the read
    // forever; a directory would yield a bare EISDIR.
    if !meta.is_file() {
        return Err(TorBinaryError::NotAFile(canonical));
    }
    // Refuse a non-executable candidate here, where the error can say why —
    // at spawn it is a content-free `ControlError::Spawn` and tor never runs,
    // so its own log (the designated diagnosis channel) is never written.
    if !is_executable(&canonical) {
        return Err(TorBinaryError::NotExecutable(canonical));
    }
    // One-shot read + digest: ~3.6 MB once at setup. `fs::read` retries
    // `ErrorKind::Interrupted` internally (unlike a hand-rolled read loop).
    let bytes = std::fs::read(&canonical).map_err(|e| TorBinaryError::Io {
        path: canonical.clone(),
        kind: e.kind(),
    })?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual == *pin {
        Ok(VerifiedTorBinary(canonical))
    } else {
        Err(TorBinaryError::HashMismatch {
            path: canonical,
            expected: *pin,
            actual,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// A pinned known-answer for the hash itself: SHA-256 of the empty input
    /// (NIST). An empty file must hash to it — this pins the algorithm,
    /// independent of any tor binary being present.
    const EMPTY_SHA256: [u8; 32] =
        hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    /// Write a file and make it executable (the gate requires launchability).
    fn write_executable(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn verify_matches_the_empty_input_sha256_vector() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty");
        write_executable(&p, b"");
        let verified = verify_candidate(&p, &EMPTY_SHA256).unwrap();
        // The witness carries the canonical form of the verified path.
        assert_eq!(verified.as_path(), p.canonicalize().unwrap());
    }

    /// The gate rejects a single flipped byte, and the mismatch carries both
    /// digests (`expected` = the pin, `actual` = what was found) so a bad pin
    /// bump is self-diagnosing.
    #[test]
    fn verify_rejects_a_tampered_byte_and_reports_both_digests() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("blob");
        let original = b"the quick brown fox jumps over the lazy dog";
        write_executable(&p, original);
        let expected: [u8; 32] = Sha256::digest(original).into();
        assert!(verify_candidate(&p, &expected).is_ok());

        // Flip the last byte; the same pin must now be rejected.
        let tampered = b"the quick brown fox jumps over the lazy dof";
        write_executable(&p, tampered);
        match verify_candidate(&p, &expected) {
            Err(TorBinaryError::HashMismatch {
                expected: e,
                actual: a,
                ..
            }) => {
                assert_eq!(e, expected);
                assert_eq!(a, <[u8; 32]>::from(Sha256::digest(tampered)));
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    /// A missing candidate is a NotFound-kind `Io`, not a false pass.
    #[test]
    fn verify_missing_file_is_io_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert!(matches!(
            verify_candidate(&missing, &[0u8; 32]),
            Err(TorBinaryError::Io {
                kind: std::io::ErrorKind::NotFound,
                ..
            })
        ));
    }

    /// A directory is refused as not-a-regular-file (before any read).
    #[test]
    fn verify_directory_is_not_a_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            verify_candidate(dir.path(), &[0u8; 32]),
            Err(TorBinaryError::NotAFile(_))
        ));
    }

    /// A readable but non-executable candidate is refused with a curated error
    /// — at spawn it would be a content-free failure tor never gets to log.
    #[cfg(unix)]
    #[test]
    fn verify_non_executable_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("not-exec");
        std::fs::write(&p, b"").unwrap(); // default 0644, no exec bit
        assert!(matches!(
            verify_candidate(&p, &EMPTY_SHA256),
            Err(TorBinaryError::NotExecutable(_))
        ));
    }

    /// The witness resolves symlinks at verification time: the canonical target
    /// is what was hashed and what will be spawned.
    #[cfg(unix)]
    #[test]
    fn verify_canonicalizes_a_symlinked_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real-tor");
        write_executable(&target, b"");
        let link = dir.path().join("tor-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let verified = verify_candidate(&link, &EMPTY_SHA256).unwrap();
        assert_eq!(verified.as_path(), target.canonicalize().unwrap());
    }

    // --- candidate_from precedence KATs (the load-bearing selection policy,
    // testable without touching process-global env). ---

    #[test]
    fn candidate_override_wins_even_over_an_existing_beside_binary() {
        let dir = tempfile::tempdir().unwrap();
        let beside = dir.path().join(TOR_EXE_NAME);
        write_executable(&beside, b"beside");
        let chosen = candidate_from(
            Some(OsString::from("/explicit/override/tor")),
            Some(dir.path()),
            None,
        );
        // The override is returned verbatim — even though it does not exist —
        // so a typo surfaces as *its* error, never a silent fallback.
        assert_eq!(chosen, Some(PathBuf::from("/explicit/override/tor")));
    }

    #[test]
    fn candidate_empty_override_is_treated_as_unset() {
        let dir = tempfile::tempdir().unwrap();
        let beside = dir.path().join(TOR_EXE_NAME);
        write_executable(&beside, b"beside");
        let chosen = candidate_from(Some(OsString::new()), Some(dir.path()), None);
        assert_eq!(chosen, Some(beside));
    }

    #[test]
    fn candidate_beside_wallet_is_preferred_over_path() {
        let beside_dir = tempfile::tempdir().unwrap();
        let beside = beside_dir.path().join(TOR_EXE_NAME);
        write_executable(&beside, b"beside");
        let path_dir = tempfile::tempdir().unwrap();
        write_executable(&path_dir.path().join(TOR_EXE_NAME), b"on-path");
        let path_var = std::env::join_paths([path_dir.path()]).unwrap();
        let chosen = candidate_from(None, Some(beside_dir.path()), Some(path_var));
        assert_eq!(chosen, Some(beside));
    }

    #[test]
    fn candidate_falls_through_to_path_when_nothing_is_beside() {
        let empty_dir = tempfile::tempdir().unwrap();
        let path_dir = tempfile::tempdir().unwrap();
        let on_path = path_dir.path().join(TOR_EXE_NAME);
        write_executable(&on_path, b"on-path");
        let path_var = std::env::join_paths([path_dir.path()]).unwrap();
        let chosen = candidate_from(None, Some(empty_dir.path()), Some(path_var));
        assert_eq!(chosen, Some(on_path));
    }

    /// PATH discovery must agree with `exec`: a non-executable entry is skipped
    /// (it could pass the hash yet a later executable one would actually run).
    #[cfg(unix)]
    #[test]
    fn candidate_path_search_skips_non_executable_entries() {
        let first = tempfile::tempdir().unwrap();
        std::fs::write(first.path().join(TOR_EXE_NAME), b"not-exec").unwrap(); // 0644
        let second = tempfile::tempdir().unwrap();
        let exec = second.path().join(TOR_EXE_NAME);
        write_executable(&exec, b"exec");
        let path_var = std::env::join_paths([first.path(), second.path()]).unwrap();
        let chosen = candidate_from(None, None, Some(path_var));
        assert_eq!(chosen, Some(exec));
    }

    #[test]
    fn candidate_none_when_nothing_is_found() {
        let empty = tempfile::tempdir().unwrap();
        let path_var = std::env::join_paths([empty.path()]).unwrap();
        assert_eq!(
            candidate_from(None, Some(empty.path()), Some(path_var)),
            None
        );
    }

    /// On a target we ship a managed tor for, the pin must be present (so
    /// `discover_and_verify` can only fail on discovery/verification, never
    /// silently on `Unpinned`). Guards against a `cfg` arm being dropped in a
    /// refactor.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn current_target_has_a_recorded_pin() {
        assert!(
            CURRENT_PIN.is_some(),
            "linux/x86_64 must have a recorded tor pin"
        );
    }

    /// The recorded pin must match the *actual* bundled binary — the runtime
    /// guard for the pin-time obligation (checklist bump correctness). Ignored
    /// in the unit gate; the pin-verify lane (and the checklist re-verify step)
    /// runs it with `SHEKYL_TEST_PINNED_TOR_BINARY` pointing at the **pinned
    /// Expert Bundle** `tor` — a distinct variable from the any-tor
    /// `SHEKYL_TEST_TOR_BINARY` the lifecycle tests use, so the two contracts
    /// cannot collide. Deliberately NOT `cfg`-gated: on a target with no pin it
    /// fails loudly ("no recorded pin") instead of compiling out and letting the
    /// checklist's re-verify step pass with zero tests run.
    #[test]
    #[ignore = "requires the pinned Tor via SHEKYL_TEST_PINNED_TOR_BINARY"]
    fn bundled_tor_matches_recorded_pin() {
        let pin = CURRENT_PIN
            .expect("this build target has no recorded pin — add the cfg arm before re-verifying");
        let bin = std::env::var_os("SHEKYL_TEST_PINNED_TOR_BINARY").expect(
            "SHEKYL_TEST_PINNED_TOR_BINARY must point at the pinned Expert Bundle tor \
             (GPG-verified per the RELEASE_CHECKLIST procedure) on the pin-verify lane",
        );
        verify_candidate(Path::new(&bin), &pin.sha256).expect(
            "bundled tor must hash to the recorded pin — if the bundle version changed, \
             re-run the full checklist procedure (GPG-verify first), never record a hash \
             from an unverified binary",
        );
    }
}
