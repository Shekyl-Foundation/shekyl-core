// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Discover the wallet's `tor` binary and **verify it against a hash pin** before
//! it is ever launched (SP-T0c, design doc DQ-T0.5).
//!
//! The 2d-2 firewall rests on *our* tor: a swapped or tampered `tor` binary
//! defeats every downstream guarantee, so trusting the binary is a **mission #1
//! precondition**, not a convenience. This module is the runtime half of that
//! trust; it pairs with a pin-time obligation recorded in
//! [`docs/RELEASE_CHECKLIST.md`](../../../../docs/RELEASE_CHECKLIST.md).
//!
//! **Two verifications, doing different jobs — do not conflate them:**
//!
//! - *Pin-time* (a maintainer, driven by the release checklist): download the
//!   Tor Expert Bundle, verify its **GPG signature** against the Tor Browser
//!   Developers signing key ([`TOR_SIGNING_KEY_FPR`]), extract, then record the
//!   **extracted binary's** SHA-256 into the pin below. This is where the signing
//!   key — the durable pin — is enforced.
//! - *Runtime* (this module, every launch): a bare extracted binary carries no
//!   attached signature, so the gate is necessarily **SHA-256 of the discovered
//!   binary == the pinned hash → launch, else hard-refuse**. The pin also carries
//!   the version + signing-key fingerprint, but those are provenance for the
//!   checklist, not used at runtime.
//!
//! The verified path feeds `control::ManagedTor::tor_binary`. The actor stays a
//! pure mechanism (it spawns whatever path it is handed); the *trust policy* lives
//! here, in discovery — so verification cannot be forgotten on some future spawn
//! path, and tests can still inject an arbitrary (unpinned) binary directly.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

/// The Tor Browser Developers OpenPGP key the Expert Bundle is verified against
/// **at pin time** (see `docs/RELEASE_CHECKLIST.md`). The durable pin is *this
/// key*, not any single hash: a version bump re-verifies the new bundle's
/// signature against this fingerprint, then records the new binary hash. Recorded
/// here for provenance; runtime verification is the per-target [`TorPin::sha256`]
/// (a bare extracted binary has no signature to check).
pub const TOR_SIGNING_KEY_FPR: &str = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290";

/// A pinned Tor release for one build target: the version (provenance) and the
/// SHA-256 of the **extracted `tor` binary** (the runtime gate).
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
    // sha256(tor) = 660a8c54d0c9341f85f0a7f827b6bde640e7db14dfde44d3856979d4ee6d16fb
    // Bundle GPG-verified against TOR_SIGNING_KEY_FPR before this hash was taken (2026-07-01).
    sha256: [
        0x66, 0x0a, 0x8c, 0x54, 0xd0, 0xc9, 0x34, 0x1f, 0x85, 0xf0, 0xa7, 0xf8, 0x27, 0xb6, 0xbd,
        0xe6, 0x40, 0xe7, 0xdb, 0x14, 0xdf, 0xde, 0x44, 0xd3, 0x85, 0x69, 0x79, 0xd4, 0xee, 0x6d,
        0x16, 0xfb,
    ],
});
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
const CURRENT_PIN: Option<TorPin> = None;

/// The `tor` executable's file name on this platform.
#[cfg(windows)]
const TOR_EXE_NAME: &str = "tor.exe";
#[cfg(not(windows))]
const TOR_EXE_NAME: &str = "tor";

/// The pin recorded for the current build target, if any (provenance / tests).
pub fn current_pin() -> Option<TorPin> {
    CURRENT_PIN
}

/// Why the wallet's `tor` binary could not be produced. Unlike `ControlError`
/// these are **setup/config** failures an operator diagnoses, and a `tor` install
/// path is not a forensic surface (it is not persona-linked), so the offending
/// path is carried for diagnosability (rule 82) — never a circuit ID, target, or
/// SOCKS username.
#[derive(Debug)]
pub enum TorBinaryError {
    /// This build target has no recorded pin, so a managed tor cannot be trusted
    /// or launched here. (Attach to an externally-run tor instead, or pin this
    /// target.)
    Unpinned,
    /// No `tor` binary was found via the override / beside-the-wallet / `PATH`
    /// search.
    NotFound,
    /// A candidate was found but could not be read to hash it.
    Io(PathBuf),
    /// A candidate was found but its SHA-256 does **not** match the pin — a
    /// tampered, wrong-version, or wrong-target binary. Launch is refused.
    HashMismatch(PathBuf),
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
            Self::Io(p) => write!(f, "could not read tor binary for verification: {}", p.display()),
            Self::HashMismatch(p) => write!(
                f,
                "tor binary failed hash-pin verification (tampered or wrong version): {}",
                p.display()
            ),
        }
    }
}

impl std::error::Error for TorBinaryError {}

/// Discover the wallet's `tor` binary and verify it against the pinned SHA-256,
/// returning its path only if it matches. The returned path is safe to hand to
/// `ManagedTor::tor_binary`.
///
/// Exactly **one** candidate is chosen, in this order, and it is the one verified:
///   1. the `SHEKYL_TOR_BINARY` env override (an operator/packager naming a
///      specific binary — still hash-gated; the override changes *where* we look,
///      never *whether* we verify),
///   2. a `tor` next to the running wallet executable (the bundled install layout),
///   3. `tor` on `PATH`.
///
/// There is deliberately **no fall-through on a hash mismatch**: discovery selects
/// a single candidate, so a tampered bundled binary can never silently defer to a
/// different tor. A mismatch is terminal — mission #1: an unpinned tor defeats the
/// firewall, so "refuse to launch" is the only safe outcome.
///
/// This performs blocking file I/O (hashing a ~5 MB binary once at setup); call it
/// before entering the actor's async hot path, not on it.
pub fn discover_and_verify() -> Result<PathBuf, TorBinaryError> {
    let pin = CURRENT_PIN.ok_or(TorBinaryError::Unpinned)?;
    let path = candidate().ok_or(TorBinaryError::NotFound)?;
    verify_file_sha256(&path, &pin.sha256)?;
    Ok(path)
}

/// The single `tor` candidate to verify — env override wins unconditionally (so an
/// explicit choice is never bypassed by a fall-through), else a binary beside the
/// wallet if present, else the first `tor` on `PATH`.
fn candidate() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SHEKYL_TOR_BINARY") {
        return Some(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(beside) = exe.parent().map(|dir| dir.join(TOR_EXE_NAME)) {
            if beside.is_file() {
                return Some(beside);
            }
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(TOR_EXE_NAME))
        .find(|c| c.is_file())
}

/// Stream the file through SHA-256 and compare to the pin. A plain (non
/// constant-time) compare is correct here: both the binary bytes and the pinned
/// hash are public, so there is no secret for a timing side-channel to leak.
fn verify_file_sha256(path: &Path, expected: &[u8; 32]) -> Result<(), TorBinaryError> {
    let mut file = std::fs::File::open(path).map_err(|_| TorBinaryError::Io(path.to_owned()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| TorBinaryError::Io(path.to_owned()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == *expected {
        Ok(())
    } else {
        Err(TorBinaryError::HashMismatch(path.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pinned known-answer for the hash itself: SHA-256 of the empty input is
    /// `e3b0c442…b855` (NIST). An empty file must verify against it — this pins the
    /// algorithm, independent of any tor binary being present.
    #[test]
    fn verify_matches_the_empty_input_sha256_vector() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty");
        std::fs::write(&p, b"").unwrap();
        let empty_sha256: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert!(verify_file_sha256(&p, &empty_sha256).is_ok());
    }

    /// The gate must reject a single flipped byte. `expected` is computed by the
    /// library's one-shot `Sha256::digest` over the *original* bytes, which also
    /// cross-checks that the streaming loop agrees with the one-shot digest.
    #[test]
    fn verify_rejects_a_tampered_byte() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("blob");
        let original = b"the quick brown fox jumps over the lazy dog";
        std::fs::write(&p, original).unwrap();
        let expected: [u8; 32] = Sha256::digest(original).into();
        assert!(verify_file_sha256(&p, &expected).is_ok());

        // Flip the last byte; the same `expected` must now be rejected.
        std::fs::write(&p, b"the quick brown fox jumps over the lazy dof").unwrap();
        assert!(matches!(
            verify_file_sha256(&p, &expected),
            Err(TorBinaryError::HashMismatch(_))
        ));
    }

    /// A missing candidate is `Io`, not a false pass.
    #[test]
    fn verify_missing_file_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert!(matches!(
            verify_file_sha256(&missing, &[0u8; 32]),
            Err(TorBinaryError::Io(_))
        ));
    }

    /// On a target we ship a managed tor for, the pin must be present (so
    /// `discover_and_verify` can only fail on discovery/mismatch, never silently on
    /// `Unpinned`). Guards against a `cfg` arm being dropped in a refactor.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn current_target_has_a_recorded_pin() {
        let pin = current_pin().expect("linux/x86_64 must have a recorded tor pin");
        assert_eq!(pin.bundle_version, "15.0.17");
    }

    /// The recorded pin must match the *actual* bundled binary — the runtime guard
    /// for the pin-time obligation (checklist bump correctness). Ignored in the unit
    /// gate; run on the integration lane with `SHEKYL_TEST_TOR_BINARY` pointing at
    /// the pinned Expert Bundle `tor`.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    #[ignore = "requires the pinned Tor via SHEKYL_TEST_TOR_BINARY"]
    fn bundled_tor_matches_recorded_pin() {
        let pin = current_pin().expect("recorded pin");
        let bin = std::env::var("SHEKYL_TEST_TOR_BINARY")
            .expect("SHEKYL_TEST_TOR_BINARY must point at the pinned tor on the integration lane");
        verify_file_sha256(Path::new(&bin), &pin.sha256).expect(
            "bundled tor must hash to the recorded pin — bump the pin if the bundle changed",
        );
    }
}
