// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Discover a `tor` binary and **verify its whole directory against a pin**
//! before it is handed to the launcher (SP-T0c, design doc DQ-T0.5; widened
//! by `TOR_BUNDLE_DISTRIBUTION.md` TB-4 and TB-7 to TB-9).
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
//!   ([`TOR_SIGNING_KEY_FPR`]) and the SHA-256 of the tarball and of each file
//!   Shekyl ships from it is recorded in `config/tor_pins.json`. That is where
//!   the signing key — the durable pin — is enforced.
//! - *Runtime* (this module, every launch): an extracted file carries no
//!   attached signature, so the gate is necessarily a comparison of digests
//!   against the row `build.rs` compiled in for this target.
//!
//! **What the gate checks, and why it is the directory and not the file.** The
//! Linux `tor` in the Expert Bundle needs three libraries it ships beside
//! itself and has no `RPATH`, so the launcher points the loader at tor's
//! directory. From that moment every entry in the directory is a candidate
//! for the loader, including subdirectories it searches first
//! (`glibc-hwcaps/<level>/`), and on Windows the executable's own directory is
//! searched before the system's. So the gate is three checks on one canonical
//! directory — the parent of the canonicalized `tor`:
//!
//! 1. the directory's entries are **exactly** the pinned files — no other
//!    entry, no subdirectory, nothing that is not a regular file. An
//!    allowlist, not a scan for library-looking names;
//! 2. each pinned file hashes to its own recorded digest;
//! 3. the candidate is the pinned executable and can be executed.
//!
//! One more condition on the directory's *name*, on Linux: the launcher gives
//! it to the loader in `LD_LIBRARY_PATH`, which is a list, so a path
//! containing `:`, `;` or `$` would be searched as some other directories.
//! Such a path is refused ([`TorBinaryError::UnsafeLoaderPath`]).
//!
//! [`VerifiedTorBinary`] carries that directory, and the launcher takes its
//! library path from the witness and nowhere else — so the directory that was
//! checked is the directory the loader is given. A symlinked install directory
//! is therefore checked and loaded at one place, its target.
//!
//! The gate is **structural, not conventional**: [`discover_and_verify`] /
//! [`discover_and_verify_at`] are the *only* producers of [`VerifiedTorBinary`],
//! and `ManagedTor::tor_binary` accepts nothing else — a spawn path cannot skip
//! verification because it cannot obtain the type without it (the same
//! make-bad-states-unrepresentable shape as SP-T0a's `ServerVerified`). The one
//! bypass is the loudly-named `VerifiedTorBinary::unchecked_for_test`, compiled
//! only under this crate's own tests or the `unpinned-tor-for-tests` feature,
//! which may be enabled on dev-dependency edges only.
//!
//! **Scope boundary — what the pin does and does not defend (read before
//! extending):** the pin defends against *at-rest* tampering — a bad download, a
//! supply-chain swap, a file replaced or planted before launch. Verification
//! reads the directory and the launcher later `exec`s **by path**, which
//! re-opens the file: an attacker who can write tor's directory *in the
//! check-to-exec window* can still swap or plant (classic TOCTOU). Such an
//! attacker can usually tamper the calling process itself, so the residual is
//! narrow — but it is a boundary, not zero. Load-bearing consequence: the
//! production bundle must live in a caller-controlled, non-world-writable
//! directory (the `tor/` directory beside the executable gives this, and the
//! `/opt/shekyl` system tier is root-owned by convention). Reopening criterion
//! (rule 21): if the threat model ever includes a local attacker with in-window
//! write access to the tor directory, close the window with fd-based exec
//! (verify the fd, `fexecve` the same fd) instead of re-litigating path-based
//! checks. Libraries the bundle does not carry — the glibc family, `libgcc_s`
//! and `libz.so.1` — come from the system and are outside the pin
//! (`TOR_BUNDLE_DISTRIBUTION.md` §5a).
//!
//! On failure surfaces: unlike `ControlError::Spawn` — which deliberately
//! carries **no path** because the actor's errors can flow into logs long after
//! setup — these errors are *pre-launch, operator-facing setup diagnostics*
//! (rule 82), and a tor install path is operator-supplied configuration, not
//! persona-linked forensic data (no circuit ID, target, or SOCKS username), so
//! the offending path and cause are carried. That asymmetry is deliberate; if
//! you change one side, reconcile the other.

use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

/// The Tor Browser Developers OpenPGP key the Expert Bundle is verified against
/// **at pin time** (see `docs/RELEASE_CHECKLIST.md`). The durable pin is *this
/// key*, not any single hash: a version bump re-verifies the new bundle's
/// signature against this fingerprint, then records the new digests. Advisory
/// at runtime — no code path checks a signature here (an extracted file has
/// none); the runtime gate is the per-file [`PinnedFile::sha256`]. Compiled
/// from `config/tor_pins.json`'s `signing_key_fingerprint`.
pub const TOR_SIGNING_KEY_FPR: &str = include!(concat!(env!("OUT_DIR"), "/tor_signing_key_fpr.rs"));

/// One file in tor's directory and the SHA-256 it must hash to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedFile {
    /// The file's name inside tor's directory (one path component).
    pub name: &'static str,
    /// SHA-256 of the file as extracted from the signature-verified bundle.
    pub sha256: [u8; 32],
}

/// A pinned Tor release for one build target: its provenance labels and the
/// complete contents of the directory `tor` runs from.
///
/// The lifetime is the pin's storage. The compiled disposition is `'static`;
/// a test borrows a stack array of [`PinnedFile`]s for the same shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TorPin<'a> {
    /// Tor Expert Bundle version the files were extracted from.
    pub bundle_version: &'a str,
    /// The Expert Bundle's target label for this build target (the suffix of
    /// the upstream tarball name, e.g. `linux-x86_64`). Provenance like the
    /// versions, plus one runtime use: composing the version-exact system
    /// directory `/opt/shekyl/<bundle_version>-<bundle_target>/`.
    pub bundle_target: &'a str,
    /// The `tor` version inside that bundle.
    pub tor_version: &'a str,
    /// The name of the `tor` executable among [`Self::files`].
    pub executable: &'a str,
    /// Whether file names in tor's directory are compared without regard to
    /// ASCII case. True on Windows, where `VERSION.DLL` and `version.dll` are
    /// one file to the loader, so the allowlist has to treat them as one name.
    pub case_insensitive_names: bool,
    /// **Every** file tor's directory holds, in slot order. The directory
    /// holding anything else is a refusal, not a warning. Each slot is matched
    /// at most once.
    pub files: &'a [PinnedFile],
}

impl TorPin<'_> {
    fn names_match(&self, found: &OsStr, pinned: &str) -> bool {
        match found.to_str() {
            Some(found) if self.case_insensitive_names => found.eq_ignore_ascii_case(pinned),
            Some(found) => found == pinned,
            // A name that is not Unicode is not one of ours.
            None => false,
        }
    }

    /// The slot `found` occupies in [`Self::files`], or `None` when the name
    /// is not pinned.
    fn file_index(&self, found: &OsStr) -> Option<usize> {
        self.files
            .iter()
            .position(|file| self.names_match(found, file.name))
    }
}

/// What Shekyl does about Tor on a build target. There is no third state: a
/// target is pinned, or it has been ruled out with a reason, and a target with
/// no row in `config/tor_pins.json` does not compile (`build.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorDisposition<'a> {
    /// Shekyl ships and launches this exact bundle.
    Pinned(TorPin<'a>),
    /// Shekyl does not manage a tor on this target. The operator runs their
    /// own and attaches it; `reason` is the sentence shown to them.
    Unavailable {
        /// Why there is no managed tor here.
        reason: &'a str,
    },
}

/// The disposition for the current build target, compiled from
/// `config/tor_pins.json` by `build.rs`.
pub const CURRENT_DISPOSITION: TorDisposition<'static> =
    include!(concat!(env!("OUT_DIR"), "/tor_disposition.rs"));

/// The pin for this build target, or the typed reason there is none.
fn current_pin() -> Result<TorPin<'static>, TorBinaryError> {
    match CURRENT_DISPOSITION {
        TorDisposition::Pinned(pin) => Ok(pin),
        TorDisposition::Unavailable { reason } => Err(TorBinaryError::Unavailable { reason }),
    }
}

/// The name of the directory, beside the running executable, that holds the
/// bundled tor in an unpacked archive: `<exe_dir>/tor/<executable>`. A
/// directory of its own because the gate requires tor's directory to hold the
/// pinned files and nothing else, which the directory of `shekyld` cannot.
const BESIDE_TOR_DIR: &str = "tor";

/// The system directory for the pinned bundle:
/// `/opt/shekyl/<bundle_version>-<bundle_target>/`. Where a system package
/// installs it. The candidate is **version-exact** — composed from the pin's
/// own labels, never globbed or latest-resolved — so a newer bundle staged
/// beside it is simply not found rather than found-and-refused. Unix-only;
/// there is no `/opt` convention on Windows.
#[cfg(unix)]
const WELL_KNOWN_TOR_DIR: &str = "/opt/shekyl";

/// Compose the version-exact system candidate for `pin`, or `None` where no
/// such convention exists for the platform.
// The wrap is cfg-dependent, not unnecessary: the non-unix arm returns `None`.
#[allow(clippy::unnecessary_wraps)]
fn well_known_candidate(pin: &TorPin<'_>) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(
            Path::new(WELL_KNOWN_TOR_DIR)
                .join(format!("{}-{}", pin.bundle_version, pin.bundle_target))
                .join(pin.executable),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = pin;
        None
    }
}

/// A tor binary whose **directory passed the pin gate** — the only currency
/// `ManagedTor::tor_binary` accepts. The fields are private and the only
/// production constructors are [`discover_and_verify`] /
/// [`discover_and_verify_at`], so holding one *is* the proof of verification
/// (the SP-T0a `ServerVerified` pattern: you cannot reach the spawn without the
/// witness). `Debug`/the carried paths are non-forensic here (see the module doc
/// on failure surfaces).
///
/// The path inside is **canonicalized at verification time**, and the library
/// directory is that path's parent, computed once. Both are always present:
/// a witness without a directory is not a witness. The launcher reads both
/// from here, so the bytes hashed, the path spawned and the directory the
/// loader is pointed at cannot name different places.
#[derive(Debug, Clone)]
pub struct VerifiedTorBinary {
    path: PathBuf,
    /// The directory whose contents the gate checked. On Linux this path is
    /// one absolute loader entry, and the launcher names it in
    /// `LD_LIBRARY_PATH` with no further test.
    library_dir: PathBuf,
}

impl VerifiedTorBinary {
    /// The verified, canonical path — for the spawn site.
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// The directory the verified `tor` lives in — the one directory the
    /// launcher may name to the loader.
    pub fn library_dir(&self) -> &Path {
        &self.library_dir
    }

    /// **Test-only bypass** of the pin gate, for lifecycle tests that inject an
    /// arbitrary (unpinned) tor — e.g. SP-T0b-2's offline child. Deliberately
    /// loud and greppable: every use is a declared exception to the gate.
    ///
    /// The launcher treats this witness as it treats a verified one — cleared
    /// environment, the loader pointed at the binary's own directory — so the
    /// lifecycle tests exercise the launch a user gets.
    ///
    /// `pub` under a feature rather than `#[cfg(test)]`-private because the
    /// supervisor that needs it (`WalletTorControl`'s `TorBinarySource`) is now a
    /// different crate, and `cfg(test)` does not cross a crate boundary. The
    /// feature may be enabled on **dev-dependency edges only**; that is a CI
    /// gate (`scripts/ci/check_test_only_features.py`) reading `cargo metadata`,
    /// not a convention. See the manifest comment for why a shipped binary
    /// cannot reach this arm.
    #[cfg(any(test, feature = "unpinned-tor-for-tests"))]
    pub fn unchecked_for_test(path: PathBuf) -> Self {
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        let library_dir = path.parent().map(Path::to_path_buf).unwrap_or_else(|| {
            panic!(
                "unchecked_for_test: {} has no parent directory to give the loader",
                path.display()
            )
        });
        // Linux names this directory in `LD_LIBRARY_PATH`, which is a list.
        // A witness that cannot be named that way is not a witness: the
        // launcher would otherwise start tor on the system search path.
        #[cfg(target_os = "linux")]
        assert!(
            loader_reads_as_one_directory(&library_dir),
            "unchecked_for_test: {} is not one absolute loader path",
            library_dir.display()
        );
        Self { path, library_dir }
    }
}

/// Why a `tor` binary could not be produced. These are **pre-launch
/// setup/config failures an operator diagnoses** — so unlike the actor's
/// content-free `ControlError::Spawn` (whose messages can flow into long-lived
/// logs), they carry the offending path and cause (rule 82). A tor install path
/// is operator-supplied configuration, not persona-linked forensic data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorBinaryError {
    /// Shekyl manages no tor on this build target
    /// ([`TorDisposition::Unavailable`]). The operator attaches their own.
    Unavailable {
        /// Why, as recorded in the pin file.
        reason: &'static str,
    },
    /// No `tor` was found via the override, the `tor/` directory beside the
    /// executable, or the system directory under `/opt/shekyl`.
    NotFound,
    /// The candidate, or an entry in its directory, exists but is not a
    /// regular file (a directory, a symlink, a FIFO, a device) — refused
    /// before it is opened, so a FIFO cannot hang discovery.
    NotAFile(PathBuf),
    /// The candidate is a regular file but not executable — it would pass the
    /// hash yet fail at spawn with an error tor never gets to log. (Unix-only
    /// check; other platforms surface the spawn failure instead.)
    NotExecutable(PathBuf),
    /// The candidate is in a pinned directory but is not the pinned
    /// executable (an override pointed at one of the libraries).
    NotTheExecutable(PathBuf),
    /// The candidate could not be read; carries the [`std::io::ErrorKind`] so
    /// permission-denied, vanished, and I/O-error are distinguishable.
    Io {
        /// The path that failed.
        path: PathBuf,
        /// Why it failed.
        kind: std::io::ErrorKind,
    },
    /// tor's directory holds something the pin does not list. **The common
    /// cause is benign**: the override points at a full extracted Expert
    /// Bundle, which carries a `pluggable_transports` directory Shekyl does
    /// not ship. It is refused all the same, because the loader is pointed at
    /// this directory and will load from it what it finds there.
    UnexpectedEntry {
        /// tor's directory.
        dir: PathBuf,
        /// The entry that is not pinned.
        name: OsString,
    },
    /// tor's directory has a path the dynamic loader would not read as one
    /// directory. The launcher names the directory to the loader in
    /// `LD_LIBRARY_PATH`, which is a *list*: `:` and `;` separate entries and
    /// `$` introduces a token (`$ORIGIN`, `$LIB`) the loader expands. A
    /// directory called `/srv/a:b/tor` would be checked as one place and
    /// searched as two others, neither of them checked.
    UnsafeLoaderPath(PathBuf),
    /// tor's directory lacks a file the pin lists.
    MissingFile {
        /// tor's directory.
        dir: PathBuf,
        /// The pinned file that is not there.
        name: &'static str,
    },
    /// A pinned file's SHA-256 does not match its pin. **The common cause is
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
            Self::Unavailable { reason } => write!(
                f,
                "Shekyl does not manage a tor on this platform ({reason}); run your own tor \
                 and attach it"
            ),
            Self::NotFound => write!(
                f,
                "no tor binary found (install the pinned bundle in the tor/ directory beside \
                 the executable or under /opt/shekyl/<version>-<target>/, or set \
                 SHEKYL_TOR_BINARY to the tor inside such a directory)"
            ),
            Self::NotAFile(p) => {
                write!(f, "not a regular file: {}", p.display())
            }
            Self::NotExecutable(p) => {
                write!(
                    f,
                    "tor binary is not executable (lost exec bit?): {}",
                    p.display()
                )
            }
            Self::NotTheExecutable(p) => {
                write!(f, "not the pinned tor executable: {}", p.display())
            }
            Self::Io { path, kind } => {
                write!(
                    f,
                    "could not read the tor bundle for verification ({kind}): {}",
                    path.display()
                )
            }
            Self::UnexpectedEntry { dir, name } => write!(
                f,
                "the tor directory {} holds {:?}, which is not part of the pinned bundle. The \
                 directory must contain the pinned files and nothing else (a full extracted \
                 Expert Bundle carries pluggable_transports/ and is refused; stage the pinned \
                 files into a directory of their own)",
                dir.display(),
                name
            ),
            Self::UnsafeLoaderPath(dir) => write!(
                f,
                "the tor directory's path contains ':', ';' or '$', which the dynamic loader \
                 reads as more than one directory: {}. Install the bundle under a path \
                 without those characters",
                dir.display()
            ),
            Self::MissingFile { dir, name } => write!(
                f,
                "the tor directory {} lacks the pinned file {name}",
                dir.display()
            ),
            Self::HashMismatch {
                path,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{} does not match the pinned Expert Bundle build (a system tor or stale \
                     install will not match; reinstall the bundled tor) — expected sha256 ",
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

/// Discover a `tor` binary and verify its directory against the pin,
/// returning a [`VerifiedTorBinary`] only if it passes.
///
/// Exactly **one** candidate is chosen, in this order, and it is the one verified:
///   1. the `SHEKYL_TOR_BINARY` env override (an operator, packager or
///      developer naming a specific binary — still gated in full: the override
///      changes *where* we look, never *whether* we verify, so it must name
///      the `tor` inside a directory holding exactly the pinned files; a
///      set-but-empty value is treated as unset),
///   2. `tor/tor` next to the running executable (the layout of an unpacked
///      release archive — note `std::env::current_exe` is best-effort by its
///      own docs, and if it errors this tier is skipped),
///   3. the system directory `/opt/shekyl/<bundle_version>-<target>/tor`
///      (version-exact, composed from the pin's own labels — where a system
///      package installs the bundle; Unix-only).
///
/// There is no `PATH` tier (`TOR_BUNDLE_DISTRIBUTION.md` TB-8): a `tor` on
/// `PATH` has its libraries elsewhere and cannot pass a directory pin, and
/// `PATH` was the widest check-to-exec window the resolver had.
///
/// There is deliberately **no fall-through on a verification failure**: one
/// candidate is selected and its failure is terminal, so a tampered bundle can
/// never silently defer to a different tor. (Fall-through on *absence* is how
/// the tiers advance; the relocated candidate is gated the same way.)
/// Mission #1: an unpinned tor defeats every downstream guarantee, so "refuse
/// to launch" is the only safe outcome.
///
/// For a caller-supplied path (a settings file), use [`discover_and_verify_at`]
/// — never route configuration through the env var.
///
/// This performs blocking file I/O (hashing the bundle, about 12 MiB, once at
/// setup); call it before entering the actor's async hot path — from async
/// code, wrap it in `tokio::task::spawn_blocking`.
pub fn discover_and_verify() -> Result<VerifiedTorBinary, TorBinaryError> {
    let pin = current_pin()?;
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let well_known = well_known_candidate(&pin);
    let path = candidate_from(
        std::env::var_os("SHEKYL_TOR_BINARY"),
        exe_dir.as_deref(),
        well_known.as_deref(),
        pin.executable,
    )
    .ok_or(TorBinaryError::NotFound)?;
    verify_candidate(&path, &pin)
}

/// Verify a **caller-supplied** tor path (e.g. from a settings file)
/// against the pin — the same gate as [`discover_and_verify`], minus discovery.
/// This is the sanctioned route for configuration: never plumb a config value
/// through the `SHEKYL_TOR_BINARY` env var (process-global, race-prone).
pub fn discover_and_verify_at(path: &Path) -> Result<VerifiedTorBinary, TorBinaryError> {
    let pin = current_pin()?;
    verify_candidate(path, &pin)
}

/// Select the single `tor` candidate from explicit inputs — the pure core of
/// discovery, separated from the process globals (env, `current_exe`) so the
/// precedence rules are unit-testable without racing the parallel test harness
/// over `std::env`.
///
/// Precedence: a non-empty override wins unconditionally (an explicit choice is
/// never bypassed by a fall-through — even if the file does not exist, so a typo
/// surfaces as *its* error, not a silent fallback); else `tor/<executable>`
/// beside the running executable if present; else the version-exact system
/// candidate if present. Presence is `is_file()` in both discovered tiers, so
/// a staged non-executable file surfaces as *its* `NotExecutable` error rather
/// than as "not found".
fn candidate_from(
    override_var: Option<OsString>,
    exe_dir: Option<&Path>,
    well_known: Option<&Path>,
    executable: &str,
) -> Option<PathBuf> {
    if let Some(p) = override_var {
        // A set-but-empty override means unset (`SHEKYL_TOR_BINARY= wallet`, an
        // unexpanded variable in a wrapper script) — fall through to discovery
        // rather than "verifying" the empty path.
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    if let Some(beside) = exe_dir.map(|dir| dir.join(BESIDE_TOR_DIR).join(executable)) {
        if beside.is_file() {
            return Some(beside);
        }
    }
    well_known.filter(|wk| wk.is_file()).map(Path::to_path_buf)
}

/// Does the path carry any execute bit? (Unix). A file with none would pass
/// the hash and then fail at spawn with an error tor never gets to log.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}
#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

/// Can `dir` be handed to the dynamic loader as a search path and mean
/// exactly itself? `LD_LIBRARY_PATH` is a list, not a path: glibc splits it
/// on `:` and `;` and expands `$`-tokens in each entry. A directory whose
/// name contains any of the three is therefore *not* the directory the
/// loader would search, and the pin gate checked only the one it was given.
/// Byte-wise on Unix, so a non-UTF-8 path is judged on what the loader sees.
fn loader_reads_as_one_directory(dir: &Path) -> bool {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        dir.as_os_str().as_bytes()
    };
    #[cfg(not(unix))]
    let bytes = dir.as_os_str().as_encoded_bytes();
    dir.is_absolute() && !bytes.iter().any(|b| matches!(b, b':' | b';' | b'$'))
}

fn io_error(path: &Path, e: &std::io::Error) -> TorBinaryError {
    TorBinaryError::Io {
        path: path.to_owned(),
        kind: e.kind(),
    }
}

/// The gate itself. Canonicalize the candidate (so the file checked and the
/// path spawned cannot diverge via relative paths, cwd changes, symlinks, or
/// the OS `exec` `PATH` search), take **its parent as tor's directory**, and
/// check that directory three ways: its entries are exactly `pin.files` and
/// all regular files; the candidate is the pinned executable and executable;
/// every pinned file hashes to its digest. Returns the witness, carrying that
/// same directory, on success. Takes the pin as a parameter so the gate is
/// KAT-testable against arbitrary pins.
fn verify_candidate(path: &Path, pin: &TorPin<'_>) -> Result<VerifiedTorBinary, TorBinaryError> {
    let canonical = std::fs::canonicalize(path).map_err(|e| io_error(path, &e))?;
    let meta = std::fs::metadata(&canonical).map_err(|e| io_error(&canonical, &e))?;
    // Refuse non-regular files *before* opening: a FIFO would block the read
    // forever; a directory would yield a bare EISDIR.
    if !meta.is_file() {
        return Err(TorBinaryError::NotAFile(canonical));
    }
    // A canonical path to a regular file always has a parent; the fallback is
    // unreachable and refuses rather than guessing a directory.
    let Some(dir) = canonical.parent().map(Path::to_path_buf) else {
        return Err(TorBinaryError::NotAFile(canonical));
    };
    // Where the launcher names this directory to the loader, the name has to
    // mean this directory and no other.
    if cfg!(target_os = "linux") && !loader_reads_as_one_directory(&dir) {
        return Err(TorBinaryError::UnsafeLoaderPath(dir));
    }

    // Exact contents, by allowlist. `symlink_metadata` on purpose: a pinned
    // name that is a symlink would pass a name check while the loader followed
    // it out of the directory, and a subdirectory is somewhere the loader
    // looks before the directory itself. A slot is the index into
    // `pin.files`; two directory entries that fold onto one slot are one
    // name too many.
    let mut paths_by_slot: Vec<Option<PathBuf>> = vec![None; pin.files.len()];
    for entry in std::fs::read_dir(&dir).map_err(|e| io_error(&dir, &e))? {
        let entry = entry.map_err(|e| io_error(&dir, &e))?;
        let name = entry.file_name();
        let Some(slot) = pin.file_index(&name) else {
            return Err(TorBinaryError::UnexpectedEntry { dir, name });
        };
        let entry_path = entry.path();
        let entry_meta =
            std::fs::symlink_metadata(&entry_path).map_err(|e| io_error(&entry_path, &e))?;
        if !entry_meta.is_file() {
            return Err(TorBinaryError::NotAFile(entry_path));
        }
        if paths_by_slot[slot].is_some() {
            return Err(TorBinaryError::UnexpectedEntry { dir, name });
        }
        paths_by_slot[slot] = Some(entry_path);
    }
    let paths_by_slot = paths_by_slot
        .into_iter()
        .enumerate()
        .map(|(slot, path)| {
            path.ok_or_else(|| TorBinaryError::MissingFile {
                dir: dir.clone(),
                name: pin.files[slot].name,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // The candidate must be the executable, not merely something pinned.
    let is_the_executable = canonical
        .file_name()
        .is_some_and(|name| pin.names_match(name, pin.executable));
    if !is_the_executable {
        return Err(TorBinaryError::NotTheExecutable(canonical));
    }
    // Refuse a non-executable candidate here, where the error can say why —
    // at spawn it is a content-free `ControlError::Spawn` and tor never runs,
    // so its own log (the designated diagnosis channel) is never written.
    if !is_executable(&canonical) {
        return Err(TorBinaryError::NotExecutable(canonical));
    }

    // One-shot read + digest per file, once at setup. `fs::read` retries
    // `ErrorKind::Interrupted` internally (unlike a hand-rolled read loop).
    for (pinned, entry_path) in pin.files.iter().zip(paths_by_slot) {
        let bytes = std::fs::read(&entry_path).map_err(|e| io_error(&entry_path, &e))?;
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if actual != pinned.sha256 {
            return Err(TorBinaryError::HashMismatch {
                path: entry_path,
                expected: pinned.sha256,
                actual,
            });
        }
    }
    Ok(VerifiedTorBinary {
        path: canonical,
        library_dir: dir,
    })
}

#[cfg(test)]
#[path = "binary_tests.rs"]
mod tests;
