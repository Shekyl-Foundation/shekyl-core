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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TorPin {
    /// Tor Expert Bundle version the files were extracted from.
    pub bundle_version: &'static str,
    /// The Expert Bundle's target label for this build target (the suffix of
    /// the upstream tarball name, e.g. `linux-x86_64`). Provenance like the
    /// versions, plus one runtime use: composing the version-exact system
    /// directory `/opt/shekyl/<bundle_version>-<bundle_target>/`.
    pub bundle_target: &'static str,
    /// The `tor` version inside that bundle.
    pub tor_version: &'static str,
    /// The name of the `tor` executable among [`Self::files`].
    pub executable: &'static str,
    /// Whether file names in tor's directory are compared without regard to
    /// ASCII case. True on Windows, where `VERSION.DLL` and `version.dll` are
    /// one file to the loader, so the allowlist has to treat them as one name.
    pub case_insensitive_names: bool,
    /// **Every** file tor's directory holds. The directory holding anything
    /// else is a refusal, not a warning.
    pub files: &'static [PinnedFile],
}

impl TorPin {
    fn names_match(&self, found: &OsStr, pinned: &str) -> bool {
        match found.to_str() {
            Some(found) if self.case_insensitive_names => found.eq_ignore_ascii_case(pinned),
            Some(found) => found == pinned,
            // A name that is not Unicode is not one of ours.
            None => false,
        }
    }

    fn pinned(&self, found: &OsStr) -> Option<&PinnedFile> {
        self.files.iter().find(|f| self.names_match(found, f.name))
    }
}

/// What Shekyl does about Tor on a build target. There is no third state: a
/// target is pinned, or it has been ruled out with a reason, and a target with
/// no row in `config/tor_pins.json` does not compile (`build.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorDisposition {
    /// Shekyl ships and launches this exact bundle.
    Pinned(TorPin),
    /// Shekyl does not manage a tor on this target. The operator runs their
    /// own and attaches it; `reason` is the sentence shown to them.
    Unavailable {
        /// Why there is no managed tor here.
        reason: &'static str,
    },
}

/// The disposition for the current build target, compiled from
/// `config/tor_pins.json` by `build.rs`.
pub const CURRENT_DISPOSITION: TorDisposition =
    include!(concat!(env!("OUT_DIR"), "/tor_disposition.rs"));

/// The pin for this build target, or the typed reason there is none.
fn current_pin() -> Result<TorPin, TorBinaryError> {
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
fn well_known_candidate(pin: &TorPin) -> Option<PathBuf> {
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
/// directory is that path's parent, computed once. The launcher reads both
/// from here: the bytes hashed, the path spawned and the directory the loader
/// is pointed at cannot name different places.
#[derive(Debug, Clone)]
pub struct VerifiedTorBinary {
    path: PathBuf,
    library_dir: Option<PathBuf>,
}

impl VerifiedTorBinary {
    /// The verified, canonical path — for the spawn site.
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// The directory the verified `tor` lives in, whose contents the gate
    /// checked — the one directory the launcher may name to the loader.
    /// `None` only for a test witness whose directory the loader could not be
    /// given by name (no absolute parent, or a path it would read as a list).
    pub fn library_dir(&self) -> Option<&Path> {
        self.library_dir.as_deref()
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
        let library_dir = path
            .parent()
            .filter(|dir| loader_reads_as_one_directory(dir))
            .map(Path::to_path_buf);
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
pub(crate) fn loader_reads_as_one_directory(dir: &Path) -> bool {
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
fn verify_candidate(path: &Path, pin: &TorPin) -> Result<VerifiedTorBinary, TorBinaryError> {
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
    // looks before the directory itself.
    let mut present: Vec<(&PinnedFile, PathBuf)> = Vec::with_capacity(pin.files.len());
    for entry in std::fs::read_dir(&dir).map_err(|e| io_error(&dir, &e))? {
        let entry = entry.map_err(|e| io_error(&dir, &e))?;
        let name = entry.file_name();
        let Some(pinned) = pin.pinned(&name) else {
            return Err(TorBinaryError::UnexpectedEntry { dir, name });
        };
        let entry_path = entry.path();
        let entry_meta =
            std::fs::symlink_metadata(&entry_path).map_err(|e| io_error(&entry_path, &e))?;
        if !entry_meta.is_file() {
            return Err(TorBinaryError::NotAFile(entry_path));
        }
        // Two entries folding to one pinned name (a case-sensitive directory
        // read under a case-insensitive rule) are one name too many.
        if present.iter().any(|(seen, _)| std::ptr::eq(*seen, pinned)) {
            return Err(TorBinaryError::UnexpectedEntry { dir, name });
        }
        present.push((pinned, entry_path));
    }
    if let Some(missing) = pin
        .files
        .iter()
        .find(|f| !present.iter().any(|(seen, _)| std::ptr::eq(*seen, *f)))
    {
        return Err(TorBinaryError::MissingFile {
            dir,
            name: missing.name,
        });
    }

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
    for (pinned, entry_path) in present {
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
        library_dir: Some(dir),
    })
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

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// A pin over `(name, contents)` pairs, the first being the executable.
    /// Leaked, because a pin is `'static` data in production and a test's
    /// handful of bytes is not worth a second, borrowed, shape of the type.
    fn pin_for(files: &[(&'static str, &[u8])], case_insensitive_names: bool) -> TorPin {
        let pinned: Vec<PinnedFile> = files
            .iter()
            .map(|(name, bytes)| PinnedFile {
                name,
                sha256: sha256(bytes),
            })
            .collect();
        TorPin {
            bundle_version: "0.0.0",
            bundle_target: "test-target",
            tor_version: "0.0.0.0",
            executable: files[0].0,
            case_insensitive_names,
            files: Box::leak(pinned.into_boxed_slice()),
        }
    }

    /// The Linux shape of a bundle: `tor` and three libraries.
    const LINUX_FILES: [(&str, &[u8]); 4] = [
        ("tor", b"tor"),
        ("libevent-2.1.so.7", b"libevent"),
        ("libssl.so.3", b"libssl"),
        ("libcrypto.so.3", b"libcrypto"),
    ];

    /// Lay `files` out in a fresh directory as a correctly staged bundle and
    /// return the directory and the path of its executable.
    fn staged(files: &[(&'static str, &[u8])]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        for (i, (name, bytes)) in files.iter().enumerate() {
            let path = dir.path().join(name);
            if i == 0 {
                write_executable(&path, bytes);
            } else {
                std::fs::write(&path, bytes).unwrap();
            }
        }
        let exe = dir.path().join(files[0].0);
        (dir, exe)
    }

    #[test]
    fn verify_matches_the_empty_input_sha256_vector() {
        let (dir, exe) = staged(&[("tor", b"")]);
        let pin = TorPin {
            files: Box::leak(Box::new([PinnedFile {
                name: "tor",
                sha256: EMPTY_SHA256,
            }])),
            ..pin_for(&[("tor", b"")], false)
        };
        let verified = verify_candidate(&exe, &pin).unwrap();
        // The witness carries the canonical form of the verified path, and
        // its directory.
        assert_eq!(verified.as_path(), exe.canonicalize().unwrap());
        assert_eq!(
            verified.library_dir(),
            Some(dir.path().canonicalize().unwrap().as_path())
        );
    }

    #[test]
    fn verify_accepts_a_correctly_staged_bundle() {
        let (_dir, exe) = staged(&LINUX_FILES);
        assert!(verify_candidate(&exe, &pin_for(&LINUX_FILES, false)).is_ok());
    }

    /// The gate rejects a single flipped byte **in any pinned file**, not only
    /// in `tor`, and the mismatch carries both digests so a bad pin bump is
    /// self-diagnosing.
    #[test]
    fn verify_rejects_a_tampered_byte_in_any_pinned_file() {
        let pin = pin_for(&LINUX_FILES, false);
        for (name, original) in LINUX_FILES {
            let (dir, exe) = staged(&LINUX_FILES);
            let mut tampered = original.to_vec();
            *tampered.last_mut().unwrap() ^= 1;
            let victim = dir.path().join(name);
            // Rewrite in place, keeping the mode.
            let mode = std::fs::metadata(&victim).unwrap().permissions();
            std::fs::write(&victim, &tampered).unwrap();
            std::fs::set_permissions(&victim, mode).unwrap();
            match verify_candidate(&exe, &pin) {
                Err(TorBinaryError::HashMismatch {
                    path,
                    expected,
                    actual,
                }) => {
                    assert_eq!(path, victim.canonicalize().unwrap(), "{name}");
                    assert_eq!(expected, sha256(original), "{name}");
                    assert_eq!(actual, sha256(&tampered), "{name}");
                }
                other => panic!("{name}: expected HashMismatch, got {other:?}"),
            }
        }
    }

    /// Every refusal is a sentence an operator reads in a log line. A string
    /// continuation that swallowed its indentation renders as a run of spaces
    /// mid-sentence, and nothing else in the tree would notice.
    #[test]
    fn refusals_render_as_single_spaced_sentences() {
        let path = PathBuf::from("/x/tor");
        let errors = [
            TorBinaryError::Unavailable { reason: "r" },
            TorBinaryError::NotFound,
            TorBinaryError::NotAFile(path.clone()),
            TorBinaryError::NotExecutable(path.clone()),
            TorBinaryError::NotTheExecutable(path.clone()),
            TorBinaryError::Io {
                path: path.clone(),
                kind: std::io::ErrorKind::NotFound,
            },
            TorBinaryError::UnexpectedEntry {
                dir: PathBuf::from("/x"),
                name: OsString::from("libz.so.1"),
            },
            TorBinaryError::MissingFile {
                dir: PathBuf::from("/x"),
                name: "tor",
            },
            TorBinaryError::UnsafeLoaderPath(PathBuf::from("/x:y")),
            TorBinaryError::HashMismatch {
                path,
                expected: [0; 32],
                actual: [1; 32],
            },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(!text.contains("  "), "{text:?}");
            assert!(!text.is_empty());
        }
    }

    // --- TB-7 part 3: the directory holds the pinned files and nothing else.
    // Three plants, each of which a loader pointed at this directory would
    // have used (TOR_BUNDLE_DISTRIBUTION.md §2 findings 10 to 12). ---

    /// A file at the top level that the pin does not list. `libz.so.1` is the
    /// library `tor` needs and the bundle does not carry.
    #[test]
    fn verify_refuses_a_planted_top_level_file() {
        let (dir, exe) = staged(&LINUX_FILES);
        std::fs::write(dir.path().join("libz.so.1"), b"planted").unwrap();
        match verify_candidate(&exe, &pin_for(&LINUX_FILES, false)) {
            Err(TorBinaryError::UnexpectedEntry { name, .. }) => {
                assert_eq!(name, OsString::from("libz.so.1"));
            }
            other => panic!("expected UnexpectedEntry, got {other:?}"),
        }
    }

    /// glibc searches `glibc-hwcaps/<level>/` under a library-path entry
    /// before the entry itself. A listing of the top level shows a directory
    /// and no library; a scan for library names passes it. The allowlist does
    /// not, because the directory is not a pinned file.
    #[test]
    fn verify_refuses_a_planted_glibc_hwcaps_library() {
        let (dir, exe) = staged(&LINUX_FILES);
        let hwcaps = dir.path().join("glibc-hwcaps").join("x86-64-v2");
        std::fs::create_dir_all(&hwcaps).unwrap();
        std::fs::write(hwcaps.join("libz.so.1"), b"planted").unwrap();
        match verify_candidate(&exe, &pin_for(&LINUX_FILES, false)) {
            Err(TorBinaryError::UnexpectedEntry { name, .. }) => {
                assert_eq!(name, OsString::from("glibc-hwcaps"));
            }
            other => panic!("expected UnexpectedEntry, got {other:?}"),
        }
    }

    /// Windows searches the executable's directory first and treats
    /// `VERSION.DLL` and `version.dll` as one name. The Windows pin lists
    /// `tor.exe` alone, so either spelling beside it is refused — and under
    /// the same rule `TOR.EXE` *is* the pinned executable, which is what shows
    /// the comparison is by folded name and not a refusal of everything.
    #[test]
    fn verify_refuses_a_planted_version_dll_under_the_windows_name_rule() {
        let files: [(&str, &[u8]); 1] = [("tor.exe", b"tor")];
        let pin = pin_for(&files, true);

        for planted in ["VERSION.DLL", "version.dll"] {
            let (dir, exe) = staged(&files);
            std::fs::write(dir.path().join(planted), b"planted").unwrap();
            match verify_candidate(&exe, &pin) {
                Err(TorBinaryError::UnexpectedEntry { name, .. }) => {
                    assert_eq!(name, OsString::from(planted));
                }
                other => panic!("{planted}: expected UnexpectedEntry, got {other:?}"),
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path().join("TOR.EXE");
        write_executable(&upper, b"tor");
        assert!(verify_candidate(&upper, &pin).is_ok());
    }

    /// The case rule is the platform's, not a blanket one: where names are
    /// case-sensitive, a differently-cased name is a different, unpinned file.
    #[test]
    fn verify_compares_names_exactly_where_the_platform_does() {
        let files: [(&str, &[u8]); 1] = [("tor", b"tor")];
        let dir = tempfile::tempdir().unwrap();
        let upper = dir.path().join("TOR");
        write_executable(&upper, b"tor");
        assert!(matches!(
            verify_candidate(&upper, &pin_for(&files, false)),
            Err(TorBinaryError::UnexpectedEntry { .. })
        ));
    }

    /// The first thing a developer tries: `SHEKYL_TOR_BINARY` pointed at the
    /// `tor` inside a full extracted Expert Bundle. Its directory carries
    /// `pluggable_transports/`, and the override tier is gated like any other.
    #[test]
    fn verify_refuses_a_full_extracted_bundle_through_the_override() {
        let (dir, exe) = staged(&LINUX_FILES);
        let transports = dir.path().join("pluggable_transports");
        std::fs::create_dir(&transports).unwrap();
        std::fs::write(transports.join("lyrebird"), b"transport").unwrap();

        let chosen = candidate_from(Some(exe.clone().into_os_string()), None, None, "tor")
            .expect("the override is the candidate");
        match verify_candidate(&chosen, &pin_for(&LINUX_FILES, false)) {
            Err(TorBinaryError::UnexpectedEntry { name, .. }) => {
                assert_eq!(name, OsString::from("pluggable_transports"));
            }
            other => panic!("expected UnexpectedEntry, got {other:?}"),
        }
    }

    /// A pinned name that is a symlink is refused even when it points at the
    /// right bytes: the loader would follow it out of the checked directory.
    #[cfg(unix)]
    #[test]
    fn verify_refuses_a_symlinked_entry_in_the_directory() {
        let (dir, exe) = staged(&LINUX_FILES);
        let outside = tempfile::tempdir().unwrap();
        let real = outside.path().join("libssl.so.3");
        std::fs::write(&real, b"libssl").unwrap();
        let link = dir.path().join("libssl.so.3");
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            verify_candidate(&exe, &pin_for(&LINUX_FILES, false)),
            Err(TorBinaryError::NotAFile(_))
        ));
    }

    /// `LD_LIBRARY_PATH` is a list. A bundle that is correct in every file
    /// but lives under a name the loader would split or expand is refused on
    /// Linux, where the launcher sets that variable: with `a:b` in the path
    /// the loader would search two directories, neither the one checked.
    #[cfg(target_os = "linux")]
    #[test]
    fn verify_refuses_a_directory_the_loader_would_read_as_a_list() {
        for odd in ["a:b", "a;b", "$ORIGIN", "x${LIB}"] {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join(odd);
            std::fs::create_dir(&dir).unwrap();
            for (i, (name, bytes)) in LINUX_FILES.iter().enumerate() {
                if i == 0 {
                    write_executable(&dir.join(name), bytes);
                } else {
                    std::fs::write(dir.join(name), bytes).unwrap();
                }
            }
            assert_eq!(
                verify_candidate(&dir.join("tor"), &pin_for(&LINUX_FILES, false)).unwrap_err(),
                TorBinaryError::UnsafeLoaderPath(dir.canonicalize().unwrap()),
                "{odd}"
            );
        }
    }

    #[test]
    fn loader_path_rule_accepts_ordinary_directories_only() {
        for ok in [
            "/opt/shekyl/15.0.24-linux-x86_64",
            "/srv/My Name/shekyl/tor",
        ] {
            assert!(loader_reads_as_one_directory(Path::new(ok)), "{ok}");
        }
        for bad in [
            "/opt/a:b",
            "/opt/a;b",
            "/opt/$ORIGIN/tor",
            "relative/tor",
            "",
        ] {
            assert!(!loader_reads_as_one_directory(Path::new(bad)), "{bad}");
        }
    }

    #[test]
    fn verify_refuses_a_directory_missing_a_pinned_file() {
        let (dir, exe) = staged(&LINUX_FILES);
        std::fs::remove_file(dir.path().join("libevent-2.1.so.7")).unwrap();
        assert_eq!(
            verify_candidate(&exe, &pin_for(&LINUX_FILES, false)).unwrap_err(),
            TorBinaryError::MissingFile {
                dir: dir.path().canonicalize().unwrap(),
                name: "libevent-2.1.so.7",
            }
        );
    }

    /// An override naming one of the libraries is in a pinned directory but is
    /// not what gets executed.
    #[test]
    fn verify_refuses_a_pinned_file_that_is_not_the_executable() {
        let (dir, _exe) = staged(&LINUX_FILES);
        assert!(matches!(
            verify_candidate(
                &dir.path().join("libssl.so.3"),
                &pin_for(&LINUX_FILES, false)
            ),
            Err(TorBinaryError::NotTheExecutable(_))
        ));
    }

    /// A missing candidate is a NotFound-kind `Io`, not a false pass.
    #[test]
    fn verify_missing_file_is_io_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert!(matches!(
            verify_candidate(&missing, &pin_for(&LINUX_FILES, false)),
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
            verify_candidate(dir.path(), &pin_for(&LINUX_FILES, false)),
            Err(TorBinaryError::NotAFile(_))
        ));
    }

    /// A readable but non-executable candidate is refused with a curated error
    /// — at spawn it would be a content-free failure tor never gets to log.
    #[cfg(unix)]
    #[test]
    fn verify_non_executable_is_refused() {
        let (dir, exe) = staged(&LINUX_FILES);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            verify_candidate(&exe, &pin_for(&LINUX_FILES, false)).unwrap_err(),
            TorBinaryError::NotExecutable(dir.path().canonicalize().unwrap().join("tor"))
        );
    }

    /// One path, checked and used. Reached through a symlinked directory (an
    /// install directory that is a link to the versioned one), the witness
    /// names the **target** for both the executable and the library
    /// directory — so what the loader is pointed at is what was checked.
    #[cfg(unix)]
    #[test]
    fn verify_through_a_symlinked_directory_checks_and_uses_the_target() {
        let (dir, _exe) = staged(&LINUX_FILES);
        let links = tempfile::tempdir().unwrap();
        let link = links.path().join("current");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();

        let real_dir = dir.path().canonicalize().unwrap();
        let verified = verify_candidate(&link.join("tor"), &pin_for(&LINUX_FILES, false)).unwrap();
        assert_eq!(verified.as_path(), real_dir.join("tor"));
        assert_eq!(verified.library_dir(), Some(real_dir.as_path()));

        // And the check is of the target: a plant there is seen through the link.
        std::fs::write(dir.path().join("libz.so.1"), b"planted").unwrap();
        assert!(matches!(
            verify_candidate(&link.join("tor"), &pin_for(&LINUX_FILES, false)),
            Err(TorBinaryError::UnexpectedEntry { .. })
        ));
    }

    /// A candidate that is itself a symlink resolves to its target, and it is
    /// the **target's** directory that must hold exactly the pinned files.
    #[cfg(unix)]
    #[test]
    fn verify_canonicalizes_a_symlinked_candidate() {
        let (dir, exe) = staged(&LINUX_FILES);
        let links = tempfile::tempdir().unwrap();
        let link = links.path().join("tor-link");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        let verified = verify_candidate(&link, &pin_for(&LINUX_FILES, false)).unwrap();
        assert_eq!(verified.as_path(), exe.canonicalize().unwrap());
        assert_eq!(
            verified.library_dir(),
            Some(dir.path().canonicalize().unwrap().as_path())
        );
    }

    // --- candidate_from precedence KATs (the load-bearing selection policy,
    // testable without touching process-global env). ---

    /// Stage an executable at `<dir>/tor/tor`, the beside-the-executable
    /// layout of an unpacked archive.
    fn beside(dir: &Path) -> PathBuf {
        let tor_dir = dir.join(BESIDE_TOR_DIR);
        std::fs::create_dir(&tor_dir).unwrap();
        let exe = tor_dir.join("tor");
        write_executable(&exe, b"beside");
        exe
    }

    #[test]
    fn candidate_override_wins_even_over_an_existing_beside_binary() {
        let dir = tempfile::tempdir().unwrap();
        beside(dir.path());
        let chosen = candidate_from(
            Some(OsString::from("/explicit/override/tor")),
            Some(dir.path()),
            None,
            "tor",
        );
        // The override is returned verbatim — even though it does not exist —
        // so a typo surfaces as *its* error, never a silent fallback.
        assert_eq!(chosen, Some(PathBuf::from("/explicit/override/tor")));
    }

    #[test]
    fn candidate_empty_override_is_treated_as_unset() {
        let dir = tempfile::tempdir().unwrap();
        let exe = beside(dir.path());
        let chosen = candidate_from(Some(OsString::new()), Some(dir.path()), None, "tor");
        assert_eq!(chosen, Some(exe));
    }

    /// Tier 2 is `<exe_dir>/tor/tor`. A `tor` file directly beside the
    /// executable — the layout before the bundle had a directory of its own —
    /// is not a candidate: its directory is the executable's and could never
    /// hold exactly the pinned files.
    #[test]
    fn candidate_beside_is_the_tor_directory_not_a_tor_file() {
        let dir = tempfile::tempdir().unwrap();
        write_executable(&dir.path().join("tor"), b"flat");
        assert_eq!(candidate_from(None, Some(dir.path()), None, "tor"), None);

        let dir = tempfile::tempdir().unwrap();
        let exe = beside(dir.path());
        assert_eq!(
            candidate_from(None, Some(dir.path()), None, "tor"),
            Some(exe)
        );
    }

    /// The system tier is consulted when nothing is beside the executable, and
    /// a beside bundle displaces it.
    #[test]
    fn candidate_well_known_yields_to_beside() {
        let wk_dir = tempfile::tempdir().unwrap();
        let wk = wk_dir.path().join("tor");
        write_executable(&wk, b"staged");

        let empty_beside = tempfile::tempdir().unwrap();
        let chosen = candidate_from(None, Some(empty_beside.path()), Some(&wk), "tor");
        assert_eq!(chosen, Some(wk.clone()));

        let beside_dir = tempfile::tempdir().unwrap();
        let exe = beside(beside_dir.path());
        let chosen = candidate_from(None, Some(beside_dir.path()), Some(&wk), "tor");
        assert_eq!(chosen, Some(exe));
    }

    /// The system candidate is version-exact, composed from the pin's own
    /// labels — the layout contract with packaging (`/opt/shekyl/
    /// <bundle_version>-<bundle_target>/tor`), pinned here so a layout drift
    /// fails a test instead of silently never matching an installed bundle.
    #[cfg(unix)]
    #[test]
    fn well_known_candidate_is_version_exact_from_the_pin() {
        let pin = TorPin {
            bundle_version: "15.0.24",
            bundle_target: "linux-x86_64",
            ..pin_for(&LINUX_FILES, false)
        };
        assert_eq!(
            well_known_candidate(&pin),
            Some(PathBuf::from("/opt/shekyl/15.0.24-linux-x86_64/tor"))
        );
    }

    /// There is no `PATH` tier (TB-8): with nothing in the three tiers the
    /// answer is "none", whatever `PATH` holds. `candidate_from` takes no
    /// `PATH` argument, so this is the absence stated as a test rather than
    /// left to be inferred from a signature.
    #[test]
    fn candidate_none_when_nothing_is_found() {
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(candidate_from(None, Some(empty.path()), None, "tor"), None);
    }

    /// The compiled disposition is self-consistent: a pinned target's
    /// executable is among its files and no two files fold to one name. (The
    /// build script refuses a pin file that breaks these; this reads the
    /// constant the binary actually carries.)
    #[test]
    fn compiled_disposition_is_well_formed() {
        match CURRENT_DISPOSITION {
            TorDisposition::Pinned(pin) => {
                assert!(pin.files.iter().any(|f| f.name == pin.executable));
                for (i, a) in pin.files.iter().enumerate() {
                    for b in &pin.files[i + 1..] {
                        assert!(!a.name.eq_ignore_ascii_case(b.name));
                    }
                }
            }
            TorDisposition::Unavailable { reason } => assert!(!reason.trim().is_empty()),
        }
        assert_eq!(TOR_SIGNING_KEY_FPR.len(), 40);
    }

    /// On a target we ship a managed tor for, the disposition must be
    /// `Pinned` (so `discover_and_verify` can only fail on discovery or
    /// verification, never on `Unavailable`). Guards against a row being
    /// flipped in `config/tor_pins.json` without anyone meaning it.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn current_target_has_a_recorded_pin() {
        assert!(
            matches!(CURRENT_DISPOSITION, TorDisposition::Pinned(_)),
            "linux/x86_64 and linux/aarch64 must have a recorded tor pin"
        );
    }

    /// The recorded pin must match the *actual* bundle — the runtime guard for
    /// the pin-time obligation (checklist bump correctness). Ignored in the
    /// unit gate; the pin-verify lane (and the checklist re-verify step) runs
    /// it with `SHEKYL_TEST_PINNED_TOR_BINARY` pointing at the `tor` inside a
    /// directory staged by `scripts/release/tor_bundle.py` from the
    /// signature-verified Expert Bundle — a distinct variable from the any-tor
    /// `SHEKYL_TEST_TOR_BINARY` the lifecycle tests use, so the two contracts
    /// cannot collide. Deliberately NOT `cfg`-gated: on a target with no pin it
    /// fails loudly instead of compiling out and letting the checklist's
    /// re-verify step pass with zero tests run.
    #[test]
    #[ignore = "requires the pinned Tor via SHEKYL_TEST_PINNED_TOR_BINARY"]
    fn bundled_tor_matches_recorded_pin() {
        let TorDisposition::Pinned(pin) = CURRENT_DISPOSITION else {
            panic!("this build target has no recorded pin — pin it before re-verifying");
        };
        let bin = std::env::var_os("SHEKYL_TEST_PINNED_TOR_BINARY").expect(
            "SHEKYL_TEST_PINNED_TOR_BINARY must point at the staged, pinned tor \
             (GPG-verified per the RELEASE_CHECKLIST procedure) on the pin-verify lane",
        );
        verify_candidate(Path::new(&bin), &pin).expect(
            "the staged bundle must match the recorded pin — if the bundle version changed, \
             re-run the full checklist procedure (GPG-verify first), never record a hash \
             from an unverified file",
        );
    }
}
