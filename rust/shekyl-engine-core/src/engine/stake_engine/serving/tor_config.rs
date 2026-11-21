// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Assemble this wallet's [`WalletTorControlConfig`].
//!
//! # Four rulings, recorded here because this is where they are visible
//!
//! `WalletTorControlConfig` has public fields, which makes it look like a settings
//! struct. It is not, and the organizing principle is that **every knob is a
//! fingerprint** — DQ-T0.7's argument about data-directory rotation (deviation
//! from defaults is itself a signature) generalizes to the whole surface. So the
//! default answer is derive-or-inherit, and exposure is justified only where the
//! operator holds information the wallet cannot.
//!
//! 1. **`data_dir` is derived, never configured** —
//!    [`tor_data_dir_from`](shekyl_engine_file::paths::tor_data_dir_from)
//!    gives DQ-T0.7's three placement requirements by construction, and
//!    forecloses the cross-wallet guard linkage a shared directory would create.
//! 2. **`binary` is discovery by default**, with one override, the serving
//!    host's `tor-file` option ([`TorFile`]) — the single item where the
//!    operator knows something the wallet cannot derive. It is an option of
//!    the process, never stored with a wallet: which Tor binary a machine has
//!    is the machine's. The hash gate runs either way.
//! 3. **`policy` gets no surface at all.** Backoff curve, `degrade_after`,
//!    `bootstrap_deadline` and `trust_retry` are all observable in retry
//!    timing, so an operator-tuned supervisor is a *distinguishable client*.
//!    The defaults are taken and pinned. This is the field most likely to
//!    acquire a knob by accident, precisely because it is a struct of public
//!    `Duration`s sitting right there.
//! 4. **`posture` is not a choice.** `PersonaServingHost::start` is the sole
//!    author of it (it overwrites whatever is passed), and vanguards are
//!    already ruled `Managed` for a serving persona and enforced by the sealed
//!    witness. `disable_network` is an offline-test knob and stays `false`.
//!
//! # The non-item, stated so nobody adds it
//!
//! **There is no serve-or-not toggle.** A staker with holdings that does not
//! serve accrues misses and eventually slashes, so serving is not a preference —
//! *the bond is the decision*. A configuration surface is exactly where someone
//! would add an "enable serving" checkbox, and it must not exist.
//!
//! # Operator-facing residual: two staking wallets on one machine
//!
//! Each derives its own directory, its own guards and its own tor process,
//! which is correct for isolation — but they are then two personas active from
//! one IP simultaneously. That is §10.9's co-activation at the *machine* level,
//! and no per-wallet mechanism can observe it, let alone prevent it. It is not
//! forced against here. **The recommended posture is one staking wallet per
//! machine (or per VM);** operators who want to serve several `P`s should serve
//! them from separate machines. Written down so it is a stated recommendation
//! rather than a discovered surprise.

use shekyl_tor_control_wallet::service::WalletTorControlConfig;

/// Why a staker could not be given a Tor configuration.
///
/// **Fail-closed, mirroring `wrap_and_start_pscan`.** A staker whose serving
/// path cannot be configured must not open, for the same reason a staker whose
/// P-scan state will not load must not open: holdings that are not served
/// accrue misses and end in a slash, and the operator cannot see it happening.
/// Opening with serving dark is opening into an accruing loss.
#[derive(Debug)]
pub enum TorConfigError {
    /// The derived `<P>.tor/` directory could not be created.
    DataDirUnusable {
        /// The path that could not be established.
        path: std::path::PathBuf,
        /// The underlying I/O failure.
        source: std::io::Error,
    },
    /// The directory exists but is group- or world-writable, so another user on
    /// this machine can tamper with the entry-guard state. DQ-T0.7 requires a
    /// wallet-controlled, non-world-writable placement; a directory that fails
    /// that is refused rather than tightened silently, because the wallet did
    /// not create it and does not know what else is relying on its mode.
    #[cfg(unix)]
    DataDirTooPermissive {
        /// The offending directory.
        path: std::path::PathBuf,
        /// Its current mode.
        mode: u32,
    },
}

impl std::fmt::Display for TorConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DataDirUnusable { path, source } => write!(
                f,
                "the wallet's Tor data directory {} could not be created: {source}",
                path.display()
            ),
            #[cfg(unix)]
            Self::DataDirTooPermissive { path, mode } => write!(
                f,
                "the wallet's Tor data directory {} is mode {mode:o}: it must not be \
                 group- or world-writable, because it holds this wallet's entry-guard \
                 identity",
                path.display()
            ),
        }
    }
}

impl std::error::Error for TorConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DataDirUnusable { source, .. } => Some(source),
            #[cfg(unix)]
            Self::DataDirTooPermissive { .. } => None,
        }
    }
}

/// The serving host's `tor-file` option, resolved once when the host reads
/// its options: the Tor binary serving runs, or discovery when unset.
///
/// A path that names no file on this machine is refused at start with its
/// remedy, never replaced by discovery, as the daemon's `tor-file` is
/// (`INPUT_GRAMMAR.md` IG-Q41; Rick, 2026-11-21): the option is the
/// machine's, so a missing file is a typo or a removed install, and serving
/// a different binary than the one named would hide it. A path naming a file
/// is taken, and the hash gate still decides whether it runs.
#[derive(Clone, Debug, Default)]
pub struct TorFile(Option<std::path::PathBuf>);

/// A `tor-file` that names no file on this machine.
#[derive(Debug)]
pub struct TorFileMissing(std::path::PathBuf);

impl std::fmt::Display for TorFileMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tor-file {} names no file on this machine: point it at the Tor binary here, \
             or remove the option to use the bundled one",
            self.0.display()
        )
    }
}

impl std::error::Error for TorFileMissing {}

impl TorFile {
    /// Unset: discovery.
    #[must_use]
    pub fn discover() -> Self {
        Self(None)
    }

    /// The option as given: `None` is discovery; a path naming a file is that
    /// file.
    ///
    /// # Errors
    ///
    /// [`TorFileMissing`] when the path names no file on this machine.
    pub fn from_option(path: Option<std::path::PathBuf>) -> Result<Self, TorFileMissing> {
        match path {
            None => Ok(Self(None)),
            Some(path) if path.is_file() => Ok(Self(Some(path))),
            Some(path) => Err(TorFileMissing(path)),
        }
    }

    /// The source serving's supervisor resolves and pin-checks.
    fn source(&self) -> shekyl_tor_control_wallet::service::TorBinarySource {
        use shekyl_tor_control_wallet::service::TorBinarySource;
        match &self.0 {
            None => TorBinarySource::Discover,
            Some(path) => TorBinarySource::At(path.clone()),
        }
    }
}

/// Assemble this wallet's [`WalletTorControlConfig`].
///
/// # Errors
///
/// [`TorConfigError`] when the derived directory cannot be created, or exists
/// with group/world-write permission. Both are fail-closed at open.
pub(crate) fn tor_service_config(
    wallet_state_path: &std::path::Path,
    tor_file: &TorFile,
) -> Result<WalletTorControlConfig, TorConfigError> {
    let data_dir = shekyl_engine_file::paths::tor_data_dir_from(wallet_state_path);
    establish_data_dir(&data_dir)?;

    Ok(WalletTorControlConfig {
        binary: tor_file.source(),
        data_dir,
        // Nothing subscribes to tor's async events in production: no call site
        // issues `SETEVENTS`, so the sink receives nothing at all. Named rather
        // than left as an anonymous dropped receiver.
        events: shekyl_tor_control_wallet::service::EventSink::unsubscribed(),
        // Ruling 3: taken, not exposed.
        policy: shekyl_tor_control_wallet::service::SupervisorPolicy::default(),
        disable_network: false,
        // Ruling 4: overwritten by `PersonaServingHost::start`, which is the
        // sole author. Passing `Client` asserts we are not the one choosing.
        posture: shekyl_tor_control_wallet::service::ServingPosture::Client,
    })
}

/// Create the derived directory **private**, or refuse a too-permissive
/// pre-existing one.
///
/// The two halves are deliberately different, and the distinction is ownership.
/// A directory this wallet creates is created at `0o700`: `create_dir_all`
/// honours the process umask, which on a typical box yields `0o775` — group
/// writable — so *not* setting the mode would leave every fresh wallet's
/// entry-guard state writable by the operator's group. A directory that was
/// already there is **refused rather than tightened**: the wallet did not create
/// it, and does not know what else is relying on its mode.
fn establish_data_dir(path: &std::path::Path) -> Result<(), TorConfigError> {
    let pre_existing = path.is_dir();
    std::fs::create_dir_all(path).map_err(|source| TorConfigError::DataDirUnusable {
        path: path.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if !pre_existing {
            // Ours, and freshly made: make it private rather than umask-shaped.
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
                |source| TorConfigError::DataDirUnusable {
                    path: path.to_path_buf(),
                    source,
                },
            )?;
        }
        let mode = std::fs::metadata(path)
            .map_err(|source| TorConfigError::DataDirUnusable {
                path: path.to_path_buf(),
                source,
            })?
            .permissions()
            .mode();
        // Group- or world-writable means another account on this machine can
        // tamper with the entry-guard state. Read access is a separate (and
        // disclosed) at-rest residual — tor's state file is plaintext by
        // DQ-T0.7 — so this checks the write bits, which are the ones that let
        // someone else *change* the guard set.
        if mode & 0o022 != 0 {
            return Err(TorConfigError::DataDirTooPermissive {
                path: path.to_path_buf(),
                mode: mode & 0o777,
            });
        }
    }
    #[cfg(not(unix))]
    let _ = pre_existing;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_tor_control_wallet::service::TorBinarySource;

    #[test]
    fn the_data_dir_is_derived_from_the_wallet_path_and_created() {
        let tmp = tempfile::tempdir().expect("tmp");
        let wallet = tmp.path().join("alice.wallet");
        let cfg = tor_service_config(&wallet, &TorFile::discover()).expect("config");
        assert_eq!(cfg.data_dir, tmp.path().join("alice.wallet.tor"));
        assert!(
            cfg.data_dir.is_dir(),
            "the directory is established at open"
        );
    }

    /// The linkage property, asserted rather than assumed: a shared directory
    /// would be a shared entry-guard set across two wallets.
    #[test]
    fn two_wallets_never_share_a_tor_directory() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a =
            tor_service_config(&tmp.path().join("one.wallet"), &TorFile::discover()).expect("a");
        let b =
            tor_service_config(&tmp.path().join("two.wallet"), &TorFile::discover()).expect("b");
        assert_ne!(a.data_dir, b.data_dir);
    }

    #[test]
    fn an_unset_option_means_discovery() {
        assert!(matches!(
            TorFile::from_option(None).expect("unset").source(),
            TorBinarySource::Discover
        ));
    }

    #[test]
    fn an_option_naming_a_file_is_taken() {
        let tmp = tempfile::tempdir().expect("tmp");
        let bin = tmp.path().join("tor");
        std::fs::write(&bin, b"not really tor, but it is a file").expect("write");
        // The hash gate runs on this later; the option selects *which*
        // candidate is gated, never whether it is.
        match TorFile::from_option(Some(bin.clone()))
            .expect("a file")
            .source()
        {
            TorBinarySource::At(p) => assert_eq!(p, bin),
            other => panic!("expected the option to be taken, got {other:?}"),
        }
    }

    /// An option naming no file on this machine refuses the start with its
    /// remedy; it is never replaced by discovery (IG-Q41, as the daemon's).
    #[test]
    fn an_option_naming_no_file_refuses_the_start_with_its_remedy() {
        let tmp = tempfile::tempdir().expect("tmp");
        let missing = tmp.path().join("no-such-tor");
        let refused = TorFile::from_option(Some(missing.clone()))
            .expect_err("a path naming no file is refused");
        let said = refused.to_string();
        assert!(said.contains(&missing.display().to_string()), "{said}");
        assert!(said.contains("point it at the Tor binary here"), "{said}");
        assert!(said.contains("remove the option"), "{said}");
    }

    #[test]
    fn the_supervisor_policy_is_taken_not_tuned() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cfg =
            tor_service_config(&tmp.path().join("w.wallet"), &TorFile::discover()).expect("config");
        // `SupervisorPolicy` is deliberately not `PartialEq` (it is a config,
        // not a value), so the assertion compares the fields whose *timing* is
        // observable — which is the property the ruling is about.
        let default = shekyl_tor_control_wallet::service::SupervisorPolicy::default();
        assert_eq!(cfg.policy.backoff_base, default.backoff_base);
        assert_eq!(cfg.policy.backoff_cap, default.backoff_cap);
        assert_eq!(cfg.policy.degrade_after, default.degrade_after);
        assert_eq!(cfg.policy.trust_retry, default.trust_retry);
        assert_eq!(cfg.policy.bootstrap_deadline, default.bootstrap_deadline);
        assert_eq!(cfg.policy.stable_reset, default.stable_reset);
        assert!(!cfg.disable_network, "offline-test knob, never production");
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_writable_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tmp");
        let wallet = tmp.path().join("loose.wallet");
        let dir = tmp.path().join("loose.wallet.tor");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod");

        // `WalletTorControlConfig` is not `Debug` (it holds an `EventSink`, a
        // forensic surface), so match rather than `expect_err`.
        match tor_service_config(&wallet, &TorFile::discover()) {
            Err(TorConfigError::DataDirTooPermissive { mode, .. }) => {
                assert_eq!(
                    mode & 0o022,
                    0o022,
                    "the group/world write bits are what fail"
                );
            }
            Err(other) => panic!("wrong refusal: {other:?}"),
            Ok(_) => panic!(
                "entry-guard state another account can rewrite must be refused, not \
                 tightened silently"
            ),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_private_directory_is_accepted() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("tight.wallet.tor");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(tor_service_config(&tmp.path().join("tight.wallet"), &TorFile::discover()).is_ok());
    }
}
