// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The default paths (`DAEMON_CONFIG_CUTOVER.md` §2.4, §2.5; IG-13).
//!
//! On Linux, FreeBSD and macOS the configuration file lives under
//! `/etc/shekyl/`. The run mode selects the root the data and log defaults
//! derive from: the account's own for a run-as-user daemon (the passwd home
//! plus `.shekyl`, or `LocalAppData\Shekyl` on Windows), and the service's
//! data home with `service`, a fixed root per platform that the service
//! manager or the installer creates and the daemon only checks
//! ([`check_service_data_home`]; Rick, 2026-11-14): `/var/lib/shekyl` on
//! Linux, `/var/db/shekyl` on FreeBSD and macOS, `%ProgramData%\shekyl` on
//! Windows.

use std::path::{Path, PathBuf};

use shekyl_options::{Code, Diagnostic, Source};

use crate::network::Network;
use crate::platform::{Platform, RunMode};

/// The daemon's root for this run mode, or the refusal when the account
/// has no home (`config.path.no-home`) or the service root is absent
/// (`config.service.root`).
///
/// # Errors
/// The typed refusal, naming the option it blocks.
pub fn root(platform: &Platform, mode: RunMode, option: &str) -> Result<PathBuf, Diagnostic> {
    match mode {
        RunMode::User => platform
            .home
            .as_deref()
            .map(|home| home.join(if cfg!(windows) { "Shekyl" } else { ".shekyl" }))
            .ok_or_else(|| Diagnostic::new(Code::PathNoHome, Source::Machine).option(option)),
        RunMode::Service => platform
            .program_data
            .as_deref()
            .map(|parent| parent.join("shekyl"))
            .ok_or_else(|| {
                Diagnostic::new(Code::ServiceRoot, Source::Machine)
                    .option(option)
                    .param(
                        "path",
                        if cfg!(windows) {
                            "%ProgramData%"
                        } else {
                            "(none)"
                        },
                    )
                    .param("found", "no machine-wide data root is reported")
            }),
    }
}

/// A service's data home, checked and never created (Rick, 2026-11-14): the
/// data directory when `data-dir` is given, otherwise the service's root.
/// It exists, it is not a link, it is owned by the daemon's account, its
/// mode is 0700, and the daemon is not root; otherwise the start refuses,
/// naming the condition (`config.service.root`). A run-as-user daemon is
/// not checked here. On Windows `service` is refused before the walk until
/// RT-W14 builds its dispatcher, and the installer's ACL is that slice's.
///
/// # Errors
///
/// `config.service.root`, naming the path and the condition that failed.
pub fn check_service_data_home(
    platform: &Platform,
    mode: RunMode,
    explicit_data_dir: Option<&Path>,
) -> Result<(), Diagnostic> {
    #[cfg(unix)]
    {
        check_service_data_home_as(
            platform,
            mode,
            explicit_data_dir,
            rustix::process::geteuid().as_raw(),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (platform, mode, explicit_data_dir);
        Ok(())
    }
}

/// [`check_service_data_home`] for the account `me`: the account is an
/// input, so each case is tested as the account it is about.
#[cfg(unix)]
fn check_service_data_home_as(
    platform: &Platform,
    mode: RunMode,
    explicit_data_dir: Option<&Path>,
    me: u32,
) -> Result<(), Diagnostic> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if mode != RunMode::Service {
        return Ok(());
    }
    let (home, option) = match explicit_data_dir {
        Some(dir) => (dir.to_path_buf(), "data-dir"),
        None => (root(platform, mode, "data-dir")?, "service"),
    };
    let shown = home.display().to_string();
    let refuse = |found: String| {
        Diagnostic::new(Code::ServiceRoot, Source::Machine)
            .option(option)
            .param("path", shown.clone())
            .param("found", found)
    };
    if me == 0 {
        return Err(refuse("the daemon runs as root".to_owned()));
    }
    let meta = std::fs::symlink_metadata(&home).map_err(|e| {
        refuse(match e.kind() {
            std::io::ErrorKind::NotFound => format!("{shown} does not exist"),
            _ => format!("{shown} cannot be read: {e}"),
        })
    })?;
    if meta.file_type().is_symlink() {
        return Err(refuse(format!("{shown} is a symbolic link")));
    }
    if !meta.is_dir() {
        return Err(refuse(format!("{shown} is not a directory")));
    }
    if meta.uid() != me {
        return Err(refuse(format!(
            "{shown} is owned by uid {}, not this account (uid {me})",
            meta.uid()
        )));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode != 0o700 {
        return Err(refuse(format!("{shown} has mode {mode:04o}, not 0700")));
    }
    Ok(())
}

/// The configuration file's default path for a network.
///
/// # Errors
/// On Windows, the root's refusal; never on Unix, where the path is fixed.
pub fn config_file_default(
    platform: &Platform,
    mode: RunMode,
    network: Network,
) -> Result<PathBuf, Diagnostic> {
    let file = format!("shekyld-{}.toml", network.name());
    if cfg!(windows) {
        Ok(root(platform, mode, "config-file")?.join(file))
    } else {
        Ok(Path::new("/etc/shekyl").join(file))
    }
}

/// The default data directory: the root and the network's subdirectory.
#[must_use]
pub fn data_dir_default(root: &Path, network: Network) -> PathBuf {
    match network.subdirectory() {
        Some(sub) => root.join(sub),
        None => root.to_path_buf(),
    }
}

/// The default log file: `logs/shekyld-<network>.log` under the root.
#[must_use]
pub fn log_file_default(root: &Path, network: Network) -> PathBuf {
    root.join("logs")
        .join(format!("shekyld-{}.log", network.name()))
}

#[cfg(test)]
mod tests {
    /// A service's data home is checked, never created, as its own account:
    /// each condition refuses with `config.service.root` naming it, and a
    /// run-as-user daemon is not checked. Red edit: drop the mode test, and
    /// the 0750 home is accepted.
    #[cfg(unix)]
    #[test]
    fn a_service_data_home_is_checked_and_never_created() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let parent = tempfile::tempdir().unwrap();
        let platform = Platform {
            program_data: Some(parent.path().to_path_buf()),
            ..Platform::default()
        };
        let home = parent.path().join("shekyl");
        let found = |r: Result<(), Diagnostic>| {
            let d = r.expect_err("refused");
            assert_eq!(d.code, Code::ServiceRoot);
            d.get("found").unwrap_or_default().to_owned()
        };
        let check = |explicit: Option<&Path>, uid| {
            check_service_data_home_as(&platform, RunMode::Service, explicit, uid)
        };

        assert!(found(check(None, 4242)).contains("does not exist"));
        assert!(!home.exists(), "the check created nothing");
        std::fs::create_dir(&home).unwrap();
        // An ordinary account's own home, whoever runs the tests: run as
        // root, the home is given to an ordinary uid.
        let me = std::fs::metadata(&home).unwrap().uid();
        let me = if me == 0 {
            std::os::unix::fs::chown(&home, Some(4242), None).unwrap();
            4242
        } else {
            me
        };
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(found(check(None, me)).contains("not 0700"));
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        check(None, me).expect("the service's own 0700 home");
        assert!(found(check(None, me + 1)).contains("owned by uid"));
        assert!(found(check(None, 0)).contains("runs as root"));

        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&home, &link).unwrap();
        assert!(found(check(Some(&link), me)).contains("symbolic link"));
        check(Some(&home), me).expect("an explicit data directory, checked the same way");

        check_service_data_home_as(&platform, RunMode::User, None, me)
            .expect("a run-as-user daemon is not checked here");
    }

    use super::*;

    fn platform() -> Platform {
        Platform {
            home: Some(PathBuf::from("/srv/op")),
            program_data: None,
            session_dir: None,
            service_rendezvous: None,
        }
    }

    #[test]
    fn the_root_is_the_account_home_and_no_home_refuses() {
        let r = root(&platform(), RunMode::User, "data-dir").unwrap();
        assert!(r.ends_with(if cfg!(windows) { "Shekyl" } else { ".shekyl" }));
        let d = root(&Platform::default(), RunMode::User, "data-dir").unwrap_err();
        assert_eq!(d.code, Code::PathNoHome);
        assert_eq!(d.option.as_deref(), Some("data-dir"));
    }

    #[test]
    fn the_service_root_is_program_data_or_a_refusal() {
        let d = root(&platform(), RunMode::Service, "log-file").unwrap_err();
        assert_eq!(d.code, Code::ServiceRoot);
        let p = Platform {
            home: None,
            program_data: Some(PathBuf::from("C:/ProgramData")),
            session_dir: None,
            service_rendezvous: None,
        };
        assert_eq!(
            root(&p, RunMode::Service, "log-file").unwrap(),
            PathBuf::from("C:/ProgramData/shekyl")
        );
    }

    #[test]
    fn defaults_follow_the_network() {
        let r = Path::new("/r");
        assert_eq!(data_dir_default(r, Network::Mainnet), PathBuf::from("/r"));
        assert_eq!(
            data_dir_default(r, Network::Testnet),
            PathBuf::from("/r/testnet")
        );
        assert_eq!(
            data_dir_default(r, Network::Regtest),
            PathBuf::from("/r/regtest")
        );
        assert_eq!(
            log_file_default(r, Network::Stagenet),
            PathBuf::from("/r/logs/shekyld-stagenet.log")
        );
        #[cfg(not(windows))]
        assert_eq!(
            config_file_default(&Platform::default(), RunMode::User, Network::Testnet).unwrap(),
            PathBuf::from("/etc/shekyl/shekyld-testnet.toml")
        );
    }
}
