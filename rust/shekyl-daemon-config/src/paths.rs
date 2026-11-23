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

#[cfg(unix)]
use crate::directory::{require_service_account, DirectoryFacts, OWNER_ONLY_DIR_MODE};
use crate::network::Network;
use shekyl_rpc_rendezvous::SERVICE_DATA_HOME;

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
            .map(shekyl_os_account::per_account_root_in)
            .ok_or_else(|| Diagnostic::new(Code::PathNoHome, Source::Machine).option(option)),
        RunMode::Service => platform
            .service_parent
            .as_deref()
            .map(|parent| parent.join(SERVICE_DATA_HOME))
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
/// naming the condition (`config.service.root`). In the default layout the
/// network's data directory `data_dir` inside the root, when it exists, is
/// [`shekyl_os_account::directory::account_alone`]: the fact the console
/// leg's bind and [`crate::Lock::creatable`] hold it to, so a set-id bit is
/// not a refusal and a directory another account can enter is. A missing
/// network directory passes; the start makes it. A run-as-user daemon is
/// not checked here. On Windows
/// `service` is refused before the walk until RT-W14 builds its dispatcher,
/// and the installer's ACL is that slice's.
///
/// # Errors
///
/// `config.service.root`, naming the path and the condition that failed.
pub fn check_service_data_home(
    platform: &Platform,
    mode: RunMode,
    explicit_data_dir: Option<&Path>,
    data_dir: &Path,
) -> Result<(), Diagnostic> {
    #[cfg(unix)]
    {
        check_service_data_home_as(
            platform,
            mode,
            explicit_data_dir,
            data_dir,
            rustix::process::geteuid().as_raw(),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (platform, mode, explicit_data_dir, data_dir);
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
    data_dir: &Path,
    me: u32,
) -> Result<(), Diagnostic> {
    if mode != RunMode::Service {
        return Ok(());
    }
    let (home, option) = match explicit_data_dir {
        Some(dir) => (dir.to_path_buf(), "data-dir"),
        None => (root(platform, mode, "data-dir")?, "service"),
    };
    let refuse = |path: &Path, found: String| {
        Diagnostic::new(Code::ServiceRoot, Source::Machine)
            .option(option)
            .param("path", path.display().to_string())
            .param("found", found)
    };
    require_service_account(me).map_err(|found| refuse(&home, found))?;
    service_owned(&home, me).map_err(|found| refuse(&home, found))?;
    // The network directory is the console's socket directory. It is the
    // account-alone fact, not the home's exact 0700: a set-id bit the home
    // refuses is not another account entering. Only a directory that is not
    // there yet passes unjudged; the start makes it 0700.
    if data_dir != home {
        match shekyl_os_account::directory::account_alone(data_dir, me) {
            Ok(_)
            | Err(shekyl_os_account::directory::AccountAloneFault::Walk(
                shekyl_os_account::directory::DirectoryFault::Missing,
            )) => {}
            Err(fault) => {
                return Err(refuse(
                    data_dir,
                    fault.clause(Some(&data_dir.display().to_string())),
                ));
            }
        }
    }
    Ok(())
}

/// `dir` is a directory, not a link, owned by `me`, mode 0700; otherwise the
/// clause naming what it is instead.
#[cfg(unix)]
fn service_owned(dir: &Path, me: u32) -> Result<(), String> {
    let shown = dir.display().to_string();
    let facts = DirectoryFacts::inspect(dir)
        .and_then(|facts| facts.require_owner(me))
        .map_err(|fault| fault.clause(Some(&shown)))?;
    if facts.is_owner_only_mode() {
        Ok(())
    } else {
        Err(format!(
            "{shown} has mode {:04o}, not {OWNER_ONLY_DIR_MODE:04o}",
            facts.mode()
        ))
    }
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
            service_parent: Some(parent.path().to_path_buf()),
            ..Platform::default()
        };
        let home = parent.path().join("shekyl");
        let found = |r: Result<(), Diagnostic>| {
            let d = r.expect_err("refused");
            assert_eq!(d.code, Code::ServiceRoot);
            d.get("found").unwrap_or_default().to_owned()
        };
        let network = home.join("testnet");
        let check = |explicit: Option<&Path>, uid| {
            let data_dir = explicit.map_or(network.as_path(), |dir| dir);
            check_service_data_home_as(&platform, RunMode::Service, explicit, data_dir, uid)
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

        check_service_data_home_as(&platform, RunMode::User, None, &network, me)
            .expect("a run-as-user daemon is not checked here");

        // The network's data directory in the default layout, held to the
        // console leg's account-alone fact: absent passes (the start makes
        // it 0700); a link, or a mode another account can enter, is named.
        // Set-id and the sticky bit are not that. Red edit: require exact
        // 0700, and the 2700 directory is refused.
        check(None, me).expect("no network directory yet");
        let elsewhere = parent.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &network).unwrap();
        let refused = check(None, me).expect_err("a linked network directory");
        assert_eq!(refused.get("path"), network.to_str());
        assert!(found(Err(refused)).contains("symbolic link"));
        std::fs::remove_file(&network).unwrap();
        std::fs::create_dir(&network).unwrap();
        // The home's account owns it, as the home was given above when the
        // tests run as root, so the mode is what this case judges.
        std::os::unix::fs::chown(&network, Some(me), None).unwrap();
        std::fs::set_permissions(&network, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(found(check(None, me)).contains("other accounts can enter"));
        for mode in [0o700, 0o2700, 0o1700] {
            std::fs::set_permissions(&network, std::fs::Permissions::from_mode(mode)).unwrap();
            check(None, me).expect("no other account can enter");
        }

        // A network directory that cannot be read is refused, never taken
        // for an absent one. Not as root, which reads through any mode. Red
        // edit: `symlink_metadata(..).is_ok()` in place of the `Missing` arm.
        if !rustix::process::geteuid().is_root() {
            let sealed = home.join("sealed");
            std::fs::create_dir(&sealed).unwrap();
            std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
            let unreadable = sealed.join("testnet");
            let refused =
                check_service_data_home_as(&platform, RunMode::Service, None, &unreadable, me);
            std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(found(refused).contains("cannot be read"));
        }
    }

    use super::*;

    fn platform() -> Platform {
        Platform {
            home: Some(PathBuf::from("/srv/op")),
            service_parent: None,
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
    fn the_service_root_is_the_service_parent_or_a_refusal() {
        let d = root(&platform(), RunMode::Service, "log-file").unwrap_err();
        assert_eq!(d.code, Code::ServiceRoot);
        let p = Platform {
            home: None,
            service_parent: Some(PathBuf::from("C:/ProgramData")),
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
