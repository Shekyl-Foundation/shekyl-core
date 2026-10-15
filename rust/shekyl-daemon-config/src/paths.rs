// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The default paths (`DAEMON_CONFIG_CUTOVER.md` §2.4, §2.5; IG-13).
//!
//! On Linux, FreeBSD and macOS the configuration file lives under
//! `/etc/shekyl/` and the data and log defaults under the account's root,
//! the passwd home plus `.shekyl`. On Windows the run mode selects one root
//! and every default derives from it: the per-account `LocalAppData\Shekyl`
//! for a run-as-user daemon, `%ProgramData%\shekyl\` with `service`, which
//! only the installer creates.

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
            .map(|pd| pd.join("shekyl"))
            .ok_or_else(|| {
                Diagnostic::new(Code::ServiceRoot, Source::Machine)
                    .option(option)
                    .param("path", "%ProgramData%")
                    .param("found", "no machine-wide data root is reported")
            }),
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
    use super::*;

    fn platform() -> Platform {
        Platform {
            home: Some(PathBuf::from("/home/op")),
            program_data: None,
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
