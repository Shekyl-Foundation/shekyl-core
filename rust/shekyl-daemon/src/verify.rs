// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The configuration check (`INPUT_GRAMMAR.md` IG-Q58…IG-Q62).
//!
//! [`walk`] asks every refusal a start makes before it creates anything,
//! and creates nothing. [`accept`] prints the verdict. Start
//! ([`crate::run::main`]) calls the walk and, when the operator did not ask
//! for the check, performs the effects the walk withheld. The questions
//! stay beside those effects; this module is the order and the printing.

use std::path::Path;

use shekyl_daemon_config::sections::{log_location_creatable, DaemonConfig, Tor};
use shekyl_daemon_config::{account, announce, marker, resolve, Lock, TABLE};
use shekyl_options::{Code, Diagnostic, Source, Value};

use crate::run::{tell, Host};

/// What the walk found: the network id a start needs, and the warnings
/// that change no verdict (the Tor pin's, IG-Q59).
pub(crate) struct Walked {
    pub(crate) network_id: [u8; 16],
    pub(crate) warnings: Vec<String>,
}

/// Why the walk stopped: a refusal (`refuse`, exit 2) or the host failure
/// a start returns as 1 (IG-Q62).
#[derive(Debug)]
pub(crate) enum Stopped {
    Refused(Vec<Diagnostic>),
    Failed(String),
}

impl From<Diagnostic> for Stopped {
    fn from(d: Diagnostic) -> Self {
        Self::Refused(vec![d])
    }
}

/// The walk (IG-Q59), in a start's order, stopping at the first refusal.
///
/// Whether the account could create the data directory and open the lock
/// file; whether the host has a network id; the marker, read and not
/// written; whether the account could create the log directory and open
/// the log file; the owner values the table accepted, judged and not
/// latched; and the managed Tor's pin, read and not started. Nothing is
/// created, opened for writing, locked or latched, so the check can run
/// while a daemon is up and leaves the machine as it found it.
pub(crate) fn walk(
    config: &DaemonConfig,
    resolved: &resolve::Resolved,
    host: &Host,
) -> Result<Walked, Stopped> {
    let network = config.network;
    Lock::creatable(&config.data_dir)?;
    let Some(network_id) = (host.network_id_of)(network.cryptonote_code()) else {
        return Err(Stopped::Failed(format!(
            "no network id for {}",
            network.name()
        )));
    };
    marker::read(&config.data_dir, network, network_id)?;
    log_location_creatable(&config.logging.file)?;
    let dev = &config.dev;
    if let Err(refusal) = shekyl_ffi::pow_randomx_ffi::check_seed_epoch(
        dev.pow_seed_epoch_blocks,
        dev.pow_seed_epoch_lag,
    ) {
        return Err(owner_refusal(resolved, refusal.row(), refusal.rule()).into());
    }
    if let Err(refusal) = shekyl_ffi::archival_ffi::check_settlement_schedule(
        dev.settlement_epoch_blocks,
        dev.archival_reorg_depth,
    ) {
        return Err(owner_refusal(resolved, refusal.row(), refusal.rule()).into());
    }
    let mut warnings = Vec::new();
    if let Tor::Managed { binary } = &config.tor {
        warnings.extend(crate::tor::pin_warning(
            binary.as_deref(),
            config.clearnet_on(),
        ));
    }
    Ok(Walked {
        network_id,
        warnings,
    })
}

/// The check's acceptance (IG-Q61).
///
/// Standard output carries the account checked and the
/// effective-configuration line. Standard error carries the development
/// levers, the posture, the walk's warnings and, run as root, the warning
/// that root's account was certified (IG-Q60). Exit 0.
pub(crate) fn accept(
    resolved: &resolve::Resolved,
    read_path: Option<&Path>,
    config_path: &Path,
    config: &DaemonConfig,
    warnings: &[String],
) -> i32 {
    let (out, err) = accepted_lines(resolved, read_path, config_path, config, warnings);
    for line in &out {
        tell(&mut std::io::stdout(), line);
    }
    for line in &err {
        tell(&mut std::io::stderr(), line);
    }
    0
}

/// [`accept`]'s lines: standard output's, then standard error's.
///
/// The shared announcement list is [`announce::announcements`]. This check
/// puts the account line ahead of the effective configuration on standard
/// output, and the rest on standard error, and adds the root warning there.
fn accepted_lines(
    resolved: &resolve::Resolved,
    read_path: Option<&Path>,
    config_path: &Path,
    config: &DaemonConfig,
    warnings: &[String],
) -> (Vec<String>, Vec<String>) {
    let announced =
        announce::announcements(&TABLE, resolved, read_path, config_path, config, warnings);
    let out = vec![
        format!("shekyld: configuration verified for {}", account::current()),
        format!("shekyld: {}", announced.effective),
    ];
    let mut err: Vec<String> = announced
        .rest
        .into_iter()
        .map(|line| format!("shekyld: {line}"))
        .collect();
    if account::is_root() {
        err.push(
            "shekyld: warning: checked as root (uid 0): this certifies root's account and \
             environment, not the daemon's; run the check as the account that starts the daemon"
                .to_owned(),
        );
    }
    (out, err)
}

/// A value its owner refuses at its own start (§6).
///
/// A row's refusal is pinned to that row, at the source the value came
/// from. A latch that already happened names no row: the machine holds the
/// fact, and either lever would be the wrong one to blame. The walk and
/// start's record both build the diagnostic here, so the row's terms are
/// written once.
pub(crate) fn owner_refusal(
    resolved: &resolve::Resolved,
    row: Option<&str>,
    rule: &str,
) -> Diagnostic {
    let Some(row) = row else {
        return Diagnostic::new(Code::ValueRange, Source::Machine).param("rule", rule);
    };
    let value = resolved
        .get(row)
        .map_or_else(|| "unset".to_owned(), Value::render);
    let source = resolved.source(row).cloned().unwrap_or(Source::Default);
    Diagnostic::new(Code::ValueRange, source)
        .option(row)
        .param("value", value)
        .param("rule", rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, OsString};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use shekyl_daemon_config::{load, Platform};
    use shekyl_options::read_cli;

    use crate::entry::ShekylDaemonEntry;
    use crate::{EXIT_FAILED, EXIT_REFUSED};

    /// Runs the check tests give the entry: a start that reaches the
    /// remnant is the failure. The count is this module's; the start
    /// tests' run counter is a different one.
    static FORBIDDEN_RUNS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn forbidden_run(
        _snapshot: *const shekyl_ffi::daemon_snapshot_ffi::ShekylDaemonSnapshot,
    ) -> std::ffi::c_int {
        FORBIDDEN_RUNS.fetch_add(1, Ordering::SeqCst);
        99
    }

    const RELEASE: &CStr = c"Test";
    const VERSION: &CStr = c"3.1.0-test";

    /// An entry whose `run` must never be reached.
    fn checking_entry() -> ShekylDaemonEntry {
        ShekylDaemonEntry {
            release_name: RELEASE.as_ptr(),
            version_full: VERSION.as_ptr(),
            protocol_version: 3,
            run: Some(forbidden_run),
            stop: None,
        }
    }

    fn host(home: &Path) -> Host {
        Host {
            platform: Platform {
                home: Some(home.to_path_buf()),
                program_data: None,
            },
            network_id_of: |code| Some([code; 16]),
        }
    }

    fn args(list: &[&str]) -> Vec<OsString> {
        std::iter::once("shekyld")
            .chain(list.iter().copied())
            .map(OsString::from)
            .collect()
    }

    /// Regtest, offline, the data directory and the log file, both missing.
    fn offline_regtest(data: &Path, log: &Path) -> Vec<OsString> {
        args(&[
            "--config-verify",
            "--network",
            "regtest",
            "--clearnet",
            "off",
            "--tor",
            "off",
            "--data-dir",
            data.to_str().unwrap(),
            "--log-file",
            log.to_str().unwrap(),
        ])
    }

    /// IG-Q59: the check accepts what a start would accept and leaves the
    /// machine as it found it: no data directory, no lock file, no marker,
    /// no log file. It takes no lock, so it accepts while a daemon holds
    /// the directory's lock.
    #[test]
    fn config_verify_accepts_and_creates_nothing_even_while_the_lock_is_held() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("deep").join("data");
        let log = d.path().join("logs").join("shekyld.log");
        let a = offline_regtest(&data, &log);
        assert_eq!(crate::run::main(&checking_entry(), &a, &host(d.path())), 0);
        assert!(
            !d.path().join("deep").exists(),
            "no data directory was created"
        );
        assert!(
            !d.path().join("logs").exists(),
            "no log directory was created"
        );
        assert_eq!(
            FORBIDDEN_RUNS.load(Ordering::SeqCst),
            0,
            "the remnant did not run"
        );
        // A daemon is up: its lock is held, its marker is written.
        let held = Lock::take(&data).unwrap();
        marker::check_or_write(&held, shekyl_daemon_config::Network::Regtest, [3u8; 16]).unwrap();
        let before = std::fs::read(data.join("shekyld.network")).unwrap();
        assert_eq!(crate::run::main(&checking_entry(), &a, &host(d.path())), 0);
        assert_eq!(std::fs::read(data.join("shekyld.network")).unwrap(), before);
        assert!(!log.exists());
        drop(held);
    }

    /// IG-Q62: a refusal a start would make is the check's refusal, exit 2,
    /// and the marker it disagreed with is left byte for byte.
    #[test]
    fn config_verify_refuses_what_a_start_refuses_and_leaves_the_marker_as_it_was() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let log = d.path().join("shekyld.log");
        std::fs::create_dir(&data).unwrap();
        let other = marker::render(shekyl_daemon_config::Network::Testnet, [9u8; 16]);
        std::fs::write(data.join("shekyld.network"), &other).unwrap();
        let a = offline_regtest(&data, &log);
        assert_eq!(
            crate::run::main(&checking_entry(), &a, &host(d.path())),
            EXIT_REFUSED
        );
        assert_eq!(
            std::fs::read_to_string(data.join("shekyld.network")).unwrap(),
            other
        );
        assert!(
            !data.join("shekyld.lock").exists(),
            "no lock file was created"
        );
        assert!(!log.exists());
    }

    /// IG-Q62: the one host failure a start returns as 1 is the check's 1,
    /// and it comes after the data directory's question, with nothing made.
    #[test]
    fn config_verify_returns_one_when_the_host_has_no_network_id() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let log = d.path().join("shekyld.log");
        let a = offline_regtest(&data, &log);
        let no_id = Host {
            platform: host(d.path()).platform,
            network_id_of: |_| None,
        };
        assert_eq!(crate::run::main(&checking_entry(), &a, &no_id), EXIT_FAILED);
        assert!(!data.exists());
    }

    /// A client invocation stops after the load, as a start does: the
    /// check accepts without calling the remnant.
    #[test]
    fn config_verify_in_client_mode_stops_after_the_load() {
        let d = tempfile::tempdir().unwrap();
        let status = crate::run::main(
            &checking_entry(),
            &args(&[
                "--config-verify",
                "--rpc-admin-listen",
                "127.0.0.1:4444",
                "status",
            ]),
            &host(d.path()),
        );
        assert_eq!(status, 0);
        assert_eq!(FORBIDDEN_RUNS.load(Ordering::SeqCst), 0, "no client ran");
        assert!(!d.path().join(".shekyl").exists());
    }

    /// The owner values the table accepted are judged in the row's terms,
    /// and judged only: the walk latches nothing, so the same process can
    /// still record the schedule a start would.
    #[test]
    fn the_walk_refuses_an_owner_value_in_the_rows_terms_without_latching() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let log = d.path().join("shekyld.log");
        let mut a = offline_regtest(&data, &log);
        a.extend(["--dev-pow-seed-epoch-blocks", "3"].map(OsString::from));
        let cli = read_cli(&TABLE, a[1..].to_vec()).unwrap();
        let loaded = load(cli, &host(d.path()).platform).unwrap();
        let Err(Stopped::Refused(ds)) = walk(&loaded.config, &loaded.resolved, &host(d.path()))
        else {
            panic!("a seed-epoch length of 3 is refused");
        };
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].code, Code::ValueRange);
        assert_eq!(ds[0].option.as_deref(), Some("dev-pow-seed-epoch-blocks"));
        assert_eq!(ds[0].get("value"), Some("3"));
        assert_eq!(
            crate::run::main(&checking_entry(), &a, &host(d.path())),
            EXIT_REFUSED
        );
        assert!(!data.exists());
        assert_eq!(FORBIDDEN_RUNS.load(Ordering::SeqCst), 0);
    }

    /// The managed Tor's pin is read and not started. A named binary that
    /// is not there is a refused pin, a warning the acceptance carries,
    /// never a refusal (TB-2). The path is the error's; the sentences are
    /// the posture's, for clearnet off.
    #[test]
    fn the_walk_warns_about_a_managed_tor_it_cannot_pin_and_accepts() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let log = d.path().join("shekyld.log");
        let missing = d.path().join("no-such-tor");
        let a = args(&[
            "--config-verify",
            "--network",
            "regtest",
            "--clearnet",
            "off",
            "--tor",
            "managed",
            "--tor-file",
            missing.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
            "--log-file",
            log.to_str().unwrap(),
        ]);
        let cli = read_cli(&TABLE, a[1..].to_vec()).unwrap();
        let loaded = load(cli, &host(d.path()).platform).unwrap();
        let walked = walk(&loaded.config, &loaded.resolved, &host(d.path())).unwrap();
        assert_eq!(walked.network_id, [3u8; 16]);
        assert_eq!(walked.warnings.len(), 1);
        let warning = &walked.warnings[0];
        assert!(warning.starts_with("warning: managed Tor: "));
        assert!(warning.contains("was not started"));
        assert!(warning.contains(missing.to_str().unwrap()));
        assert!(warning.contains("waiting for Tor"));
        assert!(warning.contains("It is not syncing."));
        let (out, err) = accepted_lines(
            &loaded.resolved,
            loaded.file_read.as_deref(),
            &loaded.config_path,
            &loaded.config,
            &walked.warnings,
        );
        assert_eq!(out.len(), 2);
        let names_the_account = out[0].contains(&account::current());
        assert!(names_the_account);
        assert!(out[0].starts_with("shekyld: configuration verified for "));
        assert!(out[1].starts_with("shekyld: effective configuration: "));
        assert!(
            out[1].contains("config-verify=true (cli)") && out[1].contains("tor=managed (cli)")
        );
        assert!(err.iter().any(|line| line.starts_with("shekyld: posture:")));
        assert!(err.iter().any(|line| line.contains("warning: managed Tor")));
        assert_eq!(crate::run::main(&checking_entry(), &a, &host(d.path())), 0);
        assert!(!data.exists());
    }
}
