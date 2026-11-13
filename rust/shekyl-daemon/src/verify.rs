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

use std::num::NonZeroUsize;
use std::path::Path;

use shekyl_daemon_config::sections::{log_location_creatable, DaemonConfig, Tor};
use shekyl_daemon_config::{
    account, announce, marker, owner_socket, resolve, Lock, Platform, TABLE,
};
use shekyl_options::{Code, Diagnostic, Source, Value};

use crate::levers;
use crate::run::tell;

/// What the walk found: the network id a start needs, and the warnings
/// that change no verdict (the Tor pin's, IG-Q59).
pub(crate) struct Walked {
    pub(crate) network_id: [u8; 16],
    pub(crate) warnings: Vec<String>,
    /// Where the owner's socket goes, checked; `None` for a service
    /// (`RPC_CHANNEL.md` §7.1, IG-Q105).
    pub(crate) owner_socket: Option<shekyl_daemon_config::OwnerSocketPlan>,
}

/// The walk (IG-Q59), in a start's order, stopping at the first refusal
/// (`refuse`, exit 2).
///
/// Whether the account could create the data directory and open the lock
/// file; the marker, read and not written, against the network's id
/// (`Network::network_id`, derived from the table's genesis hash: every
/// network has one, so the host failure IG-Q62 once named is gone);
/// whether the account could create the log directory and open the log
/// file; the owner values the table accepted, judged and not latched; a
/// `mine-threads` count above the host's parallelism, refused here so the
/// start-time miner never asks for it (Rick, 2026-11-02); and the managed
/// Tor's pin, read and not started; and where the owner's socket goes,
/// its directory asserted and nothing bound (`RPC_CHANNEL.md` §7.1).
/// Nothing is created, opened for writing, locked or latched, so the check
/// can run while a daemon is up and leaves the machine as it found it.
pub(crate) fn walk(
    config: &DaemonConfig,
    resolved: &resolve::Resolved,
    platform: &Platform,
) -> Result<Walked, Vec<Diagnostic>> {
    let network = config.network;
    Lock::creatable(&config.data_dir).map_err(one)?;
    let network_id = network.network_id();
    marker::read(&config.data_dir, network, network_id).map_err(one)?;
    log_location_creatable(&config.logging.file).map_err(one)?;
    let owner_socket = owner_socket::plan(
        config,
        platform,
        &network_id,
        resolved
            .source("rpc-socket-dir")
            .cloned()
            .unwrap_or(Source::Cli),
    )
    .map_err(one)?;
    let dev = &config.dev;
    if let Err(refusal) =
        levers::check_seed_epoch(dev.pow_seed_epoch_blocks, dev.pow_seed_epoch_lag)
    {
        return Err(vec![owner_refusal(resolved, refusal.row(), refusal.rule())]);
    }
    if let Err(refusal) =
        levers::check_settlement_schedule(dev.settlement_epoch_blocks, dev.archival_reorg_depth)
    {
        return Err(vec![owner_refusal(resolved, refusal.row(), refusal.rule())]);
    }
    if let Some(threads) = config.mine.threads {
        let host = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        let asked = usize::try_from(threads.get()).unwrap_or(usize::MAX);
        if asked > host {
            return Err(vec![owner_refusal(
                resolved,
                Some("mine-threads"),
                &format!("at most the host's parallelism, {host}"),
            )]);
        }
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
        owner_socket,
    })
}

fn one(d: Diagnostic) -> Vec<Diagnostic> {
    vec![d]
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
    let mut announced =
        announce::announcements(&TABLE, resolved, read_path, config_path, config, warnings);
    announced.rest.extend(crate::run::mining_notice(config));
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
    use std::ffi::OsString;
    use std::path::Path;

    use shekyl_daemon_config::{load, Platform};
    use shekyl_options::read_cli;

    use crate::EXIT_REFUSED;

    /// The network id every check in this module compares the marker
    /// against: regtest's, which is the genesis derivation's.
    fn regtest_id() -> [u8; 16] {
        shekyl_daemon_config::Network::Regtest.network_id()
    }

    /// A logged-in account: its home, and a private session directory
    /// for the owner's socket (`RPC_CHANNEL.md` §7.1), one per test.
    fn platform(home: &Path) -> Platform {
        Platform {
            home: Some(home.to_path_buf()),
            program_data: None,
            session_dir: crate::test_session_dir(home),
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
        assert_eq!(crate::run::main(&a, &platform(d.path())), 0);
        assert!(
            !d.path().join("deep").exists(),
            "no data directory was created"
        );
        assert!(
            !d.path().join("logs").exists(),
            "no log directory was created"
        );
        // A daemon is up: its lock is held, its marker is written.
        let held = Lock::take(&data).unwrap();
        marker::check_or_write(&held, shekyl_daemon_config::Network::Regtest, regtest_id())
            .unwrap();
        let before = std::fs::read(data.join("shekyld.network")).unwrap();
        assert_eq!(crate::run::main(&a, &platform(d.path())), 0);
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
        assert_eq!(crate::run::main(&a, &platform(d.path())), EXIT_REFUSED);
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
        let loaded = load(cli, &platform(d.path())).unwrap();
        let ds = walk(&loaded.config, &loaded.resolved, &platform(d.path()))
            .err()
            .expect("a seed-epoch length of 3 is refused");
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].code, Code::ValueRange);
        assert_eq!(ds[0].option.as_deref(), Some("dev-pow-seed-epoch-blocks"));
        assert_eq!(ds[0].get("value"), Some("3"));
        assert_eq!(crate::run::main(&a, &platform(d.path())), EXIT_REFUSED);
        assert!(!data.exists());
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
        let loaded = load(cli, &platform(d.path())).unwrap();
        let walked = walk(&loaded.config, &loaded.resolved, &platform(d.path())).unwrap();
        assert_eq!(walked.network_id, regtest_id());
        assert_eq!(walked.warnings.len(), 1);
        let warning = &walked.warnings[0];
        assert!(warning.starts_with("warning: managed Tor: "));
        assert!(warning.contains("was not started"));
        assert!(warning.contains(missing.to_str().unwrap()));
        assert!(warning.contains("this node will wait for Tor"));
        assert!(
            warning.contains("It will not sync until Tor is up."),
            "clearnet is off, and a check holds no session: {warning}"
        );
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
        assert_eq!(crate::run::main(&a, &platform(d.path())), 0);
        assert!(!data.exists());
    }

    /// `mine = on` on a node declared `Open` announces, in the check as at
    /// a start, that the miner waits for a view of the network (DC-F41);
    /// the same configuration with both connectors off, or with a closed
    /// peer list, announces nothing of the kind, and nor does `mine = off`.
    /// Red edit: drop `mining_notice` from either `accepted_lines` or the
    /// start, or make it ignore the declaration.
    #[test]
    fn mine_on_with_an_open_declaration_announces_that_the_miner_waits_for_a_view() {
        let address = shekyl_address::ShekylAddress::new(
            shekyl_address::Network::Regtest,
            [0xaa; 32],
            [0xbb; 32],
            [0xee; shekyl_address::MSG_SIGN_PK_LEN],
            vec![0xcc; shekyl_address::PQC_PAYLOAD_LEN],
        )
        .encode()
        .unwrap();
        let notice_lines = |cli: &[&str]| -> Vec<String> {
            let d = tempfile::tempdir().unwrap();
            let data = d.path().join("data");
            let log = d.path().join("shekyld.log");
            let mut full = vec![
                "--config-verify",
                "--network",
                "regtest",
                "--data-dir",
                data.to_str().unwrap(),
                "--log-file",
                log.to_str().unwrap(),
            ];
            full.extend_from_slice(cli);
            let a = args(&full);
            let cli = read_cli(&TABLE, a[1..].to_vec()).unwrap();
            let loaded = load(cli, &platform(d.path())).unwrap();
            let walked = walk(&loaded.config, &loaded.resolved, &platform(d.path())).unwrap();
            let (_, err) = accepted_lines(
                &loaded.resolved,
                loaded.file_read.as_deref(),
                &loaded.config_path,
                &loaded.config,
                &walked.warnings,
            );
            err.into_iter()
                .filter(|line| line.starts_with("shekyld: mining: "))
                .collect()
        };
        // Open: clearnet on, no closed peer list.
        let open = notice_lines(&["--tor", "off", "--mine", "on", "--mine-address", &address]);
        assert_eq!(open.len(), 1, "{open:?}");
        assert!(
            open[0].contains("waits for a view of the network"),
            "{}",
            open[0]
        );
        assert!(
            open[0].contains("`clearnet = off` and `tor = off`"),
            "{}",
            open[0]
        );
        assert!(open[0].contains("`p2p-closed-peer`"), "{}", open[0]);
        // Offline: synced at open, mines at once.
        let offline = notice_lines(&[
            "--clearnet",
            "off",
            "--tor",
            "off",
            "--mine",
            "on",
            "--mine-address",
            &address,
        ]);
        assert!(offline.is_empty(), "{offline:?}");
        // Closed: the operator named the whole network.
        let closed = notice_lines(&[
            "--tor",
            "off",
            "--p2p-closed-peer",
            "192.0.2.1:12020",
            "--mine",
            "on",
            "--mine-address",
            &address,
        ]);
        assert!(closed.is_empty(), "{closed:?}");
        // Open, but the miner is not asked to start.
        let idle = notice_lines(&["--tor", "off", "--mine-address", &address]);
        assert!(idle.is_empty(), "{idle:?}");
    }
}
