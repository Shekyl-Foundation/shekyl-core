// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The start sequence (`DAEMON_CONFIG_CUTOVER.md` §2.2) and the one stop
//! path (step 9).
//!
//! Rust owns the process from the entry: it reads its arguments, chooses
//! the network, reads and checks the file, resolves and builds the sections,
//! answers `--help` and `--version`, takes the lock, checks the marker,
//! starts logging, makes the announcements, installs the one signal owner,
//! fills the snapshot and calls the remnant's `run` on a thread of its own.
//! A stop request calls the remnant's `stop`, the thread is joined, and the
//! lock is released last. A refusal exits with 2, a runtime failure with
//! 1, and `run`'s status becomes the exit status otherwise.

use std::ffi::{c_char, c_int, CStr, CString, OsStr, OsString};
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::Path;

use shekyl_daemon_config::announce;
use shekyl_daemon_config::sections::{build, log_location_writable, DaemonConfig};
use shekyl_daemon_config::{choosers, file, marker, paths, resolve, Lock, Platform, TABLE};
use shekyl_options::{read_cli, read_file, Diagnostic, Kind, Value};
use shekyl_runtime::{RuntimeBudget, ThreadName};

use crate::entry::{ShekylDaemonEntry, ShekylDaemonSnapshot, ShekylStringList};
use crate::{help, legacy, signals};

/// A configuration refusal.
pub const EXIT_REFUSED: i32 = 2;
/// A runtime failure.
pub const EXIT_FAILED: i32 = 1;

/// The platform facts and the one derivation the entry needs, so a test
/// can run the sequence without an account or a build.
pub struct Host {
    /// The account's and the machine's roots.
    pub platform: Platform,
    /// The network id of a `cryptonote::network_type` code.
    pub network_id_of: fn(u8) -> Option<[u8; 16]>,
}

/// The entry: the whole sequence, returning the exit status.
#[must_use]
pub fn main(entry: &ShekylDaemonEntry, args: &[OsString], host: &Host) -> i32 {
    let (program, rest) = match args.split_first() {
        Some((p, rest)) => (p.clone(), rest.to_vec()),
        None => (OsString::from("shekyld"), Vec::new()),
    };
    let cli = match read_cli(&TABLE, rest.iter().cloned()) {
        Ok(cli) => cli,
        Err(ds) => return refuse(&ds),
    };
    let (network, mode) = choosers(&cli);
    let release_name = c_string(entry.release_name);
    let version_full = c_string(entry.version_full);
    if cli.given.iter().any(|g| g.row.name == "help") {
        print!(
            "{}",
            help::render(
                &TABLE,
                &program.to_string_lossy(),
                &release_name,
                &version_full
            )
        );
        return 0;
    }
    if cli.given.iter().any(|g| g.row.name == "version") {
        println!(
            "Shekyl '{release_name}' (v{version_full}, protocol {})\nOS: {} {}",
            entry.protocol_version,
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        return 0;
    }

    // The file: named, or the network's default.
    let (config_path, named) = match cli.given.iter().find(|g| g.row.name == "config-file") {
        Some(g) => match &g.value {
            Value::Path(p) => (p.clone(), true),
            _ => return EXIT_FAILED,
        },
        None => match paths::config_file_default(&host.platform, mode, network) {
            Ok(p) => (p, false),
            Err(d) => return refuse(&[d]),
        },
    };
    let opened = match file::open(&config_path, named) {
        Ok(o) => o,
        Err(d) => return refuse(&[d]),
    };
    let mut given = Vec::new();
    if let Some(config_file) = &opened {
        given = match read_file(&TABLE, &config_path, &config_file.text) {
            Ok(g) => g,
            Err(ds) => return refuse(&ds),
        };
        for g in given.iter().filter(|g| matches!(g.row.kind, Kind::Secret)) {
            if let Err(d) = config_file.secret_readable_only_by_permitted(g.row.name) {
                return refuse(&[d]);
            }
        }
    }
    let resolved = match resolve(&TABLE, network, cli, given) {
        Ok(r) => r,
        Err(ds) => return refuse(&ds),
    };
    let file_read = opened.as_ref().map(|f| f.path.as_path());
    let config = match build(&resolved, network, mode, &host.platform, file_read) {
        Ok(c) => c,
        Err(ds) => return refuse(&ds),
    };

    // Client mode: no lock, no marker, no log file, no announcement.
    if config.is_client() {
        return call_run(entry, &config, &program);
    }

    // The lock, the marker, the log location.
    let lock = match Lock::take(&config.data_dir) {
        Ok(l) => l,
        Err(d) => return refuse(&[d]),
    };
    let Some(network_id) = (host.network_id_of)(network.cryptonote_code()) else {
        eprintln!("shekyld: no network id for {}", network.name());
        return EXIT_FAILED;
    };
    if let Err(d) = marker::check_or_write(&lock, network, network_id) {
        return refuse(&[d]);
    }
    if let Err(d) = log_location_writable(&config.logging.file) {
        return refuse(&[d]);
    }

    // Logging, from its section; then the announcements, to standard error
    // and the log file whatever the level (IG-14).
    let level = shekyl_logging::subsystem::level_from_word(config.logging.level)
        .unwrap_or(tracing::Level::WARN);
    let logging = shekyl_logging::Config::with_file_sink(level, config.logging.file_sink())
        .with_directive(config.logging.directive());
    let _logger = match shekyl_logging::init(logging) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("shekyld: logging could not start: {e}");
            return EXIT_FAILED;
        }
    };
    let mut lines = vec![announce::effective_configuration(
        &TABLE,
        &resolved,
        file_read,
        &config_path,
    )];
    lines.extend(announce::dev_levers(&TABLE, &resolved));
    lines.push(announce::posture(&config));
    announce_all(&config.logging.file, &lines);

    // The environment levers today's C++ reads, set for it (legacy).
    for (key, value) in legacy::environment(&config) {
        std::env::set_var(key, value);
    }

    // The one signal owner, and the remnant on a thread of its own.
    signals::install_dispositions();
    let budget = RuntimeBudget {
        workers: NonZeroUsize::MIN,
        blocking: NonZeroUsize::MIN,
    };
    let name = ThreadName::new("shekyld-signals").expect("a non-empty name");
    let pool = match shekyl_runtime::runtime(budget, &name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("shekyld: the signal owner's runtime could not start: {e}");
            return EXIT_FAILED;
        }
    };
    let Some(run) = entry.run else {
        eprintln!("shekyld: the entry has no run");
        return EXIT_FAILED;
    };
    let Some(stop) = entry.stop else {
        eprintln!("shekyld: the entry has no stop");
        return EXIT_FAILED;
    };
    let data = SnapshotData::new(&config, &program);
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<i32>();
    let thread = std::thread::Builder::new()
        .name("shekyld-run".to_owned())
        .spawn(move || {
            let status = data.call(run);
            // The receiver is gone only if the entry already gave up.
            let _sent = done_tx.send(status);
        });
    let thread = match thread {
        Ok(t) => t,
        Err(e) => {
            eprintln!("shekyld: the run thread could not start: {e}");
            return EXIT_FAILED;
        }
    };
    let status = pool.block_on(async {
        tokio::select! {
            finished = &mut done_rx => finished.unwrap_or(EXIT_FAILED),
            requested = signals::stop_requested() => {
                match requested {
                    Ok(by) => tracing::warn!(target: "daemon", "stop requested by {by}"),
                    Err(e) => tracing::error!(target: "daemon", "the signal owner failed: {e}; stopping"),
                }
                stop();
                done_rx.await.unwrap_or(EXIT_FAILED)
            }
        }
    });
    if thread.join().is_err() {
        tracing::error!(target: "daemon", "the run thread ended by a panic");
    }
    pool.shutdown_background();
    drop(lock);
    status
}

/// Prints each refusal and returns the refusal status.
fn refuse(diagnostics: &[Diagnostic]) -> i32 {
    for d in diagnostics {
        eprintln!("shekyld: {}", d.render());
    }
    EXIT_REFUSED
}

fn c_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // The entry's strings are static C++ literals, NUL-terminated.
    unsafe_c_str(ptr)
}

#[allow(unsafe_code)]
fn unsafe_c_str(ptr: *const c_char) -> String {
    // SAFETY: the caller checked `ptr` is not null, and the entry contract
    // says it is a NUL-terminated static string.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

/// The announcements, to standard error and appended to the log file.
fn announce_all(log_file: &Path, lines: &[String]) {
    for line in lines {
        eprintln!("shekyld: {line}");
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(log_file) {
        for line in lines {
            if writeln!(f, "{line}").is_err() {
                break;
            }
        }
    }
}

/// The owned data behind a snapshot: built on the calling thread, moved to
/// the run thread, and alive for as long as `run` runs.
pub(crate) struct SnapshotData {
    data_dir: CString,
    network: u8,
    offline: bool,
    fixed_difficulty: u64,
    txpool_weight_max: u64,
    sync: bool,
    mine_address: Option<CString>,
    mine_threads: u32,
    console: bool,
    command: Vec<CString>,
    client_endpoint: Option<CString>,
    advertised_port: u16,
    argv: Vec<CString>,
}

impl SnapshotData {
    pub(crate) fn new(config: &DaemonConfig, program: &OsStr) -> Self {
        let c = |s: &str| CString::new(s.replace('\0', "")).expect("no NUL after the filter");
        Self {
            data_dir: c(&config.data_dir.display().to_string()),
            network: config.network.cryptonote_code(),
            offline: config.offline(),
            fixed_difficulty: config.dev.difficulty.unwrap_or(0),
            txpool_weight_max: config.txpool_weight_max,
            sync: config.dev.sync,
            mine_address: config.mine.address.as_deref().map(c),
            mine_threads: config.mine.threads.map_or(0, std::num::NonZeroU32::get),
            console: config.session.console,
            command: config.session.command.iter().map(|w| c(w)).collect(),
            client_endpoint: config.session.client_endpoint.map(|e| c(&e.to_string())),
            advertised_port: match &config.clearnet {
                shekyl_daemon_config::Clearnet::On { advertise, .. } => {
                    advertise.first().map_or(0, std::net::SocketAddr::port)
                }
                shekyl_daemon_config::Clearnet::Off => 0,
            },
            argv: legacy::argv(program, config).iter().map(|a| c(a)).collect(),
        }
    }

    #[cfg(test)]
    pub(crate) fn command_words(&self) -> Vec<String> {
        self.command
            .iter()
            .map(|w| w.to_string_lossy().into_owned())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn client_endpoint(&self) -> Option<String> {
        self.client_endpoint
            .as_ref()
            .map(|e| e.to_string_lossy().into_owned())
    }

    #[cfg(test)]
    pub(crate) fn data_dir(&self) -> String {
        self.data_dir.to_string_lossy().into_owned()
    }

    #[cfg(test)]
    pub(crate) fn advertised_port(&self) -> u16 {
        self.advertised_port
    }

    /// Calls `run` with pointers into this data, which outlives the call.
    fn call(&self, run: crate::entry::RunFn) -> i32 {
        let command: Vec<*const c_char> = self.command.iter().map(|w| w.as_ptr()).collect();
        let argv: Vec<*const c_char> = self.argv.iter().map(|a| a.as_ptr()).collect();
        let snapshot = ShekylDaemonSnapshot {
            data_dir: self.data_dir.as_ptr(),
            network: self.network,
            offline: self.offline,
            fixed_difficulty: self.fixed_difficulty,
            txpool_weight_max: self.txpool_weight_max,
            sync: self.sync,
            mine_address: self
                .mine_address
                .as_ref()
                .map_or(std::ptr::null(), |a| a.as_ptr()),
            mine_threads: self.mine_threads,
            console: self.console,
            command: ShekylStringList {
                items: command.as_ptr(),
                len: command.len(),
            },
            client_endpoint: self
                .client_endpoint
                .as_ref()
                .map_or(std::ptr::null(), |e| e.as_ptr()),
            advertised_port: self.advertised_port,
        };
        let argc = c_int::try_from(argv.len()).unwrap_or(c_int::MAX);
        run(&raw const snapshot, argc, argv.as_ptr())
    }
}

fn call_run(entry: &ShekylDaemonEntry, config: &DaemonConfig, program: &OsStr) -> i32 {
    let Some(run) = entry.run else {
        eprintln!("shekyld: the entry has no run");
        return EXIT_FAILED;
    };
    SnapshotData::new(config, program).call(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use std::sync::Mutex;

    static LAST_ARGC: AtomicI32 = AtomicI32::new(-1);
    static STOPS: AtomicUsize = AtomicUsize::new(0);
    static RUN_RETURNS: Mutex<i32> = Mutex::new(0);

    extern "C" fn fake_run(
        snapshot: *const ShekylDaemonSnapshot,
        argc: c_int,
        _argv: *const *const c_char,
    ) -> c_int {
        assert!(!snapshot.is_null());
        LAST_ARGC.store(argc, Ordering::SeqCst);
        *RUN_RETURNS.lock().unwrap()
    }

    extern "C" fn fake_stop() {
        STOPS.fetch_add(1, Ordering::SeqCst);
    }

    const RELEASE: &CStr = c"Test";
    const VERSION: &CStr = c"3.1.0-test";

    fn entry() -> ShekylDaemonEntry {
        ShekylDaemonEntry {
            release_name: RELEASE.as_ptr(),
            version_full: VERSION.as_ptr(),
            protocol_version: 3,
            run: Some(fake_run),
            stop: Some(fake_stop),
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

    #[test]
    fn a_refusal_exits_with_two_and_help_and_version_with_zero() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            main(&entry(), &args(&["--bogus"]), &host(d.path())),
            EXIT_REFUSED
        );
        assert_eq!(main(&entry(), &args(&["--help"]), &host(d.path())), 0);
        assert_eq!(main(&entry(), &args(&["--version"]), &host(d.path())), 0);
        assert_eq!(
            main(
                &entry(),
                &args(&["--network", "regtest", "--dev-difficulty", "0"]),
                &host(d.path())
            ),
            EXIT_REFUSED
        );
    }

    #[test]
    fn client_mode_calls_run_without_a_lock_and_returns_its_status() {
        let d = tempfile::tempdir().unwrap();
        *RUN_RETURNS.lock().unwrap() = 7;
        let status = main(
            &entry(),
            &args(&["--rpc-admin-listen", "127.0.0.1:4444", "status"]),
            &host(d.path()),
        );
        assert_eq!(status, 7);
        assert!(LAST_ARGC.load(Ordering::SeqCst) > 1);
        assert!(
            !d.path().join(".shekyl").join("shekyld.lock").exists(),
            "a client takes no lock"
        );
        *RUN_RETURNS.lock().unwrap() = 0;
    }

    #[test]
    fn the_snapshot_carries_the_twelve_values() {
        let d = tempfile::tempdir().unwrap();
        let args_v: Vec<OsString> = [
            "--network",
            "regtest",
            "--data-dir",
            d.path().to_str().unwrap(),
            "--clearnet-advertise",
            "8.8.8.8:1234",
            "status",
            "extra",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let cli = read_cli(&TABLE, args_v).unwrap();
        let (network, mode) = choosers(&cli);
        let resolved = resolve(&TABLE, network, cli, Vec::new()).unwrap();
        let config = build(&resolved, network, mode, &host(d.path()).platform, None).unwrap();
        let data = SnapshotData::new(&config, OsStr::new("shekyld"));
        assert_eq!(
            data.command_words(),
            vec!["status".to_owned(), "extra".to_owned()]
        );
        assert_eq!(data.client_endpoint().as_deref(), Some("127.0.0.1:11029"));
        assert_eq!(data.data_dir(), d.path().display().to_string());
        assert_eq!(data.advertised_port(), 1234);
        assert_eq!(data.network, 3);
    }

    /// The one test that starts a daemon: logging installs once per
    /// process, so this is the only test that reaches it.
    #[test]
    fn a_daemon_start_locks_marks_logs_announces_and_runs_the_remnant() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let log = d.path().join("logs").join("shekyld-regtest.log");
        let a = args(&[
            "--network",
            "regtest",
            "--data-dir",
            data.to_str().unwrap(),
            "--log-file",
            log.to_str().unwrap(),
        ]);
        let status = main(&entry(), &a, &host(d.path()));
        assert_eq!(status, 0);
        assert!(data.join("shekyld.lock").is_file());
        let m = std::fs::read_to_string(data.join("shekyld.network")).unwrap();
        assert!(m.contains("network = \"regtest\""), "{m}");
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("effective configuration:"), "{text}");
        assert!(text.contains("posture:"), "{text}");
        assert_eq!(
            STOPS.load(Ordering::SeqCst),
            0,
            "run finished on its own; no stop was sent"
        );
        // The lock was released at the end: it can be taken again.
        assert!(Lock::take(&data).is_ok());
    }
}
