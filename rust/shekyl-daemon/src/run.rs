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

use std::ffi::{c_char, CStr, CString, OsString};
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use shekyl_daemon_config::announce;
use shekyl_daemon_config::sections::{build, log_location_writable, DaemonConfig, Tor};
use shekyl_daemon_config::{choosers, file, marker, paths, resolve, Lock, Platform, TABLE};
use shekyl_options::{read_cli, read_file, Diagnostic, Kind, Value};
use shekyl_runtime::{RuntimeBudget, ThreadName};

use crate::entry::{ShekylDaemonEntry, ShekylDaemonSnapshot, ShekylStringList};
use crate::options::DaemonOptions;
use crate::{help, legacy, network, signals, tor};
use shekyl_daemon_rpc::options::OptionsHandle;

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
    let program = program.to_string_lossy().into_owned();
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
            help::render(&TABLE, &program, &release_name, &version_full)
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
        return call_run(entry, &config);
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

    // Step 6: what the owners read at their build, before the remnant
    // binds the seam.
    network::record(&config);

    // The one signal owner, the RPC section for the remnant's one start,
    // and the remnant on a thread of its own.
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
    // The options handle: the resolved values, the runtime rows' owners
    // behind the RPC's two methods (§2.7).
    let options: OptionsHandle = Arc::new(DaemonOptions::new(resolved.clone(), network));
    let status = supervise(entry, &config, &pool, network_id, options);
    pool.shutdown_background();
    drop(lock);
    status
}

/// What the first wait reached: the remnant's one RPC start completed
/// (§2.2 step 7's last act), that start was refused, `run` ended on its
/// own, or a stop was requested first.
enum Reached {
    Constructed,
    RpcRefused,
    Finished(i32),
    StopRequested,
}

/// Steps 7 to 9: the remnant's `run` on its own thread, the wait for its
/// RPC start, and the one stop path. Returns the exit status.
///
/// The waits run on `pool`; the stop sequence runs on this thread, outside
/// any async context, because the RPC's stop blocks on its own runtime's
/// drain and a runtime cannot be entered from inside another's `block_on`.
fn supervise(
    entry: &ShekylDaemonEntry,
    config: &DaemonConfig,
    pool: &shekyl_runtime::Pool,
    network_id: [u8; 16],
    options: OptionsHandle,
) -> i32 {
    let Some(run) = entry.run else {
        eprintln!("shekyld: the entry has no run");
        return EXIT_FAILED;
    };
    let Some(stop) = entry.stop else {
        eprintln!("shekyld: the entry has no stop");
        return EXIT_FAILED;
    };
    let mut constructed = shekyl_daemon_rpc::ffi_exports::configure(config.rpc.clone(), options);
    // Step 6: the notify runner, installed before the core that pushes to
    // it exists; its children run on the signal owner's runtime (§2.10).
    shekyl_ffi::notify_ffi::install(&config.notify, pool.handle().clone());
    // Step 6: the managed Tor's start, overlapping the core's construction;
    // awaited at step 8.
    let tor_start = tor::begin(&config.tor, &config.data_dir, pool.handle());
    let data = SnapshotData::new(config);
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

    // Step 7: the remnant constructs core, the protocol handler and
    // net_node, and calls the RPC start once; its completion is the signal
    // that the core exists for step 8.
    let reached = pool.block_on(async {
        tokio::select! {
            built = &mut constructed => match built {
                Ok(Ok(())) => Reached::Constructed,
                Ok(Err(refusal)) => {
                    tracing::error!(target: "daemon", "the RPC did not start: {refusal}");
                    Reached::RpcRefused
                }
                Err(_replaced) => {
                    tracing::error!(target: "daemon", "the RPC section was replaced before the start");
                    Reached::RpcRefused
                }
            },
            finished = &mut done_rx => Reached::Finished(finished.unwrap_or(EXIT_FAILED)),
            requested = signals::stop_requested() => {
                note_stop(requested);
                Reached::StopRequested
            }
        }
    });
    let mut tor_control = None;
    let status = match reached {
        Reached::Finished(status) => status,
        Reached::StopRequested => {
            stop_path(stop);
            pool.block_on(&mut done_rx).unwrap_or(EXIT_FAILED)
        }
        Reached::RpcRefused => {
            // The remnant's run throws and returns; a stop asked for
            // meanwhile is honoured all the same.
            let finished = pool.block_on(async {
                tokio::select! {
                    finished = &mut done_rx => Some(finished.unwrap_or(EXIT_FAILED)),
                    requested = signals::stop_requested() => {
                        note_stop(requested);
                        None
                    }
                }
            });
            match finished {
                Some(status) => status,
                None => {
                    stop_path(stop);
                    pool.block_on(&mut done_rx).unwrap_or(EXIT_FAILED)
                }
            }
        }
        Reached::Constructed => {
            // Step 8: the managed Tor, awaited; then the zone host, its
            // listeners and the dialer, each from its section; then the
            // onion, which forwards to the zone host's loopback listener.
            tor_control = match tor_start {
                Some(handle) => match pool.block_on(handle) {
                    Ok(Ok(control)) => Some(control),
                    Ok(Err(not_running)) => {
                        tracing::warn!(target: "global", "{not_running}");
                        None
                    }
                    Err(e) => {
                        tracing::error!(target: "global", "the managed Tor's start task failed: {e}");
                        None
                    }
                },
                None => None,
            };
            let tor_socks = match (&config.tor, &tor_control) {
                (Tor::Managed { .. }, Some(control)) => network::TorSocks::At {
                    socks: control.socks_addr(),
                    onion_listen: None,
                    managed: true,
                },
                (Tor::Operator { socks, onion }, _) => network::TorSocks::At {
                    socks: socks.endpoint,
                    onion_listen: onion.as_ref().map(|o| o.listen),
                    managed: false,
                },
                (Tor::Managed { .. } | Tor::Off, _) => network::TorSocks::None,
            };
            match network::start(config, network_id, tor_socks) {
                Ok(started) => {
                    if let (Some(control), Some(forward)) = (&tor_control, started.tor_forward) {
                        let published = pool.block_on(tor::publish(
                            control,
                            config.network.p2p_port(),
                            forward,
                        ));
                        tor::watch_death(control, published, pool.handle());
                    }
                    let finished = pool.block_on(async {
                        tokio::select! {
                            finished = &mut done_rx => Some(finished.unwrap_or(EXIT_FAILED)),
                            requested = signals::stop_requested() => {
                                note_stop(requested);
                                None
                            }
                        }
                    });
                    match finished {
                        Some(status) => status,
                        None => {
                            stop_path(stop);
                            pool.block_on(&mut done_rx).unwrap_or(EXIT_FAILED)
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(target: "global", "the network could not start: {e}; stopping");
                    stop_path(stop);
                    let _status = pool.block_on(&mut done_rx);
                    EXIT_FAILED
                }
            }
        }
    };
    // `run` ended: whatever stopped it, the zone host and the RPC are
    // stopped before the core they serve is gone (the remnant stops the RPC
    // too; the second is a no-op), and the managed Tor is torn down.
    network::stop();
    shekyl_daemon_rpc::ffi_exports::stop();
    if let Some(control) = tor_control {
        let exit = pool.block_on(control.shutdown());
        tracing::info!(
            target: "global",
            "the managed Tor was torn down ({exit:?}); the address is gone, a restart mints a new one"
        );
    }
    if thread.join().is_err() {
        tracing::error!(target: "daemon", "the run thread ended by a panic");
    }
    status
}

fn note_stop(requested: std::io::Result<&'static str>) {
    match requested {
        Ok(by) => tracing::warn!(target: "daemon", "stop requested by {by}"),
        Err(e) => tracing::error!(target: "daemon", "the signal owner failed: {e}; stopping"),
    }
}

/// Step 9's order: the dialer and the zone host, then the RPC, drained,
/// then the remnant's `stop`, which returns at once; the managed Tor's
/// teardown and the remnant's thread end in parallel after it, and the
/// lock is released by the caller after `run` has returned.
fn stop_path(stop: crate::entry::StopFn) {
    network::stop();
    shekyl_daemon_rpc::ffi_exports::stop();
    stop();
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
}

impl SnapshotData {
    pub(crate) fn new(config: &DaemonConfig) -> Self {
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

    /// Calls `run` with pointers into this data, which outlives the call.
    fn call(&self, run: crate::entry::RunFn) -> i32 {
        let command: Vec<*const c_char> = self.command.iter().map(|w| w.as_ptr()).collect();
        let snapshot = self.snapshot(&command);
        run(&raw const snapshot)
    }

    /// The snapshot over this data and `command`, the pointers to its
    /// command words; both must outlive every read of the result.
    fn snapshot(&self, command: &[*const c_char]) -> ShekylDaemonSnapshot {
        ShekylDaemonSnapshot {
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
        }
    }
}

/// A snapshot leased to a C++ test binary: the structure first, so its
/// address is the lease's, then what it points at.
#[repr(C)]
pub(crate) struct Leased {
    snapshot: ShekylDaemonSnapshot,
    _command: Vec<*const c_char>,
    _data: Box<SnapshotData>,
}

// SAFETY: the pointers are into `_data`, which the lease owns and never
// mutates; the C++ reads them from any thread it likes.
#[allow(unsafe_code)]
unsafe impl Send for Leased {}

/// The real parse for a C++ test binary (`shekyl_daemon_snapshot_parse`):
/// the arguments through the table, the file and the sections, with the
/// platform's roots; no lock, marker or logging. `Err` is the exit status
/// a start would have given, the refusals printed.
pub(crate) fn snapshot_for_tests(args: &[OsString], host: &Host) -> Result<Box<Leased>, i32> {
    let rest = args.get(1..).unwrap_or(&[]);
    let cli = read_cli(&TABLE, rest.iter().cloned()).map_err(|ds| refuse(&ds))?;
    let (network, mode) = choosers(&cli);
    let (config_path, named) = match cli.given.iter().find(|g| g.row.name == "config-file") {
        Some(g) => match &g.value {
            Value::Path(p) => (p.clone(), true),
            _ => return Err(EXIT_FAILED),
        },
        None => (
            paths::config_file_default(&host.platform, mode, network).map_err(|d| refuse(&[d]))?,
            false,
        ),
    };
    let opened = file::open(&config_path, named).map_err(|d| refuse(&[d]))?;
    let given = match &opened {
        Some(config_file) => {
            read_file(&TABLE, &config_path, &config_file.text).map_err(|ds| refuse(&ds))?
        }
        None => Vec::new(),
    };
    let resolved = resolve(&TABLE, network, cli, given).map_err(|ds| refuse(&ds))?;
    let file_read = opened.as_ref().map(|f| f.path.as_path());
    let config =
        build(&resolved, network, mode, &host.platform, file_read).map_err(|ds| refuse(&ds))?;
    let data = Box::new(SnapshotData::new(&config));
    let command: Vec<*const c_char> = data.command.iter().map(|w| w.as_ptr()).collect();
    let snapshot = data.snapshot(&command);
    Ok(Box::new(Leased {
        snapshot,
        _command: command,
        _data: data,
    }))
}

fn call_run(entry: &ShekylDaemonEntry, config: &DaemonConfig) -> i32 {
    let Some(run) = entry.run else {
        eprintln!("shekyld: the entry has no run");
        return EXIT_FAILED;
    };
    SnapshotData::new(config).call(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_int;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static RUNS: AtomicUsize = AtomicUsize::new(0);
    /// The RPC section, the owners' records and the signal owner's request
    /// are process-global: the tests that drive them run one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());
    static STOPS: AtomicUsize = AtomicUsize::new(0);
    static RUN_RETURNS: Mutex<i32> = Mutex::new(0);

    extern "C" fn fake_run(snapshot: *const ShekylDaemonSnapshot) -> c_int {
        assert!(!snapshot.is_null());
        RUNS.fetch_add(1, Ordering::SeqCst);
        *RUN_RETURNS.lock().unwrap()
    }

    extern "C" fn fake_stop() {
        STOPS.fetch_add(1, Ordering::SeqCst);
    }

    static STOP_ARMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// A remnant that runs until its `stop` is called, as the daemon does.
    extern "C" fn blocking_run(snapshot: *const ShekylDaemonSnapshot) -> c_int {
        assert!(!snapshot.is_null());
        while !STOP_ARMED.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        0
    }

    extern "C" fn arming_stop() {
        STOPS.fetch_add(1, Ordering::SeqCst);
        STOP_ARMED.store(true, Ordering::SeqCst);
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
        let runs_before = RUNS.load(Ordering::SeqCst);
        let status = main(
            &entry(),
            &args(&["--rpc-admin-listen", "127.0.0.1:4444", "status"]),
            &host(d.path()),
        );
        assert_eq!(status, 7);
        assert_eq!(RUNS.load(Ordering::SeqCst), runs_before + 1);
        assert!(
            !d.path().join(".shekyl").join("shekyld.lock").exists(),
            "a client takes no lock"
        );
        *RUN_RETURNS.lock().unwrap() = 0;
    }

    #[test]
    fn the_snapshot_carries_the_eleven_values() {
        let d = tempfile::tempdir().unwrap();
        let args_v: Vec<OsString> = [
            "--network",
            "regtest",
            "--data-dir",
            d.path().to_str().unwrap(),
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
        let data = SnapshotData::new(&config);
        assert_eq!(
            data.command_words(),
            vec!["status".to_owned(), "extra".to_owned()]
        );
        assert_eq!(data.client_endpoint().as_deref(), Some("127.0.0.1:11029"));
        assert_eq!(data.data_dir(), d.path().display().to_string());
        assert_eq!(data.network, 3);
    }

    /// The remnant's own request — the console's `exit`, the RPC's
    /// `stop_daemon` — reaches the one owner, which calls the remnant's
    /// `stop` and returns `run`'s status: one stop path, whatever asked.
    #[test]
    fn a_stop_request_from_the_remnant_runs_the_one_stop_path() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let d = tempfile::tempdir().unwrap();
        let a = args(&[
            "--network",
            "regtest",
            "--clearnet",
            "off",
            "--tor",
            "off",
            "--rpc-admin-listen",
            "none",
        ]);
        let cli = read_cli(&TABLE, a[1..].to_vec()).unwrap();
        let (network, mode) = choosers(&cli);
        let resolved = resolve(&TABLE, network, cli, Vec::new()).unwrap();
        let config = build(&resolved, network, mode, &host(d.path()).platform, None).unwrap();
        let entry = ShekylDaemonEntry {
            run: Some(blocking_run),
            stop: Some(arming_stop),
            ..entry()
        };
        let budget = RuntimeBudget {
            workers: NonZeroUsize::MIN,
            blocking: NonZeroUsize::MIN,
        };
        let pool =
            shekyl_runtime::runtime(budget, &ThreadName::new("test-signals").unwrap()).unwrap();
        let before = STOPS.load(Ordering::SeqCst);
        let requester = std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            crate::entry::shekyl_daemon_request_stop();
        });
        let status = supervise(
            &entry,
            &config,
            &pool,
            [3u8; 16],
            Arc::new(shekyl_daemon_rpc::options::OptionsAbsent),
        );
        requester.join().unwrap();
        assert_eq!(status, 0, "run's status is the exit status");
        assert_eq!(
            STOPS.load(Ordering::SeqCst),
            before + 1,
            "the owner called the remnant's stop exactly once"
        );
        pool.shutdown_background();
    }

    /// The one test that starts a daemon: logging installs once per
    /// process, so this is the only test that reaches it.
    #[test]
    fn a_daemon_start_locks_marks_logs_announces_and_runs_the_remnant() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let log = d.path().join("logs").join("shekyld-regtest.log");
        // Offline: the subject is the lock, the marker, the log and the
        // announcements, and a managed Tor would look for a binary here.
        let a = args(&[
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
        ]);
        // The stop counter is process-global: the delta is this test's.
        let stops_before = STOPS.load(Ordering::SeqCst);
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
            stops_before,
            "run finished on its own; no stop was sent"
        );
        // The lock was released at the end: it can be taken again.
        assert!(Lock::take(&data).is_ok());
    }
}
