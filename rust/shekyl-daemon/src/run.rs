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
//! Stop is one path: the dialer and the zone host, then the RPC, then the
//! remnant's `stop` (only when `run` has not finished) together with the
//! managed Tor's teardown. The lock is released last. A refusal exits with
//! 2, a runtime failure with 1, and `run`'s status becomes the exit status
//! otherwise.

use std::ffi::{c_char, CStr, OsString};
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::oneshot::{self, Receiver};

use shekyl_daemon_config::announce;
use shekyl_daemon_config::sections::{log_location_writable, DaemonConfig, Tor};
use shekyl_daemon_config::{marker, resolve, Lock, Platform, TABLE};
use shekyl_options::{read_cli, Code, Diagnostic, Source, Value};
use shekyl_runtime::{RuntimeBudget, ThreadName};

use shekyl_daemon_config::exit::refuse;
use shekyl_daemon_config::{load, Loaded};
use shekyl_ffi::daemon_snapshot_ffi::SnapshotData;

use crate::entry::{RunFn, ShekylDaemonEntry};
use crate::options::DaemonOptions;
use crate::{help, network, signals, tor};
use shekyl_daemon_rpc::options::OptionsHandle;

pub use shekyl_daemon_config::exit::{EXIT_FAILED, EXIT_REFUSED};

/// One line for the operator. Help and version use standard output; a
/// refusal or a failure uses standard error. A closed stream does not
/// change the exit status.
fn tell(out: &mut impl Write, line: &str) {
    drop(writeln!(out, "{line}"));
}

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
        tell(
            &mut std::io::stdout(),
            &format!(
                "Shekyl '{release_name}' (v{version_full}, protocol {})\nOS: {} {}",
                entry.protocol_version,
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        );
        return 0;
    }

    let Loaded {
        config_path,
        file_read,
        resolved,
        config,
    } = match load(cli, &host.platform) {
        Ok(loaded) => loaded,
        Err(ds) => return refuse(&ds),
    };
    let read_path = file_read.as_deref();
    let network = config.network;

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
        tell(
            &mut std::io::stderr(),
            &format!("shekyld: no network id for {}", network.name()),
        );
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
        .expect("the table admits only level words");
    let logging = shekyl_logging::Config::with_file_sink(level, config.logging.file_sink())
        .with_directive(config.logging.directive());
    let logger = match shekyl_logging::init(logging) {
        Ok(guard) => guard,
        Err(e) => {
            tell(
                &mut std::io::stderr(),
                &format!("shekyld: logging could not start: {e}"),
            );
            return EXIT_FAILED;
        }
    };
    let mut lines = vec![announce::effective_configuration(
        &TABLE,
        &resolved,
        read_path,
        &config_path,
    )];
    lines.extend(announce::dev_levers(&TABLE, &resolved));
    lines.push(announce::posture(&config));
    announce_all(&config.logging.file, &lines);

    // Step 6: what the owners read at their build, before the remnant
    // binds the seam. The schedule levers are recorded here, before the
    // core whose first epoch arithmetic would latch them exists; a value
    // the owner refuses is the row's refusal (§6).
    if let Err(disagreement) = network::record(&config) {
        tell(&mut std::io::stderr(), &format!("shekyld: {disagreement}"));
        return EXIT_FAILED;
    }
    let dev = &config.dev;
    if let Err(refusal) = shekyl_ffi::pow_randomx_ffi::record_seed_epoch(
        dev.pow_seed_epoch_blocks,
        dev.pow_seed_epoch_lag,
    ) {
        return refuse(&[owner_refusal(&resolved, refusal.row(), refusal.rule())]);
    }
    if let Err(refusal) = shekyl_ffi::archival_ffi::arm_settlement_schedule(
        dev.settlement_epoch_blocks,
        dev.archival_reorg_depth,
    ) {
        return refuse(&[owner_refusal(&resolved, refusal.row(), refusal.rule())]);
    }

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
            tell(
                &mut std::io::stderr(),
                &format!("shekyld: the signal owner's runtime could not start: {e}"),
            );
            return EXIT_FAILED;
        }
    };
    if let Err(e) = signals::own(pool.handle()) {
        tell(
            &mut std::io::stderr(),
            &format!("shekyld: the stop triggers could not be owned: {e}"),
        );
        return EXIT_FAILED;
    }
    // The options handle: the resolved values, the runtime rows' owners
    // behind the RPC's two methods (§2.7).
    let options: OptionsHandle = Arc::new(DaemonOptions::new(resolved.clone(), network));
    let status = supervise(entry, &config, &pool, network_id, options);
    pool.shutdown_background();
    drop(lock);
    // Last: every sink is a queue, and the lines logged up to here (the
    // stop's own included) reach it before the process exits. Bounded: a
    // stalled sink costs at most the flush's deadline, and nothing is said
    // about it, because the only place to say it is the stalled sink.
    let _flushed = shekyl_logging::flush(shekyl_logging::FLUSH_WITHIN);
    drop(logger);
    status
}

/// `run` returned, or a stop was requested while it was still running.
/// A small status: copied, never borrowed.
#[derive(Clone, Copy)]
enum RunWait {
    Finished(i32),
    StopRequested,
}

/// The remnant's RPC start completed, it was refused, or `run` ended or a
/// stop arrived before that start.
#[derive(Clone, Copy)]
enum Built {
    Ready,
    Refused,
    Ended(RunWait),
}

/// Steps 7 to 9: the remnant's `run` on its own thread, one wait for its
/// RPC start, one step-8 start, one wait for exit, and one teardown.
/// Returns the exit status.
///
/// The waits run on `pool`. The teardown runs on this thread, outside any
/// async context, because the RPC's stop blocks on its own runtime's drain
/// and a runtime cannot be entered from inside another's `block_on`.
fn supervise(
    entry: &ShekylDaemonEntry,
    config: &DaemonConfig,
    pool: &shekyl_runtime::Pool,
    network_id: [u8; 16],
    options: OptionsHandle,
) -> i32 {
    let Some(run) = entry.run else {
        tell(&mut std::io::stderr(), "shekyld: the entry has no run");
        return EXIT_FAILED;
    };
    let Some(stop) = entry.stop else {
        tell(&mut std::io::stderr(), "shekyld: the entry has no stop");
        return EXIT_FAILED;
    };
    let mut constructed =
        shekyl_daemon_rpc::ffi_exports::configure(config.rpc.clone(), options, config.offline());
    // Step 6: the notify runner, installed before the core that pushes to
    // it exists; its children run on the signal owner's runtime (§2.10).
    shekyl_ffi::notify_ffi::install(&config.notify, pool.handle().clone());
    // Step 6: the managed Tor's start, overlapping the core's construction;
    // awaited at step 8.
    let tor_start = tor::begin(&config.tor, &config.data_dir, pool.handle());
    let data = SnapshotData::new(config);
    let (done_tx, mut done_rx) = oneshot::channel::<i32>();
    let thread = std::thread::Builder::new()
        .name("shekyld-run".to_owned())
        .spawn(move || {
            let status = call_with(&data, run);
            // The receiver is gone only if the entry already gave up.
            let _sent = done_tx.send(status);
        });
    let thread = match thread {
        Ok(t) => t,
        Err(e) => {
            tell(
                &mut std::io::stderr(),
                &format!("shekyld: the run thread could not start: {e}"),
            );
            return EXIT_FAILED;
        }
    };

    // Step 7: the remnant constructs core, the protocol handler and
    // net_node, and calls the RPC start once; its completion is the signal
    // that the core exists for step 8.
    let mut run_status = None;
    // A network that cannot start is a failure even when `run` returned 0.
    let mut preserve_status = true;
    let mut tor_control = None;
    match pool.block_on(await_built(&mut constructed, &mut done_rx)) {
        Built::Ended(wait) => note_run(&mut run_status, wait),
        Built::Refused => note_run(&mut run_status, pool.block_on(run_or_stop(&mut done_rx))),
        Built::Ready => {
            // Step 8: the managed Tor, awaited (a stop asked meanwhile ends
            // the wait; §2.2 step 8 and the FOLLOWUPS row on the parked
            // connector); then the zone host, its listeners and the
            // dialer, each from its section; then the onion, which forwards
            // to the zone host's loopback listener.
            let tor_wait = match tor_start {
                Some(handle) => pool.block_on(async {
                    tokio::select! {
                        started = handle => Some(match started {
                            Ok(Ok(control)) => Some(control),
                            Ok(Err(not_running)) => {
                                tracing::warn!(target: "global", "{not_running}");
                                None
                            }
                            Err(e) => {
                                tracing::error!(target: "global", "the managed Tor's start task failed: {e}");
                                None
                            }
                        }),
                        cause = signals::stop_requested() => {
                            note_stop(cause);
                            None
                        }
                    }
                }),
                None => Some(None),
            };
            let Some(control) = tor_wait else {
                // Stopped during the Tor wait: nothing of step 8 starts.
                // The Tor start task finishes on the pool and is torn down
                // with it.
                return finish(
                    pool,
                    None,
                    stop,
                    thread,
                    done_rx,
                    run_status,
                    preserve_status,
                );
            };
            tor_control = control;
            let tor_socks = match (&config.tor, &tor_control) {
                (Tor::Managed { .. }, Some(control)) => network::TorSocks::At {
                    socks: shekyl_socks::Proxy::unauthenticated(control.socks_addr()),
                    onion_listen: None,
                    managed: true,
                },
                (Tor::Operator { socks, onion }, _) => network::TorSocks::At {
                    socks: network::proxy_of(socks),
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
                    note_run(&mut run_status, pool.block_on(run_or_stop(&mut done_rx)));
                }
                Err(e) => {
                    tracing::error!(target: "global", "the network could not start: {e}; stopping");
                    preserve_status = false;
                }
            }
        }
    }
    finish(
        pool,
        tor_control,
        stop,
        thread,
        done_rx,
        run_status,
        preserve_status,
    )
}

/// Step 9: the dialer and the zone host, then the RPC. The remnant's
/// stop, asked only when `run` has not finished, then joins that thread
/// while the managed Tor is torn down. Returns the exit status.
fn finish(
    pool: &shekyl_runtime::Pool,
    tor_control: Option<shekyl_tor_control_daemon::DaemonTorControl>,
    stop: crate::entry::StopFn,
    thread: std::thread::JoinHandle<()>,
    done_rx: Receiver<i32>,
    run_status: Option<i32>,
    preserve_status: bool,
) -> i32 {
    network::stop();
    shekyl_daemon_rpc::ffi_exports::stop();
    let joiner = std::thread::spawn(move || finish_remnant(stop, thread, done_rx, run_status));
    if let Some(control) = tor_control {
        let exit = pool.block_on(control.shutdown());
        tracing::info!(
            target: "global",
            "the managed Tor was torn down ({exit:?}); the address is gone, a restart mints a new one"
        );
    }
    let status = match joiner.join() {
        Ok(status) => status,
        Err(_) => {
            tracing::error!(target: "daemon", "the run thread's joiner panicked");
            EXIT_FAILED
        }
    };
    if preserve_status {
        status
    } else {
        EXIT_FAILED
    }
}

/// The RPC start, or `run` ending or a stop arriving before it.
async fn await_built(
    constructed: &mut Receiver<Result<(), String>>,
    done_rx: &mut Receiver<i32>,
) -> Built {
    tokio::select! {
        built = &mut *constructed => match built {
            Ok(Ok(())) => Built::Ready,
            Ok(Err(refusal)) => {
                tracing::error!(target: "daemon", "the RPC did not start: {refusal}");
                Built::Refused
            }
            Err(_replaced) => {
                tracing::error!(target: "daemon", "the RPC section was replaced before the start");
                Built::Refused
            }
        },
        waited = run_or_stop(done_rx) => Built::Ended(waited),
    }
}

/// `run`'s return, or a stop request. One wait, used after the RPC start
/// and again after step 8.
async fn run_or_stop(done_rx: &mut Receiver<i32>) -> RunWait {
    tokio::select! {
        finished = &mut *done_rx => RunWait::Finished(finished.unwrap_or(EXIT_FAILED)),
        cause = signals::stop_requested() => {
            note_stop(cause);
            RunWait::StopRequested
        }
    }
}

fn note_run(run_status: &mut Option<i32>, wait: RunWait) {
    if let RunWait::Finished(status) = wait {
        *run_status = Some(status);
    }
}

/// The remnant's half of step 9. `stop` is asked only when `run` has not
/// already returned. The status is `run`'s.
fn finish_remnant(
    stop: crate::entry::StopFn,
    thread: std::thread::JoinHandle<()>,
    mut done_rx: Receiver<i32>,
    status: Option<i32>,
) -> i32 {
    let status = match status {
        Some(status) => status,
        None => match done_rx.try_recv() {
            Ok(status) => status,
            Err(oneshot::error::TryRecvError::Closed) => EXIT_FAILED,
            Err(oneshot::error::TryRecvError::Empty) => {
                stop();
                done_rx.blocking_recv().unwrap_or(EXIT_FAILED)
            }
        },
    };
    if thread.join().is_err() {
        tracing::error!(target: "daemon", "the run thread ended by a panic");
    }
    status
}

/// A value its owner refuses at its own start (§6). A row's refusal is
/// pinned to that row, at the source the value came from. A latch that
/// already happened names no row: the machine holds the fact, and either
/// lever would be the wrong one to blame.
fn owner_refusal(resolved: &resolve::Resolved, row: Option<&str>, rule: &str) -> Diagnostic {
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

fn note_stop(by: &'static str) {
    tracing::warn!(target: "daemon", "stop requested by {by}");
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
        tell(&mut std::io::stderr(), &format!("shekyld: {line}"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(log_file) {
        for line in lines {
            if writeln!(f, "{line}").is_err() {
                break;
            }
        }
    }
}

/// Calls `run` with a snapshot over `data`, which outlives the call. The
/// mining header is a local: its pointers address `data`'s allocations, and
/// it lives until `run` returns.
fn call_with(data: &SnapshotData, run: RunFn) -> i32 {
    let command = data.command_ptrs();
    let header = data.mine_header();
    let snapshot = data.snapshot(&command, header.as_ref());
    run(&raw const snapshot)
}

fn call_run(entry: &ShekylDaemonEntry, config: &DaemonConfig) -> i32 {
    let Some(run) = entry.run else {
        tell(&mut std::io::stderr(), "shekyld: the entry has no run");
        return EXIT_FAILED;
    };
    call_with(&SnapshotData::new(config), run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ShekylDaemonSnapshot;
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
        let config = load(cli, &host(d.path()).platform).unwrap().config;
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
