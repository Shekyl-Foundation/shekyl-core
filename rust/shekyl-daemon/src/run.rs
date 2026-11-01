// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The start sequence (`DAEMON_CONFIG_CUTOVER.md` §2.2) and the one stop
//! path (step 9).
//!
//! Rust owns the process from its own `main`: it takes the argument
//! vector, chooses the network, reads and checks the file, resolves and builds the sections,
//! answers `--help` and `--version`, asks the configuration check
//! ([`crate::verify`]; `--config-verify` stops there, `INPUT_GRAMMAR.md`
//! IG-Q58…IG-Q62) and on a real start performs the effects that check
//! withheld, takes the lock, checks the marker, starts logging, makes the
//! announcements, installs the one signal
//! owner, fills the snapshot and calls the remnant's `run` on a thread of
//! its own, with a stack of its own size (DC-F21).
//! Stop is one path: the dialer and the zone host, then the RPC, then the
//! node (the connector finishes its message and the store closes), then the
//! remnant's `stop` (only when `run` has not finished) together with the
//! managed Tor's teardown. The lock is released last. A refusal exits with
//! 2, a runtime failure with 1, and `run`'s status becomes the exit status
//! otherwise.

use std::ffi::OsString;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::oneshot::{self, Receiver};

use shekyl_daemon_config::sections::{log_location_writable, DaemonConfig, Tor};
use shekyl_daemon_config::{announce, marker, Lock, Platform, TABLE};
use shekyl_options::read_cli;
use shekyl_runtime::{RuntimeBudget, ThreadName};

use shekyl_daemon_config::exit::refuse;
use shekyl_daemon_config::{load, Loaded};
use shekyl_ffi::daemon_snapshot_ffi::SnapshotData;

use crate::options::DaemonOptions;
use crate::remnant::{Remnant, StopFn};
use crate::{help, network, signals, tor, verify};
use shekyl_daemon_rpc::options::OptionsHandle;

pub use shekyl_daemon_config::exit::{EXIT_FAILED, EXIT_REFUSED};

/// One line for the operator. Help and version use standard output; a
/// refusal or a failure uses standard error. A closed stream does not
/// change the exit status.
pub(crate) fn tell(out: &mut impl Write, line: &str) {
    drop(writeln!(out, "{line}"));
}

/// The platform facts and the one derivation the sequence needs, so a test
/// can run it without an account or a build.
pub struct Host {
    /// The account's and the machine's roots.
    pub platform: Platform,
    /// The network id of a `cryptonote::network_type` code.
    pub network_id_of: fn(u8) -> Option<[u8; 16]>,
}

/// The whole sequence, returning the exit status.
#[must_use]
pub fn main(remnant: Remnant, args: &[OsString], host: &Host) -> i32 {
    let (program, rest) = match args.split_first() {
        Some((p, rest)) => (p.clone(), rest.to_vec()),
        None => (OsString::from("shekyld"), Vec::new()),
    };
    let program = program.to_string_lossy().into_owned();
    let cli = match read_cli(&TABLE, rest.iter().cloned()) {
        Ok(cli) => cli,
        Err(ds) => return refuse(&ds),
    };
    // The build identity, from the one home every binary reads (DC-Q20).
    let release_name = shekyl_version::RELEASE_NAME;
    let version_full = shekyl_version::VERSION_FULL;
    if cli.given.iter().any(|g| g.row.name == "help") {
        print!(
            "{}",
            help::render(&TABLE, &program, release_name, version_full)
        );
        return 0;
    }
    if cli.given.iter().any(|g| g.row.name == "version") {
        tell(
            &mut std::io::stdout(),
            &format!(
                "Shekyl '{release_name}' (v{version_full}, protocol {})\nOS: {} {}",
                shekyl_version::PROTOCOL_VERSION,
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

    // Client mode: no lock, no marker, no log file, no announcement. The
    // configuration check stops here too: a client is not a start.
    if config.is_client() {
        if config.session.verify {
            return verify::accept(&resolved, read_path, &config_path, &config, &[]);
        }
        return SnapshotData::new(&config).call(remnant.run);
    }

    // The walk (IG-Q59): every refusal a start makes before it creates
    // anything, with nothing created. The check prints its verdict and
    // exits; a start goes on to the effects the walk withheld.
    let walked = match verify::walk(&config, &resolved, host) {
        Ok(walked) => walked,
        Err(verify::Stopped::Refused(ds)) => return refuse(&ds),
        Err(verify::Stopped::Failed(line)) => {
            tell(&mut std::io::stderr(), &format!("shekyld: {line}"));
            return EXIT_FAILED;
        }
    };
    if config.session.verify {
        return verify::accept(
            &resolved,
            read_path,
            &config_path,
            &config,
            &walked.warnings,
        );
    }
    let network_id = walked.network_id;

    // The lock, the marker (read again under the lock, written when
    // absent), the log location.
    let lock = match Lock::take(&config.data_dir) {
        Ok(l) => l,
        Err(d) => return refuse(&[d]),
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
    let lines = announce::announcements(
        &TABLE,
        &resolved,
        read_path,
        &config_path,
        &config,
        &walked.warnings,
    )
    .into_lines();
    announce_all(&config.logging.file, &lines);

    // The node, after the marker and before the remnant's run (DX-Q6).
    // Its socket table is the process table, installed before `record`
    // writes the ban file onto it and before the zone server binds.
    let node = match shekyl_node::Node::open(shekyl_node::OpenArgs {
        config: &config,
        version: version_full.to_owned(),
        protocol_version: u64::from(shekyl_version::PROTOCOL_VERSION),
        // `SHEKYL_VERSION_IS_RELEASE`, the constant the version string is
        // built from. `debug_assertions` is not that flag (FLIP-Q3).
        release_build: shekyl_version::IS_RELEASE,
        request_stop: Arc::new(signals::request_stop),
    }) {
        Ok(node) => node,
        Err(error) => {
            tell(
                &mut std::io::stderr(),
                &format!("shekyld: the node did not start: {error}"),
            );
            return EXIT_FAILED;
        }
    };
    if !shekyl_ffi::seam_ffi::install_process_sockets(node.sockets()) {
        tell(
            &mut std::io::stderr(),
            "shekyld: a zone hub is already bound, so the node's socket table cannot replace it",
        );
        return EXIT_FAILED;
    }

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
        return refuse(&[verify::owner_refusal(
            &resolved,
            refusal.row(),
            refusal.rule(),
        )]);
    }
    if let Err(refusal) = shekyl_ffi::archival_ffi::arm_settlement_schedule(
        dev.settlement_epoch_blocks,
        dev.archival_reorg_depth,
    ) {
        return refuse(&[verify::owner_refusal(
            &resolved,
            refusal.row(),
            refusal.rule(),
        )]);
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
    let status = supervise(remnant, &config, &pool, network_id, options, node);
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

/// The `shekyld-run` thread's stack (DC-F21).
const REMNANT_STACK_BYTES: usize = 2 * 1024 * 1024;

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
    remnant: Remnant,
    config: &DaemonConfig,
    pool: &shekyl_runtime::Pool,
    network_id: [u8; 16],
    options: OptionsHandle,
    node: shekyl_node::Node,
) -> i32 {
    let handles = node.handles();
    let Remnant { run, stop } = remnant;
    let mut constructed = shekyl_daemon_rpc::ffi_exports::configure(
        config.rpc.clone(),
        options,
        handles,
        config.offline(),
        config.dev.rpc,
    );
    // Step 6: the notify runner, installed before the core that pushes to
    // it exists; its children run on the signal owner's runtime (§2.10).
    shekyl_ffi::notify_ffi::install(&config.notify, pool.handle().clone());
    // The managed Tor starts with the core. Step 8 does not wait for it.
    let clearnet_on = config.clearnet_on();
    let supervisor = tor::begin(
        &config.tor,
        clearnet_on,
        config.network.p2p_port(),
        &config.data_dir,
        pool.handle(),
    );
    let data = SnapshotData::new(config);
    let (done_tx, mut done_rx) = oneshot::channel::<i32>();
    let thread = std::thread::Builder::new()
        .name("shekyld-run".to_owned())
        // The remnant's stack, stated here so `RUST_MIN_STACK` cannot
        // change it (DC-F21). The C++ it runs is the daemon's construction,
        // the console and the stop wait; the deep readers (the connection
        // handlers, the RPC, the core) run on their own threads with their
        // own stacks. Two MiB is what every platform's main thread has
        // given it, and more than the std default on some.
        .stack_size(REMNANT_STACK_BYTES)
        .spawn(move || {
            let status = data.call(run);
            // The receiver is gone only if the sequence already gave up.
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
    match pool.block_on(await_built(&mut constructed, &mut done_rx)) {
        Built::Ended(wait) => note_run(&mut run_status, wait),
        Built::Refused => note_run(&mut run_status, pool.block_on(run_or_stop(&mut done_rx))),
        Built::Ready => {
            // Step 8 does not wait for Tor. Clearnet, the listeners and the
            // dialer start at once. The managed connector is parked until
            // the supervisor publishes a route.
            let tor_socks = match &config.tor {
                Tor::Managed { .. } => network::TorSocks::Managed,
                Tor::Operator { socks, onion } => network::TorSocks::Operator {
                    socks: network::proxy_of(socks),
                    onion_listen: onion.as_ref().map(|onion| onion.listen),
                },
                Tor::Off => network::TorSocks::None,
            };
            match network::start(config, network_id, tor_socks) {
                Ok(started) => {
                    if let (Some(supervisor), Some(forward)) = (&supervisor, started.tor_forward) {
                        supervisor.note_forward(forward);
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
        supervisor,
        RemnantJoin {
            stop,
            thread,
            done_rx,
            run_status,
        },
        preserve_status,
        node,
    )
}

/// The remnant half of step 9: its stop, the thread `run` is on, and the
/// status that thread has already produced when it has finished.
struct RemnantJoin {
    stop: StopFn,
    thread: std::thread::JoinHandle<()>,
    done_rx: Receiver<i32>,
    run_status: Option<i32>,
}

/// Step 9: the dialer and the zone host, then the RPC, then the node.
/// The remnant's stop, asked only when `run` has not finished, then joins
/// that thread while the managed Tor is torn down. The node is dropped
/// after the dialer and the RPC, and before the remnant is joined: the
/// connector finishes its message and the store closes before Tor is torn
/// down (`TOR_SUPERVISOR.md` §1, DX-Q6). Returns the exit status.
fn finish(
    pool: &shekyl_runtime::Pool,
    supervisor: Option<tor::Supervisor>,
    remnant: RemnantJoin,
    preserve_status: bool,
    node: shekyl_node::Node,
) -> i32 {
    network::stop();
    shekyl_daemon_rpc::ffi_exports::stop();
    // Before the remnant join, not at the end of this function: Tor's
    // teardown overlaps that join, and the store closes first.
    drop(node);
    let RemnantJoin {
        stop,
        thread,
        done_rx,
        run_status,
    } = remnant;
    let joiner = std::thread::spawn(move || finish_remnant(stop, thread, done_rx, run_status));
    if let Some(supervisor) = supervisor {
        pool.block_on(supervisor.shutdown());
        tracing::info!(target: "global", "the managed Tor was torn down");
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
    stop: StopFn,
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

fn note_stop(by: &'static str) {
    tracing::warn!(target: "daemon", "stop requested by {by}");
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

/// The process socket table, the RPC section and the signal owner are
/// process-global. A test that reads or replaces any of them holds this
/// for the whole body, so it cannot interleave with another.
#[cfg(test)]
pub(crate) fn hold_process_table() -> std::sync::MutexGuard<'static, ()> {
    tests::SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_ffi::daemon_snapshot_ffi::ShekylDaemonSnapshot;
    use std::ffi::c_int;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static RUNS: AtomicUsize = AtomicUsize::new(0);
    /// The RPC section, the owners' records, the signal owner's request
    /// and the process socket table are process-global: the tests that
    /// drive them run one at a time. [`super::hold_process_table`] is the
    /// same lock for a test outside this module.
    pub(super) static SERIAL: Mutex<()> = Mutex::new(());
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

    fn remnant() -> Remnant {
        Remnant {
            run: fake_run,
            stop: fake_stop,
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
            main(remnant(), &args(&["--bogus"]), &host(d.path())),
            EXIT_REFUSED
        );
        assert_eq!(main(remnant(), &args(&["--help"]), &host(d.path())), 0);
        assert_eq!(main(remnant(), &args(&["--version"]), &host(d.path())), 0);
        assert_eq!(
            main(
                remnant(),
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
            remnant(),
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
        let data = d.path().join("data");
        let log = d.path().join("shekyld.log");
        let a = args(&[
            "--network",
            "regtest",
            "--clearnet",
            "off",
            "--tor",
            "off",
            "--rpc-admin-listen",
            "none",
            "--data-dir",
            data.to_str().unwrap(),
            "--log-file",
            log.to_str().unwrap(),
        ]);
        let cli = read_cli(&TABLE, a[1..].to_vec()).unwrap();
        let config = load(cli, &host(d.path()).platform).unwrap().config;
        let node = shekyl_node::Node::open(shekyl_node::OpenArgs {
            config: &config,
            version: "test".to_owned(),
            protocol_version: u64::from(shekyl_version::PROTOCOL_VERSION),
            release_build: false,
            request_stop: Arc::new(crate::signals::request_stop),
        })
        .expect("the node opens");
        let remnant = Remnant {
            run: blocking_run,
            stop: arming_stop,
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
            crate::stop::shekyl_daemon_request_stop();
        });
        let status = supervise(
            remnant,
            &config,
            &pool,
            [3u8; 16],
            Arc::new(shekyl_daemon_rpc::options::OptionsAbsent),
            node,
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
    /// process, so this is the only test that reaches it. Red edit: build
    /// the node after `network::record`, or return success when the node
    /// fails to open. The fake remnant does not cover a live `shekyld`.
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
        let status = main(remnant(), &a, &host(d.path()));
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
