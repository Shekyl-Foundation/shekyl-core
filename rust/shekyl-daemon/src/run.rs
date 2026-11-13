// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The start sequence (`DAEMON_CONFIG_CUTOVER.md` §2.2) and the one stop
//! path (step 9).
//!
//! Rust owns the process from its own `main`: it takes the argument
//! vector, chooses the network, reads and checks the file, resolves and
//! builds the sections, answers `--help` and `--version`, asks the
//! configuration check ([`crate::verify`]; `--config-verify` stops there,
//! `INPUT_GRAMMAR.md` IG-Q58…IG-Q62) and on a real start performs the
//! effects that check withheld, takes the lock, checks the marker, starts
//! logging, makes the announcements, opens the node (which builds the
//! network from the plan, `P2P_3_REMNANT_CUTOVER_BRIEF.md` §2), installs
//! the one signal owner, starts the RPC and the managed Tor, and waits for
//! a stop.
//! Stop is one path: chain sync is asked to stop, the RPC drains, the node
//! is dropped (the network stops, the connector finishes its message and
//! the store closes), and the managed Tor is torn down. The lock is
//! released last. A refusal exits with 2, a runtime failure with 1, and a
//! requested stop with 0.

use std::ffi::OsString;
use std::io::Write;
use std::num::NonZeroUsize;
use std::sync::Arc;

use tokio::sync::watch;

use shekyl_daemon_config::sections::{log_location_writable, DaemonConfig};
use shekyl_daemon_config::{announce, marker, Lock, Platform, TABLE};
use shekyl_options::read_cli;
use shekyl_runtime::{RuntimeBudget, ThreadName};

use shekyl_daemon_config::exit::refuse;
use shekyl_daemon_config::{load, Loaded};

use crate::options::DaemonOptions;
use crate::{help, levers, network, notify, signals, tor, verify};
use shekyl_daemon_rpc::options::OptionsHandle;

pub use shekyl_daemon_config::exit::{EXIT_FAILED, EXIT_REFUSED};

/// One line for the operator. Help and version use standard output; a
/// refusal or a failure uses standard error. A closed stream does not
/// change the exit status.
pub(crate) fn tell(out: &mut impl Write, line: &str) {
    drop(writeln!(out, "{line}"));
}

/// The whole sequence, returning the exit status. `platform` is the
/// account's and the machine's roots, so a test can run it without an
/// account.
#[must_use]
pub fn main(args: &[OsString], platform: &Platform) -> i32 {
    // Before any handler: what this process can know about an inherited
    // ignore. On Unix that is `SIGINT`'s disposition.
    let interrupt = signals::InheritedInterrupt::at_start();
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
    } = match load(cli, platform) {
        Ok(loaded) => loaded,
        Err(ds) => return refuse(&ds),
    };
    let read_path = file_read.as_deref();
    let network = config.network;

    // The walk (IG-Q59): every refusal a start makes before it creates
    // anything, with nothing created. The check prints its verdict and
    // exits; a start goes on to the effects the walk withheld.
    let walked = match verify::walk(&config, &resolved, platform) {
        Ok(walked) => walked,
        Err(ds) => return refuse(&ds),
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
    let mut announced = announce::announcements(
        &TABLE,
        &resolved,
        read_path,
        &config_path,
        &config,
        &walked.warnings,
    );
    announced.rest.extend(mining_notice(&config));
    announced.rest.extend(interrupt.line().map(str::to_owned));
    announced.rest.extend(
        walked
            .owner_socket
            .as_ref()
            .map(|plan| owner_socket_line(network.name(), plan.instance_label(), &plan.path)),
    );
    let lines = announced.into_lines();
    announce_all(&lines);

    // The owner's socket, dialled and bound before the node opens: a second
    // daemon of this account, network and instance refuses here, with
    // nothing opened (`RPC_CHANNEL.md` §7.1). The RPC serves it once the
    // node is up.
    let owner = match walked
        .owner_socket
        .as_ref()
        .map(|plan| shekyl_daemon_rpc::owner::OwnerSocket::bind(plan, network.name()))
        .transpose()
    {
        Ok(owner) => owner,
        Err(d) => return refuse(&[d]),
    };

    // The settlement schedule, armed before the node whose first epoch
    // arithmetic would latch it exists; a value the owner refuses is the
    // row's refusal (§6). The walk judged the same value without latching.
    let dev = &config.dev;
    if let Err(refusal) =
        levers::arm_settlement_schedule(dev.settlement_epoch_blocks, dev.archival_reorg_depth)
    {
        return refuse(&[verify::owner_refusal(
            &resolved,
            refusal.row(),
            refusal.rule(),
        )]);
    }

    // The managed Tor's inbox, before the node: the network publishes into
    // it from its first value (`TOR_SUPERVISOR.md` §5). The supervisor
    // starts on it once the node is open.
    let (tor_inbox, tor_feeds) = tor::prepare();
    // The node, after the marker (DX-Q6): the store, ingest, the pool,
    // chain sync, and the network built from the plan (§2). The network's
    // ban file entries are applied before its first accept, and its
    // connectors listen and dial from here.
    let node = match shekyl_node::Node::open(shekyl_node::OpenArgs {
        config: &config,
        version: version_full.to_owned(),
        protocol_version: u64::from(shekyl_version::PROTOCOL_VERSION),
        // `SHEKYL_VERSION_IS_RELEASE`, the constant the version string is
        // built from. `debug_assertions` is not that flag (FLIP-Q3).
        release_build: shekyl_version::IS_RELEASE,
        request_stop: Arc::new(signals::request_stop),
        plan: network::plan(&config, network_id),
        supervisor: Some(tor_feeds),
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
    // `mine = on`: the configured miner, once open has returned. `None`
    // is the `mine-threads` row. A refusal drops the node (its `Drop`
    // stops it) and the start fails here, rather than inside open where
    // the same stop would run twice.
    if config.mine.start {
        if let Err(refused) = node.mining().start(None) {
            tell(
                &mut std::io::stderr(),
                &format!("shekyld: the miner did not start: {refused}"),
            );
            return EXIT_FAILED;
        }
    }
    for bound in &node.network().listening().clearnet {
        tracing::info!(target: "global", "clearnet bound to {bound}");
    }

    // The one signal owner, on a runtime of its own.
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
    if let Err(e) = signals::own(pool.handle(), interrupt) {
        tell(
            &mut std::io::stderr(),
            &format!("shekyld: the stop triggers could not be owned: {e}"),
        );
        return EXIT_FAILED;
    }
    // The options handle: the resolved values, the runtime rows' owners
    // behind the RPC's two methods (§2.7). The link rows reach the
    // network's gate.
    let link_owner = node.network().clone();
    let options: OptionsHandle = Arc::new(DaemonOptions::new(
        resolved.clone(),
        network,
        Arc::new(move |limits| link_owner.set_limits(limits)),
    ));
    let status = supervise(&config, &pool, options, node, tor_inbox, owner);
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

/// A stop was requested, or a task the node owns ended on its own. Owned
/// for the report: the fatal arm holds the fault's words, and the wait
/// moves the value out to where the report is made.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RunWait {
    /// [`signals::stop_requested`] resolved with this cause.
    StopRequested(signals::StopCause),
    /// A task the node owns ended on its own ([`shekyl_node::Node::ended`]):
    /// the daemon would stay up and never sync, or never connect a block,
    /// so it stops and exits failed.
    NodeEnded(shekyl_node::NodeEnd),
}

/// The run: the RPC's start, the notify driver, the managed Tor's start,
/// one wait for a stop, and one teardown. Returns the exit status.
///
/// The wait runs on `pool`. The teardown runs on this thread, outside any
/// async context, because the RPC's stop blocks on its own runtime's drain
/// and a runtime cannot be entered from inside another's `block_on`.
fn supervise(
    config: &DaemonConfig,
    pool: &shekyl_runtime::Pool,
    options: OptionsHandle,
    node: shekyl_node::Node,
    tor_inbox: tor::Prepared,
    owner: Option<shekyl_daemon_rpc::owner::OwnerSocket>,
) -> i32 {
    // The RPC, bound before anything is announced as up. A refusal is a
    // failed start: the node is torn down the one way. The owner's socket
    // going stops the daemon through the one stop owner. The RPC asks the
    // supervisor for `daemon_status`'s Tor fields; its inbox is made
    // already, so an ask before the loop starts waits for it.
    let gone: shekyl_daemon_rpc::run::OnRendezvousGone = Arc::new(signals::rendezvous_gone);
    let rpc = match shekyl_daemon_rpc::run::start(
        &config.rpc,
        options,
        node.handles(tor_inbox.asks()),
        config.dev.rpc,
        owner.map(|socket| (socket, gone)),
    ) {
        Ok(rpc) => Some(rpc),
        Err(refusal) => {
            tracing::error!(target: "daemon", "the RPC did not start: {refusal}; stopping");
            None
        }
    };
    // The notify runner, pushed from the chain's tip watch; its children
    // run on the signal owner's runtime (§2.10).
    let runner = Arc::new(notify::Runner::new(&config.notify, pool.handle().clone()));
    let notify_driver = pool.spawn(notify::drive_blocks(runner, node.tips()));
    // The supervisor starts with the node, under every `tor` setting. A
    // managed Tor starts with it, and the node does not wait for it:
    // clearnet, the listeners and the dialer are up already, and the
    // managed connector is parked until the supervisor publishes a route.
    let supervisor = tor::begin(
        tor_inbox,
        &config.tor,
        config.clearnet_on(),
        config.network.ports().p2p,
        &config.data_dir,
        pool.handle(),
        node.network().clone(),
    );
    if let Some(forward) = node.network().listening().tor_forward {
        supervisor.note_forward(forward);
    }
    let mut preserve_status = rpc.is_some();
    if rpc.is_some() {
        let mut ended = node.ended();
        let wait = pool.block_on(run_or_stop(&mut ended));
        note_run(&mut preserve_status, wait);
    }
    notify_driver.abort();
    finish(pool, supervisor, rpc, preserve_status, node)
}

/// The teardown: chain sync is asked to stop, the RPC drains, the node is
/// dropped (its network stops, the connector finishes its message and the
/// store closes) while the managed Tor is torn down (`TOR_SUPERVISOR.md`
/// §1, DX-Q6). Returns the exit status.
///
/// The last line the stop logs names how long the node took to close.
/// The stop path reports on itself: a store on a slow disk once held the
/// C++ daemon's main thread in uninterruptible sleep for tens of seconds
/// after its deinit line, silently. `regtest_e2e`'s
/// `a_stops_last_line_reaches_the_log_file` reads this line from the file.
fn finish(
    pool: &shekyl_runtime::Pool,
    supervisor: tor::Supervisor,
    rpc: Option<shekyl_daemon_rpc::run::Running>,
    preserve_status: bool,
    node: shekyl_node::Node,
) -> i32 {
    // Before the network closes. The owner's end reads a stop that is
    // already asked as a stop; a port dropped first would be a failure.
    node.request_sync_stop();
    if let Some(rpc) = rpc {
        rpc.stop();
    }
    let closing = std::time::Instant::now();
    drop(node);
    let closed_in = closing.elapsed();
    let managed = supervisor.managed();
    pool.block_on(supervisor.shutdown());
    if managed {
        tracing::info!(target: "global", "the managed Tor was torn down");
    }
    tracing::info!(
        target: "daemon",
        "the node closed in {closed_in:?}; the daemon exits"
    );
    if preserve_status {
        0
    } else {
        EXIT_FAILED
    }
}

/// A stop request, or a task the node owns ending on its own.
///
/// Only this wait reads the node's end watch. Teardown asks chain sync's
/// owner to stop before the network closes, and a task that was asked to
/// stop does not report, so this wait is not polled while the node is
/// dropped. A reported end is read before a stop request: the node's
/// tasks are stopped only in the teardown, so a stop cannot cause one.
async fn run_or_stop(ended: &mut watch::Receiver<Option<shekyl_node::NodeEnd>>) -> RunWait {
    tokio::select! {
        biased;
        end = node_ended(ended) => RunWait::NodeEnded(end),
        cause = signals::stop_requested() => RunWait::StopRequested(cause),
    }
}

/// Resolves when a task the node owns has ended on its own, with its end.
/// A watch that closes without one never resolves.
async fn node_ended(
    ended: &mut watch::Receiver<Option<shekyl_node::NodeEnd>>,
) -> shekyl_node::NodeEnd {
    loop {
        if let Some(end) = ended.borrow_and_update().as_ref().cloned() {
            return end;
        }
        // A watch that closed without an end never resolves. The biased
        // select then stays on the stop request.
        if ended.changed().await.is_err() {
            std::future::pending().await
        }
    }
}

/// Record what the wait returned: a stop, or a node task's own end, which
/// stops the daemon through the one stop owner and makes its exit a
/// failure.
fn note_run(preserve_status: &mut bool, wait: RunWait) {
    match wait {
        RunWait::StopRequested(cause) => {
            if matches!(cause, signals::StopCause::Fatal(_)) {
                *preserve_status = false;
            }
            deliver(stop_report(cause));
        }
        RunWait::NodeEnded(end) => {
            deliver(stop_report(signals::StopCause::Fatal(end.clone())));
            signals::fatal(end);
            *preserve_status = false;
        }
    }
}

/// What the operator is told about one stop. The match is the whole
/// policy: a new [`signals::StopCause`] variant has to choose here.
#[derive(Debug, PartialEq, Eq)]
enum StopReport {
    /// An IG-14 announcement: standard error and the log, whatever the
    /// level, with no level tag.
    Announce(String),
    /// An error event.
    Error(String),
}

fn stop_report(cause: signals::StopCause) -> StopReport {
    match cause {
        signals::StopCause::Signal(_)
        | signals::StopCause::Requested
        | signals::StopCause::RendezvousGone => {
            StopReport::Announce(format!("stop requested by {cause}"))
        }
        signals::StopCause::Fatal(end) => StopReport::Error(format!("{end}; the daemon stops")),
    }
}

fn deliver(report: StopReport) {
    match report {
        StopReport::Announce(line) => announce_all(&[line]),
        StopReport::Error(line) => tracing::error!(target: "daemon", "{line}"),
    }
}

/// The line a start with `mine = on` announces when the node's declaration
/// is `Open` (DC-F41, rule 82). Such a node mines only once it has a view
/// of its network, and a node alone on an open network never gets one:
/// until then the only signs are `mine_status`'s `cause` and a dialer
/// warning. `None` for `mine = off`, or for a node declared offline or
/// closed, which is synced at open and mines at once. The configuration
/// check repeats it ([`crate::verify`]).
#[must_use]
pub fn mining_notice(config: &DaemonConfig) -> Option<String> {
    if !config.mine.start || shekyl_node::declaration(config) != shekyl_node::Declaration::Open {
        return None;
    }
    Some(
        "mining: the miner waits for a view of the network; a node alone on an open network \
         never gets one, and mines alone only when declared offline (`clearnet = off` and \
         `tor = off`) or closed (`p2p-closed-peer`)"
            .to_owned(),
    )
}

/// The announcements, on standard error and in the log, whatever the level.
///
/// Each line is queued on the installed sinks, so the call does not wait
/// on one and does not open the log beside the rolling writer. Standard
/// error is prefixed `shekyld:`; the log line is the line alone. The
/// closing [`shekyl_logging::flush`] delivers a line queued before it.
/// The line a start announces about its owner's socket (`RPC_CHANNEL.md`
/// §7.1): the socket's name is a hash, so the operator is told which
/// network and instance it serves and where it is.
fn owner_socket_line(network: &str, instance: &str, path: &std::path::Path) -> String {
    format!(
        "owner's socket: network {network}, instance {instance}, at {}",
        path.display()
    )
}

fn announce_all(lines: &[String]) {
    for line in lines {
        shekyl_logging::announce(&format!("shekyld: {line}"), line);
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
    use std::path::Path;
    use std::sync::Mutex;

    /// The signal owner's request and the schedule latches are
    /// process-global: the tests that drive them run one at a time.
    /// [`super::hold_process_table`] is the same lock for a test outside
    /// this module.
    pub(super) static SERIAL: Mutex<()> = Mutex::new(());

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

    #[test]
    fn a_refusal_exits_with_two_and_help_and_version_with_zero() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(main(&args(&["--bogus"]), &platform(d.path())), EXIT_REFUSED);
        assert_eq!(main(&args(&["--help"]), &platform(d.path())), 0);
        assert_eq!(main(&args(&["--version"]), &platform(d.path())), 0);
        assert_eq!(
            main(
                &args(&["--network", "regtest", "--dev-difficulty", "0"]),
                &platform(d.path())
            ),
            EXIT_REFUSED
        );
        assert!(!d.path().join(".shekyl").exists(), "nothing was created");
    }

    /// `mine = on` without `mine-address` is the parser's refusal, naming
    /// that row; a `mine-threads` count above the host's parallelism is
    /// the configuration check's. Both exit 2 before anything starts
    /// (Rick, 2026-11-02): no data directory, no lock, no log. Red edit:
    /// let either reach the node.
    #[test]
    fn mine_on_without_an_address_and_too_many_threads_both_exit_two() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            main(
                &args(&["--network", "regtest", "--mine", "on"]),
                &platform(d.path())
            ),
            EXIT_REFUSED
        );
        let host_threads = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        let past = (host_threads + 1).to_string();
        assert_eq!(
            main(
                &args(&[
                    "--network",
                    "regtest",
                    "--clearnet",
                    "off",
                    "--tor",
                    "off",
                    "--mine-threads",
                    &past
                ]),
                &platform(d.path())
            ),
            EXIT_REFUSED
        );
        assert!(!d.path().join(".shekyl").exists(), "nothing started");
    }

    /// A bare word is refused before the load, the lock, or any socket.
    #[test]
    fn a_bare_word_is_refused_before_the_daemon_starts() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(main(&args(&["status"]), &platform(d.path())), EXIT_REFUSED);
        assert!(!d.path().join(".shekyl").exists(), "nothing was created");
    }

    /// An offline regtest node in `data`, with no RPC listener, and the
    /// configuration it was built from.
    fn offline_node(d: &Path, data: &Path, log: &Path) -> (DaemonConfig, shekyl_node::Node) {
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
        let config = load(cli, &platform(d)).unwrap().config;
        let node = shekyl_node::Node::open(shekyl_node::OpenArgs {
            config: &config,
            version: "test".to_owned(),
            protocol_version: u64::from(shekyl_version::PROTOCOL_VERSION),
            release_build: false,
            request_stop: Arc::new(crate::signals::request_stop),
            plan: network::plan(&config, [3u8; 16]),
            supervisor: None,
        })
        .expect("the node opens");
        (config, node)
    }

    /// The daemon's own request, the RPC's `daemon_stop`, reaches the one
    /// owner, and the run ends with 0: one stop path, whatever asked. The
    /// RPC that served it is started and stopped by the run.
    #[test]
    fn a_stop_request_runs_the_one_stop_path() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let log = d.path().join("shekyld.log");
        let (config, node) = offline_node(d.path(), &data, &log);
        let budget = RuntimeBudget {
            workers: NonZeroUsize::MIN,
            blocking: NonZeroUsize::MIN,
        };
        let pool =
            shekyl_runtime::runtime(budget, &ThreadName::new("test-signals").unwrap()).unwrap();
        // Clears a stop an earlier test latched.
        signals::own(pool.handle(), signals::InheritedInterrupt::ordinary()).expect("own");
        let requester = std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            crate::signals::request_stop();
        });
        let status = supervise(
            &config,
            &pool,
            Arc::new(shekyl_daemon_rpc::options::OptionsAbsent),
            node,
            crate::tor::prepare().0,
            None,
        );
        requester.join().unwrap();
        assert_eq!(status, 0, "a requested stop is the exit status 0");
        assert_eq!(
            pool.block_on(signals::stop_requested()),
            signals::StopCause::Requested
        );
        pool.shutdown_background();
    }

    /// The one test that starts a daemon: logging installs once per
    /// process, so this is the only test that reaches it. It locks, marks,
    /// logs, announces, opens the node and its network, runs until a stop
    /// is requested, and releases the lock. Red edit: return success when
    /// the node fails to open, or skip the marker.
    #[test]
    fn a_daemon_start_locks_marks_logs_announces_runs_and_stops_on_request() {
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
            "--rpc-admin-listen",
            "none",
            "--data-dir",
            data.to_str().unwrap(),
            "--log-file",
            log.to_str().unwrap(),
        ]);
        // The start clears the latch when it installs the signal owner,
        // after the marker and the node; a request made before that is
        // cleared with it. So the requester asks again until the run has
        // returned: the first request after the owner is installed ends it.
        let marker = data.join("shekyld.network");
        let returned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = Arc::clone(&returned);
        let requester = std::thread::spawn(move || {
            while !seen.load(std::sync::atomic::Ordering::SeqCst) {
                if marker.is_file() {
                    crate::signals::request_stop();
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
        let status = main(&a, &platform(d.path()));
        returned.store(true, std::sync::atomic::Ordering::SeqCst);
        requester.join().unwrap();
        assert_eq!(status, 0);
        assert!(data.join("shekyld.lock").is_file());
        let m = std::fs::read_to_string(data.join("shekyld.network")).unwrap();
        assert!(m.contains("network = \"regtest\""), "{m}");
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("effective configuration:"), "{text}");
        assert!(text.contains("posture:"), "{text}");
        // The stop was asked for: an announcement, in the log whatever the
        // level, with no level tag (IG-14; alpha.11 bug hunt).
        let stop = text
            .lines()
            .find(|line| line.contains("stop requested by"))
            .unwrap_or_else(|| panic!("no stop announcement: {text}"));
        assert_eq!(stop, "stop requested by the RPC's daemon_stop", "{text}");
        // The lock was released at the end: it can be taken again.
        assert!(Lock::take(&data).is_ok());
    }

    /// **A node task that ends on its own stops the daemon, and the exit
    /// is a failure** (the CS-5 tune-up, and the ingest fault of
    /// 2026-11-02). A watch that reports nothing does not end the wait. A
    /// reported end does, with its cause: the cause reaches the one stop
    /// owner, so every waiter sees it, and the status the teardown returns
    /// is a failure. The cases are the node's two producers.
    #[test]
    fn a_node_task_that_ends_on_its_own_stops_the_daemon_with_its_cause() {
        for end in [
            shekyl_node::NodeEnd::Sync(shekyl_node::EndCause::PortClosed),
            shekyl_node::NodeEnd::Ingest(shekyl_node::ServiceEnd::words("connector unreachable")),
        ] {
            a_reported_end_stops_the_daemon(end);
        }
    }

    fn a_reported_end_stops_the_daemon(end: shekyl_node::NodeEnd) {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        // Clears a stop an earlier test latched.
        signals::own(rt.handle(), signals::InheritedInterrupt::ordinary()).expect("own");
        let (ended_tx, mut ended) = watch::channel(None);
        let waited = rt.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                run_or_stop(&mut ended),
            )
            .await
        });
        assert!(waited.is_err(), "a watch with no end ended the wait");
        ended_tx.send_replace(Some(end.clone()));
        let wait = rt.block_on(run_or_stop(&mut ended));
        assert_eq!(wait, RunWait::NodeEnded(end.clone()));
        let mut preserve_status = true;
        note_run(&mut preserve_status, wait);
        assert!(!preserve_status, "the exit was not made a failure");
        assert_eq!(
            rt.block_on(signals::stop_requested()),
            signals::StopCause::Fatal(end)
        );
    }

    /// **A fatal cause on the stop arm fails the exit.** The owner's
    /// failed end is the other arm; this is a waiter that sees the cause
    /// the latch already holds. Red edit: leave `preserve_status` set.
    #[test]
    fn a_latched_fatal_cause_fails_the_exit() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        signals::own(rt.handle(), signals::InheritedInterrupt::ordinary()).expect("own");
        let end = shekyl_node::NodeEnd::Sync(shekyl_node::EndCause::EngineClosed);
        signals::fatal(end.clone());
        let (_ended_tx, mut ended) = watch::channel(None);
        let wait = rt.block_on(run_or_stop(&mut ended));
        assert_eq!(wait, RunWait::StopRequested(signals::StopCause::Fatal(end)));
        let mut preserve_status = true;
        note_run(&mut preserve_status, wait);
        assert!(!preserve_status, "a fatal cause kept the exit");
    }

    /// **An asked-for stop is announced, a forced one is the sync error.**
    /// The report matches the cause. Red edit: announce a fatal cause,
    /// or report an asked-for stop as an error.
    #[test]
    fn an_asked_for_stop_is_announced_and_a_forced_one_is_an_error() {
        use signals::StopCause;
        assert_eq!(
            stop_report(StopCause::Requested),
            StopReport::Announce("stop requested by the RPC's daemon_stop".to_owned())
        );
        #[cfg(unix)]
        assert_eq!(
            stop_report(StopCause::Signal(signals::Signal::Terminate)),
            StopReport::Announce("stop requested by SIGTERM".to_owned())
        );
        #[cfg(windows)]
        assert_eq!(
            stop_report(StopCause::Signal(signals::Signal::Shutdown)),
            StopReport::Announce("stop requested by shutdown".to_owned())
        );
        assert_eq!(
            stop_report(StopCause::Fatal(shekyl_node::NodeEnd::Sync(
                shekyl_node::EndCause::PortClosed
            ))),
            StopReport::Error(
                "chain sync stopped: the session layer dropped the sync owner; the daemon stops"
                    .to_owned()
            )
        );
        assert_eq!(
            stop_report(StopCause::Fatal(shekyl_node::NodeEnd::Ingest(
                shekyl_node::ServiceEnd::words("connector unreachable")
            ))),
            StopReport::Error(
                "the ingest service stopped: connector unreachable; the daemon stops".to_owned()
            )
        );
    }
}
