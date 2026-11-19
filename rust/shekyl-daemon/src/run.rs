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
use shekyl_options::{read_cli, Cli, Code, Diagnostic};
use shekyl_runtime::{RuntimeBudget, ThreadName};
use shekyl_spawn::owning::OwningConnection;

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

/// The one way a start ends refused or failed (Rick, 2026-11-18): each line
/// on standard error, prefixed with the daemon's name, and in the log file
/// when it can be opened. Every refusal and failure of [`main_loading`]
/// goes through it, so a service, whose standard error the operator may
/// never see, leaves why it did not start where its log is.
pub(crate) enum StartEnd {
    /// Before the configuration names a log file, and in `--config-verify`,
    /// which writes nothing: standard error alone.
    Stderr,
    /// The configuration named this log file and the logger is not running
    /// yet: the lines are appended to it as the logger would append them,
    /// the file created at `0600` when its directory exists.
    LogFile(std::path::PathBuf),
    /// The logger runs: its two sinks carry the lines, flushed before the
    /// exit.
    Logger,
}

impl StartEnd {
    /// A refusal: its diagnostics, and [`EXIT_REFUSED`].
    pub(crate) fn refuse(&self, diagnostics: &[Diagnostic]) -> i32 {
        self.say(
            &diagnostics
                .iter()
                .map(Diagnostic::render)
                .collect::<Vec<_>>(),
        );
        EXIT_REFUSED
    }

    /// A failure: its line, and [`EXIT_FAILED`].
    pub(crate) fn fail(&self, line: String) -> i32 {
        self.say(&[line]);
        EXIT_FAILED
    }

    fn say(&self, lines: &[String]) {
        match self {
            Self::Stderr => {
                for line in lines {
                    tell(&mut std::io::stderr(), &format!("shekyld: {line}"));
                }
            }
            Self::LogFile(path) => {
                for line in lines {
                    tell(&mut std::io::stderr(), &format!("shekyld: {line}"));
                }
                // A log that cannot be opened is left unwritten; standard
                // error has the lines.
                drop(shekyl_logging::append_before_start(path, lines));
            }
            Self::Logger => {
                for line in lines {
                    shekyl_logging::announce(&format!("shekyld: {line}"), line);
                }
                let _flushed = shekyl_logging::flush(shekyl_logging::FLUSH_WITHIN);
            }
        }
    }

    /// A start fault of the RPC's set-up, at its open (before the node) or
    /// its start (after it): a file held open past the wait
    /// (`config.replace.held-open`) and a missing or exposed rendezvous key
    /// (`config.service.rendezvous-key`) are refusals; anything else fails
    /// with `context` before its words.
    fn rpc_fault(
        &self,
        fault: shekyl_daemon_rpc::run::StartFault,
        data_dir: &std::path::Path,
        context: &str,
    ) -> i32 {
        match fault {
            shekyl_daemon_rpc::run::StartFault::HeldOpen(held) => {
                self.refuse(&[shekyl_daemon_config::replace::held_open_refusal(
                    &held, data_dir,
                )])
            }
            shekyl_daemon_rpc::run::StartFault::Refused(why) => {
                self.fail(format!("{context}: {why}"))
            }
            shekyl_daemon_rpc::run::StartFault::RendezvousKey { key, found } => {
                self.refuse(&[shekyl_daemon_rpc::run::rendezvous_key_refusal(&key, &found)])
            }
        }
    }
}

/// The load step of the sequence: [`fn@load`] in the daemon.
pub type LoadStep = fn(Cli, &Platform) -> Result<Loaded, Vec<Diagnostic>>;

/// The whole sequence, returning the exit status. `platform` is the
/// account's and the machine's roots, so a test can run it without an
/// account.
#[must_use]
pub fn main(args: &[OsString], platform: &Platform) -> i32 {
    main_loading(args, platform, load)
}

/// [`main`], with its load step named. The daemon's is [`fn@load`]. A test
/// that names no configuration file passes
/// [`shekyl_daemon_config::load_default_file_unread`]: `platform` gives it
/// its own roots, but on Unix the default file's path is the machine's, and
/// a test must not read the host it runs on. Every other step is this one
/// body's.
#[must_use]
pub fn main_loading(args: &[OsString], platform: &Platform, load: LoadStep) -> i32 {
    // Before any handler: what this process can know about an inherited
    // ignore. On Unix that is `SIGINT`'s disposition.
    let interrupt = signals::InheritedInterrupt::at_start();
    let mut end = StartEnd::Stderr;
    let (program, rest) = match args.split_first() {
        Some((p, rest)) => (p.clone(), rest.to_vec()),
        None => (OsString::from("shekyld"), Vec::new()),
    };
    let program = program.to_string_lossy().into_owned();
    let cli = match read_cli(&TABLE, rest.iter().cloned()) {
        Ok(cli) => cli,
        Err(ds) => return end.refuse(&ds),
    };
    // The owning connection, adopted before anything else this process does
    // (IG-Q106): close-on-exec or not inheritable before any child can be
    // spawned, so none holds a copy that outlives the daemon.
    let owning = match adopt_owning_connection(&cli) {
        Ok(owning) => owning,
        Err(d) => return end.refuse(&[d]),
    };
    // A second handle, held until this function returns and never read or
    // written. The watch drops its own handle when it sees the close, at
    // the start of the stop; this one keeps the daemon's end open through
    // the teardown, the lock's release and the log's flush. So the
    // starting process reads end of stream when the daemon is gone, not
    // when its stop began, and may start the next daemon on that read.
    let _owning_to_exit = match owning.as_ref().map(OwningConnection::try_clone).transpose() {
        Ok(held) => held,
        Err(e) => {
            return end.fail(format!("the owning connection could not be held: {e}"));
        }
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
        config_file,
        resolved,
        config,
    } = match load(cli, platform) {
        Ok(loaded) => loaded,
        Err(ds) => return end.refuse(&ds),
    };
    let network = config.network;
    // From here a refusal also reaches the log file the configuration
    // names; `--config-verify` writes nothing.
    if !config.session.verify {
        end = StartEnd::LogFile(config.logging.file.clone());
    }

    // The walk (IG-Q59): every refusal a start makes before it creates
    // anything, with nothing created. The check prints its verdict and
    // exits; a start goes on to the effects the walk withheld.
    let walked = match verify::walk(&config, &resolved, platform) {
        Ok(walked) => walked,
        Err(ds) => return end.refuse(&ds),
    };
    if config.session.verify {
        return verify::accept(&resolved, &config_file, &config, &walked.warnings);
    }
    let network_id = walked.network_id;

    // The lock, the marker (read again under the lock, written when
    // absent), the log location.
    let lock = match Lock::take(&config.data_dir) {
        Ok(l) => l,
        Err(d) => return end.refuse(&[d]),
    };
    if let Err(d) = marker::check_or_write(&lock, network, network_id) {
        return end.refuse(&[d]);
    }
    // The console key's reset (IG-Q88): under the lock just taken, held
    // through the whole replacement, so it cannot run beside a daemon and a
    // start waits on it (`RPC_CHANNEL.md` §5). It touches no other
    // enrollment, and exits without starting the node.
    if config.session.console_key_reset {
        return match shekyl_daemon_rpc::channel::reset_console_key(&config.data_dir) {
            Ok(path) => {
                tell(
                    &mut std::io::stdout(),
                    &format!(
                        "the console key was replaced; its private half is {}",
                        path.display()
                    ),
                );
                drop(lock);
                0
            }
            Err(e) => end.rpc_fault(e, &config.data_dir, "the console key was not replaced"),
        };
    }
    if let Err(d) = log_location_writable(&config.logging.file) {
        return end.refuse(&[d]);
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
            return end.fail(format!("logging could not start: {e}"));
        }
    };
    end = StartEnd::Logger;
    let mut announced =
        announce::announcements(&TABLE, &resolved, &config_file, &config, &walked.warnings);
    announced.rest.extend(mining_notice(&config));
    announced
        .rest
        .extend(interrupt.line(owning.is_some()).map(str::to_owned));
    announced.rest.extend(
        walked
            .owner_socket
            .as_ref()
            .map(|plan| owner_socket_line(network.name(), plan.instance_label(), &plan.path)),
    );
    announced
        .rest
        .extend(walked.service_rendezvous.as_deref().map(|dir| {
            service_rendezvous_line(
                network.name(),
                config.rpc.instance.label(),
                &shekyl_rpc_rendezvous::service_record_path(dir, &network_id, &config.rpc.instance),
                !config.rpc.channel_listen.is_empty(),
                !config.rpc.view_listen.is_empty(),
            )
        }));
    let lines = announced.into_lines();
    announce_all(&lines);

    // The RPC's runtime and the owner's leg, dialled and bound before the
    // node opens: a second daemon of this account, network and instance
    // refuses here, with nothing opened (`RPC_CHANNEL.md` §7.1). The RPC
    // serves it once the node is up.
    // The RPC channel's state too, under the lock: its key made on the
    // first start, its enrolled set, a service's console key (RT-O34).
    let channel = shekyl_daemon_rpc::channel::ChannelSetup {
        data_dir: config.data_dir.clone(),
        network_id,
        service: config.run_mode == shekyl_daemon_config::RunMode::Service,
        service_rendezvous: walked.service_rendezvous.clone(),
        instance: config.rpc.instance.clone(),
    };
    let prepared = match shekyl_daemon_rpc::run::prepare(
        walked
            .owner_socket
            .as_ref()
            .map(|plan| (plan, network.name())),
        Some(&channel),
    ) {
        Ok(prepared) => prepared,
        Err(shekyl_daemon_rpc::run::PrepareError::Owner(d)) => return end.refuse(&[d]),
        Err(shekyl_daemon_rpc::run::PrepareError::Runtime(e)) => {
            return end.fail(format!("the RPC's {e}"));
        }
        Err(shekyl_daemon_rpc::run::PrepareError::Channel(e)) => {
            return end.rpc_fault(e, &config.data_dir, "the RPC channel cannot start");
        }
    };

    // The settlement schedule, armed before the node whose first epoch
    // arithmetic would latch it exists; a value the owner refuses is the
    // row's refusal (§6). The walk judged the same value without latching.
    let dev = &config.dev;
    if let Err(refusal) =
        levers::arm_settlement_schedule(dev.settlement_epoch_blocks, dev.archival_reorg_depth)
    {
        return end.refuse(&[verify::owner_refusal(
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
            return end.fail(format!("the node did not start: {error}"));
        }
    };
    // `mine = on`: the configured miner, once open has returned. `None`
    // is the `mine-threads` row. A refusal drops the node (its `Drop`
    // stops it) and the start fails here, rather than inside open where
    // the same stop would run twice.
    if config.mine.start {
        if let Err(refused) = node.mining().start(None) {
            return end.fail(format!("the miner did not start: {refused}"));
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
            return end.fail(format!("the signal owner's runtime could not start: {e}"));
        }
    };
    if let Err(e) = signals::own(pool.handle(), interrupt) {
        return end.fail(format!("the stop triggers could not be owned: {e}"));
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
    // The owning connection's watch, after the stop owner: `own` clears a
    // latched stop, and a close must not be cleared.
    let ready = match owning.map(watch_owning_connection).transpose() {
        Ok(ready) => ready,
        Err(e) => {
            return end.fail(format!("the owning connection could not be watched: {e}"));
        }
    };
    let status = supervise(&config, &pool, options, node, tor_inbox, prepared, ready);
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
    prepared: shekyl_daemon_rpc::run::Prepared,
    ready: Option<OwningConnection>,
) -> i32 {
    // The RPC, bound before anything is announced as up. A refusal is a
    // failed start: the node is torn down the one way. The owner's socket
    // going stops the daemon through the one stop owner. The RPC asks the
    // supervisor for `daemon_status`'s Tor fields; its inbox is made
    // already, so an ask before the loop starts waits for it.
    let gone: shekyl_daemon_rpc::run::OnRendezvousGone = Arc::new(signals::rendezvous_gone);
    let (rpc, refused) = match shekyl_daemon_rpc::run::start(
        &config.rpc,
        options,
        node.handles(),
        tor_inbox.asks(),
        config.dev.rpc,
        prepared,
        gone,
    ) {
        Ok(rpc) => (Some(rpc), None),
        // A start refusal like any other (IG-11): through the one path, to
        // standard error and the log, and its status (2 for a held file or
        // a bad rendezvous key, 1 for a failure) is the exit's, whatever
        // the teardown reports.
        Err(fault) => (
            None,
            Some(StartEnd::Logger.rpc_fault(fault, &config.data_dir, "the RPC did not start")),
        ),
    };
    // The owner's leg is bound, served and published: the starting process
    // may call. A failed write is that process gone, which the watch reports.
    if let (Some(_), Some(mut ready)) = (&rpc, ready) {
        if let Err(e) = ready.write_ready() {
            tracing::debug!(target: "daemon", "the ready line was not written: {e}");
        }
    }
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
    let status = finish(pool, supervisor, rpc, preserve_status, node);
    exit_status(refused, status)
}

/// The run's exit: a start refusal's status when the RPC refused at its
/// start (2 for a held file or a bad rendezvous key, 1 for a failure),
/// whatever the teardown that followed reports; otherwise the teardown's.
fn exit_status(refused: Option<i32>, teardown: i32) -> i32 {
    refused.unwrap_or(teardown)
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
        signals::StopCause::OwningConnectionClosed => StopReport::Announce(
            "the process that started this daemon closed its owning connection".to_owned(),
        ),
        signals::StopCause::Fatal(end) => StopReport::Error(format!("{end}; the daemon stops")),
    }
}

/// Adopt the owning connection the command line names, if it names one
/// (IG-Q106). A number that is not a connected stream socket refuses the
/// start, naming the condition. Called once, first in the start.
#[allow(
    unsafe_code,
    reason = "adopt takes ownership of the inherited end the command line names"
)]
fn adopt_owning_connection(
    cli: &shekyl_options::Cli,
) -> Result<Option<OwningConnection>, Diagnostic> {
    let Some(given) = cli.given.iter().find(|g| g.row.name == "owning-connection") else {
        return Ok(None);
    };
    let shekyl_options::Value::Integer(number) = given.value else {
        unreachable!("the row's kind is an integer");
    };
    // SAFETY: the number is the end the starting process created for this
    // daemon and handed it by inheritance (IG-Q106); nothing else in this
    // process holds it, and the start adopts it once, before the walk, the
    // lock or any child.
    unsafe { shekyl_spawn::owning::adopt(number) }
        .map(Some)
        .map_err(|e| {
            Diagnostic::new(Code::OwningConnectionUnusable, given.source.clone())
                .option("owning-connection")
                .param("value", number.to_string())
                .param("found", e.describe())
        })
}

/// Start the owning connection's watch on a thread of its own, and return
/// the handle the ready line is written on. The watch reads until the
/// starting process closes its end or dies, then stops the daemon through
/// the one stop owner. Bytes that process sends are discarded, and said
/// once.
fn watch_owning_connection(owning: OwningConnection) -> std::io::Result<OwningConnection> {
    let ready = owning.try_clone()?;
    std::thread::Builder::new()
        .name("shekyld-owning".to_owned())
        .spawn(move || {
            let mut said = false;
            let closed = owning.wait_for_close(|bytes| {
                if !said {
                    said = true;
                    tracing::warn!(
                        target: "daemon",
                        "the process that started this daemon sent {bytes} bytes on its owning connection; it carries nothing to the daemon, and they are discarded"
                    );
                }
            });
            if let Err(e) = closed {
                tracing::debug!(target: "daemon", "the owning connection failed: {e}");
            }
            signals::owning_connection_closed();
        })?;
    Ok(ready)
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

/// The line a start announces about a service's rendezvous record
/// (`RPC_CHANNEL.md` §7.1): where it is, and what it names, which is what a
/// client on this machine can reach.
fn service_rendezvous_line(
    network: &str,
    instance: &str,
    path: &std::path::Path,
    channel: bool,
    view: bool,
) -> String {
    let names = match (channel, view) {
        (true, true) => "the channel and the view listener",
        (true, false) => "the channel",
        (false, true) => "the view listener",
        (false, false) => {
            "no listener: rpc-listen and rpc-view-listen are none, so a wallet on this \
             computer is told the node serves no wallet leg"
        }
    };
    format!(
        "service rendezvous: network {network}, instance {instance}, at {}, naming {names}",
        path.display()
    )
}

/// The line a start announces about its owner's socket (`RPC_CHANNEL.md`
/// §7.1): the socket's name is a hash, so the operator is told which
/// network and instance it serves and where it is.
fn owner_socket_line(network: &str, instance: &str, path: &std::path::Path) -> String {
    let leg = if cfg!(windows) {
        "owner's rendezvous"
    } else {
        "owner's socket"
    };
    format!(
        "{leg}: network {network}, instance {instance}, at {}",
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
#[path = "run_tests.rs"]
mod tests;
