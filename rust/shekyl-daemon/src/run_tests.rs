// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests of the daemon's start sequence.

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
        service_parent: None,
        session_dir: crate::test_session_dir(home),
        service_rendezvous: None,
    }
}

/// The entry point as these tests start it: every step of [`main`], with
/// the host's default configuration file left unread.
fn start(args: &[OsString], platform: &Platform) -> i32 {
    main_loading(
        args,
        platform,
        shekyl_daemon_config::load_default_file_unread,
    )
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
        start(&args(&["--bogus"]), &platform(d.path())),
        EXIT_REFUSED
    );
    assert_eq!(start(&args(&["--help"]), &platform(d.path())), 0);
    assert_eq!(start(&args(&["--version"]), &platform(d.path())), 0);
    assert_eq!(
        start(
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
        start(
            &args(&["--network", "regtest", "--mine", "on"]),
            &platform(d.path())
        ),
        EXIT_REFUSED
    );
    let host_threads = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let past = (host_threads + 1).to_string();
    assert_eq!(
        start(
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
    assert_eq!(start(&args(&["status"]), &platform(d.path())), EXIT_REFUSED);
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
    let config = shekyl_daemon_config::after_file(cli, &platform(d), None)
        .unwrap()
        .config;
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
    let pool = shekyl_runtime::runtime(budget, &ThreadName::new("test-signals").unwrap()).unwrap();
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
        crate::tor::prepare(None).0,
        shekyl_daemon_rpc::run::prepare(None, None).expect("the RPC's runtime"),
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
    let status = start(&a, &platform(d.path()));
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

/// A start fault of the RPC exits with its class's status (IG-11), whether
/// it comes at the RPC's open, before the node, or at its start, after the
/// node and the logger: a held file and a bad rendezvous key are refusals
/// (2), anything else a failure (1). Red edit: log the start's fault and
/// return the teardown's status, and a held record exits 1 (Copilot,
/// #1439).
#[test]
fn a_late_start_fault_keeps_its_refusal_status() {
    use shekyl_daemon_rpc::run::StartFault;
    let dir = Path::new("data");
    let held = shekyl_os_account::private_file::HeldOpen {
        held: dir.join("rpc-channel.bundle"),
        live: dir.join("rpc-channel.bundle"),
    };
    let end = StartEnd::Stderr;
    assert_eq!(
        end.rpc_fault(StartFault::HeldOpen(held), dir, "the RPC did not start"),
        EXIT_REFUSED
    );
    assert_eq!(
        end.rpc_fault(
            StartFault::RendezvousKey {
                key: r"HKEY_LOCAL_MACHINE\SOFTWARE\Shekyl\Rendezvous".to_owned(),
                found: "it does not exist".to_owned(),
            },
            dir,
            "the RPC did not start"
        ),
        EXIT_REFUSED
    );
    assert_eq!(
        end.rpc_fault(
            StartFault::Refused("bind failed".to_owned()),
            dir,
            "the RPC did not start"
        ),
        EXIT_FAILED
    );
}

/// The run's exit is the start refusal's status over the teardown's: a
/// refusal at the RPC's start (2) is not overwritten by the failed run's
/// teardown (1), and with no refusal the teardown decides. Red edit:
/// return the teardown's status, and a held record exits 1 (Copilot,
/// #1439).
#[test]
fn a_start_refusal_s_status_survives_the_teardown() {
    assert_eq!(exit_status(Some(EXIT_REFUSED), EXIT_FAILED), EXIT_REFUSED);
    assert_eq!(exit_status(Some(EXIT_FAILED), 0), EXIT_FAILED);
    assert_eq!(exit_status(None, EXIT_FAILED), EXIT_FAILED);
    assert_eq!(exit_status(None, 0), 0);
}

/// A file the daemon replaced on storage it does not support is written and
/// the start goes on, but the log says so: the path, why its save is not
/// confirmed, and the supported storage (Rick, 2026-11-19). A confirmed
/// save says nothing. Red edit: drop the warning from `warn_unconfirmed`,
/// and the unsupported volume passes unremarked.
#[test]
fn an_unconfirmed_replace_is_logged_with_its_cause() {
    use shekyl_daemon_rpc::channel::files::note_durability;
    use shekyl_os_account::private_file::{Durability, Unconfirmed};

    let path = Path::new("/data/shekyld.network");
    let fat = crate::logged(|| {
        note_durability(
            path,
            &Durability::Unconfirmed(Unconfirmed::FileSystem("FAT32".to_owned())),
        );
    });
    assert_eq!(fat.lines().count(), 1, "{fat}");
    assert!(fat.contains("WARN"), "{fat}");
    assert!(fat.contains("/data/shekyld.network"), "{fat}");
    assert!(fat.contains("FAT32"), "{fat}");
    assert!(fat.contains("supported storage"), "{fat}");
    let local = crate::logged(|| note_durability(path, &Durability::Durable));
    assert!(local.is_empty(), "{local}");
}
