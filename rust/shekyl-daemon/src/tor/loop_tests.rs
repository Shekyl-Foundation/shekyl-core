// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The supervisor's loop while Tor does not answer (Rick, 2026-11-10: the
//! supervisor never awaits Tor).
//!
//! The loop runs as the daemon runs it, on a real [`Network`], launching a
//! stand-in `tor` through the unpinned witness. A stand-in that says
//! nothing keeps the launch's first control reply from coming, so the
//! launch stays in flight for its bound; one that answers the launch and
//! then nothing, and ignores the close of its control connection, holds the
//! reap for Tor's grace. That is when an operator asks what is wrong with
//! Tor. Each stand-in records its process and its data directory, so a
//! test can see that neither outlives what ended it.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_p2p::{
    Admit, ClaimCarrier, CoreSyncData, Established, LinkLimits, Network, NetworkParts, NetworkPlan,
    NodeSync, PeerPlan, PoolDoor, Sockets, SupervisorFeeds, SyncInbound, SyncOwner, Taken, TorPlan,
    TxId,
};
use shekyl_tor_control_client::binary::VerifiedTorBinary;
use shekyl_tor_control_client::control::{ReplyFramer, SocksTimeout};
use shekyl_tor_control_client::supervisor::{Action, Input, Launch, LaunchDirectory, TorSetting};
use shekyl_tor_control_daemon::{DaemonTorConfig, DaemonTorControl};
use shekyl_tor_status::{ManagedTor, TorCause, TorState, TorStatus};
use tokio::sync::watch;

use super::inbox::inbox;
use super::{drive, Drive, PinSource, Supervises, Supervisor, SupervisorEnd, TorAsk};

struct NoSync;

impl SyncOwner for NoSync {
    fn claim(&self, _: &Established, _: CoreSyncData, _: ClaimCarrier, _: Taken) {}
    fn message(&self, _: &Established, _: SyncInbound, _: Taken) {}
}

struct EmptyPool;

impl PoolDoor for EmptyPool {
    fn admit(&self, _: &[u8]) -> Admit {
        Admit::RefusedForm
    }
    fn holds(&self, _: &TxId) -> bool {
        false
    }
    fn shown(&self, _: &TxId) {}
    fn complement(&self, _: &[TxId]) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

/// An offline network whose Tor link the supervisor feeds.
pub(super) fn network(dir: &std::path::Path, feeds: SupervisorFeeds) -> Network {
    let (_, node_sync) = watch::channel(NodeSync::Unsynchronised);
    let (_, tip) = watch::channel(CoreSyncData {
        current_height: 1,
        cumulative_difficulty: 1,
        cumulative_difficulty_top64: 0,
        top_id: [1; 32],
    });
    Network::start(NetworkParts {
        plan: NetworkPlan {
            network_id: [7; 16],
            seeds: None,
            allow_local: true,
            reserved_descriptors: 8,
            limits: LinkLimits {
                upload: None,
                download: None,
            },
            relay_noise: false,
            clearnet: None,
            tor: TorPlan::None,
            peers: PeerPlan {
                address_file: dir.join("p2pstate.bin"),
                operator: Vec::new(),
                exclusive: Vec::new(),
                disclose_early: false,
            },
            bans: Vec::new(),
        },
        sockets: Sockets::new(),
        sync: Arc::new(NoSync),
        pool: Arc::new(EmptyPool),
        node_sync,
        tip,
        supervisor: Some(feeds),
    })
    .expect("the network starts")
}

/// Set only in a stand-in: the role this test binary plays as `tor`.
const STAND_IN_ROLE: &str = "SHEKYL_TOR_STAND_IN_ROLE";

/// Set only in a stand-in: the inherited control connection's descriptor.
const STAND_IN_FD: &str = "SHEKYL_TOR_STAND_IN_FD";

/// How long a frozen stand-in lives on after its control connection
/// closes: longer than Tor's grace, so the reap has to kill it.
const FROZEN_LIVES: Duration = Duration::from_secs(45);

/// What a stand-in `tor` does on its control connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// Says nothing, and exits when the connection closes, as Tor does when
    /// it loses its owning controller.
    Quiet,
    /// Answers its first two control commands (the launch's `GETINFO
    /// version`, then the next) and then nothing, and ignores the close of
    /// its control connection: it lives on for [`FROZEN_LIVES`], until it is
    /// killed. The reap waits Tor's grace for an exit that never comes.
    Frozen,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Quiet => "quiet",
            Self::Frozen => "frozen",
        }
    }
}

/// A stand-in `tor` at `dir/tor`: a POSIX shell script that records its
/// launch, finds the inherited control connection, and `exec`s this test
/// binary (so the recorded process is the stand-in itself) to re-run `test`
/// (its full path, from `module_path!`) in `role`. The test calls
/// [`stand_in_if_requested`] first. Rust, not the shell, reads and writes
/// the connection: dash takes only one-digit descriptor numbers in a
/// redirection, and bash, whose `read -u` takes more, is neither at
/// `/bin/bash` on FreeBSD nor installed everywhere.
fn stand_in(dir: &Path, role: Role, test: &str) -> VerifiedTorBinary {
    let exe = std::env::current_exe().expect("the test binary");
    let exe = sh_quoted(exe.to_str().expect("a UTF-8 test binary path"));
    let name = sh_quoted(
        test.split_once("::")
            .expect("module path has a crate segment")
            .1,
    );
    let script = format!(
        "#!/bin/sh\n{RECORD}{OWNING_FD}export {STAND_IN_ROLE}={}\nexport {STAND_IN_FD}=\"$fd\"\n\
         exec {exe} {name} --exact --nocapture --test-threads=1\n",
        role.name()
    );
    let path = dir.join("tor");
    let mut file = std::fs::File::create(&path).expect("the stand-in");
    file.write_all(script.as_bytes())
        .expect("the stand-in's text");
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("the stand-in runs");
    VerifiedTorBinary::unchecked_for_test(path)
}

/// `text` as one POSIX shell word: single-quoted, each `'` closing the quote,
/// escaped, and reopening it, so any path a checkout can have is carried.
fn sh_quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// **A path with an apostrophe is carried to the stand-in whole** (Copilot,
/// #1493): a checkout or build directory may hold one. Red edit: quote
/// without escaping, and the word ends at the apostrophe.
#[test]
fn a_quoted_word_carries_an_apostrophe() {
    assert_eq!(sh_quoted("/srv/build"), "'/srv/build'");
    assert_eq!(sh_quoted("/srv/o'brien/t"), "'/srv/o'\\''brien/t'");
}

/// The stand-in's role, in a re-run of the test that calls it; returns in
/// the test itself. It takes the control connection by its inherited number,
/// which only `unsafe` can (rule 45: allowed on this item alone).
#[allow(unsafe_code)]
fn stand_in_if_requested() {
    use std::io::{BufRead, BufReader};
    use std::os::fd::FromRawFd;

    let Some(role) = std::env::var_os(STAND_IN_ROLE) else {
        return;
    };
    let fd = std::env::var_os(STAND_IN_FD)
        .and_then(|n| n.to_str().and_then(|n| n.parse::<libc::c_int>().ok()))
        .expect("the control connection's descriptor");
    // SAFETY: `fd` is the control connection this process inherited, and
    // nothing else in it owns that descriptor.
    let connection = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut answers = connection.try_clone().expect("the connection's write half");
    let lines = BufReader::new(connection).split(b'\n');
    if role == Role::Quiet.name() {
        for line in lines {
            if line.is_err() {
                break;
            }
        }
        std::process::exit(0);
    }
    assert_eq!(role, Role::Frozen.name(), "a stand-in role");
    let mut answered = 0;
    for line in lines {
        let Ok(line) = line else {
            break;
        };
        if answered < 2 {
            answered += 1;
            let reply: &[u8] = if line.starts_with(b"GETINFO version") {
                b"250-version=0.4.9.14\r\n250 OK\r\n"
            } else {
                b"250 OK\r\n"
            };
            if answers.write_all(reply).is_err() {
                break;
            }
        }
    }
    std::thread::sleep(FROZEN_LIVES);
    std::process::exit(0);
}

/// The line each stand-in writes when it starts: its process id and the
/// data directory it was given (`--DataDirectory`, the first argument).
const RECORD: &str = r#"echo "$$ $2" >> "$(dirname "$0")/launches"
"#;

/// The shell that finds the inherited control connection's descriptor.
const OWNING_FD: &str = r#"fd=
while [ $# -gt 0 ]; do
  if [ "$1" = "--__OwningControllerFD" ]; then fd=$2; fi
  shift
done
"#;

/// A quiet stand-in ([`Role::Quiet`]) for `test`.
fn quiet_tor(dir: &Path, test: &str) -> VerifiedTorBinary {
    stand_in(dir, Role::Quiet, test)
}

/// A frozen stand-in ([`Role::Frozen`]) for `test`.
fn frozen_tor(dir: &Path, test: &str) -> VerifiedTorBinary {
    stand_in(dir, Role::Frozen, test)
}

/// The stand-ins launched so far: each one's process and data directory.
fn launches(dir: &Path) -> Vec<(String, PathBuf)> {
    std::fs::read_to_string(dir.join("launches"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (pid, data) = line.split_once(' ')?;
            Some((pid.to_owned(), PathBuf::from(data)))
        })
        .collect()
}

/// Whether process `pid` still runs: signal 0, which checks and sends
/// nothing. No process is started for it: this process launches Tor, and a
/// start outside the spawn lock could inherit Tor's control connection.
fn alive(pid: &str) -> bool {
    let pid = pid
        .parse::<i32>()
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .expect("a recorded process id");
    rustix::process::test_kill_process(pid).is_ok()
}

/// Each stand-in launched has exited and its data directory is gone.
fn nothing_outlives(dir: &Path, after: &str) {
    let launched = launches(dir);
    assert!(!launched.is_empty(), "{after}: no stand-in was launched");
    for (pid, data) in launched {
        assert!(!alive(&pid), "{after}: the stand-in {pid} still runs");
        assert!(
            !data.exists(),
            "{after}: its data directory {} is still there",
            data.display()
        );
    }
}

/// The directory a loop test works in, by path. The directory itself is
/// [`on_the_loops_runtime`]'s, which removes it only once the runtime is gone.
pub(super) struct Dir(PathBuf);

impl Dir {
    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

/// Run a loop test on the runtime the daemon's loop needs (two workers), in a
/// fresh directory. The runtime is made after the directory, so it is dropped
/// first, a failed test included: the supervisor's task, and the stand-in it
/// launched, end before the directory is removed. Under `#[tokio::test]` the
/// directory was the test's own and went first, while that task still
/// launched into it; the removal could stop part-way and leave the stand-in
/// behind.
pub(super) fn on_the_loops_runtime<F: std::future::Future<Output = ()>>(
    test: impl FnOnce(Dir) -> F,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("the loop's runtime");
    runtime.block_on(test(Dir(dir.path().to_path_buf())));
}

/// The supervisor's loop over `tor`, under `policy`.
fn supervise(dir: &Path, tor: VerifiedTorBinary, policy: super::Policy) -> Supervisor {
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).expect("the data directory");
    let (owner, inbox, feeds) = inbox();
    let network = network(dir, feeds);
    let task = tokio::spawn(drive(
        Supervises::Managed {
            pin: PinSource::Unchecked(tor),
            onion: super::OnionSource::PerBoot,
        },
        policy,
        true,
        18_021,
        data_dir,
        inbox,
        network,
    ));
    Supervisor {
        owner,
        task: Some(task),
        managed: true,
    }
}

/// Ask the status, taken within a second.
async fn status_of(supervisor: &Supervisor, what: &str) -> ManagedTor {
    let status: TorStatus = tokio::time::timeout(Duration::from_secs(1), supervisor.status())
        .await
        .unwrap_or_else(|_| panic!("{what}: the status ask was held"))
        .expect("the loop runs");
    status
        .tor
        .expect("a managed Tor's status carries the managed object")
}

/// **A status ask and the stop are taken while Tor does not answer.** The
/// launch is sent and its reply never comes; twenty status asks, 50 ms
/// apart, are each answered within 250 ms, and the stop ends the loop
/// within 5 s, with the launch's Tor gone and its directory retired.
/// Awaiting the launch on the loop holds every ask and fails this; so does
/// a stop that leaves the launch to run on.
#[test]
fn a_status_ask_and_the_stop_are_taken_while_tor_does_not_answer() {
    stand_in_if_requested();
    on_the_loops_runtime(|dir| async move {
        let tor = quiet_tor(
            dir.path(),
            concat!(
                module_path!(),
                "::a_status_ask_and_the_stop_are_taken_while_tor_does_not_answer"
            ),
        );
        let supervisor = supervise(dir.path(), tor, super::policy());
        // The pin is accepted and the launch sent; its first reply does not come.
        tokio::time::sleep(Duration::from_millis(500)).await;
        for ask in 0..20 {
            let asked = Instant::now();
            let status = status_of(&supervisor, &format!("ask {ask}")).await;
            let took = asked.elapsed();
            assert!(took < Duration::from_millis(250), "ask {ask} took {took:?}");
            // The subject: the launch is in flight. A launch that had failed
            // would read `FailedStart`; one that had answered, `Bootstrapping`.
            assert_eq!(status.state, TorState::Restarting, "ask {ask}: {status:?}");
            assert_eq!(status.cause, None, "ask {ask}: {status:?}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::timeout(Duration::from_secs(5), supervisor.shutdown())
            .await
            .expect("the stop was taken while the launch waited");
        nothing_outlives(dir.path(), "the stop");
    });
}

/// **A launch the core gives up on ends its Tor.** The launch's first reply
/// never comes; one reply bound later (2 s here) the core faults it. The
/// launch has no clock of its own: the driver abandons it, and its task
/// stops that Tor and retires its directory, within a second. The next
/// launch waits 5 s here, so it is the abandon that ends it, not the next
/// launch taking its place. Fails if the launch waits on for a reply after
/// the core has given up (a bound of its own, or none), leaving that Tor
/// running.
#[test]
fn a_launch_the_core_gives_up_on_ends_its_tor() {
    stand_in_if_requested();
    on_the_loops_runtime(|dir| async move {
        let tor = quiet_tor(
            dir.path(),
            concat!(
                module_path!(),
                "::a_launch_the_core_gives_up_on_ends_its_tor"
            ),
        );
        let mut policy = super::policy();
        policy.reply_bound = Duration::from_secs(2);
        policy.base = Duration::from_secs(5);
        let supervisor = supervise(dir.path(), tor, policy);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = status_of(&supervisor, "before the fault").await;
            if status.cause == Some(TorCause::Unanswered) {
                break;
            }
            assert!(Instant::now() < deadline, "no fault: {status:?}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let (first, data) = launches(dir.path())
            .into_iter()
            .next()
            .expect("the first launch");
        let ended = Instant::now() + Duration::from_secs(1);
        while alive(&first) || data.exists() {
            assert!(
                Instant::now() < ended,
                "the abandoned launch's Tor {first} or its directory is still there"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::timeout(Duration::from_secs(5), supervisor.shutdown())
            .await
            .expect("the stop");
        nothing_outlives(dir.path(), "the stop");
    });
}

/// **A status ask and the stop are taken while a frozen Tor is reaped.** The
/// stand-in answers the launch and then nothing; one reply bound later (2 s
/// here) the supervisor faults it and reaps it. The stand-in ignores the
/// close of its control connection, so the reap waits Tor's grace (5 s)
/// before the kill. Once the fault is seen, twenty status asks, 50 ms
/// apart, are each answered within 250 ms, all inside that grace. The stop
/// is taken and waits for the reap, so it ends within the grace and a
/// margin, with the frozen Tor killed. Putting the reap back on the loop
/// (the loop waiting while `stop_for_respawn` runs) holds the asks and
/// fails this.
#[test]
fn a_status_ask_and_the_stop_are_taken_while_a_frozen_tor_is_reaped() {
    stand_in_if_requested();
    on_the_loops_runtime(|dir| async move {
        let tor = frozen_tor(
            dir.path(),
            concat!(
                module_path!(),
                "::a_status_ask_and_the_stop_are_taken_while_a_frozen_tor_is_reaped"
            ),
        );
        let mut policy = super::policy();
        policy.reply_bound = Duration::from_secs(2);
        let supervisor = supervise(dir.path(), tor, policy);
        // The launch is answered; a request after it is not, and is late one
        // bound later. Poll until the fault is seen: the reap is then in flight.
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let status = status_of(&supervisor, "the reap starts in the fault's step").await;
            if status.cause == Some(TorCause::Unanswered) {
                break;
            }
            assert!(Instant::now() < deadline, "no fault: {status:?}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let reaping = Instant::now();
        for ask in 0..20 {
            let asked = Instant::now();
            let status = status_of(&supervisor, &format!("ask {ask}")).await;
            let took = asked.elapsed();
            assert!(took < Duration::from_millis(250), "ask {ask} took {took:?}");
            // The subject: Tor is being restarted, not bootstrapping again.
            assert_eq!(status.state, TorState::Restarting, "ask {ask}: {status:?}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            reaping.elapsed() < Duration::from_secs(5),
            "the asks ran past the reap's grace: {:?}",
            reaping.elapsed()
        );
        tokio::time::timeout(Duration::from_secs(8), supervisor.shutdown())
            .await
            .expect("the stop was taken while the reap waited");
        nothing_outlives(dir.path(), "the stop");
    });
}

/// One `650` event line, framed as Tor sends it.
fn event(line: &str) -> shekyl_tor_control_client::control::ControlReply {
    let mut framer = ReplyFramer::default();
    framer.push_bytes(format!("650 {line}\r\n").as_bytes());
    framer
        .next_reply()
        .expect("frames")
        .expect("one complete reply")
}

/// **The onion's events are read from the `ADD_ONION` send.** Tor uploads
/// as soon as it takes the service, and its `HS_DESC` events reach the
/// inbox on their own path, ahead of the reply if the reply's task is slow.
/// Here the reply never comes: an `UPLOAD` for this onion, folded while the
/// add is in flight, starts its upload round. Fails if the service and its
/// rounds are set only when the reply is folded: the event is dropped, and
/// the first upload's probe never comes.
#[test]
fn an_upload_before_the_add_onion_reply_is_read() {
    stand_in_if_requested();
    on_the_loops_runtime(|dir| async move {
        let tor = frozen_tor(
            dir.path(),
            concat!(
                module_path!(),
                "::an_upload_before_the_add_onion_reply_is_read"
            ),
        );
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("the data directory");
        let (_owner, inbox, feeds) = inbox();
        let network = network(dir.path(), feeds);
        let events = inbox.poster().events();
        let mut drive = Drive::start(
            Supervises::Managed {
                pin: PinSource::Unchecked(tor.clone()),
                onion: super::OnionSource::PerBoot,
            },
            super::policy(),
            true,
            18_021,
            data_dir.clone(),
            inbox,
            network,
        )
        .expect("the driver");
        // A Tor that answered its launch, and answers nothing after it.
        let up = DaemonTorControl::spawn_keeping(
            DaemonTorConfig {
                tor_binary: tor,
                data_dir_parent: data_dir,
                events,
                reply_deadline: Duration::from_secs(5),
                socks_timeout: SocksTimeout::TorDefault,
                guard_state: None,
            },
            tokio::time::sleep(Duration::from_secs(5)),
        )
        .await
        .unwrap_or_else(|_| panic!("the launch"));
        drive.control = Some(up);
        drive.forward = Some(std::net::SocketAddr::from(([127, 0, 0, 1], 18_022)));
        assert_eq!(drive.send_add(1), Ok(None), "the add is sent off the loop");
        let onion = drive
            .managed
            .as_ref()
            .expect("a managed driver")
            .onion
            .service_id()
            .as_str()
            .to_owned();
        let upload = event(&format!(
            "HS_DESC UPLOAD {onion} UNKNOWN $9E67E885D46AE284534EBA3B71A2DFE13A0E4783~Torr4Tor GOkbpjFN0/2R6w08BkOWd3Zj62ZDCvu7bVmkseOLvcY"
        ));
        let inputs = drive.event_inputs(&upload);
        assert!(
            inputs
                .iter()
                .any(|input| matches!(input, Input::UploadRoundStarted { .. })),
            "the upload was not read: {inputs:?}"
        );
        if let Some(control) = drive.control.take() {
            drop(control.shutdown().await);
        }
        // The network owns a runtime, which is not dropped on an async thread.
        tokio::task::spawn_blocking(move || drop(drive))
            .await
            .expect("the driver drops");
        nothing_outlives(dir.path(), "the shutdown");
    });
}

/// **A supervisor that runs no Tor holds none of a managed Tor's secrets.**
/// Under `off` and an operator's Tor the driver starts with no onion key, no
/// probe isolation and no binary; under `managed` it holds them. A failed
/// mint is the supervisor's end, so a setting that does not use them must
/// not mint them. The mints are read through what the driver holds: a count
/// would need a hook in the mint itself. Red edit: mint the boot's secrets
/// before the setting is matched.
#[test]
fn an_unmanaged_setting_mints_no_secret() {
    on_the_loops_runtime(|dir| async move {
        for (supervises, managed) in [
            (Supervises::Unmanaged(TorSetting::Off), false),
            (Supervises::Unmanaged(TorSetting::Operator), false),
            (
                Supervises::Managed {
                    pin: PinSource::Discover(None),
                    onion: super::OnionSource::PerBoot,
                },
                true,
            ),
        ] {
            let data_dir = dir.path().join("data");
            std::fs::create_dir_all(&data_dir).expect("the data directory");
            let (_owner, inbox, feeds) = inbox();
            let network = network(dir.path(), feeds);
            let drive = Drive::start(
                supervises,
                super::policy(),
                true,
                18_021,
                data_dir,
                inbox,
                network,
            )
            .expect("the driver");
            assert_eq!(drive.managed.is_some(), managed, "a managed Tor's secrets");
            // The network owns a runtime, which is not dropped on an async thread.
            tokio::task::spawn_blocking(move || drop(drive))
                .await
                .expect("the driver drops");
        }
    });
}

/// **Under `tor = off` the supervisor answers the status and does not end
/// until its stop.** Its status ask is answered; its end does not resolve
/// while it runs; its stop is taken. Red edit: end the loop of a supervisor
/// that runs no Tor, or answer no status without one.
#[test]
fn an_off_supervisor_answers_and_runs_until_its_stop() {
    on_the_loops_runtime(|dir| async move {
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("the data directory");
        let (owner, inbox, feeds) = inbox();
        let network = network(dir.path(), feeds);
        let task = tokio::spawn(drive(
            Supervises::Unmanaged(TorSetting::Off),
            super::policy(),
            true,
            18_021,
            data_dir,
            inbox,
            network,
        ));
        let mut supervisor = Supervisor {
            owner,
            task: Some(task),
            managed: false,
        };
        let status = tokio::time::timeout(Duration::from_secs(1), supervisor.status())
            .await
            .expect("the status ask was held")
            .expect("the loop runs");
        assert!(
            status.tor.is_none(),
            "an off supervisor reported a managed Tor: {status:?}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), supervisor.ended())
                .await
                .is_err(),
            "a running supervisor reported an end"
        );
        tokio::time::timeout(Duration::from_secs(5), supervisor.shutdown())
            .await
            .expect("the stop was taken");
    });
}

/// **A Tor action asked of a supervisor that runs no Tor ends it with that
/// ask, never a panic.** The core asks for a pin, a launch, a publish or a
/// probe only while it runs this node's Tor. Each of those, put in front of
/// a `tor = off` driver, ends the loop with `NoTorToRun` of that ask. The
/// launch and the publish are not in flight: answering them as "nothing to
/// send" would leave the loop running. A shipped build aborts on a panic,
/// with no teardown and no log line. Red edit: fold on past the ask in
/// `perform`, so the loop never ends.
#[test]
fn a_tor_action_without_a_managed_tor_ends_the_supervisor() {
    on_the_loops_runtime(|dir| async move {
        let witness = VerifiedTorBinary::unchecked_for_test(dir.path().join("tor-witness"));
        let cases = [
            (Action::CheckPin, TorAsk::Pin),
            (
                Action::Spawn(Launch {
                    binary: witness,
                    directory: LaunchDirectory::Kept,
                }),
                TorAsk::Launch,
            ),
            (Action::RepublishOnion, TorAsk::Publish),
            (Action::AddOnion, TorAsk::Publish),
            (Action::Probe, TorAsk::Probe),
        ];
        for (action, ask) in cases {
            let data_dir = dir.path().join("data");
            std::fs::create_dir_all(&data_dir).expect("the data directory");
            let (_owner, inbox, feeds) = inbox();
            let network = network(dir.path(), feeds);
            let kept = network.clone();
            let mut drive = Drive::start(
                Supervises::Unmanaged(TorSetting::Off),
                super::policy(),
                true,
                18_021,
                data_dir,
                inbox,
                network,
            )
            .expect("the driver");
            drive.step.actions.push(action);
            let end = tokio::time::timeout(Duration::from_secs(5), drive.run())
                .await
                .unwrap_or_else(|_| panic!("{ask:?}: the loop ran on past the ask"));
            assert_eq!(end, Err(SupervisorEnd::NoTorToRun(ask)), "{ask:?}");
            // The network owns a runtime, which is not dropped on an async thread.
            tokio::task::spawn_blocking(move || drop(kept))
                .await
                .expect("the network drops");
        }
    });
}

/// A driver for a persistent onion: its guard manager is loaded from the
/// onion's own guard directory under `dir`.
pub(super) fn persistent(dir: &Path) -> Drive {
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).expect("the data directory");
    let (_owner, inbox, feeds) = inbox();
    let network = network(dir, feeds);
    Drive::start(
        Supervises::Managed {
            pin: PinSource::Discover(None),
            onion: super::OnionSource::Persistent(
                DaemonTorControl::mint_identity().expect("an onion identity"),
            ),
        },
        super::policy(),
        true,
        18_021,
        data_dir,
        inbox,
        network,
    )
    .expect("the driver")
}
