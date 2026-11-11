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
use shekyl_tor_control_client::supervisor::{Cause, Input, Shown};
use shekyl_tor_control_daemon::{DaemonTorConfig, DaemonTorControl};
use tokio::sync::watch;

use super::inbox::inbox;
use super::{drive, Drive, PinSource, Supervises, Supervisor};

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
fn network(dir: &std::path::Path, feeds: SupervisorFeeds) -> Network {
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

/// A stand-in `tor` at `dir/tor` with this script.
fn stand_in(dir: &std::path::Path, script: &str) -> VerifiedTorBinary {
    let path = dir.join("tor");
    let mut file = std::fs::File::create(&path).expect("the stand-in");
    file.write_all(script.as_bytes())
        .expect("the stand-in's text");
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("the stand-in runs");
    VerifiedTorBinary::unchecked_for_test(path)
}

/// The line each stand-in writes when it starts: its process id and the
/// data directory it was given (`--DataDirectory`, the first argument).
const RECORD: &str = r#"echo "$$ $2" >> "$(dirname "$0")/launches"
"#;

/// The bash that finds the inherited control connection's descriptor.
const OWNING_FD: &str = r#"fd=
while [ $# -gt 0 ]; do
  if [ "$1" = "--__OwningControllerFD" ]; then fd=$2; fi
  shift
done
"#;

/// A `tor` that says nothing on its control connection and exits when the
/// connection closes, as Tor does when it loses its owning controller.
fn quiet_tor(dir: &Path) -> VerifiedTorBinary {
    stand_in(
        dir,
        &format!(
            "#!/bin/bash\n{RECORD}{OWNING_FD}while IFS= read -r -u \"$fd\" line; do :; done\nexit 0\n"
        ),
    )
}

/// A `tor` that answers its first two control commands (the launch's
/// `GETINFO version`, then the next) and then nothing, and that ignores the
/// close of its control connection: after the supervisor closes it, it
/// keeps running until it is killed. The reap waits Tor's grace for an exit
/// that never comes.
fn frozen_tor(dir: &Path) -> VerifiedTorBinary {
    stand_in(
        dir,
        &format!(
            "#!/bin/bash\n{RECORD}{OWNING_FD}{}",
            r#"answered=0
while IFS= read -r -u "$fd" line; do
  if [ "$answered" -lt 2 ]; then
    answered=$((answered + 1))
    case "$line" in
      "GETINFO version"*) printf '250-version=0.4.9.14\r\n250 OK\r\n' >&"$fd" ;;
      *) printf '250 OK\r\n' >&"$fd" ;;
    esac
  fi
done
exec sleep 45
"#
        ),
    )
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

/// The supervisor's loop over `tor`, under `policy`.
fn supervise(dir: &Path, tor: VerifiedTorBinary, policy: super::Policy) -> Supervisor {
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).expect("the data directory");
    let (owner, inbox, feeds) = inbox();
    let network = network(dir, feeds);
    let task = tokio::spawn(drive(
        Supervises::Managed(PinSource::Unchecked(tor)),
        policy,
        true,
        18_021,
        data_dir,
        inbox,
        network,
    ));
    Supervisor {
        owner,
        task,
        managed: true,
    }
}

/// Ask the status, taken within a second.
async fn status_of(
    supervisor: &Supervisor,
    what: &str,
) -> shekyl_tor_control_client::supervisor::Status {
    tokio::time::timeout(Duration::from_secs(1), supervisor.status())
        .await
        .unwrap_or_else(|_| panic!("{what}: the status ask was held"))
        .expect("the loop runs")
}

/// **A status ask and the stop are taken while Tor does not answer.** The
/// launch is sent and its reply never comes; twenty status asks, 50 ms
/// apart, are each answered within 250 ms, and the stop ends the loop
/// within 5 s, with the launch's Tor gone and its directory retired.
/// Awaiting the launch on the loop holds every ask and fails this; so does
/// a stop that leaves the launch to run on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_status_ask_and_the_stop_are_taken_while_tor_does_not_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tor = quiet_tor(dir.path());
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
        assert_eq!(status.shown, Shown::Restarting, "ask {ask}: {status:?}");
        assert_eq!(status.cause, Cause::None, "ask {ask}: {status:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::timeout(Duration::from_secs(5), supervisor.shutdown())
        .await
        .expect("the stop was taken while the launch waited");
    nothing_outlives(dir.path(), "the stop");
}

/// **A launch the core gives up on ends its Tor.** The launch's first reply
/// never comes; one reply bound later (2 s here) the core faults it. The
/// launch has no clock of its own: the driver abandons it, and its task
/// stops that Tor and retires its directory, within a second. The next
/// launch waits 5 s here, so it is the abandon that ends it, not the next
/// launch taking its place. Fails if the launch waits on for a reply after
/// the core has given up (a bound of its own, or none), leaving that Tor
/// running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_launch_the_core_gives_up_on_ends_its_tor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tor = quiet_tor(dir.path());
    let mut policy = super::policy();
    policy.reply_bound = Duration::from_secs(2);
    policy.base = Duration::from_secs(5);
    let supervisor = supervise(dir.path(), tor, policy);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = status_of(&supervisor, "before the fault").await;
        if status.cause == Cause::ReplyLate {
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_status_ask_and_the_stop_are_taken_while_a_frozen_tor_is_reaped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tor = frozen_tor(dir.path());
    let mut policy = super::policy();
    policy.reply_bound = Duration::from_secs(2);
    let supervisor = supervise(dir.path(), tor, policy);
    // The launch is answered; a request after it is not, and is late one
    // bound later. Poll until the fault is seen: the reap is then in flight.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let status = status_of(&supervisor, "the reap starts in the fault's step").await;
        if status.cause == Cause::ReplyLate {
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
        assert_eq!(status.shown, Shown::Restarting, "ask {ask}: {status:?}");
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upload_before_the_add_onion_reply_is_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tor = frozen_tor(dir.path());
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("the data directory");
    let (_owner, inbox, feeds) = inbox();
    let network = network(dir.path(), feeds);
    let events = inbox.poster().events();
    let mut drive = Drive::start(
        Supervises::Managed(PinSource::Unchecked(tor.clone())),
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
        },
        tokio::time::sleep(Duration::from_secs(5)),
    )
    .await
    .unwrap_or_else(|_| panic!("the launch"));
    drive.control = Some(up);
    drive.forward = Some(std::net::SocketAddr::from(([127, 0, 0, 1], 18_022)));
    assert_eq!(drive.send_add(1), None, "the add is sent off the loop");
    let onion = drive.onion.service_id().as_str().to_owned();
    let upload = event(&format!(
        "HS_DESC UPLOAD {onion} UNKNOWN $9E67E885D46AE284534EBA3B71A2DFE13A0E4783~Torr4Tor GOkbpjFN0/2R6w08BkOWd3Zj62ZDCvu7bVmkseOLvcY"
    ));
    let inputs = drive.event_inputs(&upload);
    assert!(
        inputs.contains(&Input::UploadRoundStarted),
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
}
