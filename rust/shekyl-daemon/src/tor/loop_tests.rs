// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The supervisor's loop while Tor does not answer (Rick, 2026-11-10: the
//! supervisor never awaits Tor).
//!
//! The loop runs as the daemon runs it, on a real [`Network`], launching a
//! stand-in `tor` through the unpinned witness. The stand-in holds its end
//! of the inherited control connection and says nothing, so the launch's
//! first control reply never comes and the launch request stays in flight
//! for its bound. That is when an operator asks what is wrong with Tor.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_p2p::{
    Admit, ClaimCarrier, CoreSyncData, Established, LinkLimits, Network, NetworkParts, NetworkPlan,
    NodeSync, PeerPlan, PoolDoor, Sockets, SupervisorFeeds, SyncInbound, SyncOwner, Taken, TorPlan,
    TxId,
};
use shekyl_tor_control_client::binary::VerifiedTorBinary;
use shekyl_tor_control_client::supervisor::{Cause, Shown};
use tokio::sync::watch;

use super::inbox::inbox;
use super::{drive, PinSource, Supervisor};

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

/// A `tor` that takes its arguments and the inherited control connection,
/// and says nothing for longer than the test runs.
fn silent_tor(dir: &std::path::Path) -> VerifiedTorBinary {
    stand_in(dir, "#!/bin/sh\nexec sleep 45\n")
}

/// A `tor` that answers its first two control commands (the launch's
/// `GETINFO version`, then the next) and then nothing, and that ignores the
/// close of its control connection: after the supervisor closes it, it
/// keeps running until it is killed. The reap waits Tor's grace for an exit
/// that never comes.
fn frozen_tor(dir: &std::path::Path) -> VerifiedTorBinary {
    stand_in(
        dir,
        r#"#!/bin/bash
fd=
while [ $# -gt 0 ]; do
  if [ "$1" = "--__OwningControllerFD" ]; then fd=$2; fi
  shift
done
answered=0
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
"#,
    )
}

/// **A status ask and the stop are taken while Tor does not answer.** The
/// launch is sent and its reply never comes; twenty status asks, 50 ms
/// apart, are each answered within 250 ms, and the stop ends the loop
/// within 5 s. Awaiting the launch on the loop (`send_launch` running the
/// launch inline instead of through `answer_later`) holds every ask for the
/// launch's 30 s bound and fails this.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_status_ask_and_the_stop_are_taken_while_tor_does_not_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tor = silent_tor(dir.path());
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("the data directory");
    let (owner, inbox, feeds) = inbox();
    let network = network(dir.path(), feeds);
    let task = tokio::spawn(drive(
        PinSource::Unchecked(tor),
        super::policy(),
        true,
        18_021,
        data_dir,
        inbox,
        network,
    ));
    let supervisor = Supervisor { owner, task };
    // The pin is accepted and the launch sent; its first reply does not come.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for ask in 0..20 {
        let asked = Instant::now();
        let status = tokio::time::timeout(Duration::from_secs(1), supervisor.status())
            .await
            .unwrap_or_else(|_| panic!("ask {ask} was held"))
            .expect("the loop runs");
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
}

/// **A status ask and the stop are taken while a frozen Tor is reaped.** The
/// stand-in answers the launch and then nothing; one reply bound later (2 s
/// here) the supervisor faults it and reaps it. The stand-in ignores the
/// close of its control connection, so the reap waits Tor's grace (5 s)
/// before the kill. Once the fault is seen, twenty status asks, 50 ms apart,
/// are each answered within 250 ms, all inside that grace, and the stop
/// ends the loop within 5 s. Putting the reap back on the loop (the loop
/// waiting while `stop_for_respawn` runs) holds the asks and fails this.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_status_ask_and_the_stop_are_taken_while_a_frozen_tor_is_reaped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tor = frozen_tor(dir.path());
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("the data directory");
    let (owner, inbox, feeds) = inbox();
    let network = network(dir.path(), feeds);
    let mut policy = super::policy();
    policy.reply_bound = Duration::from_secs(2);
    let task = tokio::spawn(drive(
        PinSource::Unchecked(tor),
        policy,
        true,
        18_021,
        data_dir,
        inbox,
        network,
    ));
    let supervisor = Supervisor { owner, task };
    // The launch is answered; a request after it is not, and is late one
    // bound later. Poll until the fault is seen: the reap is then in flight.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let status = tokio::time::timeout(Duration::from_secs(1), supervisor.status())
            .await
            .expect("a status ask was held: the reap starts in the fault's step")
            .expect("the loop runs");
        if status.cause == Cause::ReplyLate {
            break;
        }
        assert!(Instant::now() < deadline, "no fault: {status:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let reaping = Instant::now();
    for ask in 0..20 {
        let asked = Instant::now();
        let status = tokio::time::timeout(Duration::from_secs(1), supervisor.status())
            .await
            .unwrap_or_else(|_| panic!("ask {ask} was held"))
            .expect("the loop runs");
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
    tokio::time::timeout(Duration::from_secs(5), supervisor.shutdown())
        .await
        .expect("the stop was taken while the reap waited");
}
