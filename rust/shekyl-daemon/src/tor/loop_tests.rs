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

/// A `tor` that takes its arguments and the inherited control connection,
/// and says nothing for longer than the test runs.
fn silent_tor(dir: &std::path::Path) -> VerifiedTorBinary {
    let path = dir.join("tor");
    let mut script = std::fs::File::create(&path).expect("the stand-in");
    script
        .write_all(b"#!/bin/sh\nexec sleep 45\n")
        .expect("the stand-in's text");
    drop(script);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("the stand-in runs");
    VerifiedTorBinary::unchecked_for_test(path)
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
