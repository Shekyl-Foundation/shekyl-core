// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The composition starts and stops: offline, and with a clearnet listener
//! that accepts a connection. Twice in one process, since the link gate
//! and the ban-timer generation are process-wide. And with Tor off, a
//! clearnet handshake reaches the session layer and is answered: the
//! connectors' admissions are pumped independently of one another.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use shekyl_levin::{
    invoke, BasicNodeData, BucketReader, HandshakeRequest, PortableMap, Received, COMMAND_HANDSHAKE,
};

use shekyl_p2p::{
    Admit, BanSpan, BanTarget, ClaimCarrier, ClearnetPlan, CoreSyncData, Established, LinkLimits,
    Network, NetworkParts, NetworkPlan, NodeSync, PeerPlan, PoolDoor, Sockets, SyncInbound,
    SyncOwner, Taken, TorPlan, TxId,
};
use tokio::sync::watch;

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

fn plan(dir: &std::path::Path, clearnet: Option<ClearnetPlan>) -> NetworkPlan {
    NetworkPlan {
        network_id: [7; 16],
        seeds: None,
        allow_local: true,
        reserved_descriptors: 8,
        limits: LinkLimits {
            upload: None,
            download: None,
        },
        relay_noise: false,
        clearnet,
        tor: TorPlan::None,
        peers: PeerPlan {
            address_file: dir.join("p2pstate.bin"),
            operator: Vec::new(),
            exclusive: Vec::new(),
            disclose_early: false,
        },
        bans: Vec::new(),
    }
}

fn parts(plan: NetworkPlan) -> NetworkParts {
    let (_, node_sync) = watch::channel(NodeSync::Unsynchronised);
    let (_, tip) = watch::channel(CoreSyncData {
        current_height: 1,
        cumulative_difficulty: 1,
        cumulative_difficulty_top64: 0,
        top_id: [1; 32],
    });
    NetworkParts {
        plan,
        sockets: Sockets::new(),
        sync: Arc::new(NoSync),
        pool: Arc::new(EmptyPool),
        node_sync,
        tip,
    }
}

#[test]
fn offline_starts_and_stops() {
    let dir = tempfile::tempdir().expect("tempdir");
    let network = Network::start(parts(plan(dir.path(), None))).expect("starts");
    assert!(network.listening().clearnet.is_empty());
    assert_eq!(network.listening().tor_forward, None);
    assert!(network.connections(0).connections.is_empty());
    assert_eq!(network.session_counts(), (0, 0));
    network.stop();
    network.stop();
}

#[test]
fn clearnet_binds_accepts_and_stops_twice_in_one_process() {
    for round in 0..2 {
        let dir = tempfile::tempdir().expect("tempdir");
        let clearnet = ClearnetPlan {
            listen: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
            proxy: None,
            encrypt: false,
            own: Vec::new(),
        };
        let network = Network::start(parts(plan(dir.path(), Some(clearnet)))).expect("starts");
        let bound = network.listening().clearnet[0];
        assert_ne!(bound.port(), 0, "round {round}: the listener is bound");
        // A connection is accepted; with no handshake it is a socket, not
        // a session.
        let stream = TcpStream::connect_timeout(&bound, Duration::from_secs(5))
            .expect("the listener accepts");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(network.session_counts(), (0, 0));
        assert!(network
            .bans()
            .ban(BanTarget::Host(bound.ip()), BanSpan::Permanent));
        assert!(network.bans().is_banned(bound.ip()));
        assert!(network.bans().lift(BanTarget::Host(bound.ip())));
        drop(stream);
        network.stop();
        assert!(
            TcpStream::connect_timeout(&bound, Duration::from_millis(500)).is_err(),
            "round {round}: the listener is gone after stop"
        );
    }
}

/// With Tor off the Tor admission channel has no sender and ends at start.
/// A clearnet handshake must still be adopted and answered: the pump that
/// hands admissions to the session layer retires a closed connector's arm,
/// not itself. (Found 2026-11-05 by the black-box walk: every clearnet
/// admission on a Tor-off node ended as the node's own failure.)
#[test]
fn a_clearnet_handshake_is_answered_with_tor_off() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clearnet = ClearnetPlan {
        listen: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
        proxy: None,
        encrypt: false,
        own: Vec::new(),
    };
    let network = Network::start(parts(plan(dir.path(), Some(clearnet)))).expect("starts");
    let bound = network.listening().clearnet[0];
    let mut stream =
        TcpStream::connect_timeout(&bound, Duration::from_secs(5)).expect("the listener accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let request = HandshakeRequest {
        node_data: BasicNodeData {
            network_id: [7; 16],
        },
        payload_data: CoreSyncData {
            current_height: 1,
            cumulative_difficulty: 1,
            cumulative_difficulty_top64: 0,
            top_id: [1; 32],
        },
        nonce: [0x5c; 32],
    };
    stream
        .write_all(&invoke(
            COMMAND_HANDSHAKE,
            &request.store().expect("a handshake encodes"),
        ))
        .expect("the handshake is written");
    let mut reader = BucketReader::new();
    let mut buf = vec![0u8; 65536];
    let answered = loop {
        match reader.next_message() {
            Ok(Some(Received::Response { command, .. })) if command == COMMAND_HANDSHAKE => {
                break true
            }
            Ok(Some(other)) => {
                panic!("the first message back must be the 1001 response: {other:?}")
            }
            Ok(None) => {}
            Err(e) => panic!("the response did not frame: {e}"),
        }
        match stream.read(&mut buf) {
            Ok(0) => break false,
            Ok(n) => reader.feed(&buf[..n]).expect("feed"),
            Err(e) => panic!("the peer's read ended: {e}"),
        }
    };
    assert!(
        answered,
        "the handshake must be answered: the connection was closed instead"
    );
    // The session layer writes the response before it marks the session
    // established, so no owner's first message can precede it; the board
    // can therefore trail the bytes this peer has just read. Wait for the
    // board, bounded: a session that closed instead never shows.
    let by = Instant::now() + Duration::from_secs(5);
    while network.session_counts() != (0, 1) && Instant::now() < by {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        network.session_counts(),
        (0, 1),
        "one inbound session is established"
    );
    drop(stream);
    network.stop();
}
