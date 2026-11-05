// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The p2p remnant cutover's black-box evidence
//! (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §5): a live regtest `shekyld`, a
//! simulated peer over a real socket, and nothing but the wire between
//! them. Each test asks one thing the session layer holds by type
//! (`shekyl-p2p-session`), and asks it of the shipped binary, not the
//! crate.
//!
//! `#[ignore]`d: every test needs `SHEKYLD_BIN`. Armed in
//! `scripts/ci/run_live_daemon_gates.sh` (`ARMED_LEVIN`).

mod live_daemon;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use live_daemon::{connect_from, regtest_network_id, Daemon, LoopbackHost};
use shekyl_levin::{
    invoke, notify, BasicNodeData, BucketReader, Command, CoreSyncData, GetTxpoolComplement,
    HandshakeRequest, NewTransactions, PortableMap, Received, TimedSyncRequest, COMMAND_HANDSHAKE,
    COMMAND_TIMED_SYNC, NOTIFY_GET_TXPOOL_COMPLEMENT, NOTIFY_NEW_TRANSACTIONS,
};

/// How long a test waits for the daemon to act on one message. Loopback;
/// the daemon's own timers are seconds to minutes, so a wait this long
/// that ends quiet is the daemon doing nothing, not doing it late.
const SETTLE: Duration = Duration::from_secs(5);

/// What the wire did while the peer waited.
#[derive(Debug)]
enum Wire {
    /// A whole message arrived.
    Message(Received),
    /// The daemon closed the socket.
    Closed,
    /// Nothing arrived and the socket stayed open for the whole wait.
    Quiet,
}

/// A simulated peer on one loopback host.
struct Peer {
    stream: TcpStream,
    reader: BucketReader,
}

impl Peer {
    fn connect(daemon: &Daemon, host: LoopbackHost) -> Self {
        let stream = connect_from(host.ip(), daemon.p2p_port)
            .unwrap_or_else(|e| panic!("the daemon did not accept the peer: {e}"));
        stream.set_nodelay(true).expect("nodelay");
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .expect("write timeout");
        Self {
            stream,
            reader: BucketReader::new(),
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).expect("the peer's write");
    }

    /// The next message within `within`, or how the wait ended.
    fn next(&mut self, within: Duration) -> Wire {
        let deadline = Instant::now() + within;
        let mut buf = vec![0u8; 65536];
        loop {
            match self.reader.next_message() {
                Ok(Some(message)) => return Wire::Message(message),
                Ok(None) => {}
                Err(e) => panic!("the daemon sent bytes the reader refused: {e}"),
            }
            let now = Instant::now();
            if now >= deadline {
                return Wire::Quiet;
            }
            self.stream
                .set_read_timeout(Some(deadline - now))
                .expect("read timeout");
            match self.stream.read(&mut buf) {
                Ok(0) => return Wire::Closed,
                Ok(n) => self.reader.feed(&buf[..n]).expect("feed"),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Wire::Quiet
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    return Wire::Closed
                }
                Err(e) => panic!("the peer's read: {e}"),
            }
        }
    }

    /// Whether the daemon closes the socket within `within`. The daemon's
    /// own traffic on an established session (its 2010 at establishment,
    /// its timed sync) is read past; only the close answers.
    fn is_closed_within(&mut self, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            match self.next(deadline - now) {
                Wire::Closed => return true,
                Wire::Quiet => return false,
                Wire::Message(_) => {}
            }
        }
    }

    /// Send a handshake with `claim` on `network`, and return the wire's
    /// answer.
    fn handshake(&mut self, network: [u8; 16], claim: CoreSyncData) -> Wire {
        let request = HandshakeRequest {
            node_data: BasicNodeData {
                network_id: network,
            },
            payload_data: claim,
            nonce: [0x5c; 32],
        };
        let payload = request.store().expect("a handshake encodes");
        self.send(&invoke(COMMAND_HANDSHAKE, &payload));
        self.next(SETTLE)
    }

    /// A handshake on the regtest network that the daemon answers.
    fn established(daemon: &Daemon, host: LoopbackHost, claim: CoreSyncData) -> Self {
        let mut peer = Self::connect(daemon, host);
        match peer.handshake(regtest_network_id(), claim) {
            Wire::Message(Received::Response { command, .. }) if command == COMMAND_HANDSHAKE => {}
            other => panic!(
                "the handshake must be answered; the wire did {other:?}\n--- daemon log tail ---\n{}",
                log_tail(daemon)
            ),
        }
        peer
    }

    /// Send a 1002 request carrying `claim` and expect its response: the
    /// session is alive. The claim is the peer's standing one: a timed
    /// sync replaces the claim the handshake made.
    fn timed_sync_is_answered(&mut self, claim: CoreSyncData) -> bool {
        let request = TimedSyncRequest {
            payload_data: claim,
        };
        let payload = request.store().expect("a timed sync encodes");
        self.send(&invoke(COMMAND_TIMED_SYNC, &payload));
        loop {
            match self.next(SETTLE) {
                Wire::Message(Received::Response { command, .. })
                    if command == COMMAND_TIMED_SYNC =>
                {
                    return true
                }
                // The daemon's own traffic on the session (its timed sync,
                // a chain request) is not the answer and not a refusal.
                Wire::Message(_) => {}
                Wire::Closed | Wire::Quiet => return false,
            }
        }
    }
}

/// A daemon for one test, logging at `debug` so a refusal's reason is in
/// its log when a test fails.
fn start(test: &str) -> Daemon {
    Daemon::start_with(test, None, "debug")
}

/// The daemon's log tail, for a failure message.
fn log_tail(daemon: &Daemon) -> String {
    let text = daemon.log_text();
    let lines: Vec<&str> = text.lines().rev().take(40).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
}

/// The claim a regtest node at genesis makes: one block, work 1, the
/// regtest genesis at the top. A node that hears it has a peer whose
/// claim does not exceed its own work, which resolves its opening: it
/// reads `Synced`.
fn genesis_claim() -> CoreSyncData {
    CoreSyncData {
        current_height: 1,
        cumulative_difficulty: 1,
        cumulative_difficulty_top64: 0,
        top_id: shekyl_rpc_types::genesis_hash_for(shekyl_rpc_types::Network::Regtest),
    }
}

/// A claim far ahead of a genesis node under `dev-difficulty 1`: as much
/// work as blocks, so chain sync admits it and asks the peer for headers.
/// A peer that never answers leaves the node's opening unresolved.
fn ahead_claim() -> CoreSyncData {
    CoreSyncData {
        current_height: 100,
        cumulative_difficulty: 100,
        cumulative_difficulty_top64: 0,
        top_id: [0x77u8; 32],
    }
}

fn new_transactions(txs: Vec<Vec<u8>>) -> Vec<u8> {
    let batch = NewTransactions {
        txs,
        padding: Vec::new(),
        dandelionpp_fluff: false,
    };
    notify(
        NOTIFY_NEW_TRANSACTIONS,
        &batch.store().expect("a batch encodes"),
    )
}

/// `get_info.synchronized`, the node's `SyncState::Synced` as the RPC
/// reports it (`shekyl-node/src/facts.rs`); the relay owner reads the
/// same state.
fn synchronized(daemon: &Daemon) -> Option<bool> {
    let mut s = TcpStream::connect(("127.0.0.1", daemon.rpc_port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let body = r#"{"jsonrpc":"2.0","id":"0","method":"get_info"}"#;
    let req = format!(
        "POST /json_rpc HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        daemon.rpc_port,
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    if text.contains("\"synchronized\":true") {
        Some(true)
    } else if text.contains("\"synchronized\":false") {
        Some(false)
    } else {
        None
    }
}

fn wait_until(deadline: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + deadline;
    while Instant::now() < end {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    done()
}

/// The daemon's resident set, in KiB (`/proc/<pid>/status`, `VmRSS`).
fn resident_kib(daemon: &Daemon) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{}/status", daemon.pid()))
        .expect("the daemon's /proc status");
    let line = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .expect("VmRSS");
    line.split_whitespace()
        .nth(1)
        .and_then(|n| n.parse().ok())
        .expect("VmRSS in KiB")
}

// ------------------------------------------------------------ handshake

#[test]
#[ignore = "p2p remnant cutover evidence: requires SHEKYLD_BIN; spawns a live daemon"]
fn an_other_network_handshake_is_dropped_and_the_host_is_not_banned() {
    let daemon = start("other-network");
    let host = LoopbackHost::peer(0);

    let mut stranger = Peer::connect(&daemon, host);
    match stranger.handshake([0x11; 16], genesis_claim()) {
        Wire::Closed => {}
        other => panic!(
            "an other-network handshake must close the socket unanswered; the wire did {other:?}"
        ),
    }

    // Never banned: the same host's next handshake, on the right network,
    // is answered.
    let mut returning = Peer::established(&daemon, host, genesis_claim());
    assert!(
        returning.timed_sync_is_answered(genesis_claim()),
        "the host that sent an other-network handshake must still be admitted"
    );
}

#[test]
#[ignore = "p2p remnant cutover evidence: requires SHEKYLD_BIN; spawns a live daemon"]
fn nothing_but_a_handshake_is_accepted_before_it() {
    let daemon = start("before-handshake");

    // A 1002 request before the handshake: closed, unanswered.
    let mut early_sync = Peer::connect(&daemon, LoopbackHost::peer(0));
    let request = TimedSyncRequest {
        payload_data: genesis_claim(),
    };
    early_sync.send(&invoke(
        COMMAND_TIMED_SYNC,
        &request.store().expect("encodes"),
    ));
    match early_sync.next(SETTLE) {
        Wire::Closed => {}
        other => panic!(
            "a timed sync before the handshake must close the socket; the wire did {other:?}"
        ),
    }

    // Transactions before the handshake: refused, the socket closed.
    let mut early_txs = Peer::connect(&daemon, LoopbackHost::peer(1));
    early_txs.send(&new_transactions(vec![vec![0xAB; 64]]));
    match early_txs.next(SETTLE) {
        Wire::Closed => {}
        other => panic!(
            "transactions before the handshake must close the socket; the wire did {other:?}"
        ),
    }

    // Every other command, as the notify its owner would read: each closes
    // the socket unanswered. The payload is not read before the command is
    // judged, so an empty one stands for any.
    let others = Command::ALL.into_iter().filter(|command| {
        !matches!(
            command,
            Command::Handshake | Command::TimedSync | Command::NewTransactions
        )
    });
    for (n, command) in (2u32..).zip(others) {
        let mut early = Peer::connect(&daemon, LoopbackHost::peer(n));
        early.send(&notify(command.wire_id(), &[]));
        match early.next(SETTLE) {
            Wire::Closed => {}
            other => panic!(
                "{command:?} before the handshake must close the socket; the wire did {other:?}"
            ),
        }
    }
}

#[test]
#[ignore = "p2p remnant cutover evidence: requires SHEKYLD_BIN; spawns a live daemon"]
fn a_second_handshake_closes_the_session() {
    let daemon = start("second-handshake");
    let mut peer = Peer::established(&daemon, LoopbackHost::peer(0), genesis_claim());
    let request = HandshakeRequest {
        node_data: BasicNodeData {
            network_id: regtest_network_id(),
        },
        payload_data: genesis_claim(),
        nonce: [0x5c; 32],
    };
    peer.send(&invoke(
        COMMAND_HANDSHAKE,
        &request.store().expect("a handshake encodes"),
    ));
    assert!(
        peer.is_closed_within(SETTLE),
        "a second handshake must close the session"
    );
}

// ----------------------------------------------------------- transactions

#[test]
#[ignore = "p2p remnant cutover evidence: requires SHEKYLD_BIN; spawns a live daemon"]
fn transactions_are_ignored_while_unsynchronised_and_judged_once_synced() {
    let daemon = start("txs-by-sync-state");
    // With no session the node has no view of the chain: `NoView`, and
    // the RPC's `synchronized` is false.
    assert_eq!(
        synchronized(&daemon),
        Some(false),
        "a node with no session has no view\n--- daemon log tail ---\n{}",
        log_tail(&daemon)
    );

    // A peer whose claim exceeds the node's work, and which never answers
    // the header request that claim draws, leaves the opening unresolved:
    // the node stays `NoView`, unsynchronised.
    let mut ahead = Peer::established(&daemon, LoopbackHost::peer(0), ahead_claim());
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(
        synchronized(&daemon),
        Some(false),
        "an unanswered claim ahead of the node's work must leave it without a view"
    );

    // A malformed transaction while unsynchronised is ignored: the batch
    // is not judged, so the session is not severed, and it still answers.
    ahead.send(&new_transactions(vec![vec![0xAB; 64]]));
    assert!(
        ahead.timed_sync_is_answered(ahead_claim()),
        "transactions received while unsynchronised must be ignored, not judged"
    );
    assert_eq!(synchronized(&daemon), Some(false));

    // A peer whose claim is the node's own tip answers for it. Once the
    // ahead peer has gone, every session has answered: the opening
    // resolves and the node reads `Synced`.
    let mut level = Peer::established(&daemon, LoopbackHost::peer(1), genesis_claim());
    drop(ahead);
    assert!(
        wait_until(Duration::from_secs(30), || synchronized(&daemon)
            == Some(true)),
        "with the ahead peer gone and a level peer answering, the node must read synced"
    );

    // The same batch on a synced node is judged: a malformed transaction
    // severs the session (`Admit::RefusedForm`). A well-formed one is
    // admitted and relayed, which the two-daemon origin walks show.
    level.send(&new_transactions(vec![vec![0xAB; 64]]));
    assert!(
        level.is_closed_within(SETTLE),
        "a malformed transaction on a synced node must sever the session"
    );
}

// ----------------------------------------------------------------- 2010

#[test]
#[ignore = "p2p remnant cutover evidence: requires SHEKYLD_BIN; spawns a live daemon"]
fn the_txpool_complement_is_served() {
    let daemon = start("complement");
    let mut peer = Peer::established(&daemon, LoopbackHost::peer(0), genesis_claim());
    let request = GetTxpoolComplement {
        hashes: vec![[0x42; 32]],
    };
    peer.send(&notify(
        NOTIFY_GET_TXPOOL_COMPLEMENT,
        &request.store().expect("encodes"),
    ));
    let batch = loop {
        match peer.next(SETTLE) {
            Wire::Message(Received::Notification { command, payload })
                if command == NOTIFY_NEW_TRANSACTIONS =>
            {
                break NewTransactions::load(&payload).expect("the complement decodes")
            }
            Wire::Message(_) => {}
            other => panic!("the complement must be served as a 2002; the wire did {other:?}"),
        }
    };
    // An empty pool's complement of one unknown hash is empty, and the
    // flag is the inherited reply's (stem).
    assert!(batch.txs.is_empty(), "an empty pool has no complement");
    assert!(!batch.dandelionpp_fluff);
}

// ---------------------------------------------------------- backpressure

#[test]
#[ignore = "p2p remnant cutover evidence: requires SHEKYLD_BIN; spawns a live daemon"]
fn a_flood_of_notifications_is_read_one_at_a_time_without_growing_memory() {
    let daemon = start("flood");
    // Empty batches: each is dispatched to the relay owner, judged, and
    // found to carry nothing. The session reads one frame per permit
    // (`SESSION_QUEUE_DEPTH` = 1); what the peer sends faster than that
    // waits in the kernel's buffers and, when they are full, in the peer.
    let mut peer = Peer::established(&daemon, LoopbackHost::peer(0), genesis_claim());
    let before = resident_kib(&daemon);
    let frame = new_transactions(Vec::new());
    let target: usize = 32 * 1024 * 1024;
    let mut sent = 0usize;
    let started = Instant::now();
    while sent < target {
        match peer.stream.write(&frame) {
            Ok(n) => sent += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => panic!("the flood's write failed: {e}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "the daemon stopped reading the flood: {sent} of {target} bytes in 120 s"
        );
    }
    // Let the daemon drain what the kernel holds, then ask it to answer.
    assert!(
        peer.timed_sync_is_answered(genesis_claim()),
        "the session must still answer after the flood"
    );
    let after = resident_kib(&daemon);
    let grew_kib = after.saturating_sub(before);
    eprintln!(
        "flood: {sent} bytes of 2002 in {:?}; daemon RSS {before} KiB -> {after} KiB (+{grew_kib} KiB)",
        started.elapsed()
    );
    assert!(
        grew_kib < 16 * 1024,
        "the daemon's resident set grew {grew_kib} KiB under a {sent}-byte flood: the reads were buffered, not paced"
    );
}
