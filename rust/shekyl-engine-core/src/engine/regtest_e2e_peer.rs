// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A simulated Levin peer for the regtest walks: the adversary, or the
//! network around the origin, lives here and not in the daemon (Rick,
//! 2026-10-29: "the adversary belongs in the test; the code under test is
//! the origin"). Levin over loopback TCP inside the Noise channel, the
//! clearnet every daemon speaks.
//!
//! A peer answers the handshake and every timed sync, records each
//! `NOTIFY_NEW_TRANSACTIONS` it receives with its fluff flag, and forwards
//! nothing: a stem sent to it is swallowed. A test can also make it send a
//! transaction on its own session. It listens (the daemon dials it, so it
//! can take an outbound stem slot) or dials the daemon.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shekyl_levin::{
    invoke, notify, response, BasicNodeData, BucketReader, CoreSyncData, HandshakeRequest,
    HandshakeResponse, NewTransactions, PortableMap, Received, TimedSyncResponse,
    COMMAND_HANDSHAKE, COMMAND_TIMED_SYNC, NOTIFY_NEW_TRANSACTIONS,
};
use shekyl_p2p_transport::{Initiator, RecvHalf, Responder, SendHalf};

/// How long the channel's handshake may take on a loaded host.
const CHANNEL_OPEN_WAIT: Duration = Duration::from_secs(10);
/// How long one read waits, so the session loop sees its outbox and stop.
const SESSION_READ_WAIT: Duration = Duration::from_millis(200);

/// One `NOTIFY_NEW_TRANSACTIONS` the peer received.
#[derive(Debug, Clone)]
pub(super) struct Heard {
    /// When it arrived.
    pub(super) at: Instant,
    /// The sender's fluff flag: `false` is a stem.
    pub(super) fluff: bool,
    /// The transaction blobs.
    pub(super) txs: Vec<Vec<u8>>,
}

/// A running simulated peer.
pub(super) struct TestPeer {
    /// Where it listens, for a listening peer.
    pub(super) addr: SocketAddrV4,
    heard: Arc<Mutex<Vec<Heard>>>,
    live: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    send: Sender<Vec<u8>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestPeer {
    /// Listen on a free port of loopback address `host` and serve the first
    /// connection. The daemon dials no host it already holds a session
    /// with, so two listening peers take two loopback hosts (`127.0.0.1`,
    /// `127.0.0.2`).
    pub(super) fn listen(host: Ipv4Addr) -> Self {
        let listener = TcpListener::bind(SocketAddrV4::new(host, 0)).expect("bind a test peer");
        let port = listener.local_addr().expect("local addr").port();
        let addr = SocketAddrV4::new(host, port);
        let shared = Shared::new();
        let worker = shared.clone();
        let (send, outbox) = channel();
        // Every connection is served in turn, not only the first: the
        // daemon's dialer confirms an address with one session it closes,
        // then dials again to keep one.
        let thread = std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("a non-blocking listener");
            while !worker.stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("a blocking session");
                        serve(stream, &worker, &outbox, false);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => return,
                }
            }
        });
        shared.into_peer(addr, send, thread)
    }

    /// Dial the daemon's P2P port and serve the session.
    pub(super) fn dial(daemon_p2p: u16) -> Self {
        let shared = Shared::new();
        let worker = shared.clone();
        let (send, outbox) = channel();
        let thread = std::thread::spawn(move || {
            let Ok(stream) = TcpStream::connect(("127.0.0.1", daemon_p2p)) else {
                return;
            };
            serve(stream, &worker, &outbox, true);
        });
        shared.into_peer(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), send, thread)
    }

    /// Whether a session is up now: its handshake was answered and the
    /// daemon has not closed it. A confirming dial the daemon closes at once
    /// leaves this false.
    pub(super) fn live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }

    /// Everything heard so far.
    pub(super) fn heard(&self) -> Vec<Heard> {
        self.heard
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Send `blob` to the daemon on this peer's own session, as a fluff.
    pub(super) fn fluff(&self, blob: &[u8]) {
        let body = NewTransactions {
            txs: vec![blob.to_vec()],
            padding: Vec::new(),
            dandelionpp_fluff: true,
        }
        .store()
        .expect("encode a transaction notify");
        self.send
            .send(notify(NOTIFY_NEW_TRANSACTIONS, &body))
            .expect("the peer's session is running");
    }
}

impl Drop for TestPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
    }
}

#[derive(Clone)]
struct Shared {
    heard: Arc<Mutex<Vec<Heard>>>,
    live: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl Shared {
    fn new() -> Self {
        Self {
            heard: Arc::new(Mutex::new(Vec::new())),
            live: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    fn into_peer(
        self,
        addr: SocketAddrV4,
        send: Sender<Vec<u8>>,
        thread: std::thread::JoinHandle<()>,
    ) -> TestPeer {
        TestPeer {
            addr,
            heard: self.heard,
            live: self.live,
            stop: self.stop,
            send,
            thread: Some(thread),
        }
    }
}

/// The regtest network id the daemon checks on every handshake.
fn network_id() -> [u8; 16] {
    shekyl_p2p_transport::network_id_from_genesis(&shekyl_rpc_types::genesis_hash_for(
        shekyl_rpc_types::Network::Regtest,
    ))
}

/// What this peer says of its chain: regtest's genesis and nothing on it,
/// so the daemon never asks it for blocks and reads itself synchronized.
fn sync_data() -> CoreSyncData {
    CoreSyncData {
        current_height: 1,
        cumulative_difficulty: 1,
        cumulative_difficulty_top64: 0,
        top_id: shekyl_rpc_types::genesis_hash_for(shekyl_rpc_types::Network::Regtest),
    }
}

fn serve(stream: TcpStream, shared: &Shared, outbox: &Receiver<Vec<u8>>, initiate: bool) {
    session(stream, shared, outbox, initiate);
    shared.live.store(false, Ordering::SeqCst);
}

/// The peer's socket with its open channel.
struct Link {
    sock: TcpStream,
    seal: SendHalf,
    open: RecvHalf,
    /// Ciphertext read and not yet opened.
    pending: Vec<u8>,
}

impl Link {
    /// Run this side's half of the handshake: the dialer initiates.
    fn open(mut sock: TcpStream, initiate: bool) -> Option<Self> {
        let id = network_id();
        let (seal, open) = if initiate {
            Initiator::open(&mut sock, &id).ok()?
        } else {
            Responder::accept(&mut sock, &id).ok()?
        };
        Some(Self {
            sock,
            seal,
            open,
            pending: Vec::new(),
        })
    }

    /// Seal `plain` and write it. `false` ends the session.
    fn send(&mut self, plain: &[u8]) -> bool {
        match self.seal.seal(plain) {
            Ok(wire) => self.sock.write_all(&wire).is_ok(),
            Err(_) => false,
        }
    }

    /// The next whole record's plaintext, `None` when none has arrived.
    fn next_record(&mut self) -> Result<Option<Vec<u8>>, shekyl_p2p_transport::RecordError> {
        self.open.take_one(&mut self.pending)
    }
}

fn session(stream: TcpStream, shared: &Shared, outbox: &Receiver<Vec<u8>>, initiate: bool) {
    drop(stream.set_read_timeout(Some(CHANNEL_OPEN_WAIT)));
    drop(stream.set_write_timeout(Some(Duration::from_secs(10))));
    drop(stream.set_nodelay(true));
    let Some(mut s) = Link::open(stream, initiate) else {
        return;
    };
    drop(s.sock.set_read_timeout(Some(SESSION_READ_WAIT)));
    if initiate {
        let request = HandshakeRequest {
            node_data: BasicNodeData {
                network_id: network_id(),
            },
            payload_data: sync_data(),
            nonce: [0x5e; 32],
        }
        .store()
        .expect("encode a handshake");
        if !s.send(&invoke(COMMAND_HANDSHAKE, &request)) {
            return;
        }
    }
    let mut reader = BucketReader::new();
    let mut buf = vec![0u8; 65_536];
    while !shared.stop.load(Ordering::Relaxed) {
        while let Ok(frame) = outbox.try_recv() {
            if !s.send(&frame) {
                return;
            }
        }
        loop {
            match reader.next_message() {
                Ok(Some(Received::Request { command, .. })) if command == COMMAND_HANDSHAKE => {
                    let body = HandshakeResponse {
                        node_data: BasicNodeData {
                            network_id: network_id(),
                        },
                        payload_data: sync_data(),
                        local_peerlist_new: Vec::new(),
                    }
                    .store()
                    .expect("encode a handshake response");
                    if !s.send(&response(COMMAND_HANDSHAKE, &body)) {
                        return;
                    }
                    shared.live.store(true, Ordering::SeqCst);
                }
                Ok(Some(Received::Request { command, .. })) if command == COMMAND_TIMED_SYNC => {
                    let body = TimedSyncResponse {
                        payload_data: sync_data(),
                        local_peerlist_new: Vec::new(),
                    }
                    .store()
                    .expect("encode a timed sync response");
                    if !s.send(&response(COMMAND_TIMED_SYNC, &body)) {
                        return;
                    }
                }
                Ok(Some(Received::Response { command, .. })) if command == COMMAND_HANDSHAKE => {
                    shared.live.store(true, Ordering::SeqCst);
                }
                Ok(Some(Received::Notification { command, payload }))
                    if command == NOTIFY_NEW_TRANSACTIONS =>
                {
                    if let Ok(notify) = NewTransactions::load(&payload) {
                        shared
                            .heard
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(Heard {
                                at: Instant::now(),
                                fluff: notify.dandelionpp_fluff,
                                txs: notify.txs,
                            });
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return,
            }
        }
        match s.next_record() {
            Ok(Some(plain)) => {
                if reader.feed(&plain).is_err() {
                    return;
                }
                continue;
            }
            Ok(None) => {}
            Err(_) => return,
        }
        match s.sock.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => s.pending.extend_from_slice(&buf[..n]),
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return,
        }
    }
}
