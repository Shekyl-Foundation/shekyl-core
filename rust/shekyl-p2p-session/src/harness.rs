// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! An in-memory peer for tests (feature `harness`): a [`Dial`] whose
//! channels are two capped-stream ends with the test on the far side, and
//! the frames a far side writes. The session layer's own tests and the
//! owners' tests drive it; nothing in production reaches it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use shekyl_capped_stream::{ByteQueue, InboundEnd, QueueHold, Session, StreamEnds};
use shekyl_levin::{
    invoke, notify, response, BasicNodeData, BucketReader, CoreSyncData, GetTxpoolComplement,
    HandshakeRequest, HandshakeResponse, NewTransactions, PeerlistEntry, PortableMap, Received,
    RequestHeaders, TimedSyncRequest, TimedSyncResponse, DEFAULT_MAX_PACKET_SIZE,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{
    ConnectorId, DialEnd, DialFailure, Reached, Retry, SocketId, Sockets, StreamEnd,
};
use tokio::sync::mpsc;

use crate::dial::{Channel, ConnectFuture, Dial};
use crate::endpoint::{admit, Endpoint};
use crate::Command;

/// How long a test waits for anything before it fails.
pub const WAIT: Duration = Duration::from_secs(5);
/// How long a test waits before it says nothing arrived.
pub const SETTLE: Duration = Duration::from_millis(300);

/// Block until `fut` resolves, or fail the test after [`WAIT`].
///
/// # Panics
/// Nothing within [`WAIT`].
pub async fn within<F: std::future::Future>(what: &str, fut: F) -> F::Output {
    tokio::time::timeout(WAIT, fut)
        .await
        .unwrap_or_else(|_| panic!("{what}: nothing within {WAIT:?}"))
}

/// The far side of one channel: inject bytes toward the session, read
/// what the session wrote.
pub struct Wire {
    /// The admission the channel runs under.
    pub id: SocketId,
    inject: Option<InboundEnd>,
    out: mpsc::UnboundedReceiver<Vec<u8>>,
    hold: Option<QueueHold>,
    writer: Option<JoinHandle<()>>,
    reader: BucketReader,
}

impl Wire {
    /// Build both ends. With `drain`, a writer thread drains the session's
    /// queue to the wire, one push per bucket; without it the queue fills.
    #[must_use]
    pub fn open(id: SocketId, send_cap: usize, drain: bool) -> (Self, Session) {
        let ends = StreamEnds::open(send_cap);
        let (tx, out) = mpsc::unbounded_channel();
        let writer = drain.then(|| {
            let queue: ByteQueue = ends.writer_queue.clone();
            thread::spawn(move || {
                while let Ok(bytes) = queue.pop_blocking() {
                    queue.release(bytes.len());
                    if let Err(_test_gone) = tx.send(bytes) {}
                }
            })
        });
        let mut reader = BucketReader::new();
        reader.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
        (
            Self {
                id,
                inject: Some(ends.inbound),
                out,
                hold: Some(ends.hold),
                writer,
                reader,
            },
            ends.session,
        )
    }

    /// Push raw bytes toward the session, as a connector's reader would.
    ///
    /// # Panics
    /// The inbound end was closed, or the session stopped reading.
    pub async fn inject(&self, bytes: Vec<u8>) {
        let end = self.inject.as_ref().expect("the inbound end is still open");
        end.send(bytes).await.expect("the session still reads");
    }

    /// [`Self::inject`] from a thread that is not a task.
    ///
    /// # Panics
    /// The inbound end was closed, or the session stopped reading.
    pub fn inject_blocking(&self, bytes: Vec<u8>) {
        let end = self.inject.as_ref().expect("the inbound end is still open");
        end.blocking_send(bytes).expect("the session still reads");
    }

    /// Close the inbound end without storing an end: the peer closed.
    pub fn peer_closes(&mut self) {
        drop(self.inject.take());
    }

    /// Close the inbound end with `end` stored: the connector saw it.
    pub fn connector_ends(&mut self, end: DialEnd) {
        if let Some(inbound) = self.inject.take() {
            inbound.close(end);
            drop(inbound);
        }
    }

    /// The next bucket the session wrote.
    ///
    /// # Panics
    /// The session wrote a malformed bucket, closed its queue first, or
    /// wrote nothing within [`WAIT`].
    pub async fn read(&mut self) -> Received {
        loop {
            match self.reader.next_message() {
                Ok(Some(received)) => return received,
                Ok(None) => {}
                Err(error) => panic!("the session wrote a malformed bucket: {error:?}"),
            }
            let bytes = within("a bucket from the session", self.out.recv())
                .await
                .expect("the session's queue closed before the bucket");
            self.reader.feed(&bytes).expect("the session's bytes frame");
        }
    }

    /// [`Self::read`] from a thread that is not a task, waiting up to
    /// [`WAIT`].
    ///
    /// # Panics
    /// As [`Self::read`].
    pub fn read_blocking(&mut self) -> Received {
        loop {
            match self.reader.next_message() {
                Ok(Some(received)) => return received,
                Ok(None) => {}
                Err(error) => panic!("the session wrote a malformed bucket: {error:?}"),
            }
            let bytes = self
                .out
                .blocking_recv()
                .expect("the session's queue closed before the bucket");
            self.reader.feed(&bytes).expect("the session's bytes frame");
        }
    }

    /// `true` once the session's queue closed with nothing more to read.
    pub async fn drained(&mut self) -> bool {
        within("the session's queue to close", self.out.recv())
            .await
            .is_none()
    }

    /// Whether anything is waiting to be read, after [`SETTLE`].
    pub async fn is_quiet(&mut self) -> bool {
        tokio::time::sleep(SETTLE).await;
        self.out.try_recv().is_err()
    }
}

impl Drop for Wire {
    fn drop(&mut self) {
        drop(self.inject.take());
        drop(self.hold.take());
        if let Some(writer) = self.writer.take() {
            writer.join().expect("harness writer");
        }
    }
}

/// How the loopback answers the next dial.
pub enum Answer {
    /// Admit and build a channel; the wire goes to the test.
    Connect,
    /// Refuse with this end before any I/O.
    Refuse(DialEnd),
}

/// The connectors: admission through the shared table, channels built in
/// memory. Each connected dial's far side arrives on the receiver
/// [`Self::new`] returns.
pub struct Loopback {
    sockets: Sockets,
    ceiling: InboundCeiling,
    answers: Mutex<VecDeque<Answer>>,
    dialed: mpsc::UnboundedSender<Wire>,
    send_cap: usize,
}

impl Loopback {
    /// Build the loopback over `sockets`. A dial with no queued answer
    /// connects.
    #[must_use]
    pub fn new(
        sockets: Sockets,
        ceiling: InboundCeiling,
        send_cap: usize,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<Wire>) {
        let (dialed, wires) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                sockets,
                ceiling,
                answers: Mutex::new(VecDeque::new()),
                dialed,
                send_cap,
            }),
            wires,
        )
    }

    /// Queue how the next dial is answered.
    pub fn answer_next(&self, answer: Answer) {
        self.answers.lock().expect("answers").push_back(answer);
    }

    /// Admit an inbound connection from `endpoint` and build its channel:
    /// the far side for the test, the channel for the layer to adopt.
    ///
    /// # Panics
    /// The admission table refused it.
    #[must_use]
    pub fn accept(&self, endpoint: Endpoint, send_cap: usize, drain: bool) -> (Wire, Channel) {
        let open = admit(&self.sockets, &endpoint, Tick::new(0), self.ceiling).expect("admitted");
        let (wire, session) = Wire::open(open.id(), send_cap, drain);
        (
            wire,
            Channel {
                open,
                session,
                endpoint,
                gap: None,
            },
        )
    }
}

impl Dial for Loopback {
    fn connect_async(&self, endpoint: &Endpoint) -> ConnectFuture {
        let endpoint = *endpoint;
        let answer = self
            .answers
            .lock()
            .expect("answers")
            .pop_front()
            .unwrap_or(Answer::Connect);
        let result = match answer {
            Answer::Refuse(end) => Err(end),
            Answer::Connect => {
                let now = Tick::new(0);
                match admit(&self.sockets, &endpoint, now, self.ceiling) {
                    Err(cause) => Err(DialEnd::new(
                        DialFailure::local(Retry::Again, Reached::NoStream),
                        cause,
                    )),
                    Ok(open) => {
                        let (wire, session) = Wire::open(open.id(), self.send_cap, true);
                        if let Err(_test_gone) = self.dialed.send(wire) {}
                        Ok(Channel {
                            open,
                            session,
                            endpoint,
                            gap: None,
                        })
                    }
                }
            }
        };
        Box::pin(async move { result })
    }

    fn stamp_stream_end(&self, _connector: ConnectorId, end: StreamEnd) -> DialFailure {
        match end {
            StreamEnd::PeerClosed => DialFailure::uncertain(Retry::Again, Reached::StreamOpened),
            StreamEnd::IoError | StreamEnd::SendQueueFull => {
                DialFailure::local(Retry::Again, Reached::StreamOpened)
            }
        }
    }
}

/// A peer's 1001 request.
///
/// # Panics
/// The payload does not store.
#[must_use]
pub fn handshake_request(network_id: [u8; 16], nonce: [u8; 32], tip: CoreSyncData) -> Vec<u8> {
    let payload = HandshakeRequest {
        node_data: BasicNodeData { network_id },
        payload_data: tip,
        nonce,
    }
    .store()
    .expect("request stores");
    invoke(Command::Handshake.wire_id(), &payload)
}

/// A peer's 1001 response.
///
/// # Panics
/// The payload does not store.
#[must_use]
pub fn handshake_response(
    network_id: [u8; 16],
    list: Vec<PeerlistEntry>,
    tip: CoreSyncData,
) -> Vec<u8> {
    let payload = HandshakeResponse {
        node_data: BasicNodeData { network_id },
        payload_data: tip,
        local_peerlist_new: list,
    }
    .store()
    .expect("response stores");
    response(Command::Handshake.wire_id(), &payload)
}

/// A peer's 1002 request.
///
/// # Panics
/// The payload does not store.
#[must_use]
pub fn timed_sync_request(tip: CoreSyncData) -> Vec<u8> {
    let payload = TimedSyncRequest { payload_data: tip }
        .store()
        .expect("request stores");
    invoke(Command::TimedSync.wire_id(), &payload)
}

/// A peer's 1002 response.
///
/// # Panics
/// The payload does not store.
#[must_use]
pub fn timed_sync_response(list: Vec<PeerlistEntry>, tip: CoreSyncData) -> Vec<u8> {
    let payload = TimedSyncResponse {
        payload_data: tip,
        local_peerlist_new: list,
    }
    .store()
    .expect("response stores");
    response(Command::TimedSync.wire_id(), &payload)
}

/// A peer's 2002 with `count` eight-byte transactions.
///
/// # Panics
/// The payload does not store.
#[must_use]
pub fn new_transactions(count: u8) -> Vec<u8> {
    let payload = NewTransactions {
        txs: (0..count).map(|i| vec![i; 8]).collect(),
        padding: Vec::new(),
        dandelionpp_fluff: true,
    }
    .store()
    .expect("batch stores");
    notify(Command::NewTransactions.wire_id(), &payload)
}

/// A peer's 2010 naming `count` hashes.
///
/// # Panics
/// The payload does not store.
#[must_use]
pub fn txpool_complement(count: u8) -> Vec<u8> {
    let payload = GetTxpoolComplement {
        hashes: (0..count).map(|i| [i; 32]).collect(),
    }
    .store()
    .expect("request stores");
    notify(Command::GetTxpoolComplement.wire_id(), &payload)
}

/// A peer's 2011 naming one block.
///
/// # Panics
/// The payload does not store.
#[must_use]
pub fn request_headers() -> Vec<u8> {
    let payload = RequestHeaders {
        block_ids: vec![[3; 32]],
    }
    .store()
    .expect("request stores");
    notify(Command::RequestHeaders.wire_id(), &payload)
}
