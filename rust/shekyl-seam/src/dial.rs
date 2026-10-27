// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The dialer the seam asks for a channel.
//!
//! Zone bind installs the dialer that calls a connector. The loopback
//! dialer is the strand harness: an in-memory channel, not a socket.
//! The hub does not dial and does not build a [`shekyl_capped_stream::StreamEnds`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::Thread;

use shekyl_capped_stream::Session;
use shekyl_peer_policy::InboundCeiling;
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{CloseCause, OpenSocket, SocketId};
use tokio::sync::oneshot;

use crate::endpoint::Endpoint;
use crate::hub::Hub;

/// A channel the connector already admitted and built.
pub struct Channel {
    /// The admission reservation.
    pub open: OpenSocket,
    /// The caller's end of the byte cap. The pump owns it.
    pub session: Session,
    /// What `established` posts.
    pub endpoint: Endpoint,
    /// Fires when the Levin handshake completes. `None` when this channel
    /// has no gap deadline. Dropping it ends the connector's wait.
    pub gap: Option<oneshot::Sender<()>>,
}

/// A channel still being opened: [`Dial::connect_async`]'s future.
/// Dropping it before it resolves cancels the connect, and the dialer that
/// started the connect releases whatever it reserved.
pub type ConnectFuture = Pin<Box<dyn Future<Output = Result<Channel, CloseCause>> + Send>>;

/// One dial attempt, as the outbound dialer hands it to [`Dial::spawn_attempt`].
/// It resolves when the attempt has posted its result, or at once when it
/// is cancelled. It holds no lock of the caller's.
pub type AttemptTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Opens a channel. The hub adopts the result and posts `established`.
pub trait Dial: Send + Sync {
    /// Admit and build the channel. `ceiling` and `now` are the hub's,
    /// copied before this call so the dial does not hold the table lock.
    fn connect(
        &self,
        endpoint: &Endpoint,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> Result<Channel, CloseCause>;

    /// [`Self::connect`] without blocking the caller: the outbound dialer's
    /// attempt task awaits this, on whatever [`Self::spawn_attempt`] runs it
    /// on. The default runs [`Self::connect`] at once and is ready: right
    /// for a dialer whose connect does not wait, the loopback and the test
    /// dialers. A dialer whose connect waits on the network overrides this,
    /// and its future cancels the connect when dropped.
    fn connect_async(
        &self,
        endpoint: &Endpoint,
        ceiling: InboundCeiling,
        now: Tick,
    ) -> ConnectFuture {
        let result = self.connect(endpoint, ceiling, now);
        Box::pin(std::future::ready(result))
    }

    /// Run one outbound dial attempt to its end. The dialer chooses where
    /// attempts run, as it chooses where pumps run ([`Self::drive`]).
    ///
    /// The default runs `task` on a thread of its own that polls it to the
    /// end: the harness path, for the loopback and the test dialers, whose
    /// threads no ledger counts. Zone bind overrides it and runs every
    /// attempt as a task on the transport runtime's async workers, never
    /// on its blocking pool and never on an unledgered thread: past the
    /// pool's cap, connections went deaf (`drive`'s history). Returns
    /// `false` when the attempt could not be started; it was dropped,
    /// which is its cancellation.
    fn spawn_attempt(&self, task: AttemptTask) -> bool {
        std::thread::Builder::new()
            .name("seam-attempt".to_owned())
            .spawn(move || block_on(task))
            .is_ok()
    }

    /// Push one frame into the channel the way the socket reader would.
    /// The harness does this. A connector dialer returns false: its read
    /// loop owns the sender.
    fn inject(&self, id: SocketId, frame: Vec<u8>) -> bool {
        let _ = (id, frame);
        false
    }

    /// The hub recorded a cause. Drop the harness sender so the pump's
    /// read returns. Does not join: the strand may be inside this call.
    fn reader_stopped(&self, id: SocketId) {
        let _ = id;
    }

    /// The executor dropped the link. Join the harness threads.
    fn retired(&self, id: SocketId) {
        let _ = id;
    }

    /// Run the inbound pump of `id`, a session the hub adopted: post each
    /// frame and finish the row when the reader stops. The dialer chooses
    /// where pumps run, in both directions. Zone bind runs each as a task
    /// on the transport runtime; the harness runs a thread it joins from
    /// [`Self::retired`].
    fn drive(&self, hub: &Hub, id: SocketId, session: Session);
}

/// Unpark the polling thread when the task can make progress.
struct Unpark(Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Poll `task` on this thread until it resolves, parking between polls.
fn block_on(mut task: AttemptTask) {
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    while task.as_mut().poll(&mut cx) == Poll::Pending {
        std::thread::park();
    }
}
