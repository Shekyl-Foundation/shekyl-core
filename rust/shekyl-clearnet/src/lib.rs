// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The clearnet connector.
//!
//! It is the first caller that keeps a [`shekyl_runtime::Pool`]. The worker
//! count, the blocking cap, the shutdown timeout, and the handshake span are
//! the caller's. This crate does not contain them. The daemon call site
//! labels each one unmeasured until a measurement names it.
//!
//! **The handshake queue is bounded by admission, not by Tokio.**
//! `spawn_blocking` queues without limit once the blocking cap is busy.
//! A handshake is queued only for a connection [`Sockets::accept_clearnet`]
//! has reserved, and that reservation stops at the inbound ceiling. The
//! queue cannot outgrow the connections already admitted. A length on the
//! Tokio queue would refuse a handshake the ceiling had admitted, or admit
//! one the ceiling had refused, so the queue is not given a length that
//! rejects. The same shape as the timing engine's mailbox: admission bounds
//! how many owners exist, and the queue does not apply a second cap.
//!
//! The handshake deadline is one [`OwnerClass::Transport`] owner per
//! connection. It is armed at accept, before the read and before the job
//! is queued, so time spent waiting for a blocking thread counts. The home
//! awaits that owner's wake. When the job is dequeued it checks whether
//! the wake has already been delivered, and skips the handshake if it has.
//! [`HandshakeTally`] counts those skips against the handshakes that were
//! computed. D10's flood test reads that pair.
//!
//! Before the flip, ruling 4's exception is still in force. The option off
//! omits the Noise layer the declaration adds, and the socket bytes are the
//! session bytes, which is what the differential harness compares with
//! epee. The option on follows [`stack_plan`]. Neither arm matches on a
//! network's identity.

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use shekyl_p2p_transport::NetworkId;
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::Pool;
use shekyl_timing_engine::{Clock, Handle, Tick};
use shekyl_transport_layer::{
    stack_plan, AddedLayer, CloseCause, CloseKind, NetworkColumn, Sockets, StackPlan,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

mod drive;
mod inode;
mod seam;

pub use inode::socket_descriptors;
pub use seam::ChannelChoice;

use drive::{accept_one, zero_tally, Accept};
use seam::ChannelChoice as Choice;

/// How many responder handshakes the blocking pool computed, and how many
/// it skipped because the deadline had already fired.
pub struct HandshakeTally {
    pub(crate) computed: AtomicU64,
    pub(crate) skipped: AtomicU64,
    pub(crate) queued: AtomicU64,
}

impl HandshakeTally {
    pub fn computed(&self) -> u64 {
        self.computed.load(Ordering::Acquire)
    }

    pub fn skipped(&self) -> u64 {
        self.skipped.load(Ordering::Acquire)
    }

    /// Jobs submitted and not yet finished. Admission is what caps this.
    pub fn queued(&self) -> u64 {
        self.queued.load(Ordering::Acquire)
    }
}

/// Why [`channel_choice`] could not name a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChoiceError {
    /// The encryption cell is not assessed.
    NotUsable,
    /// The plan names a layer this connector does not build.
    LayerNotBuilt,
}

/// The option, until the flip deletes the off arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearnetOption {
    /// Ruling 4. The declaration's Noise layer is not added.
    Off,
    /// Follow the declaration's stack plan.
    On,
}

/// Plaintext or Noise, from the column's plan and the option.
///
/// Off omits whatever layer the plan adds. On builds that layer. The
/// column is an argument. The function does not match on a connector id.
pub fn channel_choice(
    column: NetworkColumn,
    option: ClearnetOption,
) -> Result<ChannelChoice, ChoiceError> {
    let layers = match stack_plan(column) {
        StackPlan::Ready { layers } => layers,
        StackPlan::NotUsable => return Err(ChoiceError::NotUsable),
    };
    // Off is ruling 4's exception. An empty plan is a network that already
    // encrypts. The bytes are the same; the reason is not.
    #[allow(clippy::match_same_arms)]
    match (option, layers) {
        (ClearnetOption::Off, _) => Ok(Choice::Plain),
        (ClearnetOption::On, []) => Ok(Choice::Plain),
        (ClearnetOption::On, [AddedLayer::Noise]) => Ok(Choice::Noise),
        (ClearnetOption::On, _) => Err(ChoiceError::LayerNotBuilt),
    }
}

/// What the caller supplies. None of the spans or the budget live here.
pub struct Config {
    pub listen: SocketAddr,
    pub option: ClearnetOption,
    pub column: NetworkColumn,
    pub network_id: NetworkId,
    pub ceiling: InboundCeiling,
    /// Nanoseconds from accept until the handshake deadline.
    pub handshake_within: Tick,
    /// Passed to [`Pool::shutdown`](shekyl_runtime::Pool::shutdown).
    pub shutdown_timeout: Duration,
    /// Bytes of session plaintext the writer will hold. PWD-T6's
    /// session-established limit plus measurement. Unmeasured until that
    /// derivation is a number. A send that does not fit closes with
    /// [`CloseKind::SendQueueFull`].
    pub send_queue_bytes: usize,
    /// Pause after a transient `accept` error, so the loop does not spin.
    /// Not a protocol deadline.
    pub accept_backoff: Duration,
    pub on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
}

/// One accepted connection's session bytes, above the seam.
pub(crate) struct Overfull {
    flag: AtomicBool,
    notify: tokio::sync::Notify,
}

impl Overfull {
    fn new() -> Self {
        Self {
            flag: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn trip(&self) {
        self.flag.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn tripped(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.tripped() {
                return;
            }
            notified.await;
        }
    }
}

pub struct Session {
    inbound: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::UnboundedSender<drive::Queued>,
    queue: drive::SendQueue,
    overfull: Arc<Overfull>,
}

impl Session {
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }

    /// Queue plaintext up to the connection's byte cap. A buffer that does
    /// not fit closes the connection. The cap is the caller's.
    pub fn try_send(&self, bytes: Vec<u8>) -> Result<(), CloseKind> {
        let queued = self.queue.try_enqueue(bytes).map_err(|()| {
            self.overfull.trip();
            CloseKind::SendQueueFull
        })?;
        self.outbound.send(queued).map_err(|_| CloseKind::IoError)
    }
}

/// The listener. Drop shuts the pool down with the caller's timeout.
/// Call [`shutdown`](Self::shutdown) from outside a task.
pub struct Listener {
    pool: Option<Pool>,
    handle: tokio::runtime::Handle,
    shutdown_timeout: Duration,
    local: SocketAddr,
    pub sessions: mpsc::UnboundedReceiver<Session>,
    pub tally: Arc<HandshakeTally>,
}

impl Listener {
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn pool(&self) -> &Pool {
        self.pool.as_ref().expect("pool still held")
    }

    /// The pool's handle. For `block_on` from outside a task.
    pub fn runtime_handle(&self) -> &tokio::runtime::Handle {
        &self.handle
    }

    /// [`Pool::shutdown`](shekyl_runtime::Pool::shutdown) with the timeout
    /// from [`Config`]. Not from inside a task.
    pub fn shutdown(mut self) {
        if let Some(pool) = self.pool.take() {
            pool.shutdown(self.shutdown_timeout);
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.shutdown(self.shutdown_timeout);
        }
    }
}

/// A transient `accept` failure. `EMFILE`, `ENFILE`, and `ECONNABORTED`
/// are what a flood produces. They are not the listener closing.
pub(crate) fn accept_error_is_transient(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    ) || too_many_open_files(err.raw_os_error())
}

fn too_many_open_files(code: Option<i32>) -> bool {
    let Some(code) = code else {
        return false;
    };
    #[cfg(unix)]
    {
        // EMFILE and ENFILE. Linux and the BSDs use these numbers.
        code == 24 || code == 23
    }
    #[cfg(windows)]
    {
        // ERROR_TOO_MANY_OPEN_FILES.
        code == 4
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = code;
        false
    }
}

/// Bind on `pool` and accept. `pool` was built with [`shekyl_runtime::runtime`].
pub fn listen<C>(pool: Pool, engine: &Handle<C>, config: Config) -> std::io::Result<Listener>
where
    C: Clock + Clone + Send + Sync + 'static,
{
    let kind = channel_choice(config.column, config.option).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "column is not usable")
    })?;
    let handle = pool.handle().clone();
    let listener = pool.block_on(TcpListener::bind(config.listen))?;
    let local = listener.local_addr()?;
    let tally = Arc::new(zero_tally());
    let sockets = Sockets::new();
    let (sessions_tx, sessions_rx) = mpsc::unbounded_channel();
    let engine = engine.clone();
    let tally_loop = Arc::clone(&tally);
    pool.spawn(async move {
        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(error) if accept_error_is_transient(&error) => {
                    (config.on_cause)(CloseCause::new(CloseKind::IoError));
                    tokio::time::sleep(config.accept_backoff).await;
                    continue;
                }
                Err(_) => break,
            };
            let accept = Accept {
                stream,
                sockets: sockets.clone(),
                ceiling: config.ceiling,
                kind,
                network_id: config.network_id,
                handshake_within: config.handshake_within,
                tally: Arc::clone(&tally_loop),
                sessions: sessions_tx.clone(),
                on_cause: Arc::clone(&config.on_cause),
                send_queue_bytes: config.send_queue_bytes,
            };
            let engine = engine.clone();
            tokio::spawn(accept_one(accept, engine));
        }
    });
    Ok(Listener {
        pool: Some(pool),
        handle,
        shutdown_timeout: config.shutdown_timeout,
        local,
        sessions: sessions_rx,
        tally,
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdStream};
    use std::num::NonZeroUsize;
    use std::os::unix::io::AsRawFd;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use shekyl_p2p_transport::{prefix_for, Initiator, MESSAGE2_LEN, PREFIX_LEN};
    use shekyl_peer_policy::InboundCeiling;
    use shekyl_runtime::{runtime, RuntimeBudget, ThreadName};
    use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
    use shekyl_transport_layer::{CloseCause, CloseKind, ConnectorId, NetworkColumn};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    use super::inode::socket_descriptors;
    use super::{
        channel_choice, listen, ChannelChoice, ChoiceError, ClearnetOption, Config, Listener,
    };

    const ID: [u8; 16] = [0x11; 16];

    fn nz(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("nonzero")
    }

    /// Harness inputs. Not the daemon's budget, span, or shutdown timeout.
    fn harness_budget() -> RuntimeBudget {
        RuntimeBudget {
            workers: nz(2),
            blocking: nz(1),
        }
    }

    fn name(text: &str) -> ThreadName {
        ThreadName::new(text).expect("name")
    }

    struct Recorded {
        sink: Arc<dyn Fn(CloseCause) + Send + Sync>,
        seen: Arc<Mutex<Vec<CloseKind>>>,
    }

    fn causes() -> Recorded {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let sink: Arc<dyn Fn(CloseCause) + Send + Sync> = Arc::new(move |cause: CloseCause| {
            record.lock().expect("causes").push(cause.kind());
        });
        Recorded { sink, seen }
    }

    fn config(
        option: ClearnetOption,
        within: Tick,
        ceiling: InboundCeiling,
        on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    ) -> Config {
        Config {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            option,
            column: ConnectorId::Clearnet.column(),
            network_id: ID,
            ceiling,
            handshake_within: within,
            shutdown_timeout: Duration::from_millis(50),
            // Harness inputs. Not PWD-T6's derived limit, and not a
            // measured accept pause.
            send_queue_bytes: 64,
            accept_backoff: Duration::from_millis(1),
            on_cause,
        }
    }

    fn start(
        option: ClearnetOption,
        within: Tick,
        ceiling: InboundCeiling,
    ) -> (
        EngineService<MonotonicClock>,
        Listener,
        Arc<Mutex<Vec<CloseKind>>>,
    ) {
        let engine = EngineService::start(MonotonicClock::new());
        let pool = runtime(harness_budget(), &name("sk-clearnet")).expect("runtime");
        let recorded = causes();
        let seen = Arc::clone(&recorded.seen);
        let listener = listen(
            pool,
            &engine.handle(),
            config(option, within, ceiling, recorded.sink),
        )
        .expect("listen");
        (engine, listener, seen)
    }

    fn connect(addr: SocketAddr) -> StdStream {
        let client = StdStream::connect(addr).expect("connect");
        client.set_read_timeout(Some(Duration::from_secs(3))).ok();
        client.set_write_timeout(Some(Duration::from_secs(3))).ok();
        client
    }

    async fn next_session(
        sessions: &mut mpsc::UnboundedReceiver<super::Session>,
    ) -> super::Session {
        tokio::time::timeout(Duration::from_secs(3), sessions.recv())
            .await
            .expect("session wait")
            .expect("session")
    }

    #[test]
    fn a_flood_of_accept_errors_is_transient() {
        let refused = std::io::Error::from_raw_os_error(24);
        assert!(super::accept_error_is_transient(&refused));
        let aborted = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "aborted");
        assert!(super::accept_error_is_transient(&aborted));
        let closed = std::io::Error::new(std::io::ErrorKind::NotConnected, "closed");
        assert!(!super::accept_error_is_transient(&closed));
    }

    #[test]
    fn the_send_queue_counts_bytes_and_holds_more_than_one_buffer() {
        let queue = super::drive::SendQueue::new(4);
        let first = queue.try_enqueue(b"ab".to_vec()).expect("first");
        let second = queue.try_enqueue(b"cd".to_vec()).expect("second");
        assert!(queue.try_enqueue(b"e".to_vec()).is_err());
        drop(first);
        assert!(queue.try_enqueue(b"ef".to_vec()).is_ok());
        drop(second);
    }

    #[test]
    fn the_option_reads_the_plan_and_not_a_connector_id() {
        assert_eq!(
            channel_choice(NetworkColumn::Clearnet, ClearnetOption::Off),
            Ok(ChannelChoice::Plain)
        );
        assert_eq!(
            channel_choice(NetworkColumn::Clearnet, ClearnetOption::On),
            Ok(ChannelChoice::Noise)
        );
        assert_eq!(
            channel_choice(NetworkColumn::Tor, ClearnetOption::On),
            Ok(ChannelChoice::Plain)
        );
        assert_eq!(
            channel_choice(NetworkColumn::I2p, ClearnetOption::On),
            Err(ChoiceError::NotUsable)
        );
    }

    #[test]
    fn one_descriptor_after_the_socket_is_split() {
        let engine = EngineService::start(MonotonicClock::new());
        let pool = runtime(harness_budget(), &name("sk-inode")).expect("runtime");
        pool.block_on(async move {
            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let client =
                tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });
            let (stream, _) = listener.accept().await.expect("accept");
            let fd = stream.as_raw_fd();
            assert_eq!(socket_descriptors(fd).expect("inode"), 1);
            let (read, write) = stream.into_split();
            assert_eq!(socket_descriptors(fd).expect("inode"), 1);
            drop((read, write, client));
        });
        drop(engine);
        pool.shutdown(Duration::from_millis(50));
    }

    #[test]
    fn option_off_carries_the_bytes_it_is_given() {
        let (engine, mut listener, _) = start(
            ClearnetOption::Off,
            Tick::new(5_000_000_000),
            InboundCeiling::Bounded(4),
        );
        let mut client = connect(listener.local_addr());
        client.write_all(b"levin-bytes").expect("write");
        let handle = listener.runtime_handle().clone();
        let mut session = handle.block_on(next_session(&mut listener.sessions));
        let got = handle.block_on(session.recv()).expect("bytes");
        assert_eq!(got, b"levin-bytes");
        session.try_send(b"out".to_vec()).expect("send");
        let mut buf = [0u8; 3];
        client.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, b"out");
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn a_bad_prefix_is_fin_after_zero_bytes() {
        let (engine, listener, seen) = start(
            ClearnetOption::On,
            Tick::new(5_000_000_000),
            InboundCeiling::Bounded(4),
        );
        let mut client = connect(listener.local_addr());
        client.write_all(&[0u8; PREFIX_LEN]).expect("write");
        let mut buf = [0u8; 8];
        let n = client.read(&mut buf).expect("read");
        assert_eq!(n, 0);
        let start = Instant::now();
        while !seen
            .lock()
            .expect("causes")
            .contains(&CloseKind::PrefixMismatch)
        {
            assert!(start.elapsed() < Duration::from_secs(2), "cause");
            std::thread::sleep(Duration::from_millis(5));
        }
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn option_on_seals_above_the_seam() {
        let (engine, mut listener, _) = start(
            ClearnetOption::On,
            Tick::new(5_000_000_000),
            InboundCeiling::Bounded(4),
        );
        let mut client = connect(listener.local_addr());
        let (initiator, message1) = Initiator::new(&ID).expect("initiator");
        client.write_all(&prefix_for(&ID)).expect("prefix");
        client.write_all(&message1).expect("message1");
        let mut prefix = [0u8; PREFIX_LEN];
        client.read_exact(&mut prefix).expect("prefix");
        assert_eq!(prefix, prefix_for(&ID));
        let mut message2 = vec![0u8; MESSAGE2_LEN];
        client.read_exact(&mut message2).expect("message2");
        let (mut send, _recv) = initiator
            .read_message2(&message2)
            .expect("message2")
            .split();
        let wire = send.seal(b"hello").expect("seal");
        client.write_all(&wire).expect("record");
        let handle = listener.runtime_handle().clone();
        let mut session = handle.block_on(next_session(&mut listener.sessions));
        let got = handle.block_on(session.recv()).expect("plain");
        assert_eq!(got, b"hello");
        assert_eq!(listener.tally.computed(), 1);
        assert_eq!(listener.tally.skipped(), 0);
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn a_queued_handshake_past_its_deadline_is_skipped() {
        let within = Tick::new(150_000_000);
        let (engine, listener, _) = start(ClearnetOption::On, within, InboundCeiling::Bounded(4));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        listener.pool().spawn_blocking(move || {
            held_tx.send(()).expect("held");
            if release_rx.recv().is_err() {}
        });
        held_rx.recv().expect("blocking thread held");
        let mut client = connect(listener.local_addr());
        let (_initiator, message1) = Initiator::new(&ID).expect("initiator");
        client.write_all(&prefix_for(&ID)).expect("prefix");
        client.write_all(&message1).expect("message1");
        let start = Instant::now();
        while listener.tally.queued() == 0 {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "job was not queued"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(400));
        release_tx.send(()).expect("release");
        let mut buf = [0u8; 8];
        let n = client.read(&mut buf).expect("read");
        assert_eq!(n, 0);
        let start = Instant::now();
        while listener.tally.skipped() == 0 {
            assert!(start.elapsed() < Duration::from_secs(2), "skip");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(listener.tally.computed(), 0);
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn the_second_inbound_past_the_ceiling_is_not_a_handshake() {
        let (engine, mut listener, seen) = start(
            ClearnetOption::Off,
            Tick::new(5_000_000_000),
            InboundCeiling::Bounded(1),
        );
        let mut first = connect(listener.local_addr());
        first.write_all(b"one").expect("write");
        let handle = listener.runtime_handle().clone();
        let _session = handle.block_on(next_session(&mut listener.sessions));
        let mut second = connect(listener.local_addr());
        second.write_all(b"two").expect("write");
        let mut buf = [0u8; 4];
        let n = second.read(&mut buf).expect("read");
        assert_eq!(n, 0);
        let start = Instant::now();
        while !seen
            .lock()
            .expect("causes")
            .contains(&CloseKind::AdmissionRefused)
        {
            assert!(start.elapsed() < Duration::from_secs(2), "refused");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(listener.tally.computed(), 0);
        assert_eq!(listener.tally.queued(), 0);
        listener.shutdown();
        drop(engine);
    }
}
