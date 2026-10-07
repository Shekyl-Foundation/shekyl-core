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
//!
//! [`Listener::dial`] checks the addressing cell and then opens an
//! outbound socket. A proxy is SOCKS5 CONNECT (`shekyl-socks`). The
//! initiator handshake uses the same engine owner as the responder.
//! The outbound cap and the socket copy are [`shekyl_capped_stream`].
//! This connector passes the seam as the frame functions.

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use shekyl_net_address::NetworkAddress;
use shekyl_p2p_transport::NetworkId;
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::Pool;
use shekyl_timing_engine::{Clock, Handle, Tick};
use shekyl_transport_layer::{
    stack_plan, AddedLayer, CloseCause, NetworkColumn, Sockets, StackPlan,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

mod drive;
mod handshake;
mod inode;
mod seam;

#[cfg(unix)]
pub use inode::socket_descriptors;
pub use seam::ChannelChoice;
pub use shekyl_capped_stream::Session;

pub use drive::{
    accept_inbound, accept_one, dial_one, zero_tally, Accept, Admitted, Dial, Inbound,
};
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

/// The listener. Drop shuts the pool down with the caller's timeout.
/// Call [`shutdown`](Self::shutdown) from outside a task.
pub struct Listener<C: Clock + Clone> {
    pool: Option<Pool>,
    handle: tokio::runtime::Handle,
    shutdown_timeout: Duration,
    local: SocketAddr,
    pub sessions: mpsc::UnboundedReceiver<Session>,
    pub tally: Arc<HandshakeTally>,
    engine: Handle<C>,
    sockets: Sockets,
    kind: Choice,
    network_id: NetworkId,
    handshake_within: Tick,
    send_queue_bytes: usize,
    on_cause: Arc<dyn Fn(CloseCause) + Send + Sync>,
    admitted_tx: mpsc::UnboundedSender<Admitted>,
}

impl<C: Clock + Clone> Listener<C> {
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

impl<C> Listener<C>
where
    C: Clock + Clone + Send + Sync + 'static,
{
    /// Dial `address`. `proxy` is a SOCKS5 endpoint. `None` connects directly.
    ///
    /// The addressing cell is checked first. A name this connector does not
    /// dial is [`CloseKind::LocalClose`] and opens nothing. A SOCKS refusal
    /// is [`CloseCause::proxy_refused`] with the reply byte.
    pub fn dial(&self, address: NetworkAddress, proxy: Option<SocketAddr>) {
        let dial = drive::Dial {
            address,
            proxy,
            sockets: self.sockets.clone(),
            kind: self.kind,
            network_id: self.network_id,
            dial_within: self.handshake_within,
            proxied_dial_within: self.handshake_within,
            handshake_within: self.handshake_within,
            gap_within: None,
            tally: Arc::clone(&self.tally),
            on_cause: Arc::clone(&self.on_cause),
            send_queue_bytes: self.send_queue_bytes,
            admitted: self.admitted_tx.clone(),
        };
        let engine = self.engine.clone();
        self.handle.spawn(drive::dial_one(dial, engine));
    }
}

impl<C: Clock + Clone> Drop for Listener<C> {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.shutdown(self.shutdown_timeout);
        }
    }
}

/// Bind on `pool` and accept. `pool` was built with [`shekyl_runtime::runtime`].
///
/// `sockets` is the process-wide admission table. Clones share it. This
/// function does not mint a table: the seam and every connector count the
/// same sockets.
pub fn listen<C>(
    pool: Pool,
    engine: &Handle<C>,
    sockets: Sockets,
    config: &Config,
) -> std::io::Result<Listener<C>>
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
    let (sessions_tx, sessions_rx) = mpsc::unbounded_channel();
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel::<Admitted>();
    pool.spawn(async move {
        while let Some(admitted) = admitted_rx.recv().await {
            // The task holds the other clone and closes it when the socket ends.
            drop(admitted.open);
            drop(admitted.gap);
            if sessions_tx.send(admitted.session).is_err() {
                break;
            }
        }
    });
    let engine_dial = engine.clone();
    let sockets_dial = sockets.clone();
    let admitted_dial = admitted_tx.clone();
    let on_cause = Arc::clone(&config.on_cause);
    let network_id = config.network_id;
    let handshake_within = config.handshake_within;
    let send_queue_bytes = config.send_queue_bytes;
    let shutdown_timeout = config.shutdown_timeout;
    let ceiling = config.ceiling;
    let inbound = Inbound {
        sockets,
        ceiling: move || ceiling,
        kind,
        network_id,
        handshake_within,
        gap_within: None,
        tally: Arc::clone(&tally),
        on_cause: Arc::clone(&config.on_cause),
        send_queue_bytes,
        admitted: admitted_tx,
        backoff: config.accept_backoff,
    };
    let engine = engine.clone();
    pool.spawn(async move {
        accept_inbound(listener, inbound, engine).await;
    });
    Ok(Listener {
        pool: Some(pool),
        handle,
        shutdown_timeout,
        local,
        sessions: sessions_rx,
        tally,
        engine: engine_dial,
        sockets: sockets_dial,
        kind,
        network_id,
        handshake_within,
        send_queue_bytes,
        on_cause,
        admitted_tx: admitted_dial,
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpStream as StdStream};
    use std::num::NonZeroUsize;
    #[cfg(target_os = "linux")]
    use std::os::unix::io::AsRawFd;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use shekyl_net_address::NetworkAddress;
    use shekyl_p2p_transport::{prefix_for, Initiator, MESSAGE2_LEN, PREFIX_LEN};
    use shekyl_peer_policy::InboundCeiling;
    use shekyl_runtime::{runtime, RuntimeBudget, ThreadName};
    use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
    use shekyl_transport_layer::{CloseCause, CloseKind, ConnectorId, NetworkColumn, Sockets};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    #[cfg(target_os = "linux")]
    use super::inode::socket_descriptors;
    use super::{channel_choice, listen, ChannelChoice, ClearnetOption, Config, Listener};

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
        Listener<MonotonicClock>,
        Arc<Mutex<Vec<CloseKind>>>,
    ) {
        let engine = EngineService::start(MonotonicClock::new());
        let pool = runtime(harness_budget(), &name("sk-clearnet")).expect("runtime");
        let recorded = causes();
        let seen = Arc::clone(&recorded.seen);
        let listener = listen(
            pool,
            &engine.handle(),
            Sockets::new(),
            &config(option, within, ceiling, recorded.sink),
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
    }

    #[cfg(target_os = "linux")]
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
    fn a_zero_ceiling_refuses_before_any_handshake() {
        let (engine, listener, seen) = start(
            ClearnetOption::Off,
            Tick::new(5_000_000_000),
            InboundCeiling::Bounded(0),
        );
        let mut client = connect(listener.local_addr());
        client.write_all(b"handshake").expect("write");
        let mut buf = [0u8; 4];
        let n = client.read(&mut buf).expect("read");
        assert_eq!(n, 0);
        let start = Instant::now();
        while !seen
            .lock()
            .expect("causes")
            .contains(&CloseKind::InboundNotAccepted)
        {
            assert!(start.elapsed() < Duration::from_secs(2), "refused");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(listener.tally.queued(), 0);
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

    #[test]
    fn a_direct_dial_carries_plaintext_when_the_option_is_off() {
        let (engine, mut listener, _) = start(
            ClearnetOption::Off,
            Tick::new(5_000_000_000),
            InboundCeiling::Bounded(4),
        );
        let handle = listener.runtime_handle().clone();
        let (port, got) = handle.block_on(async {
            let server = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind");
            let port = server.local_addr().expect("addr").port();
            let got = tokio::spawn(async move {
                let (mut sock, _) = server.accept().await.expect("accept");
                let mut buf = [0u8; 3];
                use tokio::io::AsyncReadExt;
                sock.read_exact(&mut buf).await.expect("read");
                buf
            });
            (port, got)
        });
        listener.dial(
            NetworkAddress::Ipv4 {
                ip: Ipv4Addr::LOCALHOST,
                port,
            },
            None,
        );
        let session = handle.block_on(next_session(&mut listener.sessions));
        session.try_send(b"out".to_vec()).expect("send");
        assert_eq!(handle.block_on(got).expect("peer"), *b"out");
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn an_onion_name_is_not_dialed() {
        let (engine, listener, seen) = start(
            ClearnetOption::Off,
            Tick::new(5_000_000_000),
            InboundCeiling::Bounded(4),
        );
        listener.dial(
            NetworkAddress::Tor {
                host: "not-an-address.onion".to_string(),
                port: 18080,
            },
            None,
        );
        let start = Instant::now();
        while !seen
            .lock()
            .expect("causes")
            .contains(&CloseKind::LocalClose)
        {
            assert!(start.elapsed() < Duration::from_secs(2), "dial");
            std::thread::sleep(Duration::from_millis(5));
        }
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn a_refused_direct_connect_names_the_address() {
        let (engine, listener, seen) = start(
            ClearnetOption::Off,
            Tick::new(5_000_000_000),
            InboundCeiling::Bounded(4),
        );
        let handle = listener.runtime_handle().clone();
        let port = handle.block_on(async {
            let server = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind");
            let port = server.local_addr().expect("addr").port();
            drop(server);
            port
        });
        listener.dial(
            NetworkAddress::Ipv4 {
                ip: Ipv4Addr::LOCALHOST,
                port,
            },
            None,
        );
        let start_at = Instant::now();
        while !seen
            .lock()
            .expect("causes")
            .contains(&CloseKind::DialFailed)
        {
            assert!(start_at.elapsed() < Duration::from_secs(2), "refused");
            std::thread::sleep(Duration::from_millis(5));
        }
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn an_unreachable_network_stays_dialable() {
        let (engine, listener, seen) = start(
            ClearnetOption::Off,
            Tick::new(2_000_000_000),
            InboundCeiling::Bounded(4),
        );
        listener.dial(
            NetworkAddress::Ipv4 {
                ip: Ipv4Addr::new(255, 255, 255, 255),
                port: 9,
            },
            None,
        );
        let start_at = Instant::now();
        while !seen
            .lock()
            .expect("causes")
            .contains(&CloseKind::LocalClose)
        {
            assert!(start_at.elapsed() < Duration::from_secs(3), "unreachable");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !seen
                .lock()
                .expect("causes")
                .contains(&CloseKind::DialFailed),
            "an unreachable network is this node's link"
        );
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn option_on_dials_and_both_sides_read_what_was_sent() {
        let within = Tick::new(5_000_000_000);
        let (engine_a, mut responder, _) =
            start(ClearnetOption::On, within, InboundCeiling::Bounded(4));
        let (engine_b, mut initiator, _) =
            start(ClearnetOption::On, within, InboundCeiling::Bounded(4));
        let port = responder.local_addr().port();
        initiator.dial(
            NetworkAddress::Ipv4 {
                ip: Ipv4Addr::LOCALHOST,
                port,
            },
            None,
        );
        let handle_a = responder.runtime_handle().clone();
        let handle_b = initiator.runtime_handle().clone();
        let mut from_responder = handle_a.block_on(next_session(&mut responder.sessions));
        let mut from_initiator = handle_b.block_on(next_session(&mut initiator.sessions));
        from_initiator.try_send(b"ping".to_vec()).expect("ping");
        let got = handle_a.block_on(from_responder.recv()).expect("ping");
        assert_eq!(got, b"ping");
        from_responder.try_send(b"pong".to_vec()).expect("pong");
        let got = handle_b.block_on(from_initiator.recv()).expect("pong");
        assert_eq!(got, b"pong");
        responder.shutdown();
        initiator.shutdown();
        drop((engine_a, engine_b));
    }

    #[test]
    fn a_socks_proxy_is_the_path_and_a_refusal_keeps_the_reply() {
        let (engine, mut listener, _) = start(
            ClearnetOption::Off,
            Tick::new(5_000_000_000),
            InboundCeiling::Bounded(4),
        );
        let handle = listener.runtime_handle().clone();
        let (proxy_port, dest_port, got) = handle.block_on(async {
            let dest = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("dest");
            let dest_port = dest.local_addr().expect("addr").port();
            let proxy = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("proxy");
            let proxy_port = proxy.local_addr().expect("addr").port();
            let got = tokio::spawn(async move {
                let (mut sock, _) = dest.accept().await.expect("accept");
                let mut buf = [0u8; 3];
                use tokio::io::AsyncReadExt;
                sock.read_exact(&mut buf).await.expect("read");
                buf
            });
            tokio::spawn(async move {
                let (mut sock, _) = proxy.accept().await.expect("proxy accept");
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut greeting = [0u8; 3];
                sock.read_exact(&mut greeting).await.expect("greet");
                sock.write_all(&[0x05, 0x00]).await.expect("method");
                let mut head = [0u8; 4];
                sock.read_exact(&mut head).await.expect("head");
                let mut addr = [0u8; 6];
                sock.read_exact(&mut addr).await.expect("addr");
                let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                let port = u16::from_be_bytes([addr[4], addr[5]]);
                let mut upstream = TcpStream::connect(SocketAddr::from((ip, port)))
                    .await
                    .expect("upstream");
                sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("reply");
                match tokio::io::copy_bidirectional(&mut sock, &mut upstream).await {
                    Ok(_) | Err(_) => {}
                }
            });
            (proxy_port, dest_port, got)
        });
        listener.dial(
            NetworkAddress::Ipv4 {
                ip: Ipv4Addr::LOCALHOST,
                port: dest_port,
            },
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy_port))),
        );
        let session = handle.block_on(next_session(&mut listener.sessions));
        session.try_send(b"out".to_vec()).expect("send");
        assert_eq!(handle.block_on(got).expect("peer"), *b"out");
        listener.shutdown();
        drop(engine);
    }

    #[test]
    fn a_socks_refusal_carries_the_reply_byte() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let sink: Arc<dyn Fn(CloseCause) + Send + Sync> = Arc::new(move |cause| {
            record.lock().expect("causes").push(cause);
        });
        let engine = EngineService::start(MonotonicClock::new());
        let pool = runtime(harness_budget(), &name("sk-clearnet")).expect("runtime");
        let listener = listen(
            pool,
            &engine.handle(),
            Sockets::new(),
            &config(
                ClearnetOption::Off,
                Tick::new(5_000_000_000),
                InboundCeiling::Bounded(4),
                sink,
            ),
        )
        .expect("listen");
        let handle = listener.runtime_handle().clone();
        let proxy_port = handle.block_on(async {
            let proxy = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("proxy");
            let port = proxy.local_addr().expect("addr").port();
            tokio::spawn(async move {
                let (mut sock, _) = proxy.accept().await.expect("accept");
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut greeting = [0u8; 3];
                sock.read_exact(&mut greeting).await.expect("greet");
                sock.write_all(&[0x05, 0x00]).await.expect("method");
                let mut head = [0u8; 4];
                sock.read_exact(&mut head).await.expect("head");
                let mut addr = [0u8; 6];
                sock.read_exact(&mut addr).await.expect("addr");
                sock.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("reply");
            });
            port
        });
        listener.dial(
            NetworkAddress::Ipv4 {
                ip: Ipv4Addr::LOCALHOST,
                port: 9,
            },
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, proxy_port))),
        );
        let start = Instant::now();
        let cause = loop {
            if let Some(cause) = seen
                .lock()
                .expect("causes")
                .iter()
                .copied()
                .find(|cause| cause.kind() == CloseKind::ProxyRefused)
            {
                break cause;
            }
            assert!(start.elapsed() < Duration::from_secs(2), "refusal");
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(cause.reply_code(), 0x05);
        listener.shutdown();
        drop(engine);
    }
}
