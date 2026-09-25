// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Clearnet network pipe. It owns one TCP socket and speaks the prefix, the
//! Noise handshake, and the record layer.
//!
//! Levin, stem, and fluff sit above this pipe. They write and read plaintext
//! bytes and do not branch on which network carried them. An overlay (Tor,
//! I2P) is a different pipe with the same plaintext contract, not a second
//! copy of the session.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::channel::{RecvHalf, SendHalf};
use crate::noise::{HandshakeError, Initiator, Responder, MESSAGE1_LEN, MESSAGE2_LEN};
use crate::prefix::{prefix_for, NetworkId, PREFIX_LEN};
use crate::{INITIATOR_FLIGHT_LEN, RESPONDER_FLIGHT_LEN};

/// How long one handshake flight may take. A peer that cannot finish is closed.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);

/// Plaintext bytes queued ahead of the socket. One session bucket, matching
/// `shekyl_levin::DEFAULT_MAX_PACKET_SIZE`. The pipe does not parse Levin;
/// it refuses to hold more than the session is already allowed to send.
pub const PIPE_PLAINTEXT_BUDGET: usize = 100_000_000;

/// Plaintext records posted to the session and not yet released.
const SESSION_READ_WINDOW: usize = 4;

const READ_CHUNK: usize = 4096;

pub type PlainCallback = extern "C" fn(*mut std::ffi::c_void, *const u8, usize) -> i32;
pub type ClosedCallback = extern "C" fn(*mut std::ffi::c_void);
pub type ReadyCallback = extern "C" fn(*mut std::ffi::c_void);
/// `direction` is 0 for bytes read and 1 for bytes written. The return value
/// is how many milliseconds to wait before the next socket operation.
pub type WireCallback = extern "C" fn(*mut std::ffi::c_void, i32, usize) -> i32;

/// Callbacks the session installs. They may run only after [`Pipe::start`].
#[derive(Clone, Copy)]
pub struct PipeHooks {
    pub on_plain: PlainCallback,
    pub on_closed: ClosedCallback,
    pub on_ready: ReadyCallback,
    pub on_wire: WireCallback,
}

#[derive(Debug)]
pub enum PipeError {
    Io,
    Prefix,
    Handshake,
    Timeout,
    Record,
    Full,
    Closed,
    Spawn,
}

pub(crate) fn fits_plaintext_budget(queued: usize, incoming: usize) -> bool {
    incoming > 0
        && queued
            .checked_add(incoming)
            .is_some_and(|total| total <= PIPE_PLAINTEXT_BUDGET)
}

struct Outbound {
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    closed: bool,
}

struct ReadWindow {
    in_flight: usize,
}

struct Shared {
    stop: AtomicBool,
    outbound: Mutex<Outbound>,
    outbound_cv: Condvar,
    window: Mutex<ReadWindow>,
    window_cv: Condvar,
}

struct Gate {
    go: Mutex<bool>,
    cv: Condvar,
}

impl Gate {
    fn new() -> Self {
        Self {
            go: Mutex::new(false),
            cv: Condvar::new(),
        }
    }

    fn wait(&self, stop: &AtomicBool) -> bool {
        let mut go = lock(&self.go);
        while !*go && !stop.load(Ordering::Acquire) {
            go = self.cv.wait(go).unwrap_or_else(|err| err.into_inner());
        }
        *go && !stop.load(Ordering::Acquire)
    }

    fn open(&self) {
        *lock(&self.go) = true;
        self.cv.notify_all();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

/// A running clearnet pipe. `attach` returns before the handshake; `start`
/// lets the owner threads touch the socket. Callbacks do not run before `start`.
pub struct Pipe {
    shared: Arc<Shared>,
    gate: Arc<Gate>,
    stream: Arc<TcpStream>,
    reader: Mutex<Option<JoinHandle<()>>>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl Pipe {
    pub fn attach(
        stream: TcpStream,
        network_id: &NetworkId,
        initiator: bool,
        hooks: PipeHooks,
        ctx: *mut std::ffi::c_void,
    ) -> Result<Arc<Self>, PipeError> {
        stream.set_nonblocking(false).map_err(|_| PipeError::Io)?;
        // One descriptor. `Read`/`Write` exist for `&TcpStream`, so the
        // reader and the writer share this `Arc` instead of cloned fds.
        let stream = Arc::new(stream);
        let reader_stream = Arc::clone(&stream);
        let writer_stream = Arc::clone(&stream);
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            outbound: Mutex::new(Outbound {
                queue: VecDeque::new(),
                bytes: 0,
                closed: false,
            }),
            outbound_cv: Condvar::new(),
            window: Mutex::new(ReadWindow { in_flight: 0 }),
            window_cv: Condvar::new(),
        });
        let gate = Arc::new(Gate::new());
        let (keys_tx, keys_rx) = std::sync::mpsc::channel();
        let ctx_bits = ctx as usize;
        let nid = *network_id;

        let shared_r = Arc::clone(&shared);
        let gate_r = Arc::clone(&gate);
        let reader = std::thread::Builder::new()
            .name("sk-pipe-rd".to_string())
            .spawn(move || {
                read_loop(
                    reader_stream,
                    nid,
                    initiator,
                    shared_r,
                    gate_r,
                    keys_tx,
                    Session {
                        hooks,
                        ctx: ctx_bits,
                    },
                );
            })
            .map_err(|_| PipeError::Spawn)?;

        let shared_w = Arc::clone(&shared);
        let writer = match std::thread::Builder::new()
            .name("sk-pipe-wr".to_string())
            .spawn(move || {
                write_loop(
                    writer_stream,
                    shared_w,
                    keys_rx,
                    Session {
                        hooks,
                        ctx: ctx_bits,
                    },
                );
            }) {
            Ok(handle) => handle,
            Err(_) => {
                shared.stop.store(true, Ordering::Release);
                gate.open();
                let _ = reader.join();
                return Err(PipeError::Spawn);
            }
        };

        Ok(Arc::new(Self {
            shared,
            gate,
            stream,
            reader: Mutex::new(Some(reader)),
            writer: Mutex::new(Some(writer)),
        }))
    }

    /// Let the owner threads begin. The handshake, `on_ready`, wire
    /// accounting, and plaintext callbacks all happen after this returns.
    pub fn start(&self) {
        self.gate.open();
    }

    pub fn write(&self, plaintext: &[u8]) -> Result<(), PipeError> {
        if plaintext.is_empty() {
            return Ok(());
        }
        if plaintext.len() > PIPE_PLAINTEXT_BUDGET {
            return Err(PipeError::Full);
        }
        let owned = plaintext.to_vec();
        let mut queue = lock(&self.shared.outbound);
        if queue.closed || self.shared.stop.load(Ordering::Acquire) {
            return Err(PipeError::Closed);
        }
        if !fits_plaintext_budget(queue.bytes, owned.len()) {
            return Err(PipeError::Full);
        }
        queue.bytes += owned.len();
        queue.queue.push_back(owned);
        self.shared.outbound_cv.notify_one();
        Ok(())
    }

    pub fn read_done(&self) {
        let mut window = lock(&self.shared.window);
        window.in_flight = window.in_flight.saturating_sub(1);
        self.shared.window_cv.notify_one();
    }

    pub fn shutdown(&self) {
        self.shared.stop.store(true, Ordering::Release);
        {
            let mut queue = lock(&self.shared.outbound);
            queue.closed = true;
        }
        self.shared.outbound_cv.notify_all();
        self.shared.window_cv.notify_all();
        self.gate.open();
        let _ = self.stream.shutdown(Shutdown::Both);
        join_unless_self(&self.writer);
        join_unless_self(&self.reader);
    }
}

/// Joining the calling thread panics and aborts the process from `extern "C"`.
/// Drop detaches that handle; the caller is already that thread and will exit.
fn join_unless_self(slot: &Mutex<Option<JoinHandle<()>>>) {
    let Some(handle) = lock(slot).take() else {
        return;
    };
    if handle.thread().id() == std::thread::current().id() {
        return;
    }
    let _ = handle.join();
}

impl Drop for Pipe {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Clone, Copy)]
struct Session {
    hooks: PipeHooks,
    ctx: usize,
}

fn read_loop(
    stream: Arc<TcpStream>,
    network_id: NetworkId,
    initiator: bool,
    shared: Arc<Shared>,
    gate: Arc<Gate>,
    keys_tx: std::sync::mpsc::Sender<SendHalf>,
    session: Session,
) {
    if !gate.wait(&shared.stop) {
        return;
    }
    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    let (send, mut recv) = match handshake(
        &stream,
        &network_id,
        initiator,
        deadline,
        &mut |direction, n| note_wire(&session, direction, n),
    ) {
        Ok(halves) => halves,
        Err(_) => {
            report_closed(&shared, session.hooks.on_closed, session.ctx);
            return;
        }
    };
    if shared.stop.load(Ordering::Acquire) {
        return;
    }
    (session.hooks.on_ready)(session.ctx as *mut std::ffi::c_void);
    if keys_tx.send(send).is_err() {
        report_closed(&shared, session.hooks.on_closed, session.ctx);
        return;
    }
    let mut inbound = Vec::new();
    loop {
        if shared.stop.load(Ordering::Acquire) || !wait_window(&shared) {
            break;
        }
        match pull_record(&mut recv, &stream, &mut inbound, |n| {
            note_wire(&session, 0, n);
        }) {
            Ok(plain) => {
                if !deliver(&shared, session.hooks.on_plain, session.ctx, &plain) {
                    report_closed(&shared, session.hooks.on_closed, session.ctx);
                    shared.stop.store(true, Ordering::Release);
                    break;
                }
            }
            Err(_) => {
                report_closed(&shared, session.hooks.on_closed, session.ctx);
                break;
            }
        }
    }
}

fn write_loop(
    stream: Arc<TcpStream>,
    shared: Arc<Shared>,
    keys_rx: std::sync::mpsc::Receiver<SendHalf>,
    session: Session,
) {
    let Ok(mut send) = keys_rx.recv() else {
        return;
    };
    loop {
        let plain = {
            let mut queue = lock(&shared.outbound);
            while queue.queue.is_empty() && !queue.closed && !shared.stop.load(Ordering::Acquire) {
                queue = shared
                    .outbound_cv
                    .wait(queue)
                    .unwrap_or_else(|err| err.into_inner());
            }
            if queue.queue.is_empty() {
                break;
            }
            let plain = queue.queue.pop_front().expect("queue is non-empty");
            queue.bytes -= plain.len();
            plain
        };
        if shared.stop.load(Ordering::Acquire) {
            break;
        }
        let wire = match send.seal(&plain) {
            Ok(wire) => wire,
            Err(_) => {
                let _ = stream.shutdown(Shutdown::Both);
                break;
            }
        };
        if wire.is_empty() {
            continue;
        }
        if (&*stream).write_all(&wire).is_err() {
            let _ = stream.shutdown(Shutdown::Both);
            break;
        }
        note_wire(&session, 1, wire.len());
    }
}

fn note_wire(session: &Session, direction: i32, n: usize) {
    if n == 0 {
        return;
    }
    let pause = (session.hooks.on_wire)(session.ctx as *mut std::ffi::c_void, direction, n);
    if pause > 0 {
        std::thread::sleep(Duration::from_millis(u64::from(
            pause.clamp(0, 1_000) as u32
        )));
    }
}

fn report_closed(shared: &Shared, on_closed: ClosedCallback, ctx_bits: usize) {
    if !shared.stop.load(Ordering::Acquire) {
        on_closed(ctx_bits as *mut std::ffi::c_void);
    }
}

fn wait_window(shared: &Shared) -> bool {
    let mut window = lock(&shared.window);
    while window.in_flight >= SESSION_READ_WINDOW && !shared.stop.load(Ordering::Acquire) {
        window = shared
            .window_cv
            .wait(window)
            .unwrap_or_else(|err| err.into_inner());
    }
    !shared.stop.load(Ordering::Acquire)
}

fn deliver(shared: &Shared, on_plain: PlainCallback, ctx_bits: usize, plain: &[u8]) -> bool {
    lock(&shared.window).in_flight += 1;
    let rc = on_plain(
        ctx_bits as *mut std::ffi::c_void,
        plain.as_ptr(),
        plain.len(),
    );
    if rc != 0 {
        // A nonzero return means the session did not take the buffer.
        // The reader stops; the caller reports closed once.
        let mut window = lock(&shared.window);
        window.in_flight = window.in_flight.saturating_sub(1);
        shared.window_cv.notify_all();
        return false;
    }
    true
}

fn pull_record(
    recv: &mut RecvHalf,
    stream: &TcpStream,
    inbound: &mut Vec<u8>,
    mut on_read: impl FnMut(usize),
) -> Result<Vec<u8>, PipeError> {
    let mut tmp = [0u8; READ_CHUNK];
    loop {
        match recv.open_one(inbound) {
            Ok((plain, used)) => {
                inbound.drain(..used);
                return Ok(plain);
            }
            Err(crate::channel::RecordError::Truncated) => {
                let mut io = stream;
                let n = io.read(&mut tmp).map_err(|_| PipeError::Io)?;
                if n == 0 {
                    return Err(PipeError::Io);
                }
                on_read(n);
                inbound.extend_from_slice(&tmp[..n]);
            }
            Err(_) => return Err(PipeError::Record),
        }
    }
}

pub(crate) fn handshake(
    stream: &TcpStream,
    network_id: &NetworkId,
    initiator: bool,
    deadline: Instant,
    on_io: &mut dyn FnMut(i32, usize),
) -> Result<(SendHalf, RecvHalf), PipeError> {
    let halves = if initiator {
        let (ini, msg1) = Initiator::new(network_id).map_err(handshake_io)?;
        let mut flight = Vec::with_capacity(INITIATOR_FLIGHT_LEN);
        flight.extend_from_slice(&prefix_for(network_id));
        flight.extend_from_slice(&msg1);
        write_all_deadline(stream, &flight, deadline, on_io)?;
        read_prefix(stream, network_id, deadline, on_io)?;
        let mut msg2 = vec![0u8; MESSAGE2_LEN];
        read_exact(stream, &mut msg2, deadline, on_io)?;
        ini.read_message2(&msg2).map_err(handshake_io)?.split()
    } else {
        read_prefix(stream, network_id, deadline, on_io)?;
        let mut msg1 = vec![0u8; MESSAGE1_LEN];
        read_exact(stream, &mut msg1, deadline, on_io)?;
        let ready = Responder::new(network_id)
            .read_message1(&msg1)
            .map_err(handshake_io)?;
        let (established, msg2) = ready.write_message2().map_err(handshake_io)?;
        let mut flight = Vec::with_capacity(RESPONDER_FLIGHT_LEN);
        flight.extend_from_slice(&prefix_for(network_id));
        flight.extend_from_slice(&msg2);
        write_all_deadline(stream, &flight, deadline, on_io)?;
        established.split()
    };
    stream.set_read_timeout(None).map_err(|_| PipeError::Io)?;
    stream.set_write_timeout(None).map_err(|_| PipeError::Io)?;
    Ok(halves)
}

fn handshake_io(err: HandshakeError) -> PipeError {
    match err {
        HandshakeError::Decrypt
        | HandshakeError::Kem
        | HandshakeError::Length
        | HandshakeError::State => PipeError::Handshake,
    }
}

fn read_prefix(
    stream: &TcpStream,
    network_id: &NetworkId,
    deadline: Instant,
    on_io: &mut dyn FnMut(i32, usize),
) -> Result<(), PipeError> {
    let mut got = [0u8; PREFIX_LEN];
    read_exact(stream, &mut got, deadline, on_io)?;
    if got != prefix_for(network_id) {
        return Err(PipeError::Prefix);
    }
    Ok(())
}

fn read_exact(
    stream: &TcpStream,
    buf: &mut [u8],
    deadline: Instant,
    on_io: &mut dyn FnMut(i32, usize),
) -> Result<(), PipeError> {
    let mut filled = 0;
    while filled < buf.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(PipeError::Timeout);
        }
        stream
            .set_read_timeout(Some(left))
            .map_err(|_| PipeError::Io)?;
        let mut io = stream;
        match io.read(&mut buf[filled..]) {
            Ok(0) => return Err(PipeError::Io),
            Ok(n) => {
                on_io(0, n);
                filled += n;
            }
            Err(err)
                if err.kind() == ErrorKind::TimedOut || err.kind() == ErrorKind::WouldBlock =>
            {
                return Err(PipeError::Timeout);
            }
            Err(_) => return Err(PipeError::Io),
        }
    }
    Ok(())
}

fn write_all_deadline(
    stream: &TcpStream,
    bytes: &[u8],
    deadline: Instant,
    on_io: &mut dyn FnMut(i32, usize),
) -> Result<(), PipeError> {
    let mut sent = 0;
    while sent < bytes.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(PipeError::Timeout);
        }
        stream
            .set_write_timeout(Some(left))
            .map_err(|_| PipeError::Io)?;
        let mut io = stream;
        match io.write(&bytes[sent..]) {
            Ok(0) => return Err(PipeError::Io),
            Ok(n) => {
                on_io(1, n);
                sent += n;
            }
            Err(err)
                if err.kind() == ErrorKind::TimedOut || err.kind() == ErrorKind::WouldBlock =>
            {
                return Err(PipeError::Timeout);
            }
            Err(_) => return Err(PipeError::Io),
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(unsafe_code)] // the extern callbacks receive the sink as a raw context
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    #[test]
    fn plaintext_budget_is_one_session_bucket() {
        assert_eq!(
            PIPE_PLAINTEXT_BUDGET,
            usize::try_from(shekyl_levin::DEFAULT_MAX_PACKET_SIZE).unwrap()
        );
        assert!(fits_plaintext_budget(0, 1));
        assert!(fits_plaintext_budget(0, PIPE_PLAINTEXT_BUDGET));
        assert!(!fits_plaintext_budget(0, 0));
        assert!(!fits_plaintext_budget(1, PIPE_PLAINTEXT_BUDGET));
        assert!(!fits_plaintext_budget(0, PIPE_PLAINTEXT_BUDGET + 1));
    }

    #[test]
    fn wrong_prefix_fails_before_the_noise_message() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let dialer = std::thread::spawn(move || TcpStream::connect(("127.0.0.1", port)).unwrap());
        let (server, _) = listener.accept().unwrap();
        let mut client = dialer.join().unwrap();
        client.write_all(&[0xff; PREFIX_LEN]).unwrap();
        client.shutdown(Shutdown::Both).unwrap();
        assert!(matches!(
            handshake(
                &server,
                &[0x11; 16],
                false,
                Instant::now() + Duration::from_secs(2),
                &mut |_, _| {},
            ),
            Err(PipeError::Prefix)
        ));
    }

    struct Sink {
        got: Mutex<Vec<u8>>,
        cv: Condvar,
        closed: AtomicBool,
    }

    extern "C" fn on_plain(ctx: *mut std::ffi::c_void, data: *const u8, len: usize) -> i32 {
        let sink = unsafe { &*(ctx as *const Sink) };
        let bytes = unsafe { std::slice::from_raw_parts(data, len) };
        lock(&sink.got).extend_from_slice(bytes);
        sink.cv.notify_one();
        0
    }

    extern "C" fn on_closed(ctx: *mut std::ffi::c_void) {
        let sink = unsafe { &*(ctx as *const Sink) };
        sink.closed.store(true, Ordering::Release);
        sink.cv.notify_one();
    }

    extern "C" fn on_ready(_: *mut std::ffi::c_void) {}

    extern "C" fn on_wire(_: *mut std::ffi::c_void, _: i32, _: usize) -> i32 {
        0
    }

    fn hooks() -> PipeHooks {
        PipeHooks {
            on_plain,
            on_closed,
            on_ready,
            on_wire,
        }
    }

    #[test]
    fn loopback_delivers_plaintext_after_the_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = channel();
        let dialer = std::thread::spawn(move || {
            let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let sink = Sink {
                got: Mutex::new(Vec::new()),
                cv: Condvar::new(),
                closed: AtomicBool::new(false),
            };
            let pipe = Pipe::attach(
                stream,
                &[0x55; 16],
                true,
                hooks(),
                &sink as *const Sink as *mut std::ffi::c_void,
            )
            .unwrap();
            pipe.start();
            ready_tx.send(()).unwrap();
            pipe.write(b"COMMAND_HANDSHAKE-shaped-bytes").unwrap();
            let mut got = lock(&sink.got);
            let deadline = Instant::now() + Duration::from_secs(5);
            while got.is_empty() && Instant::now() < deadline {
                let (guard, _) = sink
                    .cv
                    .wait_timeout(got, Duration::from_millis(50))
                    .unwrap();
                got = guard;
            }
            let echoed = got.clone();
            drop(got);
            pipe.shutdown();
            echoed
        });
        let (stream, _) = listener.accept().unwrap();
        let sink = Sink {
            got: Mutex::new(Vec::new()),
            cv: Condvar::new(),
            closed: AtomicBool::new(false),
        };
        let pipe = Pipe::attach(
            stream,
            &[0x55; 16],
            false,
            hooks(),
            &sink as *const Sink as *mut std::ffi::c_void,
        )
        .unwrap();
        pipe.start();
        ready_rx.recv().unwrap();
        let mut got = lock(&sink.got);
        let deadline = Instant::now() + Duration::from_secs(5);
        while got.is_empty() && Instant::now() < deadline {
            let (guard, _) = sink
                .cv
                .wait_timeout(got, Duration::from_millis(50))
                .unwrap();
            got = guard;
        }
        let received = got.clone();
        drop(got);
        pipe.write(&received).unwrap();
        let echoed = dialer.join().unwrap();
        pipe.shutdown();
        assert_eq!(received, b"COMMAND_HANDSHAKE-shaped-bytes");
        assert_eq!(echoed, b"COMMAND_HANDSHAKE-shaped-bytes");
    }

    #[cfg(target_os = "linux")]
    fn descriptor_count() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn one_descriptor_per_connection() {
        let before = descriptor_count();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (pipe_tx, pipe_rx) = channel();
        let (done_tx, done_rx) = channel();
        let dialer = std::thread::spawn(move || {
            let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let sink = Sink {
                got: Mutex::new(Vec::new()),
                cv: Condvar::new(),
                closed: AtomicBool::new(false),
            };
            let pipe = Pipe::attach(
                stream,
                &[0x56; 16],
                true,
                hooks(),
                &sink as *const Sink as *mut _,
            )
            .unwrap();
            pipe.start();
            pipe_tx.send(pipe).unwrap();
            let _ = done_rx.recv();
        });
        let (stream, _) = listener.accept().unwrap();
        drop(listener);
        let sink = Sink {
            got: Mutex::new(Vec::new()),
            cv: Condvar::new(),
            closed: AtomicBool::new(false),
        };
        let pipe = Pipe::attach(
            stream,
            &[0x56; 16],
            false,
            hooks(),
            &sink as *const Sink as *mut _,
        )
        .unwrap();
        pipe.start();
        let remote = pipe_rx.recv().unwrap();
        assert_eq!(descriptor_count(), before + 2);
        remote.shutdown();
        pipe.shutdown();
        let _ = done_tx.send(());
        let _ = dialer.join();
    }

    struct Kill {
        pipe: Mutex<Option<Arc<Pipe>>>,
        plains: std::sync::atomic::AtomicUsize,
        closed: AtomicBool,
        cv: Condvar,
    }

    extern "C" fn kill_from_plain(ctx: *mut std::ffi::c_void, _: *const u8, _: usize) -> i32 {
        let kill = unsafe { &*(ctx as *const Kill) };
        kill.plains
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        if let Some(pipe) = lock(&kill.pipe).clone() {
            pipe.shutdown();
        }
        0
    }

    extern "C" fn kill_from_closed(ctx: *mut std::ffi::c_void) {
        let kill = unsafe { &*(ctx as *const Kill) };
        if let Some(pipe) = lock(&kill.pipe).clone() {
            pipe.shutdown();
        }
        kill.closed.store(true, Ordering::Release);
        kill.cv.notify_one();
    }

    #[test]
    fn shutdown_from_the_reader_does_not_abort() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let dialer = std::thread::spawn(move || {
            let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let sink = Sink {
                got: Mutex::new(Vec::new()),
                cv: Condvar::new(),
                closed: AtomicBool::new(false),
            };
            let pipe = Pipe::attach(
                stream,
                &[0x57; 16],
                true,
                hooks(),
                &sink as *const Sink as *mut _,
            )
            .unwrap();
            pipe.start();
            pipe.write(b"stop-on-plain").unwrap();
            std::thread::sleep(Duration::from_millis(200));
            pipe.shutdown();
        });
        let (stream, _) = listener.accept().unwrap();
        let kill = Kill {
            pipe: Mutex::new(None),
            plains: std::sync::atomic::AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            cv: Condvar::new(),
        };
        let pipe = Pipe::attach(
            stream,
            &[0x57; 16],
            false,
            PipeHooks {
                on_plain: kill_from_plain,
                on_closed: kill_from_closed,
                on_ready,
                on_wire,
            },
            &kill as *const Kill as *mut _,
        )
        .unwrap();
        *lock(&kill.pipe) = Some(Arc::clone(&pipe));
        pipe.start();
        let deadline = Instant::now() + Duration::from_secs(3);
        while kill.plains.load(std::sync::atomic::Ordering::Acquire) == 0
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(kill.plains.load(std::sync::atomic::Ordering::Acquire) >= 1);
        pipe.shutdown();
        dialer.join().unwrap();
    }

    extern "C" fn refuse_plain(ctx: *mut std::ffi::c_void, _: *const u8, _: usize) -> i32 {
        let kill = unsafe { &*(ctx as *const Kill) };
        kill.plains
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        1
    }

    extern "C" fn note_closed(ctx: *mut std::ffi::c_void) {
        let kill = unsafe { &*(ctx as *const Kill) };
        kill.closed.store(true, Ordering::Release);
        kill.cv.notify_one();
    }

    #[test]
    fn nonzero_plain_closes_the_reader() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let dialer = std::thread::spawn(move || {
            let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let sink = Sink {
                got: Mutex::new(Vec::new()),
                cv: Condvar::new(),
                closed: AtomicBool::new(false),
            };
            let pipe = Pipe::attach(
                stream,
                &[0x58; 16],
                true,
                hooks(),
                &sink as *const Sink as *mut _,
            )
            .unwrap();
            pipe.start();
            pipe.write(b"first").unwrap();
            std::thread::sleep(Duration::from_millis(150));
            let _ = pipe.write(b"second");
            std::thread::sleep(Duration::from_millis(150));
            pipe.shutdown();
        });
        let (stream, _) = listener.accept().unwrap();
        let kill = Kill {
            pipe: Mutex::new(None),
            plains: std::sync::atomic::AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            cv: Condvar::new(),
        };
        let pipe = Pipe::attach(
            stream,
            &[0x58; 16],
            false,
            PipeHooks {
                on_plain: refuse_plain,
                on_closed: note_closed,
                on_ready,
                on_wire,
            },
            &kill as *const Kill as *mut _,
        )
        .unwrap();
        pipe.start();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !kill.closed.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(kill.closed.load(Ordering::Acquire));
        assert_eq!(kill.plains.load(std::sync::atomic::Ordering::Acquire), 1);
        pipe.shutdown();
        dialer.join().unwrap();
    }
}
