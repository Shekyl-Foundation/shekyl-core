// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The seam's recording host.
//!
//! Until zone bind, the socket is [`shekyl_clearnet::listen`] with the
//! option off: the public listener, not the connector's tests. The bytes
//! on that session are what the seam delivers to the Levin handler. This
//! host does not link epee and does not open a second admission table.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use shekyl_clearnet::{listen, ClearnetOption, Config, Listener, Session};
use shekyl_levin::{
    response, BucketReader, HandshakeRequest, PortableMap, Received, COMMAND_HANDSHAKE,
    DEFAULT_MAX_PACKET_SIZE,
};
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::{runtime, RuntimeBudget, ThreadName, ThreadStart};
use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
use shekyl_transport_layer::{CloseCause, CloseKind, ConnectorId, Sockets};

use crate::script::{
    script, AfterHandshake, Script, READ_PAUSE, SEND_OVER_SETTLE, SEND_QUEUE_BYTES,
};
use crate::transcript::{End, Event, Role, Transcript, TranscriptVersion};
use crate::Error;

const HOST_ACCEPT_WAIT: Duration = Duration::from_secs(8);
const HOST_READ_WAIT: Duration = Duration::from_secs(8);
const HOST_SHUTDOWN: Duration = Duration::from_millis(50);
const HOST_ACCEPT_BACKOFF: Duration = Duration::from_millis(1);
const HOST_HANDSHAKE_NS: u64 = 5_000_000_000;
const HOST_WORKERS: usize = 2;
const HOST_BLOCKING: usize = 1;
const HOST_INBOUND_CEILING: u32 = 4;

/// One connection, then the host stops.
pub struct SeamHost {
    addr: SocketAddr,
    done: JoinHandle<Result<Transcript, Error>>,
}

impl SeamHost {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn finish(self) -> Result<Transcript, Error> {
        self.done
            .join()
            .map_err(|_| Error::new("seam host thread"))?
    }
}

/// Bind on loopback and serve one seeded handshake.
pub fn serve_seam_once(seed: u64) -> Result<SeamHost, Error> {
    let plan = script(seed)?;
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(
        RuntimeBudget {
            workers: nonzero(HOST_WORKERS)?,
            blocking: nonzero(HOST_BLOCKING)?,
        },
        &ThreadName::new("p2p-harness").map_err(|err| Error::new(err.to_string()))?,
        ThreadStart::none(),
    )?;
    let on_cause: Arc<dyn Fn(CloseCause) + Send + Sync> = Arc::new(|_| {});
    let mut listener = listen(
        pool,
        &engine.handle(),
        Sockets::new(),
        &Config {
            listen: SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
            option: ClearnetOption::Off,
            column: ConnectorId::Clearnet.column(),
            network_id: [0x11; 16],
            ceiling: InboundCeiling::Bounded(HOST_INBOUND_CEILING),
            handshake_within: Tick::new(HOST_HANDSHAKE_NS),
            shutdown_timeout: HOST_SHUTDOWN,
            send_queue_bytes: SEND_QUEUE_BYTES,
            accept_backoff: HOST_ACCEPT_BACKOFF,
            on_cause,
        },
    )?;
    let addr = listener.local_addr();
    let done = std::thread::spawn(move || {
        let result = serve(&mut listener, seed, &plan);
        listener.shutdown();
        drop(engine);
        result
    });
    Ok(SeamHost { addr, done })
}

fn serve(
    listener: &mut Listener<MonotonicClock>,
    seed: u64,
    plan: &Script,
) -> Result<Transcript, Error> {
    let handle = listener.runtime_handle().clone();
    let mut session = handle.block_on(async {
        tokio::time::timeout(HOST_ACCEPT_WAIT, listener.sessions.recv())
            .await
            .map_err(|_| Error::new("seam host timed out"))?
            .ok_or_else(|| Error::new("seam host session closed"))
    })?;
    let mut reader = BucketReader::new();
    let mut delivered = Vec::new();
    let mut sent = Vec::new();
    let mut events = Vec::new();
    let mut end = End::Closed;
    let mut raised = false;
    loop {
        let framed = match read_one(&handle, &mut session, &mut reader, &mut delivered) {
            Read::Message(framed) => framed,
            Read::Closed => break,
            Read::Failed(err) => return Err(err),
        };
        if plan.version() == TranscriptVersion::V2 {
            events.push(Event::Read(framed.bytes.clone()));
        }
        match answer(&framed.received, &plan.invoke_reply) {
            Answer::Handshake(bytes) => {
                session
                    .try_send(bytes.clone())
                    .map_err(|_| Error::new("send refused"))?;
                sent.extend_from_slice(&bytes);
                if plan.version() == TranscriptVersion::V2 {
                    events.push(Event::Wrote(bytes));
                }
                end = End::Established;
                if !raised {
                    reader.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
                    raised = true;
                }
                apply_after(&mut session, plan, &mut sent, &mut events)?;
            }
            Answer::EmptyInvoke(bytes) => {
                session
                    .try_send(bytes.clone())
                    .map_err(|_| Error::new("send refused"))?;
                sent.extend_from_slice(&bytes);
                if end != End::Established {
                    end = End::Refused;
                }
            }
            Answer::Notify => {
                if end != End::Established {
                    end = End::Refused;
                }
            }
        }
    }
    if sent.is_empty() {
        end = End::Closed;
    }
    Ok(Transcript {
        version: plan.version(),
        seed,
        role: Role::Host,
        sent,
        recv: delivered,
        end,
        events,
    })
}

fn apply_after(
    session: &mut Session,
    plan: &Script,
    sent: &mut Vec<u8>,
    events: &mut Vec<Event>,
) -> Result<(), Error> {
    match plan.after {
        AfterHandshake::None => Ok(()),
        AfterHandshake::Follow => {
            let follow = plan
                .follow_bytes()
                .ok_or_else(|| Error::new("follow plan without bytes"))?;
            session
                .try_send(follow.clone())
                .map_err(|_| Error::new("send refused"))?;
            sent.extend_from_slice(&follow);
            Ok(())
        }
        AfterHandshake::SendOver => {
            std::thread::sleep(SEND_OVER_SETTLE);
            let over = vec![0u8; SEND_QUEUE_BYTES + 1];
            match session.try_send(over) {
                Err(CloseKind::SendQueueFull) => Ok(()),
                Ok(()) => Err(Error::new("oversize send was accepted")),
                Err(kind) => Err(Error::new(format!("oversize send: {kind:?}"))),
            }
        }
        AfterHandshake::Pause => {
            if plan.version() == TranscriptVersion::V2 {
                events.push(Event::Stalled);
            }
            std::thread::sleep(READ_PAUSE);
            if plan.version() == TranscriptVersion::V2 {
                events.push(Event::Resumed);
            }
            Ok(())
        }
    }
}

enum Read {
    Message(Framed),
    Closed,
    Failed(Error),
}

struct Framed {
    received: Received,
    bytes: Vec<u8>,
}

enum Answer {
    Handshake(Vec<u8>),
    EmptyInvoke(Vec<u8>),
    Notify,
}

fn read_one(
    handle: &tokio::runtime::Handle,
    session: &mut Session,
    reader: &mut BucketReader,
    raw: &mut Vec<u8>,
) -> Read {
    let start = raw.len();
    loop {
        match reader.next_message() {
            Ok(Some(received)) => {
                return Read::Message(Framed {
                    received,
                    bytes: raw[start..].to_vec(),
                })
            }
            Ok(None) => {}
            Err(err) => return Read::Failed(Error::from(err)),
        }
        let waited: Result<Option<Vec<u8>>, tokio::time::error::Elapsed> =
            handle.block_on(async { tokio::time::timeout(HOST_READ_WAIT, session.recv()).await });
        match waited {
            Err(_) => return Read::Failed(Error::new("seam host read timed out")),
            Ok(None) => return Read::Closed,
            Ok(Some(chunk)) => {
                raw.extend_from_slice(&chunk);
                if let Err(err) = reader.feed(&chunk) {
                    return Read::Failed(Error::from(err));
                }
            }
        }
    }
}

fn answer(received: &Received, invoke_reply: &[u8]) -> Answer {
    match received {
        Received::Request { command, payload }
            if *command == COMMAND_HANDSHAKE && HandshakeRequest::load(payload).is_ok() =>
        {
            Answer::Handshake(invoke_reply.to_vec())
        }
        Received::Request { command, .. } => Answer::EmptyInvoke(response(*command, &[])),
        Received::Notification { .. } | Received::Response { .. } => Answer::Notify,
    }
}

fn nonzero(n: usize) -> Result<NonZeroUsize, Error> {
    NonZeroUsize::new(n).ok_or_else(|| Error::new("zero workers"))
}
