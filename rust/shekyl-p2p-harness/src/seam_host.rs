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
use shekyl_runtime::{runtime, RuntimeBudget, ThreadName};
use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
use shekyl_transport_layer::{CloseCause, ConnectorId, Sockets};

use crate::script::{script, Script, SEND_QUEUE_BYTES};
use crate::transcript::{End, Event, Role, Transcript};
use crate::Error;

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
    let script = script(seed)?;
    let engine = EngineService::start(MonotonicClock::new());
    let pool = runtime(
        RuntimeBudget {
            workers: nonzero(2)?,
            blocking: nonzero(1)?,
        },
        &ThreadName::new("p2p-harness").map_err(|err| Error::new(err.to_string()))?,
    )?;
    let on_cause: Arc<dyn Fn(CloseCause) + Send + Sync> = Arc::new(|_| {});
    let mut listener = listen(
        pool,
        &engine.handle(),
        Sockets::new(),
        Config {
            listen: SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
            option: ClearnetOption::Off,
            column: ConnectorId::Clearnet.column(),
            network_id: [0x11; 16],
            ceiling: InboundCeiling::Bounded(4),
            handshake_within: Tick::new(5_000_000_000),
            shutdown_timeout: Duration::from_millis(50),
            // One handshake bucket, and the cap seed 32 steps one byte past.
            send_queue_bytes: SEND_QUEUE_BYTES,
            accept_backoff: Duration::from_millis(1),
            on_cause,
        },
    )?;
    let addr = listener.local_addr();
    let done = std::thread::spawn(move || {
        let result = serve(&mut listener, seed, &script);
        listener.shutdown();
        drop(engine);
        result
    });
    Ok(SeamHost { addr, done })
}

fn serve(
    listener: &mut Listener<MonotonicClock>,
    seed: u64,
    script: &Script,
) -> Result<Transcript, Error> {
    let handle = listener.runtime_handle().clone();
    let mut session = handle.block_on(async {
        tokio::time::timeout(Duration::from_secs(8), listener.sessions.recv())
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
        let message = match read_one(&handle, &mut session, &mut reader, &mut delivered) {
            Read::Message(bytes) => bytes,
            Read::Closed => break,
            Read::Failed(err) => return Err(err),
        };
        if script.version == 2 {
            events.push(Event::Read(message.clone()));
        }
        match answer(&message, &handshake_response(script)) {
            Answer::Handshake(bytes) => {
                session
                    .try_send(bytes.clone())
                    .map_err(|_| Error::new("send refused"))?;
                sent.extend_from_slice(&bytes);
                if script.version == 2 {
                    events.push(Event::Wrote(bytes));
                }
                end = End::Established;
                if !raised {
                    reader.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
                    raised = true;
                }
                if let Some(follow) = &script.follow {
                    session
                        .try_send(follow.clone())
                        .map_err(|_| Error::new("send refused"))?;
                    sent.extend_from_slice(follow);
                }
                if script.send_over_cap {
                    // Let the handshake response leave before the cap refusal closes the queue.
                    std::thread::sleep(Duration::from_millis(50));
                    let over = vec![0u8; SEND_QUEUE_BYTES + 1];
                    match session.try_send(over) {
                        Ok(()) | Err(_) => {}
                    }
                }
                if script.pause_after_handshake {
                    if script.version == 2 {
                        events.push(Event::Stalled);
                    }
                    std::thread::sleep(crate::script::READ_PAUSE);
                    if script.version == 2 {
                        events.push(Event::Resumed);
                    }
                }
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
    if delivered.is_empty() && sent.is_empty() {
        end = End::Closed;
    } else if sent.is_empty() && end != End::Established {
        end = if handshake_started(&delivered) {
            End::Closed
        } else {
            End::Refused
        };
    }
    Ok(Transcript {
        version: script.version,
        seed,
        role: Role::Host,
        sent,
        recv: delivered,
        end,
        events,
    })
}

enum Read {
    Message(Vec<u8>),
    Closed,
    Failed(Error),
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
            Ok(Some(_)) => return Read::Message(raw[start..].to_vec()),
            Ok(None) => {}
            Err(err) => return Read::Failed(Error::from(err)),
        }
        let waited: Result<Option<Vec<u8>>, tokio::time::error::Elapsed> = handle
            .block_on(async { tokio::time::timeout(Duration::from_secs(8), session.recv()).await });
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

fn handshake_response(script: &Script) -> Vec<u8> {
    if let Some(follow) = &script.follow {
        if script.expected_recv.ends_with(follow.as_slice()) {
            return script.expected_recv[..script.expected_recv.len() - follow.len()].to_vec();
        }
    }
    script.expected_recv.clone()
}

fn answer(message: &[u8], handshake_response: &[u8]) -> Answer {
    let mut reader = BucketReader::new();
    if reader.feed(message).is_err() {
        return Answer::Notify;
    }
    match reader.next_message() {
        Ok(Some(Received::Request { command, payload }))
            if command == COMMAND_HANDSHAKE && HandshakeRequest::load(&payload).is_ok() =>
        {
            Answer::Handshake(handshake_response.to_vec())
        }
        Ok(Some(Received::Request { command, .. })) => Answer::EmptyInvoke(response(command, &[])),
        _ => Answer::Notify,
    }
}

fn handshake_started(bytes: &[u8]) -> bool {
    !bytes.is_empty()
}

fn nonzero(n: usize) -> Result<NonZeroUsize, Error> {
    NonZeroUsize::new(n).ok_or_else(|| Error::new("zero workers"))
}
