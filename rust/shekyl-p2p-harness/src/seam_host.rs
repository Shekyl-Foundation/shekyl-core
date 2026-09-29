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
use shekyl_levin::{BucketReader, HandshakeRequest, PortableMap, Received, COMMAND_HANDSHAKE};
use shekyl_peer_policy::InboundCeiling;
use shekyl_runtime::{runtime, RuntimeBudget, ThreadName};
use shekyl_timing_engine::{EngineService, MonotonicClock, Tick};
use shekyl_transport_layer::{CloseCause, ConnectorId, Sockets};

use crate::handshake::handshake;
use crate::transcript::{End, Role, Transcript};
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
    let script = handshake(seed)?;
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
            // One handshake bucket. Not the measured session limit.
            send_queue_bytes: 64 * 1024,
            accept_backoff: Duration::from_millis(1),
            on_cause,
        },
    )?;
    let addr = listener.local_addr();
    let done = std::thread::spawn(move || {
        let result = serve(&mut listener, seed, &script.response);
        listener.shutdown();
        drop(engine);
        result
    });
    Ok(SeamHost { addr, done })
}

fn serve(
    listener: &mut Listener<MonotonicClock>,
    seed: u64,
    response: &[u8],
) -> Result<Transcript, Error> {
    let handle = listener.runtime_handle().clone();
    let mut session = handle.block_on(async {
        tokio::time::timeout(Duration::from_secs(3), listener.sessions.recv())
            .await
            .map_err(|_| Error::new("seam host timed out"))?
            .ok_or_else(|| Error::new("seam host session closed"))
    })?;
    let delivered = read_message(&handle, &mut session)?;
    let end = if handshake_request(&delivered) {
        session
            .try_send(response.to_vec())
            .map_err(|_| Error::new("send refused"))?;
        // Stay up until the peer has read the response and closed.
        // Shutting the pool first drops the bytes still in the send queue.
        match handle
            .block_on(async { tokio::time::timeout(Duration::from_secs(3), session.recv()).await })
        {
            Ok(_) | Err(_) => {}
        }
        End::Established
    } else {
        End::Refused
    };
    Ok(Transcript {
        seed,
        role: Role::Host,
        sent: if end == End::Established {
            response.to_vec()
        } else {
            Vec::new()
        },
        recv: delivered,
        end,
    })
}

fn read_message(handle: &tokio::runtime::Handle, session: &mut Session) -> Result<Vec<u8>, Error> {
    let mut reader = BucketReader::new();
    let mut raw = Vec::new();
    loop {
        if reader.next_message()?.is_some() {
            return Ok(raw);
        }
        let waited: Result<Option<Vec<u8>>, tokio::time::error::Elapsed> = handle
            .block_on(async { tokio::time::timeout(Duration::from_secs(3), session.recv()).await });
        let chunk = waited
            .map_err(|_| Error::new("seam host read timed out"))?
            .ok_or_else(|| Error::new("seam host read closed"))?;
        raw.extend_from_slice(&chunk);
        reader.feed(&chunk)?;
    }
}

fn handshake_request(bytes: &[u8]) -> bool {
    let mut reader = BucketReader::new();
    if reader.feed(bytes).is_err() {
        return false;
    }
    match reader.next_message() {
        Ok(Some(Received::Request { command, payload })) => {
            command == COMMAND_HANDSHAKE && HandshakeRequest::load(&payload).is_ok()
        }
        _ => false,
    }
}

fn nonzero(n: usize) -> Result<NonZeroUsize, Error> {
    NonZeroUsize::new(n).ok_or_else(|| Error::new("zero workers"))
}
