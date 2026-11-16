// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The client's handshake: messages 1 to 4 over any stream, and the dial
//! policy that bounds it.

use std::sync::Arc;

use rand_core::OsRng;
use shekyl_rpc_channel::handshake::{
    Client, StaticKeypair, StaticPublic, MESSAGE2_LEN, MESSAGE4_LEN,
};
use shekyl_rpc_channel::retry::{AttemptEnd, HandshakeFailure, HandshakeRetry, Next};
use shekyl_rpc_channel::{NetworkId, BUSY_LEN};
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_stream::RecordStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::leg::{Leg, LegStream};
use super::ChannelFault;

/// How one handshake attempt ended without a session.
#[derive(Debug)]
pub enum Attempt {
    /// The daemon's busy reply, in place of message 2.
    Busy,
    /// Closed after message 1 with nothing, or with fewer bytes than a
    /// message 2 that are not the busy reply.
    ClosedAfterMessage1,
    /// Message 2 did not authenticate the daemon.
    NotTheDaemon,
    /// Closed after message 3: the claim was refused.
    ClosedAfterMessage3,
    /// The stream failed before message 2 could be written or read.
    Io(String),
    /// This client could not build its messages.
    Local(String),
}

/// An opened channel: the record stream and the ceiling message 4 carried.
pub struct Opened<S> {
    /// The record stream, before anything is sent on it.
    pub stream: RecordStream<S>,
    /// This client's ceiling on the daemon.
    pub ceiling: GrantSet,
    /// What the connection holds: the request clamped to the ceiling (§6.2).
    pub granted: GrantSet,
}

/// One dial and handshake, classified for the retry loop. Busy and a
/// deadline are retried. Every other ending is reported.
enum Step {
    /// The handshake finished. Boxed: a record stream is far larger than a
    /// retry or a fault, and a step lives only until the loop matches it.
    Opened(Box<Opened<LegStream>>),
    /// Try again under [`HandshakeRetry`].
    Retry(AttemptEnd),
    /// Stop and report this fault.
    Stop(ChannelFault),
}

/// The client's side of the handshake over `io`, any stream: messages 1 to
/// 4, then the record stream. No deadline of its own; the caller bounds it.
///
/// # Errors
///
/// [`Attempt`]: how this attempt ended.
pub async fn handshake_over<S>(
    mut io: S,
    network_id: &NetworkId,
    key: &StaticKeypair,
    daemon: &StaticPublic,
    request: GrantSet,
) -> Result<Opened<S>, Attempt>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (client, message1) =
        Client::start(network_id, key, daemon).map_err(|e| Attempt::Local(e.to_string()))?;
    io.write_all(&message1)
        .await
        .map_err(|e| Attempt::Io(e.to_string()))?;
    let mut message2 = vec![0u8; MESSAGE2_LEN];
    let read = read_up_to(&mut io, &mut message2)
        .await
        .map_err(|e| Attempt::Io(e.to_string()))?;
    if read < MESSAGE2_LEN {
        if read == BUSY_LEN && client.is_busy(&message2[..BUSY_LEN]) {
            return Err(Attempt::Busy);
        }
        return Err(Attempt::ClosedAfterMessage1);
    }
    let client = client
        .read_message2(&message2)
        .map_err(|_| Attempt::NotTheDaemon)?;
    let (client, message3) = client
        .write_message3(&request.to_payload())
        .map_err(|e| Attempt::Local(e.to_string()))?;
    io.write_all(&message3)
        .await
        .map_err(|_| Attempt::ClosedAfterMessage3)?;
    let mut message4 = vec![0u8; MESSAGE4_LEN];
    if io.read_exact(&mut message4).await.is_err() {
        return Err(Attempt::ClosedAfterMessage3);
    }
    let (established, ceiling) = client
        .read_message4(&message4)
        .map_err(|_| Attempt::NotTheDaemon)?;
    let ceiling = GrantSet::from_payload(&ceiling).map_err(|_| Attempt::NotTheDaemon)?;
    let (send, recv) = established.into_directions();
    Ok(Opened {
        stream: RecordStream::new(io, send, recv),
        ceiling,
        granted: request.intersection(ceiling),
    })
}

/// Read until `buf` is full or the stream ends; how many bytes were read.
async fn read_up_to<S: AsyncRead + Unpin>(io: &mut S, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = io.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// What a finished [`Attempt`] asks of the caller: retry busy, and report
/// every other ending. `at` is the leg as the person named it.
fn step_of(attempt: Attempt, at: &str, fingerprint: [u8; 32]) -> Step {
    match attempt {
        Attempt::Busy => Step::Retry(AttemptEnd::Busy),
        Attempt::ClosedAfterMessage1 => {
            Step::Stop(ChannelFault::NotRecognised { at: at.to_owned() })
        }
        Attempt::NotTheDaemon => Step::Stop(ChannelFault::NotTheDaemon { at: at.to_owned() }),
        Attempt::ClosedAfterMessage3 => Step::Stop(ChannelFault::NotEnrolled { fingerprint }),
        Attempt::Io(cause) => Step::Stop(ChannelFault::Unreachable {
            at: at.to_owned(),
            cause,
        }),
        Attempt::Local(why) => Step::Stop(ChannelFault::Local(why)),
    }
}

/// A daemon's channel, and this client's key for it.
#[derive(Clone)]
pub struct ChannelTarget {
    network_id: NetworkId,
    daemon: StaticPublic,
    key: Arc<StaticKeypair>,
    leg: Leg,
}

impl ChannelTarget {
    /// The daemon of `network_id` whose public bundle is `daemon`, reached
    /// at `leg`, with this client's `key`.
    #[must_use]
    pub fn new(network_id: NetworkId, daemon: StaticPublic, key: StaticKeypair, leg: Leg) -> Self {
        Self {
            network_id,
            daemon,
            key: Arc::new(key),
            leg,
        }
    }

    /// Where the daemon is.
    #[must_use]
    pub fn leg(&self) -> &Leg {
        &self.leg
    }

    /// This client's fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        *self.key.public().fingerprint().as_bytes()
    }

    /// Dial and run one handshake. A dial fault stops. A handshake fault is
    /// classified by [`step_of`].
    async fn one_attempt(&self, request: GrantSet) -> Step {
        let at = self.leg.to_string();
        let io = match self.leg.dial().await {
            Ok(io) => io,
            Err(fault) => return Step::Stop(fault),
        };
        match handshake_over(io, &self.network_id, &self.key, &self.daemon, request).await {
            Ok(opened) => Step::Opened(Box::new(opened)),
            Err(attempt) => step_of(attempt, &at, self.fingerprint()),
        }
    }

    /// Dial and run the handshake under §4.3's policy: each attempt within
    /// the handshake deadline, one silent retry after a timeout, and a
    /// jittered back-off after a busy reply until the deadline.
    ///
    /// # Errors
    ///
    /// [`ChannelFault`]: every way the channel can fail to open.
    pub async fn open(&self, request: GrantSet) -> Result<Opened<LegStream>, ChannelFault> {
        let mut retry = HandshakeRetry::new(std::time::Instant::now(), OsRng);
        loop {
            let deadline = tokio::time::Instant::from_std(retry.deadline_at());
            let step = match tokio::time::timeout_at(deadline, self.one_attempt(request)).await {
                Ok(step) => step,
                Err(_elapsed) => Step::Retry(AttemptEnd::TimedOut),
            };
            match step {
                Step::Opened(opened) => return Ok(*opened),
                Step::Stop(fault) => return Err(fault),
                Step::Retry(end) => match retry.after(end, std::time::Instant::now()) {
                    Next::StartAt(at) => tokio::time::sleep_until(at.into()).await,
                    Next::Report(HandshakeFailure::TimedOut) => return Err(ChannelFault::TimedOut),
                    Next::Report(HandshakeFailure::Busy) => return Err(ChannelFault::Busy),
                },
            }
        }
    }
}
