// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The seam's post sink (CS-3 §4.2): the Rust Levin router.
//!
//! The hub hands every [`Post`] to one sink, under its table lock, and the
//! sink must not call back into the hub. Without a sync owner attached the
//! router forwards every post unchanged, byte for byte, to the C++ handler:
//! that is the live daemon until the chain-sync cutover. Attaching an owner
//! is a decision made once, when the router is built, before any session
//! exists. A session that began unsplit has no known message boundary, so
//! splitting cannot start in the middle of one.
//!
//! With an owner attached, each session's delivered bytes are split into
//! Levin buckets by reading the 29-byte bucket header and nothing else.
//!
//! - **2011–2014** ([`SyncCommand`]) are admitted here, with their caps, and
//!   their payloads go to the owner whole. They are not added to the C++
//!   ingress.
//! - **2008, an announced block** (`NOTIFY_NEW_COMPACT_BLOCK`), is admitted
//!   here too, within its cap, and goes to the owner whole: announcements
//!   are chain sync's (CS-Q1). 2009, a peer asking for an announced block's
//!   missing transactions, stays the C++ handler's until the cutover.
//! - **The claim tap** (CS-Q10, Rick 2026-10-24): an inbound session's
//!   handshake request (1001) and either direction's timed sync (1002)
//!   carry the peer's sync payload, which the C++ handler also reads. Those
//!   buckets go to the C++ handler unchanged, and the owner gets a copy of
//!   the payload ([`Routed::Tap`]), within the command's cap, in the order
//!   the bytes arrived among the messages the owner keeps, including a
//!   payload of length zero. The router
//!   reads only the bucket header; the owner decodes the copy. Slice 4
//!   deletes the tap when the hub posts the inbound handshake's result.
//! - **Every other command**, and every other post, goes to the C++ handler
//!   unchanged. Its bytes are streamed through as they arrive, never
//!   buffered here, and the C++ ingress judges them as it does today.
//! - **One chunk in, at most one post out.** The bytes a chunk carries for
//!   the C++ handler are forwarded as one `Deliver`, so the handler calls
//!   `delivery_finished` once for it. A chunk that carries nothing for the
//!   handler is finished by the owner, from its own task, never from inside
//!   this sink, once the requests it carried are answered. A chunk that
//!   carries both is the handler's to finish, so its requests are bounded
//!   by the owner's serving queue instead (owner module docs).
//! - **A malformed bucket header is the transport's refusal, as today:**
//!   the session's bytes go to the C++ handler raw from there on, and its
//!   ingress refuses them.
//! - **The owner leaving** hands the session back as one byte stream. Bytes
//!   the split has accepted and not yet handed on go ahead of the next
//!   chunk, and the split is dropped. Framing does not resume in the middle
//!   of a bucket.
//!
//! [`Post::Established`] and [`Post::Closed`] go to the owner as well as
//! onward, and [`Post::HandshakeResult`] goes to the owner as a claim and
//! onward too, so the C++ handler keeps its own copy.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_levin::{
    BucketHead, DefinedCommand, Flags, SyncCommand, COMMAND_HANDSHAKE, COMMAND_TIMED_SYNC,
    FLAGS_DEFINED, HEADER_SIZE, NOTIFY_NEW_COMPACT_BLOCK,
};
use shekyl_seam::{ConnectorId, Post, SocketId, SyncPayload};
use tokio::sync::mpsc;

/// Where a post the router does not keep goes: the C++ handler's strand.
pub type Forward = Arc<dyn Fn(Post) + Send + Sync>;

/// What the router hands the sync owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Routed {
    /// A channel was adopted.
    Established {
        /// The session.
        id: SocketId,
        /// Its connector.
        connector: ConnectorId,
    },
    /// The outbound handshake's sync payload: the peer's claim.
    Claim {
        /// The session.
        id: SocketId,
        /// The payload's fields.
        sync: SyncPayload,
    },
    /// One whole chain-sync message.
    Message {
        /// The session.
        id: SocketId,
        /// Which command.
        command: SyncCommand,
        /// The payload, still encoded.
        payload: Vec<u8>,
    },
    /// An announced block (2008), still encoded.
    Announce {
        /// The session.
        id: SocketId,
        /// The payload.
        payload: Vec<u8>,
    },
    /// A copy of a C++-bound message that carries the peer's sync payload
    /// (module docs, the claim tap), still encoded.
    Tap {
        /// The session.
        id: SocketId,
        /// Which message.
        kind: Tapped,
        /// The payload, still encoded.
        payload: Vec<u8>,
    },
    /// A delivered chunk carried nothing for the C++ handler. The owner
    /// tells the hub the delivery is finished.
    Finished {
        /// The session.
        id: SocketId,
    },
    /// The session is gone.
    Closed {
        /// The session.
        id: SocketId,
    },
}

/// The router (module docs).
pub struct Router {
    forward: Forward,
    owner: Option<mpsc::UnboundedSender<Routed>>,
    splits: Mutex<HashMap<SocketId, Split>>,
}

impl Router {
    /// A router with no owner: every post goes to `forward` unchanged.
    #[must_use]
    pub fn pass_through(forward: Forward) -> Self {
        Self {
            forward,
            owner: None,
            splits: Mutex::new(HashMap::new()),
        }
    }

    /// A router that splits every session it sees established and routes
    /// 2011–2014 to `owner`. Build it before the first session exists.
    #[must_use]
    pub fn attached(forward: Forward, owner: mpsc::UnboundedSender<Routed>) -> Self {
        Self {
            forward,
            owner: Some(owner),
            splits: Mutex::new(HashMap::new()),
        }
    }

    /// This router as the hub's post sink.
    #[must_use]
    pub fn into_sink(self) -> Arc<dyn Fn(Post) + Send + Sync> {
        let router = Arc::new(self);
        Arc::new(move |post| router.post(post))
    }

    /// Handle one post (module docs). Never calls into the hub.
    pub fn post(&self, post: Post) {
        let Some(owner) = self.owner.as_ref().filter(|owner| !owner.is_closed()) else {
            self.forward_retired(post);
            return;
        };
        match post {
            Post::Established { id, endpoint } => {
                self.splits().insert(id, Split::default());
                (self.forward)(Post::Established { id, endpoint });
                let _gone = owner.send(Routed::Established {
                    id,
                    connector: endpoint.connector(),
                });
            }
            Post::HandshakeResult {
                id,
                connector,
                sync,
            } => {
                (self.forward)(Post::HandshakeResult {
                    id,
                    connector,
                    sync,
                });
                let _gone = owner.send(Routed::Claim { id, sync });
            }
            Post::Closed {
                id,
                connector,
                cause,
            } => {
                self.splits().remove(&id);
                (self.forward)(Post::Closed {
                    id,
                    connector,
                    cause,
                });
                let _gone = owner.send(Routed::Closed { id });
            }
            Post::Deliver {
                id,
                connector,
                bytes,
            } => {
                let fed = {
                    let mut splits = self.splits();
                    match splits.get_mut(&id) {
                        Some(split) => split.feed(&bytes),
                        None => {
                            drop(splits);
                            (self.forward)(Post::Deliver {
                                id,
                                connector,
                                bytes,
                            });
                            return;
                        }
                    }
                };
                let mut routed = fed
                    .taken
                    .into_iter()
                    .map(|taken| match taken {
                        Taken::Message(Admitted::Sync(command), payload) => Routed::Message {
                            id,
                            command,
                            payload,
                        },
                        Taken::Message(Admitted::Announce, payload) => {
                            Routed::Announce { id, payload }
                        }
                        Taken::Tap(kind, payload) => Routed::Tap { id, kind, payload },
                    })
                    .collect::<Vec<_>>();
                if fed.forward.is_empty() {
                    routed.push(Routed::Finished { id });
                }
                // A failed send means the owner is gone and every message
                // queued in this loop goes with it. The handler gets the
                // bytes still held, which include this chunk, and the split
                // ends so a later chunk is not cut against that stream.
                for item in routed {
                    if owner.send(item).is_err() {
                        let raw = {
                            let mut splits = self.splits();
                            let raw = splits.get_mut(&id).map(Split::take_raw).unwrap_or_default();
                            splits.remove(&id);
                            raw
                        };
                        (self.forward)(Post::Deliver {
                            id,
                            connector,
                            bytes: raw,
                        });
                        return;
                    }
                }
                if let Some(split) = self.splits().get_mut(&id) {
                    split.commit();
                }
                if !fed.forward.is_empty() {
                    (self.forward)(Post::Deliver {
                        id,
                        connector,
                        bytes: fed.forward,
                    });
                }
            }
        }
    }

    /// The owner is gone. A session mid-bucket sends the bytes the split
    /// still holds ahead of this chunk, then stops being split.
    fn forward_retired(&self, post: Post) {
        match post {
            Post::Deliver {
                id,
                connector,
                bytes,
            } => {
                let mut raw = self
                    .splits()
                    .remove(&id)
                    .map(|mut split| split.take_raw())
                    .unwrap_or_default();
                if !raw.is_empty() {
                    raw.extend_from_slice(&bytes);
                }
                let bytes = if raw.is_empty() { bytes } else { raw };
                (self.forward)(Post::Deliver {
                    id,
                    connector,
                    bytes,
                });
            }
            Post::Closed {
                id,
                connector,
                cause,
            } => {
                self.splits().remove(&id);
                (self.forward)(Post::Closed {
                    id,
                    connector,
                    cause,
                });
            }
            other => (self.forward)(other),
        }
    }

    fn splits(&self) -> std::sync::MutexGuard<'_, HashMap<SocketId, Split>> {
        self.splits.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A bucket the router keeps for the owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admitted {
    /// One of 2011–2014.
    Sync(SyncCommand),
    /// An announced block (2008).
    Announce,
}

impl Admitted {
    fn of(command: u32) -> Option<Self> {
        if command == NOTIFY_NEW_COMPACT_BLOCK {
            return Some(Self::Announce);
        }
        SyncCommand::from_wire(command).map(Self::Sync)
    }

    const fn payload_cap(self) -> u64 {
        match self {
            Self::Sync(command) => command.payload_cap(),
            Self::Announce => DefinedCommand::NewCompactBlock.payload_cap(),
        }
    }
}

/// A C++-bound message the owner reads a copy of for the peer's claim
/// (module docs, the claim tap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tapped {
    /// An inbound session's handshake request (1001).
    HandshakeRequest,
    /// A timed sync request (1002).
    TimedSyncRequest,
    /// A timed sync response (1002).
    TimedSyncResponse,
}

/// One bucket the owner receives, in the order the bytes arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Taken {
    /// A chain-sync message. Its bytes are not in [`Fed::forward`].
    Message(Admitted, Vec<u8>),
    /// A copy of a C++-bound payload that carries a claim. The same bytes
    /// are in [`Fed::forward`].
    Tap(Tapped, Vec<u8>),
}

/// What one chunk split into.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fed {
    /// Bytes for the C++ handler, in arrival order.
    pub forward: Vec<u8>,
    /// Whole messages and claim copies, in arrival order. A tap that
    /// preceded a kept message precedes it here.
    pub taken: Vec<Taken>,
}

/// Where a bucket's payload goes. One payload state reads every kind, so
/// a finished tap cannot sit beside a later bucket.
#[derive(Debug)]
enum Intake {
    /// The owner keeps the payload. The handler does not see the bucket.
    Keep(Admitted),
    /// The handler sees the bucket, and the owner gets a copy.
    Copy {
        /// Which claim the payload is.
        kind: Tapped,
        /// The payload so far.
        buf: Vec<u8>,
    },
    /// The handler sees the bucket. The owner does not.
    Forward,
}

impl Intake {
    /// The handler sees this bucket. A kept bucket stays with the owner.
    const fn streams(&self) -> bool {
        !matches!(self, Self::Keep(_))
    }
}

/// One session's position in its byte stream.
///
/// `raw` is every byte accepted since the last hand-off, in order. A feed
/// appends its chunk there and parses. [`Self::commit`] drops what that feed
/// handed to the handler or the owner. Until then [`Self::take_raw`] is the
/// stream the handler must see if the owner has gone: the unhanded prefix
/// and this chunk, once.
#[derive(Debug)]
pub struct Split {
    raw: Vec<u8>,
    /// `raw[..handed]` was copied into the last [`Fed`].
    handed: usize,
    /// The next byte to parse.
    cursor: usize,
    state: State,
}

impl Default for Split {
    fn default() -> Self {
        Self {
            raw: Vec::new(),
            handed: 0,
            cursor: 0,
            state: State::Header,
        }
    }
}

#[derive(Debug)]
enum State {
    /// Collecting a bucket header at `cursor`.
    Header,
    /// Reading a payload. `payload_at` is the index in `raw` of its first
    /// byte, and it is read only for [`Intake::Keep`]: a copy or a plain
    /// forward streams its bytes as they arrive.
    Payload {
        /// Where the payload goes.
        intake: Intake,
        /// Index in `raw` of the first payload byte.
        payload_at: usize,
        /// Payload bytes still to come.
        remaining: u64,
    },
    /// A header did not parse: everything from here goes to the C++
    /// handler raw, and its ingress refuses it.
    Raw,
}

impl Split {
    /// Split one delivered chunk. The chunk is kept in [`Self`] until
    /// [`commit`](Self::commit) or [`take_raw`](Self::take_raw).
    #[must_use]
    pub fn feed(&mut self, chunk: &[u8]) -> Fed {
        self.raw.extend_from_slice(chunk);
        let mut fed = Fed::default();
        loop {
            // `Header` is the resting state. Taking the state leaves that
            // placeholder until this step puts the real one back.
            let state = std::mem::replace(&mut self.state, State::Header);
            if !self.step(&mut fed, state) {
                break;
            }
        }
        fed
    }

    /// Read one state. `true` when another bucket in this chunk may start.
    fn step(&mut self, fed: &mut Fed, state: State) -> bool {
        match state {
            State::Raw => {
                fed.forward.extend_from_slice(&self.raw[self.cursor..]);
                self.cursor = self.raw.len();
                self.handed = self.cursor;
                self.state = State::Raw;
                false
            }
            State::Header => self.step_header(fed),
            State::Payload {
                intake,
                payload_at,
                remaining,
            } => self.step_payload(fed, intake, payload_at, remaining),
        }
    }

    /// A bucket header at `cursor`, or a wait when it is not whole yet.
    fn step_header(&mut self, fed: &mut Fed) -> bool {
        if self.raw.len() - self.cursor < HEADER_SIZE {
            return false;
        }
        let start = self.cursor;
        let head: [u8; HEADER_SIZE] = self.raw[start..start + HEADER_SIZE]
            .try_into()
            .expect("a whole header");
        match BucketHead::read(&head) {
            Err(_) => {
                self.state = State::Raw;
                true
            }
            Ok(bucket) => {
                self.cursor = start + HEADER_SIZE;
                let intake = intake_of(&bucket);
                if intake.streams() {
                    fed.forward.extend_from_slice(&head);
                    self.handed = self.cursor;
                }
                if bucket.payload_len == 0 {
                    finish_intake(fed, intake, Vec::new());
                    self.handed = self.cursor;
                    true
                } else {
                    self.state = State::Payload {
                        intake,
                        payload_at: self.cursor,
                        remaining: bucket.payload_len,
                    };
                    true
                }
            }
        }
    }

    /// Payload bytes at `cursor`. A finished bucket returns to the header.
    fn step_payload(
        &mut self,
        fed: &mut Fed,
        mut intake: Intake,
        payload_at: usize,
        remaining: u64,
    ) -> bool {
        let available = self.raw.len() - self.cursor;
        if available == 0 {
            self.state = State::Payload {
                intake,
                payload_at,
                remaining,
            };
            return false;
        }
        let take = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(available);
        let end = self.cursor + take;
        {
            let bytes = &self.raw[self.cursor..end];
            if let Intake::Copy { buf, .. } = &mut intake {
                buf.extend_from_slice(bytes);
            }
            if intake.streams() {
                fed.forward.extend_from_slice(bytes);
            }
        }
        self.cursor = end;
        if intake.streams() {
            self.handed = self.cursor;
        }
        let left = remaining - u64::try_from(take).unwrap_or(remaining);
        if left == 0 {
            // A kept payload is still in `raw`: its bytes were not streamed.
            // A copy's buffer holds every byte, including those an earlier
            // chunk already handed on.
            let kept = if intake.streams() {
                Vec::new()
            } else {
                self.raw[payload_at..self.cursor].to_vec()
            };
            finish_intake(fed, intake, kept);
            self.handed = self.cursor;
            true
        } else {
            self.state = State::Payload {
                intake,
                payload_at,
                remaining: left,
            };
            false
        }
    }

    /// Drop the bytes the last feed handed off. The unhanded tail stays,
    /// and a kept bucket in progress is that tail.
    pub fn commit(&mut self) {
        if self.handed == 0 {
            return;
        }
        self.raw.drain(..self.handed);
        self.cursor -= self.handed;
        if let State::Payload {
            payload_at,
            intake: Intake::Keep(_),
            ..
        } = &mut self.state
        {
            *payload_at -= self.handed;
        }
        self.handed = 0;
    }

    /// Every byte still held, including the chunk just fed. The caller
    /// forwards this once and drops the split.
    pub fn take_raw(&mut self) -> Vec<u8> {
        self.handed = 0;
        self.cursor = 0;
        self.state = State::Header;
        std::mem::take(&mut self.raw)
    }
}

/// Hand a finished bucket to `fed`. `kept` is the payload of a
/// [`Intake::Keep`]; a copy carries its own buffer.
fn finish_intake(fed: &mut Fed, intake: Intake, kept: Vec<u8>) {
    match intake {
        Intake::Keep(command) => fed.taken.push(Taken::Message(command, kept)),
        Intake::Copy { kind, buf } => fed.taken.push(Taken::Tap(kind, buf)),
        Intake::Forward => {}
    }
}

/// Where `bucket` goes. A kept command wins over a tap: the two command
/// sets are disjoint, and a kept bucket is not also copied.
fn intake_of(bucket: &BucketHead) -> Intake {
    if let Some(command) = admitted(bucket) {
        return Intake::Keep(command);
    }
    if let Some(kind) = tapped(bucket) {
        let reserve = usize::try_from(bucket.payload_len)
            .unwrap_or(0)
            .min(TAP_RESERVE);
        return Intake::Copy {
            kind,
            buf: Vec::with_capacity(reserve),
        };
    }
    Intake::Forward
}

/// The bucket the router keeps for the owner, when it admits it: a
/// notify (`Q`, not `S`, not a fragment), no undefined flag, a payload
/// within the command's cap. Anything else is not the router's, and the
/// C++ ingress judges it.
fn admitted(bucket: &BucketHead) -> Option<Admitted> {
    let command = Admitted::of(bucket.command)?;
    let flags = bucket.flags;
    let notify = flags.intersects(Flags::REQUEST)
        && !flags.intersects(Flags::RESPONSE)
        && !flags.intersects(Flags::BEGIN.union(Flags::END))
        && !bucket.expects_response();
    let defined = flags.difference(FLAGS_DEFINED).bits() == 0;
    (notify && defined && bucket.payload_len <= command.payload_cap()).then_some(command)
}

/// How much of a tapped payload is reserved up front; the rest grows as it
/// arrives, so a header's claimed length is never an allocation.
const TAP_RESERVE: usize = 4 * 1024;

/// The message a C++-bound bucket carries, when the owner reads a copy of
/// it: a whole (unfragmented) handshake request, or a timed sync request or
/// response, with no undefined flag and within the command's cap. The
/// header alone decides; the payload is not read here.
fn tapped(bucket: &BucketHead) -> Option<Tapped> {
    let flags = bucket.flags;
    let whole = !flags.intersects(Flags::BEGIN.union(Flags::END));
    let defined = flags.difference(FLAGS_DEFINED).bits() == 0;
    let request = flags.intersects(Flags::REQUEST)
        && !flags.intersects(Flags::RESPONSE)
        && bucket.expects_response();
    let response = flags.intersects(Flags::RESPONSE) && !flags.intersects(Flags::REQUEST);
    let (kind, cap) = match bucket.command {
        COMMAND_HANDSHAKE if request => (
            Tapped::HandshakeRequest,
            DefinedCommand::Handshake.payload_cap(),
        ),
        COMMAND_TIMED_SYNC if request => (
            Tapped::TimedSyncRequest,
            DefinedCommand::TimedSync.payload_cap(),
        ),
        COMMAND_TIMED_SYNC if response => (
            Tapped::TimedSyncResponse,
            DefinedCommand::TimedSync.payload_cap(),
        ),
        _ => return None,
    };
    (whole && defined && bucket.payload_len <= cap).then_some(kind)
}

#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;
