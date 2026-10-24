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

use shekyl_levin::{BucketHead, Flags, SyncCommand, FLAGS_DEFINED, HEADER_SIZE};
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
                    .messages
                    .into_iter()
                    .map(|(command, payload)| Routed::Message {
                        id,
                        command,
                        payload,
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

/// What one chunk split into.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fed {
    /// Bytes for the C++ handler, in arrival order.
    pub forward: Vec<u8>,
    /// Whole chain-sync messages, in arrival order.
    pub messages: Vec<(SyncCommand, Vec<u8>)>,
}

/// One session's position in its byte stream.
///
/// `raw` is every byte accepted since the last hand-off, in order. A feed
/// appends its chunk there and parses. [`commit`] drops what that feed
/// handed to the handler or the owner. Until then [`take_raw`] is the
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

#[derive(Clone, Copy, Debug)]
enum State {
    /// Collecting a bucket header at `cursor`.
    Header,
    /// Passing a C++-bound payload through: `remaining` bytes still to come.
    Forward {
        /// Payload bytes still to hand to the handler.
        remaining: u64,
    },
    /// A chain-sync payload. Its header and the bytes so far stay in `raw`
    /// until the payload completes, so a handler that inherits the stream
    /// still sees the bucket.
    Sync {
        /// The command.
        command: SyncCommand,
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
            match self.state {
                State::Raw => {
                    fed.forward.extend_from_slice(&self.raw[self.cursor..]);
                    self.cursor = self.raw.len();
                    self.handed = self.cursor;
                    break;
                }
                State::Header => {
                    if self.raw.len() - self.cursor < HEADER_SIZE {
                        break;
                    }
                    let start = self.cursor;
                    let head: [u8; HEADER_SIZE] = self.raw[start..start + HEADER_SIZE]
                        .try_into()
                        .expect("a whole header");
                    match BucketHead::read(&head) {
                        Err(_) => self.state = State::Raw,
                        Ok(bucket) => {
                            self.cursor = start + HEADER_SIZE;
                            match admitted(&bucket) {
                                Some(command) if bucket.payload_len == 0 => {
                                    fed.messages.push((command, Vec::new()));
                                    self.handed = self.cursor;
                                    self.state = State::Header;
                                }
                                Some(command) => {
                                    self.state = State::Sync {
                                        command,
                                        payload_at: self.cursor,
                                        remaining: bucket.payload_len,
                                    };
                                }
                                None => {
                                    fed.forward.extend_from_slice(&head);
                                    self.handed = self.cursor;
                                    self.state = if bucket.payload_len == 0 {
                                        State::Header
                                    } else {
                                        State::Forward {
                                            remaining: bucket.payload_len,
                                        }
                                    };
                                }
                            }
                        }
                    }
                }
                State::Forward { remaining } => {
                    let available = self.raw.len() - self.cursor;
                    if available == 0 {
                        break;
                    }
                    let take = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(available);
                    fed.forward
                        .extend_from_slice(&self.raw[self.cursor..self.cursor + take]);
                    self.cursor += take;
                    self.handed = self.cursor;
                    let left = remaining - u64::try_from(take).unwrap_or(remaining);
                    if left == 0 {
                        self.state = State::Header;
                    } else {
                        self.state = State::Forward { remaining: left };
                        break;
                    }
                }
                State::Sync {
                    command,
                    payload_at,
                    remaining,
                } => {
                    let available = self.raw.len() - self.cursor;
                    if available == 0 {
                        break;
                    }
                    let take = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(available);
                    self.cursor += take;
                    let left = remaining - u64::try_from(take).unwrap_or(remaining);
                    if left == 0 {
                        let payload = self.raw[payload_at..self.cursor].to_vec();
                        fed.messages.push((command, payload));
                        self.handed = self.cursor;
                        self.state = State::Header;
                    } else {
                        self.state = State::Sync {
                            command,
                            payload_at,
                            remaining: left,
                        };
                        break;
                    }
                }
            }
        }
        fed
    }

    /// Drop the bytes the last feed handed off. The unhanded tail stays,
    /// and a sync bucket in progress is that tail.
    pub fn commit(&mut self) {
        if self.handed == 0 {
            return;
        }
        self.raw.drain(..self.handed);
        self.cursor -= self.handed;
        if let State::Sync { payload_at, .. } = &mut self.state {
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

/// The chain-sync command a bucket carries, when the router admits it: a
/// notify (`Q`, not `S`, not a fragment), no undefined flag, a payload
/// within the command's cap. Anything else is not the router's, and the
/// C++ ingress judges it.
fn admitted(bucket: &BucketHead) -> Option<SyncCommand> {
    let command = SyncCommand::from_wire(bucket.command)?;
    let flags = bucket.flags;
    let notify = flags.intersects(Flags::REQUEST)
        && !flags.intersects(Flags::RESPONSE)
        && !flags.intersects(Flags::BEGIN.union(Flags::END))
        && !bucket.expects_response();
    let defined = flags.difference(FLAGS_DEFINED).bits() == 0;
    (notify && defined && bucket.payload_len <= command.payload_cap()).then_some(command)
}

#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;
