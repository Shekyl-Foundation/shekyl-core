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
//!   are chain sync's (CS-Q1), and the owner relays a connected one. 2009,
//!   a peer asking for an announced block's missing transactions, stays the
//!   C++ handler's until the cutover.
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
//!
//! [`Post::Established`] and [`Post::Closed`] go to the owner as well as
//! onward, and [`Post::HandshakeResult`] goes to the owner as a claim and
//! onward too, so the C++ handler keeps its own copy.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_levin::{
    BucketHead, DefinedCommand, Flags, SyncCommand, FLAGS_DEFINED, HEADER_SIZE,
    NOTIFY_NEW_COMPACT_BLOCK,
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
    /// A session's sync payload: the peer's claim. The outbound
    /// handshake's arrives as a post; an inbound handshake's and a timed
    /// sync's arrive as a hint ([`Router::hint`]).
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

    /// This router as the hub's post sink. The caller keeps its own
    /// `Arc` for [`Self::hint`].
    #[must_use]
    pub fn sink(self: &Arc<Self>) -> Arc<dyn Fn(Post) + Send + Sync> {
        let router = Arc::clone(self);
        Arc::new(move |post| router.post(post))
    }

    /// A session's sync payload that did not arrive as a post: an inbound
    /// handshake's, or a timed sync's (CS-Q10, until slice 4). The owner
    /// takes it as that session's claim. `false` when no owner is attached
    /// (the daemon's router before the cutover) or it is gone: the hint is
    /// dropped, and the C++ handler has its own copy.
    pub fn hint(&self, id: SocketId, sync: SyncPayload) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|owner| owner.send(Routed::Claim { id, sync }).is_ok())
    }

    /// Handle one post (module docs). Never calls into the hub.
    pub fn post(&self, post: Post) {
        let Some(owner) = self.owner.as_ref().filter(|owner| !owner.is_closed()) else {
            (self.forward)(post);
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
                    .map(|(admitted, payload)| match admitted {
                        Admitted::Sync(command) => Routed::Message {
                            id,
                            command,
                            payload,
                        },
                        Admitted::Announce => Routed::Announce { id, payload },
                    })
                    .collect::<Vec<_>>();
                if fed.forward.is_empty() {
                    routed.push(Routed::Finished { id });
                }
                // An owner gone mid-chunk cannot finish it: the chunk goes
                // to the C++ handler whole, and the session is not split
                // again.
                if routed.into_iter().any(|item| owner.send(item).is_err()) {
                    self.splits().remove(&id);
                    (self.forward)(Post::Deliver {
                        id,
                        connector,
                        bytes,
                    });
                } else if !fed.forward.is_empty() {
                    (self.forward)(Post::Deliver {
                        id,
                        connector,
                        bytes: fed.forward,
                    });
                }
            }
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

/// What one chunk split into.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fed {
    /// Bytes for the C++ handler, in arrival order.
    pub forward: Vec<u8>,
    /// Whole messages for the owner, in arrival order.
    pub messages: Vec<(Admitted, Vec<u8>)>,
}

/// One session's position in its byte stream.
#[derive(Debug)]
pub struct Split {
    state: State,
}

impl Default for Split {
    fn default() -> Self {
        Self {
            state: State::Header(Vec::with_capacity(HEADER_SIZE)),
        }
    }
}

#[derive(Debug)]
enum State {
    /// Collecting a bucket header.
    Header(Vec<u8>),
    /// Passing a C++-bound payload through: bytes still to come.
    Forward(u64),
    /// Buffering a payload for the owner.
    Sync {
        command: Admitted,
        payload: Vec<u8>,
        remaining: u64,
    },
    /// A header did not parse: everything from here goes to the C++
    /// handler raw, and its ingress refuses it.
    Raw,
}

/// How much of a chain-sync payload is reserved up front. The rest grows
/// as it arrives, so a header's claimed length is never an allocation.
const RESERVE: usize = 64 * 1024;

impl Split {
    /// Split one delivered chunk.
    #[must_use]
    pub fn feed(&mut self, mut bytes: &[u8]) -> Fed {
        let mut fed = Fed::default();
        while !bytes.is_empty() {
            match &mut self.state {
                State::Raw => {
                    fed.forward.extend_from_slice(bytes);
                    bytes = &[];
                }
                State::Header(head) => {
                    let take = (HEADER_SIZE - head.len()).min(bytes.len());
                    head.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if head.len() < HEADER_SIZE {
                        break;
                    }
                    let raw: [u8; HEADER_SIZE] =
                        head.as_slice().try_into().expect("a whole header");
                    self.state = match BucketHead::read(&raw) {
                        Err(_) => {
                            fed.forward.extend_from_slice(&raw);
                            State::Raw
                        }
                        Ok(bucket) => match admitted(&bucket) {
                            Some(command) if bucket.payload_len == 0 => {
                                fed.messages.push((command, Vec::new()));
                                State::Header(Vec::with_capacity(HEADER_SIZE))
                            }
                            Some(command) => State::Sync {
                                command,
                                payload: Vec::with_capacity(
                                    usize::try_from(bucket.payload_len)
                                        .unwrap_or(RESERVE)
                                        .min(RESERVE),
                                ),
                                remaining: bucket.payload_len,
                            },
                            None => {
                                fed.forward.extend_from_slice(&raw);
                                if bucket.payload_len == 0 {
                                    State::Header(Vec::with_capacity(HEADER_SIZE))
                                } else {
                                    State::Forward(bucket.payload_len)
                                }
                            }
                        },
                    };
                }
                State::Forward(remaining) => {
                    let take = usize::try_from(*remaining)
                        .unwrap_or(usize::MAX)
                        .min(bytes.len());
                    fed.forward.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    *remaining -= u64::try_from(take).unwrap_or(u64::MAX);
                    if *remaining == 0 {
                        self.state = State::Header(Vec::with_capacity(HEADER_SIZE));
                    }
                }
                State::Sync {
                    command,
                    payload,
                    remaining,
                } => {
                    let take = usize::try_from(*remaining)
                        .unwrap_or(usize::MAX)
                        .min(bytes.len());
                    payload.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    *remaining -= u64::try_from(take).unwrap_or(u64::MAX);
                    if *remaining == 0 {
                        let command = *command;
                        let payload = std::mem::take(payload);
                        fed.messages.push((command, payload));
                        self.state = State::Header(Vec::with_capacity(HEADER_SIZE));
                    }
                }
            }
        }
        fed
    }
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

#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;
