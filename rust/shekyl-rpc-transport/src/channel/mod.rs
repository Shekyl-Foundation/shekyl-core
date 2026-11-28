// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The RPC channel's client (`docs/design/RPC_CHANNEL.md` RT-W11): it dials
//! a daemon, runs the `hybridXK` handshake against the daemon's public
//! bundle, and carries HTTP over the record stream, behind the same calls
//! the transport's other targets offer ([`ChannelDaemon::call`],
//! [`ChannelDaemon::json_rpc`]).
//!
//! Four layers, each in its own module and usable alone:
//!
//! - [`Leg`]: where the daemon is. An IP may be direct or through a SOCKS
//!   proxy. An onion carries its proxy. A service's console leg is a
//!   socket or a Windows pipe. Dialed into a [`LegStream`]. A grammar peer
//!   becomes that leg through [`PeerRoute`], which is also the plaintext
//!   HTTP base.
//! - [`handshake_over`]: the client's side of the handshake over any
//!   stream, ending in the record stream and the ceiling message 4 carried.
//!   [`ChannelTarget::open`] dials and runs it under §4.3's policy: the
//!   handshake deadline, one silent retry after a timeout, and a jittered
//!   back-off after a busy reply.
//! - [`Session`]: hyper's `client::conn::http1` over one record stream, a
//!   connection of its own (§13, RT-W11's client contracts). A submission
//!   is sent with the stream's
//!   [`SubmissionMark`](shekyl_rpc_stream::SubmissionMark) armed, as one
//!   complete body, and the session carries nothing else until its response.
//! - [`Pool`]: up to `SESSIONS_PER_CLIENT` sessions to one daemon under one
//!   grant (§8): opened on demand, one kept open and reopened when the
//!   daemon closes it, extras closed after [`EXTRA_SESSION_IDLE`]. A request
//!   beyond the cap waits for a session, bounded by the handshake deadline.
//!   A revocation stops the pool, which does not dial again.
//!
//! [`ChannelDaemon`] is the synchronous shell over one [`Session`], the
//! shape [`crate::SyncDaemon`] has for plaintext HTTP. The key and bundle
//! helpers read and write the files a client holds.
//!
//! Every failure is a [`ChannelFault`], worded for the person who reads it
//! (§4.5, rule 81). What the client cannot tell apart, it names together and
//! points at the node's log.

mod fault;
mod handshake;
mod key;
mod leg;
mod pool;
mod reach;
mod session;
mod sync;

pub use fault::ChannelFault;
pub use handshake::{handshake_over, Attempt, ChannelTarget, Opened};
pub use key::{
    bundle_from_bytes, bundle_from_text, bundle_text, create_client_key, fingerprint_hex,
    read_client_key,
};
pub use leg::{Leg, LegStream};
pub use pool::{Lent, Pool, EXTRA_SESSION_IDLE};
pub use reach::{socks5h_url, PeerRoute, PeerRouteError};
pub use session::{is_submission, Session};
pub use sync::ChannelDaemon;

mod wallet;
pub use wallet::{account_target, default_key_file, RemoteNode, WalletChannel};
