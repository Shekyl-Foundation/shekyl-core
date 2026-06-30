// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Roll-our-own minimal Tor control-port client (SP-T0a).
//!
//! The control protocol multiplexes two kinds of message onto one socket:
//! synchronous command replies and asynchronous `SETEVENTS` events (status
//! `650`). The structural hazard the whole rule-17 call turns on is that a
//! reader which mis-frames a single event **poisons every subsequent read** — so
//! the risk is concentrated in one place, the reply demux, and tested there.
//!
//! [`framing`] is that place: a **sans-IO** state machine (no socket, no async)
//! that turns a control byte stream into [`ControlReply`]s, leaving the
//! async/command split to a single ingress fork — [`ControlReply::classify`]
//! into [`Framed`]. Keeping it sans-IO is what lets the bulk of the demux KATs run
//! in the normal unit gate rather than only against a live Tor — and (per the
//! design doc's co-validation note) the live measured test then doubles as the
//! acceptance gate for the `STREAM`/CircID read path layered on top.
//!
//! [`safecookie`] is the SAFECOOKIE crypto + the verify→authenticate typestate;
//! [`auth`] is the handshake plumbing (cookie-file read, `AUTHCHALLENGE` parse).
//! [`actor`] is the `tokio` + `kameo` driver: it runs the handshake in `on_start`,
//! then `attach_stream`s the read half so kameo merges replies into the mailbox,
//! with one-in-flight FIFO command correlation via `DelegatedReply`.

pub mod actor;
pub mod auth;
pub mod framing;
pub mod safecookie;

pub use actor::{Command, CommandResult, ControlError, EventSink, TorControl, TorControlConfig};
pub use auth::{parse_authchallenge, read_cookie_file, AuthError, ServerHash, ServerNonce};
pub use framing::{ControlReply, Framed, FramingError, ReplyFramer, ASYNC_EVENT_STATUS};
pub use safecookie::{verify_server_hash, ControlCookie, ServerVerified};
