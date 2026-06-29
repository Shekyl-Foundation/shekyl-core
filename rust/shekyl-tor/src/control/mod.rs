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
//! async/command split to the one-line [`ControlReply::is_async_event`]
//! discriminator. Keeping it sans-IO is what lets the bulk of the demux KATs run
//! in the normal unit gate rather than only against a live Tor — and (per the
//! design doc's co-validation note) the live measured test then doubles as the
//! acceptance gate for the `STREAM`/CircID read path layered on top.
//!
//! Later slices add the SAFECOOKIE handshake, the command layer (`GETINFO`,
//! `SETEVENTS`, `ADD_ONION`/`DEL_ONION`, `TAKEOWNERSHIP`), and the `tokio` socket
//! actor that drives this framer with the poll/phase discipline the reference
//! (Gosling) validates.

pub mod framing;
pub mod safecookie;

pub use framing::{ControlReply, FramingError, ReplyFramer, ASYNC_EVENT_STATUS};
pub use safecookie::{client_hash, verify_server_hash, ControlCookie};
