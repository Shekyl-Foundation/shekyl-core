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
//! with one-in-flight FIFO command correlation via `DelegatedReply`. [`bootstrap`]
//! (SP-T0b) is the sans-IO readiness half — the `BootstrapState` a consumer awaits
//! and the `GETINFO status/bootstrap-phase` parser the actor's poll task drives it
//! with (design §3b: a poll, never a `STATUS_CLIENT` subscription).
//! [`encoding`] holds the byte↔text conversions the wire needs — uppercase hex
//! and base64 — once, so a codec correction cannot land on one call site and
//! miss its counterpart.
//! [`events`] parses one asynchronous `650` line. The quoted-field lexer it
//! reads with stays private to this module: a keyword counts only at the start
//! of a token, before any quote is opened. [`upload_rounds`] is the supervisor's
//! policy over parsed `HS_DESC` events (`TSR-Q5`). Nothing in production sends
//! `SETEVENTS` yet; the policy stays because the later increments are its caller.

pub mod actor;
pub mod auth;
pub mod bootstrap;
pub mod consensus;
pub mod encoding;
mod event_lex;
pub mod events;
pub mod framing;
pub(crate) mod launch;
pub mod listeners;
pub mod onion;
pub mod ready;
pub mod safecookie;
pub mod stream;
pub mod upload_rounds;
pub mod vanguards;

pub use actor::{
    BootstrapReadiness, Command, CommandResult, ControlError, DeathSignal, EventReceiver,
    EventSink, ManagedTor, Signal, SocksPort, SystemDirectoryError, TorControlClient,
    TorControlClientConfig, TorExit, TorLaunch, EVENT_QUEUE_EVENTS,
};
pub use auth::{parse_authchallenge, read_cookie_file, AuthError, ServerHash, ServerNonce};
pub use bootstrap::{parse_bootstrap_progress, BootstrapState};
pub use events::{
    parse_event, Bootstrap, BootstrapProblem, ClientStatus, ClockSkew, GeneralStatus, HsDescAction,
    HsDescEvent, Liveness, LogEvent, LogSeverity, Recommendation, Severity, TorEvent,
    VersionReason, SUPERVISOR_EVENTS,
};
pub use framing::{
    ControlReply, Framed, FramingError, ReplyBudget, ReplyFramer, ASYNC_EVENT_STATUS,
    BULK_REPLY_BYTES, ORDINARY_REPLY_BYTES,
};
pub use listeners::parse_socks_listeners;
pub use onion::{
    evaluate_add_onion_reply, parse_service_id, AddOnion, AddOnionReplyError, OnionFlags, OnionKey,
    OnionPort, OnionPow, ServiceId, ONION_KEY_BYTES, SERVICE_ID_CHARS,
};
pub use ready::{ask_timed, wait_until_ready, AskError, WaitReadyError};
pub use safecookie::{verify_server_hash, ControlCookie, ServerVerified};
pub use stream::{parse_stream_event, CircId, StreamEvent, StreamStatus};
pub use upload_rounds::{RoundMark, UploadRounds};
pub use vanguards::{HsLayerPins, RelayFingerprint, NUM_LAYER2_GUARDS, NUM_LAYER3_GUARDS};
