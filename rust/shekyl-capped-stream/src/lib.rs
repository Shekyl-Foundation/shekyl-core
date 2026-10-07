// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The byte cap and the socket copy under every connector.
//!
//! A connector frames bytes. This crate does not. [`ByteQueue`] is the
//! outbound cap: a send that does not fit is not stored, and [`Overfull`]
//! cancels a write that has already started. [`read_capped`] and
//! [`write_capped`] are that copy. Clearnet passes its seam as the
//! frame functions. Tor passes the bytes through.
//!
//! [`StreamEnds`] is one connection. The [`Session`] is the caller's
//! end. [`QueueHold`] is the connection task's end: dropping it closes
//! the queue even when the caller still holds the session.

#![deny(unsafe_code)]

mod accept;
mod copy;
mod gate;
mod queue;
mod session;

pub use accept::accept_error_is_transient;
pub use copy::{
    process_write_stall, read_capped, refund_unsent, write_all_counted, write_capped,
    ProcessWriteStall, WriteStall, READ_CHUNK_BYTES,
};
pub use gate::{node_gate, LinkGate};
pub use shekyl_transport_layer::{recv_is_stalled, recv_mark_ms};
pub use queue::{ByteQueue, CloseReason, Overfull, PushError};
pub use session::{FrameSender, QueueHold, SendHalf, Session, StreamEnds, UNREAD_FRAMES};
