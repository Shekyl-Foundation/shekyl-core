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
mod gap;
mod gate;
mod queue;
mod read;
mod session;
mod stall;

pub use accept::accept_error_is_transient;
pub use copy::{read_capped, write_capped, write_granted, READ_CHUNK_BYTES};
pub use gap::SilenceGap;
pub use gate::{node_gate, LinkGate};
pub use queue::{ByteQueue, CloseReason, Overfull, PushError};
pub use read::{read_granted, ReadStop, ReadyRead};
pub use session::{
    FrameSender, InboundEnd, QueueHold, SendHalf, Session, StreamEnds, UNREAD_FRAMES,
};
pub use stall::{process_write_stall, ProcessWriteStall, WriteStall};
// The gate's clock, re-exported beside it. No crate in the workspace reads
// it through this path; readers import `shekyl_transport_layer` directly.
pub use shekyl_transport_layer::{monotonic_ms, recv_mark_ms};
