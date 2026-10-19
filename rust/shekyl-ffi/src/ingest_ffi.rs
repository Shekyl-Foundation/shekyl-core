// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The protocol handler's one entry into the ingest service
//! (`DRS_X_STORE_FLIP.md` DX-Q2 item 2): the only FFI the arrival path has.
//! `submit_block` and the miner enter the service's door natively.
//!
//! **Built and tested here, routed at the flip.** Nothing in C++ calls it
//! yet: the protocol handler keeps calling `core` until the flip routes its
//! block arrivals here, and chain sync and RD delete this entry with the
//! handler. The composition root installs the service's door with
//! [`install`]; C++ binds the post with [`shekyl_ingest_bind`].
//!
//! - [`shekyl_ingest_room`] reports the room before the caller sends.
//! - [`shekyl_ingest_offer_span`] takes a span from one connection and
//!   returns at once: accepted, or a refusal before acceptance (`NoRoom`,
//!   `Throttled`, `Oversize`), never a peer fault.
//! - Each accepted arrival gets exactly one reply, tagged with the arrival
//!   and the connection, posted through the bound callback, which only
//!   enqueues onto the connection's strand (the seam's shape,
//!   `seam_ffi.rs`).
//! - [`shekyl_ingest_session_closed`] forgets the connection's bucket.
//!
//! The bytes a span names are copied before the call returns: C++ owns its
//! buffers, and nothing here keeps a pointer into them.

use std::ffi::c_void;
use std::sync::Mutex;

use shekyl_chain_ingest::service::{
    Arrival, ArrivalTag, Door, Origin, Refusal, Reply, SessionId, Tagged,
};

use crate::legacy_util::{slice_from_ptr, slice_from_typed_ptr};

/// A borrowed byte buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylIngestBlob {
    pub ptr: *const u8,
    pub len: usize,
}

/// One arriving block: the caller's tag, the block blob and the listed
/// bodies it carried.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylIngestArrival {
    pub tag: u64,
    pub block: ShekylIngestBlob,
    pub bodies: *const ShekylIngestBlob,
    pub bodies_len: usize,
}

/// One reply, as posted. Which fields carry meaning is the `kind`'s:
/// `height` and `hash` for `CONNECTED`, `HELD`, `PROMOTION_REFUSED`;
/// `hash` for `UNLINKED`; `rule` (the census row's index) for `REFUSED` and
/// `PROMOTION_REFUSED`; `by` for `CANCELLED`; `height` (the depth) and `by`
/// (the cap) for `BEYOND_CAP`; `height` (the tip) and `by` (the floor) for
/// `BELOW_FLOOR`; `height` (the promoted tip's height) for `SWITCHED`. The
/// rest are zero. `MISSING_BODIES` carries its indices beside the struct.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylIngestReply {
    pub connection: u64,
    pub tag: u64,
    pub kind: u32,
    pub rule: u16,
    pub _pad: [u8; 2],
    pub height: u64,
    pub by: u64,
    pub hash: [u8; 32],
}

const _: () = {
    assert!(std::mem::size_of::<ShekylIngestReply>() == 72);
    assert!(std::mem::offset_of!(ShekylIngestReply, kind) == 16);
    assert!(std::mem::offset_of!(ShekylIngestReply, height) == 24);
    assert!(std::mem::offset_of!(ShekylIngestReply, hash) == 40);
};

/// The block connected.
pub const SHEKYL_INGEST_CONNECTED: u32 = 1;
/// A verdict against the block: the one outcome that closes the session.
pub const SHEKYL_INGEST_REFUSED: u32 = 2;
/// Its parent chain reaches no block this node holds.
pub const SHEKYL_INGEST_UNLINKED: u32 = 3;
/// This node holds it already.
pub const SHEKYL_INGEST_ALREADY_HELD: u32 = 4;
/// Stored as an alternative block.
pub const SHEKYL_INGEST_HELD: u32 = 5;
/// Stored; the switch it makes due is deeper than the cap.
pub const SHEKYL_INGEST_BEYOND_CAP: u32 = 6;
/// Stored, and the chain switched onto its branch.
pub const SHEKYL_INGEST_SWITCHED: u32 = 7;
/// Stored, and the switch was refused: a promoted block failed.
pub const SHEKYL_INGEST_PROMOTION_REFUSED: u32 = 8;
/// The switch met the undo floor.
pub const SHEKYL_INGEST_BELOW_FLOOR: u32 = 9;
/// Listed bodies to ask for, by index.
pub const SHEKYL_INGEST_MISSING_BODIES: u32 = 10;
/// An earlier block in the span was refused.
pub const SHEKYL_INGEST_CANCELLED: u32 = 11;
/// The service stopped first.
pub const SHEKYL_INGEST_STOPPED: u32 = 12;

/// The span was accepted: one reply per arrival follows.
pub const SHEKYL_INGEST_ACCEPTED: i32 = 0;
/// No room now: ask again later. Never a peer fault.
pub const SHEKYL_INGEST_NO_ROOM: i32 = 1;
/// The session's unsolicited bucket is dry. The handler may close the
/// session; it never scores it.
pub const SHEKYL_INGEST_THROTTLED: i32 = 2;
/// An arrival is larger than any valid block near the tip.
pub const SHEKYL_INGEST_OVERSIZE: i32 = 3;
/// No door is installed, or no post is bound.
pub const SHEKYL_INGEST_UNBOUND: i32 = -1;
/// A null pointer where a buffer was due.
pub const SHEKYL_INGEST_INVALID: i32 = -2;

/// The post: nullable, as C passes it (a null post unbinds).
type IngestPostFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        reply: *const ShekylIngestReply,
        indices: *const u64,
        indices_len: usize,
    ),
>;

/// The strand executor. C++ keeps it alive for as long as the bind stands.
struct Ctx(*mut c_void);

// The pointer is the executor, not a handler: every thread that posts may
// share it, and the post only enqueues.
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

struct Bound {
    ctx: Ctx,
    post: unsafe extern "C" fn(*mut c_void, *const ShekylIngestReply, *const u64, usize),
}

struct Installed {
    door: Door,
    runtime: tokio::runtime::Handle,
}

static DOOR: Mutex<Option<Installed>> = Mutex::new(None);
static POST: Mutex<Option<Bound>> = Mutex::new(None);

/// Install the service's door, and the runtime its replies are awaited on:
/// the composition root's call, at the flip. A second install replaces the
/// first.
pub fn install(door: Door, runtime: tokio::runtime::Handle) {
    *DOOR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Installed { door, runtime });
}

/// Remove the installed door: every offer after is `UNBOUND`.
pub fn uninstall() {
    *DOOR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

/// Bind the post the replies are delivered through. A null `post` or `ctx`
/// unbinds. Returns 0.
///
/// # Safety
/// `ctx` stays valid until the next bind returns; `post` only enqueues and
/// does not call back into this module before it returns.
#[no_mangle]
pub unsafe extern "C" fn shekyl_ingest_bind(ctx: *mut c_void, post: IngestPostFn) -> i32 {
    let bound = match post {
        Some(post) if !ctx.is_null() => Some(Bound {
            ctx: Ctx(ctx),
            post,
        }),
        _ => None,
    };
    *POST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = bound;
    0
}

/// The arrivals the service will accept now; 0 when no door is installed.
#[no_mangle]
pub extern "C" fn shekyl_ingest_room() -> u64 {
    DOOR.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map_or(0, |installed| {
            u64::try_from(installed.door.room()).unwrap_or(u64::MAX)
        })
}

/// Offer a span of `len` arrivals from `connection` (module docs).
/// `solicited` is nonzero for blocks this node asked for. Returns
/// `SHEKYL_INGEST_ACCEPTED` or a refusal code.
///
/// # Safety
/// `arrivals` points to `len` readable entries, and each entry's buffers
/// are readable for their lengths. Nothing is read after this returns.
#[no_mangle]
pub unsafe extern "C" fn shekyl_ingest_offer_span(
    connection: u64,
    solicited: u8,
    arrivals: *const ShekylIngestArrival,
    len: usize,
) -> i32 {
    if POST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_none()
    {
        return SHEKYL_INGEST_UNBOUND;
    }
    let Some(entries) = (unsafe { slice_from_typed_ptr(arrivals, len) }) else {
        return SHEKYL_INGEST_INVALID;
    };
    let origin = Origin::Peer {
        session: SessionId(connection),
        solicited: solicited != 0,
    };
    // Copied out of C++'s buffers now: a read here is bounded by the
    // slices just validated, and nothing keeps a pointer past the return.
    let span: Option<Vec<Arrival>> = entries
        .iter()
        .map(|entry| {
            let block = unsafe { slice_from_ptr(entry.block.ptr, entry.block.len) }?;
            let blobs = unsafe { slice_from_typed_ptr(entry.bodies, entry.bodies_len) }?;
            let bodies: Option<Vec<Vec<u8>>> = blobs
                .iter()
                .map(|blob| unsafe { slice_from_ptr(blob.ptr, blob.len) }.map(<[u8]>::to_vec))
                .collect();
            Some(Arrival {
                tag: ArrivalTag(entry.tag),
                origin,
                block: block.to_vec(),
                bodies: bodies?,
            })
        })
        .collect();
    let Some(span) = span else {
        return SHEKYL_INGEST_INVALID;
    };
    let installed = DOOR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(installed) = installed.as_ref() else {
        return SHEKYL_INGEST_UNBOUND;
    };
    match installed.door.offer_span(span) {
        Ok(tickets) => {
            for ticket in tickets {
                installed.runtime.spawn(async move {
                    post_reply(connection, ticket.reply().await);
                });
            }
            SHEKYL_INGEST_ACCEPTED
        }
        Err(Refusal::NoRoom) => SHEKYL_INGEST_NO_ROOM,
        Err(Refusal::Throttled) => SHEKYL_INGEST_THROTTLED,
        Err(Refusal::Oversize) => SHEKYL_INGEST_OVERSIZE,
    }
}

/// `connection` closed: its bucket is forgotten.
#[no_mangle]
pub extern "C" fn shekyl_ingest_session_closed(connection: u64) {
    if let Some(installed) = DOOR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        installed.door.session_closed(SessionId(connection));
    }
}

/// The reply as the C struct, and the indices `MISSING_BODIES` carries.
fn encode(connection: u64, tagged: Tagged) -> (ShekylIngestReply, Vec<u64>) {
    let mut out = ShekylIngestReply {
        connection,
        tag: tagged.tag.0,
        kind: 0,
        rule: 0,
        _pad: [0; 2],
        height: 0,
        by: 0,
        hash: [0; 32],
    };
    let mut indices = Vec::new();
    match tagged.reply {
        Reply::Connected { height, hash } => {
            out.kind = SHEKYL_INGEST_CONNECTED;
            out.height = height.to_raw();
            out.hash = hash.to_bytes();
        }
        Reply::Refused(refused) => {
            out.kind = SHEKYL_INGEST_REFUSED;
            out.rule = u16::from(refused.rule.index());
        }
        Reply::Unlinked { at } => {
            out.kind = SHEKYL_INGEST_UNLINKED;
            out.hash = at.to_bytes();
        }
        Reply::AlreadyHeld => out.kind = SHEKYL_INGEST_ALREADY_HELD,
        Reply::Held { height } => {
            out.kind = SHEKYL_INGEST_HELD;
            out.height = height.to_raw();
        }
        Reply::BeyondCap(beyond) => {
            out.kind = SHEKYL_INGEST_BEYOND_CAP;
            out.height = beyond.depth.to_raw();
            out.by = beyond.cap.to_raw();
        }
        Reply::Switched { promoted, .. } => {
            out.kind = SHEKYL_INGEST_SWITCHED;
            if let Some((height, hash)) = promoted.last() {
                out.height = height.to_raw();
                out.hash = hash.to_bytes();
            }
        }
        Reply::PromotionRefused { at, hash, refused } => {
            out.kind = SHEKYL_INGEST_PROMOTION_REFUSED;
            out.height = at.to_raw();
            out.hash = hash.to_bytes();
            out.rule = u16::from(refused.rule.index());
        }
        Reply::BelowFloor { tip, floor } => {
            out.kind = SHEKYL_INGEST_BELOW_FLOOR;
            out.height = tip;
            out.by = floor;
        }
        Reply::MissingBodies { indices: missing } => {
            out.kind = SHEKYL_INGEST_MISSING_BODIES;
            indices = missing
                .into_iter()
                .map(|i| u64::try_from(i).unwrap_or(u64::MAX))
                .collect();
        }
        Reply::Cancelled { by } => {
            out.kind = SHEKYL_INGEST_CANCELLED;
            out.by = by.0;
        }
        Reply::Stopped => out.kind = SHEKYL_INGEST_STOPPED,
    }
    (out, indices)
}

/// Post one reply through the bound callback. Unbound, it has no reader.
fn post_reply(connection: u64, tagged: Tagged) {
    let (reply, indices) = encode(connection, tagged);
    let bound = POST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(bound) = bound.as_ref() {
        // SAFETY: the bind's contract: `ctx` is live while bound, and the
        // post only enqueues.
        unsafe {
            (bound.post)(
                bound.ctx.0,
                std::ptr::from_ref(&reply),
                indices.as_ptr(),
                indices.len(),
            );
        }
    }
}

#[cfg(test)]
#[path = "ingest_ffi_tests.rs"]
mod ingest_ffi_tests;
