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
//!   `Throttled`, `Oversize`), never a peer fault. Lengths, room and the
//!   session bucket are judged before any block byte is copied. The span
//!   reserves at most the window, and each body list at most the
//!   transaction hashes its block can name.
//! - Each accepted arrival gets exactly one reply, tagged with the arrival
//!   and the connection, posted through the bound callback, which only
//!   enqueues onto the connection's strand (the seam's shape,
//!   `seam_ffi.rs`). One pump, started at [`install`], owns those replies.
//!   Unbinding drains the ones already accepted — `Stopped` included —
//!   before the post is cleared, so a shutdown cannot leave one unanswered.
//! - [`shekyl_ingest_session_closed`] forgets the connection's bucket.
//!
//! The bytes a span names are copied before the call returns, and only
//! after the door has reserved the span: C++ owns its buffers, and nothing
//! here keeps a pointer into them.

use std::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use shekyl_chain_ingest::admission::tx_names_in;
use shekyl_chain_ingest::service::{
    Arrival, ArrivalLengths, ArrivalTag, CannotFollow, Door, Origin, Refusal, Reply, SessionId,
    Tagged, Ticket,
};

use crate::legacy_util::{bounded_capacity, slice_from_ptr, slice_from_typed_ptr};

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
/// `BELOW_FLOOR`; `height` (the promoted tip's height) for `SWITCHED`;
/// `height` (the block's height) for `OUTSIDE_WINDOW`. The rest are zero.
/// `MISSING_BODIES` carries its indices beside the struct.
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
/// The door's past-cap hint: judged before the block was stored or
/// hashed. Never proof of a heavier chain. `height` is the depth, `by` the
/// cap.
pub const SHEKYL_INGEST_BEYOND_CAP: u32 = 6;
/// Stored, and the chain switched onto its branch.
pub const SHEKYL_INGEST_SWITCHED: u32 = 7;
/// Stored, and the switch was refused: a promoted block failed.
pub const SHEKYL_INGEST_PROMOTION_REFUSED: u32 = 8;
/// A stored heavier chain this node cannot follow: a pop met the undo
/// floor. `height` is the tip, `by` the floor.
pub const SHEKYL_INGEST_CANNOT_FOLLOW_BELOW_FLOOR: u32 = 9;
/// Listed bodies to ask for, by index.
pub const SHEKYL_INGEST_MISSING_BODIES: u32 = 10;
/// An earlier block in the span was refused.
pub const SHEKYL_INGEST_CANCELLED: u32 = 11;
/// The service stopped first.
pub const SHEKYL_INGEST_STOPPED: u32 = 12;
/// The block's seed is not one of the two caches this node holds. Local:
/// nothing was stored, nothing was hashed, and the session stays open.
pub const SHEKYL_INGEST_OUTSIDE_WINDOW: u32 = 13;
/// A stored heavier chain this node cannot follow: its fork is deeper than
/// the cap. `height` is the depth, `by` the cap.
pub const SHEKYL_INGEST_CANNOT_FOLLOW_BEYOND_CAP: u32 = 14;

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
/// An unbind called on a thread of the runtime that posts the replies.
/// It cannot wait for that runtime to drain, so it changes nothing: the
/// post stays bound and offers stay accepted. Unbind from another thread.
pub const SHEKYL_INGEST_REENTRANT: i32 = -3;

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
}

/// What the reply pump is asked to do. Tickets already queued are ahead of
/// a [`PumpMsg::Drain`] in the channel, so the drain posts them first.
enum PumpMsg {
    /// An accepted arrival. The pump waits for its one reply and posts it.
    Ticket { connection: u64, ticket: Ticket },
    /// Finish every ticket already accepted, then clear the post if `generation` is still current.
    Drain {
        generation: u64,
        done: std::sync::mpsc::SyncSender<()>,
    },
    /// The door was reinstalled. Finish what this pump holds and exit.
    /// The post stays: the new pump delivers through it.
    Stop,
}

struct Gate {
    /// Offers enqueue only while this is set. Unbind clears it before the
    /// drain, under this mutex and not across a wait, so an offer cannot
    /// accept a span the drain will not see.
    accepting: bool,
    pump: Option<tokio::sync::mpsc::UnboundedSender<PumpMsg>>,
    runtime: Option<tokio::runtime::Handle>,
}

static DOOR: Mutex<Option<Installed>> = Mutex::new(None);
static POST: Mutex<Option<Bound>> = Mutex::new(None);
/// Bumped on every bind and unbind. A drain clears the post only when the
/// generation it captured is still the current one, so a bind that landed
/// during the drain keeps its post.
static POST_GENERATION: AtomicU64 = AtomicU64::new(0);
static GATE: Mutex<Gate> = Mutex::new(Gate {
    accepting: false,
    pump: None,
    runtime: None,
});

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install the service's door, and the runtime its replies are awaited on:
/// the composition root's call, at the flip. A second install replaces the
/// first. The reply pump starts here, before any offer.
pub fn install(door: Door, runtime: tokio::runtime::Handle) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    runtime.spawn(reply_pump(rx));
    *lock(&DOOR) = Some(Installed { door });
    // The post lock is not held with the gate lock: bind takes them in
    // the other order.
    let post_bound = lock(&POST).is_some();
    let mut gate = lock(&GATE);
    if let Some(previous) = gate.pump.replace(tx) {
        let _stopped = previous.send(PumpMsg::Stop);
    }
    gate.runtime = Some(runtime);
    gate.accepting = post_bound;
}

/// Remove the installed door: every offer after is `UNBOUND`. The pump
/// stays until the next install, so an unbind can still drain replies the
/// service has already accepted.
pub fn uninstall() {
    *lock(&DOOR) = None;
    lock(&GATE).accepting = false;
}

/// Bind the post the replies are delivered through. A null `post` or `ctx`
/// unbinds: offers stop being accepted, replies already accepted are
/// posted, and then the post is cleared, all before this returns. Returns
/// 0, or [`SHEKYL_INGEST_REENTRANT`] for an unbind on a thread of the
/// replies' own runtime, which could not wait for them and changes
/// nothing.
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
    if bound.is_some() {
        {
            // The post and its generation change together, under the post
            // lock: a drain's check reads both under the same lock.
            let mut post = lock(&POST);
            *post = bound;
            POST_GENERATION.fetch_add(1, Ordering::AcqRel);
        }
        let mut gate = lock(&GATE);
        gate.accepting = gate.pump.is_some();
        return 0;
    }
    // The gate lock is not held with the post lock. Bind takes the post
    // first; this drops the gate before it touches the post.
    let pump = {
        let mut gate = lock(&GATE);
        let on_pump_runtime = match (gate.runtime.clone(), tokio::runtime::Handle::try_current()) {
            (Some(runtime), Ok(current)) => current.id() == runtime.id(),
            _ => false,
        };
        if on_pump_runtime {
            // Waiting for the drain here would block the runtime that
            // drains, and returning before it would let a post reach a
            // `ctx` the caller is free to release. Neither: refuse.
            return SHEKYL_INGEST_REENTRANT;
        }
        gate.accepting = false;
        gate.pump.clone()
    };
    let generation = {
        let _post = lock(&POST);
        POST_GENERATION.fetch_add(1, Ordering::AcqRel) + 1
    };
    let Some(pump) = pump else {
        clear_post_if(generation);
        return 0;
    };
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    // The pump posts what it already holds, then clears the post. A pump
    // that is already gone clears it here, or the wait below would never
    // return.
    if pump
        .send(PumpMsg::Drain {
            generation,
            done: done_tx,
        })
        .is_err()
    {
        clear_post_if(generation);
        return 0;
    }
    let _drained = done_rx.recv();
    0
}

/// The arrivals the service will accept now; 0 when no door is installed.
#[no_mangle]
pub extern "C" fn shekyl_ingest_room() -> u64 {
    lock(&DOOR).as_ref().map_or(0, |installed| {
        u64::try_from(installed.door.room()).unwrap_or(u64::MAX)
    })
}

/// Offer a span of `len` arrivals from `connection` (module docs).
/// `solicited` is nonzero for blocks this node asked for. Returns
/// `SHEKYL_INGEST_ACCEPTED` or a refusal code.
///
/// The door is taken first, so an unbound call does not read the store.
/// A span longer than the window is refused before the entries are read.
/// Lengths and null buffers are judged before a seat is taken, and the
/// block bytes are copied only after the door has reserved the span.
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
    if !lock(&GATE).accepting {
        return SHEKYL_INGEST_UNBOUND;
    }
    let door = {
        let installed = lock(&DOOR);
        let Some(installed) = installed.as_ref() else {
            return SHEKYL_INGEST_UNBOUND;
        };
        installed.door.clone()
    };
    // The window and the byte bound are the ceilings. A store the door
    // cannot read has no room, the same answer `reserve` gives.
    let Some(ceilings) = Ceilings::of(&door) else {
        return SHEKYL_INGEST_NO_ROOM;
    };
    if !ceilings.fits_span(len) {
        return SHEKYL_INGEST_NO_ROOM;
    }
    let Some(entries) = (unsafe { slice_from_typed_ptr(arrivals, len) }) else {
        return SHEKYL_INGEST_INVALID;
    };
    let origin = Origin::Peer {
        session: SessionId(connection),
        solicited: solicited != 0,
    };
    let lengths = match unsafe { ceilings.measure(entries, origin) } {
        Ok(lengths) => lengths,
        Err(CeilingFault::Oversize) => return SHEKYL_INGEST_OVERSIZE,
        Err(CeilingFault::Invalid) => return SHEKYL_INGEST_INVALID,
        Err(CeilingFault::PastWindow) => return SHEKYL_INGEST_NO_ROOM,
    };
    let reserved = match door.reserve(&lengths) {
        Ok(reserved) => reserved,
        Err(Refusal::NoRoom) => return SHEKYL_INGEST_NO_ROOM,
        Err(Refusal::Throttled) => return SHEKYL_INGEST_THROTTLED,
        Err(Refusal::Oversize) => return SHEKYL_INGEST_OVERSIZE,
    };
    // Copied out of C++'s buffers now: the reservation already holds the
    // seats, and nothing keeps a pointer past the return. A buffer that
    // fails this read gives the reservation back.
    let Some(span) = (unsafe { ceilings.copy(entries, origin) }) else {
        drop(reserved);
        return SHEKYL_INGEST_INVALID;
    };
    let gate = lock(&GATE);
    if !gate.accepting {
        drop(reserved);
        return SHEKYL_INGEST_UNBOUND;
    }
    let Some(pump) = gate.pump.clone() else {
        drop(reserved);
        return SHEKYL_INGEST_UNBOUND;
    };
    for ticket in reserved.commit(span) {
        let _queued = pump.send(PumpMsg::Ticket { connection, ticket });
    }
    SHEKYL_INGEST_ACCEPTED
}

/// `ptr` can be read for `len` bytes. A zero length names no bytes, so a
/// null pointer there is not a fault. Nothing is copied.
fn readable(ptr: *const u8, len: usize) -> bool {
    len == 0 || (!ptr.is_null() && isize::try_from(len).is_ok())
}

/// What an untrusted span may reserve before the door judges it.
///
/// The window is seats ([`Door::window`]). `max_bytes` is
/// [`Door::max_arrival_bytes`]. A body list is at most [`tx_names_in`]
/// the block blob.
struct Ceilings {
    window: usize,
    max_bytes: u64,
}

/// Why a span is not reserved. A seat is taken only for a successful measure.
enum CeilingFault {
    /// An arrival's bytes exceed the bound.
    Oversize,
    /// A buffer is missing, or the body list cannot fit in the block.
    Invalid,
    /// The span is longer than the window, so it can never be seated.
    PastWindow,
}

impl Ceilings {
    /// The door's ceilings. `None` is a store read the service has recorded.
    fn of(door: &Door) -> Option<Self> {
        Some(Self {
            window: door.window(),
            max_bytes: door.max_arrival_bytes()?,
        })
    }

    /// A span of `len` arrivals can be seated in this window.
    fn fits_span(&self, len: usize) -> bool {
        len <= self.window
    }

    /// The lengths `entries` name. Block bytes are not read.
    ///
    /// # Safety
    /// `entries` is a slice the caller already formed from a readable pointer.
    unsafe fn measure(
        &self,
        entries: &[ShekylIngestArrival],
        origin: Origin,
    ) -> Result<Vec<ArrivalLengths>, CeilingFault> {
        if !self.fits_span(entries.len()) {
            return Err(CeilingFault::PastWindow);
        }
        let Some(mut lengths) = capped_slots::<ArrivalLengths>(
            entries.len(),
            size_of::<ShekylIngestArrival>(),
            self.window,
        ) else {
            return Err(CeilingFault::PastWindow);
        };
        for entry in entries {
            lengths.push(unsafe { self.measure_one(entry, origin) }?);
        }
        Ok(lengths)
    }

    /// One arrival's lengths. The body list is reserved only after the
    /// block fits the byte bound and the list fits the names in that block.
    ///
    /// # Safety
    /// `entry`'s pointers are the caller's, checked here before any copy.
    unsafe fn measure_one(
        &self,
        entry: &ShekylIngestArrival,
        origin: Origin,
    ) -> Result<ArrivalLengths, CeilingFault> {
        if !readable(entry.block.ptr, entry.block.len) {
            return Err(CeilingFault::Invalid);
        }
        let Ok(block_len) = u64::try_from(entry.block.len) else {
            return Err(CeilingFault::Oversize);
        };
        if block_len > self.max_bytes {
            return Err(CeilingFault::Oversize);
        }
        let named = tx_names_in(entry.block.len);
        if entry.bodies_len > named {
            return Err(CeilingFault::Invalid);
        }
        let Some(blobs) = (unsafe { slice_from_typed_ptr(entry.bodies, entry.bodies_len) }) else {
            return Err(CeilingFault::Invalid);
        };
        let Some(mut body_lens) =
            capped_slots::<usize>(blobs.len(), size_of::<ShekylIngestBlob>(), named)
        else {
            return Err(CeilingFault::Invalid);
        };
        let mut carried = block_len;
        for blob in blobs {
            if !readable(blob.ptr, blob.len) {
                return Err(CeilingFault::Invalid);
            }
            let Ok(n) = u64::try_from(blob.len) else {
                return Err(CeilingFault::Oversize);
            };
            let Some(next) = carried.checked_add(n) else {
                return Err(CeilingFault::Oversize);
            };
            if next > self.max_bytes {
                return Err(CeilingFault::Oversize);
            }
            carried = next;
            body_lens.push(blob.len);
        }
        Ok(ArrivalLengths {
            tag: ArrivalTag(entry.tag),
            origin,
            block_len: entry.block.len,
            body_lens,
        })
    }

    /// Copy `entries` into owned arrivals, under the same ceilings.
    ///
    /// # Safety
    /// Each buffer was accepted by [`Self::measure`]: a non-zero length has a
    /// non-null pointer and fits `isize`, and the byte total fits the bound.
    unsafe fn copy(&self, entries: &[ShekylIngestArrival], origin: Origin) -> Option<Vec<Arrival>> {
        if !self.fits_span(entries.len()) {
            return None;
        }
        let mut span =
            capped_slots::<Arrival>(entries.len(), size_of::<ShekylIngestArrival>(), self.window)?;
        for entry in entries {
            let named = tx_names_in(entry.block.len);
            if entry.bodies_len > named {
                return None;
            }
            let block = unsafe { slice_from_ptr(entry.block.ptr, entry.block.len) }?.to_vec();
            let blobs = unsafe { slice_from_typed_ptr(entry.bodies, entry.bodies_len) }?;
            let mut bodies =
                capped_slots::<Vec<u8>>(blobs.len(), size_of::<ShekylIngestBlob>(), named)?;
            for blob in blobs {
                bodies.push(unsafe { slice_from_ptr(blob.ptr, blob.len) }?.to_vec());
            }
            span.push(Arrival {
                tag: ArrivalTag(entry.tag),
                origin,
                block,
                bodies,
            });
        }
        Some(span)
    }
}

/// `count` slots, when `max_count` elements of `stride` bytes is the budget.
///
/// [`bounded_capacity`] checks that byte budget. `max_count` is the protocol
/// ceiling, so the budget stays that many wire elements.
fn capped_slots<T>(count: usize, stride: usize, max_count: usize) -> Option<Vec<T>> {
    bounded_capacity(count, stride, max_count.checked_mul(stride)?)
}

/// Post every accepted reply. A drain finishes the tickets queued ahead of
/// it and then clears the post, when that unbind is still the latest one.
async fn reply_pump(mut rx: tokio::sync::mpsc::UnboundedReceiver<PumpMsg>) {
    let mut inflight = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    None | Some(PumpMsg::Stop) => {
                        while inflight.join_next().await.is_some() {}
                        break;
                    }
                    Some(PumpMsg::Ticket { connection, ticket }) => {
                        inflight.spawn(async move {
                            post_reply(connection, ticket.reply().await);
                        });
                    }
                    Some(PumpMsg::Drain { generation, done }) => {
                        while inflight.join_next().await.is_some() {}
                        clear_post_if(generation);
                        let _posted = done.send(());
                    }
                }
            }
            joined = inflight.join_next(), if !inflight.is_empty() => {
                // A panicked reply task must not take the pump with it.
                // The arrival's slot still answered on the service side.
                let _finished = joined;
            }
        }
    }
}

/// Clear the post when `generation` is still the unbind that asked. The
/// check and the clear are under the post lock, where a bind changes both
/// the post and the generation, so a bind that lands during a drain keeps
/// its post.
fn clear_post_if(generation: u64) {
    let mut post = lock(&POST);
    if POST_GENERATION.load(Ordering::Acquire) == generation {
        *post = None;
    }
}

/// `connection` closed: its bucket is forgotten.
#[no_mangle]
pub extern "C" fn shekyl_ingest_session_closed(connection: u64) {
    if let Some(installed) = lock(&DOOR).as_ref() {
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
        Reply::CannotFollow(CannotFollow::BeyondCap(beyond)) => {
            out.kind = SHEKYL_INGEST_CANNOT_FOLLOW_BEYOND_CAP;
            out.height = beyond.depth.to_raw();
            out.by = beyond.cap.to_raw();
        }
        Reply::CannotFollow(CannotFollow::BelowFloor { tip, floor }) => {
            out.kind = SHEKYL_INGEST_CANNOT_FOLLOW_BELOW_FLOOR;
            out.height = tip.to_raw();
            out.by = floor.to_raw();
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
        Reply::OutsideWindow { height } => {
            out.kind = SHEKYL_INGEST_OUTSIDE_WINDOW;
            out.height = height.to_raw();
        }
    }
    (out, indices)
}

/// Post one reply through the bound callback. Unbound, it has no reader.
fn post_reply(connection: u64, tagged: Tagged) {
    let (reply, indices) = encode(connection, tagged);
    let bound = lock(&POST);
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
