// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the live relay zone — RP-3a of `DAEMON_RELAY_PRIVACY.md`.
//!
//! The C++ `cryptonote::levin::notify` forwards here; the scheduling logic lives
//! in `shekyl-relay`. Transaction bodies cross as opaque blobs, because framing,
//! padding and the socket stay C++ (§18.2).
//!
//! # Why there is no `Effect` marshalling
//!
//! [`shekyl_relay::Effect`] is an enum with payloads, and moving one across a C
//! ABI means a tag plus offsets plus variant decoding on the far side — which is
//! *logic*, in the one layer §18.4a requires to be pure forwarding. That layer is
//! also the layer the 33-gtest oracle structurally cannot see, so a decoding bug
//! there hides underneath a green suite.
//!
//! So the enum is not marshalled. [`shekyl_relay_zone_poll`] takes one callback
//! **per variant** and dispatches in Rust, where the compiler checks the match.
//! C++ receives calls that are already dispatched and carry only scalars and
//! byte spans. The hazard is removed rather than guarded — the same move as
//! deriving `connection_count` instead of caching it, applied to marshalling.
//!
//! [`ShekylRelayBlob`] is the one struct that crosses, and it is not a
//! counter-example: the hazard named above is reading a *tag* and interpreting
//! a union by it. A fixed two-field span has no tag, and it buys an explicit
//! batch boundary — see the type's own note for why inferring that boundary on
//! the C++ side would be the worse trade.
//!
//! # The one deliberate cache
//!
//! `live_stems` is published as an [`AtomicUsize`] for off-task readers, because
//! `notify::get_status()` is callable from any thread. That is a copy of a fact
//! the zone derives, and it is the *legitimate* exception to
//! derive-don't-cache: the alternative — readers deriving it live — means
//! reaching into the map while the owning task mutates it, which is precisely
//! the pull-races-mutation hazard §18.5 finding 3 closed. What keeps it honest
//! is **single writer**: only [`RelayZoneHandle::publish`] writes it, and only
//! the mutating exports call that.

use std::os::raw::c_void;
use std::slice;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use shekyl_relay::{Driver, Effect, FluffReach, RelayPlan, TxBlob, Zone};
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::PeerDirection;
use shekyl_relay_privacy::stem_map::ConnectionId;

use crate::secure_relay_rng::SecureRelayRng;

/// The nil UUID: an absent stem slot, or a locally originated transaction.
const NIL: [u8; 16] = [0u8; 16];

/// Forward to the successor written into `out_dest`.
pub const SHEKYL_RELAY_PLAN_STEM: i32 = 0;
/// Stem-eligible, but nothing is routable yet — refresh connections and re-plan.
pub const SHEKYL_RELAY_PLAN_NO_ROUTE: i32 = 1;
/// Settled for this epoch: fluff. Retrying cannot change the answer.
pub const SHEKYL_RELAY_PLAN_FLUFF_EPOCH: i32 = 2;

/// One transaction blob: pointer and length, borrowed for the call.
///
/// Two scalars, and the reason a struct is acceptable here where a marshalled
/// `Effect` was not: the hazard §18.4a names is *variant decoding* — reading a
/// tag and interpreting a union by it — and a fixed two-field span carries no
/// tag to misread. It buys the property that matters more, below.
#[repr(C)]
pub struct ShekylRelayBlob {
    /// Start of `len` readable bytes, valid only for the duration of the call.
    pub ptr: *const u8,
    /// Length in bytes.
    pub len: usize,
}

/// Called once per released fluff batch, with the peer's **whole** batch.
///
/// Whole, not blob-by-blob: the daemon sends a peer's batch as a *single* levin
/// notification carrying every transaction, so a per-blob callback would turn
/// one message into N. The alternative — stream blobs and have C++ infer where
/// each peer's run ends — puts inference in the one layer that must be pure
/// forwarding, and would break silently if two batches for one peer were ever
/// emitted non-contiguously. The batch boundary is explicit instead.
pub type FluffCb =
    extern "C" fn(ctx: *mut c_void, peer: *const u8, blobs: *const ShekylRelayBlob, n: usize);

/// Called when the stem slots change: `slots` is `count` × 16 bytes, in slot
/// order, nil for an empty slot. Order and nils are load-bearing — the consumer
/// indexes by position (§16.1 contract 3).
pub type SlotsCb = extern "C" fn(ctx: *mut c_void, slots: *const u8, count: usize);

/// Opaque zone handle. C++ holds `*mut RelayZoneHandle` and nothing else.
pub struct RelayZoneHandle {
    driver: Driver,
    rng: SecureRelayRng,
    /// Published derived fact for off-task readers. Single writer: `publish`.
    live_stems: AtomicUsize,
}

impl RelayZoneHandle {
    /// Republish the derived stem count. The **only** writer of `live_stems`;
    /// every mutating export ends with this call.
    fn publish(&self) {
        self.live_stems
            .store(self.driver.zone().live_stems(), Ordering::Release);
    }
}

/// Hand each effect to the matching callback. Dispatch happens here, in Rust,
/// so no variant tag ever crosses the boundary — the reason the C++ side has no
/// decoding to get wrong (§18.4a).
fn dispatch(effects: Vec<Effect>, ctx: *mut c_void, fluff: FluffCb, slots: SlotsCb) {
    for effect in effects {
        match effect {
            Effect::Fluff { peer, blobs } => {
                // `blobs` outlives the call, so the spans stay valid for it.
                let spans: Vec<ShekylRelayBlob> = blobs
                    .iter()
                    .map(|b| ShekylRelayBlob {
                        ptr: b.as_ptr(),
                        len: b.len(),
                    })
                    .collect();
                fluff(ctx, peer.as_bytes().as_ptr(), spans.as_ptr(), spans.len());
            }
            Effect::StemSlots(list) => {
                let mut flat = Vec::with_capacity(list.len() * 16);
                for slot in &list {
                    flat.extend_from_slice(&slot.map_or(NIL, |id| *id.as_bytes()));
                }
                slots(ctx, flat.as_ptr(), list.len());
            }
        }
    }
}

/// # Safety
/// `ids` must point to `n * 16` readable bytes, or be null with `n == 0`.
unsafe fn read_ids(ids: *const u8, n: usize) -> Vec<ConnectionId> {
    let Some(len) = n.checked_mul(16) else {
        debug_assert!(false, "read_ids: n * 16 overflows");
        return Vec::new();
    };
    if len == 0 || ids.is_null() {
        return Vec::new();
    }
    let bytes = slice::from_raw_parts(ids, len);
    (0..n)
        .filter_map(|i| {
            let mut b = [0u8; 16];
            b.copy_from_slice(&bytes[i * 16..i * 16 + 16]);
            (b != NIL).then(|| ConnectionId::from_bytes(b))
        })
        .collect()
}

/// Read one connection id, mapping "no id" to `None`.
///
/// **Two encodings arrive here and both mean "no id".** The nil UUID is the
/// one production uses: `levin_notify` always passes a real `boost::uuids::uuid`
/// and sets it nil for a locally originated transaction, so nil-means-local is a
/// live contract, not a convenience. A null pointer is accepted as well, purely
/// so a caller cannot turn a missing argument into a dereference at an FFI
/// boundary — no C++ call site passes one.
///
/// # Safety
/// `p` must point to 16 readable bytes, or be null.
unsafe fn read_id(p: *const u8) -> Option<ConnectionId> {
    if p.is_null() {
        return None;
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(slice::from_raw_parts(p, 16));
    (b != NIL).then(|| ConnectionId::from_bytes(b))
}

/// Open a zone. Release with [`shekyl_relay_zone_free`].
///
/// The epoch length is a parameter because the daemon runs two zone flavours
/// with different ones — `CRYPTONOTE_DANDELIONPP_MIN_EPOCH` (600 s) on public
/// zones, `CRYPTONOTE_NOISE_MIN_EPOCH` (300 s) on i2p/tor. C++ already selects
/// between them at construction; passing the choice through keeps one owner of
/// it rather than a second copy of the rule here.
///
/// `outbound_fluff_only` is the i2p/tor rule: fluff to outbound connections
/// only, never to an inbound peer. It is a property of the *network* rather than
/// of noise mode — a hidden-service zone with noise disabled still needs it — so
/// it is passed rather than derived from the epoch parameters. See
/// [`FluffReach::OutboundOnly`].
///
/// Returns null on input a zone cannot be built from: a `stems` that would
/// overflow the slot arithmetic, or a zero epoch — which is not merely useless
/// but harmful, since every wake would find the epoch expired and the daemon's
/// relay timer would spin. The caller treats null as a startup logic error.
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_new(
    now_ms: u64,
    stems: usize,
    min_epoch_secs: u32,
    epoch_jitter_secs: u32,
    outbound_fluff_only: bool,
) -> *mut RelayZoneHandle {
    if stems == usize::MAX || min_epoch_secs == 0 {
        return std::ptr::null_mut();
    }
    let params = DandelionParams {
        min_epoch_secs,
        epoch_jitter_secs,
        ..DandelionParams::inherited()
    };
    let reach = if outbound_fluff_only {
        FluffReach::OutboundOnly
    } else {
        FluffReach::EveryPeer
    };
    let mut rng = SecureRelayRng;
    let zone = Zone::new(params, stems, reach, now_ms, &mut rng);
    let handle = RelayZoneHandle {
        driver: Driver::new(zone),
        rng,
        live_stems: AtomicUsize::new(0),
    };
    handle.publish();
    Box::into_raw(Box::new(handle))
}

/// Free a zone. Null is a no-op; free exactly once.
///
/// # Safety
/// `handle` must come from [`shekyl_relay_zone_new`] and not yet be freed.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_free(handle: *mut RelayZoneHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// A peer completed its handshake.
///
/// A nil or null `id` is ignored: neither names a connection to track.
///
/// # Safety
/// `handle` must be live; `id` must point to 16 readable bytes, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_on_handshake(
    handle: *mut RelayZoneHandle,
    id: *const u8,
    is_income: bool,
) {
    if handle.is_null() {
        return;
    }
    let Some(peer) = read_id(id) else { return };
    let direction = if is_income {
        PeerDirection::Inbound
    } else {
        PeerDirection::Outbound
    };
    let h = &mut *handle;
    h.driver.zone_mut().on_handshake_complete(peer, direction);
    h.publish();
}

/// A peer disconnected.
///
/// A nil or null `id` is ignored: neither names a connection to forget.
///
/// # Safety
/// `handle` must be live; `id` must point to 16 readable bytes, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_on_close(handle: *mut RelayZoneHandle, id: *const u8) {
    if handle.is_null() {
        return;
    }
    let Some(peer) = read_id(id) else { return };
    let h = &mut *handle;
    h.driver.zone_mut().on_connection_close(&peer);
    h.publish();
}

/// Stem slots backed by a live peer — the inherited `connection_count`.
///
/// Reads the published atomic, so it is safe from any thread. A null handle
/// reads 0.
///
/// # Safety
/// `handle` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_live_stems(handle: *const RelayZoneHandle) -> usize {
    if handle.is_null() {
        return 0;
    }
    (*handle).live_stems.load(Ordering::Acquire)
}

/// The next time the driver has work, in the caller's millisecond clock.
///
/// # Safety
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_next_wake(handle: *const RelayZoneHandle) -> u64 {
    if handle.is_null() {
        return 0;
    }
    (*handle).driver.next_wake()
}

/// Decide what to do with a batch: `SHEKYL_RELAY_PLAN_STEM` (writing the
/// successor into `out_dest`), `..._NO_ROUTE`, or `..._FLUFF_EPOCH`.
///
/// Three-way rather than a bool because the caller must distinguish a
/// *transient* failure to route — refresh connections and re-plan — from an
/// epoch decision no refresh can change, and because the two produce different
/// `relay_method` events. The alternative is C++ re-evaluating
/// `!fluffing || local_origin` for itself, which duplicates the RD-4 predicate
/// (§16.1); see [`RelayPlan`] for the full reasoning.
///
/// A null handle reports `NO_ROUTE`: nothing is routable through a zone that
/// does not exist, and the caller's fallback is then the safe one.
///
/// `source` is the relaying peer, or the **nil UUID** for a transaction this
/// node originated — the distinction RD-4 turns on, so it is a contract rather
/// than a convention. Null is accepted and means the same thing.
///
/// Production notify prefers [`shekyl_relay_zone_plan_relay_with_refresh`],
/// which owns the one mid-call refresh on `NO_ROUTE`. This pure plan remains
/// for callers that already refreshed (send-failure retry) and for tests.
///
/// # Safety
/// `handle` must be live; `source` must point to 16 readable bytes or be null;
/// `out_dest` must point to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_plan_relay(
    handle: *mut RelayZoneHandle,
    source: *const u8,
    local_origin: bool,
    out_dest: *mut u8,
) -> i32 {
    if handle.is_null() || out_dest.is_null() {
        return SHEKYL_RELAY_PLAN_NO_ROUTE;
    }
    let h = &mut *handle;
    let source = read_id(source);
    let plan = h
        .driver
        .zone_mut()
        .plan_relay(source, local_origin, &mut h.rng);
    h.publish();
    write_plan(plan, out_dest)
}

/// Plan a relay; on `NO_ROUTE`, merge `outbound` into the stem map once and
/// re-plan, delivering new slots through `on_slots` if the set changed.
///
/// This is the production path for `dandelionpp_notify`: the refresh policy
/// lives in Rust with the rest of zone scheduling, so the C++ shim only offers
/// the outbound snapshot and performs transport. A settled fluff epoch does not
/// refresh. See [`shekyl_relay::Zone::plan_relay_with_refresh`].
///
/// # Safety
/// `handle` must be live; `source` must point to 16 readable bytes or be null;
/// `outbound` must point to `n * 16` readable bytes or be null with `n == 0`;
/// `out_dest` must point to 16 writable bytes; the slots callback must be valid
/// for the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_plan_relay_with_refresh(
    handle: *mut RelayZoneHandle,
    source: *const u8,
    local_origin: bool,
    outbound: *const u8,
    n: usize,
    out_dest: *mut u8,
    ctx: *mut c_void,
    on_slots: SlotsCb,
) -> i32 {
    if handle.is_null() || out_dest.is_null() {
        return SHEKYL_RELAY_PLAN_NO_ROUTE;
    }
    let peers = read_ids(outbound, n);
    let h = &mut *handle;
    let source = read_id(source);
    let (plan, effects) =
        h.driver
            .plan_relay_with_refresh(source, local_origin, &peers, &mut h.rng);
    h.publish();
    dispatch(effects, ctx, noop_fluff, on_slots);
    write_plan(plan, out_dest)
}

/// Write a plan into `out_dest` and return its C code.
///
/// # Safety
/// `out_dest` must point to 16 writable bytes.
unsafe fn write_plan(plan: RelayPlan, out_dest: *mut u8) -> i32 {
    match plan {
        RelayPlan::Stem(destination) => {
            std::ptr::copy_nonoverlapping(destination.as_bytes().as_ptr(), out_dest, 16);
            SHEKYL_RELAY_PLAN_STEM
        }
        RelayPlan::NoRoute => {
            std::ptr::copy_nonoverlapping(NIL.as_ptr(), out_dest, 16);
            SHEKYL_RELAY_PLAN_NO_ROUTE
        }
        RelayPlan::FluffEpoch => {
            std::ptr::copy_nonoverlapping(NIL.as_ptr(), out_dest, 16);
            SHEKYL_RELAY_PLAN_FLUFF_EPOCH
        }
    }
}

/// Merge the caller's current outbound set into the stem map mid-epoch,
/// delivering the new slots through `on_slots` if the set changed.
///
/// Ports `update_channels::run`. On a public zone this is the only thing that
/// ever populates the map: `notify` is constructed before any peer connects, so
/// without it every transaction would fluff.
///
/// # Safety
/// `handle` must be live; `outbound` must point to `n * 16` readable bytes or be
/// null with `n == 0`; the callback must be valid for the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_update_stems(
    handle: *mut RelayZoneHandle,
    outbound: *const u8,
    n: usize,
    ctx: *mut c_void,
    on_slots: SlotsCb,
) {
    if handle.is_null() {
        return;
    }
    let peers = read_ids(outbound, n);
    let h = &mut *handle;
    let effects = h.driver.update_stems(&peers, &mut h.rng);
    h.publish();
    dispatch(effects, ctx, noop_fluff, on_slots);
}

/// Accept a batch of transaction blobs for fluffing to every peer but `source`.
///
/// Returns **how many peers took the batch**, so the caller can report the
/// inherited "no available connections" warning. That answer is a property of
/// the batch, not of any one blob, which is the other reason this takes the
/// whole batch: offered blob-by-blob the caller would get N identical answers
/// and have to decide what to do with them.
///
/// Each valid span is copied into a shared [`TxBlob`] once; peer queues clone
/// the handle rather than the bytes.
///
/// # Safety
/// `handle` must be live; `blobs` must point to `n` `ShekylRelayBlob` values
/// (or be null with `n == 0`). For each element: if `len == 0` the span is an
/// empty blob and `ptr` may be null; if `len > 0` then `ptr` must be non-null
/// and point to `len` readable bytes. A null `ptr` with non-zero `len` is
/// rejected for the whole call (returns 0, queues nothing). `source` must
/// point to 16 readable bytes, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_queue_fluff(
    handle: *mut RelayZoneHandle,
    now_ms: u64,
    blobs: *const ShekylRelayBlob,
    n: usize,
    source: *const u8,
) -> usize {
    if handle.is_null() || n == 0 {
        return 0;
    }
    if blobs.is_null() {
        return 0;
    }
    let Some(txs) = read_blobs(blobs, n) else {
        return 0;
    };
    let source = read_id(source);
    let h = &mut *handle;
    let accepted = h
        .driver
        .zone_mut()
        .queue_fluff(&txs, source, now_ms, &mut h.rng);
    h.publish();
    accepted
}

/// Copy `n` FFI spans into shared blobs. `None` if any span is null with a
/// non-zero length — fail closed rather than drop individual txs silently.
///
/// # Safety
/// `blobs` must point to `n` readable `ShekylRelayBlob` values. Each non-empty
/// span's `ptr` must be non-null and cover `len` bytes.
unsafe fn read_blobs(blobs: *const ShekylRelayBlob, n: usize) -> Option<Vec<TxBlob>> {
    let mut out = Vec::with_capacity(n);
    for b in slice::from_raw_parts(blobs, n) {
        if b.len == 0 {
            // Empty is legitimate; `from_raw_parts(null, 0)` is UB, so use the
            // empty Arc without touching the pointer.
            out.push(TxBlob::from([] as [u8; 0]));
            continue;
        }
        if b.ptr.is_null() {
            // Fail closed: do not copy a non-empty span from a null pointer.
            // Production C++ always passes live `blobdata`; this guards a second
            // caller and turns an immediate UB path into a clean 0 return.
            return None;
        }
        out.push(Arc::from(slice::from_raw_parts(b.ptr, b.len)));
    }
    Some(out)
}

/// Run every step due at `now_ms`, delivering results through the callbacks.
///
/// # Safety
/// `handle` must be live; `outbound` must point to `n * 16` readable bytes or be
/// null with `n == 0`; the callbacks must be valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_poll(
    handle: *mut RelayZoneHandle,
    now_ms: u64,
    outbound: *const u8,
    n: usize,
    ctx: *mut c_void,
    on_fluff: FluffCb,
    on_slots: SlotsCb,
) {
    if handle.is_null() {
        return;
    }
    let peers = read_ids(outbound, n);
    let h = &mut *handle;
    let effects = h.driver.poll(now_ms, &peers, &mut h.rng);
    h.publish();
    dispatch(effects, ctx, on_fluff, on_slots);
}

/// Release every pending fluff batch — what `notify::run_fluff()` drives.
///
/// # Safety
/// `handle` must be live; the callback must be valid for the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_force_fluff(
    handle: *mut RelayZoneHandle,
    now_ms: u64,
    ctx: *mut c_void,
    on_fluff: FluffCb,
) {
    if handle.is_null() {
        return;
    }
    let h = &mut *handle;
    let effects = h.driver.force_fluff(now_ms);
    h.publish();
    dispatch(effects, ctx, on_fluff, noop_slots);
}

/// Start a new epoch immediately — what `notify::run_epoch()` drives.
///
/// # Safety
/// `handle` must be live; `outbound` must point to `n * 16` readable bytes or be
/// null with `n == 0`; the callback must be valid for the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_force_epoch(
    handle: *mut RelayZoneHandle,
    now_ms: u64,
    outbound: *const u8,
    n: usize,
    ctx: *mut c_void,
    on_slots: SlotsCb,
) {
    if handle.is_null() {
        return;
    }
    let peers = read_ids(outbound, n);
    let h = &mut *handle;
    let effects = h.driver.force_epoch(now_ms, &peers, &mut h.rng);
    h.publish();
    dispatch(effects, ctx, noop_fluff, on_slots);
}

/// Placeholders for the exports that cannot produce the other variant. Reaching
/// one is a dispatch bug, so they assert in debug rather than failing silently.
extern "C" fn noop_fluff(_: *mut c_void, _: *const u8, _: *const ShekylRelayBlob, _: usize) {
    debug_assert!(false, "force_epoch produced a Fluff effect");
}
extern "C" fn noop_slots(_: *mut c_void, _: *const u8, _: usize) {
    debug_assert!(false, "force_fluff produced a StemSlots effect");
}

#[cfg(test)]
mod tests;
