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

use shekyl_relay::{Driver, Effect, FluffReach, RelayPlan, Zone};
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::rng::RelayRng;
use shekyl_relay_privacy::schedule::PeerDirection;
use shekyl_relay_privacy::stem_map::ConnectionId;

/// The nil UUID: an absent stem slot, or a locally originated transaction.
const NIL: [u8; 16] = [0u8; 16];

/// Forward to the successor written into `out_dest`.
pub const SHEKYL_RELAY_PLAN_STEM: i32 = 0;
/// Stem-eligible, but nothing is routable yet — refresh connections and re-plan.
pub const SHEKYL_RELAY_PLAN_NO_ROUTE: i32 = 1;
/// Settled for this epoch: fluff. Retrying cannot change the answer.
pub const SHEKYL_RELAY_PLAN_FLUFF_EPOCH: i32 = 2;

/// Production RNG — OS entropy, matching the C++ `crypto::random_device` the
/// ported scheduling used. Never the deterministic `SplitMix64`.
struct SecureRelayRng;

impl RelayRng for SecureRelayRng {
    fn next_u64(&mut self) -> u64 {
        use rand::RngCore;
        rand::rngs::OsRng.next_u64()
    }
}

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
/// # Safety
/// `handle` must be live; `blobs` must point to `n` spans, each readable for
/// its own length; `source` must point to 16 readable bytes, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_queue_fluff(
    handle: *mut RelayZoneHandle,
    now_ms: u64,
    blobs: *const ShekylRelayBlob,
    n: usize,
    source: *const u8,
) -> usize {
    if handle.is_null() || blobs.is_null() || n == 0 {
        return 0;
    }
    let txs: Vec<Vec<u8>> = slice::from_raw_parts(blobs, n)
        .iter()
        .map(|b| slice::from_raw_parts(b.ptr, b.len).to_vec())
        .collect();
    let source = read_id(source);
    let h = &mut *handle;
    let accepted = h
        .driver
        .zone_mut()
        .queue_fluff(&txs, source, now_ms, &mut h.rng);
    h.publish();
    accepted
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
mod tests {
    use super::*;
    use std::cell::RefCell;

    // The "C++ side", simulated: recording callbacks that capture exactly what
    // crosses the boundary. This is the Effect seam test §18.4a asks for, and it
    // runs without a daemon build — which is what lets the transparency check
    // gate the expensive oracle rather than trail it.
    #[derive(Default)]
    struct Recorder {
        fluffed: Vec<([u8; 16], Vec<Vec<u8>>)>,
        slots: Vec<Vec<[u8; 16]>>,
    }

    thread_local! {
        static REC: RefCell<Recorder> = RefCell::new(Recorder::default());
    }

    extern "C" fn rec_fluff(
        _: *mut c_void,
        peer: *const u8,
        blobs: *const ShekylRelayBlob,
        n: usize,
    ) {
        let mut p = [0u8; 16];
        unsafe { p.copy_from_slice(slice::from_raw_parts(peer, 16)) };
        let batch = unsafe { slice::from_raw_parts(blobs, n) }
            .iter()
            .map(|b| unsafe { slice::from_raw_parts(b.ptr, b.len) }.to_vec())
            .collect();
        REC.with(|r| r.borrow_mut().fluffed.push((p, batch)));
    }

    extern "C" fn rec_slots(_: *mut c_void, slots: *const u8, count: usize) {
        let flat = unsafe { slice::from_raw_parts(slots, count * 16) };
        let list = (0..count)
            .map(|i| {
                let mut s = [0u8; 16];
                s.copy_from_slice(&flat[i * 16..i * 16 + 16]);
                s
            })
            .collect();
        REC.with(|r| r.borrow_mut().slots.push(list));
    }

    fn reset() {
        REC.with(|r| *r.borrow_mut() = Recorder::default());
    }

    fn id(byte: u8) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = byte;
        b
    }

    #[test]
    fn fluff_effects_cross_with_peer_and_payload_intact() {
        reset();
        unsafe {
            let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
            shekyl_relay_zone_on_handshake(h, id(1).as_ptr(), true);
            let blob = [0xAB, 0xCD, 0xEF];
            let batch = [ShekylRelayBlob {
                ptr: blob.as_ptr(),
                len: blob.len(),
            }];
            assert_eq!(
                shekyl_relay_zone_queue_fluff(h, 0, batch.as_ptr(), 1, std::ptr::null()),
                1,
                "the one connected peer took the batch"
            );
            shekyl_relay_zone_force_fluff(h, 0, std::ptr::null_mut(), rec_fluff);
            shekyl_relay_zone_free(h);
        }
        REC.with(|r| {
            let rec = r.borrow();
            assert_eq!(rec.fluffed.len(), 1, "one batch to one peer");
            assert_eq!(rec.fluffed[0].0, id(1), "peer id crossed intact");
            assert_eq!(
                rec.fluffed[0].1,
                vec![vec![0xAB, 0xCD, 0xEF]],
                "payload intact"
            );
        });
    }

    #[test]
    fn a_peers_batch_crosses_as_one_call_sorted_and_deduplicated() {
        // Two properties the daemon depends on, neither visible to a test that
        // only checks the transactions arrived:
        //
        // 1. **One call per peer.** The batch becomes a single levin
        //    notification carrying every transaction. Delivered blob-by-blob it
        //    would become N notifications — same bytes on the wire, N times the
        //    messages, and a per-peer message count that leaks how many
        //    transactions were batched together.
        // 2. **Sorted and de-duplicated**, which the inherited code did at the
        //    send site under the comment "don't leak receive order". Receive
        //    order is an observable: it is the order a relaying node saw
        //    transactions arrive, and forwarding it hands that ordering to
        //    every peer downstream.
        reset();
        unsafe {
            let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
            shekyl_relay_zone_on_handshake(h, id(1).as_ptr(), true);
            // Offered high-to-low, with a repeat: order and duplication both
            // have to be removed for the assertion below to hold.
            let raw = [[0x33u8], [0x11], [0x22], [0x11]];
            let batch: Vec<ShekylRelayBlob> = raw
                .iter()
                .map(|b| ShekylRelayBlob {
                    ptr: b.as_ptr(),
                    len: 1,
                })
                .collect();
            shekyl_relay_zone_queue_fluff(h, 0, batch.as_ptr(), batch.len(), std::ptr::null());
            shekyl_relay_zone_force_fluff(h, 0, std::ptr::null_mut(), rec_fluff);
            shekyl_relay_zone_free(h);
        }
        REC.with(|r| {
            let rec = r.borrow();
            assert_eq!(rec.fluffed.len(), 1, "one call carries the whole batch");
            assert_eq!(
                rec.fluffed[0].1,
                vec![vec![0x11], vec![0x22], vec![0x33]],
                "sorted ascending with the duplicate removed — not receive order"
            );
        });
    }

    /// **Sole witness — do not delete as redundant. Read this before touching it.**
    ///
    /// This is the only test in the tree asserting that the stem-slot snapshot
    /// crosses the boundary in **index order with nils in position**. Nothing
    /// else covers it, and in particular the 33 `levin_notify` gtests do not:
    /// they assert **counts** (`EXPECT_EQ(2u, sent)`, `connections_filled`) and
    /// that a stem lands on an *outbound* peer — never that noise channel `i` is
    /// bound to stem slot `i` (`DAEMON_RELAY_PRIVACY.md` §18.4b, finding 2).
    /// Count assertions look like coverage and are not.
    ///
    /// The property is contract 3 (§16.1): `update_channels::post` computes
    /// `i = id - begin()` and posts to `channels[i]`, so a snapshot that
    /// compacted a nil away or reordered slots would silently bind covert
    /// channels to the wrong connections — no crash, no failing count, wrong
    /// peers.
    ///
    /// **RP-3b is the round that consumes this positionally**, and it is also
    /// the round where the inherited names are least trustworthy (`run_stems`
    /// cancels noise timers). So the reader most likely to consider this test
    /// redundant is the one porting the covert path, looking at count-asserting
    /// gtests, three commits deep. If the property ever becomes genuinely
    /// covered elsewhere, delete this test *in the commit that adds that
    /// coverage* and say so — not before.
    ///
    /// **Negative-controlled.** Two bugs were injected into `dispatch` and both
    /// fail this test: compacting the nil away, and reversing slot order. That
    /// check is the reason the body looks the way it does — an earlier version
    /// carried this same docstring while never producing a nil at all, and
    /// caught neither bug. A seal that says "sole witness" over a body that does
    /// not test the property is worse than no test, because it tells the next
    /// reader the coverage already exists.
    #[test]
    fn stem_slots_cross_in_index_order_with_nils_in_position() {
        // Ground truth is read from the zone directly, NOT from the pushed
        // snapshot, and that is load-bearing. An earlier version of this test
        // derived which peer to keep from the pushed array — which made a
        // *reversal* self-consistent and undetectable, because the expectation
        // travelled through the very transform under test. A marshalling test
        // whose expected value is computed from the marshalled output can only
        // ever check that the output equals itself.
        fn truth(h: *const RelayZoneHandle) -> Vec<[u8; 16]> {
            unsafe { &*h }
                .driver
                .zone()
                .stem_slots()
                .iter()
                .map(|s| s.map_or(NIL, |id| *id.as_bytes()))
                .collect()
        }

        reset();
        let (filled, after) = unsafe {
            let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
            let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
            shekyl_relay_zone_force_epoch(h, 0, peers.as_ptr(), 3, std::ptr::null_mut(), rec_slots);
            let filled = REC.with(|r| r.borrow().slots[0].clone());
            assert_eq!(
                filled,
                truth(h),
                "the pushed snapshot must be the zone's slots, in the zone's order"
            );

            // Now empty a slot and offer no replacement: re-offer ONLY the peer
            // in slot 1. Slot 0's peer is gone with nothing to backfill it, so
            // the map holds a hole — which is the state this test exists for,
            // and which a snapshot of three-candidates-into-two-slots never
            // reaches. `dispatch` maps `None` to nil via `map_or`; swap that for
            // anything that skips instead and the hole compacts, silently
            // shifting slot 1's peer onto covert channel 0.
            let keep = filled[1];
            shekyl_relay_zone_update_stems(h, keep.as_ptr(), 1, std::ptr::null_mut(), rec_slots);
            let after = REC.with(|r| r.borrow().slots.last().cloned());
            if let Some(after) = &after {
                assert_eq!(
                    *after,
                    truth(h),
                    "with a hole in it, the pushed snapshot must still be the \
                     zone's slots in the zone's order"
                );
            }
            shekyl_relay_zone_free(h);
            (filled, after)
        };

        assert_eq!(filled.len(), 2, "width preserved across the boundary");
        for s in &filled {
            assert_ne!(*s, NIL, "both slots filled from three candidates");
        }

        let after = after.expect("emptying a slot changes the set, so it pushes");
        assert_eq!(
            after.len(),
            2,
            "the span keeps its width when a slot empties"
        );
        assert_eq!(
            after[0], NIL,
            "the emptied slot stays nil IN POSITION — if this is the surviving \
             peer, the hole was compacted away and every covert channel after it \
             is now bound to the wrong connection"
        );
        assert_eq!(
            after[1], filled[1],
            "the surviving stem keeps slot 1 rather than sliding to slot 0"
        );
    }

    #[test]
    fn live_stems_atomic_tracks_the_derived_value_after_every_mutation() {
        // The one deliberate cache. Single writer is what makes it honest, so
        // this asserts the published value equals the derived one after each
        // kind of mutation — a second writer, or a missed publish, shows here.
        unsafe {
            let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
            let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
            assert_eq!(shekyl_relay_zone_live_stems(h), 0, "fresh zone");

            shekyl_relay_zone_on_handshake(h, id(1).as_ptr(), false);
            assert_eq!(shekyl_relay_zone_live_stems(h), 0, "no stems drawn yet");

            shekyl_relay_zone_force_epoch(h, 0, peers.as_ptr(), 3, std::ptr::null_mut(), rec_slots);
            assert_eq!(
                shekyl_relay_zone_live_stems(h),
                (*h).driver.zone().live_stems(),
                "published value must equal the derived one after an epoch"
            );
            assert_eq!(shekyl_relay_zone_live_stems(h), 2);

            shekyl_relay_zone_on_close(h, id(1).as_ptr());
            assert_eq!(
                shekyl_relay_zone_live_stems(h),
                (*h).driver.zone().live_stems(),
                "published value must track a close"
            );
            shekyl_relay_zone_free(h);
        }
    }

    #[test]
    fn the_three_plan_outcomes_stay_distinct_across_the_boundary() {
        // The C++ caller branches three ways on this code: send, refresh-and-
        // retry, or fluff. Collapsing any two of them here is invisible to the
        // 33 gtests as a *routing* failure — the transaction still goes
        // somewhere — but it changes which `relay_method` event is emitted and
        // whether a recoverable stem is abandoned.
        unsafe {
            let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
            let mut out = [0u8; 16];

            assert_eq!(
                shekyl_relay_zone_plan_relay(h, std::ptr::null(), true, out.as_mut_ptr()),
                SHEKYL_RELAY_PLAN_NO_ROUTE,
                "no slots populated yet: transient, and a refresh may fix it"
            );
            assert_eq!(out, NIL, "no successor to report");

            // Refresh, exactly as `dandelionpp_notify`'s retry does.
            let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
            shekyl_relay_zone_update_stems(h, peers.as_ptr(), 3, std::ptr::null_mut(), rec_slots);

            // Drive to a fluff epoch. The role is drawn from OS entropy, so it
            // is reached by re-drawing rather than by construction; at q = 20%
            // the loop bound is astronomically slack.
            let mut rolls = 0;
            while !(*h).driver.zone().is_fluffing() {
                shekyl_relay_zone_force_epoch(
                    h,
                    0,
                    peers.as_ptr(),
                    3,
                    std::ptr::null_mut(),
                    rec_slots,
                );
                rolls += 1;
                assert!(rolls < 10_000, "no fluff epoch in 10k draws");
            }

            assert_eq!(
                shekyl_relay_zone_plan_relay(h, id(7).as_ptr(), false, out.as_mut_ptr()),
                SHEKYL_RELAY_PLAN_FLUFF_EPOCH,
                "a relayed tx in a fluff epoch is settled — retrying is wasted work"
            );
            assert_eq!(
                shekyl_relay_zone_plan_relay(h, std::ptr::null(), true, out.as_mut_ptr()),
                SHEKYL_RELAY_PLAN_STEM,
                "RD-4 across the boundary: the origin stems even in a fluff epoch"
            );
            assert_ne!(out, NIL, "a stem plan must carry its successor");
            shekyl_relay_zone_free(h);
        }
    }

    #[test]
    fn the_nil_uuid_means_locally_originated_which_is_what_cpp_actually_sends() {
        // The encoding production depends on, and — until this test — the one
        // encoding nothing exercised. `levin_notify` never passes a null
        // `source`: it passes `uuid_bytes(source_)`, a real 16-byte uuid that is
        // *nil-valued* when the node originated the transaction. Every other
        // seam test here reaches "local origin" through the null pointer
        // instead, so `read_id`'s `(b != NIL)` check — the line that turns those
        // bytes into `None` — had no coverage at all.
        //
        // Delete that check and nothing failed: a local transaction would become
        // "sourced from connection nil", get pinned in the stem map under a peer
        // id that does not exist, and share one slot with every other local
        // transaction for the epoch. Routing changes, no test notices.
        //
        // So this asserts the two encodings agree, on the axis RD-4 turns on:
        // nil-source + local_origin must stem during a fluff epoch exactly as
        // the null-source path does.
        unsafe {
            let peers: Vec<u8> = [id(1), id(2), id(3)].concat();
            let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
            shekyl_relay_zone_update_stems(h, peers.as_ptr(), 3, std::ptr::null_mut(), rec_slots);

            let mut rolls = 0;
            while !(*h).driver.zone().is_fluffing() {
                shekyl_relay_zone_force_epoch(
                    h,
                    0,
                    peers.as_ptr(),
                    3,
                    std::ptr::null_mut(),
                    rec_slots,
                );
                rolls += 1;
                assert!(rolls < 10_000, "no fluff epoch in 10k draws");
            }

            let mut from_nil = [0u8; 16];
            let mut from_null = [0u8; 16];
            let nil_plan =
                shekyl_relay_zone_plan_relay(h, NIL.as_ptr(), true, from_nil.as_mut_ptr());
            let null_plan =
                shekyl_relay_zone_plan_relay(h, std::ptr::null(), true, from_null.as_mut_ptr());

            assert_eq!(
                nil_plan, SHEKYL_RELAY_PLAN_STEM,
                "a nil source IS local origin — RD-4 stems it even in a fluff epoch"
            );
            assert_eq!(
                nil_plan, null_plan,
                "the two spellings of \"no source\" must not route differently"
            );
            // Same source, so the epoch's pinning must send both to one slot.
            assert_eq!(from_nil, from_null, "both pin to the same stem successor");
            shekyl_relay_zone_free(h);
        }
    }

    #[test]
    fn polling_at_the_reported_wake_time_releases_the_batch() {
        // The production path, and the only test of it anywhere: the daemon
        // arms its timer on `next_wake()` and calls `poll()` when it fires. The
        // 33 gtests never reach this — their `io_service_.poll()` runs only
        // *ready* handlers, and the wake deadline is seconds to minutes out, so
        // every gtest drives the zone through `force_fluff`/`force_epoch`
        // instead. Without this, `next_wake` could report a time `poll` did not
        // agree was due and nothing in the tree would notice.
        reset();
        unsafe {
            let h = shekyl_relay_zone_new(0, 2, 600, 30, false);
            shekyl_relay_zone_on_handshake(h, id(1).as_ptr(), true);

            let blob = [0x5Au8];
            let batch = [ShekylRelayBlob {
                ptr: blob.as_ptr(),
                len: 1,
            }];
            shekyl_relay_zone_queue_fluff(h, 0, batch.as_ptr(), 1, std::ptr::null());

            let due = shekyl_relay_zone_next_wake(h);
            assert!(due > 0, "a queued batch must report a future wake");

            if due > 1 {
                shekyl_relay_zone_poll(
                    h,
                    due - 1,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    rec_fluff,
                    rec_slots,
                );
                REC.with(|r| assert!(r.borrow().fluffed.is_empty(), "not due yet"));
            }

            shekyl_relay_zone_poll(
                h,
                due,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                rec_fluff,
                rec_slots,
            );
            shekyl_relay_zone_free(h);
        }
        REC.with(|r| {
            let rec = r.borrow();
            assert_eq!(
                rec.fluffed.len(),
                1,
                "the batch releases at the wake it reported"
            );
            assert_eq!(rec.fluffed[0].1, vec![vec![0x5Au8]]);
        });
    }

    #[test]
    fn a_zone_that_would_spin_is_refused_rather_than_built() {
        // A zero epoch expires at every wake, so the daemon's relay timer would
        // re-arm in the past forever. Refusing construction turns a silent
        // busy-loop in the p2p reactor into a loud startup failure.
        assert!(
            shekyl_relay_zone_new(0, 2, 0, 30, false).is_null(),
            "zero epoch"
        );
        assert!(
            shekyl_relay_zone_new(0, usize::MAX, 600, 30, false).is_null(),
            "unrepresentable stem width"
        );
    }

    #[test]
    fn a_null_handle_is_a_safe_no_op_on_every_export() {
        reset();
        unsafe {
            let null: *mut RelayZoneHandle = std::ptr::null_mut();
            shekyl_relay_zone_on_handshake(null, id(1).as_ptr(), true);
            shekyl_relay_zone_on_close(null, id(1).as_ptr());
            assert_eq!(shekyl_relay_zone_live_stems(null), 0);
            assert_eq!(shekyl_relay_zone_next_wake(null), 0);
            let mut out = [0u8; 16];
            assert_eq!(
                shekyl_relay_zone_plan_relay(null, id(1).as_ptr(), true, out.as_mut_ptr()),
                SHEKYL_RELAY_PLAN_NO_ROUTE,
                "nothing routes through a zone that does not exist"
            );
            shekyl_relay_zone_update_stems(
                null,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                rec_slots,
            );
            shekyl_relay_zone_poll(
                null,
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                rec_fluff,
                rec_slots,
            );
            shekyl_relay_zone_free(null);
        }
        REC.with(|r| assert!(r.borrow().fluffed.is_empty(), "no effects from a null zone"));
    }
}
