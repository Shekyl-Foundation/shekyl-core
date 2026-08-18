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
//! **A second dividend, unclaimed when this was decided and collected in RP-3b.**
//! The original argument was only that dispatching here removes the *decoding*
//! failure mode. It also makes **adding a variant a compile error at every
//! consumer**: `Effect::CovertSend` broke [`dispatch`] and two further matches
//! the moment it was introduced, and each had to be answered explicitly. Had the
//! variant crossed as an integer tag, the new case would have been a silent
//! default on the C++ side — which does not surface as a test failure but as a
//! covert channel that quietly never fires. Exhaustiveness is doing work here
//! that the decoding argument never claimed.
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
use std::sync::{Arc, Mutex};

use shekyl_relay::{
    AchievedOutConnections, Driver, Effect, FloorTransition, FloorWatch, FluffReach, RelayCarrier,
    RelayPlan, StemTallySnapshot, TxBlob, TxId, Zone,
};
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::PeerDirection;
use shekyl_relay_privacy::stem_map::ConnectionId;
use shekyl_relay_privacy::zone::RelayZone;

use crate::secure_relay_rng::SecureRelayRng;

/// The nil UUID: an absent stem slot, or a locally originated transaction.
const NIL: [u8; 16] = [0u8; 16];

/// Forward to the successor written into `out_dest`.
pub const SHEKYL_RELAY_PLAN_STEM: i32 = 0;
/// Stem-eligible, but nothing is routable yet — refresh connections and re-plan.
pub const SHEKYL_RELAY_PLAN_NO_ROUTE: i32 = 1;
/// Settled for this epoch: fluff. Retrying cannot change the answer.
pub const SHEKYL_RELAY_PLAN_FLUFF_EPOCH: i32 = 2;

/// Carrier: the zone's ordinary connection.
pub const SHEKYL_RELAY_CARRIER_ORDINARY: u8 = 0;
/// Carrier: a covert channel, bound to the stem slot (§20.3).
pub const SHEKYL_RELAY_CARRIER_COVERT: u8 = 1;

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

/// Called when covert channel `channel` comes due with its stem slot unbound:
/// clear it — nil the binding, discard buffers — on the channel's strand.
///
/// **The other half of the deleted slot array** (§20.3). The binding itself
/// travels with each [`CovertSendCb`] call; the *loss* of a binding cannot,
/// because an unbound channel emits no sends (CV-2) — and without it the C++
/// enqueue guard reads a stale binding forever, so a dormant channel
/// accumulates queued messages without bound. One channel index crosses: no
/// array, no slot order, no width for C++ to reconcile.
///
/// **Fires at every due tick while the slot stays unbound** — derived from the
/// map at each poll, never pushed once at the transition — so the receiver
/// must be idempotent (clearing a cleared channel is a no-op) and a lost or
/// swallowed clear self-heals one covert interval later. This is why only
/// [`shekyl_relay_zone_poll`] takes this callback: commands mutate and return
/// nothing, and every covert consequence rides the schedule.
pub type CovertUnbindCb = extern "C" fn(ctx: *mut c_void, channel: usize);

/// Called when covert channel `channel` is due to send.
///
/// **No payload discriminant, and that is CV-4** (§20.2). Rust decides *when*
/// and *which channel*; C++ decides *what* — dummy, or the next queued real
/// fragment — from a queue Rust cannot see. Adding a kind, a queue depth, or a
/// "has real pending" flag here would hand the scheduler exactly the input
/// needed to let the cadence react to traffic, and the resulting change would
/// look like a latency optimisation rather than the covert-channel leak it is.
/// `peer` is the 16-byte connection id of the stem slot the channel is bound
/// to — never nil, because an unbound slot emits nothing at all (CV-2). The
/// **binding travels with the send** instead of as a pushed slot array: this is
/// §20.3's inversion, and it is what lets the array (and its positional
/// decoding on the C++ side) be deleted.
pub type CovertSendCb = extern "C" fn(ctx: *mut c_void, channel: usize, peer: *const u8);

/// Zone-shape flags for [`shekyl_relay_zone_new`].
///
/// **Named bits, deliberately, instead of a second `bool` parameter.** RP-3b
/// needs the zone to carry a covert-enabled fact alongside the existing
/// outbound-fluff rule; appending `covert_enabled: bool` would have put two
/// adjacent `bool`s at the end of a C signature, where a transposition
/// compiles cleanly on both sides and is silent at runtime.
///
/// Transposing *these two* is not a generic footgun — it swaps the i2p/tor
/// outbound-only fluff rule with the covert enable, which is exactly the
/// regression RP-3a's first pass shipped and the eight `private_*` gtests
/// caught (§18.4c). The header is hand-written rather than cbindgen-generated,
/// so nothing mechanically checks the C++ declaration against this definition;
/// a bitmask removes the ordering question rather than relying on that check.
///
/// The i2p/tor rule: fluff to outbound connections only, never to an inbound
/// peer, who on a hidden service is a stranger that dialled us. It follows the
/// **network**, not covert mode — a hidden-service zone with covert disabled
/// still needs it, which is why the two bits are independent.
pub const SHEKYL_RELAY_ZONE_OUTBOUND_FLUFF_ONLY: u32 = 1 << 0;

/// This zone runs covert (noise) channels. See
/// [`SHEKYL_RELAY_ZONE_OUTBOUND_FLUFF_ONLY`] for why these are bits.
pub const SHEKYL_RELAY_ZONE_COVERT_ENABLED: u32 = 1 << 1;

/// Supplies the outbound connection set on demand.
///
/// [`shekyl_relay_zone_poll`] invokes this **at most once per call, and only
/// when a wake crosses an epoch boundary** and the stem map must be rebuilt — a
/// plain fluff-release wake never calls it, so the caller never pays for the
/// connection scan the inherited fluff path also skipped. It writes the id count
/// through `out_n` and returns a pointer to `*out_n * 16` readable bytes that
/// stays valid until the poll returns, or null with `*out_n == 0` for an empty
/// set.
///
/// This is a *pull*, the one this module otherwise forbids (§18.5 finding 3) —
/// but the hazard there was C++ reaching into the Rust-owned stem map off-strand
/// while the driver mutates it. This reads the reverse direction: it pulls the
/// **C++/asio-owned** connection table, synchronously, on the same strand the
/// wake fired on, and hands the bytes straight back. No Rust zone state is read,
/// so the race the seal names cannot arise.
///
/// Being a C++ callback reached from Rust, it must not unwind: a throw across
/// this boundary is undefined behaviour, so the C++ side catches internally and
/// reports an empty set.
pub type OutboundCb = extern "C" fn(ctx: *mut c_void, out_n: *mut usize) -> *const u8;

/// Opaque zone handle. C++ holds `*mut RelayZoneHandle` and nothing else.
pub struct RelayZoneHandle {
    driver: Driver,
    rng: SecureRelayRng,
    /// Published derived facts for off-strand readers. Single writer: [`Self::publish`].
    ///
    /// Same discipline as §18.5 finding 1 for `live_stems`: anything readable
    /// from outside the zone strand must be an atomic snapshot, not a direct
    /// borrow of zone state (which mutators race).
    live_stems: AtomicUsize,
    /// Pending stem observations — wiring witnesses and future consumers read
    /// this off-strand; the zone's `HashMap` is only touched on the strand.
    stem_in_flight: AtomicUsize,
    /// The §55 telemetry readout as a published light snapshot.
    ///
    /// Same §18.5 discipline as the atomics above, for a variable-length
    /// payload: the strand publishes an [`Arc`] of [`StemTallySnapshot`] rows
    /// (no zone borrow off-strand). JSON is **not** built here — that is a
    /// rare RPC concern and would tax every handshake/poll/`publish` for a
    /// path that is almost never read. Off-strand readers clone the `Arc`
    /// (cheap) and copy fixed-size rows; the C++ merge edge emits JSON once.
    stem_tallies: Mutex<Arc<Vec<(ConnectionId, StemTallySnapshot)>>>,
}

impl RelayZoneHandle {
    /// Republish derived facts for off-strand readers. The **only** writer of
    /// `live_stems`, `stem_in_flight`, and `stem_tallies`.
    ///
    /// Call from every export that can change either fact: stem-map rebuilds,
    /// handshake/close, plan-with-refresh, poll/force (expire), and the stem
    /// observation mutators themselves. Skipping it after a stem-watch write
    /// would leave `stem_in_flight` stale for off-strand readers.
    fn publish(&self) {
        self.live_stems
            .store(self.driver.zone().live_stems(), Ordering::Release);
        self.stem_in_flight.store(
            self.driver.zone().stem_observations_in_flight(),
            Ordering::Release,
        );
        let snap = Arc::new(self.driver.zone().stem_snapshot());
        // Poisoning cannot happen: the only writer is this method and the only
        // reader is an Arc clone + row copy, neither of which panics while
        // holding the lock.
        if let Ok(mut slot) = self.stem_tallies.lock() {
            *slot = snap;
        }
    }
}

/// Fixed-layout stem-tally row for the §55 transit path.
///
/// Native endian, 40 bytes. Published as rows so multi-zone merge can sort and
/// emit JSON once at the edge rather than splicing hand-rolled arrays. Layout
/// must match `ShekylStemTallyRow` in `shekyl_ffi.h`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylStemTallyRow {
    pub peer: [u8; 16],
    pub propagated: u64,
    pub silent: u64,
    pub distinct_sources: u64,
}

const STEM_TALLY_ROW_SIZE: usize = 40;

const _: () = assert!(std::mem::size_of::<ShekylStemTallyRow>() == STEM_TALLY_ROW_SIZE);

/// Hand each effect to the matching callback. Dispatch happens here, in Rust,
/// so no variant tag ever crosses the boundary — the reason the C++ side has no
/// decoding to get wrong (§18.4a).
fn dispatch(
    effects: Vec<Effect>,
    ctx: *mut c_void,
    fluff: FluffCb,
    unbind: CovertUnbindCb,
    covert: CovertSendCb,
) {
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
            Effect::CovertSend { channel, peer } => {
                covert(ctx, channel, peer.as_bytes().as_ptr());
            }
            Effect::CovertUnbind { channel } => {
                unbind(ctx, channel);
            }
        }
    }
}

/// See [`noop_unbind`] — `force_fluff` releases batches and can produce
/// neither covert variant.
extern "C" fn noop_covert(_: *mut c_void, _: usize, _: *const u8) {
    debug_assert!(false, "force_fluff produced a CovertSend effect");
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

/// Read `n` packed 32-byte transaction ids.
///
/// Mirrors [`read_ids`]' boundary discipline: the length is computed with
/// `checked_mul` so a bogus `n` cannot wrap into a short slice, and the raw
/// pointer is turned into a slice **once** rather than per element — there is
/// no index arithmetic left to get wrong.
///
/// **No nil filtering, unlike [`read_ids`].** An all-zero connection id is a
/// sentinel meaning "no peer"; an all-zero *transaction* hash is just a hash
/// this node will never have stemmed, and dropping it would silently shorten
/// the caller's batch.
///
/// # Safety
/// `hashes` must point to `n * 32` readable bytes, or be null with `n == 0`.
unsafe fn read_tx_ids(hashes: *const u8, n: usize) -> Vec<TxId> {
    let Some(len) = n.checked_mul(32) else {
        debug_assert!(false, "read_tx_ids: n * 32 overflows");
        return Vec::new();
    };
    if len == 0 || hashes.is_null() {
        return Vec::new();
    }
    slice::from_raw_parts(hashes, len)
        .chunks_exact(32)
        .map(|c| TxId::from_bytes(c.try_into().expect("chunks_exact(32) yields 32 bytes")))
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
/// `zone` is the `epee::net_utils::zone` discriminant this handle serves. It
/// selects the transport-bound half of [`DandelionParams`] (§89.2) and is
/// therefore NOT redundant with `outbound_fluff_only`: fluff reach is a
/// property of the network, transit latency is a property of the transport,
/// and outbound-only fluff on clearnet is still an open item (§25.5). An
/// out-of-domain byte decodes to `Invalid`, which draws the longer (anonymity)
/// parameters — the fail-safe direction.
///
/// Returns null on input a zone cannot be built from: a `stems` that would
/// overflow the slot arithmetic, or a zero epoch — which is not merely useless
/// but harmful, since every wake would find the epoch expired and the daemon's
/// relay timer would spin. The caller treats null as a startup logic error.
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_new(
    now_ms: u64,
    zone: u8,
    stems: usize,
    min_epoch_secs: u32,
    epoch_jitter_secs: u32,
    flags: u32,
) -> *mut RelayZoneHandle {
    if stems == usize::MAX || min_epoch_secs == 0 {
        return std::ptr::null_mut();
    }
    let outbound_fluff_only = flags & SHEKYL_RELAY_ZONE_OUTBOUND_FLUFF_ONLY != 0;
    let covert_enabled = flags & SHEKYL_RELAY_ZONE_COVERT_ENABLED != 0;
    let params = DandelionParams {
        min_epoch_secs,
        epoch_jitter_secs,
        // `adopted_for`, not `adopted`: `hop` is transport-bound (§89.2), and
        // this zone's stem-observation window must be drawn from the SAME
        // parameters as the embargo its successor draws for the same
        // transaction. A clearnet-provisioned window on an anonymity zone
        // expires as `silent` long before an honest successor is even allowed
        // to re-relay, so `stem_tallies` would report the whole anonymity peer
        // set as withholding. The epoch pair stays C++-owned and crosses as
        // the arguments above.
        ..DandelionParams::adopted_for(RelayZone::from_ffi_u8(zone))
    };
    let reach = if outbound_fluff_only {
        FluffReach::OutboundOnly
    } else {
        FluffReach::EveryPeer
    };
    let mut rng = SecureRelayRng;
    let zone = Zone::new(params, stems, reach, covert_enabled, now_ms, &mut rng);
    let handle = RelayZoneHandle {
        driver: Driver::new(zone),
        rng,
        live_stems: AtomicUsize::new(0),
        stem_in_flight: AtomicUsize::new(0),
        stem_tallies: Mutex::new(Arc::new(Vec::new())),
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

/// Configured stem width (slot count). When covert is enabled this is also the
/// covert channel count — channel `i` follows slot `i`. C++ sizes its channel
/// deque from this rather than from a parallel `#define`, so the two widths
/// cannot silently diverge.
///
/// # Safety
/// `handle` must be null or live. Null returns 0.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_stem_width(handle: *const RelayZoneHandle) -> usize {
    match handle.as_ref() {
        Some(h) => h.driver.zone().stem_width(),
        None => 0,
    }
}

/// Whether this zone runs covert (noise) channels.
///
/// The **single owner** of a fact C++ used to re-derive at nine sites from
/// `!zone::noise.empty()` — a byte payload doing double duty as its own enable
/// flag (§20.4). C++ now asks rather than re-derives.
///
/// Frozen at construction, so this is a plain read with no publish/atomic
/// dance: unlike `live_stems` there is no writer after `new`, and nothing to
/// race. Returns `false` for a null handle — a caller that lost its zone has no
/// covert channels by construction, and the alternative (abort) would turn a
/// C++ lifetime bug into a daemon crash at a read that cannot itself be wrong.
///
/// # Safety
/// `handle` must be null or a live zone from [`shekyl_relay_zone_new`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_covert_enabled(handle: *const RelayZoneHandle) -> bool {
    match handle.as_ref() {
        Some(h) => h.driver.zone().covert_enabled(),
        None => false,
    }
}

/// Record that `n` transactions were stemmed to `successor` — the observation
/// half of §12.11's per-successor signal (§38, §46).
///
/// `hashes` is `n` packed 32-byte **canonical transaction hashes** (F-9,
/// §48): blob bytes are not a stable identity — the stem side would hash what
/// it sent and the arrival side what the network returned, and nothing
/// enforces intermediate nodes preserve encoding. The canonical hash is
/// computed from the *parsed* transaction, so both sides derive the key from
/// the same input. C++ parses once and hands packed hashes; no blobs cross for
/// observation. `successor` is the peer's 16-byte connection uuid; `source` is
/// the arriving peer's uuid or null for locally-originated (`in_mapping_[nil]`).
///
/// **The observation window is drawn in the zone**, from the adopted embargo
/// timer cached at zone construction against the zone's own params — not
/// rebuilt here. This export is marshaling only (rule 20): if §12.11's window
/// ever diverges from the embargo, the change is one field on `Zone`.
///
/// # Safety
/// `handle` must be null (no-op) or a live zone from
/// [`shekyl_relay_zone_new`]. `hashes` must point at `32 * n` readable
/// bytes; `successor` must point at 16 readable bytes, and `source` at 16
/// when non-null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_record_stem(
    handle: *mut RelayZoneHandle,
    hashes: *const u8,
    n: usize,
    successor: *const u8,
    source: *const u8,
    now_ms: u64,
) {
    let Some(h) = handle.as_mut() else { return };
    // A nil successor is refused as well as a null one: `read_id`'s
    // nil-means-no-id contract is live here, and an observation charged to
    // "no peer" is not a thing this watch can resolve.
    let Some(succ) = read_id(successor) else {
        return;
    };
    let ids = read_tx_ids(hashes, n);
    if ids.is_empty() {
        return;
    }
    let src = read_id(source);
    h.driver
        .zone_mut()
        .record_stem(&ids, succ, src, now_ms, &mut h.rng);
    h.publish();
}

/// Record that `n` transactions arrived `from` a peer — any zone, any path,
/// but **not any peer** (§38.1's "data, not a decision"; F-10, §49).
///
/// Resolves matching pending stem observations as propagated **except** where
/// the arrival came from the successor the observation is charged to: a
/// dropper that echoes back what it was stemmed would otherwise resolve its
/// own record for one message. `from` may be null when the arrival has no
/// peer; null can never equal a successor, which is always a real connection.
///
/// Unknown hashes are ignored, so calling with never-stemmed transactions is
/// free. Call on **every** zone's handle, not only the receiving zone's: a
/// stem placed on one zone can return through another, and only the zone
/// holding the pending entry can resolve it — *the zone is unconstrained, the
/// peer is not.*
///
/// # Safety
/// `handle` must be null (no-op) or a live zone from
/// [`shekyl_relay_zone_new`]. `hashes` must point at `32 * n` readable
/// bytes, and `from` at 16 when non-null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_record_arrival(
    handle: *mut RelayZoneHandle,
    hashes: *const u8,
    n: usize,
    from: *const u8,
) {
    let Some(h) = handle.as_mut() else { return };
    let ids = read_tx_ids(hashes, n);
    if ids.is_empty() {
        return;
    }
    // One call with the whole batch, not one per id: `record_arrival` takes a
    // slice, and the per-id loop was re-entering the zone `n` times to do work
    // it does in one pass.
    h.driver.zone_mut().record_arrival(&ids, read_id(from));
    h.publish();
}

/// Copy this zone's published stem-outcome rows into `buf` (§55).
///
/// Returns the number of rows the snapshot holds — **which may exceed
/// `cap`**, in which case nothing is written and the caller retries with a
/// larger buffer (or uses the returned count after a successful write; never
/// require the second call's count to equal the first probe).
///
/// **Transit, not structure.** The data is Rust's and the consumer is Rust's
/// (`shekyl-daemon-rpc`); the hop through C++ exists only because `net_node`
/// owns zone-handle lifetime. Rows (not JSON) so multi-zone merge can sort
/// and serialise once at the edge. Disappears with the p2p migration.
///
/// Reads a published [`Arc`] snapshot, never the zone map (§18.5).
///
/// # Safety
/// `handle` must be null (returns 0) or a live zone from
/// [`shekyl_relay_zone_new`]. When `cap > 0`, `buf` must be writable for
/// `cap` [`ShekylStemTallyRow`]s.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_stem_snapshot(
    handle: *const RelayZoneHandle,
    buf: *mut ShekylStemTallyRow,
    cap: usize,
) -> usize {
    let Some(h) = handle.as_ref() else {
        return 0;
    };
    // Clone the Arc under the lock, then drop the guard before writing so a
    // slow reader cannot stall the strand's next `publish`.
    let snap = {
        let Ok(slot) = h.stem_tallies.lock() else {
            return 0;
        };
        Arc::clone(&*slot)
    };
    let n = snap.len();
    if !buf.is_null() && n <= cap {
        for (i, (peer, t)) in snap.iter().enumerate() {
            // SAFETY: `n <= cap` and `buf` is writable for `cap` rows.
            std::ptr::write(
                buf.add(i),
                ShekylStemTallyRow {
                    peer: *peer.as_bytes(),
                    propagated: t.propagated,
                    silent: t.silent,
                    distinct_sources: t.distinct_sources,
                },
            );
        }
    }
    n
}

/// Stem observations still pending resolution.
///
/// Reads the published atomic, so it is safe from any thread — the same
/// discipline as [`shekyl_relay_zone_live_stems`]. The zone's pending map is
/// only touched on the strand; this export never borrows it. A null handle
/// reads 0.
///
/// # Safety
/// `handle` must be null or a live zone from [`shekyl_relay_zone_new`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_stem_in_flight(handle: *const RelayZoneHandle) -> usize {
    match handle.as_ref() {
        Some(h) => h.stem_in_flight.load(Ordering::Acquire),
        None => 0,
    }
}

/// R-1: should this *originated* transaction take the anonymity zone?
/// One roll, at origination (Q12-D5a). Relayed traffic does not call this.
///
/// **A verdict crosses, not a probability.** The rate and its reasoning stay
/// in Rust; C++ asks a yes/no question at the one origination site and acts
/// on the answer. Handing C++ the probability would put the draw — and a
/// second place to get the rate wrong — on the wrong side of the boundary.
///
/// Handle-free: the roll is a property of the policy, not of any zone
/// instance, and it draws from the process CSPRNG exactly as the embargo does.
///
/// **Callers own the pre-fluff test.** This says *whether to take anonymity*,
/// not *whether the transaction is still stemming*. A transaction that has
/// fluffed must leave the zone, or one that entered over Tor never reaches
/// the public network.
/// §18.4's diagnostic store — **deliberately NOT on `RelayZoneHandle`**: the
/// FOLLOWUPS spec forbids the integer landing on the handle the stem/fluff
/// decision reads, so that reaching this state from a wire path requires a
/// call to a diagnostic-named global, a visible edit no review misses. Keyed
/// by zone byte (one anonymity zone per byte per process); lives for the
/// process, which a diagnostic may.
fn floor_watches() -> &'static Mutex<std::collections::HashMap<u8, FloorWatch>> {
    static WATCHES: std::sync::OnceLock<Mutex<std::collections::HashMap<u8, FloorWatch>>> =
        std::sync::OnceLock::new();
    WATCHES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// §18.4's live diagnostic: record the zone's achieved outbound
/// anonymity-CONNECTION count; returns the floor transition (0 steady,
/// 1 went below, 2 recovered) for the operator warn log. The floor
/// comparison lives in [`FloorWatch::note`] — the logging path — and this
/// state is readable by NOTHING on a wire path (§18.3).
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_note_achieved_out(zone: u8, achieved: u32) -> u8 {
    match floor_watches().lock() {
        Ok(mut m) => m
            .entry(zone)
            .or_insert_with(|| {
                FloorWatch::new(shekyl_relay_privacy::params::MIN_PROVISIONED_OUT_PEERS)
            })
            .note(AchievedOutConnections::new(achieved)) as u8,
        Err(_) => FloorTransition::Steady as u8,
    }
}

/// Admin-surface read of the §18.4 diagnostic (`/get_stem_tallies`,
/// AdminOnly). False (writes nothing) until the zone's first note — no data
/// is never a fabricated zero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_floor_snapshot(
    zone: u8,
    out_achieved: *mut u32,
    out_floor: *mut u32,
    out_below: *mut bool,
) -> bool {
    if out_achieved.is_null() || out_floor.is_null() || out_below.is_null() {
        return false;
    }
    let snap = match floor_watches().lock() {
        Ok(m) => m.get(&zone).and_then(FloorWatch::snapshot),
        Err(_) => None,
    };
    match snap {
        Some(s) => {
            *out_achieved = s.achieved;
            *out_floor = s.floor;
            *out_below = s.below;
            true
        }
        None => false,
    }
}

/// R-1 origination roll AND its zone mapping, one crossing (rule 40's
/// coarse-call rule): draws whether this ORIGINATED transaction takes the
/// anonymity zone and returns the zone byte `send_txs` reads — `invalid` (0,
/// fail-closed anonymity) or `public_` (1, clearnet BY DESIGN, not fallback).
///
/// Replaces the `shekyl_relay_zone_divert_originated_tx` +
/// `shekyl_relay_zone_originated_zone_from_anonymity_roll` pair, whose only
/// caller fed the first's bool straight into the second — a Rust-owned value
/// crossing to C++ only to cross straight back for a two-arm map. The rate
/// and the mapping both stay in Rust; a zone byte crosses, not a probability
/// and not an intermediate verdict. Relayed traffic does not call this; it
/// inherits its arrival zone.
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_roll_originated_zone() -> u8 {
    let mut rng = SecureRelayRng;
    let take = shekyl_relay_privacy::divert_to_anonymity_zone(&mut rng);
    shekyl_relay::zone_route::originated_zone_from_anonymity_roll(take) as u8
}

/// The outbound-connection floor the embargo provisioning assumes (F-8b, §45).
///
/// `fluff_return_ms` is measured at usable degree 12; a zone configured below
/// that has a real fluff first-passage the embargo was not derived for, in the
/// privacy-losing direction. The `--tx-proxy` parser refuses counts below this
/// value. Handle-free: the floor is a property of the derivation, not of any
/// zone instance.
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_min_provisioned_out_peers() -> u32 {
    shekyl_relay_privacy::params::MIN_PROVISIONED_OUT_PEERS
}

/// Outbound connections a node opens per zone by default (rule 20: Rust owns
/// the value, C++ consumes it).
///
/// Replaces `#define P2P_DEFAULT_CONNECTIONS_COUNT`. The relay-privacy
/// instruments simulate the deployed out-degree, so a `#define` C++ could move
/// without any Rust test failing left the measurements free to describe a
/// network that does not exist. Not the same quantity as
/// `shekyl_relay_zone_min_provisioned_out_peers`: this is the configuration
/// the privacy numbers are measured **at**, that one is a floor derived
/// **from** those measurements.
#[no_mangle]
pub extern "C" fn shekyl_p2p_default_out_peers() -> u32 {
    shekyl_relay_privacy::params::P2P_DEFAULT_OUT_PEERS
}

// ---------------------------------------------------------------------------
// Once-at-origin zone routing (Q12-D5a; Q12_D6A_PEER_DISCOVERY_RUN.md §§12, 18)
//
// The decision family moved from C++ `cryptonote_protocol/enums.h` under rule
// 20; C++ keeps the `zone_route` compile-time token as a seam guard whose body
// forwards here. Bytes cross raw and are `static_assert`ed on the C++ side
// against `relay_method`, `epee::net_utils::zone` and `zone_route::decision`.
//
// Unknown bytes are a caller bug (same process, asserted contract), and they
// map to the SAFE arm — fail-closed / false — never to a guess that could put
// a transaction on clearnet. Refuse-to-leak is this family's whole invariant
// (§30.5), so the defensive default is the invariant itself.
// ---------------------------------------------------------------------------

/// Q12-D5a once-at-origin routing: `(relay_method byte, zone byte)` → decision
/// byte (0 = keep_arrival, 1 = anonymity_fail_closed, 2 = public_clearnet).
///
/// Unknown method or zone bytes return `1` (fail-closed: send nothing).
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_once_at_origin_route(tx_relay: u8, origin_zone: u8) -> u8 {
    use shekyl_relay::zone_route::{once_at_origin_route, NetZone, RelayMethod};
    match (
        RelayMethod::from_byte(tx_relay),
        NetZone::from_byte(origin_zone),
    ) {
        (Some(m), Some(z)) => once_at_origin_route(m, z) as u8,
        _ => shekyl_relay::zone_route::ZoneRouteDecision::AnonymityFailClosed as u8,
    }
}

/// §30.5 / §89.8: an origin on a non-public zone keeps its `local` txpool
/// record whatever the transport did.
///
/// # Unknown-byte policy — and why `false` is NOT the safe arm here
///
/// For this predicate the leak direction is inverted relative to its
/// siblings: `false` on a `local` origin lets the record upgrade to
/// `stem`/`fluff` (`levin_notify.cpp`'s record site), and the monotone
/// upgrade means the next pool re-relay places the entry in `public_req` —
/// an anonymity-origin transaction on clearnet. So an unknown **zone** byte
/// on a decodable `local` origin returns `true`: a zone this build cannot
/// decode is not provably public, and keeping `local` fail-closes later
/// (pool re-relay → `invalid` → send nothing). The cost is liveness on a
/// zone that does not exist; the alternative is the §30.5 leak. An unknown
/// **method** byte returns `false` — no `local` claim is invented for a
/// class this build cannot name.
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_originated_stays_in_zone(tx_relay: u8, nzone: u8) -> bool {
    use shekyl_relay::zone_route::{originated_stays_in_zone, NetZone, RelayMethod};
    match (RelayMethod::from_byte(tx_relay), NetZone::from_byte(nzone)) {
        (Some(m), Some(z)) => originated_stays_in_zone(m, z),
        (Some(RelayMethod::Local), None) => true,
        _ => false,
    }
}

/// Pre-fluff relay methods (stem / local). Unknown bytes return `false`.
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_is_pre_fluff_relay(tx_relay: u8) -> bool {
    shekyl_relay::zone_route::RelayMethod::from_byte(tx_relay)
        .is_some_and(shekyl_relay::zone_route::is_pre_fluff_relay)
}

/// R-1 coherence: pre-fluff on a real anonymity origin. Unknown bytes return
/// `false` (no coherence claim is invented for a zone that does not decode).
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_r1_coherence_keeps_origin(
    tx_relay: u8,
    origin_zone: u8,
) -> bool {
    use shekyl_relay::zone_route::{r1_coherence_keeps_origin, NetZone, RelayMethod};
    match (
        RelayMethod::from_byte(tx_relay),
        NetZone::from_byte(origin_zone),
    ) {
        (Some(m), Some(z)) => r1_coherence_keeps_origin(m, z),
        _ => false,
    }
}

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
/// re-plan.
///
/// This is the production path for `dandelionpp_notify`: the refresh policy
/// lives in Rust with the rest of zone scheduling, so the C++ shim only offers
/// the outbound snapshot and performs transport. A settled fluff epoch does not
/// refresh. See [`shekyl_relay::Zone::plan_relay_with_refresh`]. No callback:
/// commands return nothing, and a covert channel the refresh leaves unbound
/// clears at its next due tick through [`shekyl_relay_zone_poll`]'s
/// `on_unbind`.
///
/// # Safety
/// `handle` must be live; `source` must point to 16 readable bytes or be null;
/// `outbound` must point to `n * 16` readable bytes or be null with `n == 0`;
/// `out_dest` must point to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_plan_relay_with_refresh(
    handle: *mut RelayZoneHandle,
    source: *const u8,
    local_origin: bool,
    outbound: *const u8,
    n: usize,
    out_dest: *mut u8,
) -> i32 {
    if handle.is_null() || out_dest.is_null() {
        return SHEKYL_RELAY_PLAN_NO_ROUTE;
    }
    let peers = read_ids(outbound, n);
    let h = &mut *handle;
    let source = read_id(source);
    let plan = h
        .driver
        .zone_mut()
        .plan_relay_with_refresh(source, local_origin, peers, &mut h.rng);
    h.publish();
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

/// Plan a relay **and** the wire that carries it — phase, carrier and slot in
/// **one** crossing (rule 40).
///
/// Supersedes [`shekyl_relay_zone_plan_relay_with_refresh`] for the covert
/// path. The precedent for folding a decision and its mapping into a single
/// call rather than shuttling an intermediate verdict is
/// `shekyl_relay_zone_roll_originated_zone`.
///
/// Return value is the same `SHEKYL_RELAY_PLAN_*` code as the older entry
/// point, so a caller that ignores the carrier reads exactly what it read
/// before. `out_carrier` receives `SHEKYL_RELAY_CARRIER_*`; `out_channel`
/// receives the covert channel — **which is the stem slot index** — and is
/// meaningful **only** when the carrier is covert. It is written as `0` on the
/// ordinary carrier rather than left untouched, so a caller cannot read a stale
/// slot from a previous call.
///
/// # This entry point deliberately has NO production caller yet
///
/// `DAEMON_RELAY_PRIVACY.md` §42.5b's ownership split lands the decision half
/// first; the C++ covert branch is restructured to consume it in a following
/// change (`COVER_TRAFFIC_RESTORATION.md` §2.1 stages 2–3). **Do not delete
/// this as unused** — it is the seam that restructure lands against, and the
/// audit at `COVER_TRAFFIC_RESTORATION.md` §1.6 states the conditions under
/// which the cover mechanism may be removed, none of which is a caller grep.
///
/// # Safety
/// `handle` must be live; `source` must point to 16 readable bytes or be null;
/// `outbound` must point to `n * 16` readable bytes or be null with `n == 0`;
/// `out_dest` must point to 16 writable bytes; `out_carrier` must point to one
/// writable byte; `out_channel` must point to a writable `u32`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_plan_dispatch_with_refresh(
    handle: *mut RelayZoneHandle,
    source: *const u8,
    local_origin: bool,
    outbound: *const u8,
    n: usize,
    out_dest: *mut u8,
    out_carrier: *mut u8,
    out_channel: *mut u32,
) -> i32 {
    if handle.is_null() || out_dest.is_null() || out_carrier.is_null() || out_channel.is_null() {
        // Fail closed on every out-param: a caller that got NO_ROUTE must not
        // then read an uninitialised carrier and treat it as covert.
        if !out_carrier.is_null() {
            *out_carrier = SHEKYL_RELAY_CARRIER_ORDINARY;
        }
        if !out_channel.is_null() {
            *out_channel = 0;
        }
        return SHEKYL_RELAY_PLAN_NO_ROUTE;
    }
    let peers = read_ids(outbound, n);
    let h = &mut *handle;
    let source = read_id(source);
    let dispatch =
        h.driver
            .zone_mut()
            .plan_dispatch_with_refresh(source, local_origin, peers, &mut h.rng);
    h.publish();
    match dispatch.carrier {
        RelayCarrier::Ordinary => {
            *out_carrier = SHEKYL_RELAY_CARRIER_ORDINARY;
            *out_channel = 0;
        }
        RelayCarrier::Covert { channel } => {
            *out_carrier = SHEKYL_RELAY_CARRIER_COVERT;
            *out_channel = u32::try_from(channel).unwrap_or(u32::MAX);
        }
    }
    write_plan(dispatch.plan, out_dest)
}

/// Merge the caller's current outbound set into the stem map mid-epoch.
///
/// Ports `update_channels::run`. On a public zone this is the only thing that
/// ever populates the map: `notify` is constructed before any peer connects, so
/// without it every transaction would fluff. The daemon reaches it on three
/// paths: a new outbound connection, a covert send that failed, and the forced
/// refresh after a stem send failure. No callback: commands return nothing,
/// and a covert channel the merge leaves unbound clears at its next due tick
/// through [`shekyl_relay_zone_poll`]'s `on_unbind`.
///
/// # Safety
/// `handle` must be live; `outbound` must point to `n * 16` readable bytes or be
/// null with `n == 0`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_update_stems(
    handle: *mut RelayZoneHandle,
    outbound: *const u8,
    n: usize,
) {
    if handle.is_null() {
        return;
    }
    let peers = read_ids(outbound, n);
    let h = &mut *handle;
    // Since §20.3 nothing re-points on a push — an unbound channel clears at
    // its next due tick via `poll`.
    h.driver.zone_mut().update_stems(peers, &mut h.rng);
    h.publish();
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
/// The outbound set is not passed in: `gather_outbound` is called back **only**
/// when a wake crosses an epoch boundary and the stem map is rebuilt, so a
/// fluff-release wake — the common case — never triggers the connection scan.
/// See [`OutboundCb`] for why this pull is the sanctioned exception to §18.5.
///
/// # Safety
/// `handle` must be live; the callbacks must be valid for the duration of the
/// call. `gather_outbound` must honour the [`OutboundCb`] contract: on return,
/// its pointer covers `*out_n * 16` readable bytes (or is null with `*out_n`
/// zero), valid until this call returns, and it must not unwind.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_poll(
    handle: *mut RelayZoneHandle,
    now_ms: u64,
    ctx: *mut c_void,
    gather_outbound: OutboundCb,
    on_fluff: FluffCb,
    on_unbind: CovertUnbindCb,
    on_covert: CovertSendCb,
) {
    if handle.is_null() {
        return;
    }
    let h = &mut *handle;
    let effects = h.driver.poll(
        now_ms,
        || {
            let mut n: usize = 0;
            let ptr = gather_outbound(ctx, &raw mut n);
            // SAFETY: the `OutboundCb` contract makes `ptr` cover `n * 16`
            // readable bytes (or null with `n == 0`), valid for this call.
            unsafe { read_ids(ptr, n) }
        },
        &mut h.rng,
    );
    h.publish();
    dispatch(effects, ctx, on_fluff, on_unbind, on_covert);
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
    dispatch(effects, ctx, on_fluff, noop_unbind, noop_covert);
}

/// Start a new epoch immediately — what `notify::run_epoch()` drives. No
/// callback: the rollover's covert consequences ride the schedule, exactly as
/// a deadline-crossing rollover's do.
///
/// # Safety
/// `handle` must be live; `outbound` must point to `n * 16` readable bytes or be
/// null with `n == 0`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_force_epoch(
    handle: *mut RelayZoneHandle,
    now_ms: u64,
    outbound: *const u8,
    n: usize,
) {
    if handle.is_null() {
        return;
    }
    let peers = read_ids(outbound, n);
    let h = &mut *handle;
    h.driver.force_epoch(now_ms, &peers, &mut h.rng);
    h.publish();
}

/// Placeholders for the exports that cannot produce the other variants.
/// Reaching one is a dispatch bug, so they assert in debug rather than failing
/// silently.
extern "C" fn noop_unbind(_: *mut c_void, _: usize) {
    debug_assert!(false, "force_fluff produced a CovertUnbind effect");
}

#[cfg(test)]
mod tests;
