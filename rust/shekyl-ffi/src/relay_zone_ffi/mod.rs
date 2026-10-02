// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the live relay zone — RP-3a of `DAEMON_RELAY_PRIVACY.md`.
//!
//! The C++ `cryptonote::levin::notify` forwards here; the scheduling logic lives
//! in `shekyl-relay`. On the ORDINARY path transaction bodies cross as opaque
//! blobs, because framing, padding and the socket stay C++ (§18.2).
//!
//! The CARRIER is the one exception, and it is a narrow one: a real fragment
//! is framed and padded HERE (`fragmented_notify`) before it enters the queue,
//! because the carrier's unit is a fixed window rather than a message. C++
//! could not do that framing without knowing the window, which is
//! `NoiseQueues`' own invariant and deliberately not exported. The socket
//! stays C++ on both paths.
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
//! consumer**: `Effect::NoiseSend` broke [`dispatch`] and two further matches
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

use shekyl_levin::{NewTransactions, PortableMap, NOTIFY_NEW_TRANSACTIONS};
use shekyl_relay::{
    AchievedOutConnections, CarrierToken, ConnectorId, Driver, Effect, FloorTransition, FloorWatch,
    NodeSync, NoiseQueues, Relay, RelayCarrier, RelayPlan, StemTallySnapshot, TxBlob, TxId,
};
use shekyl_relay_privacy::params::{carrier, DandelionParams};
use shekyl_relay_privacy::schedule::PeerDirection;
use shekyl_relay_privacy::stem_map::ConnectionId;

use crate::secure_relay_rng::SecureRelayRng;

/// Connectors named by bits of `mask`, in [`ConnectorId::ALL`] order.
/// A bit past [`ConnectorId::COUNT`] is a caller bug and refuses the handle.
fn connectors_from_mask(mask: u32) -> Result<Vec<ConnectorId>, ()> {
    let known = (1u32 << ConnectorId::COUNT) - 1;
    if mask & !known != 0 {
        return Err(());
    }
    Ok(ConnectorId::ALL
        .iter()
        .copied()
        .filter(|connector| mask & (1u32 << connector.index()) != 0)
        .collect())
}

/// `connector` is a [`ConnectorId`] discriminant. Unknown bytes are false.
#[no_mangle]
pub extern "C" fn shekyl_connector_address_hidden_from_peer(connector: u8) -> bool {
    connector_from_byte(connector).is_some_and(shekyl_relay::address_hidden_from_peer)
}

/// This connector's native encryption cell says a network observer cannot
/// read the byte stream. Unknown bytes are false. Not the anonymity cell:
/// [`shekyl_connector_address_hidden_from_peer`] is that one.
#[no_mangle]
pub extern "C" fn shekyl_connector_link_encrypted(connector: u8) -> bool {
    connector_from_byte(connector).is_some_and(shekyl_relay::link_encrypted)
}

/// The construction bit: some configured connector declares the peer does
/// not learn this node's address. Null is false.
///
/// # Safety
/// `handle` must be live or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_hop0_restricted(handle: *const RelayZoneHandle) -> bool {
    if handle.is_null() {
        return false;
    }
    (*handle).driver.zone().hop0_restricted()
}

fn connector_from_byte(byte: u8) -> Option<ConnectorId> {
    ConnectorId::ALL
        .iter()
        .copied()
        .find(|connector| u8::try_from(connector.index()).ok() == Some(byte))
}

/// The nil UUID: an absent stem slot, or a locally originated transaction.
const NIL: [u8; 16] = [0u8; 16];

/// Forward to the successor written into `out_dest`.
pub const SHEKYL_RELAY_PLAN_STEM: i32 = 0;
/// Stem-eligible, but nothing is routable yet — refresh connections and re-plan.
pub const SHEKYL_RELAY_PLAN_NO_ROUTE: i32 = 1;
/// Settled for this epoch: fluff. Retrying cannot change the answer.
pub const SHEKYL_RELAY_PLAN_FLUFF_EPOCH: i32 = 2;
/// Local origin while this node is unsynchronised. Send nothing, record nothing.
pub const SHEKYL_RELAY_PLAN_AWAIT_SYNC: i32 = 3;

fn node_sync_from_ffi(node_synchronised: bool) -> NodeSync {
    if node_synchronised {
        NodeSync::Synchronised
    } else {
        NodeSync::Unsynchronised
    }
}

/// Carrier: the zone's ordinary connection.
pub const SHEKYL_RELAY_CARRIER_ORDINARY: u8 = 0;
/// Carrier: a covert channel, bound to the stem slot (§20.3).
pub const SHEKYL_RELAY_CARRIER_NOISE: u8 = 1;

const _: () = {
    assert!(SHEKYL_RELAY_CARRIER_ORDINARY == 0);
    assert!(SHEKYL_RELAY_CARRIER_NOISE == 1);
};

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

// `NoiseUnbindCb` is DELETED, not kept as a souvenir (rule 15).
//
// It carried "this channel's slot is unbound, clear it" to a C++ side that
// held the buffers, and its doc argued the loss of a binding could not travel
// with a send because an unbound channel emits none (CV-2). That reasoning is
// intact; what changed is WHO clears. Since #515 the buffers are Rust's, and
// since the carrier caller `Effect::NoiseUnbind` is consumed inside Rust by
// `NoiseQueues::unbind` — the call that invalidates outstanding send tokens.
// C++ has no channel state left, so the callback had no job the moment the
// join landed, and a callback with no job is not a backstop.
//
// The idempotence it asked for still holds where the state now lives: the
// effect still fires at every due tick while the slot stays unbound, and
// `unbind` is a no-op on an already-cleared channel.

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
pub type NoiseSendCb = extern "C" fn(
    ctx: *mut c_void,
    channel: usize,
    peer: *const u8,
    bytes: *const u8,
    len: usize,
) -> bool;

/// What became of a message handed to the carrier — reported once, terminally.
///
/// `token` is the value the enqueuer minted; `sent` is true only when every
/// window of the message was accepted by the transport — see
/// [`shekyl_relay::CarrierOutcome`] for why that is acceptance and not
/// acknowledgement.
///
/// # Both arms, and the false one is why this exists
///
/// A completion signal alone leaves the caller waiting forever on a message
/// the carrier discarded (`NoiseQueues::unbind` clears a channel). `sent =
/// false` is that case, and the caller must read it as **not relayed** rather
/// than as "not yet": the pool's `relayed` bit chooses an origin's backoff,
/// and an origin given the derived interval for a discarded transaction waits
/// it out for something that was never sent.
///
/// # This is NOT a CV-4 breach, and the argument is the one that widened
/// [`NoiseSendCb`]
///
/// CV-4 forbids feeding the SCHEDULER traffic-dependent input. The barrier is
/// that the cadence decides *when* to emit and *to whom*; this reports what
/// the cadence already did, after it did it — downstream of both decisions,
/// exactly like `NoiseSend::sent` / `::failed`, which resolve a send the
/// scheduler had already chosen. Nothing here is readable by the schedule.
///
/// Stated here rather than left to be re-derived, because "a new FFI export on
/// the noise path" is what a future reviewer will read as a breach without the
/// argument in front of them.
///
/// # Contract for an implementer
///
/// - `peer` covers **16 readable bytes** when `sent` is true, and is **null**
///   when it is false: a discarded message has no successor to charge. Read it
///   only on the `sent` arm, and only for the duration of the call.
/// - `token` is the value the enqueuer minted, returned verbatim. The queue
///   never interprets it.
/// - **Must not unwind** across the boundary, and **must not re-enter the
///   handle** — see [`shekyl_relay_zone_poll`], which holds `&mut` on the zone
///   and a second borrow of the carrier queue for the whole call. Buffer what
///   this reports and act on it after `poll` returns.
///
/// The C header states the same contract for a C implementer
/// (`ShekylRelayCarrierResolvedCb` in `shekyl_ffi.h`); the two doc systems
/// cannot reference each other, which is the boundary that earns the second
/// copy.
pub type CarrierResolvedCb =
    extern "C" fn(ctx: *mut c_void, token: u64, sent: bool, peer: *const u8);

/// Zone-shape flags for [`shekyl_relay_zone_new`].
///
/// **Named bits, deliberately, instead of a second `bool` parameter.** RP-3b
/// needs the zone to carry a covert-enabled fact alongside the existing
/// outbound-fluff rule; appending `noise_enabled: bool` would have put two
/// adjacent `bool`s at the end of a C signature, where a transposition
/// compiles cleanly on both sides and is silent at runtime.
///
/// Bit 0 is not a flag. It used to mean "fluff to outbound peers only".
/// Fluff reach is per session now: an inbound anonymity session receives
/// a fluff. Passing bit 0 does nothing, and the value is not reserved as
/// a constant — a named unused bit is the grep hit that gets finished.
///
/// This zone runs covert (noise) channels. The header is hand-written
/// rather than cbindgen-generated, so the value is pinned by
/// `zone_flag_bits_do_not_transpose` against `shekyl_ffi.h`.
pub const SHEKYL_RELAY_ZONE_NOISE_ENABLED: u32 = 1 << 1;

/// Opaque zone handle. C++ holds `*mut RelayZoneHandle` and nothing else.
pub struct RelayZoneHandle {
    driver: Driver,
    /// The carrier's buffers, held **beside** [`Driver`] and never inside it.
    ///
    /// `None` on a zone without the carrier. Two postures, and they must be
    /// stated apart because this PR made the first sentence of the earlier
    /// draft false:
    ///
    /// - **shipped default** — every zone, C++-built or otherwise, since
    ///   `make_relay_zone` sets the noise flag only behind
    ///   `set_carrier_development`, which defaults off;
    /// - **development-enabled** — an ENCRYPTED zone built after
    ///   `set_carrier_development(true)` holds `Some`. A cleartext one still
    ///   does not, and that refusal is `Relay::new`'s (§93.2), not the flag's.
    ///
    /// Ownership here rather than in `Driver` is CV-4's type barrier expressed
    /// as a field, and that is unchanged by either posture: the scheduler
    /// cannot consult what it cannot reach.
    noise: Option<NoiseQueues>,
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

/// Not a connector index. Matches `SHEKYL_CONNECTOR_BYTE_UNSPECIFIED`.
pub const CONNECTOR_BYTE_UNSPECIFIED: u8 = 0xff;

/// Fixed-layout stem-tally row for the §55 transit path.
///
/// Native endian, 48 bytes. The connector is the index the stem was
/// forwarded on; [`CONNECTOR_BYTE_UNSPECIFIED`] means the tally recorded
/// none. Padding keeps the next row 8-aligned. Layout must match
/// `ShekylStemTallyRow` in `shekyl_ffi.h`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylStemTallyRow {
    pub peer: [u8; 16],
    pub propagated: u64,
    pub silent: u64,
    pub distinct_sources: u64,
    pub connector: u8,
    pub _pad: [u8; 7],
}

const STEM_TALLY_ROW_SIZE: usize = 48;

const _: () = assert!(std::mem::size_of::<ShekylStemTallyRow>() == STEM_TALLY_ROW_SIZE);

/// Hand each effect to the matching callback. Dispatch happens here, in Rust,
/// so no variant tag ever crosses the boundary — the reason the C++ side has no
/// decoding to get wrong (§18.4a).
/// The carrier join lives here, and `queues` is borrowed rather than owned by
/// [`Driver`] — CV-4's type barrier, unchanged. The cadence has already fixed
/// *when* and *to whom* by the time `poll` returns its effects; only then is
/// the queue consulted for *what*. A `Driver` that could see the queue could
/// let the cadence react to traffic, which is the leak CV-4 forbids.
fn dispatch(
    effects: Vec<Effect>,
    ctx: *mut c_void,
    fluff: FluffCb,
    noise: NoiseSendCb,
    resolved: CarrierResolvedCb,
    queues: Option<&mut NoiseQueues>,
) {
    let mut queues = queues;
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
            Effect::NoiseSend { channel, peer } => {
                // No queue means the zone has no carrier, and the cadence
                // cannot have produced this effect — a zone only schedules
                // noise when `noise_enabled`. Dropping silently would hide a
                // real construction bug, so it fails loudly in debug and is
                // inert in release rather than sending an unframed nothing.
                let Some(q) = queues.as_deref_mut() else {
                    debug_assert!(false, "NoiseSend on a zone with no carrier queue");
                    continue;
                };
                let Some(send) = q.take_for_send(channel, peer) else {
                    continue;
                };
                // `take_for_send` is NON-DESTRUCTIVE: it hands back the same
                // fragment until something resolves the token. That is the
                // whole reason the callback had to widen — without a status
                // coming back, `sent` could never be called and every take
                // would reproduce this fragment forever.
                //
                // The two resolutions are not symmetric. `sent` advances one
                // fragment; `failed` RESTARTS the channel — offset and binding
                // cleared, epoch bumped — so a multi-window message resumes
                // from its first fragment rather than its current one. A
                // partly sent message must not be finished to a different
                // successor, and the queue cannot know how much of it the
                // failed send was accepted with.
                let bytes = send.bytes();
                let accepted = noise(
                    ctx,
                    channel,
                    peer.as_bytes().as_ptr(),
                    bytes.as_ptr(),
                    bytes.len(),
                );
                if accepted {
                    send.sent(q);
                } else {
                    send.failed(q);
                }
            }
            Effect::NoiseUnbind { channel } => {
                // Consumed entirely in Rust. `unbind` is what invalidates
                // outstanding tokens, so it is not the lesser half of the
                // join — omitting it would leave a token resolvable against
                // a slot that no longer has a peer.
                //
                // Asserts on a missing queue for the same reason the send arm
                // does, and the premise is the same one: `Driver::poll` emits
                // EITHER noise effect only behind `due_noise_channel`, which
                // is `None` unless the zone's schedule is `On`. So a zone that
                // can produce this cannot lack a queue, and silence here would
                // hide the construction bug rather than the scheduling one.
                let Some(q) = queues.as_deref_mut() else {
                    debug_assert!(false, "NoiseUnbind on a zone with no carrier queue");
                    continue;
                };
                q.unbind(channel);
            }
        }
    }

    // Drained ONCE, after every effect, because both arms can produce an
    // outcome: `sent` completes a message and `unbind` discards whatever a
    // channel still held. Draining inside the send arm would report
    // completions and miss discards.
    if let Some(q) = queues {
        for outcome in q.take_resolved() {
            // The peer travels with the verdict because the enqueuer cannot
            // know it: a channel binds to whatever its slot holds at send
            // time. Null on a discard — there is no successor to charge.
            match outcome.peer() {
                Some(peer) => resolved(
                    ctx,
                    outcome.token().0,
                    outcome.was_sent(),
                    peer.as_bytes().as_ptr(),
                ),
                None => resolved(
                    ctx,
                    outcome.token().0,
                    outcome.was_sent(),
                    core::ptr::null(),
                ),
            }
        }
    }
}

/// A placeholder for the exports that hold no carrier queue, and so can
/// resolve nothing. `force_fluff` passes `None` for the queue, so `dispatch`
/// never reaches the drain — this exists to make that unreachability explicit
/// rather than to be called.
extern "C" fn noop_carrier_resolved(_ctx: *mut c_void, _token: u64, _sent: bool, _peer: *const u8) {
    debug_assert!(false, "force_fluff resolved a carrier message");
}

/// A placeholder for the exports that cannot produce a `NoiseSend`.
/// `force_fluff` releases batches and can produce neither covert variant;
/// reaching this is a dispatch bug, so it asserts in debug rather than failing
/// silently, and reports "not accepted" so no token is ever resolved by it.
extern "C" fn noop_noise(_: *mut c_void, _: usize, _: *const u8, _: *const u8, _: usize) -> bool {
    debug_assert!(false, "force_fluff produced a NoiseSend effect");
    false
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
/// `hashes` must point to `n * 32` readable bytes, **or be null** — which
/// yields an empty batch whatever `n` says, rather than reading through it.
/// The tolerance is `slice_from_ptr`'s and is deliberate at a C boundary: a
/// caller that passes null with a non-zero count has a bug, and "record
/// nothing" is the reading that does not corrupt anything on the way to
/// finding it.
unsafe fn read_tx_ids(hashes: *const u8, n: usize) -> Vec<TxId> {
    let Some(len) = n.checked_mul(32) else {
        debug_assert!(false, "read_tx_ids: n * 32 overflows");
        return Vec::new();
    };
    // Same seam as `read_ids`: fixing one reader and leaving its sibling on a
    // raw `from_raw_parts` is the synchronize-the-duplicate shape, so both move
    // together.
    let Some(bytes) = crate::legacy_util::slice_from_ptr(hashes, len) else {
        debug_assert!(
            isize::try_from(len).is_ok(),
            "read_tx_ids: {len} bytes exceeds the isize::MAX slice bound"
        );
        return Vec::new();
    };
    bytes
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
    // Not routed through `slice_from_ptr`: the length is the literal 16, which
    // is provably inside the `isize::MAX` bound the seam exists to enforce.
    // Only caller-controlled lengths need the seam.
    b.copy_from_slice(slice::from_raw_parts(p, 16));
    (b != NIL).then(|| ConnectionId::from_bytes(b))
}

/// Open a zone. Release with [`shekyl_relay_zone_free`].
///
/// The epoch length is a parameter because it is C++-owned and already
/// crosses this boundary. Every relay C++ constructs today uses
/// `CRYPTONOTE_DANDELIONPP_MIN_EPOCH` (600 s); a future in-process caller
/// may pass another. Passing the choice through keeps one owner of it
/// rather than a second copy of the rule here.
///
/// Fluff reach is not a flag. An inbound session receives a fluff. The
/// old outbound-only bit is gone; passing bit 0 does nothing.
///
/// `configured` is the relay's identity: one bit per connector index. A
/// bit past the connector count refuses the handle. The epoch pair is the
/// caller's. The stem embargo is drawn later, from the connector that
/// forwarded the stem. Cover is refused unless some named connector's
/// encryption cell says the link is encrypted.
///
/// Returns null on input a relay cannot be built from: a `stems` that would
/// overflow the slot arithmetic, or a zero epoch — which is not merely useless
/// but harmful, since every wake would find the epoch expired and the daemon's
/// relay timer would spin. The caller treats null as a startup logic error.
///
/// It also returns null on a configuration [`Relay::new`] refuses.
/// `SHEKYL_RELAY_ZONE_NOISE_ENABLED` with no link-encrypted connector is
/// noise on a cleartext link, where padding sizes conceals nothing an
/// observer cannot already read. [`Relay::new`] also refuses a channel
/// count other than the inherited width, and a noise epoch too short to
/// carry a full-size message. Every [`shekyl_relay::RelayNewError`] maps
/// to null because that is the only channel a C ABI has.
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_new(
    now_ms: u64,
    stems: usize,
    min_epoch_secs: u32,
    epoch_jitter_secs: u32,
    flags: u32,
    configured: u32,
) -> *mut RelayZoneHandle {
    if stems == usize::MAX || min_epoch_secs == 0 {
        return std::ptr::null_mut();
    }
    let noise_enabled = flags & SHEKYL_RELAY_ZONE_NOISE_ENABLED != 0;
    let Ok(configured_connectors) = connectors_from_mask(configured) else {
        return std::ptr::null_mut();
    };
    // The epoch scheduler reads only this pair. Embargo timers are built
    // per connector inside `Relay::new`, from measured transit.
    let params = DandelionParams {
        min_epoch_secs,
        epoch_jitter_secs,
        ..DandelionParams::inherited()
    };
    let mut rng = SecureRelayRng;
    // `Err` is a refused configuration, not an allocation failure. See
    // `Relay::new`. Null is the only channel a C ABI has for saying so.
    let Ok(zone) = Relay::new(
        params,
        stems,
        noise_enabled,
        &configured_connectors,
        now_ms,
        &mut rng,
    ) else {
        return core::ptr::null_mut();
    };
    // The carrier's buffers are built exactly when the zone carries it. The
    // window is `dummy.len()` and nothing else (`carrier::WINDOW_BYTES` is a
    // construction parameter, never a runtime reference), so the dummy is
    // sized here and the queue owns the length invariant from then on.
    //
    // Built when the zone carries — which, by default, is never: the flag
    // comes from `set_carrier_development`, off unless a test or a developer
    // turns it on. `Some` here is the development posture, not the shipped one.
    //
    // `noise_notify` and not `vec![0; N]`: the dummy goes ON THE WIRE, so it
    // has to BE a levin message — command 0, `B|E`, body length written into
    // the header — or the peer rejects the zero signature and closes the
    // connection. An all-zeros buffer is the right length and not a frame,
    // which is the failure that looks like a working carrier locally and
    // drops every peer in production. The queue's own module doc names this
    // constructor; the first draft here ignored it.
    let noise = if noise_enabled {
        let Ok(dummy) = shekyl_levin::noise_notify(carrier::WINDOW_BYTES) else {
            return core::ptr::null_mut();
        };
        // The budget is what ONE EPOCH can deliver on a channel — a backlog
        // bound, since nothing drains the queue at a roll. It is the only
        // bound there is, and the caller's identity map grows behind it, so
        // the epoch is the argument that sizes both. See `window_budget`.
        let budget = carrier::noise_windows_in_epoch(min_epoch_secs) as usize;
        let Some(q) = NoiseQueues::new(stems, dummy, budget) else {
            // Same refusal channel as `Relay::new` above: a null handle.
            return core::ptr::null_mut();
        };
        Some(q)
    } else {
        None
    };
    let handle = RelayZoneHandle {
        driver: Driver::new(zone),
        noise,
        rng,
        live_stems: AtomicUsize::new(0),
        stem_in_flight: AtomicUsize::new(0),
        stem_tallies: Mutex::new(Arc::new(Vec::new())),
    };
    handle.publish();
    Box::into_raw(Box::new(handle))
}

/// Hand the carrier **one** transaction to carry on `channel`.
///
/// Returns `true` if it was accepted. `false` covers **every** refusal, and a
/// caller cannot tell them apart from the return alone — so they are listed
/// rather than implied, because "refused" reads as the queue's size rule and
/// most of these are not that:
///
/// - a null `handle` or `tx`, or `tx_len == 0`;
/// - a zone with **no carrier** — the ordinary case, since the flag defaults
///   off, and the one most likely to be misread as a fragment-size violation;
/// - serialising or framing the notification failed;
/// - the queue refused it: no such `channel`, or the framed message is not a
///   whole number of windows / exceeds `carrier::MAX_FRAGMENTS`;
/// - **the channel is FULL** — it already holds an epoch's worth of windows.
///
/// That last one is the only refusal reachable by doing nothing wrong. The
/// others are caller bugs or a transaction the carrier structurally cannot
/// take; this one means the carrier is saturated, and the answer is the
/// ordinary wire — which is what the producer does.
///
/// A single boolean is still kept deliberately, but NOT because "none of
/// these is recoverable", which is what this said before the budget existed
/// and is no longer true. It is kept because the caller's recovery is the
/// same for all of them: send it the ordinary way. A status enum would invite
/// branching on a distinction that changes nothing the caller does.
///
/// # One transaction per notification, made unrepresentable
///
/// `COVER_TRAFFIC_RESTORATION.md` §2.9b requires the carrier's caller to
/// normalise to one transaction per notification, because two transactions in
/// one carrier message share **one window, one slot and one successor** — the
/// pairwise linkage Dandelion++ exists to deny. No cap size fixes that, and
/// the queue cannot enforce it because it sees opaque bytes.
///
/// So this crossing takes **one transaction blob**, not a vector, and Rust
/// does the levin framing. A batch is not something a caller can express here
/// and then be refused for; it is not sayable. That is the difference between
/// a requirement and a check — §2.9b was documented for a later caller and
/// nearly went to the wrong owner entirely, which is exactly how a rule that
/// is only written down gets skipped.
///
/// `dandelionpp_fluff` is **false**: the carrier attaches *below* the phase,
/// and a transaction travelling on it is stemming.
///
/// # Safety
/// `handle` must be live. `tx` must cover `tx_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_noise_enqueue(
    handle: *mut RelayZoneHandle,
    channel: usize,
    tx: *const u8,
    tx_len: usize,
    token: u64,
) -> bool {
    if handle.is_null() || tx.is_null() || tx_len == 0 {
        return false;
    }
    let h = &mut *handle;
    let Some(q) = h.noise.as_mut() else {
        return false;
    };
    // Through the crate's FFI-read seam rather than a raw `from_raw_parts`:
    // it carries the `isize::MAX` language-level bound and the null check, and
    // SA-R-7's ratchet exists so a new raw site has to justify itself instead
    // of accruing quietly. There is nothing to justify here — this read is
    // exactly what the seam is for.
    let Some(blob) = crate::legacy_util::slice_from_ptr(tx, tx_len) else {
        return false;
    };
    let body = NewTransactions {
        txs: vec![blob.to_vec()],
        padding: Vec::new(),
        dandelionpp_fluff: false,
    };
    let Ok(payload) = body.store() else {
        return false;
    };

    // `fragmented_notify`, NOT `notify`. The queue slices what it is given
    // into window-sized emissions, so a single ordinary bucket puts a header
    // on the FIRST window only — and that header claims the whole body. Every
    // later window then goes out as headerless bytes, and the peer reads the
    // next ordinary message on that connection as a continuation of a body
    // that never ends. That corrupts the stream rather than losing a message.
    //
    // This is exactly what `fragmented_notify` exists for: each window gets
    // its own header (`B` / middle / `E`) and the last is zero-padded to the
    // window. It also SUPERSEDES the pad-to-a-whole-window loop that stood
    // here — padding to the window is its job, and it does it without the
    // convergence dance the padding field's own length varint forced.
    let Ok(framed) = shekyl_levin::fragmented_notify(q.window(), NOTIFY_NEW_TRANSACTIONS, &payload)
    else {
        return false;
    };
    q.enqueue(channel, framed, CarrierToken(token))
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

/// A peer's Levin handshake completed (session established).
///
/// A nil or null `id` is ignored: neither names a connection to track.
///
/// # Safety
/// `handle` must be live; `id` must point to 16 readable bytes, or be null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_on_session_established(
    handle: *mut RelayZoneHandle,
    id: *const u8,
    is_income: bool,
    network: u8,
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
    let Some(connector) = connector_from_byte(network) else {
        tracing::error!(
            "session established with connector byte {network:#x}; the relay does not know it, so the session is not registered"
        );
        return;
    };
    // `publish` is `&self` and must not overlap the `driver`/`rng` borrow.
    {
        let RelayZoneHandle { driver, rng, .. } = &mut *handle;
        driver
            .zone_mut()
            .on_session_established(peer, direction, connector, rng);
    }
    (*handle).publish();
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

/// Configured stem width (slot count). When noise is enabled this is also the
/// noise channel count — channel `i` follows slot `i`.
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

/// Whether this zone runs noise channels.
///
/// The **single owner** of a fact C++ used to re-derive at nine sites from
/// `!zone::noise.empty()` — a byte payload doing double duty as its own enable
/// flag (§20.4). C++ now asks rather than re-derives.
///
/// Frozen at construction, so this is a plain read with no publish/atomic
/// dance: unlike `live_stems` there is no writer after `new`, and nothing to
/// race. Returns `false` for a null handle — a caller that lost its zone has no
/// noise channels by construction, and the alternative (abort) would turn a
/// C++ lifetime bug into a daemon crash at a read that cannot itself be wrong.
///
/// # Safety
/// `handle` must be null or a live zone from [`shekyl_relay_zone_new`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_noise_enabled(handle: *const RelayZoneHandle) -> bool {
    match handle.as_ref() {
        Some(h) => h.driver.zone().noise_enabled(),
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
/// ever diverges from the embargo, the change is one field on `Relay`.
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
/// Returns how many of `hashes` this arrival resolved as **propagated**, and
/// writes their 32-byte ids into `out_propagated` in order. The count is
/// bounded by `n`, so a caller sizes the buffer once at `32 * n`. Passing
/// `out_propagated == null` — and only that argument — makes this a count-only
/// call: the verdicts are still resolved, nothing is written.
///
/// # Safety
/// `handle` must be null (returns 0) or a live zone from
/// [`shekyl_relay_zone_new`]. `hashes` must point at `32 * n` readable bytes
/// **or be null**, in which case nothing is recorded and the call returns 0 —
/// the boundary is deliberately tolerant here, so a caller bug is an empty
/// batch rather than undefined behaviour (see [`read_tx_ids`]). `from` must
/// point at 16 readable bytes when non-null, and `out_propagated` must be
/// null or writable for `32 * n` bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_record_arrival(
    handle: *mut RelayZoneHandle,
    hashes: *const u8,
    n: usize,
    from: *const u8,
    out_propagated: *mut u8,
) -> usize {
    let Some(h) = handle.as_mut() else { return 0 };
    let ids = read_tx_ids(hashes, n);
    if ids.is_empty() {
        return 0;
    }
    // One call with the whole batch, not one per id: `record_arrival` takes a
    // slice, and the per-id loop was re-entering the zone `n` times to do work
    // it does in one pass.
    let propagated = h.driver.zone_mut().record_arrival(&ids, read_id(from));
    h.publish();

    // The verdicts leave through a caller-sized buffer rather than a callback
    // or a retained store. Bounded by construction — `propagated` is a subset
    // of `ids` — so the caller sizes at `32 * n` once and never probes for a
    // count it might race.
    if out_propagated.is_null() {
        return propagated.len();
    }
    for (i, tx) in propagated.iter().enumerate() {
        core::ptr::copy_nonoverlapping(tx.as_bytes().as_ptr(), out_propagated.add(i * 32), 32);
    }
    propagated.len()
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
                    connector: t
                        .connector
                        .and_then(|connector| u8::try_from(connector.index()).ok())
                        .unwrap_or(CONNECTOR_BYTE_UNSPECIFIED),
                    _pad: [0; 7],
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

/// §18.4's diagnostic store. Process-global, keyed by connector index
/// (0 clearnet, 1 tor). Deliberately not on the relay handle: a wire path
/// reaches it only through this diagnostic export.
fn floor_watches() -> &'static Mutex<std::collections::HashMap<u8, FloorWatch>> {
    static WATCHES: std::sync::OnceLock<Mutex<std::collections::HashMap<u8, FloorWatch>>> =
        std::sync::OnceLock::new();
    WATCHES.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// §18.4's live diagnostic: record this connector's achieved outbound
/// connection count. Returns the floor transition (0 steady, 1 went below,
/// 2 recovered) for the operator warn log. The floor comparison lives in
/// [`FloorWatch::note`] — the logging path — and this state is readable by
/// nothing on a wire path (§18.3).
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_note_achieved_out(connector: u8, achieved: u32) -> u8 {
    match floor_watches().lock() {
        Ok(mut m) => m
            .entry(connector)
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
    connector: u8,
    out_achieved: *mut u32,
    out_floor: *mut u32,
    out_below: *mut bool,
) -> bool {
    if out_achieved.is_null() || out_floor.is_null() || out_below.is_null() {
        return false;
    }
    let snap = match floor_watches().lock() {
        Ok(m) => m.get(&connector).and_then(FloorWatch::snapshot),
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

/// A local origin keeps the pool record at `local` when hop 0 cannot draw
/// a clearnet edge.
///
/// Recording `stem` or `fluff` would let the pool's monotone upgrade leave
/// `local` permanently, and the next re-relay would publish the user's
/// transaction on every edge. An unknown method byte returns false: this
/// function does not invent a `local` claim for a class it cannot name.
/// `hop0_restricted` is the relay's construction bit, not a zone byte.
#[no_mangle]
pub extern "C" fn shekyl_relay_zone_origin_keeps_local_record(
    tx_relay: u8,
    hop0_restricted: bool,
) -> bool {
    shekyl_types::relay::RelayMethod::from_byte(tx_relay)
        .is_some_and(|method| shekyl_relay::origin_keeps_local_record(method, hop0_restricted))
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_next_wake(handle: *const RelayZoneHandle) -> u64 {
    if handle.is_null() {
        return 0;
    }
    (*handle).driver.next_wake()
}

/// Decide what to do with a batch: `SHEKYL_RELAY_PLAN_STEM` (writing the
/// successor into `out_dest`), `..._NO_ROUTE`, `..._FLUFF_EPOCH`, or
/// `..._AWAIT_SYNC`.
///
/// Not a bool, because the caller must distinguish a *transient* failure to
/// route — refresh connections and re-plan — from an epoch decision no
/// refresh can change, and from a hold that sends nothing. The routable
/// outcomes also produce different `relay_method` events. The alternative is
/// C++ re-evaluating `!fluffing || local_origin` for itself, which duplicates
/// the RD-4 predicate (§16.1); see [`RelayPlan`] for the full reasoning.
///
/// `node_synchronised` is this node's chain sync, converted once here into
/// [`NodeSync`]. It is not a second spelling of `local_origin`.
///
/// A null handle reports `NO_ROUTE`: nothing is routable through a zone that
/// does not exist, and the caller's fallback is then the safe one. That is
/// not an `AWAIT_SYNC` decision — there is no zone to withhold for.
///
/// `source` is the relaying peer, or the **nil UUID** for a transaction this
/// node originated — the distinction RD-4 turns on, so it is a contract rather
/// than a convention. Null is accepted and means the same thing.
///
/// Production notify prefers [`shekyl_relay_zone_plan_dispatch_with_refresh`].
/// [`shekyl_relay_zone_plan_relay_with_refresh`] owns the one mid-call refresh
/// on `NO_ROUTE`. This pure plan remains for callers that already refreshed
/// (send-failure retry) and for tests. `AWAIT_SYNC` does not refresh.
///
/// # Safety
/// `handle` must be live; `source` must point to 16 readable bytes or be null;
/// `out_dest` must point to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_plan_relay(
    handle: *mut RelayZoneHandle,
    source: *const u8,
    local_origin: bool,
    node_synchronised: bool,
    out_dest: *mut u8,
) -> i32 {
    if handle.is_null() || out_dest.is_null() {
        return SHEKYL_RELAY_PLAN_NO_ROUTE;
    }
    let h = &mut *handle;
    let source = read_id(source);
    let plan = h.driver.zone_mut().plan_relay(
        source,
        local_origin,
        node_sync_from_ffi(node_synchronised),
        &mut h.rng,
    );
    h.publish();
    write_plan(plan, out_dest)
}

/// Plan a relay; on `NO_ROUTE`, merge this zone's established outbound
/// sessions into the stem map once and re-plan.
///
/// The refresh policy lives in Rust with the rest of zone scheduling. The
/// candidates are the session registry. A settled fluff epoch does not
/// refresh, and neither does `AWAIT_SYNC`. See
/// [`shekyl_relay::Relay::plan_relay_with_refresh`]. No callback: commands
/// return nothing, and a covert channel the refresh leaves unbound clears at
/// its next due tick through [`shekyl_relay_zone_poll`]'s `on_unbind`.
///
/// # Safety
/// `handle` must be live; `source` must point to 16 readable bytes or be null;
/// `out_dest` must point to 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_plan_relay_with_refresh(
    handle: *mut RelayZoneHandle,
    source: *const u8,
    local_origin: bool,
    node_synchronised: bool,
    out_dest: *mut u8,
) -> i32 {
    if handle.is_null() || out_dest.is_null() {
        return SHEKYL_RELAY_PLAN_NO_ROUTE;
    }
    let h = &mut *handle;
    let source = read_id(source);
    let plan = h.driver.zone_mut().plan_relay_with_refresh(
        source,
        local_origin,
        node_sync_from_ffi(node_synchronised),
        &mut h.rng,
    );
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
        RelayPlan::AwaitSync => {
            std::ptr::copy_nonoverlapping(NIL.as_ptr(), out_dest, 16);
            SHEKYL_RELAY_PLAN_AWAIT_SYNC
        }
    }
}

/// Plan a relay **and** the wire that carries it — phase, carrier and slot in
/// **one** crossing (rule 40).
///
/// Supersedes [`shekyl_relay_zone_plan_relay_with_refresh`] for the covert
/// path. Phase, carrier, and slot cross together rather than as an
/// intermediate verdict the caller would map a second time.
///
/// Return value is the same `SHEKYL_RELAY_PLAN_*` code as the older entry
/// point, so a caller that ignores the carrier reads exactly what it read
/// before. `out_carrier` receives `SHEKYL_RELAY_CARRIER_*`; `out_channel`
/// receives the covert channel — **which is the stem slot index** — and is
/// meaningful **only** when the carrier is covert. It is written as `0` on the
/// ordinary carrier rather than left untouched, so a caller cannot read a stale
/// slot from a previous call.
///
/// # Its production caller landed 2026-08-29
///
/// `DAEMON_RELAY_PRIVACY.md` §42.5b's ownership split landed the decision half
/// first, and this entry point stood without a caller until then — kept
/// deliberately, because the audit at `COVER_TRAFFIC_RESTORATION.md` §1.6
/// states the conditions under which the cover mechanism may be removed and
/// none of them is a caller grep.
///
/// `dandelionpp_notify` is that caller now: it consumes this plan and enqueues
/// on `SHEKYL_RELAY_CARRIER_NOISE` instead of sending directly
/// (`COVER_TRAFFIC_RESTORATION.md` §3.1a).
///
/// # Safety
/// `handle` must be live; `source` must point to 16 readable bytes or be null;
/// `out_dest` must point to 16 writable bytes; `out_carrier` must point to one
/// writable byte; `out_channel` must point to a writable `u32`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_plan_dispatch_with_refresh(
    handle: *mut RelayZoneHandle,
    source: *const u8,
    local_origin: bool,
    node_synchronised: bool,
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
        // `out_dest` too: the comment above claims EVERY out-param, and it did
        // not cover this one. A caller that mishandles the return code would
        // otherwise read whatever was in its buffer as a stem successor.
        if !out_dest.is_null() {
            std::ptr::copy_nonoverlapping(NIL.as_ptr(), out_dest, 16);
        }
        return SHEKYL_RELAY_PLAN_NO_ROUTE;
    }
    let h = &mut *handle;
    let source = read_id(source);
    let dispatch = h.driver.zone_mut().plan_dispatch_with_refresh(
        source,
        local_origin,
        node_sync_from_ffi(node_synchronised),
        &mut h.rng,
    );
    h.publish();
    match dispatch.carrier {
        RelayCarrier::Ordinary => {
            *out_carrier = SHEKYL_RELAY_CARRIER_ORDINARY;
            *out_channel = 0;
        }
        RelayCarrier::Noise { channel } => match u32::try_from(channel.get()) {
            Ok(channel) => {
                *out_carrier = SHEKYL_RELAY_CARRIER_NOISE;
                *out_channel = channel;
            }
            Err(_) => {
                /* Unreachable: `channel` is a stem slot index, bounded by the
                stem width. Handled anyway because the previous spelling was
                `unwrap_or(u32::MAX)`, and `u32::MAX` is the worst possible
                value to hand across a boundary where it becomes an index —
                a clamp that fabricates an out-of-bounds channel is strictly
                worse than no clamp.

                Degrades the CARRIER, not the routing: the stem still goes,
                over the ordinary connection. §92.4's rule is that carrier
                unavailability must never travel as a routing verdict, which
                is why this is not a NO_ROUTE. */
                debug_assert!(false, "noise channel {} exceeds u32", channel.get());
                *out_carrier = SHEKYL_RELAY_CARRIER_ORDINARY;
                *out_channel = 0;
            }
        },
    }
    write_plan(dispatch.plan, out_dest)
}

/// Merge this zone's established outbound sessions into the stem map.
///
/// An outbound handshake already does this. What remains is the explicit
/// refresh: a covert send that failed, and the retry after a stem send
/// failure. A full map returns unchanged and draws nothing. No callback:
/// commands return nothing, and a covert channel the merge leaves unbound
/// clears at its next due tick through [`shekyl_relay_zone_poll`]'s
/// `on_unbind`.
///
/// # Safety
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_update_stems(handle: *mut RelayZoneHandle) {
    if handle.is_null() {
        return;
    }
    let h = &mut *handle;
    // Since §20.3 nothing re-points on a push — an unbound channel clears at
    // its next due tick via `poll`. Candidates are the zone's outbound sessions.
    h.driver.zone_mut().update_stems(&mut h.rng);
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
/// An epoch boundary rebuilds the stem map from the zone's established
/// outbound sessions. A fluff-release wake does not.
///
/// # Safety
/// `handle` must be live; the callbacks must be valid for the duration of the
/// call and must not unwind.
///
/// **NO CALLBACK MAY RE-ENTER THIS HANDLE.** This function holds
/// `&mut RelayZoneHandle` for its whole body — and a mutable borrow of the
/// carrier queue across `dispatch` — while it invokes every callback. Calling
/// any `shekyl_relay_zone_*` function on the same handle from inside one
/// constructs a second `&mut` aliasing those live borrows, which is undefined
/// behaviour. It applies to all three callbacks: buffer whatever the
/// callback learns and act on it after this returns.
///
/// Stated on both sides of the boundary deliberately: a Rust caller reads this
/// section, a C caller reads `shekyl_relay_zone_poll` in `shekyl_ffi.h`, and
/// neither doc system can reference the other — the FFI boundary is the
/// uncrossable one that earns a second copy. Both must name all three
/// callbacks. The C++ producer did exactly this, recording a stem observation
/// from the resolution callback, until review caught it.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_poll(
    handle: *mut RelayZoneHandle,
    now_ms: u64,
    ctx: *mut c_void,
    on_fluff: FluffCb,
    on_noise: NoiseSendCb,
    on_carrier_resolved: CarrierResolvedCb,
) {
    if handle.is_null() {
        return;
    }
    let h = &mut *handle;
    let effects = h.driver.poll(now_ms, &mut h.rng);
    h.publish();
    dispatch(
        effects,
        ctx,
        on_fluff,
        on_noise,
        on_carrier_resolved,
        h.noise.as_mut(),
    );
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
    dispatch(
        effects,
        ctx,
        on_fluff,
        noop_noise,
        noop_carrier_resolved,
        None,
    );
}

/// Start a new epoch immediately — what `notify::run_epoch()` drives. No
/// callback: the rollover's covert consequences ride the schedule, exactly as
/// a deadline-crossing rollover's do.
///
/// # Safety
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn shekyl_relay_zone_force_epoch(handle: *mut RelayZoneHandle, now_ms: u64) {
    if handle.is_null() {
        return;
    }
    let h = &mut *handle;
    h.driver.force_epoch(now_ms, &mut h.rng);
    h.publish();
}

#[cfg(test)]
mod tests;
