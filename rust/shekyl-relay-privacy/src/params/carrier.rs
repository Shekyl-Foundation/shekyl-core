// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The carrier's numbers: the emission window and the fragment cap, both
//! derived from the transactions they carry; the cover budget, the one stated
//! number (`CVR-R5`); and the cadence and the epoch tail derived from those.
//!
//! # Not `inherited`, and the distinction is the point
//!
//! [`super::inherited`] holds the values the C++ relay block carried. These
//! two are **not** inherited: they replace
//! `CRYPTONOTE_NOISE_BYTES` (3 KiB) and `CRYPTONOTE_MAX_FRAGMENTS` (20), both
//! of which are deleted from C++ by the same change that adds this module —
//! discharging the FOLLOWUP `levin_notify.cpp` recorded beside its own guard
//! ("*the constants should cross to Rust and `NoiseQueues`' window should be
//! derived from them, at which point this assertion moves with them*").
//!
//! # Why the inherited pair could not stay
//!
//! Neither had a derivation. The 3 KiB window was a Monero cadence artifact,
//! and **`CRYPTONOTE_MAX_FRAGMENTS` was set equal to
//! the windows a 300 s epoch afforded** — the epoch *ceiling*
//! on the cap rather than a cap derived from the transactions it has to carry.
//! It was a number satisfying a constraint nobody had connected to its
//! subject, so it was unattached rather than wrong.

/// Bytes in one noise emission — every send, real fragment and dummy alike.
///
/// # A construction parameter, NOT a runtime reference
///
/// This sizes the dummy a caller hands to `NoiseQueues::new`. The queue's
/// own `window()` is `dummy.len()` **and nothing else**, deliberately: one
/// source of truth inside the queue is what makes the length property
/// checkable there. **Nothing may read this constant at send time.** If a
/// caller ever compares `queue.window()` against this value, the duplicate
/// that design removed is back — and the two can then disagree, which is
/// the length leak the invariant exists to prevent.
///
/// # Derivation
///
/// The modal transaction whole at **every** tree depth, plus its levin
/// envelope, plus margin:
///
/// | term | bytes |
/// | --- | --- |
/// | modal tx (1-in/2-out) at `MAX_TREE_DEPTH`, widest fee varint | 17,080 |
/// | `NOTIFY_NEW_TRANSACTIONS` envelope | 73 |
/// | **required** | **17,153** |
/// | this window | 20,480 |
/// | margin | 3,327 (19.4 %) |
///
/// The envelope is **not** a constant: it steps 70 → 71 → 73 B as the
/// blob's length varint widens (at 64 B and at 16 KiB), and each
/// additional transaction in a batch adds 2 B below 16 KiB and 4 B at or
/// above it. 73 is its value for one transaction anywhere above the 16 KiB
/// varint boundary, which covers this whole range — but the test measures
/// it rather than assuming it, because a
/// single reading at one blob size would have embedded a shape into a
/// shape-independent number.
///
/// Sized at *max* depth rather than genesis depth so the fragment count
/// cannot flip from 1 to 2 as the curve tree deepens: a hop that doubles on
/// a chain-state threshold is exactly the timing-observable drift a fixed
/// window exists to avoid.
///
/// **Not sized to hold the largest admissible transaction.** That is the
/// fragment cap's job ([`MAX_FRAGMENTS`]); conflating the two forces a
/// ~98 KiB window, which at the same cadence spends close to five times
/// [`PER_NODE_BUDGET_BYTES_PER_SEC`]. `tests/carrier_window.rs` asserts that
/// breach as the negative control, rather than leaving it as an assertion
/// in prose.
///
/// The derivation is **enforced, not performed** — `tests/carrier_window.rs`
/// builds a real `NOTIFY_NEW_TRANSACTIONS` at the predicted size and
/// asserts it fits, so a proof-size change reds a test naming this constant
/// instead of silently eroding the margin. Both numbers above are read back
/// from `predict_size_and_weight` and `notify` there; neither is a literal
/// the test could agree with by construction.
pub const WINDOW_BYTES: usize = 20_480;

/// The most windows one real notification may occupy on a noise channel.
///
/// # Derived, and comfortable
///
/// A correctness bound: `ceil(S_max / WINDOW_BYTES)`, where `S_max` is the
/// **structural** maximum message — the largest transaction the wire admits
/// (8-in/16-out at `MAX_TREE_DEPTH`) plus its levin envelope, which is
/// `ceil(97_658 / 20_480) = 5`.
///
/// The transaction alone is **97,580 B at a five-byte fee varint and
/// 97,585 B at `u64::MAX`** — the fee is a varint, so its width moves with
/// its value. A note that gives two figures for it is giving this one
/// transaction at two fees. The bound is taken at the wider one, because a bound
/// evaluated at a plausible fee is one a large fee can cross.
///
/// The structural max is the right basis *here*, where it is a correctness
/// bound that does not drift as the tree deepens — unlike the window, which
/// is sized for the latency of the common case.
///
/// The levin packet limit affords far more; `tests/carrier_window.rs`
/// asserts it against the real constant. The derivation itself is
/// `ceil(S_max / WINDOW_BYTES)`, pinned as equality there, because a
/// one-sided bound would go green under any larger cap.
///
/// It also sizes the epoch tail ([`EPOCH_TAIL_WINDOWS`]), which is what lets
/// a message started just before an epoch boundary finish on the peer it
/// started with.
pub const MAX_FRAGMENTS: u32 = 5;

/// Windows each channel sends to the peer it was bound to after an epoch
/// boundary, before it takes its new peer (`CVR-R4`; Rick, 2026-11-18).
///
/// `MAX_FRAGMENTS − 1`: a message may start in the last window before the
/// boundary, and a full-size one then needs this many more to finish. No
/// new message starts during the tail, so every message that started before
/// the boundary finishes on its own peer, and a roll never hands a prefix of
/// a transaction to a peer that will not see the rest. With nothing in
/// flight the tail's windows are dummies, and the switch comes after the
/// same count of windows either way, so the switch point says nothing about
/// whether a message was in flight.
///
/// This replaces a probability check that a full-size message clears its
/// epoch: under a memoryless cadence no epoch length guarantees that, and
/// the tail makes the epoch length irrelevant to it. Peer loss still
/// restarts a half-sent message (CV-1); that does not depend on what was
/// being sent.
pub const EPOCH_TAIL_WINDOWS: u32 = MAX_FRAGMENTS - 1;

/// The cover budget, **per node**, in bytes per second: 8 KiB/s
/// (`CVR-R5`; Rick, 2026-11-15).
///
/// The one stated number of the carrier. The cadence follows from it
/// ([`MEAN_CADENCE_MS`]); nothing else here is chosen. Per node, with no
/// network term: a node runs [`super::inherited::NOISE_CHANNELS`] channels,
/// one per stem slot, whatever connectors the sessions in those slots ride,
/// so a second network adds no channel and no bytes.
///
/// It is a mean. The cadence is memoryless, so over a short span the rate
/// sits either side of it and has no peak to state; over a day it is this
/// figure times the seconds the carrier runs.
///
/// **It counts plaintext** (Rick, 2026-11-19): the bytes the carrier hands
/// to its sessions, [`WINDOW_BYTES`] a window. What a connector adds to
/// frame a window is that connector's cost and is not in this figure:
/// clearnet under Noise adds 34 bytes a window on the wire, and Tor adds
/// none at the seam this node writes to. So the cadence is an exact
/// 5 000 ms on every connector, and a node's cover on the wire is this
/// figure plus its connectors' framing.
pub const PER_NODE_BUDGET_BYTES_PER_SEC: u32 = 8 * 1024;

/// How many cover budgets the smallest upload limit is.
///
/// **Stated, not derived** (Rick, 2026-11-19). One budget is the cover;
/// the second is room for the connectors' framing of it and for everything
/// else the node uploads. No measurement stands behind the 2, and it
/// reopens before genesis with the budget (`TOR_COVER_POSTURE.md` §8).
pub const UPLOAD_FLOOR_BUDGETS: u32 = 2;

/// The smallest `p2p-upload-max` a node running cover may set, in bytes per
/// second: [`UPLOAD_FLOOR_BUDGETS`] × the budget, 16 KiB/s.
///
/// A limit below it is refused at start and at runtime while `relay-cover`
/// is on (`shekyl-daemon-config`, `read_rates`). It is taken from the
/// budget alone: no connector's framing is read into it.
///
/// It does not reserve anything. Under any limit a window takes its turn
/// at the link's limiter with the node's other writes, so cover is best
/// effort under the cap (`DAEMON_RELAY_PRIVACY.md` §93.2a).
pub const UPLOAD_FLOOR_BYTES_PER_SEC: u32 = UPLOAD_FLOOR_BUDGETS * PER_NODE_BUDGET_BYTES_PER_SEC;

/// Mean time between one channel's windows, in milliseconds: channels ×
/// window ÷ budget (`CVR-R5`), 5 000 ms.
///
/// Derived, so changing the budget, the window or the channel count moves
/// it, and the build fails rather than rounding if the division is not exact
/// (a rounded mean would put the node a fraction of a byte per second over
/// its budget, or under it, with nothing saying so).
pub const MEAN_CADENCE_MS: u32 = {
    let numerator = (WINDOW_BYTES as u64) * (super::inherited::NOISE_CHANNELS as u64) * 1_000;
    let budget = PER_NODE_BUDGET_BYTES_PER_SEC as u64;
    assert!(
        numerator.is_multiple_of(budget),
        "channels x window / budget must be a whole number of milliseconds"
    );
    let mean = numerator / budget;
    assert!(
        mean > 0 && mean <= u32::MAX as u64,
        "the mean cadence fits u32"
    );
    #[allow(clippy::cast_possible_truncation)]
    {
        mean as u32
    }
};

/// The grain of the cadence draw, in milliseconds.
///
/// The cadence is memoryless (`CVR-R4`; §56.5): the wait before a channel's
/// next window is a geometric count of these ticks, the discrete form of an
/// exponential, so the time since the last window says nothing about when
/// the next comes and a transaction's arrival cannot be read off the
/// emission it rides. A bounded draw (`min + U[0, width]`) is the shape §56
/// measured a residual channel in, and it is gone.
///
/// Ten milliseconds: a tenth of the 100 ms resolution the pass mark scores
/// windows at (`CVR-R7`), so the grain sits below what the deciding test
/// can see, and the coarsest power of ten under it. A finer grain buys
/// nothing that test can resolve and needs a table past the geometric
/// table's support at this mean.
pub const CADENCE_TICK_MS: u32 = 10;

/// The cadence mean in [`CADENCE_TICK_MS`] ticks: the geometric table's
/// mean. Exact, or the build fails.
pub const MEAN_CADENCE_TICKS: u32 = {
    assert!(
        MEAN_CADENCE_MS.is_multiple_of(CADENCE_TICK_MS),
        "the mean cadence must be a whole number of ticks"
    );
    MEAN_CADENCE_MS / CADENCE_TICK_MS
};

/// One channel's mean rate, in bytes per second: one window per
/// [`MEAN_CADENCE_MS`], 4 096 B/s.
///
/// The figure a single connection carries: a channel rides one session, so
/// a Tor circuit or a clearnet connection carrying a channel is sized
/// against this, not against the node budget. The design-load floor check
/// (`tests/carrier_window.rs`) reads it.
pub const PER_CHANNEL_BYTES_PER_SEC: u32 = {
    let raw = (WINDOW_BYTES as u64) * 1_000 / (MEAN_CADENCE_MS as u64);
    assert!(raw <= u32::MAX as u64, "the channel rate fits u32");
    #[allow(clippy::cast_possible_truncation)]
    {
        raw as u32
    }
};

// The channels spend exactly the budget: cross-multiplied, so a breach
// smaller than one byte per second cannot hide in a floor.
const _: () = assert!(
    (PER_CHANNEL_BYTES_PER_SEC as u64) * (super::inherited::NOISE_CHANNELS as u64)
        == PER_NODE_BUDGET_BYTES_PER_SEC as u64,
    "the node's channels must spend exactly its cover budget"
);

/// The most windows one channel may hold pending: one full-size message
/// (`CVR-R5`; Rick, 2026-11-18).
///
/// A simple cap, not a derivation. A full-size message fits an empty
/// channel, and up to this many one-window messages queue behind one
/// another; beyond it the queue refuses, and the stem takes `CVR-R6`'s
/// fallbacks (a relayed stem ends its stem phase, this node's own
/// transaction waits). The embargo is sized at a channel's expected
/// occupancy ([`channel_occupancy`]), not with this cap present at every
/// hop: a queue this deep is rare at the design load, and a stem that
/// meets one is covered by the embargo's reshape, at a recovery slower
/// than without cover.
pub const BACKLOG_CAP_WINDOWS: u32 = MAX_FRAGMENTS;

/// The longest the embargo may be, in seconds: 30 minutes
/// (`COVER_TRAFFIC_RESTORATION.md` §1.7, Axis 1, a hard bound; kept, Rick
/// 2026-11-18).
///
/// Fixed, and derived from no per-connector embargo: a bound read off the
/// embargoes it bounds rises with them and never binds. Thirty minutes is
/// what a user can be told a transaction may take before it is seen.
pub const EMBARGO_LIMIT_SECS: u32 = 30 * 60;

/// The smallest network the embargo is sized for, in nodes: 100.
/// **Assumption** (Rick, 2026-11-18), until the fleet measures it.
///
/// Basis: a ruled starting figure, not a reading. A channel's load is the
/// network's stem traffic spread over every node's channels, so a smaller
/// network puts more of it on each one, and the embargo grows with it.
/// `tests/carrier_embargo.rs` pins the size below which the embargo would
/// pass [`EMBARGO_LIMIT_SECS`].
pub const SMALLEST_NETWORK_NODES: u32 = 100;

/// The network's transaction rate at its design capacity, in thousandths of
/// a transaction per second: the full-reward zone filled with the lightest
/// admissible transaction, every block. 199 (0.1986 per second, rounded up).
///
/// Stated here because this crate's default build links neither the wire
/// nor the chain's parameters; `tests/carrier_window.rs` enforces it against
/// `MIN_BLOCK_WEIGHT`, the lightest transaction's weight and the block time,
/// so a change to any of them reds a test naming this constant.
pub const DESIGN_NETWORK_MILLI_TX_PER_SEC: u32 = 199;

/// One channel's stem load at the design capacity, in transactions per
/// second, on a network of `nodes` nodes (`CVR-R5`).
///
/// Every transaction is stemmed for the mean stem length (`100 / q` hops at
/// a fluff probability of `q` per cent), and each hop occupies one channel
/// of one node; the network has [`super::inherited::NOISE_CHANNELS`]
/// channels per node.
#[must_use]
pub fn channel_load_tx_per_sec(nodes: u32, fluff_probability_pct: u32) -> f64 {
    let network = f64::from(DESIGN_NETWORK_MILLI_TX_PER_SEC) / 1_000.0;
    let stem_hops = 100.0 / f64::from(fluff_probability_pct);
    #[allow(clippy::cast_precision_loss)]
    let channels = super::inherited::NOISE_CHANNELS as f64 * f64::from(nodes);
    network * stem_hops / channels
}

/// The share of an epoch a channel spends in its tail, starting nothing:
/// the tail's mean span over the shortest epoch.
#[must_use]
pub fn tail_share(min_epoch_secs: u32) -> f64 {
    let tail_ms = f64::from(EPOCH_TAIL_WINDOWS) * f64::from(MEAN_CADENCE_MS);
    let epoch_ms = (f64::from(min_epoch_secs) * 1_000.0).max(1.0);
    (tail_ms / epoch_ms).min(1.0)
}

/// The share of the time a channel has a message ahead of the next one: its
/// load ([`channel_load_tx_per_sec`]) over its rate less the tail's share
/// ([`tail_share`]). Below one, or the channel cannot carry its load (the
/// floor check, `CVR-R5`).
#[must_use]
pub fn channel_occupancy(nodes: u32, fluff_probability_pct: u32, min_epoch_secs: u32) -> f64 {
    let rate = 1_000.0 / f64::from(MEAN_CADENCE_MS) * (1.0 - tail_share(min_epoch_secs));
    channel_load_tx_per_sec(nodes, fluff_probability_pct) / rate
}
