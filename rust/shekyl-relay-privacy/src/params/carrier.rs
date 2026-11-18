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
//! [`noise_windows_in_epoch`]`(300)`** — the epoch *ceiling*
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

/// The hold before a node starts a broadcast that ends a stem, in carrier
/// windows: the hold is this many independent draws of the cadence
/// (`CVR-R10`; Rick, 2026-11-18).
///
/// # Why a hold
///
/// On clearnet, cover runs on a node's stem connections and nowhere else,
/// so a watcher of the node's links sees which connections are stems. A
/// broadcast that starts the moment a stem arrives then shows which stem
/// connection just delivered a transaction: the last stem hop. The hold
/// puts windows from every stem predecessor between the delivery and the
/// broadcast, so the broadcast's start no longer points at one of them.
///
/// # The length
///
/// What it must achieve: by the time the broadcast starts, several windows
/// have arrived from each of the node's stem predecessors. Each predecessor
/// sends on its channel at the memoryless cadence, so over a hold of `n`
/// cadence draws it sends a count with mean `n`, and the chance it sends
/// none is `2^−n` (the hold and its windows are draws of one law). `n` is
/// [`MAX_FRAGMENTS`]: every predecessor is expected to send as many windows
/// as the longest message occupies, so the delivering run, however many
/// windows it took, sits inside a span in which every predecessor sent a
/// run as long. At five, a given predecessor sends nothing during the hold
/// one time in 32, and at least two windows about nine times in ten. The
/// mean hold is `MAX_FRAGMENTS × MEAN_CADENCE_MS`, 25 s, added to a
/// transaction's propagation at the node that ends its stem.
///
/// # The ambiguity it buys
///
/// Drawn from the window schedule and nothing about the transaction, the
/// hold is independent of which predecessor delivered. A watcher who sees
/// the broadcast start sees, from each of the node's `P` stem predecessors,
/// about [`MAX_FRAGMENTS`] windows over the hold before it, and any of them
/// may be the delivery. With one predecessor there is nothing to choose
/// between: the last stem hop is that predecessor, a residual the user
/// documents state. On Tor a watcher cannot separate the node's
/// connections, so there is nothing to point at. How well a watcher still
/// picks the delivering predecessor, by the node's count of predecessors,
/// is measured with the pass mark (`CVR-R7`); the per-peer delays as a
/// broadcast spreads (`FLUFF_AVERAGE_*`) are unchanged.
pub const BROADCAST_HOLD_WINDOWS: u32 = MAX_FRAGMENTS;

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
pub const PER_NODE_BUDGET_BYTES_PER_SEC: u32 = 8 * 1024;

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
/// against this, not against the node budget. The upload floor
/// (`p2p-upload-max` against the cover rate) and the design-load floor
/// check (`tests/carrier_window.rs`) read it.
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

/// Windows an epoch of `min_epoch_secs` delivers on one channel at the mean
/// cadence: the size of a channel's backlog bound.
///
/// Integer division, so a partial window does not count. A backlog bound,
/// not a delivery promise: a message accepted behind it waits up to about an
/// epoch for the wire.
#[must_use]
// The `as u32` cannot truncate: the mean is 5 000 ms, over 1 000, so the
// quotient is strictly less than `min_epoch_secs`, already a `u32`.
#[allow(clippy::cast_possible_truncation)]
pub const fn noise_windows_in_epoch(min_epoch_secs: u32) -> u32 {
    ((min_epoch_secs as u64 * 1_000) / MEAN_CADENCE_MS as u64) as u32
}
