// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The carrier's two **derived** sizes — the emission window and the fragment
//! cap.
//!
//! # Not `inherited`, and the distinction is the point
//!
//! [`super::inherited`] is the single Rust mirror of the `cryptonote_config.h`
//! relay block. These two are **not** mirrors: they replace
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

use crate::zone::RelayZone;

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
/// | modal tx (1-in/2-out) at `MAX_TREE_DEPTH`, widest fee varint | 17,015 |
/// | `NOTIFY_NEW_TRANSACTIONS` envelope | 77 |
/// | **required** | **17,092** |
/// | this window | 20,480 |
/// | margin | 3,388 (19.8 %) |
///
/// The envelope is **not** a constant: it steps 74 → 75 → 77 B as the
/// blob's length varint widens, and gains ~2 B per additional transaction
/// in a batch. 77 is its value for one transaction anywhere above the
/// 16 KiB varint boundary, which covers this whole range — but the test
/// measures it rather than assuming it, because a single reading at one
/// blob size would have embedded a shape into a shape-independent number.
///
/// Sized at *max* depth rather than genesis depth so the fragment count
/// cannot flip from 1 to 2 as the curve tree deepens: a hop that doubles on
/// a chain-state threshold is exactly the timing-observable drift a fixed
/// window exists to avoid.
///
/// **Not sized to hold the largest admissible transaction.** That is the
/// fragment cap's job ([`MAX_FRAGMENTS`]); conflating the two forces a
/// ~98 KiB window, which at any usable cadence breaches the pre-registered
/// 8 KiB/s bandwidth ceiling (`COVER_TRAFFIC_RESTORATION.md` §1.7 axis 2).
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
/// `ceil(98_046 / 20_480) = 5`.
///
/// The transaction alone is **97,964 B at a realistic fee and 97,969 B at
/// `u64::MAX`** — the fee is a varint, so its width moves with its value.
/// Both figures appear in this round's notes and they are the same
/// transaction. The bound is taken at the wider one, because a bound
/// evaluated at a plausible fee is one a large fee can cross.
///
/// The structural max is the right basis *here*, where it is a correctness
/// bound that does not drift as the tree deepens — unlike the window, which
/// is sized for the latency of the common case.
///
/// Two ceilings sit above it and neither binds: the epoch affords
/// [`noise_windows_in_epoch`]`(300) = 44` windows — 20 before the 2026-08-28
/// cadence change, and the coincidence that made the inherited cap equal to
/// that number is gone rather than moved — and the levin packet limit affords
/// far more. Both are asserted in
/// `tests/carrier_window.rs` against the real constants. The derivation itself
/// is `ceil(S_max / WINDOW_BYTES)`, pinned as equality there — the inherited
/// 20 sat in `[ceil, epoch-ceiling]` and would still go green under a
/// one-sided bound.
pub const MAX_FRAGMENTS: u32 = 5;

/// Minimum gap between covert emissions, in **milliseconds**.
///
/// # No longer inherited, which is why it lives here
///
/// This was `inherited::NOISE_MIN_DELAY_SECS`, mirroring
/// `CRYPTONOTE_NOISE_MIN_DELAY` (10 s). That `#define` and
/// `CRYPTONOTE_NOISE_DELAY_RANGE` are **deleted from C++ by the same change
/// that moves the pair here** — they had zero readers, so keeping them would
/// have left two copies of a privacy constant with nothing forcing them to
/// agree, and this change makes them disagree. A mirror of nothing is not a
/// mirror; [`super::inherited`]'s own rule puts it in this module.
///
/// # Milliseconds, and the unit change is the safety mechanism
///
/// The shipped cadence is 3.333 s, which is not a whole number of seconds, so
/// seconds stopped being able to express it. Renaming `_SECS` to `_MS` is not
/// cosmetic: every consumer multiplied by 1 000, and a consumer missed during
/// a value-only edit would have compiled and run **1 000× wrong**. Renamed,
/// each one fails to build until it is read.
pub const NOISE_MIN_DELAY_MS: u32 = 3_333;

/// Width of the uniform jitter added to [`NOISE_MIN_DELAY_MS`], in
/// milliseconds. The draw is inclusive — `U[0, NOISE_DELAY_JITTER_MS]`.
///
/// **Must stay non-zero, and the reason is §56 rather than arithmetic.** At
/// zero the cadence has no width, the covert channel becomes a **metronome**,
/// and Q-11 Unit 2 disqualified that shape at a **1.000** re-identification
/// rate under the strong matcher — a fixed period is a permanent per-stream
/// identifier. The build fails rather than the daemon degrading, because the
/// failure is silent in both places it would land: the daemon would emit a
/// perfectly periodic carrier while still calling it jittered, and the Unit 2
/// sweep would run its `BoundedUniform` and `Metronome` arms on the *same law
/// under two names*.
///
/// # The jitter-to-base ratio is DOUBLED, deliberately — not preserved
///
/// Shipped was `10 s + U[0, 5 s]`: a ratio of **0.5**. This is
/// `3 333 + U[0, 3 334]`: a ratio of **1.0**. The cadence round was specified
/// as "preserving §56's ratio" and the numbers given did not preserve it — a
/// ratio-preserving 5 s mean would have been `4 000 + U[0, 2 000]`. Corrected
/// in the record rather than in the constants, because the doubling is in the
/// safe direction and is **measured**: more relative jitter is stronger
/// against a matcher, and §56.7's bounded residual falling 0.120 → 0.058 at a
/// 10 s blackout is that effect.
///
/// **Do not read 1.0 as the invariant.** §56 constrains the jitter to be
/// non-zero, and the real standing requirement is that jitter **scales with
/// the base rather than staying fixed** — a fixed width against a shrinking
/// base is the path back to the metronome. Neither 0.5 nor 1.0 is a derived
/// quantity; the warrant for this one is the linkage measurement, and a future
/// cadence should re-measure rather than copy the number.
///
/// # Why 3 334 and not 3 333
///
/// The odd split is what makes the mean **exactly** 5 000 ms:
/// `3 333 + 3 334/2`. A symmetric `3 333 + U[0, 3 333]` means 4 999.5 ms,
/// which puts the worst-posture node rate at 16 385.6 B/s — **1.6 B/s above**
/// [`PER_NODE_CEILING_BYTES_PER_SEC`], so the ceiling assert below would fail
/// on a rounding artifact rather than on a design decision. Half a
/// millisecond of asymmetry is not a privacy quantity; a ceiling that holds
/// by construction is.
pub const NOISE_DELAY_JITTER_MS: u32 = 3_334;

const _: () = assert!(
    NOISE_DELAY_JITTER_MS > 0,
    "covert cadence jitter must be non-zero: at zero the carrier is a \
     metronome, which Q-11 Unit 2 (§56) disqualified at a 1.000 \
     re-identification rate"
);

/// Mean covert cadence, in milliseconds: `min + width/2`, the jitter being
/// uniform and inclusive.
pub const MEAN_CADENCE_MS: u32 = NOISE_MIN_DELAY_MS + NOISE_DELAY_JITTER_MS / 2;

const _: () = assert!(
    MEAN_CADENCE_MS == 5_000,
    "the cadence mean is the bandwidth denominator and every rate figure in \
     COVER_TRAFFIC_RESTORATION.md sec 3.3 is stated against exactly 5 000 ms"
);

/// Encrypted zones one node may carry at once — the **worst posture**.
///
/// Tor and I2P today. This is the multiplier that made the old per-zone
/// figure misleading: `NOISE_CHANNELS` is documented as *"max outbound
/// connections **per zone**"*, so a per-zone rate understates a dual-zone node
/// by exactly this factor.
///
/// # Counted from the canonical zone set, not transcribed
///
/// A literal `2` here would have been a hand-maintained copy of an answer that
/// lives in [`RelayZone::is_encrypted`], and the ceiling's whole claim is that
/// adding a third encrypted zone is a **build break**. A transcribed count
/// makes that claim false — the new zone would raise the real bandwidth while
/// this constant, and therefore the assert, stayed put. So it is derived from
/// [`RelayZone::ALL`] through the same predicate the carrier uses to decide
/// noise eligibility, and `RelayZone::position`'s wildcard-free match is what
/// stops a new variant from being added without passing through here.
pub const CEILING_ZONES: u32 = {
    let mut i = 0;
    let mut n = 0;
    while i < RelayZone::ALL.len() {
        if RelayZone::ALL[i].is_encrypted() {
            n += 1;
        }
        i += 1;
    }
    n
};

/// SUSTAINED cover-bandwidth ceiling, **per node**, in bytes per second.
///
/// # The denominator is per NODE, ruled 2026-08-28
///
/// `COVER_TRAFFIC_RESTORATION.md` §3.3 recorded the two halves of the old
/// comparison sitting on different denominators — an 8 KiB/s ceiling checked
/// against a per-*zone* figure — and left the ruling owed. It is per node.
/// A dual-zone node is the posture to state, because it is the one that
/// exists, and a per-zone ceiling leaves the per-node total unbounded in the
/// number of zones.
///
/// # SUSTAINED, and the word is load-bearing
///
/// The denominator is [`MEAN_CADENCE_MS`], so this bounds the **long-run mean**
/// rate — which is the quantity a link is provisioned against, and the one
/// "cover bandwidth per node" means. It is **not** an instantaneous cap. A
/// jittered emitter's shortest interval is [`NOISE_MIN_DELAY_MS`], so a burst
/// runs at [`PER_NODE_PEAK_BYTES_PER_SEC`] — `mean / min` = 1.5× this figure —
/// and over any finite window the realised average sits either side of the
/// mean rather than under it.
///
/// That is inherent to a jittered cadence rather than a defect in the budget:
/// removing the overshoot means removing the jitter, which is the metronome
/// §56 disqualified. Both numbers are stated so a reader provisioning a
/// circuit uses the peak and a reader pricing a month uses the mean, instead
/// of one number being asked to do both jobs.
///
/// # It is a statement of maximum cost, not a bound with slack
///
/// The assert below holds at **exact equality** and that is deliberate:
/// `20 480 B × 2 channels × 2 zones ÷ 5 s = 16 384 B/s`. §3.3 objected that a
/// ceiling at 1.25× margin was "not constraining a future cadence proposal
/// without constraining this one"; at 1.0× it does not pretend to. What it
/// does instead is make any future change **say so** — shortening the cadence,
/// widening the window, or adding a third encrypted zone is a build break
/// here, and moving the ceiling becomes an explicit edit with a reason rather
/// than a figure quietly going stale in a table.
pub const PER_NODE_CEILING_BYTES_PER_SEC: u32 = 16 * 1024;

// Cross-multiplied rather than divided, and the reason is the claim above.
// `PER_NODE_CEILING_BYTES_PER_SEC` says the ceiling holds *by construction*;
// an integer division floors, so a breach smaller than 1 B/s would satisfy a
// `rate <= ceiling` form while the true average sat over it. The rational
// comparison has no such gap — and a check that rounds cannot support a claim
// that the constants were chosen to avoid rounding.
const _: () = assert!(
    (WINDOW_BYTES as u64)
        * (super::inherited::NOISE_CHANNELS as u64)
        * (CEILING_ZONES as u64)
        * 1_000
        <= (PER_NODE_CEILING_BYTES_PER_SEC as u64) * (MEAN_CADENCE_MS as u64),
    "worst-posture cover bandwidth exceeds the per-node ceiling: WINDOW_BYTES \
     x NOISE_CHANNELS x CEILING_ZONES / mean cadence must stay at or under \
     PER_NODE_CEILING_BYTES_PER_SEC (COVER_TRAFFIC_RESTORATION.md sec 3.3)"
);

/// Peak cover bandwidth per node, in bytes per second — the burst a circuit
/// has to absorb, as opposed to the sustained load it is provisioned for.
///
/// Every channel emitting at [`NOISE_MIN_DELAY_MS`], the shortest interval the
/// cadence can draw. Exactly `mean / min` = **1.5×**
/// [`PER_NODE_CEILING_BYTES_PER_SEC`], and it is derived rather than written
/// so it cannot drift from the cadence it comes out of.
///
/// **Deliberately not asserted against a ceiling of its own.** No peak budget
/// has ever been pre-registered, and inventing one here would be a constant
/// with no warrant — the kind of number a later reader treats as derived
/// because it sits next to derived ones. What it is for is disclosure: §3.3's
/// figures are sustained, and an operator sizing a circuit needs this one.
pub const PER_NODE_PEAK_BYTES_PER_SEC: u32 = {
    let raw = (WINDOW_BYTES as u64)
        * (super::inherited::NOISE_CHANNELS as u64)
        * (CEILING_ZONES as u64)
        * 1_000
        / (NOISE_MIN_DELAY_MS as u64);
    // Checked rather than assumed. Unlike `noise_windows_in_epoch`, the fit is
    // NOT provable from the shape of the expression: `peak = sustained x
    // mean/min`, and `mean/min` is unbounded as the jitter grows against the
    // base. It is 1.5x today; an assert is what keeps that from becoming a
    // silent truncation if it ever is not.
    assert!(
        raw <= u32::MAX as u64,
        "peak cover bandwidth no longer fits u32"
    );
    #[allow(clippy::cast_possible_truncation)]
    {
        raw as u32
    }
};

/// Windows an epoch of `min_epoch_secs` affords at the **slowest** cadence
/// (`NOISE_MIN_DELAY_MS + NOISE_DELAY_JITTER_MS`).
///
/// Integer division: one window short of `MAX_FRAGMENTS * per_send` drops a
/// whole window. A full-size message still occupying a window when the epoch
/// rolls is discarded by CV-1 and never arrives.
///
/// This is the **ceiling** [`MAX_FRAGMENTS`] must stay under, not its
/// definition — the inherited value was silently set equal to it.
///
/// Moved here with the cadence it divides by, and now in milliseconds.
///
/// Widened to `u64` internally: `min_epoch_secs * 1_000` in `u32` caps the
/// domain at ~49 days of epoch and panics in debug above it. The epoch is a
/// security parameter that this arc has already discussed lengthening (§57's
/// second exit), so a silent domain limit on the function that prices it is
/// the wrong place to economise.
#[must_use]
// The `as u32` cannot truncate: `per_send` is 6 667 ms, comfortably over
// 1 000, so the quotient is strictly LESS than `min_epoch_secs` — which is
// already a `u32`. Widening the numerator removes the overflow without
// widening the result.
#[allow(clippy::cast_possible_truncation)]
pub const fn noise_windows_in_epoch(min_epoch_secs: u32) -> u32 {
    let per_send = (NOISE_MIN_DELAY_MS + NOISE_DELAY_JITTER_MS) as u64;
    ((min_epoch_secs as u64 * 1_000) / per_send) as u32
}
