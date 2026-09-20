// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon tip the `SF-D5` anchor gate runs against, and the freshness
//! policy that decides when it is too old to gate on (`WSS-24`).
//!
//! # Why the daemon and not the store
//!
//! The gate is `anchor ∈ [p − 720 − L, p − 720 + L]` for the persona's own
//! height `p`, with `L = 4`. `p` used to be the **principal's block-scan
//! tip** — how far the wallet's own ingest had advanced the serving store.
//! Nothing bounds that lag below `L`: the only freshness check on the
//! serving side (`caught_up`, slack 64) feeds the operator alarm board and
//! gates nothing. So an honest `P` whose wallet refresh was five blocks
//! behind at challenge time refused a *valid* challenge, missed the pass,
//! and was slashed for its own scanner's cadence.
//!
//! The subject of the gate is the chain, so the reading must come from the
//! thing that tracks the chain: the configured daemon, read over `P`'s own
//! transport. A scan tip is a fact about the wallet; a daemon tip is a fact
//! about the chain, and only the second is what the anchor is anchored to.
//!
//! # Heights here are BLOCK heights, never chain heights
//!
//! Admission builds its window from `predecessor_height` — a block height —
//! and the window's centre is `predecessor_height − 720`
//! (`attestation_wire_kat.rs`'s `SIG_ANCHOR_HEIGHT`). `P`'s gate centres on
//! `own_height − 720`, so the two centres coincide only when `own_height` is
//! the **top block's height**.
//!
//! The daemon's `get_info.height` is the *chain* height — top block height
//! plus one (`core_rpc_server.cpp`: `get_blockchain_top(res.height, …);
//! ++res.height;`). A caller that stamped it unconverted would centre `P`'s
//! gate one block high and let it sign anchors that admission then refuses.
//! [`DaemonTipCache::stamp_synced`] therefore names its parameter
//! `top_block_height`, and the conversion belongs to whoever reads the RPC.
//!
//! # Why a cache, and why age is the thing bounded
//!
//! [`PassSigner::own_height`](shekyl_p_serve::PassSigner::own_height) is
//! synchronous — it is called from the serve loop's blocking pool, once per
//! fetch, and must not become a network round trip on the serving path. A
//! producer stamps this cache on a cadence and the gate reads it, which is
//! the shape that trait's doc already anticipates ("a host that stamps an
//! atomic is also fine").
//!
//! A cached height is wrong by however long it has sat. That error is
//! measured in the same unit as the gate's tolerance, so the bound is a
//! wall-clock age chosen well under `L` blocks by the caller that knows the
//! block target — not a constant picked here. Past `max_age` the reading is
//! [`None`], which is the same answer as "unreadable" and takes the same
//! path: the shared 404 plus a `ServeCounters` lookup failure. No new error
//! surface.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The daemon's tip as of a moment, or nothing.
///
/// `None` from [`height`](Self::height) means the gate must refuse, and it
/// means it for three different reasons that the serve loop deliberately
/// does not distinguish (all three render the identical 404):
///
/// - nothing has been stamped yet — the wallet has just started serving;
/// - the daemon last said something that means it is **not following the
///   chain**, so its tip is not the chain's tip;
/// - the last stamp is older than `max_age`.
///
/// # Reachability is absence of a fact, not a fact
///
/// A failed poll does **not** clear the cache: an unreachable daemon has
/// told us nothing, and the age bound already covers "nobody has confirmed
/// this recently". Clearing on a single transient RPC blip would refuse
/// every challenge in that window and slash an honest `P` for a dropped
/// loopback connection — the exact failure `WSS-24` exists to remove, coming
/// back through a different door.
///
/// A daemon that reports itself **not following the chain** is the opposite
/// case: that is an affirmative statement about its own tip, so
/// [`stamp_not_following`](Self::stamp_not_following) clears immediately
/// regardless of age. What counts as such a statement is the producer's to
/// decide — this type holds the consequence, not the diagnosis.
#[derive(Debug)]
pub struct DaemonTipCache {
    /// How old a stamp may be and still gate. Supplied by the caller that
    /// knows the block target (see the module doc).
    max_age: Duration,
    /// `Some((top_block_height, stamped_at))`, or `None` for "no usable
    /// tip". Plain data with no invariant across its fields, which is why a
    /// poisoned lock is recovered rather than propagated.
    state: Mutex<Option<(u64, Instant)>>,
}

impl DaemonTipCache {
    /// An empty cache whose stamps expire after `max_age`.
    ///
    /// Until the first [`stamp_synced`](Self::stamp_synced) the gate refuses
    /// everything, which is the correct direction: a persona that cannot say
    /// where the chain is must not certify where it was 720 blocks ago.
    #[must_use]
    pub fn new(max_age: Duration) -> Self {
        Self {
            max_age,
            state: Mutex::new(None),
        }
    }

    /// Record the daemon's tip, read at this moment from a daemon that
    /// reported itself synchronized.
    ///
    /// `top_block_height` is the height of the **top block** — not the
    /// chain height an info surface reports. See the module doc; getting
    /// this wrong centres the gate one block high.
    pub fn stamp_synced(&self, top_block_height: u64) {
        self.stamp_synced_at(top_block_height, Instant::now());
    }

    /// Record that the daemon is **not following the chain** — it is still
    /// syncing, has no peers, is offline, or knows it refused a switch.
    ///
    /// Clears any held tip: the daemon has affirmatively said its height is
    /// not the chain's, and a stale-but-young stamp from before it stopped
    /// following is not evidence about the chain now.
    ///
    /// Deliberately **not** called for an unreachable or unreadable daemon —
    /// see this type's doc: absence of a fact is not a fact.
    pub fn stamp_not_following(&self) {
        *self.guard() = None;
    }

    /// The tip to gate on, or `None` per [`DaemonTipCache`]'s contract.
    #[must_use]
    pub fn height(&self) -> Option<u64> {
        self.height_at(Instant::now())
    }

    /// [`stamp_synced`](Self::stamp_synced) against a caller-supplied
    /// instant, so the age policy is testable without sleeping.
    pub(crate) fn stamp_synced_at(&self, top_block_height: u64, at: Instant) {
        *self.guard() = Some((top_block_height, at));
    }

    /// [`height`](Self::height) against a caller-supplied `now`, so the age
    /// policy is testable without sleeping.
    ///
    /// `now` before the stamp (a clock that went backwards, or a test
    /// reading in the past) reads as age zero via `saturating_duration_since`
    /// rather than as an enormous age — the tip is not *less* trustworthy
    /// for the clock having moved the wrong way, and the next stamp fixes it.
    pub(crate) fn height_at(&self, now: Instant) -> Option<u64> {
        let (height, at) = (*self.guard())?;
        (now.saturating_duration_since(at) <= self.max_age).then_some(height)
    }

    /// The state, recovering a poisoned lock.
    ///
    /// The guarded value is `Copy` data with no invariant spanning its
    /// fields, so a panic elsewhere cannot have left it half-written. The
    /// alternative — propagating the poison — would turn an unrelated panic
    /// into a permanent refusal to serve, which is a slash.
    fn guard(&self) -> std::sync::MutexGuard<'_, Option<(u64, Instant)>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_AGE: Duration = Duration::from_secs(120);

    fn cache() -> DaemonTipCache {
        DaemonTipCache::new(MAX_AGE)
    }

    #[test]
    fn an_unstamped_cache_refuses() {
        assert_eq!(
            cache().height(),
            None,
            "a persona that has never read a tip must not gate on one"
        );
    }

    #[test]
    fn a_fresh_stamp_is_the_tip_it_recorded() {
        let c = cache();
        let now = Instant::now();
        c.stamp_synced_at(9_000, now);
        assert_eq!(c.height_at(now), Some(9_000));
    }

    /// The age bound is a boundary, and the boundary is inclusive: a stamp
    /// exactly `max_age` old still gates, one tick past it does not. Asserted
    /// on both sides so a `<` / `<=` flip cannot pass.
    #[test]
    fn a_stamp_gates_until_max_age_and_not_past_it() {
        let c = cache();
        let now = Instant::now();
        c.stamp_synced_at(9_000, now);

        assert_eq!(
            c.height_at(now + MAX_AGE),
            Some(9_000),
            "exactly at the bound is still fresh"
        );
        assert_eq!(
            c.height_at(now + MAX_AGE + Duration::from_millis(1)),
            None,
            "past the bound the tip is too old to centre a +/-4 block gate"
        );
    }

    /// Re-stamping is what keeps a persona serving: the age is measured from
    /// the latest stamp, not the first.
    #[test]
    fn restamping_restarts_the_age() {
        let c = cache();
        let t0 = Instant::now();
        c.stamp_synced_at(9_000, t0);
        let t1 = t0 + MAX_AGE;
        c.stamp_synced_at(9_001, t1);
        assert_eq!(
            c.height_at(t1 + MAX_AGE),
            Some(9_001),
            "the second stamp's age, not the first's"
        );
    }

    /// A daemon that says it is syncing invalidates the tip immediately —
    /// the distinguishing case against a plain age-out, which would have
    /// kept gating on the pre-sync stamp for the rest of its window.
    #[test]
    fn a_daemon_that_stopped_following_clears_a_stamp_that_is_still_young() {
        let c = cache();
        let now = Instant::now();
        c.stamp_synced_at(9_000, now);
        c.stamp_not_following();
        assert_eq!(
            c.height_at(now),
            None,
            "not-following is an affirmative fact about the tip, not a stale reading"
        );
    }

    /// The counterpart to the test above, and the reason the producer must
    /// *not* call `stamp_not_following` when a poll simply fails: an unreachable
    /// daemon leaves the held tip alone, and it ages out on schedule.
    #[test]
    fn a_held_tip_survives_until_it_ages_out_when_nothing_is_stamped() {
        let c = cache();
        let now = Instant::now();
        c.stamp_synced_at(9_000, now);
        // No stamp at all — the producer's poll failed.
        assert_eq!(
            c.height_at(now + MAX_AGE),
            Some(9_000),
            "a dropped loopback poll must not refuse an in-window challenge"
        );
        assert_eq!(c.height_at(now + MAX_AGE + Duration::from_secs(1)), None);
    }

    /// A clock that moves backwards must not read as an enormous age.
    #[test]
    fn a_reading_before_the_stamp_is_age_zero_not_expired() {
        let c = cache();
        let now = Instant::now();
        c.stamp_synced_at(9_000, now + Duration::from_secs(5));
        assert_eq!(c.height_at(now), Some(9_000));
    }
}
