// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Derived challenge assignment — the exact-min urn
//! (`ARCHIVAL_CHALLENGE_MECHANISM.md` §2 / §7.1 ruling, build-authorized by
//! §9.5).
//!
//! `assignment(h) = f(block_hash(h−1), drawable_set)`: every node computes
//! the epoch's challenge assignments identically from chain state; nothing
//! is recorded for selection. Grinding the assignment costs discarding a
//! valid block. This module is **pure computation with no wire surface** —
//! the drawable-set snapshot (pairs holding their shard at the epoch's
//! open, §4.1 Pin-5 quantization) is the caller's input, and the outputs
//! are pair assignments per block.
//!
//! ## The spec, precisely (so the implementation cannot drift silently)
//!
//! - **Canonical order (§9.5 pin 1, stated exactly):** the drawable set is
//!   strictly increasing by `p_id` bytes lexicographically, then by
//!   `shard_id` **numerically** — equivalently, memcmp over
//!   `p_id ‖ shard_id_be` (big-endian). This is precisely the derived
//!   `Ord` on [`DrawablePair`], and it is **NOT** the little-endian wire
//!   encoding of `shard_id` (under LE bytes, shard 256 would sort before
//!   shard 1 — a second implementation sorting by the wire bytes would
//!   derive a divergent candidate list). Construction rejects anything
//!   out of order, so every node indexes the same list identically.
//! - **Schedule:** `total = λ_target · D` draws spread evenly over the
//!   epoch: through block index `h` (0-based), exactly
//!   `⌊(h+1)·total/E⌋` draws have occurred (`E` = blocks per epoch), so
//!   per-block counts differ by at most one.
//! - **Waves:** under exact-min the draws complete coverage count `w` for
//!   every pair before count `w+1` begins, so the epoch is `λ_target`
//!   consecutive **selections-without-replacement over the full pair
//!   list** (Fisher–Yates driven by the draw stream). At each wave start
//!   the working list resets to canonical order; within a wave, draw `j`
//!   picks a uniform index into the remaining prefix and swap-removes it
//!   (swap with the last remaining slot). The classic algorithm is the
//!   spec; the pinned KAT is its cross-version seed.
//! - **Per-draw randomness (§9.5 pin 2):** a domain-separated cSHAKE256
//!   stream — `cSHAKE256(label, prev_block_hash ‖ in_block_index_le ‖
//!   attempt_le)`, first 8 bytes as a little-endian `u64`, rejection-
//!   sampled into `[0, remaining)` with the modulo-bias zone; `attempt`
//!   increments on rejection. Never a general-purpose PRNG.
//! - **λ_target is a parameter (§9.5 pin 3):** the 2-of-3 ruling's value
//!   (3) is supplied by the caller; nothing here hardcodes it.
//!
//! ## Streaming shape
//!
//! The urn is a sequential feed: call [`ChallengeUrn::advance_block`] once
//! per epoch block, in height order, with that block's predecessor hash.
//! There is no caller-supplied block index — position is internal, so a
//! skipped or double-fed height is unrepresentable. On reorg, discard the
//! urn and rebuild from epoch open (recompute-on-reorg; the replay cost is
//! the caller's to budget, measured at maturity scale by the `#[ignore]`
//! test below).
//!
//! Lookahead is one block by construction: block `h`'s assignments depend
//! only on `block_hash(h−1)`, which exists one block before the draws it
//! seeds (the §7.1 exposure arithmetic, `3τ/SEB`, prices exactly this).

use crate::hash::cshake256_32;

/// SP 800-185 customization label for the per-draw stream (rule 30:
/// explicit label + version; bumping the construction bumps the suffix).
pub const CHALLENGE_ASSIGNMENT_CUSTOMIZATION: &[u8] = b"shekyl/archival-challenge-assignment-v1";

/// One drawable `(P, s)` pair — the unit of challenge obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DrawablePair {
    /// Persona canonical id (32 bytes; the derived-order major key).
    pub p_id: [u8; 32],
    /// Shard id (the minor key).
    pub shard_id: u64,
}

/// Construction rejections — every variant is a caller error, not a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssignmentError {
    /// The drawable set is not strictly increasing by `(p_id, shard_id)`
    /// at this index (covers both disorder and duplicates).
    #[error("drawable set not strictly increasing at index {index}")]
    NotCanonicallyOrdered {
        /// Offending index into the caller's pair list.
        index: usize,
    },
    /// `λ_target = 0` schedules nothing and is a misconfiguration, not an
    /// epoch with no work.
    #[error("λ_target must be positive")]
    ZeroLambda,
    /// `epoch_blocks = 0` has no block to schedule into.
    #[error("epoch_blocks must be positive")]
    ZeroEpochBlocks,
    /// `λ_target · D` overflows `u64` (impossible population).
    #[error("λ_target · D overflows u64")]
    TotalDrawsOverflow,
    /// More than `u32::MAX` drawable pairs (impossible population; the
    /// working list indexes pairs as `u32`).
    #[error("drawable set has more than u32::MAX pairs")]
    TooManyPairs,
    /// The schedule would place more than `u32::MAX` draws in a single
    /// block. The per-draw stream's in-block counter is a fixed 4-byte
    /// input to the domain-separated cSHAKE (widening it would change the
    /// derivation itself), so the bound is enforced here instead — a
    /// release-mode wrap would repeat stream inputs and corrupt the
    /// assignment sequence.
    #[error("schedule would place more than u32::MAX draws in one block")]
    PerBlockDrawsOverflow,
}

/// Feed rejection: every block of the epoch has already been fed.
///
/// The urn is strictly sequential — there is no out-of-order feed path —
/// so the only feed error is "epoch complete." On reorg, discard and
/// rebuild from epoch open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    /// Every block of the epoch has been fed.
    #[error("challenge-assignment epoch fully fed")]
    EpochComplete,
}

/// The exact-min urn for one settlement epoch: feed it each block's
/// predecessor hash **in height order** and it yields that block's
/// assignments. All state is a pure function of `(drawable set, λ_target,
/// epoch_blocks, hashes fed so far)` — recomputable from chain data,
/// reorg-safe by re-derivation (`§2`: nothing to void; assignments simply
/// re-derive on the new chain).
#[derive(Debug, Clone)]
pub struct ChallengeUrn {
    pairs: Vec<DrawablePair>,
    /// Working list of indices into `pairs` for the current wave;
    /// `remaining` is its live prefix length.
    working: Vec<u32>,
    remaining: usize,
    /// Draws performed so far across the epoch.
    done: u64,
    /// `λ_target · D`.
    total: u64,
    epoch_blocks: u64,
    /// Next block index to be fed (0-based within the epoch).
    next_block: u64,
}

impl ChallengeUrn {
    /// Build the urn for one epoch. `pairs` must be strictly increasing by
    /// `(p_id, shard_id)` — the canonical order every node derives
    /// identically. An empty set is a valid epoch with no draws.
    pub fn new(
        pairs: Vec<DrawablePair>,
        lambda_target: u32,
        epoch_blocks: u64,
    ) -> Result<Self, AssignmentError> {
        if lambda_target == 0 {
            return Err(AssignmentError::ZeroLambda);
        }
        if epoch_blocks == 0 {
            return Err(AssignmentError::ZeroEpochBlocks);
        }
        for i in 1..pairs.len() {
            if pairs[i - 1] >= pairs[i] {
                return Err(AssignmentError::NotCanonicallyOrdered { index: i });
            }
        }
        let d32 = u32::try_from(pairs.len()).map_err(|_| AssignmentError::TooManyPairs)?;
        let total = u64::from(lambda_target)
            .checked_mul(u64::from(d32))
            .ok_or(AssignmentError::TotalDrawsOverflow)?;
        // The Bresenham schedule places at most ⌈total/E⌉ draws in one
        // block; the stream's in-block counter is a fixed 4-byte input, so
        // that ceiling must fit u32 (see `PerBlockDrawsOverflow`).
        if total.div_ceil(epoch_blocks) > u64::from(u32::MAX) {
            return Err(AssignmentError::PerBlockDrawsOverflow);
        }
        let working: Vec<u32> = (0..d32).collect();
        let remaining = working.len();
        Ok(ChallengeUrn {
            pairs,
            working,
            remaining,
            done: 0,
            total,
            epoch_blocks,
            next_block: 0,
        })
    }

    /// Epoch-relative index of the next block this urn will assign
    /// (0-based). Equals `epoch_blocks` when the epoch is fully fed.
    #[must_use]
    pub fn next_block(&self) -> u64 {
        self.next_block
    }

    /// Draws scheduled through block index `h` (inclusive): the even-spread
    /// schedule `⌊(h+1)·total/E⌋`.
    fn due_through(&self, h: u64) -> u64 {
        // u128 intermediate: the product needs the wider type; the
        // quotient never does (h+1 ≤ E, so it is bounded by `total`).
        let due = (u128::from(h) + 1) * u128::from(self.total) / u128::from(self.epoch_blocks);
        u64::try_from(due).expect("due <= total, which is u64")
    }

    /// Feed the next epoch block with its **predecessor hash** (the hash of
    /// the block at absolute height one below the block being assigned)
    /// and receive the pairs assigned at that height, in draw order.
    ///
    /// Feeds are strictly sequential. On reorg, discard the urn and rebuild
    /// from epoch open (recompute-on-reorg; see module docs).
    pub fn advance_block(
        &mut self,
        prev_block_hash: &[u8; 32],
    ) -> Result<Vec<DrawablePair>, FeedError> {
        if self.next_block >= self.epoch_blocks {
            return Err(FeedError::EpochComplete);
        }
        let h = self.next_block;
        self.next_block += 1;
        let due = self.due_through(h);
        // Capacity is a hint; saturate rather than cast on 32-bit targets.
        let mut assigned = Vec::with_capacity(usize::try_from(due - self.done).unwrap_or(0));
        let mut in_block_index: u32 = 0;
        while self.done < due {
            // Wave boundary: reset the working list to canonical order so
            // each wave is an independent selection-without-replacement.
            if self.remaining == 0 {
                for (i, slot) in self.working.iter_mut().enumerate() {
                    *slot = u32::try_from(i).expect("D bounded to u32 at construction");
                }
                self.remaining = self.working.len();
            }
            let idx = usize::try_from(draw_below(
                prev_block_hash,
                in_block_index,
                self.remaining as u64,
            ))
            .expect("draw result < remaining, which is usize");
            let pair_index = self.working[idx];
            self.working.swap(idx, self.remaining - 1);
            self.remaining -= 1;
            self.done += 1;
            in_block_index += 1;
            assigned.push(self.pairs[pair_index as usize]);
        }
        Ok(assigned)
    }

    /// Draws performed so far (settlement-side denominator bookkeeping is
    /// derived, never counted from records — §4.2).
    #[must_use]
    pub fn draws_done(&self) -> u64 {
        self.done
    }
}

/// Assign every block of an epoch in one shot — the pure, desync-free form
/// of a full-epoch recompute. `prev_hashes.len()` is the epoch length;
/// entry `h` is the predecessor hash for epoch-relative block `h` (i.e.
/// `block_hash` of the block at absolute height one below that block).
/// An empty slice is [`AssignmentError::ZeroEpochBlocks`].
pub fn assign_epoch(
    pairs: Vec<DrawablePair>,
    lambda_target: u32,
    prev_hashes: &[[u8; 32]],
) -> Result<Vec<Vec<DrawablePair>>, AssignmentError> {
    let epoch_blocks = prev_hashes.len() as u64;
    let mut urn = ChallengeUrn::new(pairs, lambda_target, epoch_blocks)?;
    let mut out = Vec::with_capacity(prev_hashes.len());
    for prev in prev_hashes {
        // Sequential feed cannot fail mid-epoch after a successful `new`
        // for this hash count — EpochComplete only after E feeds.
        out.push(
            urn.advance_block(prev)
                .expect("exactly epoch_blocks feeds before EpochComplete"),
        );
    }
    Ok(out)
}

/// Uniform draw in `[0, n)` from the domain-separated stream: rejection
/// sampling over `cSHAKE256(label, prev_hash ‖ in_block_index ‖ attempt)`
/// taking the first 8 bytes little-endian. `n` must be nonzero.
///
/// When `n == 1` the result is forced (`0`) regardless of the digest —
/// that is the §7.1 wave-tail. The stream is still evaluated so a second
/// implementation that always runs the loop matches byte-for-byte.
fn draw_below(prev_block_hash: &[u8; 32], in_block_index: u32, n: u64) -> u64 {
    assert!(n > 0, "uniform draw from an empty range");
    let zone = u64::MAX - (u64::MAX % n);
    let mut attempt: u32 = 0;
    loop {
        let mut input = [0u8; 40];
        input[0..32].copy_from_slice(prev_block_hash);
        input[32..36].copy_from_slice(&in_block_index.to_le_bytes());
        input[36..40].copy_from_slice(&attempt.to_le_bytes());
        let digest = cshake256_32(CHALLENGE_ASSIGNMENT_CUSTOMIZATION, &input);
        let v = u64::from_le_bytes(digest[0..8].try_into().expect("8-byte slice"));
        if v < zone {
            return v % n;
        }
        attempt += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn pair(tag: u8, shard: u64) -> DrawablePair {
        DrawablePair {
            p_id: [tag; 32],
            shard_id: shard,
        }
    }

    /// Deterministic stand-in for the block hash at epoch-relative height
    /// `h` (and for the pre-epoch predecessor when `h == u64::MAX` is not
    /// used — see [`prev_hash_for`]).
    fn block_hash_at(h: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&h.to_le_bytes());
        out
    }

    /// Predecessor hash for epoch-relative block `h`: the hash of the
    /// block at height `h−1`, or a fixed pre-epoch seed when `h == 0`.
    /// Pins the documented `assignment(h) = f(block_hash(h−1), …)` contract
    /// in every test that drives the urn.
    fn prev_hash_for(h: u64) -> [u8; 32] {
        if h == 0 {
            // Distinct from any `block_hash_at(h)` used in small epochs.
            [0xEE; 32]
        } else {
            block_hash_at(h - 1)
        }
    }

    fn run(pairs: Vec<DrawablePair>, lambda: u32, blocks: u64) -> Vec<Vec<DrawablePair>> {
        let prevs: Vec<[u8; 32]> = (0..blocks).map(prev_hash_for).collect();
        assign_epoch(pairs, lambda, &prevs).expect("valid epoch")
    }

    #[test]
    fn canonical_order_is_enforced_at_construction() {
        // Disorder and duplication both reject with the offending index —
        // the §9.5 pin as a type-level property, not a convention.
        let unsorted = vec![pair(2, 0), pair(1, 0)];
        assert_eq!(
            ChallengeUrn::new(unsorted, 3, 10).unwrap_err(),
            AssignmentError::NotCanonicallyOrdered { index: 1 }
        );
        let dup = vec![pair(1, 7), pair(1, 7)];
        assert_eq!(
            ChallengeUrn::new(dup, 3, 10).unwrap_err(),
            AssignmentError::NotCanonicallyOrdered { index: 1 }
        );
        assert_eq!(
            ChallengeUrn::new(vec![], 0, 10).unwrap_err(),
            AssignmentError::ZeroLambda
        );
        assert_eq!(
            ChallengeUrn::new(vec![], 3, 0).unwrap_err(),
            AssignmentError::ZeroEpochBlocks
        );
    }

    #[test]
    fn canonical_order_is_numeric_shard_id_not_wire_le_bytes() {
        // The exact statement of pin 1: shard_id compares NUMERICALLY
        // (equivalently big-endian memcmp), never as the little-endian
        // wire bytes. Under LE-byte order, (p, 256) would sort before
        // (p, 1); the canonical order says the opposite, and this test is
        // what a divergent second implementation fails.
        let ordered = vec![pair(1, 1), pair(1, 256)];
        assert!(ChallengeUrn::new(ordered, 3, 10).is_ok());
        let le_byte_order = vec![pair(1, 256), pair(1, 1)];
        assert_eq!(
            ChallengeUrn::new(le_byte_order, 3, 10).unwrap_err(),
            AssignmentError::NotCanonicallyOrdered { index: 1 }
        );
    }

    #[test]
    fn per_block_draw_ceiling_must_fit_the_stream_counter() {
        // ⌈total/E⌉ > u32::MAX would wrap the 4-byte in-block stream
        // counter in release and repeat cSHAKE inputs — rejected at
        // construction instead (the counter width is part of the
        // derivation and cannot widen). Exercised via a one-block epoch
        // with λ·D = 3·(2³²−1) > u32::MAX.
        let small: Vec<_> = (0..3u8).map(|t| pair(t, 0)).collect();
        assert_eq!(
            ChallengeUrn::new(small, u32::MAX, 1).unwrap_err(),
            AssignmentError::PerBlockDrawsOverflow
        );
    }

    #[test]
    fn every_pair_is_assigned_exactly_lambda_times() {
        // Exact coverage — the exact-min ruling's defining property, and
        // the redraw floor with it (λ ≥ 2 ⇒ every pair re-drawn).
        let pairs: Vec<_> = (0..7u8).map(|t| pair(t, u64::from(t) * 3)).collect();
        let per_block = run(pairs.clone(), 3, 13);
        let mut counts: BTreeMap<DrawablePair, u32> = BTreeMap::new();
        for block in &per_block {
            for p in block {
                *counts.entry(*p).or_insert(0) += 1;
            }
        }
        assert_eq!(counts.len(), pairs.len());
        assert!(counts.values().all(|&c| c == 3));
    }

    #[test]
    fn schedule_spreads_evenly() {
        // Per-block draw counts differ by at most one, and they sum to
        // λ·D — the Bresenham schedule stated in the module spec.
        let pairs: Vec<_> = (0..5u8).map(|t| pair(t, 0)).collect();
        let per_block = run(pairs, 3, 8);
        let sizes: Vec<usize> = per_block.iter().map(Vec::len).collect();
        let (min, max) = (
            *sizes.iter().min().expect("nonempty"),
            *sizes.iter().max().expect("nonempty"),
        );
        assert!(max - min <= 1, "uneven schedule: {sizes:?}");
        assert_eq!(sizes.iter().sum::<usize>(), 15);
    }

    #[test]
    fn waves_complete_before_the_next_begins() {
        // The exact-min invariant: at every block boundary, issued counts
        // across pairs differ by at most one.
        let pairs: Vec<_> = (0..6u8).map(|t| pair(t, 1)).collect();
        let mut urn = ChallengeUrn::new(pairs.clone(), 3, 9).expect("valid urn");
        let mut counts: BTreeMap<DrawablePair, u32> = BTreeMap::new();
        for h in 0..9 {
            for p in urn.advance_block(&prev_hash_for(h)).expect("in-order feed") {
                *counts.entry(p).or_insert(0) += 1;
            }
            let lo = pairs
                .iter()
                .map(|p| counts.get(p).copied().unwrap_or(0))
                .min();
            let hi = pairs
                .iter()
                .map(|p| counts.get(p).copied().unwrap_or(0))
                .max();
            assert!(
                hi.expect("some") - lo.expect("some") <= 1,
                "counts diverged past one wave at block {h}"
            );
        }
    }

    #[test]
    fn assignments_are_deterministic_and_hash_sensitive() {
        let pairs: Vec<_> = (0..5u8).map(|t| pair(t, 2)).collect();
        let a = run(pairs.clone(), 2, 7);
        let b = run(pairs.clone(), 2, 7);
        assert_eq!(a, b, "same inputs must derive the same assignments");

        // Perturb ONE predecessor hash at a block whose draw has real
        // entropy (block 1: wave-1 remainder is 4, so the draw is a
        // genuine 1-of-4 choice). NOTE the pitfall this test first hit:
        // wave tails narrow PROGRESSIVELY — remaining = 2 is a coin flip
        // between two known pairs, and the final draw of each wave is
        // fully forced (`remaining == 1`, hash-independent), recurring
        // once per wave. That is the §7.1 accepted 3τ/SEB exposure in
        // miniature; a perturbation landing on a forced draw changes
        // nothing, which is why this test perturbs an entropic block.
        let mut urn = ChallengeUrn::new(pairs, 2, 7).expect("valid urn");
        let mut c = Vec::new();
        for h in 0..7 {
            let hash = if h == 1 { [0xAB; 32] } else { prev_hash_for(h) };
            c.push(urn.advance_block(&hash).expect("in-order feed"));
        }
        assert_eq!(
            a[..1],
            c[..1],
            "blocks before the perturbation are unchanged"
        );
        assert_ne!(a[1..], c[1..], "the perturbed hash must move some draw");
    }

    #[test]
    fn empty_drawable_set_is_a_valid_epoch_with_no_draws() {
        let mut urn = ChallengeUrn::new(vec![], 3, 4).expect("valid urn");
        for h in 0..4 {
            assert!(urn
                .advance_block(&prev_hash_for(h))
                .expect("in-order feed")
                .is_empty());
        }
        assert_eq!(
            urn.advance_block(&prev_hash_for(4)),
            Err(FeedError::EpochComplete),
            "epoch fully fed"
        );
        assert_eq!(urn.draws_done(), 0);
        assert_eq!(urn.next_block(), 4);
    }

    #[test]
    fn sequential_feed_is_the_only_representable_shape() {
        // Position is internal: the caller cannot skip or double-feed a
        // height — those states are unrepresentable. After E successful
        // advances the only remaining error is EpochComplete.
        let pairs: Vec<_> = (0..3u8).map(|t| pair(t, 0)).collect();
        let mut urn = ChallengeUrn::new(pairs, 2, 6).expect("valid urn");
        assert_eq!(urn.next_block(), 0);
        urn.advance_block(&prev_hash_for(0)).expect("first feed");
        assert_eq!(urn.next_block(), 1);
        for h in 1..6 {
            urn.advance_block(&prev_hash_for(h)).expect("in-order feed");
        }
        assert_eq!(
            urn.advance_block(&prev_hash_for(6)),
            Err(FeedError::EpochComplete)
        );
    }

    #[test]
    fn assign_epoch_empty_hashes_is_zero_epoch_blocks() {
        let pairs = vec![pair(0, 0)];
        assert_eq!(
            assign_epoch(pairs, 1, &[]).unwrap_err(),
            AssignmentError::ZeroEpochBlocks
        );
    }

    /// Measures the recompute-on-reorg cost the caller must budget: a
    /// full-epoch replay at maturity scale (D = 324,000, λ = 3,
    /// SEB = 10,000 → 972,000 cSHAKE draws), which is the worst-case
    /// rebuild after a reorg near epoch end. Run with `--ignored`
    /// (release) to get the number on the target machine; this lands in
    /// the connect path's budget and must be a measured figure, not an
    /// assumption.
    #[test]
    #[ignore]
    fn measure_full_epoch_replay_cost_at_maturity() {
        let pairs: Vec<_> = (0..324_000u32)
            .map(|i| {
                let mut p_id = [0u8; 32];
                p_id[0..4].copy_from_slice(&i.to_be_bytes());
                DrawablePair { p_id, shard_id: 0 }
            })
            .collect();
        let mut urn = ChallengeUrn::new(pairs, 3, 10_000).expect("valid urn");
        let start = std::time::Instant::now();
        for h in 0..10_000 {
            urn.advance_block(&prev_hash_for(h)).expect("in-order feed");
        }
        let elapsed = start.elapsed();
        assert_eq!(urn.draws_done(), 972_000);
        eprintln!("full-epoch replay at maturity: {elapsed:?} for 972,000 draws");
    }

    /// Golden KAT — the cross-version determinism seed (consensus-port
    /// discipline: the pinned corpus IS the spec). Self-generated at the
    /// module's birth and pinned; any change to the stream construction,
    /// the schedule, the wave reset, or the swap-remove evolution moves
    /// these indices and must arrive as a deliberate v2 label bump.
    ///
    /// Seeds follow the documented predecessor contract: block `h` is fed
    /// `prev_hash_for(h)` (pre-epoch constant at `h == 0`, else
    /// `block_hash_at(h − 1)`).
    #[test]
    fn golden_assignment_vector_is_pinned() {
        let pairs: Vec<_> = (0..4u8).map(|t| pair(t, u64::from(t))).collect();
        let per_block = run(pairs, 2, 5);
        let tags: Vec<Vec<u8>> = per_block
            .iter()
            .map(|block| block.iter().map(|p| p.p_id[0]).collect())
            .collect();
        assert_eq!(
            tags,
            // Predecessor-linked seeds (`prev_hash_for`): pre-epoch constant
            // at h=0, then block_hash_at(h−1). Regenerated when the test
            // harness adopted that contract (was previously seed_at(h)).
            vec![vec![0], vec![3, 2], vec![1], vec![2, 0], vec![1, 3]],
            "pinned golden vector moved — the derivation changed shape"
        );
    }
}
