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
//! - **Canonical order (§9.5 pin 1):** the drawable set is strictly
//!   increasing by `(p_id, shard_id)` bytes; construction rejects anything
//!   else, so every node indexes the same candidate list identically.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentError {
    /// The drawable set is not strictly increasing by `(p_id, shard_id)`
    /// at this index (covers both disorder and duplicates).
    NotCanonicallyOrdered { index: usize },
    /// `λ_target = 0` schedules nothing and is a misconfiguration, not an
    /// epoch with no work.
    ZeroLambda,
    /// `epoch_blocks = 0` has no block to schedule into.
    ZeroEpochBlocks,
    /// `λ_target · D` overflows `u64` (impossible population).
    TotalDrawsOverflow,
    /// More than `u32::MAX` drawable pairs (impossible population; the
    /// working list indexes pairs as `u32`).
    TooManyPairs,
}

/// Feed rejections — the urn is stateful, so a desynced feed must be an
/// **error, not a silently wrong assignment stream** (the
/// make-bad-states-unrepresentable posture). On any reorg the caller
/// rebuilds from epoch open and replays — recompute-on-reorg is the ruled
/// shape; the replay cost is the caller's to budget (measured at maturity
/// scale by the `#[ignore]` test below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedError {
    /// Every block of the epoch has been fed.
    EpochComplete,
    /// The caller's epoch-relative block index does not match the urn's
    /// position — a desynced feed (skipped block, double-feed, or a reorg
    /// the caller failed to rebuild for).
    WrongBlockIndex { expected: u64, got: u64 },
}

/// The exact-min urn for one settlement epoch: feed it each block's
/// predecessor hash **in height order** and it yields that block's
/// assignments. All state is a pure function of `(drawable set, λ_target,
/// epoch_blocks, hashes fed so far)` — recomputable from chain data,
/// reorg-safe by re-derivation (`§2`: nothing to void; assignments simply
/// re-derive on the new chain).
#[derive(Debug, Clone)]
pub struct ChallengeUrn {
    /// The epoch-open block hash this urn is bound to: the identity of
    /// the chain history it was built from. The module cannot verify the
    /// fed hashes chain to it, but exposing it lets the caller assert the
    /// binding when rebuilding after a reorg — a cross-fork feed becomes
    /// checkable instead of silent.
    epoch_open_hash: [u8; 32],
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
    /// Build the urn for one epoch, bound to `epoch_open_hash` (the hash
    /// of the epoch's opening block — the identity of the snapshot the
    /// drawable set was derived from). `pairs` must be strictly increasing
    /// by `(p_id, shard_id)` — the canonical order every node derives
    /// identically. An empty set is a valid epoch with no draws.
    pub fn new(
        epoch_open_hash: [u8; 32],
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
        let working: Vec<u32> = (0..d32).collect();
        let remaining = working.len();
        Ok(ChallengeUrn {
            epoch_open_hash,
            pairs,
            working,
            remaining,
            done: 0,
            total,
            epoch_blocks,
            next_block: 0,
        })
    }

    /// The epoch-open block hash this urn was constructed against — the
    /// caller asserts this against the chain when rebuilding after a
    /// reorg, so a cross-fork or stale urn is detectable.
    #[must_use]
    pub fn epoch_open_hash(&self) -> &[u8; 32] {
        &self.epoch_open_hash
    }

    /// Draws scheduled through block index `h` (inclusive): the even-spread
    /// schedule `⌊(h+1)·total/E⌋`.
    fn due_through(&self, h: u64) -> u64 {
        // u128 intermediate: the product needs the wider type; the
        // quotient never does (h+1 ≤ E, so it is bounded by `total`).
        let due = (u128::from(h) + 1) * u128::from(self.total) / u128::from(self.epoch_blocks);
        u64::try_from(due).expect("due <= total, which is u64")
    }

    /// Feed block `h` (the caller's epoch-relative index, 0-based) with
    /// its **predecessor hash** (the hash of block `h−1`) and receive the
    /// pairs assigned at `h`, in draw order. `h` must equal the urn's own
    /// position — a mismatched index is a desynced feed and returns
    /// [`FeedError::WrongBlockIndex`] instead of a silently wrong
    /// assignment stream. On any reorg, discard the urn and rebuild from
    /// epoch open (recompute-on-reorg; see [`FeedError`]).
    pub fn advance_block(
        &mut self,
        h: u64,
        prev_block_hash: &[u8; 32],
    ) -> Result<Vec<DrawablePair>, FeedError> {
        if self.next_block >= self.epoch_blocks {
            return Err(FeedError::EpochComplete);
        }
        if h != self.next_block {
            return Err(FeedError::WrongBlockIndex {
                expected: self.next_block,
                got: h,
            });
        }
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

/// Uniform draw in `[0, n)` from the domain-separated stream: rejection
/// sampling over `cSHAKE256(label, prev_hash ‖ in_block_index ‖ attempt)`
/// taking the first 8 bytes little-endian. `n` must be nonzero.
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

    /// Deterministic per-height stand-in for a block hash.
    fn hash_at(h: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&h.to_le_bytes());
        out
    }

    const OPEN_HASH: [u8; 32] = [7; 32];

    fn run(pairs: Vec<DrawablePair>, lambda: u32, blocks: u64) -> Vec<Vec<DrawablePair>> {
        let mut urn = ChallengeUrn::new(OPEN_HASH, pairs, lambda, blocks).expect("valid urn");
        (0..blocks)
            .map(|h| urn.advance_block(h, &hash_at(h)).expect("in-order feed"))
            .collect()
    }

    #[test]
    fn canonical_order_is_enforced_at_construction() {
        // Disorder and duplication both reject with the offending index —
        // the §9.5 pin as a type-level property, not a convention.
        let unsorted = vec![pair(2, 0), pair(1, 0)];
        assert_eq!(
            ChallengeUrn::new(OPEN_HASH, unsorted, 3, 10).unwrap_err(),
            AssignmentError::NotCanonicallyOrdered { index: 1 }
        );
        let dup = vec![pair(1, 7), pair(1, 7)];
        assert_eq!(
            ChallengeUrn::new(OPEN_HASH, dup, 3, 10).unwrap_err(),
            AssignmentError::NotCanonicallyOrdered { index: 1 }
        );
        assert_eq!(
            ChallengeUrn::new(OPEN_HASH, vec![], 0, 10).unwrap_err(),
            AssignmentError::ZeroLambda
        );
        assert_eq!(
            ChallengeUrn::new(OPEN_HASH, vec![], 3, 0).unwrap_err(),
            AssignmentError::ZeroEpochBlocks
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
        let mut urn = ChallengeUrn::new(OPEN_HASH, pairs.clone(), 3, 9).expect("valid urn");
        let mut counts: BTreeMap<DrawablePair, u32> = BTreeMap::new();
        for h in 0..9 {
            for p in urn.advance_block(h, &hash_at(h)).expect("in-order feed") {
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
        let mut urn = ChallengeUrn::new(OPEN_HASH, pairs, 2, 7).expect("valid urn");
        let mut c = Vec::new();
        for h in 0..7 {
            let hash = if h == 1 { [0xAB; 32] } else { hash_at(h) };
            c.push(urn.advance_block(h, &hash).expect("in-order feed"));
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
        let mut urn = ChallengeUrn::new(OPEN_HASH, vec![], 3, 4).expect("valid urn");
        for h in 0..4 {
            assert!(urn
                .advance_block(h, &hash_at(h))
                .expect("in-order feed")
                .is_empty());
        }
        assert_eq!(
            urn.advance_block(4, &hash_at(4)),
            Err(FeedError::EpochComplete),
            "epoch fully fed"
        );
        assert_eq!(urn.draws_done(), 0);
    }

    #[test]
    fn desynced_feed_is_an_error_not_a_wrong_stream() {
        // The urn is stateful; a skipped block, a double-feed, or an
        // un-rebuilt reorg must surface as an error, never as a silently
        // divergent assignment stream.
        let pairs: Vec<_> = (0..3u8).map(|t| pair(t, 0)).collect();
        let mut urn = ChallengeUrn::new(OPEN_HASH, pairs, 2, 6).expect("valid urn");
        urn.advance_block(0, &hash_at(0)).expect("in-order feed");
        assert_eq!(
            urn.advance_block(0, &hash_at(0)),
            Err(FeedError::WrongBlockIndex {
                expected: 1,
                got: 0
            }),
            "double-feed rejected"
        );
        assert_eq!(
            urn.advance_block(2, &hash_at(2)),
            Err(FeedError::WrongBlockIndex {
                expected: 1,
                got: 2
            }),
            "skipped block rejected"
        );
        // The rejected feeds must not have advanced state.
        urn.advance_block(1, &hash_at(1))
            .expect("in-order feed resumes");
        assert_eq!(urn.epoch_open_hash(), &OPEN_HASH);
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
        let mut urn = ChallengeUrn::new(OPEN_HASH, pairs, 3, 10_000).expect("valid urn");
        let start = std::time::Instant::now();
        for h in 0..10_000 {
            urn.advance_block(h, &hash_at(h)).expect("in-order feed");
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
    #[test]
    fn golden_assignment_vector_is_pinned() {
        let pairs: Vec<_> = (0..4u8).map(|t| pair(t, u64::from(t))).collect();
        let per_block = run(pairs.clone(), 2, 5);
        let tags: Vec<Vec<u8>> = per_block
            .iter()
            .map(|block| block.iter().map(|p| p.p_id[0]).collect())
            .collect();
        assert_eq!(
            tags,
            vec![vec![0], vec![1, 2], vec![3], vec![3, 0], vec![1, 2]],
            "pinned golden vector moved — the derivation changed shape"
        );
    }
}
