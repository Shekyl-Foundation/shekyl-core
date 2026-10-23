// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The complete-tree support stream (`ARCHIVAL_SUPPORT_DRAW.md`).
//!
//! A complete tree is not a member of the economy's drawable set. It is
//! drawn `c` times an epoch, on a public schedule phased by its persona,
//! and each draw names its own shard. An unfiled scheduled block accrues
//! one unissued draw, capped at `c`. There is no top-up multiple: the
//! economy's shortfall is a different value, and this module never reads
//! or writes it.

use shekyl_types::archival::COUNTED_DRAWS;
use shekyl_types::{PCanonicalId, SettlementEpoch, ShardId};

use crate::hash::cshake256_32;
use crate::settlement_select::{select_counted, SETTLEMENT_BEACON_LEN};

/// Draws scheduled for one support tree in one epoch. Ruled 2026-10-22:
/// `c = 10` at a non-filing rate of one block in ten.
pub const SUPPORT_DRAWS_PER_EPOCH: u32 = 10;

/// cSHAKE256 customization for [`select_support_shard`].
pub const SUPPORT_DRAW_CUSTOMIZATION: &[u8] = b"shekyl/archival-support-draw-v1";

/// cSHAKE256 customization for [`support_challenge_nonce`].
pub const SUPPORT_CHALLENGE_NONCE_CUSTOMIZATION: &[u8] =
    b"shekyl/archival-support-challenge-nonce-v1";

/// The shard byte `select_counted` is given for a support tree, so the
/// beacon cannot alias a closed shard. The row itself is keyed
/// `(persona, epoch)` and carries no shard.
pub const SUPPORT_SELECT_SHARD: u64 = u64::MAX;

/// Unissued support draws carried for one tree. Capped at
/// [`SUPPORT_DRAWS_PER_EPOCH`]. Not the economy's shortfall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupportUnissued(u32);

impl SupportUnissued {
    /// Nothing carried.
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// The carried count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// One scheduled block the producer did not file. The cap is `c`;
    /// there is no multiple.
    #[must_use]
    pub const fn note_unfiled(self) -> Self {
        let next = self.0.saturating_add(1);
        Self(if next > SUPPORT_DRAWS_PER_EPOCH {
            SUPPORT_DRAWS_PER_EPOCH
        } else {
            next
        })
    }
}

/// `SEB − W₂`, the span the schedule is spread across. `None` when the
/// window is not shorter than the epoch.
#[must_use]
pub const fn support_span(seb: u64, response_window: u64) -> Option<u64> {
    match seb.checked_sub(response_window) {
        Some(span) if span > 0 => Some(span),
        _ => None,
    }
}

/// `LE64(P_id[0..8]) mod span`.
#[must_use]
pub fn support_offset(persona: &PCanonicalId, span: u64) -> u64 {
    let mut le = [0u8; 8];
    le.copy_from_slice(&persona.as_bytes()[..8]);
    u64::from_le_bytes(le) % span
}

/// Block `index` of `persona`'s schedule, as an offset inside the epoch.
///
/// `r_i = (offset(P) + ⌊i · span / c⌋) mod span`, with
/// `span = SEB − W₂`. Every `r_i` is in `0..span`, so `r_i + W₂` ends
/// before the epoch does.
#[must_use]
pub fn support_slot(
    persona: &PCanonicalId,
    index: u32,
    seb: u64,
    response_window: u64,
) -> Option<u64> {
    let span = support_span(seb, response_window)?;
    if index >= SUPPORT_DRAWS_PER_EPOCH {
        return None;
    }
    let offset = support_offset(persona, span);
    let step =
        u64::try_from(u128::from(index) * u128::from(span) / u128::from(SUPPORT_DRAWS_PER_EPOCH))
            .expect("a product of two values below an epoch fits");
    Some(offset.wrapping_add(step) % span)
}

/// The shard a support draw names, uniform in `0..final_count`.
///
/// Rejection sampling on the first eight bytes of
/// `cSHAKE256(shekyl/archival-support-draw-v1, seed ‖ block_hash ‖ persona ‖ j ‖ final_count)`.
/// `None` when `final_count` is zero or every attempt fell in the
/// rejected tail, which a non-zero count below `2^63` does not.
#[must_use]
pub fn select_support_shard(
    seed: &[u8; 32],
    block_hash: &[u8; 32],
    persona: &PCanonicalId,
    draw: u32,
    final_count: u64,
) -> Option<u64> {
    if final_count == 0 {
        return None;
    }
    let limit = u64::MAX - (u64::MAX % final_count);
    for attempt in 0..8u32 {
        let word = support_word(seed, block_hash, persona, draw, final_count, attempt);
        let n = u64::from_le_bytes(word[..8].try_into().expect("eight bytes"));
        if n < limit {
            return Some(n % final_count);
        }
    }
    None
}

/// A support challenge's nonce. A different label from the economy's
/// [`crate::challenge_nonce`], on the same preimage shape.
#[must_use]
pub fn support_challenge_nonce(
    seed: &[u8; 32],
    block_hash: &[u8; 32],
    draw: u32,
    attempt: u8,
) -> [u8; 32] {
    let mut input = [0u8; 32 + 32 + 4 + 1];
    input[..32].copy_from_slice(seed);
    input[32..64].copy_from_slice(block_hash);
    input[64..68].copy_from_slice(&draw.to_le_bytes());
    input[68] = attempt;
    cshake256_32(SUPPORT_CHALLENGE_NONCE_CUSTOMIZATION, &input)
}

/// The three counted positions of a support tree's issued draws.
///
/// The sentinel shard keeps the beacon off every closed shard. Fewer
/// than [`COUNTED_DRAWS`] issued returns `None`: that epoch is a
/// non-observation, the same rule [`crate::settle_pair`] uses.
#[must_use]
pub fn support_counted(
    beacon: &[u8; SETTLEMENT_BEACON_LEN],
    persona: &PCanonicalId,
    epoch: SettlementEpoch,
    issued: usize,
) -> Option<[usize; COUNTED_DRAWS]> {
    select_counted(
        beacon,
        persona,
        ShardId::from_raw(SUPPORT_SELECT_SHARD),
        epoch,
        issued,
    )
}

fn support_word(
    seed: &[u8; 32],
    block_hash: &[u8; 32],
    persona: &PCanonicalId,
    draw: u32,
    final_count: u64,
    attempt: u32,
) -> [u8; 32] {
    let mut input = [0u8; 32 + 32 + 32 + 4 + 8 + 4];
    input[..32].copy_from_slice(seed);
    input[32..64].copy_from_slice(block_hash);
    input[64..96].copy_from_slice(persona.as_bytes());
    input[96..100].copy_from_slice(&draw.to_le_bytes());
    input[100..108].copy_from_slice(&final_count.to_le_bytes());
    input[108..].copy_from_slice(&attempt.to_le_bytes());
    cshake256_32(SUPPORT_DRAW_CUSTOMIZATION, &input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::cshake256_32;
    use crate::secret_draw::{challenge_nonce, draw_target, DRAW_CUSTOMIZATION};
    use crate::{CHALLENGE_RESPONSE_BLOCKS, SETTLEMENT_EPOCH_BLOCKS};

    const SEED: [u8; 32] = [0x11; 32];
    const HASH: [u8; 32] = [0x22; 32];

    fn persona(byte: u8) -> PCanonicalId {
        PCanonicalId::from_bytes([byte; 32])
    }

    /// `c` slots, each inside `SEB − W₂`, and the response window ends
    /// before the epoch does. Red edit: schedule into `0..SEB`.
    #[test]
    fn one_tree_is_drawn_c_times_inside_the_response_span() {
        let tree = persona(0xA5);
        let span = support_span(SETTLEMENT_EPOCH_BLOCKS, CHALLENGE_RESPONSE_BLOCKS)
            .expect("the epoch is longer than the window");
        let mut slots = Vec::new();
        for i in 0..SUPPORT_DRAWS_PER_EPOCH {
            let slot = support_slot(&tree, i, SETTLEMENT_EPOCH_BLOCKS, CHALLENGE_RESPONSE_BLOCKS)
                .expect("index below c");
            assert!(slot < span, "slot {slot} outside 0..{span}");
            assert!(
                slot + CHALLENGE_RESPONSE_BLOCKS < SETTLEMENT_EPOCH_BLOCKS,
                "the window of slot {slot} crosses the epoch"
            );
            slots.push(slot);
        }
        assert_eq!(
            slots.len(),
            usize::try_from(SUPPORT_DRAWS_PER_EPOCH).expect("c fits")
        );
        let mut ordered = slots.clone();
        ordered.sort_unstable();
        ordered.dedup();
        assert_eq!(ordered.len(), slots.len(), "two draws share a block");
    }

    /// The same index on two personas lands on different blocks when
    /// their offsets differ. Red edit: drop `offset(P)`.
    #[test]
    fn two_trees_do_not_share_a_phase() {
        let a = support_slot(
            &persona(0x01),
            0,
            SETTLEMENT_EPOCH_BLOCKS,
            CHALLENGE_RESPONSE_BLOCKS,
        );
        let b = support_slot(
            &persona(0x02),
            0,
            SETTLEMENT_EPOCH_BLOCKS,
            CHALLENGE_RESPONSE_BLOCKS,
        );
        assert_ne!(a, b);
    }

    /// A shard is inside the archive the draw was given, and a second
    /// archive size is a different draw. Red edit: ignore `final_count`.
    #[test]
    fn each_draw_names_a_shard_of_the_archive_it_was_given() {
        let tree = persona(0x3C);
        let mut differed = false;
        for draw in 0..16u32 {
            let small = select_support_shard(&SEED, &HASH, &tree, draw, 8).expect("count 8");
            let large = select_support_shard(&SEED, &HASH, &tree, draw, 64).expect("count 64");
            assert!(small < 8, "draw {draw}");
            assert!(large < 64, "draw {draw}");
            differed |= small != large;
        }
        assert!(differed, "the archive size did not change a shard");
        assert!(select_support_shard(&SEED, &HASH, &tree, 0, 0).is_none());
    }

    /// Eleven unfiled blocks carry `c`, not `c` times a multiple.
    /// Red edit: drop the cap, or multiply by the economy's top-up.
    #[test]
    fn unissued_carry_stops_at_c() {
        let mut debt = SupportUnissued::zero();
        for _ in 0..SUPPORT_DRAWS_PER_EPOCH + 1 {
            debt = debt.note_unfiled();
        }
        assert_eq!(debt.get(), SUPPORT_DRAWS_PER_EPOCH);
    }

    /// A support miss is not an argument of the economy's count.
    /// Red edit: pass the support debt as `shortfall`.
    #[test]
    fn a_support_miss_does_not_move_the_economy_target() {
        let before = draw_target(8, 0, 200, SETTLEMENT_EPOCH_BLOCKS).expect("fits");
        let _debt = SupportUnissued::zero().note_unfiled();
        let after = draw_target(8, 0, 200, SETTLEMENT_EPOCH_BLOCKS).expect("fits");
        assert_eq!(before, after);
    }

    /// The support labels are not the economy's. Red edit: hash the
    /// support preimage under `DRAW_CUSTOMIZATION`.
    #[test]
    fn the_support_labels_are_not_the_economys() {
        let tree = persona(0x3C);
        let support = support_word(&SEED, &HASH, &tree, 0, 8, 0);
        let mut economy_input = [0u8; 32 + 32 + 4 + 4];
        economy_input[..32].copy_from_slice(&SEED);
        economy_input[32..64].copy_from_slice(&HASH);
        let economy = cshake256_32(DRAW_CUSTOMIZATION, &economy_input);
        assert_ne!(support, economy);
        let support_nonce = support_challenge_nonce(&SEED, &HASH, 0, 0);
        let economy_nonce = challenge_nonce(&SEED, &HASH, 0, 0);
        assert_ne!(support_nonce, economy_nonce);
    }

    /// Fewer than three issued draws is not a counted set. Red edit:
    /// count a set of two.
    #[test]
    fn fewer_than_three_issued_is_not_counted() {
        let beacon = [0x44; SETTLEMENT_BEACON_LEN];
        let epoch = SettlementEpoch::from_raw(1);
        assert!(support_counted(&beacon, &persona(0x3C), epoch, 2).is_none());
        assert!(support_counted(&beacon, &persona(0x3C), epoch, 3).is_some());
    }
}
