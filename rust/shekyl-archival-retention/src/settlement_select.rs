// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Settlement's two hash constructions: which three of a pair's issued
//! draws count, and the running digest of an epoch's issued draws.
//!
//! Design: [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](../../../docs/design/ARCHIVAL_SERVE_CREDIT_SPEC.md)
//! §9.3 (the selection) and §10 (the digest). Both are consensus: every node
//! must select the same three draws and fold the same terms.
//!
//! # The selection
//!
//! A pair's issued draws are taken in `(h, j)` order. Fewer than
//! [`COUNTED_DRAWS`] settles NonObservation and selects nothing. Otherwise
//! three are chosen uniformly without replacement, by a partial
//! Fisher–Yates whose randomness is a beacon the pair could not have known
//! while the epoch ran. Because any issued draw may be one of the three, a
//! persona cannot learn mid-epoch that its outcome is already decided.
//!
//! # The digest
//!
//! Each issued draw adds one 256-bit term to its epoch's digest, as an
//! integer modulo `2^256`. A sum does not depend on order: admission folds
//! draws as blocks reveal them, and settlement walks them pair by pair. The
//! digest guards a node's own store against drift between those two moments.
//! It is not built to resist a party that chooses the draws.

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};
use shekyl_types::archival::{COUNTED_DRAWS, ISSUED_DIGEST_LEN};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

/// cSHAKE256 customization for [`select_counted`] (rule 30: one label, one
/// function, versioned).
pub const SETTLEMENT_SELECT_CUSTOMIZATION: &[u8] = b"shekyl/archival-settlement-select-v1";

/// cSHAKE256 customization for [`issued_draw_term`].
pub const ISSUED_INDEX_CUSTOMIZATION: &[u8] = b"shekyl/archival-issued-index-v1";

/// The settlement beacon's width: one block hash.
pub const SETTLEMENT_BEACON_LEN: usize = 32;

/// Attempts at one position before the candidate in hand is accepted. The
/// same cap as the draw's own selection, so the loop is total. A rejection
/// needs a 64-bit value in the top `r` of `2^64`, so no input reaches it.
const SELECT_ATTEMPTS: u32 = 256;

/// The positions, in `(h, j)` order, of the three draws that count for a
/// pair with `issued` issued draws in `epoch`.
///
/// `None` when `issued` is below [`COUNTED_DRAWS`]: the pair is not observed
/// this epoch and nothing is selected.
///
/// For position `k` of 0, 1, 2, with `r = issued − k`:
///
/// ```text
/// zone = (2^64 − 1) − ((2^64 − 1) mod r)
/// for attempt = 0, 1, …, 255
///     x = cSHAKE256_32(SETTLEMENT_SELECT_CUSTOMIZATION,
///           beacon ‖ persona[32] ‖ shard_le[8] ‖ epoch_le[8] ‖ k_le[4] ‖ attempt_le[4])
///     v = LE64(x[0..8])
///     if attempt < 255 and v ≥ zone:  continue
///     break
/// swap L[k] and L[k + (v mod r)]
/// ```
///
/// and the counted draws are `L[0]`, `L[1]`, `L[2]`.
#[must_use]
pub fn select_counted(
    beacon: &[u8; SETTLEMENT_BEACON_LEN],
    persona: &PCanonicalId,
    shard: ShardId,
    epoch: SettlementEpoch,
    issued: usize,
) -> Option<[usize; COUNTED_DRAWS]> {
    if issued < COUNTED_DRAWS {
        return None;
    }
    // The list is `0..issued` with at most three positions moved, so only
    // the moves are held: a pair with many issued draws costs three hashes,
    // not an array of its length.
    let mut moved: Vec<(usize, usize)> = Vec::with_capacity(2 * COUNTED_DRAWS);
    let at = |moved: &[(usize, usize)], position: usize| {
        moved
            .iter()
            .rev()
            .find(|(p, _)| *p == position)
            .map_or(position, |(_, value)| *value)
    };
    let mut counted = [0usize; COUNTED_DRAWS];
    for (k, slot) in counted.iter_mut().enumerate() {
        let remaining = u64::try_from(issued - k).expect("a list length fits a u64");
        let offset = usize::try_from(candidate(beacon, persona, shard, epoch, k, remaining))
            .expect("an offset below the list length fits a usize");
        let chosen = at(&moved, k + offset);
        let displaced = at(&moved, k);
        moved.push((k + offset, displaced));
        moved.push((k, chosen));
        *slot = chosen;
    }
    Some(counted)
}

/// A value in `0..remaining`, uniform up to the cap, for position `k`.
fn candidate(
    beacon: &[u8; SETTLEMENT_BEACON_LEN],
    persona: &PCanonicalId,
    shard: ShardId,
    epoch: SettlementEpoch,
    k: usize,
    remaining: u64,
) -> u64 {
    let zone = u64::MAX - (u64::MAX % remaining);
    let k = u32::try_from(k).expect("a counted position fits a u32");
    let mut value = 0u64;
    for attempt in 0..SELECT_ATTEMPTS {
        let mut hasher: CShake256 =
            CoreWrapper::from_core(CShake256Core::new(SETTLEMENT_SELECT_CUSTOMIZATION));
        hasher.update(beacon);
        hasher.update(persona.as_bytes());
        hasher.update(&shard.to_raw().to_le_bytes());
        hasher.update(&epoch.to_raw().to_le_bytes());
        hasher.update(&k.to_le_bytes());
        hasher.update(&attempt.to_le_bytes());
        let mut first = [0u8; 8];
        hasher.finalize_xof().read(&mut first);
        value = u64::from_le_bytes(first);
        if value < zone {
            break;
        }
    }
    value % remaining
}

/// One issued draw's term in its epoch's digest:
/// `cSHAKE256_32(ISSUED_INDEX_CUSTOMIZATION,
/// persona[32] ‖ shard_le[8] ‖ epoch_le[8] ‖ h_le[8] ‖ j_le[4])`.
#[must_use]
pub fn issued_draw_term(
    persona: &PCanonicalId,
    shard: ShardId,
    epoch: SettlementEpoch,
    issuing_height: BlockHeight,
    draw: u32,
) -> [u8; ISSUED_DIGEST_LEN] {
    let mut hasher: CShake256 =
        CoreWrapper::from_core(CShake256Core::new(ISSUED_INDEX_CUSTOMIZATION));
    hasher.update(persona.as_bytes());
    hasher.update(&shard.to_raw().to_le_bytes());
    hasher.update(&epoch.to_raw().to_le_bytes());
    hasher.update(&issuing_height.to_raw().to_le_bytes());
    hasher.update(&draw.to_le_bytes());
    let mut out = [0u8; ISSUED_DIGEST_LEN];
    hasher.finalize_xof().read(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_types::archival::IssuedDigest;

    fn persona(byte: u8) -> PCanonicalId {
        PCanonicalId::from_bytes([byte; 32])
    }

    fn select(beacon: u8, p: u8, shard: u64, n: usize) -> Option<[usize; COUNTED_DRAWS]> {
        select_counted(
            &[beacon; 32],
            &persona(p),
            ShardId::from_raw(shard),
            SettlementEpoch::from_raw(5),
            n,
        )
    }

    /// The vectors of the specification's §9.3, computed there with an
    /// independent cSHAKE256. Each is the position, in the original
    /// `(h, j)` order, of `L[0]`, `L[1]`, `L[2]` after the three swaps.
    #[test]
    fn the_selection_matches_the_specifications_vectors() {
        assert_eq!(select(0x33, 0x44, 7, 3), Some([2, 0, 1]));
        assert_eq!(select(0x33, 0x44, 7, 4), Some([0, 3, 2]));
        assert_eq!(select(0x33, 0x44, 7, 5), Some([1, 2, 4]));
        assert_eq!(select(0x33, 0x44, 7, 10), Some([6, 3, 8]));
        assert_eq!(select(0x33, 0x44, 7, 255), Some([101, 80, 189]));
        assert_eq!(select(0x33, 0x44, 7, 1_000), Some([896, 786, 146]));
        // One input moved at a time: the persona, the shard, the beacon.
        assert_eq!(select(0x33, 0x45, 7, 10), Some([7, 1, 2]));
        assert_eq!(select(0x33, 0x44, 8, 10), Some([0, 8, 2]));
        assert_eq!(select(0x34, 0x44, 7, 10), Some([8, 0, 4]));
    }

    #[test]
    fn fewer_than_three_issued_selects_nothing() {
        for n in 0..COUNTED_DRAWS {
            assert_eq!(select(0x33, 0x44, 7, n), None);
        }
    }

    #[test]
    fn the_three_are_distinct_positions_of_the_list() {
        for n in COUNTED_DRAWS..40 {
            let [a, b, c] = select(0x33, 0x44, 7, n).expect("three or more");
            assert!(a < n && b < n && c < n, "a position past a list of {n}");
            assert!(a != b && a != c && b != c, "a draw counted twice at {n}");
        }
    }

    /// The sparse bookkeeping is the same shuffle as swapping a whole list.
    #[test]
    fn holding_only_the_moves_is_the_whole_list_shuffle() {
        for n in COUNTED_DRAWS..60 {
            let mut list: Vec<usize> = (0..n).collect();
            for k in 0..COUNTED_DRAWS {
                let remaining = u64::try_from(n - k).unwrap();
                let offset = usize::try_from(candidate(
                    &[0x33; 32],
                    &persona(0x44),
                    ShardId::from_raw(7),
                    SettlementEpoch::from_raw(5),
                    k,
                    remaining,
                ))
                .unwrap();
                list.swap(k, k + offset);
            }
            assert_eq!(
                select(0x33, 0x44, 7, n),
                Some([list[0], list[1], list[2]]),
                "at {n} issued"
            );
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn term(p: u8, height: u64, draw: u32) -> [u8; ISSUED_DIGEST_LEN] {
        issued_draw_term(
            &persona(p),
            ShardId::from_raw(7),
            SettlementEpoch::from_raw(5),
            BlockHeight::from_raw(height),
            draw,
        )
    }

    /// The vectors of the specification's §10.
    #[test]
    fn the_digest_matches_the_specifications_vectors() {
        let first = term(0x44, 1_000_000, 0);
        let second = term(0x44, 1_000_000, 1);
        let third = term(0x45, 1_000_001, 0);

        let mut digest = IssuedDigest::ZERO;
        digest.fold(&first);
        assert_eq!(
            hex(digest.as_bytes()),
            "bfd102a54a70d66500e5aa5a15c8e11aa13653be7ea706101c1d0ed6923ffce9"
        );
        digest.fold(&second);
        assert_eq!(
            hex(digest.as_bytes()),
            "9a32f23e5e03cab824e593d674dc90552ef10973da5a2c90f1ff833854d35941"
        );
        digest.fold(&third);
        let all = "053b7619b7c9a1dee912ba0905b91ccb33b8eeb958117c98456e36ea41e99ec8";
        assert_eq!(hex(digest.as_bytes()), all);

        // Any order.
        let mut other = IssuedDigest::ZERO;
        for t in [&third, &first, &second] {
            other.fold(t);
        }
        assert_eq!(hex(other.as_bytes()), all);
    }

    #[test]
    fn a_draw_that_differs_in_one_field_has_a_different_term() {
        let base = term(0x44, 1_000_000, 0);
        assert_ne!(base, term(0x45, 1_000_000, 0));
        assert_ne!(base, term(0x44, 1_000_001, 0));
        assert_ne!(base, term(0x44, 1_000_000, 1));
        let other_shard = issued_draw_term(
            &persona(0x44),
            ShardId::from_raw(8),
            SettlementEpoch::from_raw(5),
            BlockHeight::from_raw(1_000_000),
            0,
        );
        assert_ne!(base, other_shard);
        let other_epoch = issued_draw_term(
            &persona(0x44),
            ShardId::from_raw(7),
            SettlementEpoch::from_raw(6),
            BlockHeight::from_raw(1_000_000),
            0,
        );
        assert_ne!(base, other_epoch);
    }
}
