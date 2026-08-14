// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bond-post observation — the single owner of "what counts as a cleartext
//! bond-post observation" in a scanned transaction.
//!
//! Two consumers read `Input::BondPost` from blocks in hand:
//!
//! - the **P-scan dual extractor** (`pscan::scan_step::run_dual_extractor`),
//!   which matches observations against the bonded-persona set and records
//!   [`BondPostMatch`](super::pscan::scan_step::BondPostMatch) rows into the
//!   sealed accrual evidence; and
//! - the **principal scan's bond watch** (SA-R-6 from-seed reconstruction):
//!   the refresh/rescan merge matches observations against the persisted
//!   probe-id cache (`StakingBlock::persona_id_cache`) to re-adopt bonds a
//!   restored wallet's record lost and raise the monotone `p_slot` cursor.
//!
//! Both must agree byte-for-byte on what an observation *is* — the id lift at
//! the wire→domain boundary and the post-kind byte — or the probe could sight
//! a bond the P-scan would later fail to corroborate (or vice versa), and the
//! sighting bridge in the open-time reconcile would wedge. Hence one free
//! function for the lift, and one for "lookup this id in an id→slot map":
//! which map (bonded personas vs probe-id cache) stays with each consumer.

use std::collections::BTreeMap;

use shekyl_engine_state::StakingBlock;
use shekyl_types::PCanonicalId;
use shekyl_wire::transaction::{BondPostKind, Input, Transaction};

use super::error::RefreshError;
use crate::scan::{BondSightingObserved, ScanResult};

/// One cleartext bond-post observation lifted from a transaction input:
/// the posting persona's public canonical id and the wire post-kind byte.
/// Carries no height/tx context — the caller owns that pairing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct BondPostObservation {
    /// The posting persona's canonical id, lifted from the wire `[u8; 32]`
    /// once, at the wire→domain boundary.
    pub(crate) p_canonical_id: PCanonicalId,
    /// Wire post-kind byte (`0x00` = JoinMarket; otherwise the `Other` tag),
    /// via [`post_kind_byte`].
    pub(crate) post_kind: u8,
}

/// Iterate the bond-post observations in one transaction, in input order.
///
/// Pure read of public wire data — no secret is touched, nothing is cloned.
/// A transaction with no `Input::BondPost` yields nothing at the cost of an
/// input walk (inputs are few; bond posts are rare).
pub(crate) fn bond_post_observations(
    tx: &Transaction,
) -> impl Iterator<Item = BondPostObservation> + '_ {
    tx.prefix.inputs.iter().filter_map(|input| match input {
        Input::BondPost(bp) => Some(BondPostObservation {
            p_canonical_id: PCanonicalId::from_bytes(bp.p_canonical_id),
            post_kind: post_kind_byte(&bp.kind),
        }),
        _ => None,
    })
}

/// The wire post-kind byte (JoinMarket's dense tag is `0x00`,
/// `shekyl_wire::transaction` §9.11). Single-sourced from the wire crate's own
/// [`BOND_POST_KIND_JOINMARKET`](shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET)
/// so the recorded byte and the confirmation filter in
/// [`PScanAccrual`](super::pscan::accrual::PScanAccrual) cannot drift from the
/// wire definition.
pub(crate) fn post_kind_byte(kind: &BondPostKind) -> u8 {
    match kind {
        BondPostKind::JoinMarket { .. } => shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET,
        BondPostKind::Other(b) => *b,
    }
}

/// Observations in `tx` whose canonical id is in `watch`, paired with the
/// mapped slot. Shared match — the P-scan extractor and the principal-scan
/// watch differ only in *which* id→slot map they pass.
pub(crate) fn match_watch<'a>(
    tx: &'a Transaction,
    watch: &'a BTreeMap<PCanonicalId, u32>,
) -> impl Iterator<Item = (BondPostObservation, u32)> + 'a {
    bond_post_observations(tx).filter_map(move |obs| {
        watch
            .get(&obs.p_canonical_id)
            .copied()
            .map(|slot| (obs, slot))
    })
}

/// Slot-resolved sightings in `tx` at `height` against the principal scan's
/// probe-id watch. The producer owns per-attempt dedup and the reorg rewind;
/// this is just the per-tx match.
pub(crate) fn sightings_in<'a>(
    tx: &'a Transaction,
    height: u64,
    watch: &'a BTreeMap<PCanonicalId, u32>,
) -> impl Iterator<Item = BondSightingObserved> + 'a {
    match_watch(tx, watch).map(move |(_, slot)| BondSightingObserved {
        block_height: height,
        slot,
    })
}

/// Extend the persisted probe-id cache to cover the derive-forward window
/// `{bonded} ∪ {cursor ..= cursor + window}` — called at open (`assemble`),
/// the one seam where the seed is transiently in scope. Derive-once: a slot
/// already cached is skipped (ids are pure functions of the seed and never
/// invalidate), and a durably-retired slot is never cached (its cursor burn
/// is arm #2's; the watch must not churn re-adopting it).
pub(crate) fn extend_probe_cache<E>(
    staking: &mut StakingBlock,
    retired: &std::collections::BTreeSet<u32>,
    window: u32,
    mut id_of_slot: impl FnMut(u32) -> Result<PCanonicalId, E>,
) -> Result<(), E> {
    for slot in staking.derive_forward_slots(window) {
        if retired.contains(&slot) || staking.persona_id_cache.contains_key(&slot) {
            continue;
        }
        let id = id_of_slot(slot)?;
        staking.persona_id_cache.insert(slot, id);
    }
    Ok(())
}

/// The producer-facing watch map: the probe-id cache inverted (id → slot),
/// with `retired` filtered out — a cache row from an *earlier* open whose
/// slot has since retired must not re-enter the watch. On an unreadable
/// seal the refusal set is empty and arm #2 heals any re-adoption at the
/// next open (converging).
pub(crate) fn watch_map(
    staking: &StakingBlock,
    retired: &std::collections::BTreeSet<u32>,
) -> BTreeMap<PCanonicalId, u32> {
    let mut map = BTreeMap::new();
    for (slot, id) in &staking.persona_id_cache {
        if retired.contains(slot) {
            continue;
        }
        let previous = map.insert(*id, *slot);
        // Two slots sharing a canonical id would mean a collision in the
        // persona derivation (cSHAKE over distinct derived pubkeys) — not a
        // state this map may paper over with a silent overwrite, since the
        // sighting would then resolve to the wrong slot. Fail loudly in
        // debug; in release the later (higher) slot wins deterministically.
        debug_assert!(
            previous.is_none(),
            "duplicate persona canonical id across probe-cache slots"
        );
    }
    map
}

/// O5 untrusted-`ScanResult` contract checks for the bond-watch sightings.
///
/// Height checks mirror the per-height-vector gates the merge body applies
/// (empty range carries no sightings; every height sits inside the processed
/// range). The **slot** check is the load-bearing extra: a sighting adopts
/// into `bonded_slots` and raises the monotone cursor, so an unknown slot
/// would permanently burn the allocation sequence. Only a slot already in
/// `persona_id_cache` — a slot this wallet asked to watch — may be adopted.
/// Called under the ledger write guard, **before** the LedgerBlock apply, so
/// a malformed result cannot advance the tip and then fail.
pub(crate) fn validate_bond_sightings(
    result: &ScanResult,
    staking: &StakingBlock,
) -> Result<(), RefreshError> {
    if result.processed_height_range.start == result.processed_height_range.end
        && !result.bond_sightings.is_empty()
    {
        return Err(RefreshError::MalformedScanResult {
            reason: "bond_sightings non-empty for empty processed_height_range",
        });
    }
    if result
        .bond_sightings
        .iter()
        .any(|s| !result.processed_height_range.contains(&s.block_height))
    {
        return Err(RefreshError::MalformedScanResult {
            reason: "bond_sighting height outside processed_height_range",
        });
    }
    if result
        .bond_sightings
        .iter()
        .any(|s| !staking.persona_id_cache.contains_key(&s.slot))
    {
        return Err(RefreshError::MalformedScanResult {
            reason: "bond_sighting slot not in persona_id_cache",
        });
    }
    Ok(())
}

/// Bond watch (SA-R-6): adopt each sighted slot into the staking record and
/// raise the monotone `p_slot` cursor — the merge-side half of the from-seed
/// reconstruction.
///
/// **Positive evidence only.** A sighting is a bond post actually observed in
/// a scanned block, so the raise is sound on any coverage — no absence claim
/// is made, no exhaustiveness token consulted. Adoption is what keeps the
/// persona derivable under Model D: `bonded_slots` is the only derive-forward
/// input, so raising past a sighted slot without adopting it would strand the
/// bond (the arm-#4 adopt-before-raise lesson, applied here).
///
/// Sightings survive a later reorg of the sighted block: a burned slot is the
/// privacy-correct direction, and the sighting-aware arm #3 drops a refuted
/// row at the next open once the P-scan's coverage passes it.
///
/// Sorted insert: `bonded_slots` stays ascending (persisted-byte determinism
/// — two wallets in the same logical state serialize identically), and a
/// sighted slot may sit *below* existing entries after a partial rollback.
pub(crate) fn adopt_bond_sightings(staking: &mut StakingBlock, sightings: &[BondSightingObserved]) {
    if sightings.is_empty() {
        return;
    }
    let mut sighted_high: Option<u32> = None;
    for s in sightings {
        staking.record_first_sighting(s.slot, shekyl_types::BlockHeight::from_raw(s.block_height));
        if let Err(pos) = staking.bonded_slots.binary_search(&s.slot) {
            staking.bonded_slots.insert(pos, s.slot);
        }
        sighted_high = Some(sighted_high.map_or(s.slot, |m| m.max(s.slot)));
    }
    // A chain-proven bond makes this wallet a staker: the next open spawns
    // the actor and the P-scan corroborates (then supersedes) the sightings.
    staking.staking_enabled = true;
    if let Some(high) = sighted_high {
        let raised = staking.monotone_current_slot(Some(high));
        if raised > staking.p_slot {
            staking.p_slot = raised;
        }
    }
    tracing::info!(
        sighted = sightings.len(),
        cursor = staking.p_slot,
        "bond watch: chain-observed bond posts adopted at merge"
    );
}

#[cfg(test)]
mod tests {
    use super::{adopt_bond_sightings, validate_bond_sightings};
    use crate::engine::RefreshError;
    use crate::scan::ScanResult;

    fn sighting(slot: u32, height: u64) -> crate::scan::BondSightingObserved {
        crate::scan::BondSightingObserved {
            block_height: height,
            slot,
        }
    }

    /// A staking block whose probe cache covers `slots` (dummy public ids).
    /// O5's slot-membership check reads this map; the bytes are not matched.
    fn staking_with_cached_slots(slots: &[u32]) -> shekyl_engine_state::StakingBlock {
        let mut staking = shekyl_engine_state::StakingBlock::empty();
        for (i, &slot) in slots.iter().enumerate() {
            let mut bytes = [0u8; 32];
            bytes[0] = u8::try_from(i.saturating_add(1)).unwrap_or(1);
            staking
                .persona_id_cache
                .insert(slot, shekyl_types::PCanonicalId::from_bytes(bytes));
        }
        staking
    }

    /// The from-seed reconstruction's merge half: sighting a bond for a slot
    /// the record lost ADOPTS it (sorted), records the first-sighting height,
    /// re-arms staking, and raises the monotone cursor above the highest
    /// sighted slot — on a fresh (restored) staking block starting from zero.
    #[test]
    fn adopt_bond_sightings_adopts_raises_and_rearms_from_zero() {
        let mut staking = shekyl_engine_state::StakingBlock::empty();
        adopt_bond_sightings(
            &mut staking,
            &[sighting(0, 100), sighting(2, 130), sighting(1, 120)],
        );
        assert_eq!(staking.bonded_slots, vec![0, 1, 2], "adopted, ascending");
        assert!(
            staking.staking_enabled,
            "a chain-proven bond re-arms staking"
        );
        assert_eq!(
            staking.p_slot, 3,
            "cursor raised one past the highest sighting"
        );
        assert_eq!(
            staking.bond_sightings.get(&2).map(|h| h.to_raw()),
            Some(130),
            "first-sighting height recorded"
        );
    }

    /// A sighted slot below existing entries (partial rollback shape) inserts
    /// in sorted position; an already-bonded slot neither duplicates nor
    /// disturbs; the cursor never lowers.
    #[test]
    fn adopt_bond_sightings_sorted_insert_no_dup_never_lowers() {
        let mut staking = shekyl_engine_state::StakingBlock::new(true, 6, vec![5]);
        adopt_bond_sightings(&mut staking, &[sighting(3, 90), sighting(5, 95)]);
        assert_eq!(
            staking.bonded_slots,
            vec![3, 5],
            "sorted insert below, no dup"
        );
        assert_eq!(
            staking.p_slot, 6,
            "cursor already above every sighting stays put (never lowered)"
        );
    }

    /// Duplicate sightings of the same slot keep the EARLIEST height —
    /// including when a later call (or a later row in the same untrusted
    /// batch) lists a lower height. The evidence bar arm #3 reads must
    /// not depend on producer order.
    #[test]
    fn adopt_bond_sightings_first_height_wins() {
        let mut staking = shekyl_engine_state::StakingBlock::empty();
        adopt_bond_sightings(&mut staking, &[sighting(0, 50)]);
        adopt_bond_sightings(&mut staking, &[sighting(0, 80)]);
        assert_eq!(staking.bond_sightings.get(&0).map(|h| h.to_raw()), Some(50));
        // One batch, high then low: the min wins, not the first row.
        adopt_bond_sightings(&mut staking, &[sighting(0, 90), sighting(0, 40)]);
        assert_eq!(staking.bond_sightings.get(&0).map(|h| h.to_raw()), Some(40));
        assert_eq!(staking.bonded_slots, vec![0]);
    }

    /// O5 contract: an empty processed range must carry no sightings, and a
    /// sighting height outside the range is malformed.
    #[test]
    fn validate_bond_sightings_rejects_contract_violations() {
        let staking = staking_with_cached_slots(&[0]);
        let mut empty_range = ScanResult::empty_at(1, None);
        empty_range.bond_sightings.push(sighting(0, 5));
        assert!(matches!(
            validate_bond_sightings(&empty_range, &staking),
            Err(RefreshError::MalformedScanResult { .. })
        ));

        let mut out_of_range = ScanResult::empty_at(1, None);
        out_of_range.processed_height_range = 10..20;
        out_of_range.bond_sightings.push(sighting(0, 25));
        assert!(matches!(
            validate_bond_sightings(&out_of_range, &staking),
            Err(RefreshError::MalformedScanResult { .. })
        ));

        let mut ok = ScanResult::empty_at(1, None);
        ok.processed_height_range = 10..20;
        ok.bond_sightings.push(sighting(0, 15));
        assert!(validate_bond_sightings(&ok, &staking).is_ok());
    }

    /// A sighting whose slot is not in the probe cache is malformed — this
    /// bites against a producer (or test double) naming an unwatched slot,
    /// which would otherwise permanently raise the monotone cursor. It does
    /// NOT cover retired-slot re-adoption (arm #2 heals that at the next
    /// open; the cache may still hold the retired row).
    #[test]
    fn validate_bond_sightings_rejects_a_slot_not_in_the_probe_cache() {
        let staking = staking_with_cached_slots(&[0]);
        let mut unknown = ScanResult::empty_at(1, None);
        unknown.processed_height_range = 10..20;
        unknown.bond_sightings.push(sighting(999, 15));
        let err = validate_bond_sightings(&unknown, &staking).expect_err("unknown slot");
        match err {
            RefreshError::MalformedScanResult { reason } => {
                assert!(reason.contains("persona_id_cache"), "got {reason:?}");
            }
            other => panic!("expected MalformedScanResult, got {other:?}"),
        }
    }
}
