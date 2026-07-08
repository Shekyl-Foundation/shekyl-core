// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! GF-4b backing-eligibility gate: the [`BackingSet`] constructor-mint type
//! (`ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.4).
//!
//! **Why the wallet type is the *only* enforcement layer (the C-1 review
//! anchor).** Consensus is lineage-blind (`REWARD_EMISSION_VIN_PLAN.md`
//! §8.0.3: unenforceable by construction) **and** spend-blind for backing
//! (Q11: tree-root-anchored membership — even a *spent* rung-3 output
//! remains provable). No daemon-side check can ever reject a rung-3
//! backing. The C-1 designated-backing selector must therefore obtain its
//! candidate **exclusively through [`BackingSet`]** — no direct
//! `funding_outputs` read on the backing path. That exclusivity is a named
//! C-1 merge-review item (GF-4b doc §5 item 1), checked at the PR boundary
//! rather than remembered.

use shekyl_engine_state::pscan_state::{MintLineageOutput, PFundingOutputRecord};
use shekyl_types::BlockHeight;

/// The backing-eligible subset of a persona's **spendable** funding records
/// — possession is proof that every member's lineage is rung 1 or rung 2
/// (`EmissionReward` / `BondPostChange`); a rung-3 (`ExternalTransfer`)
/// record inside one is unrepresentable
/// (`ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.4).
///
/// Constructor-mint pattern (the `RetirementWitness` /
/// `SpentRecordsDurablyPruned` shape): the field is private and
/// [`BackingSet::from_spendable`] is the sole constructor, so the eligibility
/// filter cannot be bypassed by literal construction.
///
/// **Filter, not fail-closed, on rung-3 input — deliberately.** Post-bond,
/// `P` may legitimately hold *new* raw funding outputs awaiting the next
/// re-bond sweep (the multi-tranche exception, GF-4b §3.5); their presence
/// in the wallet is legal. What must be impossible is their presence in the
/// backing candidate set — the constructor is the boundary that makes the
/// bad state unrepresentable rather than an error to handle. A fail-closed
/// constructor would turn a legal wallet state into a runtime error on
/// every between-sweeps emission.
#[allow(dead_code)] // transient — the C-1 designated-backing selector (arity-1
                    // `emission_wire.rs` pin) is the consumer; GF-4b doc §5 item 1.
pub(crate) struct BackingSet {
    /// Backing-eligible records, in the caller's order. Private on purpose —
    /// see the type docs.
    records: Vec<PFundingOutputRecord>,
}

#[allow(dead_code)] // transient — the C-1 designated-backing selector is the consumer.
impl BackingSet {
    /// Build the backing-eligible set from a persona's **spendable** funding
    /// records, filtering to the rung-1/rung-2 lineages and dropping
    /// `ExternalTransfer`.
    ///
    /// **Precondition (caller contract, named by the function name):**
    /// `records` is the persona's *spendable* slice — the GF4b-6 filter
    /// (`spendable_height ≤` the caller's reference height) already applied,
    /// exactly as the sweep applies it. Immature records must not reach this
    /// constructor: they would inflate the survivor tripwire below with
    /// false positives the spendability filter is designed to remove
    /// (GF-4b §3.4, minor note on GF4b-3).
    ///
    /// `last_sweep_height` is the max height of the persona's own
    /// **confirmed** bond posts (durable in `bond_post_matches`) — the
    /// boundary separating a legitimate between-sweeps tranche from a sweep
    /// regression:
    ///
    /// - a legitimate tranche is a rung-3 with `height > last_sweep_height`
    ///   (arrived after the last sweep; silently dropped, by design);
    /// - a survivor is a rung-3 with `height ≤ last_sweep_height` — it was
    ///   in scope for a sweep that should have consumed it.
    ///
    /// **The survivor tripwire (GF4b-3) — and its named false-positive
    /// mode.** The constructor `debug_assert!`s that no rung-3 record at or
    /// below `last_sweep_height` is present, so a sweep regression fails
    /// loudly in debug/test builds while release builds keep filter
    /// semantics (a wallet must not crash on a state it can filter). The
    /// assert's premise is **not airtight**: `P`'s funding set is
    /// adversary-influenceable (anyone can mine or send to `P`'s public
    /// pubkey, GF-4b §3.3), so a fire means a sweep bug **or** a
    /// late-surfaced low-height output (reorg-resurfaced, or an adversarial
    /// low-height output discovered late) — investigate, do not assume the
    /// sweep. The spendability precondition above removes the *immature*
    /// subset of these false positives; the mature-but-late subset remains a
    /// benign, debug-only false positive, accepted as the cost of keeping
    /// the sweep-regression tripwire armed.
    pub(crate) fn from_spendable(
        records: &[PFundingOutputRecord],
        last_sweep_height: BlockHeight,
    ) -> Self {
        debug_assert!(
            !records.iter().any(|r| {
                r.lineage == MintLineageOutput::ExternalTransfer && r.height <= last_sweep_height
            }),
            "rung-3 record at or below last_sweep_height ({last_sweep_height:?}) reached \
             BackingSet construction: a sweep bug OR a late-surfaced low-height output \
             (reorg / adversarial mine discovered late) — investigate, do not assume the sweep \
             (GF4b-3, ARCHIVAL_GF4B_BACKING_LINEAGE.md §3.4)"
        );

        Self {
            records: records
                .iter()
                .filter(|r| {
                    matches!(
                        r.lineage,
                        MintLineageOutput::EmissionReward | MintLineageOutput::BondPostChange
                    )
                })
                .cloned()
                .collect(),
        }
    }

    /// The backing-eligible records — every member is rung 1 or rung 2 by
    /// construction. The C-1 arity-1 selector picks its single designated
    /// backing output from this slice and nowhere else.
    pub(crate) fn records(&self) -> &[PFundingOutputRecord] {
        &self.records
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::bond_assembly::{sweep_funding_outputs, SpentRecordsDurablyPruned};
    use shekyl_types::{BlockHeight, SettlementEpoch};
    use shekyl_units::AtomicUnits;

    fn record(
        gindex: u64,
        height: u64,
        amount: u64,
        lineage: MintLineageOutput,
    ) -> PFundingOutputRecord {
        PFundingOutputRecord {
            p_slot: 0,
            tx_hash: [u8::try_from(gindex & 0xFF).expect("masked to a byte"); 32],
            index_in_transaction: 0,
            gindex,
            output_key: [1u8; 32],
            commitment: [2u8; 32],
            ciphertext_x25519: [3u8; 32],
            ciphertext_ml_kem: vec![4u8; 8],
            amount: AtomicUnits::from_raw(amount),
            height: BlockHeight::from_raw(height),
            epoch: SettlementEpoch::from_raw(0),
            lineage,
            spendable_height: shekyl_engine_state::transfer::eligible_height(
                BlockHeight::from_raw(height),
                shekyl_types::Timelock::None,
            ),
        }
    }

    /// Lineage filter: rung 1 and rung 2 are admitted; rung 3 above
    /// `last_sweep_height` (the legal between-sweeps tranche) is silently
    /// dropped — no assert, no error (GF-4b §3.4 filter-not-fail-closed).
    #[test]
    fn filters_to_backing_eligible_lineages() {
        let last_sweep_height = BlockHeight::from_raw(100);
        let records = vec![
            record(1, 90, 500, MintLineageOutput::BondPostChange),
            record(2, 95, 700, MintLineageOutput::EmissionReward),
            // Legal tranche: rung 3 arrived after the last sweep.
            record(3, 150, 900, MintLineageOutput::ExternalTransfer),
        ];

        let set = BackingSet::from_spendable(&records, last_sweep_height);
        let gindexes: Vec<u64> = set.records().iter().map(|r| r.gindex).collect();
        assert_eq!(
            gindexes,
            vec![1, 2],
            "rung 1/2 admitted; the legal rung-3 tranche is dropped without incident"
        );
    }

    /// GF4b-3 survivor tripwire: a rung-3 at or below `last_sweep_height`
    /// trips the `debug_assert!` in debug/test builds.
    #[test]
    #[should_panic(expected = "rung-3 record at or below last_sweep_height")]
    fn survivor_trips_the_debug_assert() {
        let last_sweep_height = BlockHeight::from_raw(100);
        let records = vec![
            record(1, 90, 500, MintLineageOutput::BondPostChange),
            // Survivor: rung 3 that a sweep should have consumed.
            record(2, 80, 700, MintLineageOutput::ExternalTransfer),
        ];
        let _ = BackingSet::from_spendable(&records, last_sweep_height);
    }

    /// The zero-pre-bond-output test (GF-4b §3.4 definition, §4 item 3) —
    /// state-level, against the sweep + the funding-record set (the
    /// bond-post path's data plane; `AssembleBond` stays dead code, so no
    /// end-to-end tx is built).
    ///
    /// One persona slot, mixed lineage: raw funding (rung 3) plus a
    /// `BondPostChange` record from a prior post. Asserts, in order:
    ///
    /// 1. the sweep selection **is** the full unreserved *spendable*
    ///    eligible set — including records a greedy subset selector would
    ///    have left behind;
    /// 2. the post-sweep **spendable** remainder is empty — in particular,
    ///    zero spendable `ExternalTransfer` records survive;
    /// 3. the post-bond state (the new bond-post change record, lineage
    ///    `BondPostChange`) yields a `BackingSet` containing it, while a
    ///    rung-3 record above `last_sweep_height` (the legal-tranche case)
    ///    injected into the same input set is **not** in the resulting set.
    ///
    /// (Assert 4 of the definition — the survivor tripwire — is
    /// `survivor_trips_the_debug_assert` above.)
    #[test]
    fn zero_pre_bond_output_survives_the_sweep() {
        let reference_height = BlockHeight::from_raw(1_000);

        // Pre-sweep state: three raw funding outputs (rung 3) and one
        // change record from a prior post (rung 2). Amounts chosen so a
        // greedy subset selector would stop after the first two records —
        // the third rung-3 record (gindex 12) is exactly the survivor class
        // the sweep exists to eliminate.
        let pre_sweep = vec![
            record(10, 100, 600, MintLineageOutput::ExternalTransfer),
            record(11, 110, 500, MintLineageOutput::ExternalTransfer),
            record(12, 120, 400, MintLineageOutput::ExternalTransfer),
            record(13, 130, 300, MintLineageOutput::BondPostChange),
        ];
        let required = 1_000; // A greedy selector satisfies this at two records.

        let selection = sweep_funding_outputs(
            &SpentRecordsDurablyPruned::for_test(),
            &pre_sweep,
            0,
            &Default::default(),
            required,
            reference_height,
        )
        .expect("sweep succeeds");

        // (1) The sweep is the full spendable eligible set.
        let swept: std::collections::BTreeSet<u64> =
            selection.records.iter().map(|r| r.gindex).collect();
        assert_eq!(
            swept,
            [10, 11, 12, 13].into_iter().collect(),
            "sweep consumed everything, including the record a greedy subset leaves behind"
        );
        assert_eq!(selection.total, 1_800);

        // (2) Post-confirmation spendable remainder is empty. Durable
        // pruning is SP-R0-gated, so model spent-removal as records minus
        // swept gindexes.
        let remainder: Vec<&PFundingOutputRecord> = pre_sweep
            .iter()
            .filter(|r| !swept.contains(&r.gindex) && r.spendable_height <= reference_height)
            .collect();
        assert!(
            remainder.is_empty(),
            "zero spendable records — in particular zero rung-3 — survive the sweep"
        );

        // (3) Post-bond state: the confirmed post leaves one change record
        // (rung 2) at the post's height; a later rung-3 tranche arrives
        // above last_sweep_height. The BackingSet contains exactly the
        // change record.
        let last_sweep_height = BlockHeight::from_raw(200); // The confirmed post's height.
        let post_bond = vec![
            record(20, 200, 750, MintLineageOutput::BondPostChange),
            // Legal between-sweeps tranche (height > last_sweep_height).
            record(21, 250, 123, MintLineageOutput::ExternalTransfer),
        ];
        let set = BackingSet::from_spendable(&post_bond, last_sweep_height);
        let eligible: Vec<u64> = set.records().iter().map(|r| r.gindex).collect();
        assert_eq!(
            eligible,
            vec![20],
            "the bond-post change record is backing-eligible; the raw tranche is not"
        );
    }
}
