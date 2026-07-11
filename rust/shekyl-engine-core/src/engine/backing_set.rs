// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! GF-4b backing-eligibility gate: the [`BackingSet`] constructor-mint type
//! and the C-1 designated-backing selector (`ARCHIVAL_GF4B_BACKING_LINEAGE.md`
//! §3.4, §5 item 1).
//!
//! **Why the wallet type is the *only* enforcement layer (the C-1 review
//! anchor).** Consensus is lineage-blind (`REWARD_EMISSION_VIN_PLAN.md`
//! §8.0.3: unenforceable by construction) **and** spend-blind for backing
//! (Q11: tree-root-anchored membership — even a *spent* rung-3 output
//! remains provable). No daemon-side check can ever reject a rung-3
//! backing. The designated-backing selector therefore obtains its candidate
//! **exclusively through [`BackingSet`]** — structurally, not by review
//! memory: [`BackingSet::designate_backing`] is [`DesignatedBacking`]'s sole
//! constructor, and the set's record slice has no production accessor (the
//! test-inspection `records()` is `cfg(test)`), so there is no path from
//! `funding_outputs` to a backing candidate that bypasses the eligibility
//! filter (GF-4b doc §5 item 1, checked here by shape and at the PR boundary
//! by grep).

use std::collections::BTreeSet;

use shekyl_engine_state::pscan_state::{MintLineageOutput, PFundingOutputRecord};
use shekyl_types::BlockHeight;

use crate::engine::bond_assembly::{
    sweep_funding_outputs, BondAssemblyError, FundingSelection, SpentRecordsDurablyPruned,
};

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
pub(crate) struct BackingSet {
    /// Backing-eligible records, in the caller's order. Private on purpose —
    /// see the type docs.
    records: Vec<PFundingOutputRecord>,
    /// The spendability anchor the set was built against — retained so the
    /// backing decision and everything downstream of it (the fee sweep, the
    /// C-4 same-tip check) share literally the same height rather than
    /// re-supplied copies that can drift (GF-4b §4 item 6).
    reference_height: BlockHeight,
}

impl BackingSet {
    /// Build the backing-eligible set from a persona's **spendable** funding
    /// records, filtering to the rung-1/rung-2 lineages and dropping
    /// `ExternalTransfer`.
    ///
    /// **Spendability is enforced here, not assumed of the caller.** The
    /// constructor applies the GF4b-6 filter itself — `spendable_height ≤
    /// reference_height`, exactly as the sweep applies it — so the `spendable`
    /// in the name is a guarantee the type owns rather than a precondition a
    /// future caller must remember. `reference_height` is the caller's
    /// spendability anchor (the chain height the backing decision is made
    /// against). Because the filter runs *before* the survivor tripwire,
    /// immature records cannot inflate it with false positives (GF-4b §3.4,
    /// minor note on GF4b-3).
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
    /// sweep. The enforced spendability filter above removes the *immature*
    /// subset of these false positives; the mature-but-late subset remains a
    /// benign, debug-only false positive, accepted as the cost of keeping
    /// the sweep-regression tripwire armed.
    pub(crate) fn from_spendable(
        records: &[PFundingOutputRecord],
        reference_height: BlockHeight,
        last_sweep_height: BlockHeight,
    ) -> Self {
        // Enforce the spendability precondition here rather than trust the
        // caller (GF4b-6): a record is in the tree iff `spendable_height <=
        // reference_height`, exactly as the sweep applies it. Filtering
        // before the survivor tripwire drops the immature subset of its false
        // positives by construction, and makes the type's "spendable"
        // guarantee hold for every member rather than by remembered contract.
        let spendable: Vec<&PFundingOutputRecord> = records
            .iter()
            .filter(|r| r.spendable_height <= reference_height)
            .collect();

        debug_assert!(
            !spendable.iter().any(|r| {
                r.lineage == MintLineageOutput::ExternalTransfer && r.height <= last_sweep_height
            }),
            "rung-3 record at or below last_sweep_height ({last_sweep_height:?}) reached \
             BackingSet construction: a sweep bug OR a late-surfaced low-height output \
             (reorg / adversarial mine discovered late) — investigate, do not assume the sweep \
             (GF4b-3, ARCHIVAL_GF4B_BACKING_LINEAGE.md §3.4)"
        );

        Self {
            reference_height,
            records: spendable
                .into_iter()
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

    /// The C-1 designated-backing selector (GF-4b §5 item 1, arity-1 per the
    /// `emission_wire.rs` single-vin pin): pick the persona's **single**
    /// designated backing output, consuming `self` so the candidate set
    /// cannot be re-consulted for a second designation.
    ///
    /// **Policy: most-recent-eligible — highest `(height, gindex)`.** The
    /// reveal is equally safe for rung 1 and rung 2 (`REWARD_EMISSION_VIN_PLAN.md`
    /// §8.0.3), so a lineage preference would add a distinguishable
    /// selection fingerprint without a safety benefit; keying on height
    /// alone (structural, lineage-blind) minimizes the revealed output's age
    /// instead. The order is total — distinct outputs have distinct
    /// gindexes — so the pick is deterministic.
    ///
    /// **Reproducible, not merely locally deterministic.** `BackingSet`
    /// membership is itself a deterministic function of chain state at
    /// `reference_height` (the constructor's spendability + lineage filters
    /// over scan-derived records), so two wallet instances — or the same
    /// wallet before and after a rescan — designate the **same** backing at
    /// the same reference height. "Most recent" is reproducible because the
    /// set it selects over is, not just because the comparator is total.
    ///
    /// An empty set refuses with [`InsufficientBacking`] — the bootstrap
    /// state before the first bond post confirms (GF-4b §4 item 3), or a
    /// persona whose only records are immature or rung-3 tranches. The
    /// caller waits or bonds; nothing is assembled.
    pub(crate) fn designate_backing(self) -> Result<DesignatedBacking, InsufficientBacking> {
        let reference_height = self.reference_height;
        self.records
            .into_iter()
            .max_by_key(|r| (r.height, r.gindex))
            .map(|record| DesignatedBacking {
                record,
                reference_height,
            })
            .ok_or(InsufficientBacking { reference_height })
    }

    /// Test-only inspection of the eligible records. Production code has no
    /// accessor to the slice **on purpose**: the only way a record leaves a
    /// `BackingSet` is through [`Self::designate_backing`], which is what
    /// makes "candidates come exclusively through `BackingSet`" a property
    /// of the type rather than a review obligation.
    #[cfg(test)]
    pub(crate) fn records(&self) -> &[PFundingOutputRecord] {
        &self.records
    }
}

/// The persona has no backing-eligible spendable output at the reference
/// height — no rung-1/rung-2 record to designate as the emission claim's
/// backing (GF-4b §4 item 3's bootstrap state, or an all-immature /
/// all-rung-3 wallet). Caller-recoverable refusal (rule 82): bond first
/// (the first confirmed post's change record is the first backing), or wait
/// for maturity; nothing was assembled or persisted.
#[derive(Debug, thiserror::Error)]
#[error(
    "no backing-eligible spendable output at reference height {reference_height:?}: \
     an emission claim needs a confirmed rung-1/rung-2 output as its designated \
     backing — post a bond first, or wait for a pending one to confirm and mature"
)]
pub(crate) struct InsufficientBacking {
    /// The spendability anchor the empty set was built against.
    pub reference_height: BlockHeight,
}

/// The single designated backing output of an emission claim (arity-1), as
/// selected by [`BackingSet::designate_backing`] — the **sole** constructor;
/// the record field is private so a backing candidate cannot be minted from
/// a raw `funding_outputs` read (GF-4b §5 item 1's exclusivity, by shape).
///
/// The type also owns the **Q11 fee-exclusion**: the designated backing
/// must never double as a fee input (one output serving once as backing and
/// once as a `txin_to_key` spend is the CB-4 double-use), and the exclusion
/// lives here — at fee-candidate-set construction — rather than at a call
/// site that must remember it. [`Self::fee_sweep`] is the claim path's only
/// fee-selection entry, and it inserts the backing's `gindex` into the
/// exclusion set before delegating, so a fee selection containing the
/// backing is unrepresentable through this path.
pub(crate) struct DesignatedBacking {
    /// The designated backing record. Private — see the type docs.
    record: PFundingOutputRecord,
    /// The spendability anchor inherited from the [`BackingSet`] this
    /// backing was designated from. The fee sweep below reuses it, so the
    /// backing decision and the fee-input spendability are anchored to the
    /// same height by construction; the C-4 handler's same-tip check
    /// (GF-4b §4 item 6) compares this single value against the tip the
    /// tree context and membership paths are fetched at, and
    /// refuses-and-refetches on mismatch.
    reference_height: BlockHeight,
}

impl DesignatedBacking {
    /// The designated backing record (read-only).
    pub(crate) fn record(&self) -> &PFundingOutputRecord {
        &self.record
    }

    /// The spendability anchor the backing was designated at — the height
    /// the C-4 same-tip check verifies against the assembly tip (GF-4b §4
    /// item 6).
    pub(crate) fn reference_height(&self) -> BlockHeight {
        self.reference_height
    }

    /// The claim path's fee-input selection: [`sweep_funding_outputs`] with
    /// the designated backing structurally excluded (Q11) and the
    /// spendability anchor inherited from the backing decision (item 6).
    ///
    /// `reserved` is the live pending posts' reservation union, exactly as
    /// on the bond path; this method unions the backing's `gindex` into it
    /// before delegating, so the exclusion cannot be forgotten or applied
    /// against the wrong output. The C-4 handler obtains fee inputs
    /// **exclusively** through this method — the same monopoly discipline as
    /// `sweep_funding_outputs` on the bond path (GF-4b §5 item 4's grep
    /// shape), reviewed at the PR boundary.
    pub(crate) fn fee_sweep(
        &self,
        pruning_landed: &SpentRecordsDurablyPruned,
        records: &[PFundingOutputRecord],
        p_slot: u32,
        reserved: &BTreeSet<u64>,
        required: u64,
    ) -> Result<FundingSelection, BondAssemblyError> {
        let mut excluded = reserved.clone();
        excluded.insert(self.record.gindex);
        sweep_funding_outputs(
            pruning_landed,
            records,
            p_slot,
            &excluded,
            required,
            self.reference_height,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::bond_assembly::{sweep_funding_outputs, SpentRecordsDurablyPruned};
    use crate::engine::test_support::funding_record;
    use shekyl_types::BlockHeight;

    /// Slot-0 wrapper over the crate's single `funding_record` fixture — this
    /// module varies `lineage`, so it threads that through.
    fn record(
        gindex: u64,
        height: u64,
        amount: u64,
        lineage: MintLineageOutput,
    ) -> PFundingOutputRecord {
        funding_record(0, gindex, height, amount, lineage)
    }

    /// Lineage filter: rung 1 and rung 2 are admitted; rung 3 above
    /// `last_sweep_height` (the legal between-sweeps tranche) is silently
    /// dropped — no assert, no error (GF-4b §3.4 filter-not-fail-closed).
    #[test]
    fn filters_to_backing_eligible_lineages() {
        // Far-future reference height: every fixture record is spendable, so
        // this test isolates the lineage filter from the GF4b-6 spendability
        // filter.
        let reference_height = BlockHeight::from_raw(1_000_000);
        let last_sweep_height = BlockHeight::from_raw(100);
        let records = vec![
            record(1, 90, 500, MintLineageOutput::BondPostChange),
            record(2, 95, 700, MintLineageOutput::EmissionReward),
            // Legal tranche: rung 3 arrived after the last sweep.
            record(3, 150, 900, MintLineageOutput::ExternalTransfer),
        ];

        let set = BackingSet::from_spendable(&records, reference_height, last_sweep_height);
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
        // Far-future reference: the survivor is spendable, so it reaches the
        // tripwire (the spendability filter does not mask a mature survivor).
        let reference_height = BlockHeight::from_raw(1_000_000);
        let last_sweep_height = BlockHeight::from_raw(100);
        let records = vec![
            record(1, 90, 500, MintLineageOutput::BondPostChange),
            // Survivor: rung 3 that a sweep should have consumed.
            record(2, 80, 700, MintLineageOutput::ExternalTransfer),
        ];
        let _ = BackingSet::from_spendable(&records, reference_height, last_sweep_height);
    }

    /// GF4b-6 enforcement: the constructor applies the spendability filter
    /// itself, so (a) an immature rung-1/2 record is excluded from the set,
    /// and (b) an immature rung-3 at or below `last_sweep_height` does **not**
    /// trip the survivor tripwire — the immature subset of false positives is
    /// removed before the assert, exactly as the type doc claims. Contrast
    /// `survivor_trips_the_debug_assert`, whose survivor is *spendable*.
    #[test]
    fn immature_records_are_excluded_before_the_tripwire() {
        // reference_height sits far below every record's spendable_height
        // (height + SPENDABLE_AGE), so both records are immature regardless of
        // the exact lock window.
        let reference_height = BlockHeight::from_raw(100);
        let last_sweep_height = BlockHeight::from_raw(250);
        let records = vec![
            // Immature rung-2: backing-eligible by lineage, but not yet in the
            // tree at reference_height → excluded.
            record(1, 200, 500, MintLineageOutput::BondPostChange),
            // Immature rung-3 at/below last_sweep_height: a survivor by height,
            // but the spendability filter removes it before the tripwire.
            record(2, 200, 700, MintLineageOutput::ExternalTransfer),
        ];

        let set = BackingSet::from_spendable(&records, reference_height, last_sweep_height);
        assert!(
            set.records().is_empty(),
            "immature records — including the rung-2 — are excluded by the enforced spendability filter"
        );
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
        let set = BackingSet::from_spendable(&post_bond, reference_height, last_sweep_height);
        let eligible: Vec<u64> = set.records().iter().map(|r| r.gindex).collect();
        assert_eq!(
            eligible,
            vec![20],
            "the bond-post change record is backing-eligible; the raw tranche is not"
        );
    }

    /// Most-recent-eligible selection: highest `(height, gindex)` wins, so
    /// the pick is total-ordered and deterministic. Two records share the
    /// top height to exercise the gindex tie-break.
    #[test]
    fn designates_the_most_recent_eligible_backing() {
        let reference_height = BlockHeight::from_raw(1_000_000);
        let last_sweep_height = BlockHeight::from_raw(100);
        let records = vec![
            record(1, 90, 500, MintLineageOutput::BondPostChange),
            record(2, 95, 700, MintLineageOutput::EmissionReward),
            // Height tie at 95: the higher gindex is the later output in
            // chain order and wins the tie-break.
            record(3, 95, 300, MintLineageOutput::BondPostChange),
        ];

        let designated = BackingSet::from_spendable(&records, reference_height, last_sweep_height)
            .designate_backing()
            .expect("eligible records exist");
        assert_eq!(
            designated.record().gindex,
            3,
            "highest (height, gindex) is designated"
        );
        assert_eq!(
            designated.reference_height(),
            reference_height,
            "the designation carries the set's spendability anchor"
        );
    }

    /// The bootstrap refusal (GF-4b §4 item 3's precondition): a wallet
    /// whose only records are a legal rung-3 tranche and an immature rung-2
    /// has an empty `BackingSet`, and designation refuses with
    /// `InsufficientBacking` carrying the anchor it was evaluated at.
    #[test]
    fn insufficient_backing_refuses_on_the_bootstrap_state() {
        let reference_height = BlockHeight::from_raw(1_000);
        let last_sweep_height = BlockHeight::from_raw(100);
        let records = vec![
            // Legal tranche: rung 3 above the last sweep — never eligible.
            record(1, 150, 900, MintLineageOutput::ExternalTransfer),
            // Backing-eligible lineage but immature at the reference height.
            record(2, 999, 500, MintLineageOutput::BondPostChange),
        ];

        // No `expect_err`: `DesignatedBacking` intentionally derives no
        // `Debug` (same redaction posture as `FundingSelection` — the
        // contained funding record is the sensitive part).
        match BackingSet::from_spendable(&records, reference_height, last_sweep_height)
            .designate_backing()
        {
            Ok(_) => panic!("expected InsufficientBacking"),
            Err(err) => assert_eq!(err.reference_height, reference_height),
        }
    }

    /// GF-4b §4 item 3, the first-emission integration shape: after the
    /// first bond post confirms, the persona's designated backing **is** the
    /// post's change record (rung 2) — and a *more recent* rung-3 tranche
    /// cannot displace it, because lineage filtering happens upstream of the
    /// most-recent-eligible comparator. The tranche is deliberately the
    /// highest-height record so this test fails if the rung-3 exclusion ever
    /// moved downstream of (or into) the selection policy.
    #[test]
    fn first_emission_backing_is_the_bond_post_change() {
        let reference_height = BlockHeight::from_raw(1_000_000);
        let last_sweep_height = BlockHeight::from_raw(200); // The confirmed first post's height.
        let post_first_bond = vec![
            // The first post's change record — the persona's only rung-1/2.
            record(20, 200, 750, MintLineageOutput::BondPostChange),
            // A more recent legal tranche (height 250 > 200): ineligible
            // despite being the most recent record in the wallet.
            record(21, 250, 900, MintLineageOutput::ExternalTransfer),
        ];

        let designated =
            BackingSet::from_spendable(&post_first_bond, reference_height, last_sweep_height)
                .designate_backing()
                .expect("the change record is eligible");
        assert_eq!(
            designated.record().gindex,
            20,
            "the first emission's backing is the bond-post change record, \
             not the more recent rung-3 tranche"
        );
        assert_eq!(
            designated.record().lineage,
            MintLineageOutput::BondPostChange
        );
    }

    /// Q11 fee-exclusion, with its premise armed: the designated backing is
    /// spendable and unreserved, so the **plain** sweep would select it —
    /// proven first, so the exclusion assertion below cannot pass vacuously.
    /// `fee_sweep` over the same records must exclude exactly the backing
    /// (double-use unrepresentable) while still honoring the live
    /// reservation set.
    #[test]
    fn fee_sweep_excludes_the_designated_backing() {
        let reference_height = BlockHeight::from_raw(1_000_000);
        let last_sweep_height = BlockHeight::from_raw(100);
        let records = vec![
            record(1, 90, 500, MintLineageOutput::BondPostChange),
            record(2, 95, 700, MintLineageOutput::EmissionReward), // → designated
            // Legal tranche (height > last_sweep_height): fee-eligible,
            // never backing-eligible.
            record(3, 150, 400, MintLineageOutput::ExternalTransfer),
        ];
        let reserved: std::collections::BTreeSet<u64> = [1].into_iter().collect();

        // Premise: without the exclusion, the sweep selects the backing.
        let plain = sweep_funding_outputs(
            &SpentRecordsDurablyPruned::for_test(),
            &records,
            0,
            &reserved,
            0,
            reference_height,
        )
        .expect("plain sweep succeeds");
        assert!(
            plain.records.iter().any(|r| r.gindex == 2),
            "premise: the backing is sweep-eligible, so the exclusion below is load-bearing"
        );

        let designated = BackingSet::from_spendable(&records, reference_height, last_sweep_height)
            .designate_backing()
            .expect("eligible records exist");
        assert_eq!(
            designated.record().gindex,
            2,
            "premise: gindex 2 is the backing"
        );

        let fee = designated
            .fee_sweep(
                &SpentRecordsDurablyPruned::for_test(),
                &records,
                0,
                &reserved,
                0,
            )
            .expect("fee sweep succeeds");
        let fee_gindexes: Vec<u64> = fee.records.iter().map(|r| r.gindex).collect();
        assert!(
            !fee_gindexes.contains(&2),
            "the designated backing never appears in the fee selection (Q11)"
        );
        assert!(
            !fee_gindexes.contains(&1),
            "live reservations remain excluded alongside the backing"
        );
        assert_eq!(
            fee_gindexes,
            vec![3],
            "the fee sweep is the plain sweep minus the backing and reservations"
        );
    }

    /// Item 6 anchoring: the fee sweep reuses the backing's own
    /// `reference_height` (one anchor, stored once at `BackingSet`
    /// construction), so a record immature at the backing's anchor cannot
    /// enter the fee selection even though the caller never re-supplies a
    /// height to `fee_sweep`.
    #[test]
    fn fee_sweep_shares_the_backing_reference_height() {
        // eligible_height(999, None) = 999 + SPENDABLE_AGE > 1_000, so the
        // tranche is immature at the anchor while the older records are
        // spendable.
        let reference_height = BlockHeight::from_raw(1_000);
        let last_sweep_height = BlockHeight::from_raw(100);
        let records = vec![
            record(1, 90, 500, MintLineageOutput::BondPostChange), // → designated
            // Legal tranche (height > last_sweep_height), spendable at 1_000.
            record(2, 150, 400, MintLineageOutput::ExternalTransfer),
            record(3, 999, 900, MintLineageOutput::ExternalTransfer), // immature at 1_000
        ];

        let designated = BackingSet::from_spendable(&records, reference_height, last_sweep_height)
            .designate_backing()
            .expect("eligible record exists");
        let fee = designated
            .fee_sweep(
                &SpentRecordsDurablyPruned::for_test(),
                &records,
                0,
                &Default::default(),
                0,
            )
            .expect("fee sweep succeeds");
        let fee_gindexes: Vec<u64> = fee.records.iter().map(|r| r.gindex).collect();
        assert_eq!(
            fee_gindexes,
            vec![2],
            "the immature record is excluded by the inherited anchor; the backing by Q11"
        );
    }
}
