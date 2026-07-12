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
//!
//! **The designation-event seal (`SweptFeeInputs` → [`ClaimOperands`]).**
//! The same monopoly discipline extends to the claim message's operands
//! (`EMISSION_CLAIM_BUILDER.md` §8's named forward item): the handler's two
//! old step-2 runtime refusals (`StaleClaimAnchor`, `BackingInFeeSet`) were
//! one invariant — *these operands came from one designation event* —
//! enforced as comparisons because the message fields were freely
//! constructible. [`DesignatedBacking::fee_sweep`] now consumes the
//! designation **and** the claim source and mints [`SweptFeeInputs`], the
//! sealed triple; [`SweptFeeInputs::with_paths`] zips the membership paths
//! in without breaking the seal; the message takes the resulting
//! [`ClaimOperands`] whole. Cross-pairing a fee selection, a designation,
//! and a source from different events is unrepresentable, and the refusal
//! arms are deleted, not relocated (the one remaining runtime comparison —
//! designation anchor vs. source tip — happens once, at the mint).

use std::collections::BTreeSet;

use shekyl_engine_state::pscan_state::{MintLineageOutput, PFundingOutputRecord};
use shekyl_tx_builder::LeafEntry;
use shekyl_types::{BlockHeight, GlobalOutputIndex, PSlot};
use shekyl_units::AtomicUnits;

use crate::engine::bond_assembly::{
    sweep_funding_outputs, BondAssemblyError, FundingInputContext, FundingSelection,
    SpentRecordsDurablyPruned,
};
use crate::engine::emission_source::EmissionClaimSource;

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
    /// The spendability anchor the set was built against — the chain **tip**
    /// (a height, `chain_height − 1`) — retained so the backing decision and
    /// everything downstream of it (the fee sweep, the C-4 same-tip check)
    /// share literally the same height rather than re-supplied copies that
    /// can drift (GF-4b §4 item 6).
    reference_height: BlockHeight,
}

impl BackingSet {
    /// Build the backing-eligible set from **the claimant persona's**
    /// spendable funding records, filtering to the rung-1/rung-2 lineages
    /// and dropping `ExternalTransfer`.
    ///
    /// **The slot filter is enforced here, not assumed of the caller.**
    /// `records` may be the wallet's all-slot `funding_outputs` union;
    /// only `p_slot`'s records enter the set. Without this filter the
    /// most-recent-eligible comparator can designate ANOTHER slot's record
    /// (rotation overlap: the new persona's bond-post change is the newest
    /// rung-2 on chain), and the claimant's key re-derivation then fails
    /// the pre-flight leaf gate on every claim attempt — a persona
    /// deterministically unable to claim. The fee sweep applies the same
    /// slot filter (`sweep_funding_outputs`); the two paths must not
    /// differ. Filtering before the survivor tripwire also keeps the
    /// tripwire per-persona: another slot's rung-3 tranche must not trip
    /// against *this* persona's sweep boundary.
    ///
    /// **Spendability is enforced here too.** The constructor applies the
    /// GF4b-6 filter itself — `spendable_height ≤ reference_height`,
    /// exactly as the sweep applies it — so the `spendable` in the name is
    /// a guarantee the type owns rather than a precondition a future
    /// caller must remember. `reference_height` is the caller's
    /// spendability anchor: the chain **tip** the backing decision is made
    /// against (a height, `chain_height − 1` — never the block count
    /// itself, which would admit a record one block early and report a
    /// not-yet-existing height in the refusal). Because the filter runs
    /// *before* the survivor tripwire, immature records cannot inflate it
    /// with false positives (GF-4b §3.4, minor note on GF4b-3).
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
    pub(crate) fn from_spendable<'a, I>(
        records: I,
        p_slot: PSlot,
        reference_height: BlockHeight,
        last_sweep_height: BlockHeight,
    ) -> Self
    where
        I: IntoIterator<Item = &'a PFundingOutputRecord>,
    {
        // Enforce the slot + spendability preconditions here rather than
        // trust the caller (type docs; GF4b-6): only the claimant slot's
        // records, and a record is in the tree iff `spendable_height <=
        // reference_height`, exactly as the sweep applies both. Filtering
        // before the survivor tripwire drops the immature and foreign-slot
        // subsets of its false positives by construction, and makes the
        // type's guarantees hold for every member rather than by
        // remembered contract.
        let spendable: Vec<&PFundingOutputRecord> = records
            .into_iter()
            .filter(|r| r.p_slot == p_slot && r.spendable_height <= reference_height)
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
    /// same height by construction; the mint-time same-tip check (GF-4b §4
    /// item 6, [`Self::fee_sweep`]) compares this single value against the
    /// claim source's gather tip and refuses-and-refetches on mismatch.
    reference_height: BlockHeight,
}

impl DesignatedBacking {
    /// The designated backing record (read-only).
    pub(crate) fn record(&self) -> &PFundingOutputRecord {
        &self.record
    }

    /// The claim path's fee-input selection **and the designation-event
    /// seal's mint site** (module docs): [`sweep_funding_outputs`] with the
    /// designated backing structurally excluded (Q11) and the spendability
    /// anchor inherited from the backing decision (item 6), consuming the
    /// designation *and* the claim source so the three operands leave as one
    /// sealed [`SweptFeeInputs`].
    ///
    /// The item-6 same-tip comparison happens **once, here**: the
    /// designation's stored anchor must equal the source's gather tip
    /// (`chain_height − 1` — a height, never the block count), or backing
    /// spendability and claim-window finalization were evaluated against
    /// different chains ([`ClaimFundingError::StaleClaimAnchor`]; the caller
    /// refetches both at one tip). Downstream there is nothing left to
    /// re-check — the witness carries the pairing.
    ///
    /// `reserved` is the live pending posts' reservation union, exactly as
    /// on the bond path; this method unions the backing's `gindex` into it
    /// before delegating, so the exclusion cannot be forgotten or applied
    /// against the wrong output. The claim path obtains fee inputs
    /// **exclusively** through this method — the same monopoly discipline as
    /// `sweep_funding_outputs` on the bond path (GF-4b §5 item 4's grep
    /// shape), reviewed at the PR boundary.
    ///
    /// A sweep whose eligible set is **empty** refuses structurally
    /// ([`ClaimFundingError::ClaimFeeInputsRequired`], regardless of the fee
    /// amount): the loud reward vout consumes the entire mint, so the fee
    /// side must supply the tx's pseudoOuts and its FCMP++ fee-side proof
    /// anchor from at least one separate spendable output. A sweep that
    /// selects something but falls short of `fee` — including eligible
    /// records that all carry amount 0 — is a genuine shortfall and keeps
    /// the [`BondAssemblyError::InsufficientFunding`] taxonomy.
    pub(crate) fn fee_sweep<'a, I>(
        self,
        source: EmissionClaimSource,
        pruning_landed: &SpentRecordsDurablyPruned,
        records: I,
        p_slot: PSlot,
        reserved: &BTreeSet<GlobalOutputIndex>,
        fee: AtomicUnits,
    ) -> Result<SweptFeeInputs, ClaimFundingError>
    where
        I: IntoIterator<Item = &'a PFundingOutputRecord>,
    {
        if source.chain_height.tip() != Some(self.reference_height) {
            return Err(ClaimFundingError::StaleClaimAnchor {
                anchor: self.reference_height.to_raw(),
                tip: source.chain_height.tip().map_or(0, BlockHeight::to_raw),
            });
        }

        let mut excluded = reserved.clone();
        excluded.insert(self.record.gindex);
        let selection = sweep_funding_outputs(
            pruning_landed,
            records,
            p_slot,
            &excluded,
            fee,
            self.reference_height,
        )
        .map_err(|err| match err {
            // The sweep's typed empty-eligible-set refusal IS the structural
            // no-fee-input state. Deliberately NOT keyed on
            // `InsufficientFunding { available: 0 }`: zero available also
            // occurs when eligible records exist but all carry amount 0 (a
            // representable CT state) — that is a genuine shortfall whose
            // remedy is funding, and it keeps the shortfall taxonomy below.
            BondAssemblyError::NoSpendableFunding => {
                ClaimFundingError::ClaimFeeInputsRequired { fee: fee.to_raw() }
            }
            other => ClaimFundingError::Assembly(other),
        })?;

        Ok(SweptFeeInputs {
            source,
            backing: self,
            selection,
            fee,
        })
    }
}

/// The sealed designation-event triple (module docs): the claim source, the
/// designated backing, and the fee selection swept **against that backing at
/// that source's tip** — [`DesignatedBacking::fee_sweep`] is the sole
/// constructor, so possession is proof the three operands came from one
/// designation event. Every field is private; the only exits are
/// [`Self::path_records`] (borrowed, for membership-path assembly) and
/// [`Self::with_paths`] (consuming, into [`ClaimOperands`]).
pub(crate) struct SweptFeeInputs {
    /// The claim source the designation was anchored against.
    source: EmissionClaimSource,
    /// The designated backing (its `gindex` is excluded from `selection` by
    /// the mint).
    backing: DesignatedBacking,
    /// The swept fee selection — non-empty by [`FundingSelection`]'s own
    /// constructor invariant.
    selection: FundingSelection,
    /// The fee the sweep was run against (`selection.total >= fee`, by the
    /// sweep's shortfall refusal).
    fee: AtomicUnits,
}

impl SweptFeeInputs {
    /// The records needing curve-tree membership paths, in path-request
    /// order: the backing first, then the fee records in sweep
    /// (oldest-first) order. [`Self::with_paths`] consumes the assembled
    /// paths in exactly this order.
    pub(crate) fn path_records(&self) -> impl Iterator<Item = &PFundingOutputRecord> {
        std::iter::once(&self.backing.record).chain(self.selection.records.iter())
    }

    /// Test-only inspection of the swept fee records (the production exits
    /// are `path_records` and `with_paths`; see the type docs).
    #[cfg(test)]
    pub(crate) fn fee_records(&self) -> &[PFundingOutputRecord] {
        &self.selection.records
    }

    /// Zip the assembled membership paths in — one per [`Self::path_records`]
    /// entry, same order — producing the message-ready [`ClaimOperands`]
    /// without breaking the seal. Refuses a count mismatch loudly
    /// ([`ClaimFundingError::PathCount`]) rather than mis-pairing paths to
    /// records.
    pub(crate) fn with_paths(
        self,
        mut paths: Vec<MembershipPath>,
    ) -> Result<ClaimOperands, ClaimFundingError> {
        let expected = 1 + self.selection.records.len();
        if paths.len() != expected {
            return Err(ClaimFundingError::PathCount {
                expected,
                got: paths.len(),
            });
        }
        let fee_paths = paths.split_off(1);
        let backing_path = paths
            .pop()
            .expect("length checked above: exactly 1 remains");
        let fee_funding = self
            .selection
            .records
            .into_iter()
            .zip(fee_paths)
            .map(|(record, path)| FundingInputContext {
                record,
                leaf_chunk: path.leaf_chunk,
                c1_layers: path.c1_layers,
                c2_layers: path.c2_layers,
            })
            .collect();
        Ok(ClaimOperands {
            source: self.source,
            backing: self.backing,
            backing_path,
            fee_funding,
            fee: self.fee,
            fee_total: self.selection.total,
        })
    }
}

/// One output's curve-tree membership path — public tree data only,
/// assembled by the Engine-side orchestrator against one reference snapshot
/// and consumed for both the backing and the fee legs.
///
/// Deliberately **not** a [`FundingInputContext`]: that type carries its own
/// record copy, and a second record here could silently disagree with the
/// sealed witness's private records (the single source of truth for which
/// outputs participate). Carrying the path alone keeps one record, one
/// owner; [`SweptFeeInputs::with_paths`] pairs paths to records by the
/// mint's own order.
pub(crate) struct MembershipPath {
    /// All outputs in the same Selene leaf chunk as this output.
    pub leaf_chunk: Vec<LeafEntry>,
    /// Selene (C1) branch layers, bottom-to-top.
    pub c1_layers: Vec<Vec<[u8; 32]>>,
    /// Helios (C2) branch layers, bottom-to-top.
    pub c2_layers: Vec<Vec<[u8; 32]>>,
}

/// The complete, sealed operand set of one emission-claim assembly — the
/// [`SweptFeeInputs`] triple with the membership paths zipped in
/// ([`SweptFeeInputs::with_paths`], the sole constructor). The
/// `AssembleEmissionClaim` message takes this whole; the handler
/// destructures it via [`Self::into_parts`] and re-checks **nothing** —
/// same-tip and Q11 consistency are properties of the type, not runtime
/// comparisons (module docs).
pub(crate) struct ClaimOperands {
    source: EmissionClaimSource,
    backing: DesignatedBacking,
    backing_path: MembershipPath,
    fee_funding: Vec<FundingInputContext>,
    fee: AtomicUnits,
    fee_total: AtomicUnits,
}

impl ClaimOperands {
    /// Destructure for handler consumption (the seal's job ends at the
    /// message boundary; the handler owns the parts).
    pub(crate) fn into_parts(self) -> ClaimOperandParts {
        ClaimOperandParts {
            source: self.source,
            backing: self.backing,
            backing_path: self.backing_path,
            fee_funding: self.fee_funding,
            fee: self.fee,
            fee_total: self.fee_total,
        }
    }
}

/// The destructured [`ClaimOperands`] — produced only by
/// [`ClaimOperands::into_parts`], inside the handler.
pub(crate) struct ClaimOperandParts {
    /// The decoded claim source (daemon gather + local dedup).
    pub source: EmissionClaimSource,
    /// The designated backing (owns the backing record).
    pub backing: DesignatedBacking,
    /// The backing output's membership path.
    pub backing_path: MembershipPath,
    /// The fee funding inputs with their membership paths, in sweep order.
    /// Non-empty, backing-free, and anchored with the backing — by the mint.
    pub fee_funding: Vec<FundingInputContext>,
    /// The fee the sweep was run against.
    pub fee: AtomicUnits,
    /// The swept fee inputs' exact sum (`>= fee`, by the sweep's shortfall
    /// refusal — the handler's change math needs no re-summation).
    pub fee_total: AtomicUnits,
}

/// Why [`DesignatedBacking::fee_sweep`] (or [`SweptFeeInputs::with_paths`])
/// refused to mint. Every arm is caller-recoverable — nothing was assembled,
/// signed, or reserved.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClaimFundingError {
    /// The designation's stored spendability anchor does not equal the claim
    /// source's gather **tip** (`chain_height − 1`; the anchor is a height,
    /// never the block count) — item 6, checked once at the mint. Assembling
    /// against a stale anchor would let backing eligibility and claim-window
    /// finalization diverge across two tips; the caller refetches the claim
    /// source and re-designates the backing at one tip, then retries.
    #[error(
        "stale claim anchor: the backing was designated at height {anchor} but the \
         claim source was gathered at tip {tip}; refetch both at one tip and retry"
    )]
    StaleClaimAnchor { anchor: u64, tip: u64 },

    /// The fee sweep selected **zero** fee-funding inputs. At least one
    /// spendable `ToKey` input is structurally required regardless of the
    /// fee amount — the loud reward vout consumes the entire mint, so the
    /// fee side must supply the tx's pseudoOuts and its FCMP++ fee-side
    /// proof anchor. Deliberately **not** `InsufficientFunding` (rule 82):
    /// with `fee == 0` that would read "insufficient funding: available 0,
    /// required 0" — a shortfall error with no shortfall, misdirecting the
    /// remedy. The remedy is to have ANY spendable funding output: fund the
    /// persona or wait for one to mature, then retry.
    #[error(
        "emission claim needs at least one fee input regardless of the fee amount ({fee}): \
         the reward vout consumes the whole mint, so pseudoOuts and the FCMP++ fee-side \
         anchor must come from a separate spendable output — fund the persona or wait \
         for maturity"
    )]
    ClaimFeeInputsRequired { fee: u64 },

    /// The assembled membership paths did not pair one path per witness
    /// record — an internal plumbing defect surfaced loudly rather than
    /// mis-indexed.
    #[error("membership paths diverged from the witness records: expected {expected}, got {got}")]
    PathCount { expected: usize, got: usize },

    /// The underlying sweep refused (a genuine shortfall, or arithmetic
    /// overflow — see the wrapped [`BondAssemblyError`]).
    #[error(transparent)]
    Assembly(#[from] BondAssemblyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::bond_assembly::{sweep_funding_outputs, SpentRecordsDurablyPruned};
    use crate::engine::emission_claim::test_fixtures::source_at_count;
    use crate::engine::test_support::funding_record;
    use shekyl_types::BlockHeight;

    /// A claim source gathered at the tip a designation was anchored at —
    /// the coherent pairing [`DesignatedBacking::fee_sweep`] mints from.
    fn source_at_tip(tip: u64) -> EmissionClaimSource {
        source_at_count(tip + 1, vec![], vec![])
    }

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

        let set = BackingSet::from_spendable(
            &records,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        );
        let gindexes: Vec<u64> = set.records().iter().map(|r| r.gindex.to_raw()).collect();
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
        let _ = BackingSet::from_spendable(
            &records,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        );
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

        let set = BackingSet::from_spendable(
            &records,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        );
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
            shekyl_types::PSlot::from_raw(0),
            &Default::default(),
            shekyl_units::AtomicUnits::from_raw(required),
            reference_height,
        )
        .expect("sweep succeeds");

        // (1) The sweep is the full spendable eligible set.
        let swept: std::collections::BTreeSet<u64> = selection
            .records
            .iter()
            .map(|r| r.gindex.to_raw())
            .collect();
        assert_eq!(
            swept,
            [10, 11, 12, 13].into_iter().collect(),
            "sweep consumed everything, including the record a greedy subset leaves behind"
        );
        assert_eq!(selection.total, shekyl_units::AtomicUnits::from_raw(1_800));

        // (2) Post-confirmation spendable remainder is empty. Durable
        // pruning is SP-R0-gated, so model spent-removal as records minus
        // swept gindexes.
        let remainder: Vec<&PFundingOutputRecord> = pre_sweep
            .iter()
            .filter(|r| {
                !swept.contains(&r.gindex.to_raw()) && r.spendable_height <= reference_height
            })
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
        let set = BackingSet::from_spendable(
            &post_bond,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        );
        let eligible: Vec<u64> = set.records().iter().map(|r| r.gindex.to_raw()).collect();
        assert_eq!(
            eligible,
            vec![20],
            "the bond-post change record is backing-eligible; the raw tranche is not"
        );
    }

    /// The slot filter: the set is the **claimant persona's** — a foreign
    /// slot's newer, otherwise-eligible record (the rotation-overlap window:
    /// the new persona's bond-post change is the newest rung-2 on chain)
    /// must neither enter the set nor win the most-recent-eligible
    /// comparator. Without the filter, the claimant's key re-derivation
    /// would fail the pre-flight leaf gate on every claim attempt for as
    /// long as the foreign record stays newest — a persona deterministically
    /// unable to claim.
    #[test]
    fn foreign_slot_records_never_enter_the_set() {
        let reference_height = BlockHeight::from_raw(1_000_000);
        let last_sweep_height = BlockHeight::from_raw(100);
        let records = vec![
            // The claimant's own (older) backing-eligible record.
            funding_record(0, 1, 90, 500, MintLineageOutput::BondPostChange),
            // A foreign slot's NEWER eligible record — the overlap window.
            funding_record(1, 2, 300, 700, MintLineageOutput::BondPostChange),
        ];

        let set = BackingSet::from_spendable(
            &records,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        );
        let gindexes: Vec<u64> = set.records().iter().map(|r| r.gindex.to_raw()).collect();
        assert_eq!(gindexes, vec![1], "only the claimant slot's records enter");

        let designated = BackingSet::from_spendable(
            &records,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        )
        .designate_backing()
        .expect("the claimant's record designates");
        assert_eq!(
            designated.record().gindex.to_raw(),
            1,
            "the foreign slot's newer record must not win the comparator"
        );

        // A foreign slot's rung-3 survivor must not trip the claimant's
        // tripwire either (the survivor semantics are per-persona).
        let with_foreign_survivor = vec![
            funding_record(0, 1, 90, 500, MintLineageOutput::BondPostChange),
            funding_record(1, 3, 50, 900, MintLineageOutput::ExternalTransfer),
        ];
        let set = BackingSet::from_spendable(
            &with_foreign_survivor,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        );
        assert_eq!(set.records().len(), 1, "no trip, foreign survivor filtered");
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

        let designated = BackingSet::from_spendable(
            &records,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        )
        .designate_backing()
        .expect("eligible records exist");
        assert_eq!(
            designated.record().gindex.to_raw(),
            3,
            "highest (height, gindex) is designated"
        );
        assert_eq!(
            designated.reference_height, reference_height,
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
        match BackingSet::from_spendable(
            &records,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        )
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

        let designated = BackingSet::from_spendable(
            &post_first_bond,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        )
        .designate_backing()
        .expect("the change record is eligible");
        assert_eq!(
            designated.record().gindex.to_raw(),
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
        let reserved: std::collections::BTreeSet<GlobalOutputIndex> =
            [GlobalOutputIndex::from_raw(1)].into_iter().collect();

        // Premise: without the exclusion, the sweep selects the backing.
        let plain = sweep_funding_outputs(
            &SpentRecordsDurablyPruned::for_test(),
            &records,
            PSlot::from_raw(0),
            &reserved,
            AtomicUnits::ZERO,
            reference_height,
        )
        .expect("plain sweep succeeds");
        assert!(
            plain.records.iter().any(|r| r.gindex.to_raw() == 2),
            "premise: the backing is sweep-eligible, so the exclusion below is load-bearing"
        );

        let designated = BackingSet::from_spendable(
            &records,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        )
        .designate_backing()
        .expect("eligible records exist");
        assert_eq!(
            designated.record().gindex.to_raw(),
            2,
            "premise: gindex 2 is the backing"
        );

        let swept = designated
            .fee_sweep(
                source_at_tip(reference_height.to_raw()),
                &SpentRecordsDurablyPruned::for_test(),
                &records,
                PSlot::from_raw(0),
                &reserved,
                AtomicUnits::ZERO,
            )
            .expect("fee sweep succeeds");
        let fee_gindexes: Vec<u64> = swept
            .fee_records()
            .iter()
            .map(|r| r.gindex.to_raw())
            .collect();
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
        // The seal's path-request order: the backing first, then the fees.
        let path_order: Vec<u64> = swept.path_records().map(|r| r.gindex.to_raw()).collect();
        assert_eq!(path_order, vec![2, 3]);
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

        let designated = BackingSet::from_spendable(
            &records,
            PSlot::from_raw(0),
            reference_height,
            last_sweep_height,
        )
        .designate_backing()
        .expect("eligible record exists");
        let swept = designated
            .fee_sweep(
                source_at_tip(reference_height.to_raw()),
                &SpentRecordsDurablyPruned::for_test(),
                &records,
                PSlot::from_raw(0),
                &Default::default(),
                AtomicUnits::ZERO,
            )
            .expect("fee sweep succeeds");
        let fee_gindexes: Vec<u64> = swept
            .fee_records()
            .iter()
            .map(|r| r.gindex.to_raw())
            .collect();
        assert_eq!(
            fee_gindexes,
            vec![2],
            "the immature record is excluded by the inherited anchor; the backing by Q11"
        );
    }

    /// Item 6 at the mint: a designation anchored at a height other than the
    /// claim source's gather **tip** (`chain_height − 1` — a height, never
    /// the block count) refuses as [`ClaimFundingError::StaleClaimAnchor`]
    /// carrying both operands, before any sweep work — the caller refetches
    /// both at one tip and retries. The count itself is the classic
    /// off-by-one and must also refuse. (Formerly the handler's step-2
    /// runtime check; the seal moved it here, once.)
    #[test]
    fn fee_sweep_refuses_a_stale_anchor() {
        let tip = 1_000_000u64;
        let last_sweep_height = BlockHeight::from_raw(100);
        let records = vec![record(1, 90, 500, MintLineageOutput::BondPostChange)];
        let designate_at = |anchor: u64| {
            BackingSet::from_spendable(
                &records,
                PSlot::from_raw(0),
                BlockHeight::from_raw(anchor),
                last_sweep_height,
            )
            .designate_backing()
            .expect("one eligible record designates")
        };

        // Anchored two past the tip.
        let err = designate_at(tip + 2)
            .fee_sweep(
                source_at_tip(tip),
                &SpentRecordsDurablyPruned::for_test(),
                &records,
                PSlot::from_raw(0),
                &Default::default(),
                AtomicUnits::ZERO,
            )
            .err()
            .expect("a stale anchor must refuse");
        assert!(
            matches!(
                err,
                ClaimFundingError::StaleClaimAnchor { anchor, tip: t }
                    if anchor == tip + 2 && t == tip
            ),
            "expected StaleClaimAnchor with both operands, got {err:?}"
        );

        // The block COUNT as the anchor (the unit mismatch this check pins):
        // one past the tip, must refuse — a count-anchored designation
        // admits records one block early.
        let err = designate_at(tip + 1)
            .fee_sweep(
                source_at_tip(tip),
                &SpentRecordsDurablyPruned::for_test(),
                &records,
                PSlot::from_raw(0),
                &Default::default(),
                AtomicUnits::ZERO,
            )
            .err()
            .expect("the count-as-height anchor must refuse");
        assert!(
            matches!(err, ClaimFundingError::StaleClaimAnchor { .. }),
            "expected StaleClaimAnchor, got {err:?}"
        );
    }

    /// Fee inputs are structurally mandatory (the reward is fully consumed
    /// by the loud vout, so a zero-input claim has no pseudoOuts to fund a
    /// fee): a sweep that selects nothing refuses with the **structural**
    /// [`ClaimFundingError::ClaimFeeInputsRequired`] — never a shortfall
    /// (with `fee == 0` that would read `InsufficientFunding { 0, 0 }`, a
    /// self-contradiction misdirecting the remedy) — and a present-but-short
    /// selection refuses with the actual shortfall. (Formerly the handler's
    /// step-5 checks; the seal moved them to the mint.)
    #[test]
    fn fee_sweep_requires_a_fee_input_structurally() {
        let tip = 1_000_000u64;
        let last_sweep_height = BlockHeight::from_raw(100);
        // The backing is the persona's ONLY record: the Q11 exclusion leaves
        // the fee sweep nothing to select.
        let records = vec![record(1, 90, 500, MintLineageOutput::BondPostChange)];
        let designate = || {
            BackingSet::from_spendable(
                &records,
                PSlot::from_raw(0),
                BlockHeight::from_raw(tip),
                last_sweep_height,
            )
            .designate_backing()
            .expect("one eligible record designates")
        };

        // Arm 1: nothing selectable — structural refusal, at fee 1 000 AND
        // at fee 0 (the 0/0 shortfall trap the variant exists to avoid).
        for fee in [1_000u64, 0] {
            let err = designate()
                .fee_sweep(
                    source_at_tip(tip),
                    &SpentRecordsDurablyPruned::for_test(),
                    &records,
                    PSlot::from_raw(0),
                    &Default::default(),
                    AtomicUnits::from_raw(fee),
                )
                .err()
                .expect("an empty fee selection must refuse");
            assert!(
                matches!(
                    err,
                    ClaimFundingError::ClaimFeeInputsRequired { fee: f } if f == fee
                ),
                "expected ClaimFeeInputsRequired at fee {fee}, got {err:?}"
            );
        }

        // Arm 2: a fee input exists but falls short of the fee — a genuine
        // shortfall, so `InsufficientFunding` is the right taxonomy.
        let with_short = vec![
            record(1, 90, 500, MintLineageOutput::BondPostChange),
            record(2, 150, 400, MintLineageOutput::ExternalTransfer),
        ];
        let err = BackingSet::from_spendable(
            &with_short,
            PSlot::from_raw(0),
            BlockHeight::from_raw(tip),
            last_sweep_height,
        )
        .designate_backing()
        .expect("eligible record exists")
        .fee_sweep(
            source_at_tip(tip),
            &SpentRecordsDurablyPruned::for_test(),
            &with_short,
            PSlot::from_raw(0),
            &Default::default(),
            AtomicUnits::from_raw(1_000),
        )
        .err()
        .expect("short fee funding must refuse");
        assert!(
            matches!(
                err,
                ClaimFundingError::Assembly(BondAssemblyError::InsufficientFunding {
                    available: 400,
                    required: 1_000,
                })
            ),
            "expected InsufficientFunding(400/1000), got {err:?}"
        );

        // Arm 3: an eligible fee record EXISTS but carries amount 0 (a
        // representable CT state). This is a shortfall — the persona is
        // funded-but-valueless, and the remedy is accrual — NOT the
        // structural no-fee-input refusal, whose "fund the persona" text
        // would misdirect. Pins the taxonomy the sweep's typed
        // empty-eligible-set arm exists to keep separate.
        let with_zero = vec![
            record(1, 90, 500, MintLineageOutput::BondPostChange),
            record(2, 150, 0, MintLineageOutput::ExternalTransfer),
        ];
        let err = BackingSet::from_spendable(
            &with_zero,
            PSlot::from_raw(0),
            BlockHeight::from_raw(tip),
            last_sweep_height,
        )
        .designate_backing()
        .expect("eligible record exists")
        .fee_sweep(
            source_at_tip(tip),
            &SpentRecordsDurablyPruned::for_test(),
            &with_zero,
            PSlot::from_raw(0),
            &Default::default(),
            AtomicUnits::from_raw(1_000),
        )
        .err()
        .expect("zero-value fee funding must refuse as a shortfall");
        assert!(
            matches!(
                err,
                ClaimFundingError::Assembly(BondAssemblyError::InsufficientFunding {
                    available: 0,
                    required: 1_000,
                })
            ),
            "a present-but-zero-value selection is a shortfall, got {err:?}"
        );
    }

    /// [`SweptFeeInputs::with_paths`] pairs one path per witness record —
    /// backing first, fees in sweep order — and refuses a count mismatch
    /// loudly rather than mis-pairing.
    #[test]
    fn with_paths_pairs_by_the_mints_order_and_refuses_a_count_mismatch() {
        let tip = 1_000_000u64;
        let last_sweep_height = BlockHeight::from_raw(100);
        let records = vec![
            record(1, 90, 500, MintLineageOutput::BondPostChange), // → designated
            record(2, 150, 400, MintLineageOutput::ExternalTransfer),
            record(3, 160, 300, MintLineageOutput::ExternalTransfer),
        ];
        let sweep = || {
            BackingSet::from_spendable(
                &records,
                PSlot::from_raw(0),
                BlockHeight::from_raw(tip),
                last_sweep_height,
            )
            .designate_backing()
            .expect("eligible record exists")
            .fee_sweep(
                source_at_tip(tip),
                &SpentRecordsDurablyPruned::for_test(),
                &records,
                PSlot::from_raw(0),
                &Default::default(),
                AtomicUnits::ZERO,
            )
            .expect("fee sweep succeeds")
        };
        let path = |marker: u8| MembershipPath {
            leaf_chunk: vec![],
            c1_layers: vec![vec![[marker; 32]]],
            c2_layers: vec![],
        };

        // Count mismatch (backing + 2 fees = 3 expected) refuses loudly.
        let err = sweep()
            .with_paths(vec![path(0), path(1)])
            .err()
            .expect("a path-count mismatch must refuse");
        assert!(
            matches!(
                err,
                ClaimFundingError::PathCount {
                    expected: 3,
                    got: 2
                }
            ),
            "expected PathCount, got {err:?}"
        );

        // Correct count: paths pair by the mint's order — the backing takes
        // path 0; the fee records (sweep order: gindex 2 then 3) take paths
        // 1 and 2.
        let parts = sweep()
            .with_paths(vec![path(0), path(1), path(2)])
            .expect("matched paths zip")
            .into_parts();
        assert_eq!(parts.backing.record().gindex.to_raw(), 1);
        assert_eq!(parts.backing_path.c1_layers, vec![vec![[0u8; 32]]]);
        let paired: Vec<(u64, u8)> = parts
            .fee_funding
            .iter()
            .map(|f| (f.record.gindex.to_raw(), f.c1_layers[0][0][0]))
            .collect();
        assert_eq!(
            paired,
            vec![(2, 1), (3, 2)],
            "fee paths pair to fee records in sweep order"
        );
        assert_eq!(parts.fee_total, AtomicUnits::from_raw(700));
    }
}
