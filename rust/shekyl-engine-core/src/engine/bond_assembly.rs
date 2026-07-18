// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! WI-2 — production bond assembly (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.2–§3.3).
//!
//! This module is the **P-1 provenance boundary** (SP-T4 §3.1.1 pin P-1):
//! [`PBoundBytes`] lives here and its constructor is private to the module, so
//! possession of a `PBoundBytes` is proof the bytes came out of this module's
//! assemble/finalize path (or its [`PBoundBytes::from_pending`] re-lift of a
//! record this path previously sealed). No re-wrap site exists anywhere else.
//!
//! The module carries the Engine-side **public** halves of WI-2:
//!
//! - **D-A2 funding sweep** ([`sweep_funding_outputs`]): deterministic
//!   oldest-first consumption of the assembling persona's **entire**
//!   unreserved spendable slice of the sealed [`PFundingOutputRecord`] set
//!   (GF-4b sweep semantics, `ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.1 —
//!   subset selection ceased to exist with the rename).
//! - The **error surface** ([`BondAssemblyError`]) for the assemble path's
//!   named failure modes (§3.6, rule 82).
//!
//! The actor-side halves (P spend-bundle derivation, prefix assembly, vin
//! build + invariant A-1, proving, PQC auth completion, the `PBoundBytes`
//! mint) build on these types; secrets never appear in this module's Engine
//! surface (rule 36).

use shekyl_archival_retention::bond_wire::{
    ArchivalBondPostVin, BondPostKind as RetentionBondPostKind,
};
use shekyl_archival_retention::{HoldingsDescriptor, HoldingsKind};
use shekyl_engine_state::pending_post_block::PendingBondPost;
use shekyl_engine_state::pscan_state::PFundingOutputRecord;
use shekyl_tx_builder::{encode_final_tx, LeafEntry, WireEncodeInput};
use shekyl_types::{BlockHeight, GlobalOutputIndex, PCanonicalId, PSlot};
use shekyl_units::AtomicUnits;
use shekyl_wire::{BondPost, BondPostKind as WireBondPostKind, Holdings, Input};

// ---------------------------------------------------------------------------
// PBoundBytes — the byte↔persona pairing, minted only here (pin P-1)
// ---------------------------------------------------------------------------

/// `P`-bound transaction bytes — the byte↔persona pairing carried as a value
/// (`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md` §3.1 part 4).
///
/// [`BroadcastSubmitter::submit_bound`] accepts only this type and
/// equality-checks the carried persona against the submitter's
/// constructor-bound persona, so `P1`'s bytes cannot ride `P2`'s circuit.
/// Full per-persona type *branding* is rejected (the persona set is dynamic;
/// rule-21 reopen in §3.1 part 4) — the pairing is a checked value, not a
/// type parameter.
///
/// **Provenance pins (§3.1.1 part 6), discharged here:**
///
/// - **P-1 — single mint site.** The constructor ([`Self::bind`]) is private
///   to this module: production bytes are minted exactly once, by the
///   assemble/finalize path, from the transaction it just encoded. The only
///   other production path is [`Self::from_pending`], which re-lifts a
///   [`PendingBondPost`] this module previously sealed — trusting our own
///   prior seal, exactly as `PScanAccrual::from_state` trusts the sealed
///   frontier. Tests use [`Self::bind_for_test`].
/// - **P-2 — retries re-send the stored value.** The pending record persists
///   the pairing's fields (`persona`, `tx_bytes`); F31/watchdog resubmits
///   re-lift and re-send the *stored* bytes through the same
///   `submit_bound` choke path, never a re-encode.
///
/// [`BroadcastSubmitter::submit_bound`]: super::transaction_submitter::BroadcastSubmitter::submit_bound
//
// `allow(dead_code)`: transient — the production minter is the WI-2 assemble
// handler; the production consumer is the WI-3 dispatch driver.
#[allow(dead_code)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PBoundBytes {
    persona: PCanonicalId,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for PBoundBytes {
    /// **Redacted on purpose** — the pairing *is* the persona↔transaction
    /// link; rendering it through a log / error / `{:?}` path is the
    /// off-chain correlation the firewall exists to prevent. (The persona id
    /// alone already truncates its own `Debug`; the pairing redacts wholesale.)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PBoundBytes(<redacted persona-bound tx>)")
    }
}

#[allow(dead_code)]
impl PBoundBytes {
    /// Bind fully-assembled, signed transaction bytes to the persona they
    /// were built for. **Private to this module** (pin P-1): the only mint
    /// site is the assemble/finalize path.
    fn bind(persona: PCanonicalId, bytes: Vec<u8>) -> Self {
        Self { persona, bytes }
    }

    /// Re-lift a sealed [`PendingBondPost`] into its transform-shaped twin
    /// (rule 18) for dispatch. The record's `(persona, tx_bytes)` pair was
    /// written by this module's assemble path (persist-before-dispatch), so
    /// the re-lift trusts the seal — pin P-2's "retries re-send the stored
    /// value" is this function feeding `submit_bound`.
    pub(crate) fn from_pending(post: &PendingBondPost) -> Self {
        Self::bind(post.persona, post.tx_bytes.clone())
    }

    /// The persona these bytes are bound to.
    pub(crate) fn persona(&self) -> &PCanonicalId {
        &self.persona
    }

    /// The wire-encoded transaction bytes (read-only; dispatch consumes via
    /// [`Self::into_bytes`]).
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the pairing, yielding the bytes for a transport that has
    /// already passed the persona check (`submit_bound`'s post-check hand-off).
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Test-only constructor for exercising `submit_bound`'s pairing check
    /// without running the full assemble path. Never a production mint site.
    #[cfg(test)]
    pub(crate) fn bind_for_test(persona: PCanonicalId, bytes: Vec<u8>) -> Self {
        Self::bind(persona, bytes)
    }
}

// ---------------------------------------------------------------------------
// Errors (§3.6, rule 82)
// ---------------------------------------------------------------------------

/// Failure surface of the bond-assembly path (`ARCHIVAL_BOND_WI2_ASSEMBLY.md`
/// §3.6). Every arm names its operator-facing disposition: refusals are
/// caller-recoverable states, defects are fail-closed build errors.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BondAssemblyError {
    /// The persona's spendable funding set (unreserved, scan-discovered
    /// outputs) sums below the bond floor + fee. Fund-from-earnings ramp
    /// (`ARCHIVAL_TIMING_CONSTANTS.md` §7): the caller waits for more
    /// earnings; there is **no** reach-across to principal outputs (that
    /// reach-across is the funding-seam linkage the architecture firewalls).
    #[error(
        "insufficient P-side funding: {available} available < {required} required; \
         the persona funds bonds from its own earnings — wait for further accrual"
    )]
    InsufficientFunding {
        /// Sum of the unreserved spendable records.
        available: u64,
        /// `bond_floor(holdings) + fee`.
        required: u64,
    },

    /// The persona's eligible funding set is **empty** at the sweep's
    /// reference height: nothing discovered, or everything is immature or
    /// reserved by in-flight posts. Structurally distinct from
    /// [`Self::InsufficientFunding`] (records exist but sum short —
    /// including all-zero-amount records, a representable CT state): the
    /// remedies differ, and the claim path maps only *this* arm to its
    /// structural no-fee-input refusal.
    #[error(
        "no spendable P-side funding outputs at the reference height: none discovered, \
         or all are immature or reserved by in-flight posts; fund the persona or wait \
         for maturity/confirmation"
    )]
    NoSpendableFunding,

    /// A live pending post already exists for this persona. JoinMarket-only
    /// at genesis: one live post per persona (§3.5); the caller waits for the
    /// pending post to confirm or fail before re-assembling.
    #[error("a pending bond post already exists for this persona; one live post per persona")]
    PendingPostExists,

    /// The curve-tree / ledger anchoring procedure could not produce a
    /// submittable [`ReferenceBlock`](shekyl_curve_tree::ReferenceBlock)
    /// (tree too far behind, ingest missing, ledger hash missing, chain too
    /// short). Loud resync — never a silent path fail (WI-2 F-6).
    #[error("bond reference unavailable: {detail}; resync")]
    ReferenceResyncing {
        /// Operator-facing detail naming which arm of the anchoring gate fired.
        detail: &'static str,
    },

    /// A swept record cleared the spendability filter but has no drained
    /// leaf in the REFERENCE tree yet (the reference lags tip by
    /// `REF_ANCHOR_AGE`, so a freshly-matured output can be spendable at
    /// tip and absent at the reference) — the one path-assembly refusal
    /// that is wait-and-retry, not a defect. Typed so retry policy (the
    /// regtest harness today, production retry logic later) matches on the
    /// variant instead of substring-scanning a rendered
    /// `ClientError::OutputNotDrained`.
    #[error(
        "funding output (gindex {gindex}) is not yet drained into the reference tree; \
         wait for the tree to catch up and retry"
    )]
    OutputNotYetDrained {
        /// The global output index the reference tree has no leaf for.
        gindex: u64,
    },

    /// Invariant A-1 (§3.3 step 4, fail closed): the signed vin's
    /// wire-encoded `BondPost` fields differ from the prefix's `BondPost`
    /// input. The signature binds a different post than the prefix hash
    /// covered — a build defect, never a recoverable state.
    #[error(
        "bond-post input mismatch: the signed vin does not match the prefix's BondPost \
         input (invariant A-1) — build defect, nothing was persisted"
    )]
    BondPostMismatch,

    /// The funding arithmetic (`floor + fee`, change split, balance rule)
    /// overflowed u64 — unreachable with consensus-bounded amounts; fail
    /// closed rather than wrap.
    #[error("funding amount arithmetic overflowed")]
    AmountOverflow,

    /// `bond_floor(holdings)` is zero — structurally invalid holdings (empty
    /// / zero-count descriptor). Same refusal the wire builder and retention
    /// verifier raise (`BondBuildError::BondFloorZero`); refuse before sweep
    /// so a zero-`required` never reaches `assemble_tx` as an empty path set.
    #[error("bond_floor(holdings) is zero; holdings are structurally invalid")]
    BondFloorZero,

    /// A cryptographic step of the assemble pipeline failed (spend-bundle
    /// derivation, output construction, proving, PQC auth signing, or wire
    /// encoding). `stage` names the pipeline step; `detail` is the wrapped
    /// error's rendering (public error text — never key material). Nothing
    /// was persisted (§3.6: no partial state, funding never reserved).
    #[error("bond assembly failed at {stage}: {detail}")]
    Build {
        /// Pipeline step that failed.
        stage: &'static str,
        /// Rendered cause.
        detail: String,
    },
}

impl BondAssemblyError {
    /// Shorthand for the pipeline-step failure arm.
    pub(crate) fn build(stage: &'static str, err: impl std::fmt::Display) -> Self {
        Self::Build {
            stage,
            detail: err.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// D-A2 — funding sweep (WI-2 §3.2 as amended by GF-4b §3.1)
// ---------------------------------------------------------------------------

/// Witness that durable removal of confirmed-spent funding records has
/// landed (`ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.2, GF4b-5 structural gate).
///
/// [`sweep_funding_outputs`] cannot be called without one. Load-bearing under
/// sweep semantics: **any single** stale spent record is in *every* subsequent
/// sweep, so one confirmed post would poison every later bond post for that
/// persona (daemon-rejected duplicate key image) unless pruning is live.
///
/// **The precondition holds — SP-R0 arm #1 landed the pruning** (disposition
/// D-1(a), `ARCHIVAL_BOND_SP_R0_PLAN.md` §2/§4): the arm-(c) spent-key-image
/// watch in `run_dual_extractor` and the prune-at-ingest in
/// `PScanAccrual::ingest` are **unconditional** in every production scan
/// step, and pre-genesis every wallet fresh-syncs from block 0 with the watch
/// on (D-2's airtight no-bump form) — so "the funding store durably prunes
/// spent records" holds for every wallet state that can exist.
/// [`arm1_watch_pruning_live`](Self::arm1_watch_pruning_live) is the **sole
/// production constructor**, and the witness **stays** (per the executed
/// rule-21 clause): any future build that removes or conditions the
/// watch/prune must first confront this type and its tripwire.
///
/// **Two named bounds on the attestation** (neither opens the poison):
///
/// - **Retired-persona window — deferred to arm #2.** A record whose owning
///   slot is not resident-**bonded** is unwatchable by construction (the keys
///   are wiped), so a spend scanned during a retired window is not observed
///   and sealed ranges never re-scan. Arm #2's retire-time atomic prune
///   (`docs/FOLLOWUPS.md`, SP-R0 arm #2) closes this by removing the
///   records *with* the persona. Until it lands, the sweep never reaches
///   such a record while retired (the sweep is scoped to the assembling —
///   resident-bonded — persona), and a re-bond of the same persona before
///   arm #2 is the tracked residual, not a silent one.
/// - **Quarantined records.** A record whose watch key-image derivation
///   fails deterministically is skipped from the watch (loudly), never
///   step-fatal. Sound because assemble re-derives the same bundle
///   (`derive_spend_parts`) and fails identically — a record the watch
///   cannot derive can never be swept into a bond post.
///
/// Reversion clause (rule 21, executed 2026-07-18 as disposition (a)): if the
/// watch or the prune is ever made conditional (feature-gated, posture-gated,
/// or skippable), the attestation below is void — the constructor must grow a
/// real precondition and this doc must be rewritten, not deleted.
pub(crate) struct SpentRecordsDurablyPruned {
    _sealed: (),
}

impl SpentRecordsDurablyPruned {
    /// The **sole production constructor** — minted by SP-R0 arm #1 (see the
    /// type docs for the soundness argument: unconditional watch + prune +
    /// pre-genesis fresh-sync). Callers are the production assemble/dispatch
    /// paths (bond orchestrator, claim orchestrator, claim-dispatch seam) via
    /// the activation round's entry.
    pub(crate) fn arm1_watch_pruning_live() -> Self {
        Self { _sealed: () }
    }

    /// Test-only mint — the only other constructor (KATs exercise the sweep
    /// through it without touring the scan path).
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self { _sealed: () }
    }
}

/// The outcome of the D-A2 sweep: the consumed funding records (oldest-first
/// order preserved) and their exact sum.
///
/// **Invariant — `records` is non-empty.** [`sweep_funding_outputs`] is the
/// sole constructor and refuses a sweep that consumes nothing, so possession
/// of a `FundingSelection` is proof of ≥1 funding record. Callers rely on this
/// (the orchestrator indexes `paths[0]` after a length-equality check against
/// `records`); do not add a constructor that can bypass the refusal.
///
/// Redacted `Debug` via the contained records' own redaction; the struct adds
/// nothing renderable beyond the total, so it derives nothing.
pub(crate) struct FundingSelection {
    /// The swept records, in deterministic (oldest-first) order.
    pub records: Vec<PFundingOutputRecord>,
    /// Exact sum of the swept records' amounts.
    pub total: AtomicUnits,
}

/// D-A2 funding **sweep** (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.2 as amended by
/// `ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.1), Engine-side over public data
/// only. Consumes the assembling persona's **entire** unreserved spendable
/// eligible set — there is no way to express a subset:
///
/// 1. **Eligibility.** The sweep is scoped to `p_slot` — the assembling
///    persona's outputs only. This is load-bearing, not a filter of
///    convenience: the `AssembleBond` handler re-derives every input's spend
///    secrets with **one** persona's keys ([`derive_p_source_secrets_bundle`]
///    keyed on the handle's slot), so a record belonging to a *different*
///    bonded persona would derive a wrong key image and the daemon would reject
///    the post. The sealed set mixes every bonded persona's records
///    (`bonded_scan_inputs` slot-tags each), so the slot filter is what keeps
///    the sweep self-consistent with the single-persona derivation.
///    Every persisted record is already final (the pscan ingest horizon is
///    `tip − ARCHIVAL_REORG_DEPTH_BLOCKS`). Records whose `gindex` appears in
///    `reserved` — the union of live pending posts' reservation sets — are
///    excluded; the pending record is the single source of reservation truth.
///    Records whose `spendable_height` exceeds `reference_height` are
///    excluded (GF4b-6, §3.6): "consume everything" means everything
///    *spendable* — an immature record's leaf is absent from the curve tree,
///    so no membership proof exists and consuming it would deny bonding
///    until maturity, whether it arrived by ordinary fresh funding
///    (+`SPENDABLE_AGE`) or an adversarial coinbase-to-`P` (+60). Immature
///    records survive the sweep **by design** and join the next one.
///
/// [`derive_p_source_secrets_bundle`]: super::stake_engine::derive_p_source_secrets_bundle
/// 2. **Ramp.** If the swept total is below `required`, refuse with
///    [`BondAssemblyError::InsufficientFunding`].
/// 3. **Extent + order.** *All* eligible records, oldest-first
///    `(height, gindex)` — D-A2's determinism/auditability rationale survives
///    as the ordering of the swept input list. The early break at
///    `sum ≥ required` is gone: a subset selector leaves rung-3 funding
///    outputs alive in `P`'s spendable set, and GF-4b's structural-emptiness
///    claim ("nothing raw survives backing-eligible") rests on the bond
///    post consuming everything (§3.1's recorded argument; priority-2 binds
///    over assembly convenience). The change-split math absorbs the larger
///    remainder unchanged (`funding == change + fee + credit`).
///
/// `required` is `bond_floor(holdings) + fee`, computed by the caller with
/// checked arithmetic. `reference_height` is the sweep's spendability
/// anchor: the chain height the assemble path builds against (a record is in
/// the tree iff `spendable_height <= reference_height`).
///
/// **Why the witness parameter (do not remove without the FOLLOWUP):**
/// `reserved` covers only *live pending posts*. A funding output spent by a
/// bond post that has since **confirmed** is un-reserved (its pending record
/// cleared) yet still present in `records` — nothing prunes
/// `funding_outputs` on spend today, and under sweep semantics such a record
/// is in **every** subsequent sweep, poisoning every later bond post for the
/// persona until durable removal lands. [`SpentRecordsDurablyPruned`] makes
/// that sequencing compile-enforced. See FOLLOWUPS "2d-1 WI-2 — durable
/// removal of SPENT funding outputs".
#[allow(dead_code)] // transient — consumed by the Engine-side WI-2 orchestrator as it lands.
pub(crate) fn sweep_funding_outputs<'a, I>(
    _pruning_landed: &SpentRecordsDurablyPruned,
    records: I,
    p_slot: PSlot,
    reserved: &std::collections::BTreeSet<GlobalOutputIndex>,
    required: AtomicUnits,
    reference_height: BlockHeight,
) -> Result<FundingSelection, BondAssemblyError>
where
    I: IntoIterator<Item = &'a PFundingOutputRecord>,
{
    let mut eligible: Vec<&PFundingOutputRecord> = records
        .into_iter()
        .filter(|r| {
            r.p_slot == p_slot
                && !reserved.contains(&r.gindex)
                && r.spendable_height <= reference_height
        })
        .collect();
    // Oldest-first: height, then gindex. Distinct outputs have distinct
    // gindexes, so the order is total and deterministic.
    eligible.sort_by_key(|r| (r.height, r.gindex));

    // An empty eligible set refuses structurally BEFORE any arithmetic —
    // never as a `0 < required` shortfall, which would conflate "nothing to
    // sweep" with "records exist but sum short" (the all-zero-amount case
    // makes the two genuinely different states with different remedies).
    // This is also what makes `FundingSelection` non-empty *by
    // construction*, so the downstream `assemble_tx` / `paths[0]` path can
    // never index an empty vec.
    if eligible.is_empty() {
        return Err(BondAssemblyError::NoSpendableFunding);
    }

    // Sweep: the entire eligible set, no early break — a subset is
    // inexpressible from here down. One pass sums and materializes the
    // records together, so the reported `total` cannot drift from the
    // `records` actually returned (the change-split invariant
    // `funding == change + fee + credit` relies on that agreement).
    let mut total = AtomicUnits::ZERO;
    let mut records = Vec::with_capacity(eligible.len());
    for record in eligible {
        total = total
            .checked_add(record.amount)
            .ok_or(BondAssemblyError::AmountOverflow)?;
        records.push(record.clone());
    }

    if total < required {
        return Err(BondAssemblyError::InsufficientFunding {
            available: total.to_raw(),
            required: required.to_raw(),
        });
    }

    Ok(FundingSelection { records, total })
}

// ---------------------------------------------------------------------------
// D-A3 — assembly-flow types and the PBoundBytes mint site (§3.3)
// ---------------------------------------------------------------------------

/// One selected funding input, ready for the actor's `AssembleBond` handler:
/// the public identity record (D-A1) plus its curve-tree membership path,
/// already mapped to the tx-builder's mirror types by the Engine-side
/// orchestrator (§3.3 Engine step 2). Carries **public data only** — the
/// spend bundle is re-derived from `record.{ciphertext, index}` inside the
/// actor (rule 36).
pub(crate) struct FundingInputContext {
    /// The persisted public-identity funding record.
    pub record: PFundingOutputRecord,
    /// All outputs in the same Selene leaf chunk as this input.
    pub leaf_chunk: Vec<LeafEntry>,
    /// Selene (C1) branch layers, bottom-to-top.
    pub c1_layers: Vec<Vec<[u8; 32]>>,
    /// Helios (C2) branch layers, bottom-to-top.
    pub c2_layers: Vec<Vec<[u8; 32]>>,
}

/// Map a [`HoldingsDescriptor`] (the retention-side typed holdings) onto the
/// canonical wire [`Holdings`] enum.
pub(crate) fn wire_holdings(holdings: &HoldingsDescriptor) -> Holdings {
    match holdings.kind {
        HoldingsKind::ShardSetCompact => Holdings::ShardSetCompact(holdings.shard_ids.to_vec()),
        HoldingsKind::CompleteTree => Holdings::CompleteTree,
    }
}

/// Map a built [`ArchivalBondPostVin`] onto the canonical wire
/// [`Input::BondPost`] prefix input (`GENESIS_TX_WIRE_FORMAT.md` §9.11).
///
/// The GF-1 debit-authorizer `bond_spend_pk` rides the vin itself
/// (JoinMarket-coupled per §9.11 — the GF-1 wire increment collapsed the old
/// caller-supplies-alongside seam), so this mapping just moves it across; the
/// vin's `write`/`read` coupling guarantees a JoinMarket vin carries a
/// canonical-length key.
///
/// Refuses a non-JoinMarket vin: JoinMarket is the only post kind valid at
/// genesis, and the `bond_spend_pk` coupling below is JoinMarket-specific.
pub(crate) fn wire_bond_post_input(vin: &ArchivalBondPostVin) -> Result<Input, BondAssemblyError> {
    match vin.post_kind {
        RetentionBondPostKind::JoinMarket => {}
        other => {
            return Err(BondAssemblyError::build(
                "wire bond-post mapping",
                format!("non-JoinMarket post kind {other:?} is invalid at genesis"),
            ));
        }
    }
    Ok(Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vin.hybrid_public_key.clone(),
        p_canonical_id: vin.p_canonical_id,
        kind: WireBondPostKind::JoinMarket {
            bond_spend_pk: vin.bond_spend_pk.clone(),
        },
        holdings: wire_holdings(&vin.holdings),
        bonded_total_atomic: vin.bonded_total_atomic,
        bond_credit: vin.bond_credit,
        bond_debit: vin.bond_debit,
    })))
}

/// Finalize the assembled bond transaction: serialize the fully-populated
/// [`WireEncodeInput`] via the canonical encoder and **mint the
/// [`PBoundBytes`] pairing** — the single production mint site (pin P-1).
///
/// The bytes bound here are the encoder's output over the typed parts the
/// assemble path built, never caller-supplied bytes: possession of the
/// returned value is proof the transaction came out of this path.
pub(crate) fn finalize_bond_tx(
    persona: PCanonicalId,
    input: &WireEncodeInput,
) -> Result<PBoundBytes, BondAssemblyError> {
    let bytes = encode_final_tx(input).map_err(|e| BondAssemblyError::build("wire encoding", e))?;
    Ok(PBoundBytes::bind(persona, bytes))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_support::funding_record;
    use shekyl_engine_state::pending_post_block::PendingPostState;
    use shekyl_engine_state::pscan_state::MintLineageOutput;
    use shekyl_types::BlockHeight;

    // The sweep is lineage-blind (it consumes *all* spendable funding
    // regardless of rung — GF-4b §3.1), so these helpers pin rung 3 as the
    // representative fixture lineage; both delegate to the crate's single
    // `funding_record` builder (the immature-exclusion KATs override
    // `spendable_height` on the returned record).
    fn record(gindex: u64, height: u64, amount: u64) -> PFundingOutputRecord {
        record_for_slot(0, gindex, height, amount)
    }

    fn record_for_slot(p_slot: u32, gindex: u64, height: u64, amount: u64) -> PFundingOutputRecord {
        funding_record(
            p_slot,
            gindex,
            height,
            amount,
            MintLineageOutput::ExternalTransfer,
        )
    }

    /// A far-future reference height: every plain-maturity fixture record is
    /// spendable, so tests exercising non-spendability concerns are
    /// unaffected by the GF4b-6 filter.
    const REF_HEIGHT: u64 = 1_000_000;

    fn sweep(
        records: &[PFundingOutputRecord],
        p_slot: u32,
        reserved: &std::collections::BTreeSet<u64>,
        required: u64,
        reference_height: u64,
    ) -> Result<FundingSelection, BondAssemblyError> {
        let reference_height = BlockHeight::from_raw(reference_height);
        let reserved: std::collections::BTreeSet<_> = reserved
            .iter()
            .copied()
            .map(shekyl_types::GlobalOutputIndex::from_raw)
            .collect();
        sweep_funding_outputs(
            &SpentRecordsDurablyPruned::for_test(),
            records,
            shekyl_types::PSlot::from_raw(p_slot),
            &reserved,
            AtomicUnits::from_raw(required),
            reference_height,
        )
    }

    fn picked_gindexes(selection: &FundingSelection) -> Vec<u64> {
        selection
            .records
            .iter()
            .map(|r| r.gindex.to_raw())
            .collect()
    }

    /// GF-4b §3.1: the sweep consumes the **entire** spendable eligible set
    /// oldest-first — no early break at `required`, no expressible subset.
    /// (Formerly the subset selector's stop-when-satisfied test; the sweep
    /// conversion inverts the expectation.)
    #[test]
    fn sweep_consumes_the_entire_eligible_set_oldest_first() {
        // Deliberately unsorted input; heights 30/10/20, and a same-height
        // pair (10) discriminated by gindex.
        let records = vec![
            record(5, 30, 1_000),
            record(3, 10, 400),
            record(1, 10, 300),
            record(4, 20, 500),
        ];
        let selection = sweep(&records, 0, &Default::default(), 1_000, REF_HEIGHT).expect("sweeps");
        // Oldest-first over *everything*: 300+400 ≥ 1000 would have stopped
        // the old selector at [1, 3]; the sweep consumes all four.
        let picked = picked_gindexes(&selection);
        assert_eq!(picked, vec![1, 3, 4, 5], "the full eligible set, ordered");
        assert_eq!(selection.total, AtomicUnits::from_raw(2_200));
    }

    /// §3.2 rule 1: records reserved by a live pending post are excluded —
    /// the pending record is the single source of reservation truth.
    #[test]
    fn reserved_gindexes_are_excluded() {
        let records = vec![record(1, 10, 600), record(2, 20, 600)];
        let reserved = [1u64].into_iter().collect();
        let selection = sweep(&records, 0, &reserved, 500, REF_HEIGHT).expect("sweeps");
        let picked = picked_gindexes(&selection);
        assert_eq!(picked, vec![2], "the reserved record must not be swept");
    }

    /// §3.2 rule 1 (persona scoping): the sealed set mixes every bonded
    /// persona's records, but the sweep funds **one** persona's bond — records
    /// owned by a different `p_slot` must never be swept (they would derive a
    /// wrong key image under the single-persona `AssembleBond` derivation).
    #[test]
    fn sweep_excludes_other_personas_records() {
        // Persona 0 alone has just under the requirement; persona 1 has plenty.
        // A slot-blind sweep would reach across and "succeed" with persona
        // 1's outputs — the exact mis-keying this filter closes.
        let records = vec![
            record_for_slot(0, 1, 10, 400),
            record_for_slot(1, 2, 10, 5_000),
            record_for_slot(1, 3, 20, 5_000),
        ];
        // Assembling for persona 0: only its own 400 is eligible → refuse.
        let err = sweep(&records, 0, &Default::default(), 1_000, REF_HEIGHT)
            .err()
            .expect("persona 0 cannot reach across to persona 1's outputs");
        match err {
            BondAssemblyError::InsufficientFunding { available, .. } => {
                assert_eq!(available, 400, "only persona 0's own record is counted");
            }
            other => panic!("expected InsufficientFunding, got {other:?}"),
        }
        // Assembling for persona 1: sweeps persona 1's records — all of them.
        let selection = sweep(&records, 1, &Default::default(), 1_000, REF_HEIGHT).expect("sweeps");
        let picked = picked_gindexes(&selection);
        assert_eq!(
            picked,
            vec![2, 3],
            "persona 1's entire eligible set, never persona 0's"
        );
    }

    /// §3.2 rule 2 (fund-from-earnings ramp): a swept total below the
    /// requirement refuses with the exact `available`/`required` pair.
    #[test]
    fn insufficient_funding_refuses_with_available_and_required() {
        let records = vec![record(1, 10, 300), record(2, 20, 200)];
        let reserved = [2u64].into_iter().collect();
        let err = sweep(&records, 0, &reserved, 1_000, REF_HEIGHT)
            .err()
            .expect("must refuse");
        match err {
            BondAssemblyError::InsufficientFunding {
                available,
                required,
            } => {
                assert_eq!(available, 300, "available excludes the reserved record");
                assert_eq!(required, 1_000);
            }
            other => panic!("expected InsufficientFunding, got {other:?}"),
        }
    }

    /// GF4b-6 (§3.6): an immature record — `spendable_height` above the
    /// sweep's reference height — is excluded, and the sweep over the mature
    /// remainder still succeeds. Exercises both arrival paths: ordinary
    /// fresh funding (plain +`SPENDABLE_AGE` maturity) and a coinbase-shaped
    /// +60 lock (the adversarial mine-to-`P` griefing vector the sweep's
    /// totality would otherwise convert into a bonding denial).
    #[test]
    fn sweep_excludes_immature_records() {
        // reference_height 25: record at height 10 matured at 20 (in);
        // record at height 20 matures at 30 (out, ordinary +10 flow).
        let records = vec![record(1, 10, 600), record(2, 20, 600)];
        let selection = sweep(&records, 0, &Default::default(), 500, 25).expect("sweeps");
        let picked = picked_gindexes(&selection);
        assert_eq!(picked, vec![1], "the immature record is not in the sweep");
        assert_eq!(selection.total, AtomicUnits::from_raw(600));

        // Coinbase-shaped arrival: same height as the mature record, but the
        // +60 lock (via spendable_height) keeps it out until height 70.
        let mut coinbase_shaped = record(3, 10, 600);
        coinbase_shaped.spendable_height = BlockHeight::from_raw(10 + 60);
        let records = vec![record(1, 10, 600), coinbase_shaped];
        let selection = sweep(&records, 0, &Default::default(), 500, 25).expect("sweeps");
        let picked = picked_gindexes(&selection);
        assert_eq!(
            picked,
            vec![1],
            "an adversarially-mined immature coinbase cannot deny the bond"
        );
    }

    /// GF-4b §3.1 structural emptiness at the sweep boundary: the swept set
    /// **is** the spendable eligible set — filtering the input by the sweep's
    /// own eligibility predicate and subtracting the selection leaves
    /// nothing. (The state-level zero-pre-bond-output test extends this to
    /// the post-sweep record set; this KAT pins the function's totality.)
    #[test]
    fn sweep_leaves_no_spendable_eligible_remainder() {
        let reserved: std::collections::BTreeSet<u64> = [4u64].into_iter().collect();
        let mut immature = record(5, 90, 250);
        immature.spendable_height = BlockHeight::from_raw(150);
        let records = vec![
            record(1, 10, 300),
            record(2, 20, 400),
            record_for_slot(7, 3, 15, 999), // other persona
            record(4, 25, 500),             // reserved
            immature,                       // survives by design (GF4b-6)
        ];
        let selection = sweep(&records, 0, &reserved, 100, 100).expect("sweeps");
        let swept: std::collections::BTreeSet<u64> = selection
            .records
            .iter()
            .map(|r| r.gindex.to_raw())
            .collect();
        let remainder: Vec<u64> = records
            .iter()
            .filter(|r| {
                r.p_slot == shekyl_types::PSlot::from_raw(0)
                    && !reserved.contains(&r.gindex.to_raw())
                    && r.spendable_height <= BlockHeight::from_raw(100)
            })
            .map(|r| r.gindex.to_raw())
            .filter(|g| !swept.contains(g))
            .collect();
        assert!(
            remainder.is_empty(),
            "a spendable eligible record survived the sweep: {remainder:?}"
        );
        assert_eq!(
            swept.len(),
            2,
            "exactly the two spendable, unreserved, own-slot records"
        );
    }

    /// C-1 §5 item 4 / F-4: `sweep_funding_outputs` remains the sole
    /// funding-selection entry, and `SpentRecordsDurablyPruned` has no
    /// production constructor (only `for_test`).
    #[test]
    fn f4_sweep_is_sole_funding_selector_and_witness_is_test_only() {
        // Drop only the trailing `mod tests` — earlier `#[cfg(test)]` item
        // attrs (`bind_for_test`, `for_test`) live in the production region
        // of the source text and must remain visible to the witness check.
        // Whole-file `include_str!` would self-match the assertion literals
        // below (`wire.rs` tripwire shape).
        let src = include_str!("bond_assembly.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("bond_assembly.rs has a production section");
        let backing = include_str!("backing_set.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("backing_set.rs has a production section");
        // Sole funding-selection definition lives here; no alternate selector
        // in BackingSet. Orchestrator monopoly is asserted in
        // `bond_orchestrator::tests`.
        let sweep_def = concat!("pub(crate) fn sweep", "_funding_outputs");
        assert!(
            src.contains(sweep_def),
            "sweep definition must remain in bond_assembly"
        );
        let retired_def = concat!("fn select", "_funding_outputs");
        let retired = concat!("select", "_funding_outputs");
        assert!(
            !src.contains(retired_def),
            "retired subset selector must not reappear in bond_assembly"
        );
        assert!(
            !backing.contains(retired),
            "BackingSet must not revive the subset selector"
        );
        // Exactly ONE production constructor: SP-R0 arm #1's attestation
        // (`arm1_watch_pruning_live`), plus `for_test` under cfg(test) — and
        // nothing else. Inspect the impl region only — narrative mentions of
        // constructors elsewhere in production docs must not false-positive.
        let impl_region = src
            .split("impl SpentRecordsDurablyPruned")
            .nth(1)
            .and_then(|rest| rest.split("/// The outcome of the D-A2 sweep").next())
            .expect("SpentRecordsDurablyPruned impl region");
        assert!(
            impl_region.contains("fn arm1_watch_pruning_live()"),
            "the sole production SpentRecordsDurablyPruned constructor (SP-R0 arm #1) must remain"
        );
        assert!(
            impl_region.contains("fn for_test()"),
            "test-only witness constructor must remain"
        );
        assert!(
            !impl_region.contains("pub(crate) fn new(")
                && !impl_region.contains("pub fn new(")
                && !impl_region.contains("pub(crate) fn mint("),
            "no second production SpentRecordsDurablyPruned constructor"
        );
        // Orchestrator's sole-funding-path claim is asserted in
        // `bond_orchestrator::tests` (keeps this KAT independent of that module).
    }

    /// Pin P-2 round-trip: a sealed [`PendingBondPost`]'s `(persona, tx_bytes)`
    /// re-lifts into the exact `PBoundBytes` value the assemble path bound.
    #[test]
    fn from_pending_relifts_the_sealed_pairing() {
        let persona = PCanonicalId::from_bytes([9u8; 32]);
        let bytes = vec![1, 2, 3, 4];
        let post = PendingBondPost {
            p_slot: PSlot::from_raw(0),
            persona,
            tx_bytes: bytes.clone(),
            entry_offset_blocks: 3,
            bond_post_offset_blocks: 7,
            anchor_t0: BlockHeight::from_raw(100),
            funding_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(1)],
            state: PendingPostState::Pending,
        };
        let bound = PBoundBytes::from_pending(&post);
        assert_eq!(bound.persona(), &persona);
        assert_eq!(bound.bytes(), bytes.as_slice());
        assert_eq!(bound, PBoundBytes::bind_for_test(persona, bytes));
    }

    /// The pairing's `Debug` is redacted wholesale — the persona↔tx link is
    /// exactly what must never reach a log path.
    #[test]
    fn pbound_bytes_debug_is_redacted() {
        let bound = PBoundBytes::bind_for_test(PCanonicalId::from_bytes([7u8; 32]), vec![0xAB]);
        let rendered = format!("{bound:?}");
        assert!(
            !rendered.contains("AB"),
            "bytes must not render: {rendered}"
        );
        assert_eq!(rendered, "PBoundBytes(<redacted persona-bound tx>)");
    }
}
