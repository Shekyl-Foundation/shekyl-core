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
//! - **D-A2 funding selection** ([`select_funding_outputs`]): deterministic
//!   oldest-first greedy accumulation over the sealed [`PFundingOutputRecord`]
//!   set, excluding records reserved by a live pending post.
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
use shekyl_types::PCanonicalId;
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

    /// A live pending post already exists for this persona. JoinMarket-only
    /// at genesis: one live post per persona (§3.5); the caller waits for the
    /// pending post to confirm or fail before re-assembling.
    #[error("a pending bond post already exists for this persona; one live post per persona")]
    #[allow(dead_code)] // transient — constructed by the D-A4 pending-post gate as it lands.
    PendingPostExists,

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
// D-A2 — funding selection (§3.2)
// ---------------------------------------------------------------------------

/// The outcome of D-A2 selection: the chosen funding records (oldest-first
/// order preserved) and their exact sum.
///
/// Redacted `Debug` via the contained records' own redaction; the struct adds
/// nothing renderable beyond the total, so it derives nothing.
pub(crate) struct FundingSelection {
    /// The selected records, in selection (oldest-first) order.
    #[allow(dead_code)] // transient — read by the Engine-side WI-2 orchestrator as it lands.
    pub records: Vec<PFundingOutputRecord>,
    /// Exact sum of the selected records' amounts.
    #[allow(dead_code)] // transient — read by the Engine-side WI-2 orchestrator as it lands.
    pub total: u64,
}

/// D-A2 funding selection (`ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.2), Engine-side
/// over public data only:
///
/// 1. **Eligibility.** Every persisted record is already final (the pscan
///    ingest horizon is `tip − ARCHIVAL_REORG_DEPTH_BLOCKS`). Records whose
///    `gindex` appears in `reserved` — the union of live pending posts'
///    reservation sets — are excluded; the pending record is the single
///    source of reservation truth.
/// 2. **Ramp.** If the unreserved sum is below `required`, refuse with
///    [`BondAssemblyError::InsufficientFunding`].
/// 3. **Order.** Oldest-first (height, then gindex) greedy accumulation until
///    `sum ≥ required`. Deterministic and auditable; input-selection
///    unlinkability pressure does not apply here — these are P-local outputs
///    spent to P's own bond, and the post names `P` in cleartext anyway.
///
/// `required` is `bond_floor(holdings) + fee`, computed by the caller with
/// checked arithmetic.
#[allow(dead_code)] // transient — consumed by the Engine-side WI-2 orchestrator as it lands.
pub(crate) fn select_funding_outputs(
    records: &[PFundingOutputRecord],
    reserved: &std::collections::BTreeSet<u64>,
    required: u64,
) -> Result<FundingSelection, BondAssemblyError> {
    let mut eligible: Vec<&PFundingOutputRecord> = records
        .iter()
        .filter(|r| !reserved.contains(&r.gindex))
        .collect();
    // Oldest-first: height, then gindex. Distinct outputs have distinct
    // gindexes, so the order is total and deterministic.
    eligible.sort_by_key(|r| (r.height, r.gindex));

    let mut selected = Vec::new();
    let mut total: u64 = 0;
    for record in &eligible {
        if total >= required {
            break;
        }
        total = total
            .checked_add(record.amount.to_raw())
            .ok_or(BondAssemblyError::AmountOverflow)?;
        selected.push((*record).clone());
    }

    if total < required {
        // `total` here is the full unreserved sum (the loop only stops early
        // once `required` is met), so it doubles as `available`.
        return Err(BondAssemblyError::InsufficientFunding {
            available: total,
            required,
        });
    }

    Ok(FundingSelection {
        records: selected,
        total,
    })
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
        HoldingsKind::ShardSetCompact => Holdings::ShardSetCompact(holdings.shard_ids.clone()),
        HoldingsKind::CompleteTree => Holdings::CompleteTree,
    }
}

/// Map a built [`ArchivalBondPostVin`] onto the canonical wire
/// [`Input::BondPost`] prefix input (`GENESIS_TX_WIRE_FORMAT.md` §9.11).
///
/// `bond_spend_pk` is the GF-1 debit-authorizer hybrid public key
/// (JoinMarket-coupled on the wire per §9.11); the vin itself does not carry
/// it, so the caller supplies P's canonical `bond_spend_pk` bytes alongside.
///
/// Refuses a non-JoinMarket vin: JoinMarket is the only post kind valid at
/// genesis, and the `bond_spend_pk` coupling below is JoinMarket-specific.
pub(crate) fn wire_bond_post_input(
    vin: &ArchivalBondPostVin,
    bond_spend_pk: Vec<u8>,
) -> Result<Input, BondAssemblyError> {
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
        kind: WireBondPostKind::JoinMarket { bond_spend_pk },
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
    use shekyl_engine_state::pending_post_block::PendingPostState;
    use shekyl_types::{BlockHeight, SettlementEpoch};
    use shekyl_units::AtomicUnits;

    fn record(gindex: u64, height: u64, amount: u64) -> PFundingOutputRecord {
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
        }
    }

    /// §3.2 rule 3: oldest-first (height, then gindex) greedy accumulation,
    /// stopping at the first record that satisfies `required`.
    #[test]
    fn selection_is_oldest_first_and_stops_when_satisfied() {
        // Deliberately unsorted input; heights 30/10/20, and a same-height
        // pair (10) discriminated by gindex.
        let records = vec![
            record(5, 30, 1_000),
            record(3, 10, 400),
            record(1, 10, 300),
            record(4, 20, 500),
        ];
        let selection =
            select_funding_outputs(&records, &Default::default(), 1_000).expect("selects");
        // Oldest-first: (10,1) then (10,3) then (20,4); 300+400+500 ≥ 1000.
        let picked: Vec<u64> = selection.records.iter().map(|r| r.gindex).collect();
        assert_eq!(picked, vec![1, 3, 4]);
        assert_eq!(selection.total, 1_200);
    }

    /// §3.2 rule 1: records reserved by a live pending post are excluded —
    /// the pending record is the single source of reservation truth.
    #[test]
    fn reserved_gindexes_are_excluded() {
        let records = vec![record(1, 10, 600), record(2, 20, 600)];
        let reserved = [1u64].into_iter().collect();
        let selection = select_funding_outputs(&records, &reserved, 500).expect("selects");
        let picked: Vec<u64> = selection.records.iter().map(|r| r.gindex).collect();
        assert_eq!(picked, vec![2], "the reserved record must not be selected");
    }

    /// §3.2 rule 2 (fund-from-earnings ramp): an unreserved sum below the
    /// requirement refuses with the exact `available`/`required` pair.
    #[test]
    fn insufficient_funding_refuses_with_available_and_required() {
        let records = vec![record(1, 10, 300), record(2, 20, 200)];
        let reserved = [2u64].into_iter().collect();
        let err = select_funding_outputs(&records, &reserved, 1_000)
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

    /// Pin P-2 round-trip: a sealed [`PendingBondPost`]'s `(persona, tx_bytes)`
    /// re-lifts into the exact `PBoundBytes` value the assemble path bound.
    #[test]
    fn from_pending_relifts_the_sealed_pairing() {
        let persona = PCanonicalId::from_bytes([9u8; 32]);
        let bytes = vec![1, 2, 3, 4];
        let post = PendingBondPost {
            p_slot: 0,
            persona,
            tx_bytes: bytes.clone(),
            entry_offset_blocks: 3,
            bond_post_offset_blocks: 7,
            anchor_t0: BlockHeight::from_raw(100),
            funding_gindexes: vec![1],
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
