// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! JoinMarket bond-post semantic verify (gate-4 §3.2–3.5).
//!
//! Structural bounds (hybrid pubkey length) and `P_canonical_id` hint checks stay
//! in C++ consensus glue; this module covers post-kind, holdings, term rigidity,
//! floor equality, and record-existence (via `record_exists` from LMDB).
//!
//! Two rules here are about the transaction or the block rather than the vin, so
//! they sit outside the per-kind verifiers as free predicates:
//! [`bond_post_block_unique`] (one bond post per `P` per block) and
//! [`bond_post_funding_floor_met`] (at least one real spend input). Both follow
//! the same decision-placement pin — C++ marshals the operands, Rust decides —
//! though only the first is wired through the FFI so far; the second is called
//! by the wallet-side producer while the daemon still counts inputs in C++.

use thiserror::Error;

use crate::bond_floor::{bond_floor, bond_floor_of};
use crate::bond_wire::{ArchivalBondPostVin, BondKind, BondPostKind, HoldingsKind};
use crate::distinct::all_distinct;
use crate::release_cooldown::{release_cooldown_elapsed, slashes_settled_through};

#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum BondPostError {
    #[error("post_kind is not JoinMarket at genesis")]
    PostKindNotJoinMarket,
    #[error("ShardSetCompact requires at least one shard")]
    ShardSetCompactEmpty,
    #[error("CompleteTree must not carry shard ids")]
    CompleteTreeWithShardIds,
    #[error("JoinMarket bond-post must not carry bond_debit")]
    BondDebitNonzero,
    #[error("bond_credit and bond_debit are both non-zero")]
    BothTermsNonzero,
    #[error("bond_floor(holdings) is zero")]
    BondFloorZero,
    #[error("bonded_total_atomic and bond_credit must equal bond_floor")]
    FloorMismatch,
    #[error("bond record already exists for P_canonical_id")]
    RecordExists,
    #[error(
        "JoinMarket endpoint is the all-zero key: the bond record encodes \
         \"no endpoint\" as zero, so a zero key would connect as a bond that \
         advertises nothing"
    )]
    EndpointZero,
    #[error("post_kind is not Release")]
    PostKindNotRelease,
    #[error("Release requires an existing bond record")]
    RecordMissing,
    #[error("Release on a record with zero bonded total (nothing to release)")]
    NothingToRelease,
    #[error("Release bond-post must not carry bond_credit")]
    ReleaseCreditNonzero,
    #[error("Release full-exit holdings must be empty, not a floor-zero shard set")]
    ReleaseHoldingsNotEmpty,
    #[error("post-connect bonded_total_atomic must equal bond_floor(holdings)")]
    ReleaseFloorMismatch,
    #[error("Release is a full exit: post-connect bonded_total_atomic must be zero")]
    NotFullRelease,
    #[error("Release bond_debit must equal the record's current bonded_total")]
    DebitNotFullBalance,
    #[error("Release release cooldown has not elapsed")]
    CooldownNotElapsed,
    #[error("record interval log is full; the connect's clean interval-close cannot append")]
    IntervalLogFull,
    #[error("slash scheduler has not settled every epoch through the last-served anchor")]
    SlashSettlementPending,
    #[error("post_kind is not Reinstate")]
    PostKindNotReinstate,
    #[error("Reinstate is only valid on a ShardSetCompact record (not CompleteTree)")]
    ReinstateOnCompleteTree,
    #[error("Reinstate post-holdings must be ShardSetCompact")]
    ReinstatePostNotCompact,
    #[error("Reinstate requires an open bad interval (the record is not slashed)")]
    ReinstateNotSlashed,
    #[error(
        "record carries more than one open bad interval — record corruption (the \
         same-epoch slash coalescing invariant, P2B-9 Pin 5, guarantees at most one)"
    )]
    ReinstateMultipleOpenIntervals,
    #[error(
        "record interval log lacks Reinstate headroom (> 254 entries): re-arming \
         slashability must leave one slot for the next slash and one for the Release \
         clean close, so exit stays reachable"
    )]
    ReinstateIntervalLogHeadroom,
    #[error(
        "Reinstate terms mismatch: bond_debit and bond_credit must both be 0, and \
         bonded_total_atomic must equal the record's current bonded_total \
         (a persona's bond is immutable; Reinstate moves no collateral)"
    )]
    ReinstateTerms,
    #[error(
        "Reinstate post-holdings must equal the record's current holdings \
         (a persona's bond is immutable; holdings change is persona rotation)"
    )]
    ReinstateHoldingsChanged,
    #[error(
        "record bonded_total != bond_floor(record holdings) — record corruption; \
         rejected at verify so a verify-valid tx can never meet the connect \
         fold's loud floor belt (tx rejection, not a chain halt)"
    )]
    ReinstateRecordFloorBroken,
}

/// Set equality of two shard lists (order-agnostic). `post` must be duplicate-free;
/// the record's `current` is trusted. Used by [`verify_reinstate_bond_post`] and the
/// connect fold: a persona's bond is immutable, so reinstatement cannot change
/// holdings (2026-09-20 ruling).
pub(crate) fn holdings_unchanged(current: &[u64], post: &[u64]) -> bool {
    let mut post_sorted = post.to_vec();
    post_sorted.sort_unstable();
    if post_sorted.windows(2).any(|w| w[0] == w[1]) {
        return false;
    }
    let mut cur_sorted = current.to_vec();
    cur_sorted.sort_unstable();
    post_sorted == cur_sorted
}

/// Verify `Reinstate` bond-post semantics — post-slash reinstatement of a record with
/// an open bad interval (gate-4 §3.4; P2B-9, ratified 2026-07-14; holdings pin
/// restated 2026-09-20). Zero-money path (`bond_credit == bond_debit == 0`), so
/// the pqc auth is the identity key `P_pubkey` (the GF-1 selector routes
/// non-debit → identity; enforced C++-side — P2B-9 Pin 4).
///
/// **Reinstatement, not re-entry and not a holdings change:** the record resumes
/// in place — same `P_canonical_id`, same shards and add-epochs, same backlog.
/// The precondition is *an open bad interval exists* (`good_standing == false`,
/// both slash severities); an `Exited` record is excluded structurally (its clean
/// interval-close is zero-length, never open). Post-holdings must **equal** the
/// record's current holdings (the 2026-09-20 immutable-bond ruling: a persona
/// cannot keep `P` and change the bond; rotation is `Release` + `JoinMarket`).
/// A terminal slash that emptied the record cannot reinstate — empty holdings
/// have no position, and re-entry is `JoinMarket` under a new persona. The
/// interval log must leave headroom (`≤ 254` entries, Pin 6): re-arming
/// slashability must keep one slot for the next slash and one for the `Release`
/// clean close, so exit is always reachable. Exactly one open interval may exist
/// (Pin 5's coalescing invariant); more is record corruption, rejected here so a
/// verify-valid tx can never meet the connect fold's loud multiplicity belt.
pub fn verify_reinstate_bond_post(
    vin: &ArchivalBondPostVin,
    record_bonded_total: Option<u64>,
    record_holdings_kind: HoldingsKind,
    record_held_shard_ids: &[u64],
    record_bad_intervals: &[crate::consensus_state::BadInterval],
) -> Result<(), BondPostError> {
    if !matches!(vin.kind, BondKind::Reinstate) {
        return Err(BondPostError::PostKindNotReinstate);
    }
    let Some(current_bonded) = record_bonded_total else {
        return Err(BondPostError::RecordMissing);
    };
    // A CompleteTree record with an open bad interval is unrepresentable (the
    // demotion flips the kind atomically with the interval append) — belt anyway.
    if record_holdings_kind != HoldingsKind::ShardSetCompact {
        return Err(BondPostError::ReinstateOnCompleteTree);
    }
    if vin.holdings.kind != HoldingsKind::ShardSetCompact {
        return Err(BondPostError::ReinstatePostNotCompact);
    }
    // Reinstatement needs a position: empty holdings have no shards to serve.
    // A terminal slash that emptied the record re-enters via JoinMarket under a
    // new persona — there is no in-place path that puts shards back on this P.
    if vin.holdings.shard_ids.is_empty() {
        return Err(BondPostError::ShardSetCompactEmpty);
    }
    // (No oversize guard here: `vin.holdings.shard_ids` is a `ShardSet`, bounded
    // at construction, so an oversize post is unrepresentable by the time verify
    // runs — the former `ReinstatePostOversize` belt was retired with the newtype.
    // The raw-slice connect path re-guards it in `reinstate_connect`'s `PostOversize`.)
    // Precondition: exactly one open bad interval (Pin 5's coalescing invariant).
    let open_count = record_bad_intervals
        .iter()
        .filter(|iv| iv.end_exclusive == u64::MAX)
        .count();
    if open_count == 0 {
        return Err(BondPostError::ReinstateNotSlashed);
    }
    if open_count > 1 {
        return Err(BondPostError::ReinstateMultipleOpenIntervals);
    }
    // Pin 6 headroom: one slot reserved for the next slash + one for the Release
    // clean close (the close below is in-place, so post-Reinstate size == size).
    if record_bad_intervals.len() > crate::bond_connect::MAX_BOND_BAD_INTERVALS - 2 {
        return Err(BondPostError::ReinstateIntervalLogHeadroom);
    }
    // Immutable-bond: post-holdings equal current. Growth, shed, and swap are
    // all the same refusal — a persona does not keep P and change the bond.
    if !holdings_unchanged(record_held_shard_ids, &vin.holdings.shard_ids) {
        return Err(BondPostError::ReinstateHoldingsChanged);
    }
    // §3.2 record floor invariant, checked HERE against the marshaled record
    // facts — not deferred to the connect fold's RecordFloorInvariantBroken
    // belt: a floor-drifted record would otherwise let this tx verify and then
    // FATAL-abort every node at block connect. Verify rejects the tx; the fold's
    // belt stays for verify-bypassing callers.
    if bond_floor_of(record_holdings_kind, record_held_shard_ids.len()) != current_bonded {
        return Err(BondPostError::ReinstateRecordFloorBroken);
    }
    // Zero-money: no debit, no credit, bonded_total unchanged (equals the
    // record and equals bond_floor(post) — which is bond_floor(current) under
    // holdings equality).
    if vin.bond_debit != 0 || vin.bond_credit != 0 || vin.bonded_total_atomic != current_bonded {
        return Err(BondPostError::ReinstateTerms);
    }
    Ok(())
}

/// Verify JoinMarket bond-post semantics after wire decode and LMDB substrate read.
///
/// `record_exists` is `true` when `get_archival_bond_hybrid_pubkey` would succeed.
///
/// The endpoint (`EU-D3`) is the persona's onion public key, committed once at
/// connect and immutable for the record's life. It is not validated as a key
/// (any non-zero 32 bytes pass — a bad endpoint is self-harm the P pays for at
/// the next challenge), but the **all-zero key is refused**: the bond record
/// stores "no endpoint" as the zero key and cannot tell the two apart, so a
/// zero key would connect as a bonded persona that advertises nothing.
pub fn verify_join_market_bond_post(
    vin: &ArchivalBondPostVin,
    record_exists: bool,
) -> Result<(), BondPostError> {
    let BondKind::JoinMarket { endpoint, .. } = &vin.kind else {
        return Err(BondPostError::PostKindNotJoinMarket);
    };

    if endpoint.iter().all(|b| *b == 0) {
        return Err(BondPostError::EndpointZero);
    }

    match vin.holdings.kind {
        HoldingsKind::ShardSetCompact if vin.holdings.shard_ids.is_empty() => {
            return Err(BondPostError::ShardSetCompactEmpty);
        }
        HoldingsKind::CompleteTree if !vin.holdings.shard_ids.is_empty() => {
            return Err(BondPostError::CompleteTreeWithShardIds);
        }
        _ => {}
    }

    if vin.bond_credit > 0 && vin.bond_debit > 0 {
        return Err(BondPostError::BothTermsNonzero);
    }
    if vin.bond_debit != 0 {
        return Err(BondPostError::BondDebitNonzero);
    }

    let floor = bond_floor(&vin.holdings);
    if floor == 0 {
        return Err(BondPostError::BondFloorZero);
    }
    if vin.bonded_total_atomic != floor || vin.bond_credit != floor {
        return Err(BondPostError::FloorMismatch);
    }

    if record_exists {
        return Err(BondPostError::RecordExists);
    }

    Ok(())
}

/// Every Release guard that runs **before the release cooldown** — i.e. every
/// guard decidable without the per-shard last-served scan.
///
/// Split out for the same reason as [`release_vin_statics`], and to fix a
/// sharper problem: the daemon's gather deliberately skips its per-shard scan
/// for exactly these three states, and the submit battery's skipped-scan belt
/// sits **above** them. Without this, an ordinary malformed Release tripped the
/// belt and was logged at `error!` as an internal inconsistency, when the
/// honest answer was a quiet `Malformed` naming the guard that refused it.
/// Running these before the belt restores the belt's meaning: reaching it now
/// means a skip nothing explains.
///
/// It holds the original sequence **including** [`release_vin_statics`], and
/// that is not tidiness: an earlier revision extracted only the record-keyed
/// guards, which moved `DebitNotFullBalance` ahead of `NotFullRelease` for a vin
/// invalid in both ways. `shekyl-ffi` pins that mapping and went red. A
/// refactor that changes which error a caller sees is not a refactor, so the
/// whole pre-cooldown block moves together and the order is preserved by
/// construction.
///
/// The caller supplies `current_bonded` already unwrapped, because record
/// ABSENCE is a different verdict on the submit path (a competing exit,
/// classified at Phase D) than it is here.
pub fn release_pre_cooldown_guards(
    vin: &ArchivalBondPostVin,
    current_bonded: u64,
    record_bad_interval_count: usize,
) -> Result<(), BondPostError> {
    if current_bonded == 0 {
        return Err(BondPostError::NothingToRelease);
    }
    release_vin_statics(vin)?;
    // The debit removes the whole current balance (§3.2 table; §4.3 refund).
    if vin.bond_debit != current_bonded {
        return Err(BondPostError::DebitNotFullBalance);
    }
    // The connect must append the clean interval-close (§4.3 F3); a full log
    // (`bond_connect::MAX_BOND_BAD_INTERVALS`, the codec's `kMaxBadIntervals`
    // pin) makes the tx unconnectable, so it is unverifiable too.
    if record_bad_interval_count >= crate::bond_connect::MAX_BOND_BAD_INTERVALS {
        return Err(BondPostError::IntervalLogFull);
    }
    Ok(())
}

/// The Release guards that need **only the vin** — no record, no chain state.
///
/// Split out of [`verify_release_bond_post`] so the daemon's submit pre-gate can
/// run them *before* it asks for the §8.7.1.1 fact bundle. That gather performs
/// a per-shard last-served scan under the pool and blockchain locks, and for a
/// `CompleteTree` record its cost tracks the frozen-segment count, so any guard
/// that can refuse without it should refuse first: a caller holding the cold
/// key can otherwise mint fresh signatures over a vin these checks already
/// doom, and buy that scan once per forged txid.
///
/// Extracted rather than restated. A second copy of a consensus guard living in
/// the RPC crate is the drift this codebase spends its gates preventing; here
/// the block path and the submit pre-gate call the same function, and the order
/// inside `verify_release_bond_post` is unchanged.
pub fn release_vin_statics(vin: &ArchivalBondPostVin) -> Result<(), BondPostError> {
    if !matches!(vin.kind, BondKind::Release) {
        return Err(BondPostError::PostKindNotRelease);
    }
    if vin.bond_credit != 0 {
        return Err(BondPostError::ReleaseCreditNonzero);
    }

    // Step-4 floor equality on the vin's post-connect state (§3.5 debit-path note).
    let floor = bond_floor(&vin.holdings);
    // A full Release ends at the canonical empty holdings, whose floor is 0. But
    // `bond_floor` also returns 0 for a structurally-invalid (oversize) shard set,
    // so a floor-0 descriptor that still carries shards is not an exit — reject it
    // rather than let it masquerade as empty. (Join rejects floor-0 outright as
    // `BondFloorZero`; Release cannot, because the empty end-state is legitimately
    // floor 0, so it guards the non-empty case explicitly.)
    if floor == 0 && !vin.holdings.shard_ids.is_empty() {
        return Err(BondPostError::ReleaseHoldingsNotEmpty);
    }
    if vin.bonded_total_atomic != floor {
        return Err(BondPostError::ReleaseFloorMismatch);
    }
    // Full exit: post-connect total is zero (⇒ empty holdings, by floor equality).
    if vin.bonded_total_atomic != 0 {
        return Err(BondPostError::NotFullRelease);
    }
    Ok(())
}

/// Verify `Release` bond-post semantics — a full record release (gate-4 §3.2/§3.4/
/// §3.5/§4.3; `PHASE_2B_FSM_RETOOL.md` P2B-8).
///
/// Marshaled facts from LMDB (C++ reads, Rust decides — same split as
/// [`verify_join_market_bond_post`]): `record_bonded_total` is `None` when no bond
/// record exists for `P_canonical_id`; `last_served_epoch` is the derived
/// whole-record release-cooldown anchor
/// ([`crate::release_cooldown::whole_record_last_served`] over the per-shard
/// reverse-cursor maxima — for a `CompleteTree` record the maxima come from the
/// all-shards `P`-prefix scan, since the record stores no shard list), read at
/// `current_settlement_epoch`; `last_settled_slash_epoch` is the slash scheduler's
/// monotone watermark (`None` before any epoch settles).
///
/// The vin's `holdings` / `bonded_total_atomic` are the **post-connect** state
/// (gate-4 §3.5 debit-path note, ratified P2B-8): a full `Release` ends at empty
/// holdings, so `bonded_total_atomic == 0 == bond_floor(∅)`, and the debit removes
/// the whole current balance. There is no partial-release kind: a persona who
/// wants a smaller set rotates (`Release` + `JoinMarket` under a new P).
///
/// `record_bad_interval_count` is the record's interval-log length; verify
/// rejects a log at [`MAX_BOND_BAD_INTERVALS`](crate::bond_connect::MAX_BOND_BAD_INTERVALS)
/// because the connect's clean interval-close could not append — a tx that
/// verifies but cannot connect would be a deterministic halt, so verify and
/// connect enforce the same bound.
pub fn verify_release_bond_post(
    vin: &ArchivalBondPostVin,
    record_bonded_total: Option<u64>,
    record_bad_interval_count: usize,
    last_served_epoch: Option<u64>,
    last_settled_slash_epoch: Option<u64>,
    current_settlement_epoch: u64,
) -> Result<(), BondPostError> {
    if vin.post_kind() != BondPostKind::Release {
        return Err(BondPostError::PostKindNotRelease);
    }

    let Some(current_bonded) = record_bonded_total else {
        return Err(BondPostError::RecordMissing);
    };
    release_pre_cooldown_guards(vin, current_bonded, record_bad_interval_count)?;

    // Release cooldown: the grace window past the last served epoch must have
    // elapsed (gate-4 §4.3; the Gate-6 F-D3/F-D4 gate).
    if !release_cooldown_elapsed(last_served_epoch, current_settlement_epoch) {
        return Err(BondPostError::CooldownNotElapsed);
    }

    // Slash settlement: the scheduler's watermark must have reached the anchor,
    // so every epoch up to the last serve has been slash-processed on bonded
    // collateral before the release verifies. The cooldown alone leaves a
    // one-block connect-ordering race open (`release_cooldown` module docs).
    // Together the two checks pin the ratified guarantee (2026-07-12): epochs
    // through the anchor are settled; the unserved exit tail is forgiven;
    // slashability ends at the Release connect — the refund is never clawed back.
    if !slashes_settled_through(last_settled_slash_epoch, last_served_epoch) {
        return Err(BondPostError::SlashSettlementPending);
    }

    Ok(())
}

/// Block-level intra-block cross-tx bond-post uniqueness — at most **one**
/// bond-post vin per `P_canonical_id` per block (gate-4 §3.5; the emission
/// `(P, E)` pass's sibling,
/// [`emission_block_claims_unique`](crate::claimed_epochs::emission_block_claims_unique)).
///
/// Per-tx verify runs against pre-block DB state, so every same-`P` same-block
/// pair — JoinMarket+JoinMarket (double `total_bonded_atomic` credit),
/// Release+Release (double debit), JoinMarket+Release, Reinstate+Reinstate —
/// passes per-tx verify independently; each
/// pair interacts through the per-`P` record and the global counter, and the
/// §4.5 conservation audit is **not** a backstop (a double-credit doubles both
/// sides of `total_bonded == Σ bonded_P` consistently, so it passes on corrupt
/// state). This pass — run once per block over every bond-post vin's
/// `P_canonical_id`, before connect — is the layer that **rejects the block**.
/// Keyed on `P` alone, not `(P, post_kind)`: lifecycle transitions have no
/// legitimate multi-post-per-block use, and rejecting outright avoids inviting
/// intra-block ordering dependence. C++ only marshals the ids; the verdict is
/// decided here (the emission §9.5 item-6 decision-placement pin).
///
/// **Deliberately NOT covered (ratified 2026-07-12): a serve-credit response
/// and a `Release` for the same `P` in one block.** The pair is benign under
/// the settled release semantics: a served epoch carries a serve bit and is
/// slash-immune outright, and the epochs the fresh credit would have re-armed
/// the cooldown over are the unserved exit tail, which is exit-forgiven by
/// construction (`release_cooldown` module docs). Rejecting the pair would
/// force an honest exiting `P` to forfeit its final epoch's earned credit or
/// delay the exit a full cooldown — real cost, zero slashable exposure closed.
#[must_use]
pub fn bond_post_block_unique(p_canonical_ids: &[[u8; 32]]) -> bool {
    all_distinct(p_canonical_ids)
}

/// Whether a bond-post **transaction** meets the funding-input floor: at least
/// one real `txin_to_key` spend input, whatever the post kind.
///
/// A property of the transaction rather than of the bond vin, which is why it
/// is a free predicate here and not an arm of the per-kind verifiers above —
/// none of them is given the tx's input list. It binds on every kind: a credit
/// post funds the floor from `P`'s spendable outputs, and a debit post still
/// needs one real input for the fee, because released collateral enters the
/// balance equation as a *source* term and cannot pay for an input that does
/// not exist.
///
/// **Order matters to anyone mirroring this.** The floor binds *after* the
/// per-kind semantic verify and *before* every amount rule (pseudoOuts count,
/// reference block, CT balance). A producer that checks it later refuses a
/// no-input transaction by naming some amount instead, and then the wallet and
/// the chain disagree about why an irreversible operation was refused.
///
/// **Decision placement — the standing pin [`bond_post_block_unique`] carries:
/// C++ marshals, Rust decides** (`ARCHIVAL_BOND_GATE4.md`).
/// This predicate is the rule's Rust owner: `AssembleRelease`
/// (`shekyl-engine-core`) calls it instead of restating the condition. The
/// daemon still decides it in C++ — `Blockchain::check_tx_inputs`
/// (`src/cryptonote_core/blockchain.cpp`, *"Archival bond-post tx requires at
/// least one txin_to_key funding input"*) counts `txin_to_key` vins inline —
/// and that copy is the one to **delete** when the tx-verification path
/// migrates, by marshaling the count to this function. It is not a second rule
/// to keep in sync.
#[must_use]
pub fn bond_post_funding_floor_met(spend_input_count: usize) -> bool {
    spend_input_count > 0
}

#[cfg(test)]
#[path = "bond_post_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "bond_post_funding_tests.rs"]
mod funding_floor_tests;
