// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.J, the emission **statics** (`CHAIN_RULES_SLICE_8.md` §5 row
//! 8): the four rows of the C++ emission arm (`blockchain.cpp`, the
//! `is_archival_emission_tx` branch of `check_tx_inputs`) that read the
//! transaction's bytes and nothing else. In the arm's order: the vin
//! parses (CEN-J19), the emission slot's hybrid key derives the vin's
//! `P_canonical_id` (CEN-J20), the **signable hash** is the prefix hash
//! with the emission vin removed (CEN-J22), and the **reward commit set** is
//! the loud vouts in vout order with their checked sum (CEN-J24). The two
//! definition rows yield the operands of the verify crossing — CEN-J25,
//! `shekyl_emission_vin_verify(…, signable_tx_hash, commits, count, …)` —
//! which is row 9's and reads them from here ([`J22::signable_hash`],
//! [`J24::reward_commits`]), so the pool, the block and the verify cannot
//! disagree on what the auths signed over.
//!
//! These run in `tx_form` after H22 has required the emission's shape (one
//! auth per vin, the balance with the mint on the debit slot), so a body
//! with no auth for its emission slot is H22's refusal, not J20's; asked
//! alone, each row still refuses what it cannot judge (J20 and J24 on a
//! body whose bytes they cannot read), the I5/H10 arrangement.
//!
//! What they do **not** read: no record (J23's frozen closes and the
//! claimant's bond are `tx_emission_against`'s, with the verify and the
//! fee-input proof, J26), no tree root (J21). The positive witness for every
//! one of them is row 7's **driven claim** — the engine's
//! `AssembleEmissionClaim` through the ingest driver — not a constructed
//! body: the harness's `fixture::emission_vin` is a parseable vin with
//! filler auths and backing, enough for these rows and for L7, and
//! nothing J25 would accept.

use shekyl_archival_retention::{
    p_canonical_id_from_hybrid_pubkey, ArchivalRewardEmissionVin, RewardCommit,
};
use shekyl_types::PrefixHash;
use shekyl_wire::{Ct, Input};

use crate::census::CenRow;
use crate::rules::tx::TxClass;
use crate::rules::{Rule, TxContext, TxRule, TxScope};
use crate::verdict::{InvalidBlock, Verdict};

/// The emission vin — its index and its bytes — if the class is
/// `Emission`. H6 has refused a second archival vin before any rule here
/// runs, so a class of `Emission` holds exactly one; its index is where the
/// C++'s `archival_emission_index` points.
pub(crate) fn the_emission<'tx>(cx: &TxContext<'tx>) -> Option<(usize, &'tx [u8])> {
    if !matches!(cx.class, TxClass::Emission { .. }) {
        return None;
    }
    cx.tx
        .prefix
        .inputs
        .iter()
        .enumerate()
        .find_map(|(index, item)| match item {
            Input::ArchivalRewardEmission { canonical_bytes } => {
                Some((index, canonical_bytes.as_slice()))
            }
            _ => None,
        })
}

/// CEN-J19: the emission vin's opaque bytes parse as an
/// [`ArchivalRewardEmissionVin`] **and are consumed exactly** — the FFI
/// extractor's parse (`shekyl_archival_emission_vin_extract`:
/// `ArchivalRewardEmissionVin::read` and an empty remainder). The census
/// row's "claimed epochs, ≥ 1" is the codec's: `read` refuses an epoch
/// count outside `1..=MAX_SETTLEMENT_EPOCHS_PER_EMISSION`, so the C++'s
/// separate `vin_epochs_len == 0` guard is unreachable past the parse and
/// is not re-stated here.
pub(crate) struct J19;

impl Rule for J19 {
    const ROW: CenRow = CenRow::J19;
}

impl J19 {
    /// The crate's one parse of an emission vin — this row, in a function:
    /// the block-level [`ArchivalKey::of`](crate::rules::body::ArchivalKey)
    /// (G9, and L7 through it) reads the claims through the same parse, so
    /// a vin that this row admits is a vin the uniqueness pass and the
    /// fold can read, and the converse.
    pub(crate) fn parse(bytes: &[u8]) -> Option<ArchivalRewardEmissionVin> {
        let mut cursor = bytes;
        let vin = ArchivalRewardEmissionVin::read(&mut cursor).ok()?;
        cursor.is_empty().then_some(vin)
    }
}

impl TxRule for J19 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let Some((_, bytes)) = the_emission(cx) else {
            return Ok(());
        };
        if Self::parse(bytes).is_none() {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-J20: the hybrid key in the emission slot's `pqc_auths` entry derives
/// the vin's `P_canonical_id` — [`p_canonical_id_from_hybrid_pubkey`] over
/// the slot's key equals it over the vin's `p_pubkey`, the id being the
/// comparable because the vin's key stays inside the opaque blob (the C++:
/// `shekyl_archival_p_canonical_id_from_pubkey(emission_auth.hybrid_public_key)
/// == p_canonical_id`). The tx-wide hybrid signature over that slot
/// (CEN-I17/I18) is then **P's**: the claim is signed by the persona whose
/// record it draws on, the bond post's key-equality pin (CEN-J13) with the
/// id as the comparable. A slot the body does not carry, or a vin this row
/// cannot read, is refused here when the row is asked alone.
pub(crate) struct J20;

impl Rule for J20 {
    const ROW: CenRow = CenRow::J20;
}

impl TxRule for J20 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let Some((index, bytes)) = the_emission(cx) else {
            return Ok(());
        };
        let refuse = || Err(InvalidBlock::new(Self::ROW, cx.locus()));
        let Some(vin) = J19::parse(bytes) else {
            return refuse();
        };
        let Ct::Fcmp { pqc_auths, .. } = &cx.tx.ct else {
            return refuse();
        };
        let Some(auth) = pqc_auths.get(index) else {
            return refuse();
        };
        if p_canonical_id_from_hybrid_pubkey(&auth.hybrid_public_key)
            != p_canonical_id_from_hybrid_pubkey(&vin.p_pubkey)
        {
            return refuse();
        }
        Ok(())
    }
}

/// CEN-J22, a **definition**: the emission claim's `signable_tx_hash` is
/// the prefix hash of the transaction **with the emission vin removed
/// wholesale** (F-C1c; the C++ erases `vin[archival_emission_index]` from a
/// copy of the prefix and hashes it). The vin cannot be covered by the hash
/// its own auths and backing proof sign — the circularity — and every
/// property the exclusion loses is re-bound by the Q1 auth message (the
/// vin's fields) and the reward commit set (CEN-J24); the tx-level hybrid
/// auth (CEN-I17/I18) still covers the complete prefix. The hash itself is
/// the wire's one derivation, [`shekyl_wire::TxPrefix::hash`], over the
/// edited prefix — the same function the engine's claim assembler reaches
/// through `tx_prefix_hash_from_parts_with_extra` and the row-7 differential
/// pins (`the_drivers_assembly_and_the_handler_emit_identical_bytes`).
///
/// Nothing fails a definition. The row runs in `tx_form` so the derivation
/// is exercised at both sites on every emission, and is recorded there;
/// the consumer is CEN-J25's verify crossing (row 9), which reads
/// [`Self::signable_hash`].
pub(crate) struct J22;

impl Rule for J22 {
    const ROW: CenRow = CenRow::J22;
}

impl J22 {
    /// The signable hash, if the class is `Emission`.
    pub(crate) fn signable_hash(cx: &TxContext<'_>) -> Option<PrefixHash> {
        let (index, _) = the_emission(cx)?;
        let mut prefix = cx.tx.prefix.clone();
        prefix.inputs.remove(index);
        Some(prefix.hash())
    }
}

impl TxRule for J22 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        // The derivation is the check: a definition has no refusal, and
        // computing the operand here is what `implemented(J22)` names.
        let _signable = Self::signable_hash(cx);
        Ok(())
    }
}

/// CEN-J24: the **reward commit set** is the loud (non-zero plaintext
/// amount) vouts in vout order, each as `(commitment, amount, one-time
/// key)` — the 72-byte `mask ‖ amount_le8 ‖ key` entries the C++ flattens
/// for the verify — and the reward total is their **checked sum**, the
/// inflation-audit operand (`shekyl_checked_sum_amounts`: overflow
/// refuses). Zero-amount vouts are ordinary confidential change and join
/// neither. The one predicate the row states beyond the definition is the
/// C++'s `outPk.size() == vout.size()`: a commitment per output, so the
/// set is well-defined (CEN-H17's arity clause names it first in
/// `tx_form`). A `Ct::Null` emission has no commitments and is refused
/// here when the row is asked alone (H22 names it first in `tx_form`).
///
/// The sum is the same checked fold CEN-H22 runs for the balance; H9 has
/// refused an overflowing output sum before either. The consumer is
/// CEN-J25's verify crossing (row 9), which reads [`Self::reward_commits`].
pub(crate) struct J24;

impl Rule for J24 {
    const ROW: CenRow = CenRow::J24;
}

impl J24 {
    /// The ordered reward commit set and its checked sum: `Ok(None)` off the
    /// emission class, `Err` under this row where the set is not
    /// well-defined.
    pub(crate) fn reward_commits(cx: &TxContext<'_>) -> Verdict<Option<(Vec<RewardCommit>, u64)>> {
        if the_emission(cx).is_none() {
            return Ok(None);
        }
        let refuse = || Err(InvalidBlock::new(Self::ROW, cx.locus()));
        let Ct::Fcmp { base, .. } = &cx.tx.ct else {
            return refuse();
        };
        let outputs = &cx.tx.prefix.outputs;
        if base.commitments.len() != outputs.len() {
            return refuse();
        }
        let commits: Vec<RewardCommit> = outputs
            .iter()
            .zip(&base.commitments)
            .filter(|(output, _)| output.amount != 0)
            .map(|(output, commitment)| RewardCommit {
                commitment: *commitment,
                amount_plain: output.amount,
                one_time_key: output.key,
            })
            .collect();
        let sum = commits
            .iter()
            .try_fold(0u64, |acc, commit| acc.checked_add(commit.amount_plain));
        let Some(sum) = sum else {
            return refuse();
        };
        Ok(Some((commits, sum)))
    }
}

impl TxRule for J24 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        Self::reward_commits(cx).map(|_| ())
    }
}

#[cfg(test)]
#[path = "tx_emission_tests.rs"]
mod tx_emission_tests;
