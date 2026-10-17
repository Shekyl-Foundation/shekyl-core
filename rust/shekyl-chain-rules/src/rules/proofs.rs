// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The verify that needs no chain (`CHAIN_RULES_CRATE.md` §4.6, 2026-10-16).
//!
//! CEN-I17/I18 and CEN-I15, CEN-J26, CEN-J27's verify half run in `form`,
//! before any write. [`super::tx_against`] keeps the view-bound half: it
//! reads the chain and compares. The two do not share a file, because a
//! verify that reads no view is not a
//! [`TxAgainstRule`](crate::rules::TxAgainstRule) and must not grow the
//! module that is. The census still names I17 and I18 at
//! `rules::tx_against`, which re-exports them.

use crate::block::{ReferenceClaims, VerifiedReference};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::rules::tx::TxClass;
use crate::rules::tx_against::{proof_reference, to_key_slots, ReferenceContext, I15, J27};
use crate::rules::tx_emission_against::J26;
use crate::rules::{Rule, TxContext};
use crate::verdict::{InvalidBlock, Locus, Verdict};
use shekyl_crypto_pq::signature::verify_pqc_auth;
use shekyl_types::SigningPayloadHash;
use shekyl_wire::Ct;

/// Call counters for the two verification bodies, so a test can hold that
/// `validate` runs neither (`CHAIN_RULES_CRATE.md` §4.6: no second verify
/// site) while `form` runs both. Test-only: nothing in production reads
/// them.
#[cfg(any(test, feature = "harness"))]
pub mod probes {
    use core::cell::Cell;

    thread_local! {
        static FCMP: Cell<u64> = const { Cell::new(0) };
        static SIGNATURES: Cell<u64> = const { Cell::new(0) };
    }

    /// How many times [`shekyl_fcmp::proof::verify`] was called through
    /// CEN-I15's body (the spend's, the emission's fee inputs as J26, the
    /// bond post's funding spends as J27) **on this thread**. Per thread,
    /// so a probe over one stage is not moved by another test's `form` on
    /// a sibling thread — the test runs both stages on its own thread.
    #[must_use]
    pub fn fcmp_verifies() -> u64 {
        FCMP.with(Cell::get)
    }

    /// How many signatures CEN-I18 verified on this thread.
    #[must_use]
    pub fn signature_verifies() -> u64 {
        SIGNATURES.with(Cell::get)
    }

    /// One FCMP++ verify through CEN-I15's body, on this thread.
    pub(in crate::rules) fn count_fcmp() {
        FCMP.with(|c| c.set(c.get() + 1));
    }

    /// One signature CEN-I18 verified, on this thread.
    pub(in crate::rules) fn count_signature() {
        SIGNATURES.with(|c| c.set(c.get() + 1));
    }
}

/// The rows [`judge_proofs`] records — the three verify rows, one per
/// class that carries a proof — which it records **vacuous** on every
/// other class, as [`super::tx_against::judge_reference`] records the
/// step rows.
const PROOF_ROWS: [CenRow; 3] = [I15::ROW, J26::ROW, J27::ROW];

/// The verify rows, run in `form` over the caller's claims (2026-10-16,
/// `CHAIN_RULES_CRATE.md` §4.6 — the third claim): CEN-I15 on a spend,
/// CEN-J26 on an emission's fee inputs, CEN-J27's verify half on a bond
/// post's funding spends, each over [`to_key_slots`] against the claimed
/// root and the body's declared depth (`layers = declared + 1`). Vacuous
/// on every other class.
///
/// A proof-bearing transaction whose reference the caller did not claim is
/// not verified here and yields `None`; `validate` then refuses it on
/// CEN-I10/I11 or faults [`Stale::Reference`](crate::fault::Stale::Reference)
/// — there is no second verify site. A declared depth the verifier cannot
/// size (`0`, or past a `u8`) yields `None` too: that is CEN-I13's refusal,
/// which `validate` keeps.
///
/// Yields what the proof was verified against, for `validate` to compare
/// with the chain's context.
///
/// `cached` is CEN-M8's cache: the triple this node verified this
/// transaction's proof against when it last judged it, read back by the
/// pool at a re-admission (DRS-E5 PR-b b4). When it is exactly the claim
/// this judgement would verify under, the proof is not verified again —
/// the transaction's identity commits to the proof's bytes, and the triple
/// is the whole of what the verify reads besides them — and the row is
/// recorded as verified. Only the FCMP++ verify is skipped: the
/// signatures and, at `Lone`, the range proof run as always. `form` passes
/// `None`: a block's proofs are verified in its own judgement, never
/// trusted from a pool (`E5-Q8`).
pub(crate) fn judge_proofs(
    cx: &TxContext<'_>,
    claims: &ReferenceClaims,
    cached: Option<VerifiedReference>,
    coverage: &mut RuleCoverage,
) -> Verdict<Option<VerifiedReference>> {
    let (row, verifies) = match cx.class {
        TxClass::Spend { .. } => (I15::ROW, true),
        TxClass::Emission { .. } => (J26::ROW, true),
        TxClass::BondPost { .. } => (J27::ROW, true),
        TxClass::Coinbase | TxClass::ServeCreditOnly { .. } => (I15::ROW, false),
    };
    for vacuous in PROOF_ROWS {
        if !verifies || vacuous != row {
            coverage.insert(vacuous);
        }
    }
    if !verifies {
        return Ok(None);
    }
    let Some(reference) = proof_reference(cx.tx) else {
        // A `Null` CT on a proof-bearing class: CEN-H15 in `tx_form`, and
        // I10's refusal in `validate`. Nothing to verify.
        return Ok(None);
    };
    let Some(claim) = claims.get(&reference) else {
        return Ok(None);
    };
    let declared = match &cx.tx.ct {
        Ct::Fcmp {
            prunable: Some(prunable),
            ..
        } => prunable.tree_depth,
        _ => return Ok(None),
    };
    let Ok(tree_depth) = u8::try_from(declared) else {
        return Ok(None);
    };
    if tree_depth == 0 {
        return Ok(None);
    }
    let verified = VerifiedReference { reference, claim };
    if cached == Some(verified) {
        coverage.insert(row);
        return Ok(Some(verified));
    }
    let context = ReferenceContext {
        ref_height: claim.height,
        anchor: claim.root,
        tree_depth,
    };
    if I15::verify(cx.tx, &to_key_slots(cx.tx), &context).is_err() {
        return Err(InvalidBlock::new(row, cx.locus()));
    }
    coverage.insert(row);
    Ok(Some(verified))
}

/// CEN-I17, a **definition**: what each input's hybrid signature is over —
/// the PQC signing preimage, `FCMP_SPEND_SIGNING_PREIMAGE.md` §1.1: the
/// pruned segment ‖ keccak256(prunable) ‖ that input's PQC header ‖
/// keccak256 of every input's hybrid public key, so neither the proof nor
/// any input's key can be swapped under a standing signature. **Adopted**
/// from the wire, not re-derived: [`shekyl_wire::PqcSigningPreimage`] is the
/// one derivation the wallet signs over and the daemon verifies against
/// (through `shekyl_tx_pqc_signing_payload_hashes`; slice 6 Q7 (c)), and it
/// is held to the specification's output over eight daemon-accepted shapes
/// by `shekyl-wire/tests/pqc_signing_preimage_kat.rs`. A second body here
/// would be the two-sources class the cutover closed.
///
/// Recorded as coverage where the hashes are derived, the D4 arrangement:
/// nothing about a candidate fails a definition, and
/// `implemented(rules::tx_against::I17)` names this derivation (re-exported
/// from [`super::tx_against`]). Stateless — it reads the transaction alone —
/// so it lives with the verify that consumes it, not beside the view-bound
/// anchor.
///
/// The consumer is CEN-I18's signature verification: [`judge_signatures`]
/// runs the two as one sequence, this row yielding and I18 verifying.
pub(crate) struct I17;

impl Rule for I17 {
    const ROW: CenRow = CenRow::I17;
}

impl I17 {
    /// Every input's `signed_hash(i)`, in input order, recorded as this row.
    /// Empty for a body with no `pqc_auths` — the coinbase, and the
    /// serve-credit form, which CEN-H20 forbids to carry any: that form is
    /// signed over the pass record instead (CEN-J10), so this row and I18
    /// are vacuous on it by construction, not by exemption.
    pub(crate) fn signed_hashes(
        cx: &TxContext<'_>,
        coverage: &mut RuleCoverage,
    ) -> Vec<SigningPayloadHash> {
        coverage.insert(Self::ROW);
        cx.tx.pqc_signing_payload_hashes()
    }
}

/// CEN-I18: every input's hybrid PQC signature — Ed25519 **and** ML-DSA-65,
/// or the M-of-N multisig container — verifies over that input's
/// `signed_hash(i)` (`verify_transaction_pqc_auth`, `tx_pqc_verify.cpp`;
/// gated at `blockchain.cpp:4277–4285` on every non-coinbase transaction
/// but the serve credit). The verification body is
/// [`shekyl_crypto_pq::signature::verify_pqc_auth`], **the same function
/// the daemon's `shekyl_pqc_verify` and daemon-rpc's K13 call** — scheme
/// dispatch, the tx-auth domains and the container parse live there once,
/// so the validator, the daemon and the pool cannot disagree on what a
/// valid slot is. The slot's structural pins (`auth_version`, `flags`,
/// scheme id, key-blob length) are CEN-I16's, in `tx_form`.
///
/// Refuses at the input whose signature does not verify. Vacuous on the
/// two classes with no `pqc_auths` by construction — the coinbase, and the
/// serve-credit form, which CEN-H20 forbids them because its
/// countersignature is CEN-J10's, over the pass record: I17 yields nothing
/// there and this row verifies nothing, and neither reaches for J10's
/// object (`i17_reads_none_of_a_serve_credits_pass_record_…`).
pub(crate) struct I18;

impl Rule for I18 {
    const ROW: CenRow = CenRow::I18;
}

impl I18 {
    /// Verify `pqc_auths[i]` over `hashes[i]` for every input.
    ///
    /// The hashes are I17's, one per auth by construction
    /// ([`shekyl_wire::Transaction::pqc_signing_payload_hashes`]); a body
    /// for which I17 yielded none while `pqc_auths` is populated — the
    /// storage-pruned form, which `tx_form` refuses before this stage and
    /// the wire never carries — has no message for its signatures to be
    /// over, and is refused at the transaction rather than silently
    /// verified over nothing.
    ///
    /// The row is recorded only when the check passes, including the
    /// vacuous non-`Fcmp` arm. A refusal leaves it unrecorded, as
    /// [`crate::rules::run_tx`] does for a stateless rule.
    pub(crate) fn check(
        cx: &TxContext<'_>,
        hashes: &[SigningPayloadHash],
        coverage: &mut RuleCoverage,
    ) -> Verdict<()> {
        let Ct::Fcmp { pqc_auths, .. } = &cx.tx.ct else {
            coverage.insert(Self::ROW);
            return Ok(());
        };
        if pqc_auths.len() != hashes.len() {
            return Err(InvalidBlock::new(Self::ROW, Locus::Tx { slot: cx.slot }));
        }
        for (input, (auth, hash)) in pqc_auths.iter().zip(hashes).enumerate() {
            #[cfg(any(test, feature = "harness"))]
            probes::count_signature();
            if verify_pqc_auth(
                auth.scheme_id,
                &auth.hybrid_public_key,
                &auth.hybrid_signature,
                hash.as_bytes(),
            )
            .is_err()
            {
                return Err(InvalidBlock::new(
                    Self::ROW,
                    Locus::Input {
                        slot: cx.slot,
                        input,
                    },
                ));
            }
        }
        coverage.insert(Self::ROW);
        Ok(())
    }
}

/// CEN-I17 and CEN-I18 as one sequence: I17 yields every input's signing
/// hash, I18 verifies each input's signature over it. The D4 arrangement
/// [`super::tx_against::judge_reference`] uses for I10–I12 — the definition
/// row records at the derivation, the verification row consumes the operand
/// it yielded.
pub(crate) fn judge_signatures(cx: &TxContext<'_>, coverage: &mut RuleCoverage) -> Verdict<()> {
    let signed_hashes = I17::signed_hashes(cx, coverage);
    I18::check(cx, &signed_hashes, coverage)
}
