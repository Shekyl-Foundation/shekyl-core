// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.I, the stateless rows — input-path predicates decidable from
//! the bytes alone (`CHAIN_RULES_SLICE_6.md` commit 2).
//!
//! These run in `tx_form` **after** the 4.H line, the archival shape arms
//! (H20–H22) and H19's layout check. A transaction that fails its shape and
//! an input-path row is named by the shape: a proof-less bond post is H21,
//! not I1. The input cap still precedes proof verification, which lives in
//! `tx_against` and the H19 batch fold, both after `tx_form` returns.
//!
//! Where an archival shape already states a count, the 4.I row is the
//! regular spend's. H20, H21 and H22 fold their counts into one shape rule.
//! I8, I9 and I14 therefore judge `TxClass::Spend` and record as evaluated
//! on the archival classes.

use crate::census::CenRow;
use crate::rules::tx::TxClass;
use crate::rules::{Rule, TxContext, TxRule, TxScope};
use crate::verdict::{InvalidBlock, Verdict};
use shekyl_crypto_pq::multisig::HYBRID_SCHEME_ID_MULTISIG;
use shekyl_crypto_pq::signature::HYBRID_SCHEME_ID_ED25519_ML_DSA_65;
use shekyl_wire::transaction::{
    MAX_FCMP_INPUTS, PQC_HYBRID_SINGLE_KEY_LEN, PQC_MAX_PUBLIC_KEY_BLOB,
};
use shekyl_wire::{Ct, Input};

// ---- census 4.I, the stateless rows (slice 6 commit 2) ------------------
//
// The input-side shape rules the C++ `check_tx_inputs` states before any
// chain read (`blockchain.cpp`, the `reject_form` arms ahead of the
// key-image and reference-block lookups) and `tx_pqc_verify.cpp`'s
// structural pass over `pqc_auths`. Every one is decidable from the bytes,
// so every one is `tx_form`'s. The view-bound rows (I7, I10–I13) and the
// verification rows (I15, I17, I18) are `tx_against`'s, later commits.
//
// **Where an archival shape already states a count, the 4.I row is the
// regular spend's.** H20 (serve-credit: no `pqc_auths`, no proof), H21
// (bond post: `pqc_auths == vin`, `pseudoOuts == spends`, proof present) and
// H22 (emission: the same, proof present iff fee spends) each fold their
// counts into one shape rule, as the C++ does in each shape's arm. I8, I9
// and I14 therefore judge `TxClass::Spend` and record as evaluated — the
// premise checked, the count another row's — on the archival classes. The
// census names the split: I9 "regular spend; archival shapes use their
// spend-subset counts, CEN-H21/H22"; I8 "serve-credit excepted".

/// CEN-I1: a non-serve-credit transaction has at least two outputs
/// (`blockchain.cpp`: *"has fewer than two outputs"*, `tx.version >= 2 &&
/// !is_archival_serve_credit_only`). Spend, bond post and emission alike;
/// the serve-credit response has none by H20. Ratified `≥ 2`
/// (`GENESIS_TX_WIRE_FORMAT.md` :167 — *"earlier 'exactly one' was
/// over-strict"*). Non-coinbase: the coinbase's count is CEN-F4's.
pub(crate) struct I1;

impl Rule for I1 {
    const ROW: CenRow = CenRow::I1;
}

impl TxRule for I1 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if matches!(cx.class, TxClass::ServeCreditOnly { .. }) {
            return Ok(());
        }
        if cx.tx.prefix.outputs.len() < 2 {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-I4: at most [`MAX_FCMP_INPUTS`] inputs, counting the whole `vin`
/// (`blockchain.cpp`: *"has N inputs, max is FCMP_MAX_INPUTS_PER_TX"*).
///
/// **Unconditional.** The C++ sits this check, with H15's, inside
/// `if (m_nettype != FAKECHAIN)` — the one 4.I cell §3.4's sweep found
/// varying by nettype. Rule 71: nettype selects data, never control flow
/// on the consensus surface; the exemption served the proof-less C++ test
/// builder TXE-Q1 deletes, and a Rust rule that read the nettype here
/// would be the first in this crate to do so. The divergence is on the
/// CSR-3a register as DIVERGENT with identity-on-Fakechain as the failure.
///
/// **The number is inherited, not derived.** The cap is a hand-maintained
/// wire constant (`MAX_FCMP_INPUTS`, mirroring `cryptonote_config.h`'s
/// `FCMP_MAX_INPUTS_PER_TX`), not `config/`, and its only recorded
/// rationale is RingCT-era ("bounds proof generation time and tx size").
/// Measured (`shekyl-wire/tests/input_cap_cost.rs`;
/// `CHAIN_RULES_SLICE_6.md` §5.4) against CEN-H3's `TX_WEIGHT_LIMIT`
/// (149 400), the ceiling an accepted spend actually meets: 6.4 KB per
/// input on the wire; 11.9 ms (i9-11950H) and 64.9 ms (Pi 4) of verifier
/// time per input, linear on both. That weight limit admits 22 inputs of
/// this shape, so the cap of 8 binds by about 2.75×. The 1 MiB parser
/// bound is a wider ceiling and is not this measurement. The cap moves no
/// per-block bound — H3 does — and what it bounds is per-transaction
/// verifier work. Carried as inherited-and-unjustified with the derivation
/// owed (FOLLOWUPS); this rule enforces the value while the value is
/// decided, and does not argue for it.
pub(crate) struct I4;

impl Rule for I4 {
    const ROW: CenRow = CenRow::I4;
}

impl TxRule for I4 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if cx.tx.prefix.inputs.len() > MAX_FCMP_INPUTS {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-I5: `ToKey` key images are **strictly descending** by byte order in
/// input order (`blockchain.cpp` *"transaction has unsorted inputs"*:
/// `memcmp(ki, last) >= 0` refuses), archival inputs — which carry no key
/// image — skipped over, not reset at. One rule, two guarantees: an
/// unsorted pair and a repeated pair are both refused. Ratified strictly
/// descending (`GENESIS_TX_WIRE_FORMAT.md` §12 :871; the examination found
/// and fixed a reversed direction against the oracle). CEN-H10 stays as
/// the repeat's own row (slice 6 Q4 (a)): a repeat is refused on H10 first
/// in `tx_form`'s order, and I5 refuses the same bytes on its own row when
/// asked alone.
pub(crate) struct I5;

impl Rule for I5 {
    const ROW: CenRow = CenRow::I5;
}

impl TxRule for I5 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let mut last: Option<&[u8; 32]> = None;
        for input in &cx.tx.prefix.inputs {
            let Input::ToKey { key_image, .. } = input else {
                continue;
            };
            if last.is_some_and(|previous| key_image >= previous) {
                return Err(InvalidBlock::new(Self::ROW, cx.locus()));
            }
            last = Some(key_image);
        }
        Ok(())
    }
}

/// CEN-I6: every `ToKey` input's `key_offsets` is empty — there are no ring
/// offsets under FCMP++ (`FCMP_PLUS_PLUS.md` §7 step 3a; rule 60, the
/// decoy path is deleted). The C++ states it once per shape
/// (`blockchain.cpp` *"has non-empty key_offsets"*, regular / bond-post /
/// emission arms); one rule here over every class.
pub(crate) struct I6;

impl Rule for I6 {
    const ROW: CenRow = CenRow::I6;
}

impl TxRule for I6 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let offsets_present = cx.tx.prefix.inputs.iter().any(
            |input| matches!(input, Input::ToKey { key_offsets, .. } if !key_offsets.is_empty()),
        );
        if offsets_present {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-I8, the regular spend's arm: `pqc_auths.len() == vin.len()`
/// (`blockchain.cpp` *"pqc_auths count N does not match input count"*,
/// `!is_archival_serve_credit_only`). The serve-credit exception is H20's
/// (*must be zero*); the bond-post and emission counts are H21's and H22's
/// (module section docs). Evaluated on every class; decides on `Spend`.
pub(crate) struct I8;

impl Rule for I8 {
    const ROW: CenRow = CenRow::I8;
}

impl TxRule for I8 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if !matches!(cx.class, TxClass::Spend { .. }) {
            return Ok(());
        }
        let auths = match &cx.tx.ct {
            Ct::Fcmp { pqc_auths, .. } => pqc_auths.len(),
            Ct::Null(_) => 0,
        };
        if auths != cx.tx.prefix.inputs.len() {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-I9, the regular spend's arm: `pseudoOuts.len() == vin.len()`
/// (`blockchain.cpp` *"pseudoOuts count N does not match input count"*).
/// The archival shapes count their spend subset under H21/H22 (the census
/// row's own words). A spend with no prunable region has no pseudo-outs and
/// is refused here; the storage-pruned form is not a shape consensus
/// admits at connect.
pub(crate) struct I9;

impl Rule for I9 {
    const ROW: CenRow = CenRow::I9;
}

impl TxRule for I9 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if !matches!(cx.class, TxClass::Spend { .. }) {
            return Ok(());
        }
        let pseudo_outs = match &cx.tx.ct {
            Ct::Fcmp {
                prunable: Some(p), ..
            } => p.pseudo_outs.len(),
            _ => 0,
        };
        if pseudo_outs != cx.tx.prefix.inputs.len() {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-I14, the regular spend's arm: the FCMP++ membership proof is
/// non-empty (`blockchain.cpp` *"has empty proof"*, step 4 of the regular
/// arm). The archival shapes carry the same presence test inside H21
/// (bond post: present) and H22 (emission: present iff fee spends); the
/// serve-credit response must carry none (H20). Presence only — what the
/// proof proves is CEN-I15's, in `tx_against` with the tree.
pub(crate) struct I14;

impl Rule for I14 {
    const ROW: CenRow = CenRow::I14;
}

impl TxRule for I14 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if !matches!(cx.class, TxClass::Spend { .. }) {
            return Ok(());
        }
        let present = matches!(
            &cx.tx.ct,
            Ct::Fcmp { prunable: Some(p), .. } if !p.fcmp_proof.is_empty()
        );
        if !present {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// The least a multisig key blob can be: the container header
/// (`tx_pqc_verify.cpp:56` `MULTISIG_KEY_HEADER_LEN = 3` — version,
/// `n_total`, `threshold`). The exact container parse is `shekyl_crypto_pq::
/// multisig`'s, run by CEN-I17/I18 when the signature is verified; this
/// bound is the structural floor the C++ applies before that parse.
const MULTISIG_KEY_BLOB_MIN: usize = 3;

/// CEN-I16: every `pqc_auth`'s structure (`tx_pqc_verify.cpp:161–221`) —
/// `auth_version == 1`; `flags == 0`; `scheme_id` is the solo hybrid
/// ([`HYBRID_SCHEME_ID_ED25519_ML_DSA_65`]) or the multisig container
/// ([`HYBRID_SCHEME_ID_MULTISIG`]), with **no** cross-input agreement
/// required (MSW-6 withdrawn); a solo key blob exactly
/// [`PQC_HYBRID_SINGLE_KEY_LEN`]; a multisig key blob within
/// `[MULTISIG_KEY_BLOB_MIN, PQC_MAX_PUBLIC_KEY_BLOB]`. Every class that
/// carries auths; a serve-credit response carries none (H20) and records
/// as evaluated over the empty vector. The signature blob's own bound is a
/// DoS ceiling on the wire, not a census row.
pub(crate) struct I16;

impl Rule for I16 {
    const ROW: CenRow = CenRow::I16;
}

impl TxRule for I16 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let Ct::Fcmp { pqc_auths, .. } = &cx.tx.ct else {
            return Ok(());
        };
        let refuse = || Err(InvalidBlock::new(Self::ROW, cx.locus()));
        for auth in pqc_auths {
            if auth.auth_version != 1 || auth.flags != 0 {
                return refuse();
            }
            let key = auth.hybrid_public_key.len();
            let well_formed = match auth.scheme_id {
                HYBRID_SCHEME_ID_ED25519_ML_DSA_65 => key == PQC_HYBRID_SINGLE_KEY_LEN,
                HYBRID_SCHEME_ID_MULTISIG => {
                    (MULTISIG_KEY_BLOB_MIN..=PQC_MAX_PUBLIC_KEY_BLOB).contains(&key)
                }
                _ => false,
            };
            if !well_formed {
                return refuse();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tx_inputs_tests.rs"]
mod tx_inputs_tests;
