// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.H — the transaction on its own (`CHAIN_RULES_SLICE_5.md`).
//!
//! Everything about one transaction that is decidable from its bytes alone,
//! with no chain state: the C++ `ver_non_input_consensus`
//! (`tx_verification_utils.cpp`) and its callees, which the C++ runs at
//! pool admission and again at block connect over the pool supplement
//! (CEN-G3). Here that is one function, [`tx_form`](crate::tx_form), and
//! these are its rules — [`TxRule`]s, each stating its [`TxScope`], each
//! refusing at the slot the caller judged ([`TxContext::locus`]: the pool's
//! `TxSlot::Lone`, `validate`'s `Miner` / `Listed(n)`).
//!
//! # The coinbase
//!
//! `validate` runs `tx_form` on the miner transaction too (slice 5 Q2). The
//! C++ reaches the coinbase through four block-side 4.H calls in
//! `prevalidate_miner_transaction` (`check_outs_overflow` H9,
//! `check_output_types` H12, `check_outs_valid` H7,
//! `check_commitment_mask_valid` H17 — `blockchain.cpp:1437–1458`) and
//! states the rest, `check_tx_outputs` included, for the non-input
//! consensus path only; so a rule scoped
//! `NonCoinbase` is recorded **vacuous** on the coinbase — the row was
//! evaluated, and holds trivially — and a rule scoped `All` runs again on
//! the coinbase under its own row even where a 4.F row (F8, F9, F10) judged
//! the same bytes. Two rows, one body, both recorded; no cross-family
//! "already checked" reasoning inside the validator.
//!
//! "The coinbase" here is a **position** — [`TxKind::of`] the slot — not a
//! shape: a sole-`gen` transaction in a listed or lone slot is
//! coinbase-shaped and is judged as a non-coinbase transaction, which is
//! how CEN-H5 gets to refuse it (Q2 as amended).
//!
//! # The wire twin
//!
//! Fourteen of these rows already run in Rust as
//! `shekyl_wire::Transaction::validate` — a row-less twin of the C++ that
//! the **wallet** calls and the daemon's Rust never does (slice 5 §3.1). The
//! rules here are the rule of record; the twin is held to them by the
//! conformance test in `tx_tests` (Q1 as ruled: every `Err(` arm of the
//! twin classified parse or rule→row, none sampled).

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::rules::{Rule, TxContext, TxKind, TxRule, TxScope};
use crate::verdict::{InvalidBlock, Locus, TxSlot, Verdict};
use shekyl_economics::FULL_REWARD_ZONE;
use shekyl_units::AtomicUnits;
use shekyl_wire::{Ct, Input, Transaction};

// ---- the classification -------------------------------------------------

/// What the inputs make a transaction — the C++ `classify_archival_tx`
/// (`cryptonote_basic.h`), single-sourced with `check_inputs_types_supported`
/// so every shape rule reads one classification (slice 5 Q4). A rule-side
/// notion, not the wire's: it says which 4.H shape applies.
///
/// Derived once per transaction by [`TxClass::derive`], which judges
/// **CEN-H5's `gen` half** (a `gen` input outside the coinbase position) and
/// **CEN-H6** (the archival mixings) as it counts — the two rows whose
/// statement *is* the classification's well-formedness — so a class exists
/// only for a transaction that passed both, and no consumer needs an
/// unreachable arm for a mixed shape. Total on every input vector,
/// including the empty one (CEN-H4's, refused after).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxClass {
    /// The coinbase position holding a sole `gen` (CEN-F1's shape).
    Coinbase,
    /// Key-imaged `ToKey` spends and nothing else — the ordinary spend, or
    /// an empty input vector (H4 refuses it next).
    Spend {
        /// How many.
        spends: usize,
    },
    /// Serve-credit responses and nothing else (gate-2 §5).
    ServeCreditOnly {
        /// How many.
        credits: usize,
    },
    /// One bond post, with its funding spends (E3 Q3 arity 1).
    ///
    /// `credit` and `debit` are that post's terms, copied at derivation.
    /// The class does not store an index back into the input vector: H6 has
    /// already required exactly one post, and a later lookup that failed
    /// would be a bug in this function reported as the transaction's refusal.
    BondPost {
        /// The co-resident `ToKey` spends.
        spends: usize,
        /// `bond_credit` of the one post.
        credit: u64,
        /// `bond_debit` of the one post.
        debit: u64,
    },
    /// One reward emission, with its optional fee spends (C-1 Q11).
    Emission {
        /// The co-resident `ToKey` spends.
        spends: usize,
    },
}

/// The input counts one pass over the vector yields.
#[derive(Default)]
struct Counts {
    gen: usize,
    spends: usize,
    credits: usize,
    bond_posts: usize,
    emissions: usize,
    credit: u64,
    debit: u64,
}

impl TxClass {
    /// Derive the class, judging H5 (`gen` half) and H6 at the site.
    pub(crate) fn derive(
        tx: &Transaction,
        slot: TxSlot,
        kind: TxKind,
        coverage: &mut RuleCoverage,
    ) -> Verdict<Self> {
        let locus = Locus::Tx { slot };
        let inputs = &tx.prefix.inputs;
        // The coinbase position holding what CEN-F1 requires of it. Anything
        // else at that slot is F1's refusal in `form`, before this runs; if
        // it arrives here it is classified as its inputs say, totally.
        if kind == TxKind::Coinbase && matches!(inputs.as_slice(), [Input::Gen(_)]) {
            coverage.insert(H5::ROW);
            coverage.insert(H6::ROW);
            return Ok(Self::Coinbase);
        }
        let mut n = Counts::default();
        for input in inputs {
            match input {
                Input::Gen(_) => n.gen += 1,
                Input::ToKey { .. } => n.spends += 1,
                Input::ServeCredit { .. } => n.credits += 1,
                Input::BondPost(bond) => {
                    n.bond_posts += 1;
                    n.credit = bond.bond_credit;
                    n.debit = bond.bond_debit;
                }
                Input::ArchivalRewardEmission { .. } => n.emissions += 1,
            }
        }
        // CEN-H5, the `gen` half: `txin_gen` is forbidden outside the
        // coinbase position (`check_inputs_types_supported`). The script
        // variants are unrepresentable in `shekyl_wire::Input` — the row's
        // other half, by construction.
        if n.gen > 0 {
            return Err(InvalidBlock::new(H5::ROW, locus));
        }
        coverage.insert(H5::ROW);
        // CEN-H6, the archival mixings, in the C++'s order: serve credits
        // mix with nothing; at most one bond post; at most one emission;
        // emission and bond post never co-reside.
        let mixed = (n.credits > 0 && n.spends + n.bond_posts + n.emissions > 0)
            || n.bond_posts > 1
            || n.emissions > 1
            || (n.emissions == 1 && n.bond_posts > 0);
        if mixed {
            return Err(InvalidBlock::new(H6::ROW, locus));
        }
        coverage.insert(H6::ROW);
        // With H5 and H6 passed the four shapes are exhaustive.
        Ok(if n.credits > 0 {
            Self::ServeCreditOnly { credits: n.credits }
        } else if n.bond_posts == 1 {
            Self::BondPost {
                spends: n.spends,
                credit: n.credit,
                debit: n.debit,
            }
        } else if n.emissions == 1 {
            Self::Emission { spends: n.spends }
        } else {
            Self::Spend { spends: n.spends }
        })
    }
}

/// CEN-H5: the input-variant whitelist — `gen` only in the coinbase
/// position (judged at [`TxClass::derive`]); the script variants
/// unrepresentable (`by_construction` on `shekyl_wire::Input`).
pub(crate) struct H5;

impl Rule for H5 {
    const ROW: CenRow = CenRow::H5;
}

/// CEN-H6: the archival vin mixings, judged at [`TxClass::derive`] —
/// single-sourced with the classification, as the C++ single-sources it.
pub(crate) struct H6;

impl Rule for H6 {
    const ROW: CenRow = CenRow::H6;
}

// ---- the limits ---------------------------------------------------------
//
// Frozen constants beside the rules that read them, not `RuleSet` fields
// (slice 5 Q5 as amended, on the F21 ground): a limit joins the rule set
// when a schedule step can name a different one, and none of these can —
// the C++ NIC's HF dispatch collapses to one arm at HF1. Each is pinned to
// its `cryptonote_config.h` `#define` by parsing the header (`tx_tests`),
// and to the wire crate's copy of the same number by an equality test,
// so the codec's DoS bound and the consensus limit cannot drift apart
// without a test saying so — and so the rule's source is the C++
// definition, never the codec (§3.1).

/// CEN-H1: the serialized size a transaction may not exceed —
/// `CRYPTONOTE_MAX_TX_SIZE`.
pub(crate) const MAX_TX_SIZE: usize = 1_000_000;

/// CEN-H3's operand: the bytes a block reserves for its coinbase —
/// `CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE`.
pub(crate) const COINBASE_BLOB_RESERVED: usize = 600;

/// CEN-H3: the weight a transaction may not exceed — **derived**, never
/// restated: half the minimum block weight (the full-reward zone,
/// `shekyl-economics`'s generated constant) less the coinbase reserve, the
/// C++ `get_transaction_weight_limit`.
pub(crate) const fn max_tx_weight() -> usize {
    // `FULL_REWARD_ZONE` is a `u64` generated from `config/`; it is a block
    // weight and fits a `usize` on every target this validator builds for.
    (FULL_REWARD_ZONE / 2) as usize - COINBASE_BLOB_RESERVED
}

/// CEN-H16: `unlock_time` values at or above this are timestamps, which
/// consensus rejects — `CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL`
/// (`CRYPTONOTE_MAX_BLOCK_NUMBER`).
pub(crate) const UNLOCK_TIME_SENTINEL: u64 = 500_000_000;

// ---- the rows -----------------------------------------------------------

/// CEN-H1: serialized size ≤ [`MAX_TX_SIZE`] (`ver_non_input_consensus`
/// rule 1). Non-coinbase: the coinbase's size is bounded through the block.
pub(crate) struct H1;

impl Rule for H1 {
    const ROW: CenRow = CenRow::H1;
}

impl TxRule for H1 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if cx.tx.serialized_len() > MAX_TX_SIZE {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-H3: weight ≤ [`max_tx_weight`] (`ver_non_input_consensus` rule 4).
/// Non-coinbase, as H1.
pub(crate) struct H3;

impl Rule for H3 {
    const ROW: CenRow = CenRow::H3;
}

impl TxRule for H3 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if cx.tx.weight() > max_tx_weight() {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-H4: a non-coinbase transaction has at least one input
/// (`core::check_tx_semantic`, `cryptonote_core.cpp`). The coinbase has
/// exactly one by CEN-F1 and is out of this row's scope.
pub(crate) struct H4;

impl Rule for H4 {
    const ROW: CenRow = CenRow::H4;
}

impl TxRule for H4 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if cx.tx.prefix.inputs.is_empty() {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-H16: `unlock_time` < [`UNLOCK_TIME_SENTINEL`] — a height, never a
/// timestamp (`Blockchain::check_tx_outputs`, reached from the non-input
/// consensus path only; the coinbase's unlock time is CEN-F6's exact
/// `height + window`). Non-coinbase — corrected at slice 5 commit 2 from
/// `All`, which had been read off the census's stale `:1692` pin rather
/// than the call site.
pub(crate) struct H16;

impl Rule for H16 {
    const ROW: CenRow = CenRow::H16;
}

impl TxRule for H16 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if cx.tx.prefix.unlock_time >= UNLOCK_TIME_SENTINEL {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-H9: the amounts sum without overflow on **both** sides
/// (`check_money_overflow` = `check_inputs_overflow && check_outs_overflow`,
/// `cryptonote_format_utils.cpp:593–632`). The input side sums only
/// `txin_to_key.amount` — `gen` and the three archival vins are skipped,
/// their value being CT-side or opaque — exactly as the census row states.
/// Run on the coinbase too (`prevalidate_miner_transaction`, where CEN-F7
/// judges the output sum under its own row). `checked_add`, never
/// saturating: an overflow is a refusal, not a smaller number.
///
/// The input half was missing at first landing and found in review (#839):
/// `ToKey.amount` is an arbitrary parsed `u64` the wire admits — FCMP++
/// gives it no meaning, which is precisely why nothing else bounds it — so
/// two inputs carrying `u64::MAX` and `1` passed here while the C++ refused.
pub(crate) struct H9;

impl Rule for H9 {
    const ROW: CenRow = CenRow::H9;
}

impl TxRule for H9 {
    const SCOPE: TxScope = TxScope::All;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let refuse = || Err(InvalidBlock::new(Self::ROW, cx.locus()));
        let inputs = cx
            .tx
            .prefix
            .inputs
            .iter()
            .try_fold(0u64, |acc, input| match input {
                Input::ToKey { amount, .. } => acc.checked_add(*amount),
                Input::Gen(_)
                | Input::ServeCredit { .. }
                | Input::BondPost(_)
                | Input::ArchivalRewardEmission { .. } => Some(acc),
            });
        if inputs.is_none() {
            return refuse();
        }
        let outputs = cx
            .tx
            .prefix
            .outputs
            .iter()
            .try_fold(0u64, |acc, out| acc.checked_add(out.amount));
        if outputs.is_none() {
            return refuse();
        }
        Ok(())
    }
}

/// CEN-H14: every output amount is `0` — confidential — except in a
/// well-formed **emission** transaction, whose loud reward vouts are the
/// commit set (`check_tx_outputs`; `REWARD_EMISSION_LEG.md` §5.5). Reads the
/// class, as the C++ reads `classify_archival_tx` rather than a bare vin
/// count, so a malformed pairing (already H6's refusal) could never exempt
/// itself. Non-coinbase: the coinbase's amounts are 4.F's.
pub(crate) struct H14;

impl Rule for H14 {
    const ROW: CenRow = CenRow::H14;
}

impl TxRule for H14 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if matches!(cx.class, TxClass::Emission { .. }) {
            return Ok(());
        }
        if cx.tx.prefix.outputs.iter().any(|out| out.amount != 0) {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-H10: no key image repeats within one transaction
/// (`check_tx_inputs_keyimages_diff`); archival vins carry none and are
/// skipped. CEN-I5's strictly-descending order (slice 6) forbids the same
/// thing; this is the inherited belt, its own cheap predicate until slice 6
/// decides whether it collapses (Q6). Non-coinbase.
pub(crate) struct H10;

impl Rule for H10 {
    const ROW: CenRow = CenRow::H10;
}

impl TxRule for H10 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let mut seen = std::collections::BTreeSet::new();
        for input in &cx.tx.prefix.inputs {
            if let Input::ToKey { key_image, .. } = input {
                if !seen.insert(*key_image) {
                    return Err(InvalidBlock::new(Self::ROW, cx.locus()));
                }
            }
        }
        Ok(())
    }
}

/// CEN-H15, the `Null` half: a non-coinbase transaction's CT is
/// `CTTypeFcmpPlusPlusPqc`, never `CTTypeNull` (`check_tx_inputs`,
/// `blockchain.cpp`: *"CTTypeNull is only allowed for coinbase"*). The type
/// *set* — nothing but those two — is unrepresentable in `shekyl_wire::Ct`
/// and holds by construction (registry).
///
/// **Unconditional here, and unconditional in the C++ too** (slice 5 Q9,
/// ruled 2026-09-23; grading corrected the same day). The C++ carries a
/// `m_nettype != FAKECHAIN` gate near this rule (`blockchain.cpp:3396`),
/// and for eight hours this comment and the CSR-3a row read it as H15's —
/// *"a Fakechain node admits `Null`-CT spends"*. It is CEN-I2's earlier
/// refusal; H15's own sites — `ver_non_input_consensus`'s `case
/// CTTypeNull` (`tx_verification_utils.cpp:223`) and `check_tx_inputs`'s
/// `switch` (`blockchain.cpp:3550`) — refuse on every nettype, and the
/// `else` at `:3539` refuses a `Null` spend on Fakechain before either. The
/// gate was read, the belt below it was not (rule 16's corollary). The
/// ruling stands on its own ground: arm (d), data on the Fakechain rule
/// set, would have made this the first 4.H rule to read one, for a
/// consumer (the proof-less C++ test builder) TXE-Q1 deletes.
pub(crate) struct H15;

impl Rule for H15 {
    const ROW: CenRow = CenRow::H15;
}

impl TxRule for H15 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if matches!(cx.tx.ct, Ct::Null(_)) {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// The bound on a BP+'s round count: `6 + log₂(MAX_OUTPUTS)`
/// (`n_bulletproof_amounts_base`: `L_size <= 6 + extra_bits`, with
/// `1 << extra_bits == max_outputs` asserted in the C++).
const BP_PLUS_MAX_ROUNDS: usize = 6 + shekyl_wire::transaction::MAX_OUTPUTS.ilog2() as usize;

/// CEN-H19, the **layout** half: the aggregate BP+ is canonical for the
/// output count — exactly one proof when there are outputs and none when
/// there are none (`outPk.size() == n_bulletproof_plus_amounts(...)`, which
/// is `0` for no proof); `|L| = |R|`, `6 ≤ |L| ≤ 6 + log₂ MAX_OUTPUTS`;
/// and the padded amount count `2^(|L|−6)` lies in `[n_out, 2·n_out)`
/// (`n_bulletproof_amounts_base`; `V` is reconstructed from the masks, so
/// `V_size = n_out` by construction). Every non-coinbase shape, the
/// archival ones included (`verArchivalCtBalanceAndRange` runs the same
/// layout check when a proof is present).
///
/// The **verification** half — the range proof itself, batched across the
/// block — lands with slice 6's proof bodies (Q3 (b)). Until then the row
/// stays `pending`, and `tx_form` runs this rule through
/// [`crate::rules::run_tx_unrecorded`]: a refusal is H19's, a pass is not
/// coverage. Slice 6 switches that call to [`crate::rules::run_tx`] and
/// flips the registry entry.
pub(crate) struct H19;

impl Rule for H19 {
    const ROW: CenRow = CenRow::H19;
}

impl TxRule for H19 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let prunable = match &cx.tx.ct {
            Ct::Fcmp { prunable, .. } => prunable.as_ref(),
            Ct::Null(_) => None,
        };
        if !Self::canonical(prunable, cx.tx.prefix.outputs.len()) {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

impl H19 {
    /// The layout predicate, on a prunable region (or none) and the output
    /// count. `true` is canonical; it decides nothing about the proof.
    pub(crate) fn canonical(prunable: Option<&shekyl_wire::Prunable>, n_out: usize) -> bool {
        let proofs = prunable.map_or(&[][..], |p| p.bulletproofs.as_slice());
        match proofs {
            [] => n_out == 0,
            [bp] => {
                let rounds = bp.l.len();
                if bp.r.len() != rounds || !(6..=BP_PLUS_MAX_ROUNDS).contains(&rounds) {
                    return false;
                }
                let padded = 1usize << (rounds - 6);
                n_out > 0 && n_out <= padded && padded < 2 * n_out
            }
            _ => false,
        }
    }
}

/// CEN-H20: the serve-credit-only CT shape (`ver_non_input_consensus`'s
/// serve-credit arm + `verCtSemanticsFeeOnly`): no `pqc_auths`, no outputs,
/// zero fee, `CTTypeFcmpPlusPlusPqc`, no spend material (no BP+, no FCMP++
/// proof, no pseudo-outs). The fee-only balance `Σ masks + fee·H = identity`
/// is then **vacuous** — no masks, `fee = 0` — which is what the C++'s call
/// into `shekyl_verify_ct_balance` with empty masks and zero fee computes,
/// so the row is complete without a curve operation. Applies to the
/// serve-credit-only class; recorded vacuous on every other class.
pub(crate) struct H20;

impl Rule for H20 {
    const ROW: CenRow = CenRow::H20;
}

impl TxRule for H20 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if !matches!(cx.class, TxClass::ServeCreditOnly { .. }) {
            return Ok(());
        }
        let refuse = || Err(InvalidBlock::new(Self::ROW, cx.locus()));
        let Ct::Fcmp {
            fee,
            pqc_auths,
            prunable,
            base,
            ..
        } = &cx.tx.ct
        else {
            return refuse();
        };
        if *fee != 0
            || !pqc_auths.is_empty()
            || !cx.tx.prefix.outputs.is_empty()
            || !base.commitments.is_empty()
        {
            return refuse();
        }
        if let Some(p) = prunable {
            if !p.bulletproofs.is_empty() || !p.fcmp_proof.is_empty() || !p.pseudo_outs.is_empty() {
                return refuse();
            }
        }
        Ok(())
    }
}

// ---- the adopted crypto rows -------------------------------------------
//
// H7, H17, H18, H21, H22 call the Rust bodies the C++ already marshals to —
// `shekyl-ct-balance` for points, masks and the plain balance,
// `shekyl-archival-retention` for the bond-post / emission balance with
// its credit-xor-debit term — so a divergence between what the pool and
// the connect path accept and what these rows accept is not possible: it
// is one function.

/// The output keys as one `N × 32` buffer, the shape `check_output_keys`
/// takes. (The miner module has its own; a shared helper would couple two
/// families for eight lines.)
fn flat_keys(tx: &Transaction) -> Vec<u8> {
    tx.prefix.outputs.iter().flat_map(|o| o.key).collect()
}

/// The commitment masks as one `N × 32` buffer, and the fee, for either CT
/// form.
fn flat_masks(tx: &Transaction) -> Vec<u8> {
    let (Ct::Null(base) | Ct::Fcmp { base, .. }) = &tx.ct;
    base.commitments.iter().flatten().copied().collect()
}

/// The pseudo-outs as one `N × 32` buffer; empty when there is no prunable
/// region.
fn flat_pseudo_outs(tx: &Transaction) -> Vec<u8> {
    match &tx.ct {
        Ct::Fcmp {
            prunable: Some(p), ..
        } => p.pseudo_outs.iter().flatten().copied().collect(),
        _ => Vec::new(),
    }
}

/// CEN-H7: every output key is a canonical, prime-order, non-identity point
/// (`check_outs_valid` → `shekyl_check_output_keys`; run on the coinbase
/// from `prevalidate_miner_transaction`, where CEN-F9 judges the same keys
/// under its own row). Every transaction.
pub(crate) struct H7;

impl Rule for H7 {
    const ROW: CenRow = CenRow::H7;
}

impl TxRule for H7 {
    const SCOPE: TxScope = TxScope::All;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if shekyl_ct_balance::check_output_keys(&flat_keys(cx.tx)).is_err() {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-H11: every key image is in the prime-order subgroup and is not the
/// identity (`check_tx_inputs_keyimages_domain`: `ki ≠ identity`,
/// `order·ki == identity`; archival vins carry no image and are skipped).
/// The predicate is `check_output_keys`'s — valid point, canonical
/// encoding, torsion-free, non-identity — which is the same set the C++
/// accepts: its decode refuses a non-canonical encoding before the order
/// check runs, and a non-canonical encoding of a spent image would
/// otherwise be a second byte string for one spend, the double-spend the
/// census's §3.4 y-normalization question circles. Non-coinbase. At 4.H
/// this is all a key image is held to; CEN-I15's proof binds it to the
/// spent output (slice 6).
pub(crate) struct H11;

impl Rule for H11 {
    const ROW: CenRow = CenRow::H11;
}

impl TxRule for H11 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let images: Vec<u8> = cx
            .tx
            .prefix
            .inputs
            .iter()
            .filter_map(|input| match input {
                Input::ToKey { key_image, .. } => Some(*key_image),
                _ => None,
            })
            .flatten()
            .collect();
        if shekyl_ct_balance::check_output_keys(&images).is_err() {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-H17: every commitment mask is a canonical prime-order point and
/// non-trivial — never the identity, never `G` — and a coinbase's mask
/// additionally differs from `zeroCommit(amount)`
/// (`check_commitment_mask_valid` → `shekyl-ct-balance`; run on the
/// coinbase from `prevalidate_miner_transaction`, where CEN-F10 judges the
/// same masks). One mask per output (the arity clause CEN-L11's grading
/// depends on). Every transaction; the subject follows the CT form.
pub(crate) struct H17;

impl Rule for H17 {
    const ROW: CenRow = CenRow::H17;
}

impl TxRule for H17 {
    const SCOPE: TxScope = TxScope::All;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        use shekyl_ct_balance::{check_commitment_masks, MaskSubject};
        let masks = flat_masks(cx.tx);
        let n_out = cx.tx.prefix.outputs.len();
        let amounts: Vec<u64>;
        let subject = match &cx.tx.ct {
            Ct::Null(_) => {
                amounts = cx.tx.prefix.outputs.iter().map(|o| o.amount).collect();
                MaskSubject::Coinbase { amounts: &amounts }
            }
            Ct::Fcmp { .. } => MaskSubject::Spend,
        };
        if check_commitment_masks(&masks, n_out, subject).is_err() {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// CEN-H18: the plain spend's cleartext balance —
/// `Σ pseudoOuts = Σ masks + fee·H`, canonical points
/// (`verCtSemanticsSimple` → `shekyl_verify_ct_balance`). Applies to the
/// spend class; the archival shapes carry their own balance (H20–H22) and
/// record this row vacuous.
pub(crate) struct H18;

impl Rule for H18 {
    const ROW: CenRow = CenRow::H18;
}

impl TxRule for H18 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if !matches!(cx.class, TxClass::Spend { .. }) {
            return Ok(());
        }
        let Ct::Fcmp { fee, .. } = &cx.tx.ct else {
            // H15 refused a `Null` spend before this ran.
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        };
        let balanced = shekyl_ct_balance::verify_ct_balance(
            &flat_pseudo_outs(cx.tx),
            &flat_masks(cx.tx),
            AtomicUnits::from_raw(*fee),
            &[],
            &[],
        );
        if balanced.is_err() {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

/// The archival balance body both H21 and H22 reach — `Σ pseudoOuts +
/// debit·H = Σ masks + fee·H + credit·H` with the credit-xor-debit term
/// (`verArchivalCtBalanceAndRange` → `shekyl_archival_verify_bond_post_ct_balance`).
/// `Err` is the row's refusal, whichever clause failed: an invalid point, a
/// sum mismatch, or both terms set.
fn archival_balance(tx: &Transaction, credit: u64, debit: u64) -> Result<(), ()> {
    use shekyl_archival_retention::bond_ct_balance::{verify_bond_post_ct_balance, BondTerm};
    let Ct::Fcmp { fee, .. } = &tx.ct else {
        return Err(());
    };
    let term = BondTerm::from_credit_debit(credit, debit).map_err(|_| ())?;
    verify_bond_post_ct_balance(&flat_pseudo_outs(tx), &flat_masks(tx), *fee, term).map_err(|_| ())
}

/// CEN-H21: the bond-post shape and balance (`ver_non_input_consensus`'s
/// bond-post arm + `verCtSemanticsBondPost`): `pqc_auths == vin count`,
/// at least one funding spend, `pseudoOuts == spend count`, a non-empty
/// FCMP++ proof, `CTTypeFcmpPlusPlusPqc`, and the balance with
/// `(credit, debit) = (bond_credit, bond_debit)`. Applies to the bond-post
/// class. **The funding-input half** — empty offsets, unspent images, the
/// FCMP++ proof over the spend subset — is 4.I's (I10–I15).
pub(crate) struct H21;

impl Rule for H21 {
    const ROW: CenRow = CenRow::H21;
}

impl TxRule for H21 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let TxClass::BondPost {
            spends,
            credit,
            debit,
        } = cx.class
        else {
            return Ok(());
        };
        let refuse = || Err(InvalidBlock::new(Self::ROW, cx.locus()));
        let Ct::Fcmp {
            pqc_auths,
            prunable: Some(prunable),
            ..
        } = &cx.tx.ct
        else {
            return refuse();
        };
        if pqc_auths.len() != cx.tx.prefix.inputs.len()
            || spends == 0
            || prunable.pseudo_outs.len() != spends
            || prunable.fcmp_proof.is_empty()
        {
            return refuse();
        }
        if archival_balance(cx.tx, credit, debit).is_err() {
            return refuse();
        }
        Ok(())
    }
}

/// CEN-H22: the emission shape and balance (`ver_non_input_consensus`'s
/// emission arm + `verCtSemanticsEmission`): the reward total is the checked
/// sum of the loud vout amounts and is positive; `pqc_auths == vin count`;
/// `pseudoOuts == fee-input count`; the FCMP++ proof is present iff fee
/// inputs are; `CTTypeFcmpPlusPlusPqc`; and the balance with the mint on the
/// debit slot — `Σ pseudoOuts + total_reward·H = Σ masks + fee·H`. The
/// checked sum is the one CEN-J24 uses (`shekyl_checked_sum_amounts`'s
/// body); H9 has already refused an overflowing sum. Applies to the emission
/// class.
pub(crate) struct H22;

impl Rule for H22 {
    const ROW: CenRow = CenRow::H22;
}

impl TxRule for H22 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let TxClass::Emission { spends, .. } = cx.class else {
            return Ok(());
        };
        let refuse = || Err(InvalidBlock::new(Self::ROW, cx.locus()));
        let Ct::Fcmp {
            pqc_auths,
            prunable,
            ..
        } = &cx.tx.ct
        else {
            return refuse();
        };
        let total_reward = cx
            .tx
            .prefix
            .outputs
            .iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.amount));
        let Some(total_reward) = total_reward.filter(|t| *t > 0) else {
            return refuse();
        };
        let (pseudo_outs, proof_present) = match prunable {
            Some(p) => (p.pseudo_outs.len(), !p.fcmp_proof.is_empty()),
            None => (0, false),
        };
        if pqc_auths.len() != cx.tx.prefix.inputs.len()
            || pseudo_outs != spends
            || proof_present != (spends > 0)
        {
            return refuse();
        }
        if archival_balance(cx.tx, 0, total_reward).is_err() {
            return refuse();
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tx_tests.rs"]
mod tx_tests;

#[cfg(test)]
#[path = "tx_conformance_tests.rs"]
mod tx_conformance_tests;
