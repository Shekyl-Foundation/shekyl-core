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
use shekyl_wire::{Input, Transaction};

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
    BondPost {
        /// The bond post's input index.
        post: usize,
        /// The co-resident `ToKey` spends.
        spends: usize,
    },
    /// One reward emission, with its optional fee spends (C-1 Q11).
    Emission {
        /// The emission's input index.
        at: usize,
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
    bond_post_at: usize,
    emission_at: usize,
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
        for (i, input) in inputs.iter().enumerate() {
            match input {
                Input::Gen(_) => n.gen += 1,
                Input::ToKey { .. } => n.spends += 1,
                Input::ServeCredit { .. } => n.credits += 1,
                Input::BondPost(_) => {
                    n.bond_posts += 1;
                    n.bond_post_at = i;
                }
                Input::ArchivalRewardEmission { .. } => {
                    n.emissions += 1;
                    n.emission_at = i;
                }
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
                post: n.bond_post_at,
                spends: n.spends,
            }
        } else if n.emissions == 1 {
            Self::Emission {
                at: n.emission_at,
                spends: n.spends,
            }
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

/// CEN-H9: the output amounts sum without overflow (`check_outs_overflow`
/// → `check_money_overflow`; run on the coinbase from
/// `prevalidate_miner_transaction`, where CEN-F7 judges the same sum under
/// its own row). Every transaction. `checked_add`, never saturating: an
/// overflow is a refusal, not a smaller number.
pub(crate) struct H9;

impl Rule for H9 {
    const ROW: CenRow = CenRow::H9;
}

impl TxRule for H9 {
    const SCOPE: TxScope = TxScope::All;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let sum = cx
            .tx
            .prefix
            .outputs
            .iter()
            .try_fold(0u64, |acc, out| acc.checked_add(out.amount));
        if sum.is_none() {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
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

#[cfg(test)]
#[path = "tx_tests.rs"]
mod tx_tests;
