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
//! C++ reaches the coinbase through three block-side 4.H calls (H12, H15,
//! H17) and states the rest for non-coinbase transactions; so a rule scoped
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
use crate::rules::{Rule, TxContext, TxRule, TxScope};
use crate::verdict::{InvalidBlock, Verdict};
use shekyl_economics::FULL_REWARD_ZONE;

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
/// timestamp (`Blockchain::check_tx_outputs`, which the C++ runs on the
/// coinbase too, before its non-coinbase path). Every transaction.
pub(crate) struct H16;

impl Rule for H16 {
    const ROW: CenRow = CenRow::H16;
}

impl TxRule for H16 {
    const SCOPE: TxScope = TxScope::All;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        if cx.tx.prefix.unlock_time >= UNLOCK_TIME_SENTINEL {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tx_tests.rs"]
mod tx_tests;
