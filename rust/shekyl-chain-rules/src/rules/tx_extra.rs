// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.I, the `tx_extra` rows — CEN-I19 (the PQC field shape every
//! transaction carries) and CEN-I20 (the coinbase's closed grammar) —
//! adopted from `shekyl_wire::tx_extra` (`CHAIN_RULES_SLICE_6.md` commit 3).
//!
//! **Adopted, not restated.** The wire crate owns the parser and both shape
//! predicates (TXE, `TX_EXTRA_RUST_CUTOVER.md`); the C++ reaches them
//! through one adapter, `check_tx_extra_shape` → `shekyl_tx_extra_shape_of`,
//! from `check_tx_semantic` (`cryptonote_core.cpp`) and from the coinbase
//! prevalidation (`blockchain.cpp`). These two rules call the same
//! functions the adapter calls, so a grammar change is one edit in one
//! crate and the validator cannot drift from the wire.
//!
//! **Where the two rows meet.** The C++ emits one refusal; the census splits
//! it by subject. I19 is the per-output PQC fields — exactly one `0x06` of
//! `1120·n` and one `0x07` of `64·n` iff `n > 0`, each `0x07` entry's
//! leading point canonical — and *"`tx_extra` must parse"*. I20 is the
//! coinbase grammar, judged at [`TxSlot::Miner`](crate::TxSlot) only
//! ([`TxScope::Coinbase`], slice 6 Q6). The census words *"off the coinbase,
//! no `0x02` at all"* under I20; that clause is decided on a **listed**
//! transaction, which a `Coinbase`-scoped rule never sees, and the C++ emits
//! it from I19's site (`ExtraSubject::General`). The crate therefore refuses
//! a stray nonce on **I19**, and the census cell moves the clause with
//! commit 10 — a relocation of wording between two rows the same adapter
//! serves, disclosed in §5 row 3, not a rule change.
//!
//! **Order.** In `check_tx_semantic` the shape check follows `check_outs_valid`
//! (H7) and `outPk == vout` (H8) and precedes `check_money_overflow` (H9):
//! `tx_form` runs I19 and I20 between H7 and H9 for the same reason it keeps
//! the rest of the C++'s order — it decides *which* row refuses a
//! transaction that breaks several.

use crate::census::CenRow;
use crate::rules::{Rule, TxContext, TxKind, TxRule, TxScope};
use crate::verdict::{InvalidBlock, Verdict};
use shekyl_wire::tx_extra::{
    check_coinbase_extra_shape, check_pqc_field_shape_of, check_tx_extra_shape, parse,
    ExtraSubject, TxExtraField,
};

/// The parsed `extra`, or `None` when it does not parse — an unknown tag, a
/// truncated field. Both rules parse; the extra is bounded
/// (`MAX_TX_EXTRA`) and the parse is a fraction of what either verifies
/// against, so a shared field on [`TxContext`] would buy nothing but a
/// context change.
fn fields(cx: &TxContext<'_>) -> Option<Vec<TxExtraField>> {
    parse(&cx.tx.prefix.extra).ok()
}

/// CEN-I19: `tx_extra` parses, and with `n = vout.len()` carries exactly one
/// `0x06` KEM-ciphertext field of `1120·n` bytes and exactly one `0x07`
/// leaf-entry field of `64·n` bytes when `n > 0`, neither when `n == 0`,
/// every `0x07` entry's leading 32 bytes a canonical prime-order
/// non-identity point (`PL-D3`). Every transaction, the coinbase included
/// (`prevalidate_miner_transaction` runs the same adapter).
///
/// On a listed transaction the subject is [`ExtraSubject::General`], which
/// also refuses a `0x02` nonce — the clause the census files under I20 and
/// the C++ emits here (module docs). On the coinbase the grammar is I20's,
/// so this rule checks the PQC fields alone and leaves the nonce and the
/// pubkey to it.
pub(crate) struct I19;

impl Rule for I19 {
    const ROW: CenRow = CenRow::I19;
}

impl TxRule for I19 {
    const SCOPE: TxScope = TxScope::All;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let Some(fields) = fields(cx) else {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        };
        let n_outputs = cx.tx.prefix.outputs.len();
        let passes = match cx.kind {
            TxKind::Coinbase => check_pqc_field_shape_of(&fields, n_outputs).is_ok(),
            TxKind::Listed => {
                check_tx_extra_shape(&fields, n_outputs, ExtraSubject::General).is_ok()
            }
        };
        if passes {
            Ok(())
        } else {
            Err(InvalidBlock::new(Self::ROW, cx.locus()))
        }
    }
}

/// CEN-I20: the coinbase's `extra` is exactly `[0x01 pubkey(32), 0x02
/// nonce(8), 0x06 KEM(1120·n), 0x07 leaf(64·n)]` in that order for
/// `n = vout.len() > 0`, exactly the first two when `n == 0`, and nothing
/// else (`TXE-Q6′`, ruled 2026-09-23; `check_coinbase_extra_shape`). The
/// whitelist is the rule, so an addition is a consensus amendment.
///
/// Judged at `Miner` and nowhere else — [`TxScope::Coinbase`]'s pin: a
/// coinbase-shaped body at `Lone` is not this rule's to admit (its nonce is
/// refused by I19's `General` subject; its `Gen` input by the non-coinbase
/// rows), and a non-coinbase body at `Miner` is refused here for lacking the
/// grammar, whatever its inputs say.
pub(crate) struct I20;

impl Rule for I20 {
    const ROW: CenRow = CenRow::I20;
}

impl TxRule for I20 {
    const SCOPE: TxScope = TxScope::Coinbase;

    fn check(cx: &TxContext<'_>) -> Verdict<()> {
        let Some(fields) = fields(cx) else {
            // An unparseable extra is I19's refusal; I19 runs first and
            // this arm is unreachable in `tx_form`'s order — kept so the
            // rule is total on its own, not by the order of another.
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        };
        check_coinbase_extra_shape(&fields, cx.tx.prefix.outputs.len())
            .map_err(|_| InvalidBlock::new(Self::ROW, cx.locus()))
    }
}

#[cfg(test)]
#[path = "tx_extra_tests.rs"]
mod tx_extra_tests;
