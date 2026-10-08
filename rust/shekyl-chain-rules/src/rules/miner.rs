// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.F — the miner transaction (`CHAIN_RULES_SLICE_4.md`).
//!
//! The coinbase is judged as **one field of the block**: these are
//! block-level rules reading `block.miner_transaction`, and a refusal points
//! at [`TxSlot::Miner`] (Q6, ruled: one vocabulary for "which transaction").
//! It *also* passes `tx_form` at that slot (slice 5 Q2): the 4.H rows the
//! C++ states for every transaction (H16, H17, …) run on it under their own
//! row, and the non-coinbase rows are recorded vacuous there — so where a
//! 4.F row and a 4.H row judge the same bytes (F9/H7, F10/H17), both are
//! recorded, and neither reasons from the other having run.
//!
//! # Two kinds of row
//!
//! **Predicates** — F1, F3, F7, F9, F10 are stateless ([`FormRule`]); F4,
//! F5, F6 read the connecting height ([`BlockRule`]). The height is
//! **caller-derived** — `cx.connecting`, from the view's tip — and never
//! `Input::Gen`'s claim: F5 is the one row that *reads* the claim, and it
//! compares it to the view's height (census F4 note: "spoof closed by F5").
//!
//! **Definitions** — F13 (the base subsidy), F15 (the release-modulated
//! emission), F20 (the volume window) and F11 (genesis accepts its
//! configured emission; nothing is recomputed) are derivations
//! [`Emission::derive`] prices, not checks: the CEN-D4 shape. They record
//! their rows at the derivation site and run at every height, so coverage
//! is complete at genesis too: at height `0` the derivation is the
//! *observation* that the amount is configured (F11), which is what the
//! C++ does (`validate_miner_transaction`: `base_reward = money_in_use;
//! return true`). The priced value is F14b's operand: `rules::reward::
//! judge_emission` applies the weight penalty to it under CEN-G6's median
//! (slice 7 commit 5), and the paid reward, its split and the advanced
//! supply ride on the verdict as `PaidEmission`; [`Emission`] itself stays
//! local to `validate`.
//!
//! Four rows hold **by construction** (`RowStatus::ByConstruction`, Q4).
//! F2 (the wire admits one transaction version) and F8 (one output tag)
//! are falsified in `miner_tests`. F19 (parent state is the view's brand)
//! is falsified by the `compile_fail` doctests on `validate`. F21 is
//! [`EMISSION_SPLIT_EPOCH`].
//!
//! # What is not here
//!
//! F14/F14b (the weight penalty), F16 (the split) and G12 (the supply)
//! are `rules::reward`'s — the definition chain after the medians (slice 7
//! commit 5). F18 (the exact payout) needs F17's `miner_fee_income` and is
//! wave B's. F17's operand `n` is the **closed archival-shard count** at
//! parent state ([`closed_shards_before`]): the shards of `W` archival
//! bytes the parent chain's fold has filled (`SHT-Q2`;
//! `ARCHIVAL_PRUNED_DAEMON_MODE.md` PDM-Q6 item 4; DRS-E4 `ARW-Q6`). The
//! C++ template still reads its own partition — the curve tree's frozen
//! J-segment count (`Blockchain::parent_frozen_segment_count`), the
//! divergence CEN-L10 rules deliberate: the LMDB store keeps no archival
//! fold, the escalation ships flat so the split is bit-identical, and the
//! C++ is deleted at cutover rather than taught a second fold. The
//! arithmetic bodies for all of them are Rust already (`shekyl-economics`,
//! adopted by the slice-4 precursor).
//!
//! # The economic parameters
//!
//! Every derivation prices with [`economics()`] — the build-generated
//! `EconomicParams` from `config/economics_params.json`, the same set the
//! C++ reaches through `shekyl_block_reward`. The set is not yet a
//! `RuleSet` field: F14b (slice 7) is the first row whose *rule* varies
//! with a parameter the penalty reads, and the lift belongs to the slice
//! that needs it (rule 21 — no pre-provisioned field without a consumer).

use std::sync::OnceLock;

use shekyl_ct_balance::{check_commitment_masks, check_output_keys, MaskSubject};
use shekyl_economics::params::TX_VOLUME_WINDOW;
use shekyl_economics::{
    base_block_reward, effective_emission, tail_subsidy_per_block, CirculatingSupply,
    ClosedShardCount, EconomicParams, TxVolume,
};
use shekyl_types::{shard_of, BlockHeight};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Ct, Input, Transaction};

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, Fault, ViewRead};
use crate::rules::{recorded, BlockContext, BlockRule, FormContext, FormRule, Rule};
use crate::verdict::{InvalidBlock, Locus, TxSlot, Verdict};
use crate::view::ChainView;

/// The refusal locus of every 4.F predicate: the miner transaction.
const MINER: Locus = Locus::Tx {
    slot: TxSlot::Miner,
};

/// The economic parameters the 4.F derivations price with: the
/// build-generated set (`config/economics_params.json` →
/// `EconomicParams::default()`), resolved once and checked once — a set
/// whose tail subsidy does not fit cannot price any block, and stops here
/// rather than in a rule (module docs). See the module docs for why this
/// is not a `RuleSet` field yet.
pub(crate) fn economics() -> &'static EconomicParams {
    static PARAMS: OnceLock<EconomicParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let params = EconomicParams::default();
        assert!(
            tail_subsidy_per_block(&params).is_ok(),
            "config/economics_params.json: final_subsidy_per_minute × (daa_target_seconds / 60) \
             does not fit u64 — the tail subsidy cannot be priced"
        );
        params
    })
}

/// CEN-F21: the height the staker share's decay is measured from
/// (`genesis_ng_height`). One on every issued chain — the C++ returns the
/// one-row hardfork table's height, and
/// `the_emission_split_epoch_is_the_hardfork_tables_first_row` pins this
/// constant to those three tables.
///
/// CEN-F16 passes it to `shekyl_economics::compute_emission_split`
/// (`rules::reward::judge_emission`, slice 7 commit 5). It
/// becomes a [`crate::RuleSet`] field when a schedule step names a different
/// epoch. Until then a field would be copied into every rule-set mismatch
/// and no row would read it.
///
/// Public since E6 slice 6 for the same one reason as [`tx_volume_window`]:
/// the producer's split (`shekyl-block-template`) is priced at the epoch
/// the validator will judge, read here, not restated.
pub const EMISSION_SPLIT_EPOCH: BlockHeight = BlockHeight::from_raw(1);

// ---------------------------------------------------------------------------
// Stateless predicates (form)
// ---------------------------------------------------------------------------

/// CEN-F1: the coinbase has exactly one input, and it is `txin_gen`.
pub(crate) struct F1;

impl Rule for F1 {
    const ROW: CenRow = CenRow::F1;
}

impl FormRule for F1 {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        match cx
            .candidate
            .block
            .miner_transaction
            .prefix
            .inputs
            .as_slice()
        {
            [Input::Gen(_)] => Ok(()),
            _ => Err(InvalidBlock::new(Self::ROW, MINER)),
        }
    }
}

/// CEN-F3: the coinbase's CT type is `Null` — no FCMP++ signature
/// material. The one shape the wire admits for a coinbase's balance leg.
pub(crate) struct F3;

impl Rule for F3 {
    const ROW: CenRow = CenRow::F3;
}

impl FormRule for F3 {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        match cx.candidate.block.miner_transaction.ct {
            Ct::Null(_) => Ok(()),
            Ct::Fcmp { .. } => Err(InvalidBlock::new(Self::ROW, MINER)),
        }
    }
}

/// CEN-F7: the coinbase's output amounts sum without overflow
/// (`check_outs_overflow`). A `checked_add` fold; the amounts are
/// cleartext on a coinbase, so the sum is a `u64` question.
pub(crate) struct F7;

impl Rule for F7 {
    const ROW: CenRow = CenRow::F7;
}

impl FormRule for F7 {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        let mut sum = 0u64;
        for output in &cx.candidate.block.miner_transaction.prefix.outputs {
            sum = match sum.checked_add(output.amount) {
                Some(sum) => sum,
                None => return Err(InvalidBlock::new(Self::ROW, MINER)),
            };
        }
        Ok(())
    }
}

/// CEN-F9: every coinbase output key is a canonical, prime-order,
/// non-identity point (`GENESIS_TX_WIRE_FORMAT.md` §2.3). Adopted:
/// `shekyl_ct_balance::check_output_keys`, the body the C++
/// `check_outs_valid` marshals to.
pub(crate) struct F9;

impl Rule for F9 {
    const ROW: CenRow = CenRow::F9;
}

impl FormRule for F9 {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        let keys = flat_keys(&cx.candidate.block.miner_transaction);
        match check_output_keys(&keys) {
            Ok(()) => Ok(()),
            Err(_) => Err(InvalidBlock::new(Self::ROW, MINER)),
        }
    }
}

/// CEN-F10: one commitment mask per output; each canonical prime-order,
/// not the identity, not `G`, and not `zeroCommit(amount)` — the
/// amount-leaking fingerprint (`GENESIS_TX_WIRE_FORMAT.md` §2.3). Adopted:
/// `shekyl_ct_balance::check_commitment_masks` under
/// [`MaskSubject::Coinbase`] — the subject is this rule's to state, never
/// a caller's selection (slice 4 precursor S27). The arity clause is the
/// same call (S25).
pub(crate) struct F10;

impl Rule for F10 {
    const ROW: CenRow = CenRow::F10;
}

impl FormRule for F10 {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        let tx = &cx.candidate.block.miner_transaction;
        let masks = flat_masks(tx);
        let amounts: Vec<u64> = tx.prefix.outputs.iter().map(|o| o.amount).collect();
        let subject = MaskSubject::Coinbase { amounts: &amounts };
        match check_commitment_masks(&masks, tx.prefix.outputs.len(), subject) {
            Ok(()) => Ok(()),
            Err(_) => Err(InvalidBlock::new(Self::ROW, MINER)),
        }
    }
}

/// The output keys as one `N × 32` buffer, the shape `check_output_keys`
/// takes.
fn flat_keys(tx: &Transaction) -> Vec<u8> {
    tx.prefix
        .outputs
        .iter()
        .flat_map(|o| o.key.iter().copied())
        .collect()
}

/// The commitment masks as one `N × 32` buffer, from whichever CT arm the
/// transaction carries (F3 has already refused a coinbase that is not
/// `Null`; this stays total so F10 never reads past a refusal).
fn flat_masks(tx: &Transaction) -> Vec<u8> {
    let base = match &tx.ct {
        Ct::Null(base) | Ct::Fcmp { base, .. } => base,
    };
    base.commitments
        .iter()
        .flat_map(|m| m.iter().copied())
        .collect()
}

// ---------------------------------------------------------------------------
// View-bound predicates (validate)
// ---------------------------------------------------------------------------

/// CEN-F4: the coinbase has exactly one output; genesis is exempt. The
/// height is the connecting height — caller-derived — never the coinbase's
/// own claim (that is F5's subject).
pub(crate) struct F4;

impl Rule for F4 {
    const ROW: CenRow = CenRow::F4;
}

impl BlockRule for F4 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        if cx.connecting.is_zero()
            || cx.candidate().block.miner_transaction.prefix.outputs.len() == 1
        {
            Ok(Ok(()))
        } else {
            Ok(Err(InvalidBlock::new(Self::ROW, MINER)))
        }
    }
}

/// CEN-F5: `txin_gen.height` equals the block's chain position. The one
/// row that reads the coinbase's height claim, and it reads it only to
/// compare against the view's — which is why F4 and F6 may trust
/// `cx.connecting` (the spoof closure). F1 has established there is
/// exactly one `Gen` input; this stays total for any shape.
pub(crate) struct F5;

impl Rule for F5 {
    const ROW: CenRow = CenRow::F5;
}

impl BlockRule for F5 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        match cx
            .candidate()
            .block
            .miner_transaction
            .prefix
            .inputs
            .as_slice()
        {
            [Input::Gen(claimed)] if *claimed == cx.connecting.to_raw() => Ok(Ok(())),
            _ => Ok(Err(InvalidBlock::new(Self::ROW, MINER))),
        }
    }
}

/// CEN-F6: the coinbase's `unlock_time` equals `height + window`, the
/// window being the rule set's [`mined_money_unlock_window`]
/// (`RuleSet::mined_money_unlock_window`; 60 — Q5). The sum is checked: a
/// height near `u64::MAX` is not a chain any node reaches, and a wrap
/// there would compare an unlock time against a number that means nothing.
pub(crate) struct F6;

impl Rule for F6 {
    const ROW: CenRow = CenRow::F6;
}

impl BlockRule for F6 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        let window = cx.formed.rule_set().mined_money_unlock_window().to_raw();
        let expected = cx.connecting.to_raw().checked_add(window);
        let unlock = cx.candidate().block.miner_transaction.prefix.unlock_time;
        if expected == Some(unlock) {
            Ok(Ok(()))
        } else {
            Ok(Err(InvalidBlock::new(Self::ROW, MINER)))
        }
    }
}

// ---------------------------------------------------------------------------
// Definitions (priced here, recorded in coverage)
// ---------------------------------------------------------------------------

/// CEN-F11: genesis (height 0) is accepted with its configured emission —
/// structure validated by the predicates above, the amount **not
/// recomputed**. Recorded when [`Emission::derive`] observes genesis; the
/// "as configured" identity half of the row is CEN-E1's at the height-0
/// anchor (Q3 (a)).
pub(crate) struct F11;

impl Rule for F11 {
    const ROW: CenRow = CenRow::F11;
}

/// CEN-F13: the base subsidy — the emission curve at the parent's gross
/// accumulator, floored at the tail (`shekyl_economics::base_block_reward`,
/// adopted). A definition row: the value, not a check.
pub(crate) struct F13;

impl Rule for F13 {
    const ROW: CenRow = CenRow::F13;
}

/// CEN-F15: the release-modulated emission — the curve scaled by the
/// clamped volume ratio, then floored at the tail
/// (`shekyl_economics::effective_emission`, FL-R12′'s composition). A
/// definition row.
pub(crate) struct F15;

impl Rule for F15 {
    const ROW: CenRow = CenRow::F15;
}

/// CEN-F20: the volume operand — the exact window `(tx_count_sum, blocks)`
/// over the prior `min(height, W)` blocks, `(0, 0)` at genesis, formed from
/// two recorded prefix sums (two view reads, not `W`). A definition row.
pub(crate) struct F20;

impl Rule for F20 {
    const ROW: CenRow = CenRow::F20;
}

/// What the 4.F derivations established for the candidate: the emission it
/// is priced at, and the parent's gross emission it was priced from.
/// `rules::reward::judge_emission` reads both: the subsidy as F14b's
/// operand, the accumulator as G12's (the one parent read, made here and
/// not repeated — F19's single-read discipline).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Emission {
    /// The volume window the release multiplier read (CEN-F20).
    tx_volume: TxVolume,
    /// The subsidy for this height.
    subsidy: Subsidy,
    /// The parent's `coins_generated` — zero at genesis — the accumulator
    /// F13 priced from and G12 advances.
    parent_coins_generated: AtomicUnits,
}

/// The subsidy a candidate is priced at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Subsidy {
    /// Genesis: the configured emission stands; nothing is recomputed
    /// (CEN-F11).
    Configured,
    /// Every later height: the curve at the parent's accumulator.
    Derived {
        /// The base subsidy, tail-floored (CEN-F13).
        base: AtomicUnits,
        /// The release-modulated emission, tail-floored (CEN-F15). The
        /// weight penalty (F14b) applies to *this*, in slice 7.
        effective: AtomicUnits,
        /// The fee burn's two chain-state operands (CEN-F17), read at the
        /// same parent state as the accumulator.
        burn: BurnOperands,
    },
}

/// CEN-F17's operands that come from the chain rather than the block —
/// read once, at parent state, beside the accumulator (F19's single-read
/// discipline; the C++ reads both at `blockchain.cpp:5810`–`:5819` and
/// hands them to verify and the accrual alike).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BurnOperands {
    /// The circulating supply the burn ratio reads: `coins_generated −
    /// total_burned` at parent state (FL-R16c's definition, derived by the
    /// one owner; `total_burned > coins_generated` is
    /// [`Corrupt::BurnExceedsEmission`], never a zero).
    pub(crate) supply: CirculatingSupply,
    /// The D2 escalation operand `n`: the archival shards the **parent**
    /// chain has closed, [`closed_shards_before`] the connecting height —
    /// its recorded `cumulative_archival_len` over `W`, at the partition's
    /// one boundary function `shekyl_types::shard_of`.
    pub(crate) closed_shards: ClosedShardCount,
}

impl Emission {
    /// The volume window the release multiplier read (CEN-F20) — F14b's
    /// operand through `paid_block_reward`.
    pub(crate) const fn tx_volume(&self) -> TxVolume {
        self.tx_volume
    }

    /// The subsidy this candidate is priced at — F14b's other operand,
    /// and the arm (configured at genesis, derived after) the reward chain
    /// branches on.
    pub(crate) const fn subsidy(&self) -> Subsidy {
        self.subsidy
    }

    /// Derive the 4.F definitions for a candidate connecting at
    /// `connecting`, recording F11, F13, F15 and F20 as evaluated. Reads
    /// the parent's `coins_generated` and the two prefix sums that bound
    /// the volume window; at genesis reads nothing and records the
    /// configured arm.
    ///
    /// Every arithmetic here is total over the chain facts: the curve is
    /// total over `u64`, and the tail subsidy — the one operation that can
    /// fail — was priced when [`economics()`] resolved the parameters.
    pub(crate) fn derive<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
        coverage: &mut RuleCoverage,
    ) -> Result<Self, Fault<V::Fault>> {
        let params = economics();
        let tx_volume = F20::window(view, connecting, coverage)?;
        let (subsidy, parent_coins_generated) = match connecting.to_raw().checked_sub(1) {
            None => {
                coverage.insert(F11::ROW);
                coverage.insert(F13::ROW);
                coverage.insert(F15::ROW);
                (Subsidy::Configured, AtomicUnits::ZERO)
            }
            Some(parent) => {
                let parent_coins = recorded(view, BlockHeight::from_raw(parent))?.coins_generated;
                let already_generated = parent_coins.to_raw();
                let base = priced(base_block_reward(already_generated, params));
                let effective = priced(effective_emission(already_generated, tx_volume, params));
                coverage.insert(F11::ROW);
                coverage.insert(F13::ROW);
                coverage.insert(F15::ROW);
                let burn = BurnOperands::read(view, connecting, parent_coins)?;
                (
                    Subsidy::Derived {
                        base: AtomicUnits::from_raw(base),
                        effective: AtomicUnits::from_raw(effective),
                        burn,
                    },
                    parent_coins,
                )
            }
        };
        Ok(Self {
            tx_volume,
            subsidy,
            parent_coins_generated,
        })
    }

    /// The parent's gross emission (zero at genesis) — G12's operand, read
    /// once.
    pub(crate) const fn parent_coins_generated(&self) -> AtomicUnits {
        self.parent_coins_generated
    }
}

/// The archival shards closed **through** `height`: the recorded
/// `cumulative_archival_len` — every transaction's archival length in
/// blocks `0..=height` (`SHT-Q2`) — over `W`, at the partition's one
/// boundary function `shekyl_types::shard_of`. Shard `k` holds the
/// transactions whose fold-before lies in `[k·W, (k+1)·W)`, so it is closed
/// once the fold has reached `(k+1)·W`, and the closed shards are exactly
/// `0..n`.
///
/// This is the read the archival surface shares: the slash scan's universe
/// (E4 §3.7) and CEN-F17's operand ([`closed_shards_before`]) are this
/// function at two heights, and the store's discard is the same
/// `shard_of` over the same fold. Height `h` is a per-height record any
/// height `≤ tip` has, so `AboveTip` is [`Corrupt::HoleBelowTip`].
///
/// # Errors
///
/// [`ViewRead::View`] on a view fault; [`ViewRead::Corrupt`] when `height`
/// is not recorded.
pub fn closed_shards_through<'id, V: ChainView<'id>>(
    view: &V,
    height: BlockHeight,
) -> Result<ClosedShardCount, ViewRead<V::Fault>> {
    let through = recorded(view, height)?.cumulative_archival_len;
    Ok(ClosedShardCount::new(shard_of(through).to_raw()))
}

/// CEN-F17's escalation operand `n` for a block connecting at `connecting`:
/// [`closed_shards_through`] the **parent**, `connecting − 1` — the shards
/// the chain had closed before this block added to the fold. Genesis has
/// no parent and nothing before it: [`ClosedShardCount::ZERO`].
///
/// Parent state by construction, not by assertion: the read is keyed by
/// the height the candidate names, never by the tip after it connected,
/// so the block cannot move its own split (the C++ read-point's throwing
/// `db_height == block_height` check guards the same property on a store
/// whose count is not height-indexed).
///
/// **Public for the one reason [`tx_volume_window`] and
/// [`effective_median_at`](crate::effective_median_at) are**: the block
/// producer prices its coinbase at the operand the validator judges it by
/// (`shekyl-block-template` takes `closed_shards` as a context field, and
/// the caller composing that context reads it *here*), never from a second
/// copy of the definition.
///
/// # Errors
///
/// As [`closed_shards_through`], at the parent.
pub fn closed_shards_before<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
) -> Result<ClosedShardCount, ViewRead<V::Fault>> {
    match connecting.to_raw().checked_sub(1) {
        None => Ok(ClosedShardCount::ZERO),
        Some(parent) => closed_shards_through(view, BlockHeight::from_raw(parent)),
    }
}

impl BurnOperands {
    /// The two reads, at parent state, for a candidate connecting at
    /// `connecting` whose parent's accumulator is `parent_coins`.
    ///
    /// A burned fold above the accumulator is
    /// [`Corrupt::BurnExceedsEmission`]; the operand's own faults are
    /// [`closed_shards_before`]'s.
    fn read<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
        parent_coins: AtomicUnits,
    ) -> Result<Self, ViewRead<V::Fault>> {
        let total_burned = view.total_burned().map_err(ViewRead::View)?;
        let supply = CirculatingSupply::derive(parent_coins, total_burned).map_err(|_| {
            ViewRead::Corrupt(Corrupt::BurnExceedsEmission {
                coins_generated: parent_coins,
                total_burned,
            })
        })?;
        Ok(Self {
            supply,
            closed_shards: closed_shards_before(view, connecting)?,
        })
    }
}

/// Unwrap an emission whose ONLY failure is priced out by [`economics()`].
///
/// # This is safe for two functions, and it is not a general unwrapper
///
/// `base_block_reward` and `effective_emission` each have exactly one `?` —
/// `tail_subsidy_per_block(params)` — and everything else in them
/// (`curve_emission`, `calc_release_multiplier`, `apply_release_multiplier`)
/// is infallible. That failure is a function of the PARAMETERS alone, and
/// [`economics()`] asserts it away before any rule runs, so no block a peer
/// sends can reach the panic. Those are the only two call sites, and the
/// property was checked at each rather than assumed of the module.
///
/// **`emission.rs` as a whole does NOT have that property, and passing one of
/// the others here would make this `unreachable!` a panic a peer can trigger
/// in the validator.** `block_reward_with_penalty` returns
/// `EmissionError::BlockTooBig` from `current_block_weight` — a quantity read
/// off the wire — and `projected_already_generated` / `base_emission_at`
/// carry height-dependent `Overflow` arms. A validator that panics on a
/// malformed block is a remote crash, not a rejection.
///
/// **So: adding a `priced(...)` call site means re-checking that the function
/// passed has no data-dependent `Err`.** The stronger fix is a distinct
/// params-only error type so the compiler enforces this instead of a comment;
/// that changes `shekyl-economics`' public signatures and belongs to a round
/// that owns that crate, not to a chain-rules slice.
///
/// *(An earlier revision of this comment said `tail_subsidy_per_block` was
/// "the sole `?`" in `emission.rs`. That is true of these two callees and
/// false of the module, and it is exactly the sentence that would license the
/// unsafe call site above.)*
fn priced(emission: Result<u64, shekyl_economics::EmissionError>) -> u64 {
    match emission {
        Ok(value) => value,
        Err(_) => unreachable!("economics() priced the tail subsidy when the parameters resolved"),
    }
}

impl F20 {
    /// [`tx_volume_window`], recorded as evaluated.
    fn window<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
        coverage: &mut RuleCoverage,
    ) -> Result<TxVolume, Fault<V::Fault>> {
        coverage.insert(Self::ROW);
        tx_volume_window(view, connecting).map_err(Fault::from)
    }
}

/// CEN-F20's operand: `(Σ tx_hashes.len() over blocks [h − n, h − 1], n)`
/// with `n = min(h, W)`, from two prefix sums: `ctc(h − 1) − ctc(h − 1 −
/// n)`, the lower term `0` when the window reaches genesis. `(0, 0)` at
/// height 0. The window `W` is `shekyl_economics::TX_VOLUME_WINDOW` (720),
/// the constant the C++ `get_tx_volume_window` reads.
///
/// **Public for one reason** (E6 slice 6, `CHAIN_RULES_SLICE_6.md` §5.3):
/// the block producer prices its coinbase at the same volume operand the
/// validator judges it by — `shekyl-block-template` takes the window as a
/// context field, and the caller composing that context reads it *here*
/// rather than from a second copy of the two-prefix-sum definition. A
/// producer with its own copy is the divergence CEN-F18 would later catch
/// one block too late. The rule's coverage insert stays with
/// [`F20`]; this is the definition alone.
///
/// One position, [`ViewRead`]: the view's fault, or
/// [`Corrupt::TxCountNotMonotone`] when the prefix sum decreased — a store
/// that does not hold what it claims, never a saturated zero. A definition
/// raises no stale premise, so the type is the parent-side read's own
/// rather than a `Fault` with an arm that cannot occur, and rather than a
/// nested `Result` that re-encodes it.
///
/// # Errors
///
/// [`ViewRead::View`] on a view fault; [`ViewRead::Corrupt`] when a height
/// the window spans is not recorded, or the prefix sum decreased.
pub fn tx_volume_window<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
) -> Result<TxVolume, ViewRead<V::Fault>> {
    let span = tx_volume_span(connecting);
    let Some(upper_at) = span.upper else {
        return Ok(TxVolume::window(0, 0));
    };
    let prefix_sum = |at: BlockHeight| -> Result<u64, ViewRead<V::Fault>> {
        Ok(recorded(view, at)?.cumulative_tx_count)
    };
    let upper = prefix_sum(upper_at)?;
    let lower = match span.lower {
        None => 0,
        Some(at) => prefix_sum(at)?,
    };
    span.volume(upper, lower)
        .ok_or(ViewRead::Corrupt(Corrupt::TxCountNotMonotone {
            at: upper_at,
        }))
}

/// Where CEN-F20's window lies at a connecting height: how many blocks it
/// spans and whose prefix sums it subtracts. [`tx_volume_window`] is this
/// plus two reads of the store; [`tx_volume_span`] is the definition
/// without the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxVolumeSpan {
    /// Blocks in the window: `min(h, W)`, `0` at genesis.
    pub blocks: u64,
    /// The height whose prefix sum is the upper term, `h − 1`; `None` at
    /// genesis, where the window is empty.
    pub upper: Option<BlockHeight>,
    /// The height whose prefix sum is the lower term, `h − n − 1`; `None`
    /// when the window reaches genesis and the lower term is `0`.
    pub lower: Option<BlockHeight>,
}

impl TxVolumeSpan {
    /// The operand from the prefix sums read at [`Self::upper`] and
    /// [`Self::lower`], `0` for an absent term. `None` when the upper sum
    /// is below the lower.
    ///
    /// A prefix sum is non-decreasing along a conforming chain (the store
    /// folds it under SI-8). A decrease is not a small window, it is a
    /// record that does not hold what it claims — a fault for the caller to
    /// raise, never a saturated zero that `calc_release_multiplier` would
    /// price as a dormant chain.
    #[must_use]
    pub fn volume(self, upper_sum: u64, lower_sum: u64) -> Option<TxVolume> {
        upper_sum
            .checked_sub(lower_sum)
            .map(|sum| TxVolume::window(sum, self.blocks))
    }
}

/// [`TxVolumeSpan`] at `connecting`: `n = min(h, W)` blocks, `[h − n, h − 1]`.
#[must_use]
pub fn tx_volume_span(connecting: BlockHeight) -> TxVolumeSpan {
    let h = connecting.to_raw();
    let Some(parent) = h.checked_sub(1) else {
        return TxVolumeSpan {
            blocks: 0,
            upper: None,
            lower: None,
        };
    };
    let blocks = h.min(TX_VOLUME_WINDOW);
    // `h >= blocks`, so `h - blocks` is the first height in the window;
    // its predecessor's prefix sum is the lower term, absent when the
    // window starts at genesis.
    let first_in_window = h - blocks;
    TxVolumeSpan {
        blocks,
        upper: Some(BlockHeight::from_raw(parent)),
        lower: first_in_window.checked_sub(1).map(BlockHeight::from_raw),
    }
}

#[cfg(test)]
#[path = "miner_tests.rs"]
mod miner_tests;
