// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.J, the bond-state rows: on a serve-credit vin
//! (`CHAIN_RULES_SLICE_8.md` §5 row 3) the named persona has a bond record
//! (CEN-J4), the credited epoch is at or past the first the persona may
//! serve (CEN-J5, `E ≥ join + 1`), and the persona is `good_through` it
//! (CEN-J6); on a bond post (§5 rows 4 and 5) the slot's key is the one the
//! post's kind selects (CEN-J13) and the post's semantics hold against the
//! record — a JoinMarket's floor and claim slot (CEN-J14), a Release's full
//! exit, cooldown and settlement (CEN-J16), a Reinstate's open interval and
//! unchanged holdings (CEN-J18) — [`judge_bond_post`] below.
//!
//! The serve-credit rows are three over **one view read per vin**,
//! [`ChainView::bond_record`], in the C++'s order — `check_tx_inputs`
//! reads the record (`get_archival_bond_hybrid_pubkey`), then its join
//! epoch against `shekyl_archival_serve_credit_epoch_ok`, then
//! `archival_bond_good_through`, which is the retention crate's
//! [`good_through`] over the record's intervals (`blockchain.cpp`, the
//! serve-credit arm; `db_lmdb.cpp`, `archival_bond_good_through_ffi`).
//!
//! **The record is read off the view the block is judged against**, as the
//! C++ reads it off the DB before the block (`check_tx_inputs` runs before
//! `add_block`). A join listed in the same block as the credit has not yet
//! written its record, so the credit is refused here on J4 — the C++'s
//! answer. The archival fold's in-block sequencing (`archival/inputs.rs`,
//! `apply_input` through `post`) saw such a join; until this module every
//! fixture pair in three crates relied on that admission, and the C++ never
//! gave it (slice 8 row 3's finding; the fixtures moved in the commit
//! before this one). The fold's L7 arm stays as the backstop beneath J4
//! (`STORE_INVARIANT_REGISTER.md` SI-15 is the store's belt beneath both).
//!
//! What these rows do **not** read: no credit count or pass bit (CEN-G7's
//! duplicate pass and the store's `pass_count`), no pruned record (CEN-J2,
//! CEN-J10), no window (CEN-J7: `H_close` and the seal, Slice C). A vin the
//! crate's one parse cannot read is CEN-J1's (Slice C) and, until then,
//! L7's at the fold; this module skips it rather than refusing it under a
//! row whose statement is about a record, not about bytes.
//!
//! The witness for J5 and J6, and for every accept, is a **driven chain** —
//! the ingest driver's `Persona::join` / `serve_credit` through `connect` —
//! never a constructed record: `MockChain` holds no bonds by policy
//! (`harness.rs`, `archival_reads!(empty)`; DRS-E4 §5.2, *No `Mock*`
//! archival state*). That policy is exactly J4's negative, so J4's refusal
//! and the three rows' vacuity off-class are the unit tests here
//! (`tx_bond_tests.rs`); the store witnesses J4 over a `Bond`-stubbed
//! session (`archival_write_tests`, ARW-9).

use shekyl_archival_retention::{
    check_admission, cold_authority_pin, good_through, serve_credit_epoch_ok,
    verify_join_market_bond_post, verify_reinstate_bond_post, verify_release_bond_post,
    whole_record_last_served, AdmissionShard, ArchivalBondPostVin, BondKind,
    BondPostKind as RetentionKind, HoldingsDescriptor, HoldingsKind, ParentStateHoldings,
    ShardClose, ShardSet, ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
};
use shekyl_types::archival::{BondRecord, Holdings};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_wire::transaction::{BondPost, Holdings as WireHoldings, PqcAuth};
use shekyl_wire::{Ct, Input};

use crate::archival::{closed_and_final, shard_close_height, BondArm, L7};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::ViewRead;
use crate::rule_set::RuleSet;
use crate::rules::body::ArchivalKey;
use crate::rules::tx::TxClass;
use crate::rules::{Rule, TxContext};
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::{ChainView, Tip};

/// CEN-J4: the persona a serve-credit vin names has a bond record on the
/// view. The C++'s `get_archival_bond_hybrid_pubkey` miss; the fold's L7
/// is the backstop beneath it.
pub(crate) struct J4;

impl Rule for J4 {
    const ROW: CenRow = CenRow::J4;
}

/// CEN-J5: the credited settlement epoch is at or past `E_first = join + 1`
/// — [`serve_credit_epoch_ok`] over the record's `join_settlement_epoch`,
/// the function the C++ calls through `shekyl_archival_serve_credit_epoch_ok`.
/// Runs before J6 because [`good_through`] is also false below `E_first`,
/// and the row that names the reason is this one.
pub(crate) struct J5;

impl Rule for J5 {
    const ROW: CenRow = CenRow::J5;
}

/// CEN-J6: the persona is `good_through` the credited epoch —
/// [`good_through`] over the record's `bad_intervals`, the function the
/// C++ calls through `shekyl_archival_good_through`. A record with an open
/// bad interval (a slash not yet reinstated from) fails here; so does a
/// closed one that covers `E`.
pub(crate) struct J6;

impl Rule for J6 {
    const ROW: CenRow = CenRow::J6;
}

const ROWS: [CenRow; 3] = [J4::ROW, J5::ROW, J6::ROW];

/// CEN-J4, CEN-J5 and CEN-J6 as one sequence over every serve-credit vin of
/// a [`TxClass::ServeCreditOnly`] transaction, in vin order, one
/// [`ChainView::bond_record`] read each. A transaction of any other class
/// records the three rows vacuous (no credit vin to judge; H6 has already
/// refused a mixed shape). A refusal names the vin ([`Locus::Input`]).
///
/// # Errors
///
/// The view's fault, from the record read.
pub(crate) fn judge_serve_credit_bond<'id, V: ChainView<'id>>(
    cx: &TxContext<'_>,
    view: &V,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, V::Fault> {
    if matches!(cx.class, TxClass::ServeCreditOnly { .. }) {
        for (input, item) in cx.tx.prefix.inputs.iter().enumerate() {
            if !matches!(item, Input::ServeCredit { .. }) {
                continue;
            }
            // A vin that does not parse is J1's (Slice C), module docs.
            let Some(ArchivalKey::ServeCredit { p, epoch, .. }) = ArchivalKey::of(item) else {
                continue;
            };
            let locus = Locus::Input {
                slot: cx.slot,
                input,
            };
            let Some(record) = view.bond_record(&PCanonicalId::from_bytes(p))? else {
                return Ok(Err(InvalidBlock::new(J4::ROW, locus)));
            };
            // The retention predicates take the raw epochs (an FFI-shaped
            // surface the C++ calls too); the typed record is read here and
            // unwrapped at this edge only.
            let join = record.join_settlement_epoch.to_raw();
            if !serve_credit_epoch_ok(epoch, join) {
                return Ok(Err(InvalidBlock::new(J5::ROW, locus)));
            }
            if !good_through(join, epoch, &record.bad_intervals) {
                return Ok(Err(InvalidBlock::new(J6::ROW, locus)));
            }
        }
    }
    for row in ROWS {
        coverage.insert(row);
    }
    Ok(Ok(()))
}

// ---- CEN-J13, J14, J16, J18: the bond post against its record ----------
// ---- (slice 8 rows 4 and 5) ---------------------------------------------

/// CEN-J13: the bond slot's `pqc_auths[i].hybrid_public_key` is the key
/// the post's kind selects. A **Release** (the debit arm) authorizes only
/// against the record's committed `bond_spend_pk` — the retention crate's
/// [`cold_authority_pin`], the function the C++ calls through
/// `shekyl_archival_cold_authority_pin`, which also refuses a record that
/// commits no key (`RecordCommitsNoKey`: the identity key never authorizes
/// a value-out). A **JoinMarket** or **Reinstate** (the credit arms)
/// authorizes with the identity key, `P_pubkey` — the post's own
/// `hybrid_public_key` (`blockchain.cpp`, *"credit-path pqc auth key does
/// not match the identity key P_pubkey"*).
///
/// The slot's signature is I18's; this row asks **which key** signed, and
/// without it I18 verifies a Release against whatever key the slot carries
/// — another persona's Release of a bonded record, signed by the poster's
/// own identity key, connected and H21 paid the record's collateral to the
/// poster (slice 8 row 2's finding, the hint finding's money form; the pin
/// at `archival_hint_tests.rs` flips with this rule). The pool
/// refused the relayed form through the submit verifier; a block carrying
/// one did not meet this pin anywhere in `shekyl-chain-rules`.
///
/// Reads the record **off the view before the block**, as J4 does and as
/// the C++ reads the DB: a Release for a persona with **no record** is not
/// this row's — the C++ gates the pin on `have_record`
/// (`blockchain.cpp:4509–4515`), so the pin passes and the semantic
/// verify's `RECORD_MISSING` refuses, which is [`J16`]'s. (Row 4 wrote
/// *"which here is the fold's L7"*; true until row 5 landed J16 ahead of
/// the fold — records-was.) A kind no arm names is [`L7`]'s, in this
/// sequence and at the fold; this row judges the three kinds the C++
/// function has arms for. A bond post whose `pqc_auths` has no slot at the
/// vin is this row too, at the point the arm reads the slot — after that
/// arm's non-slot check, so a JoinMarket whose statics fail is still
/// [`J14`]'s and a Reinstate whose terms fail is still [`J18`]'s.
pub(crate) struct J13;

impl Rule for J13 {
    const ROW: CenRow = CenRow::J13;
}

/// CEN-J14: a JoinMarket post's statics against the record's absence —
/// the retention crate's [`verify_join_market_bond_post`], the function the
/// C++ calls through `shekyl_archival_verify_join_market_bond_post`
/// (`blockchain.cpp:4617–4619`, `record_exists` from
/// `get_archival_bond_hybrid_pubkey`). A persona that already has a record
/// may not join again (`RecordExists`); the post's `bonded_total` and
/// `bond_credit` are both the floor times the shards held — one for a
/// complete tree (`FloorMismatch`, GF-1 §3); a compact set holds at least
/// one shard (`ShardSetCompactEmpty`) and a complete tree lists none
/// (`CompleteTreeWithShardIds`); the serving endpoint is set
/// (`EndpointZero`); a credit post carries no debit (`BondDebitNonzero`).
///
/// The multiplier is the corpus gap slice 8 §2 named: every join the
/// fixtures and the driver posted before this row held a complete tree at
/// one floor, so a two-shard join at one floor connected in this crate
/// and never in the C++. Before J13 on the join arm, as the C++ verifies
/// the post before it pins the identity key (`:4619` then `:4695`).
pub(crate) struct J14;

impl Rule for J14 {
    const ROW: CenRow = CenRow::J14;
}

/// CEN-J15: a compact JoinMarket's held shards are admissible at the
/// parent — every shard is **valid, closed and final** and **priced**, and
/// the holding as a whole is **viable** (`blockchain.cpp:4640–4680`; the
/// predicate `ARCHIVAL_BOND_ADD_ADMISSION.md`, its shape SO-D8 §8.0
/// input 4; the viability floor D3/R3). Per held shard, in the order the
/// C++ gathers, reading the view **at the admitting block's parent** — a
/// join's own block cannot close a shard it holds (`parent_height =
/// chain_height − 1`, "tip would self-score"):
///
/// 1. [`closed_and_final`]`(view, shard, parent, rule_set.reorg_cap())` —
///    a ghost shard past the frontier, the open frontier shard and a shard
///    closed fewer than `reorg_cap` blocks below the parent are each
///    refused here, not at the fold. The cap is the rule set's reorg-cap
///    job, never the pass-anchor setting (CEN-J15's row; FOLLOWUPS, the
///    count-versus-height row). The C++ has no site for this step: its
///    gather marshals a freeze-height *presence* bit for the age and never
///    asks whether the shard is closed, so a join onto the open frontier
///    shard is admitted there (rule 16: the predicate was ruled, not
///    inherited) and refused here.
/// 2. [`ChainView::r_market`] at the **last settled epoch as of the
///    parent**: the slash watermark ([`ChainView::last_settled_slash_epoch`],
///    A9), the last epoch whose slash pass — and so whose emission gather —
///    has run (`ARCHIVAL_SETTLEMENT_WRITER.md` `SO-D11c`). One recorded
///    definition of "settled", not `epoch(parent) − 1`: the price rows of
///    that epoch are written by the pass at the last block of the
///    parent's epoch, an epoch after it closed. `None` — no epoch settled
///    yet, or a shard that was not closed and final when the epoch was
///    gathered — refuses the join (slice 8 Q4, ruled fail-closed). The C++ reads the row's
///    absence as `0` and scores it; that is the one ruled non-parity on
///    this row, and a conformance trip over a chain whose join lands
///    before the shard's first close reproduces it as a Rust refusal
///    against a C++ accept.
/// 3. The gather — each shard's `r_market` and the age of its close at the
///    parent ([`ShardClose::age_milli`] under the rule set's schedule, the
///    source the epoch close reads SEB from, `ARW-15`; the FFI's
///    `parent_state_shards_from_gather` builds the same rows from the
///    process-latched schedule for the C++) — through the retention
///    crate's [`check_admission`]: the credited work at `r_market + 1`
///    clears [`ADMISSION_MIN_WORK_MILLI`].
///
/// A complete tree names no shard and is admitted without a gather
/// (`check_admission`'s dominance argument); the C++ skips the gather for
/// it too. Between J14 and J13 on the join arm, as the C++ verifies the
/// post (`:4619`), gathers and checks admission (`:4640`), then pins the
/// identity key (`:4695`).
///
/// The first 4.J row to read a per-height record (the archival fold, through
/// the predicate), so [`judge_bond_post`]'s fault is a [`ViewRead`] from this
/// row on: a shard the frontier counts closed with no height that closed it
/// is [`Corrupt::ShardCloseUnplaced`], the writer halt, never a refusal.
///
/// # Witness
///
/// The accept and the refusals, each one operand from it, are unit tests
/// over a `MockChain` whose fold is synthesized (`tx_bond_tests.rs`): a
/// shard closes when the fold reaches `(shard + 1) · W` with
/// `W = SHARD_LENGTH` — 3 MB of real proof bytes per shard — and the price
/// is a planted `r_market` row (`MockChain::with_r_market`, the one
/// archival read the harness plants, for this reason). On a driven chain
/// the operands are reached, not planted: the ingest crate's
/// `scenario_shard::close_shards` fills a shard with real spends and lets
/// it close, and the join scenario, the slash chain and the LMDB
/// slash-fixture replica join it at `first_admissible_compact_join` —
/// refused on this row one block earlier, admitted there. Those run in the
/// ingest crate's live lane (`--ignored`; minutes of real proofs), which
/// no CI workflow runs; the default lane's driven joins are onto the
/// complete tree, which this row admits without a gather.
pub(crate) struct J15;

impl Rule for J15 {
    const ROW: CenRow = CenRow::J15;
}

/// CEN-J16: a Release post against the record — the retention crate's
/// [`verify_release_bond_post`], the function the C++ calls through
/// `shekyl_archival_verify_release_bond_post` (`blockchain.cpp:4540–4557`).
/// The record exists (`RecordMissing`); the debit is the record's whole
/// `bonded_total` and the post's total agrees (`DebitNotFullBalance`,
/// `NotFullRelease`) — a Release is the whole exit, never a partial one;
/// the **cooldown** has elapsed since the persona last served
/// (`CooldownNotElapsed`, [`whole_record_last_served`] over the per-shard
/// maxima and `RELEASE_COOLDOWN_EPOCHS`), so a slash for the last epochs
/// served can still land on the collateral; and every epoch served has
/// been **settled** for slashes (`SlashSettlementPending`, the view's
/// slash watermark against the last served). The record's interval log is
/// not full (`IntervalLogFull`).
///
/// Three view reads beyond J13's record: the per-shard `last_served`
/// maxima — per held shard for a compact record
/// ([`ChainView::last_served_epoch`], the C++'s
/// `archival_bond_last_served_epochs` over `held_shard_ids`), every served
/// shard for a complete tree ([`ChainView::served_shards`], its
/// `archival_bond_all_last_served_epochs`) — and the slash watermark
/// ([`ChainView::last_settled_slash_epoch`]). The **current epoch** is the
/// rule set's schedule at the connecting height — the C++'s
/// `settlement_epoch_at_height(chain_height)` — the first transaction rule
/// (4.I/4.J) to read a parameter off the rule set; `tx_against` itself only
/// compares the rule set to the one the form was judged under. After J13 on the Release arm, as the C++ pins the key
/// (`:4515`) before it verifies the post (`:4542`): a Release signed by the
/// wrong key refuses on the key, whatever its terms.
pub(crate) struct J16;

impl Rule for J16 {
    const ROW: CenRow = CenRow::J16;
}

/// CEN-J18: a Reinstate post against the record — the retention crate's
/// [`verify_reinstate_bond_post`], the function the C++ calls through
/// `shekyl_archival_verify_reinstate_bond_post` (`blockchain.cpp:4576–4591`).
/// The record exists (`RecordMissing`) and has an **open** bad interval to
/// close — a slash not yet reinstated from (`ReinstateNotSlashed`); the
/// post's holdings are the record's, kind and shard set alike
/// (`ReinstateHoldingsChanged`: a Reinstate restores, it does not re-shape);
/// the terms are the record's `bonded_total` with a matching credit and no
/// debit (`ReinstateTerms`). Before J13 on the Reinstate arm, as the C++
/// verifies the post (`:4581`) before it pins the identity key (`:4607`).
pub(crate) struct J18;

impl Rule for J18 {
    const ROW: CenRow = CenRow::J18;
}

const POST_ROWS: [CenRow; 5] = [J13::ROW, J14::ROW, J15::ROW, J16::ROW, J18::ROW];

/// CEN-J13, J14, J15, J16 and J18 as one sequence over the one bond post
/// of a [`TxClass::BondPost`] transaction, in the C++'s **per-kind order**
/// (`blockchain.cpp`, the three arms of its bond-post check): a JoinMarket
/// is J14, J15, then J13; a Release is J13 then J16; a Reinstate is J18
/// then J13. The order is the row a post failing two of them refuses on,
/// and the C++'s is the one a conformance trip reproduces. Every other
/// class records the five rows vacuous. A refusal names the post's vin
/// ([`Locus::Input`]).
///
/// One record read per post, shared by the rows that need it, as the C++
/// reads `get_archival_bond_value` once per arm.
///
/// The arm is [`BondArm::of`], the classifier the fold uses. A kind it
/// does not name is [`L7`] at the post's vin, and the four post rows are
/// not recorded: the post was not judged. The fold's L7 arm stays the belt
/// for a transition caller that skipped this sequence.
///
/// The rule set reaches two rows: J15's reorg cap and settlement schedule,
/// J16's current epoch.
///
/// The slot H21 pairs with the vin is read by position. A transaction whose
/// `pqc_auths` is shorter than its inputs is H21's when `tx_form` ran; this
/// sequence still fails closed, on J13, at the arm that reads the slot —
/// after that arm's non-slot check, in the C++'s order — so a caller that
/// has not run H21 does not record the post rows over a post it did not pin.
/// A Release with no record never reads the slot: J13 is gated on the
/// record, and J16 refuses `RecordMissing`.
///
/// A post the retention vin cannot be built from ([`retention_vin`]: a
/// compact set that is not a [`ShardSet`]) is refused under the row that
/// would have read the vin — the wire parse already refuses a duplicate or
/// an over-cap list (CEN-H-rows), so the arm is unreachable from bytes
/// and fails closed rather than passing a post no verify judged.
///
/// # Errors
///
/// The view's fault, from the record read, J15's fold and price reads or
/// J16's serving reads; [`ViewRead::Corrupt`] from J15's predicate when
/// the fold counts a shard closed that no height closed
/// ([`crate::Corrupt::ShardCloseUnplaced`]).
pub(crate) fn judge_bond_post<'id, V: ChainView<'id>>(
    cx: &TxContext<'_>,
    view: &V,
    rule_set: &RuleSet,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, ViewRead<V::Fault>> {
    if matches!(cx.class, TxClass::BondPost { .. }) {
        let pqc_auths: &[PqcAuth] = match &cx.tx.ct {
            Ct::Fcmp { pqc_auths, .. } => pqc_auths,
            _ => &[],
        };
        for (input, item) in cx.tx.prefix.inputs.iter().enumerate() {
            let Input::BondPost(post) = item else {
                continue;
            };
            let locus = Locus::Input {
                slot: cx.slot,
                input,
            };
            let Some(arm) = BondArm::of(post) else {
                return Ok(Err(InvalidBlock::new(L7::ROW, locus)));
            };
            let verdict = match &arm {
                BondArm::JoinMarket { .. } => {
                    judge_join_market(view, rule_set, &arm, pqc_auths, input, locus)?
                }
                BondArm::Release { .. } => {
                    judge_release(view, rule_set, &arm, pqc_auths, input, locus)
                        .map_err(ViewRead::View)?
                }
                BondArm::Reinstate { .. } => {
                    judge_reinstate(view, &arm, pqc_auths, input, locus).map_err(ViewRead::View)?
                }
            };
            if verdict.is_err() {
                return Ok(verdict);
            }
        }
    }
    for row in POST_ROWS {
        coverage.insert(row);
    }
    Ok(Ok(()))
}

/// JoinMarket, J14, J15, then J13 (`blockchain.cpp:4619`, `:4640`,
/// `:4695`). The statics do not read the slot, so a join that fails them
/// refuses on J14 even when the slot is missing or carries the wrong key;
/// a holding that is not admissible refuses on J15 before the key is read.
fn judge_join_market<'id, V: ChainView<'id>>(
    view: &V,
    rule_set: &RuleSet,
    arm: &BondArm<'_>,
    pqc_auths: &[PqcAuth],
    input: usize,
    locus: Locus,
) -> Result<Verdict<()>, ViewRead<V::Fault>> {
    let post = arm.post();
    let Some(vin) = retention_vin(arm) else {
        return Ok(Err(InvalidBlock::new(J14::ROW, locus)));
    };
    let record_exists = view
        .bond_record(&post.p_canonical_id)
        .map_err(ViewRead::View)?
        .is_some();
    if verify_join_market_bond_post(&vin, record_exists).is_err() {
        return Ok(Err(InvalidBlock::new(J14::ROW, locus)));
    }
    if !holding_admissible(view, rule_set, &vin.holdings)? {
        return Ok(Err(InvalidBlock::new(J15::ROW, locus)));
    }
    if !identity_signs(pqc_auths, input, post) {
        return Ok(Err(InvalidBlock::new(J13::ROW, locus)));
    }
    Ok(Ok(()))
}

/// J15's body: the per-shard gather at the admitting block's parent, then
/// [`check_admission`]. A complete tree gathers nothing and is admitted; a
/// compact set connecting at genesis has no parent to read and no shard
/// can be closed, so it is not admissible. Per shard, in list order:
/// [`closed_and_final`] under the rule set's reorg cap, then the price at
/// the slash watermark as of the parent — `None`, watermark or row, is not
/// admissible (slice 8 Q4) — then the age of the close the predicate just
/// read, under the rule set's schedule.
///
/// # Errors
///
/// The view's fault, or [`ViewRead::Corrupt`] from the predicate.
fn holding_admissible<'id, V: ChainView<'id>>(
    view: &V,
    rule_set: &RuleSet,
    holdings: &HoldingsDescriptor,
) -> Result<bool, ViewRead<V::Fault>> {
    fn parent_state(shards: &[AdmissionShard]) -> ParentStateHoldings<'_> {
        ParentStateHoldings {
            shards,
            age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
        }
    }
    if holdings.kind == HoldingsKind::CompleteTree {
        return Ok(check_admission(holdings, &parent_state(&[])).is_ok());
    }
    let connecting = Tip::connecting_height(view.tip().map_err(ViewRead::View)?.as_ref());
    let Some(parent) = connecting
        .to_raw()
        .checked_sub(1)
        .map(BlockHeight::from_raw)
    else {
        return Ok(false);
    };
    let schedule = rule_set.settlement_schedule();
    let Some(settled) = view.last_settled_slash_epoch().map_err(ViewRead::View)? else {
        return Ok(false);
    };
    let mut gathered = Vec::with_capacity(holdings.shard_ids.len());
    for &raw in holdings.shard_ids.as_slice() {
        let shard = ShardId::from_raw(raw);
        if !closed_and_final(view, shard, parent, rule_set.reorg_cap())? {
            return Ok(false);
        }
        let Some(r_market) = view.r_market(shard, settled).map_err(ViewRead::View)? else {
            return Ok(false);
        };
        // The close the predicate found: closed through the parent, so the
        // search places it (a fold that cannot is the predicate's Corrupt).
        let close = ShardClose::ClosedAt(shard_close_height(view, shard, parent)?);
        gathered.push(AdmissionShard {
            r_market: r_market.to_raw(),
            age_milli: close.age_milli(parent, schedule.blocks().get()),
        });
    }
    Ok(check_admission(holdings, &parent_state(&gathered)).is_ok())
}

/// Release, J13 then J16 (`blockchain.cpp:4515`, `:4542`). The pin is gated
/// on the record, as the C++ gates it on `have_record`: with no record J13
/// does not run, missing slot included, and J16 refuses `RecordMissing`.
fn judge_release<'id, V: ChainView<'id>>(
    view: &V,
    rule_set: &RuleSet,
    arm: &BondArm<'_>,
    pqc_auths: &[PqcAuth],
    input: usize,
    locus: Locus,
) -> Result<Verdict<()>, V::Fault> {
    let post = arm.post();
    let record = view.bond_record(&post.p_canonical_id)?;
    if let Some(record) = &record {
        let Some(auth) = pqc_auths.get(input) else {
            return Ok(Err(InvalidBlock::new(J13::ROW, locus)));
        };
        if cold_authority_pin(
            RetentionKind::Release,
            post.bond_debit,
            &record.bond_spend_pk,
            &auth.hybrid_public_key,
        )
        .is_err()
        {
            return Ok(Err(InvalidBlock::new(J13::ROW, locus)));
        }
    }
    let Some(vin) = retention_vin(arm) else {
        return Ok(Err(InvalidBlock::new(J16::ROW, locus)));
    };
    if !release_terms_hold(view, rule_set, &vin, record.as_ref())? {
        return Ok(Err(InvalidBlock::new(J16::ROW, locus)));
    }
    Ok(Ok(()))
}

/// Reinstate, J18 then J13 (`blockchain.cpp:4581`, `:4607`). The terms do
/// not read the slot, so a reinstate that fails them refuses on J18 even
/// when the slot is missing or carries the wrong key.
fn judge_reinstate<'id, V: ChainView<'id>>(
    view: &V,
    arm: &BondArm<'_>,
    pqc_auths: &[PqcAuth],
    input: usize,
    locus: Locus,
) -> Result<Verdict<()>, V::Fault> {
    let post = arm.post();
    let Some(vin) = retention_vin(arm) else {
        return Ok(Err(InvalidBlock::new(J18::ROW, locus)));
    };
    let record = view.bond_record(&post.p_canonical_id)?;
    if !reinstate_terms_hold(&vin, record.as_ref()) {
        return Ok(Err(InvalidBlock::new(J18::ROW, locus)));
    }
    if !identity_signs(pqc_auths, input, post) {
        return Ok(Err(InvalidBlock::new(J13::ROW, locus)));
    }
    Ok(Ok(()))
}

/// The credit arms sign with the post's identity key. A missing slot is the
/// same refusal as the wrong key: the arm that reads the slot did not find
/// the key it selects.
fn identity_signs(pqc_auths: &[PqcAuth], input: usize, post: &BondPost) -> bool {
    pqc_auths
        .get(input)
        .is_some_and(|auth| auth.hybrid_public_key == post.hybrid_public_key)
}

/// J16's body: [`verify_release_bond_post`] over the record's facts and
/// the three serving reads (rule docs). `None` record → the verify's
/// `RecordMissing`, with the serving reads skipped as the C++ skips them
/// (`:4529`).
fn release_terms_hold<'id, V: ChainView<'id>>(
    view: &V,
    rule_set: &RuleSet,
    vin: &ArchivalBondPostVin,
    record: Option<&BondRecord>,
) -> Result<bool, V::Fault> {
    let persona = PCanonicalId::from_bytes(vin.p_canonical_id);
    let (bonded_total, bad_interval_count, last_served) = match record {
        None => (None, 0, None),
        Some(record) => {
            let maxima: Vec<u64> = match &record.holdings {
                Holdings::ShardSet(held) => {
                    let mut maxima = Vec::with_capacity(held.len());
                    for h in held.iter() {
                        if let Some(epoch) = view.last_served_epoch(&persona, h.shard)? {
                            maxima.push(epoch.to_raw());
                        }
                    }
                    maxima
                }
                Holdings::CompleteTree => view
                    .served_shards(&persona)?
                    .into_iter()
                    .map(|s| s.last_served.to_raw())
                    .collect(),
            };
            (
                Some(record.bonded_total.to_raw()),
                record.bad_intervals.len(),
                whole_record_last_served(&maxima),
            )
        }
    };
    let last_settled_slash_epoch = view
        .last_settled_slash_epoch()?
        .map(SettlementEpoch::to_raw);
    let connecting = Tip::connecting_height(view.tip()?.as_ref());
    let current_epoch = rule_set
        .settlement_schedule()
        .epoch_at_height(connecting.to_raw());
    Ok(verify_release_bond_post(
        vin,
        bonded_total,
        bad_interval_count,
        last_served,
        last_settled_slash_epoch,
        current_epoch,
    )
    .is_ok())
}

/// J18's body: [`verify_reinstate_bond_post`] over the record's facts.
/// `None` record → the verify's `RecordMissing`; the holdings arguments
/// are then the vin's own, which the verify does not reach.
fn reinstate_terms_hold(vin: &ArchivalBondPostVin, record: Option<&BondRecord>) -> bool {
    let Some(record) = record else {
        return verify_reinstate_bond_post(vin, None, vin.holdings.kind, &[], &[]).is_ok();
    };
    let held: Vec<u64> = match &record.holdings {
        Holdings::ShardSet(held) => held.iter().map(|h| h.shard.to_raw()).collect(),
        Holdings::CompleteTree => Vec::new(),
    };
    verify_reinstate_bond_post(
        vin,
        Some(record.bonded_total.to_raw()),
        record.holdings.kind(),
        &held,
        &record.bad_intervals,
    )
    .is_ok()
}

/// The classified arm as the retention crate's vin — the marshal the three
/// `verify_*` functions read. The kind is the arm's, so a kind no arm names
/// never reaches here ([`L7`] refused it). The holdings and the amounts are
/// the post's. `None` is a compact set that is not a [`ShardSet`]
/// (duplicate, over cap) — the wire parse refuses those before any rule
/// runs, so the arm is unreachable from bytes and fails closed.
///
/// The submit pool's `retention_vin` (`shekyl-daemon-rpc`,
/// `submit/verifier.rs`) is a different function. It takes a caller-supplied
/// retention kind and a separate `bond_spend_pk`, and it does not classify
/// the post. The two are not interchangeable, and neither is a copy of the
/// other. The pool's deletes when pool admission calls [`crate::tx_against`]
/// (DRS-E5); until that caller lands, the pool's stays. The follow-up names
/// both shapes (`docs/FOLLOWUPS.md`).
pub(crate) fn retention_vin(arm: &BondArm<'_>) -> Option<ArchivalBondPostVin> {
    let post = arm.post();
    let (holdings_kind, shard_ids) = match &post.holdings {
        WireHoldings::ShardSetCompact(ids) => (
            HoldingsKind::ShardSetCompact,
            ShardSet::new(ids.clone()).ok()?,
        ),
        WireHoldings::CompleteTree => (HoldingsKind::CompleteTree, ShardSet::empty()),
    };
    let kind = match arm {
        BondArm::JoinMarket {
            bond_spend_pk,
            endpoint,
            ..
        } => BondKind::JoinMarket {
            bond_spend_pk: bond_spend_pk.to_vec(),
            endpoint: *endpoint,
        },
        BondArm::Release { .. } => BondKind::Release,
        BondArm::Reinstate { .. } => BondKind::Reinstate,
    };
    Some(ArchivalBondPostVin {
        hybrid_public_key: post.hybrid_public_key.clone(),
        p_canonical_id: post.p_canonical_id.to_bytes(),
        kind,
        holdings: HoldingsDescriptor {
            kind: holdings_kind,
            shard_ids,
        },
        bonded_total_atomic: post.bonded_total_atomic,
        bond_credit: post.bond_credit,
        bond_debit: post.bond_debit,
    })
}

#[cfg(test)]
#[path = "tx_bond_tests.rs"]
mod tx_bond_tests;
