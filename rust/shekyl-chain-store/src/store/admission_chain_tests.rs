// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Admission against a store chain (`SO-D12` increment 4a, §5).
//!
//! The bundle is the fixture producer's. The view that judges it is the
//! store's, so the commitment, the hashes, `D` and the issued counts are
//! the chain's.
//!
//! Every epoch numbered in this file's prose is counted from the personas'
//! join epoch: "epoch 2" is `shifted(2)` ([`shifted`]), because the chain
//! loads the captured shard-fill prefix first and the personas join after it.

use shekyl_archival_retention::{
    challenge_nonce, draw_commit, section_root, select_draw, BundleBody, BundleRef, DrawableEpoch,
    PassBitmap, PassStream,
};
use shekyl_chain_rules::harness::bundle::BundleWorld;
use std::collections::BTreeMap;

use shekyl_chain_rules::{
    admission_plan, judge_bundles, AdmissionFault, AtHeight, BlockDrawsFloor, BundleInvalid,
    BundleRefused, BundleView as _, Corrupt, DrawableMemo, EpochFloor, SettlementCheck, Settling,
};
use shekyl_harness_spender::Persona;
use shekyl_types::archival::{BlockDraws, DrawCommitment, IssuedDigest};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, SettlementEpoch};
use shekyl_wire::tx_extra::{self, TxExtraField};
use shekyl_wire::Transaction;

use crate::codec::Canonical;
use crate::ids::IssuedDrawKey;

use super::super::super::connect_fixtures::{
    batch_root_going_into, candidate_over, judge_with_memo,
};
use super::super::super::{SettlementFault, StoreBundleView, StoreInvariant};
use super::super::{shifted, SlashedChain, TestErr, RULES, WITNESS_PERSONAS};
use super::{h_open, join_witness_shard_set, no_draws, witness_shard_slots};

/// Ten blocks after epoch 2 opens. With a shard set of the witness width,
/// this harness's schedule draws once here.
fn drawing_height() -> BlockHeight {
    BlockHeight::from_raw(h_open(shifted(2)) + 10)
}

pub(super) struct Linked {
    pub(super) draws: BlockDraws,
    pub(super) hash: BlockHash,
}

struct Prepared {
    chain: SlashedChain,
    memo: DrawableMemo,
    /// Hash of the block at `h_open(shifted(2))`.
    open_hash: BlockHash,
    /// Hash of the drawing block.
    hash: BlockHash,
    /// Hash of the block before it, the anchor.
    anchor_hash: BlockHash,
    /// The count row the drawing block stored.
    count: u32,
    /// The support seats the drawing block stored. Which complete trees a
    /// block seats is a hash of each persona's id
    /// (`shekyl_archival_retention::support_seated_at`), so it moves with
    /// the personas' keys: the fixture reads it from the chain and states
    /// it, rather than assuming the block seated nobody.
    support: u32,
}

fn prepare(label: &str) -> Prepared {
    let open = h_open(shifted(2));
    let mut chain = SlashedChain::build_with(label, WITNESS_PERSONAS, open - 2, no_draws);
    // The joins are complete trees, so they are not in D. The planted set
    // has the witness width: the width this schedule draws once from, at
    // [`drawing_height`].
    join_witness_shard_set(&mut chain);
    let mut memo = DrawableMemo::new();
    let mut open_hash = None;
    let mut anchor_hash = chain.grown.tip();
    for height in open..drawing_height().to_raw() {
        let linked = connect_plain(&mut chain, Some(&mut memo));
        if height == open {
            open_hash = Some(linked.hash);
        }
        anchor_hash = linked.hash;
    }
    let world = BundleWorld::with(drawing_height(), BundleWorld::SEED, 1, &RULES);
    let commitment =
        DrawCommitment::from_bytes(draw_commit(&world.witness_public_key, &world.seed));
    let linked = connect_committed(&mut chain, &mut memo, commitment);
    let count = linked.draws.count;
    assert_eq!(count, 1, "epoch 2's tenth block draws once");
    let seats = chain
        .store
        .begin_read()
        .expect("read")
        .support_row(drawing_height(), BlockDrawsFloor::NONE)
        .expect("read")
        .expect("the drawing block wrote its support row")
        .seats;
    let support = u32::try_from(seats.len()).expect("a block seats fewer than 2^32 trees");
    Prepared {
        chain,
        memo,
        open_hash: open_hash.expect("the open connected"),
        hash: linked.hash,
        anchor_hash,
        count,
        support,
    }
}

pub(super) fn connect_plain(chain: &mut SlashedChain, memo: Option<&mut DrawableMemo>) -> Linked {
    let txs = chain.grown.realise(&[]);
    let mut linked = None;
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let judged = chain
            .grown
            .judge_listing_with_memo(&view, &chain.rules, &txs, memo)?;
        linked = Some(Linked {
            draws: judged.block().archival().draws(),
            hash: judged.block().block().hash(),
        });
        batch.connect(judged, chain.rules)?;
        Ok(())
    });
    out.expect("the block connects");
    linked.expect("the verdict")
}

pub(super) fn connect_committed(
    chain: &mut SlashedChain,
    memo: &mut DrawableMemo,
    commitment: DrawCommitment,
) -> Linked {
    let height = chain.grown.height();
    let previous = chain.grown.tip();
    let mut linked = None;
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let root = batch_root_going_into(&view, height.to_raw())?;
        let mut candidate = candidate_over(root, height.to_raw(), previous, Vec::new());
        candidate.block.miner_transaction =
            with_commitment(candidate.block.miner_transaction, commitment);
        let judged = judge_with_memo(&view, candidate, &chain.rules, Some(memo))?;
        linked = Some(Linked {
            draws: judged.block().archival().draws(),
            hash: judged.block().block().hash(),
        });
        let block = judged.block().block().clone();
        chain.grown.record(&block, &[]);
        batch.connect(judged, chain.rules)?;
        Ok(())
    });
    out.expect("the committed block connects");
    linked.expect("the verdict")
}

fn with_commitment(mut tx: Transaction, commitment: DrawCommitment) -> Transaction {
    let fields = tx.prefix.parse_extra().expect("the fixture extra parses");
    let fields: Vec<_> = fields
        .into_iter()
        .map(|field| match field {
            TxExtraField::DrawCommitment(_) => TxExtraField::DrawCommitment(commitment),
            other => other,
        })
        .collect();
    tx.prefix.extra = tx_extra::serialize(&fields).expect("the grammar round-trips");
    tx
}

fn drawable(prepared: &Prepared) -> &DrawableEpoch {
    prepared
        .memo
        .get(
            RULES.settlement_schedule().epoch_at(drawing_height()),
            &prepared.open_hash,
        )
        .expect("the open filed D")
}

fn produce(prepared: &Prepared) -> (BundleRef, BundleBody) {
    let h = drawing_height();
    let anchor = h - BlockCount::ONE;
    let mut world = BundleWorld::with(h, BundleWorld::SEED, prepared.count, &RULES);
    world.view.hashes.insert(h, prepared.hash);
    world.view.hashes.insert(anchor, prepared.anchor_hash);
    let drawable = drawable(prepared);
    let selected = select_draw(&world.seed, &prepared.hash, 0, drawable.len(), |_| {
        Ok::<_, core::convert::Infallible>(true)
    })
    .expect("a short read does not fail")
    .expect("the planted set selects");
    let pair = drawable.pair(selected.index).expect("the index is in D");
    let signers: Vec<Persona> = witness_shard_slots().map(Persona::at).collect();
    let signer = signers
        .iter()
        .find(|persona| {
            drawable
                .receipt_key(selected.index)
                .is_some_and(|key| persona.keys().receipt_sign_pk == *key)
        })
        .expect("D's receipt key is one of the planted personas");
    let nonce = challenge_nonce(&world.seed, &prepared.hash, 0, 0);
    let record = world.record_signed_by(
        &signer.keys().receipt_sign_sk,
        pair.shard.to_raw(),
        0,
        anchor,
        PassStream::Economy,
        &nonce,
    );
    // The support stream is stated at the width the block issued, with no
    // support pass: zero seats is an empty bitmap, and a seated tree is an
    // observation this producer did not pass. Either way the bundle carries
    // the one economy record and nothing else.
    let (reference, body) = world.assemble_support(
        PassBitmap::from_passes(prepared.count, [0]).expect("one pass"),
        PassBitmap::from_passes(prepared.support, []).expect("no support pass"),
        &[record],
    );
    (reference, body)
}

fn admit(prepared: &mut Prepared) -> (Vec<shekyl_chain_rules::Admitted>, BlockDraws) {
    let (reference, body) = produce(prepared);
    let height = prepared.chain.grown.height();
    let mut admitted = None;
    let mut counted = None;
    let out: Result<(), TestErr> = prepared.chain.store.write(|batch| {
        let view = batch.chain_view();
        {
            let bundle_view =
                StoreBundleView::new(&view, &prepared.memo, height, RULES.settlement_schedule());
            assert_eq!(
                bundle_view
                    .support_count(reference.h())
                    .expect("the read")
                    .expect("the seat row"),
                prepared.support,
                "the bundle states the support width the store issued"
            );
        }
        // The block carries the section; `validate` admits it and the
        // verdict carries what `connect` journals.
        let txs = prepared.chain.grown.realise(&[]);
        let judged = prepared.chain.grown.judge_listing_with_section(
            &view,
            &RULES,
            &txs,
            Some(&mut prepared.memo),
            std::slice::from_ref(&reference),
            vec![body],
        )?;
        counted = Some(judged.block().archival().draws());
        let verdict = judged.block().admitted().to_vec();
        batch.connect(judged, RULES)?;
        admitted = Some(verdict);
        Ok(())
    });
    out.expect("admission connects");
    (admitted.expect("the verdict"), counted.expect("the count"))
}

fn draws_row(chain: &SlashedChain, height: BlockHeight) -> Option<BlockDraws> {
    chain
        .store
        .begin_read()
        .expect("read")
        .block_draws(height, BlockDrawsFloor::NONE)
        .expect("read")
}

fn draws_of(chain: &SlashedChain, height: BlockHeight) -> BlockDraws {
    draws_row(chain, height).expect("the row")
}

fn index_of(
    chain: &SlashedChain,
    epoch: SettlementEpoch,
) -> Vec<shekyl_types::archival::IndexedDraw> {
    let floor = EpochFloor::<Settling>::under(chain.grown.height(), RULES.settlement_schedule());
    chain
        .store
        .begin_read()
        .expect("read")
        .issued_draws(epoch, floor)
        .expect("index")
}

fn pop_one(chain: &mut SlashedChain) {
    let popped: Result<crate::store::Popped, TestErr> = chain.store.write(|batch| Ok(batch.pop()?));
    popped.expect("pop");
    chain.grown.pop();
}

/// A real bundle, judged through the store view and written. Pop of the
/// next block leaves the admission. Pop of the admitting block restores
/// the index, the digest, the reveal and the draw row. The next block's
/// count is unchanged at `h_incl` and reduced through `issued_short`.
#[test]
fn a_verified_bundle_is_what_the_store_writes_and_pop_restores() {
    let mut prepared = prepare("admit-e2e");
    let h = drawing_height();
    let (admitted, counted) = admit(&mut prepared);
    let one = &admitted[0];
    assert_eq!(one.draws.len(), 1);
    assert_eq!(
        one.support.len(),
        usize::try_from(prepared.support).expect("fits"),
        "one observation per issued support seat"
    );
    assert!(
        one.support.iter().all(|seat| !seat.passed),
        "the fixture passes no support draw"
    );
    let epoch = RULES.settlement_schedule().epoch_at(h);
    let rows = index_of(&prepared.chain, epoch);
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.issuing_height, h);
    assert_eq!(
        row.draw, 0,
        "the key's ordinal is j, not the pair's place in D"
    );
    assert_eq!(row.persona, one.draws[0].pair.persona);
    assert_eq!(row.shard, one.draws[0].pair.shard);
    assert_eq!(row.state.passed, one.draws[0].passed);
    let including = h + BlockCount::ONE;
    assert_eq!(row.state.revealed_at, including);
    let plan = admission_plan(
        including,
        RULES.settlement_schedule(),
        &admitted,
        &BTreeMap::new(),
    )
    .expect("the fixture's one bundle plans");
    assert_eq!(plan.issued_short(), 1, "one new draw of this epoch");
    let mut digest = IssuedDigest::ZERO;
    for issues in plan.epochs() {
        for term in issues.terms() {
            digest.fold(&term);
        }
    }
    let floor =
        EpochFloor::<Settling>::under(prepared.chain.grown.height(), RULES.settlement_schedule());
    assert_eq!(
        prepared
            .chain
            .store
            .begin_read()
            .expect("read")
            .issued_digest(epoch, floor)
            .expect("digest"),
        digest
    );
    assert!(draws_of(&prepared.chain, h).revealed);
    let section = prepared
        .chain
        .store
        .begin_read()
        .expect("read")
        .bundle_references_at(including)
        .expect("read");
    let AtHeight::Recorded(Some(section)) = section else {
        panic!("the admitting block records its section: {section:?}");
    };
    assert_eq!(section.as_slice().len(), 1, "one reference, as admitted");
    let incl = draws_of(&prepared.chain, including);
    assert_eq!(
        incl.count, counted.count,
        "admission does not change the count"
    );
    assert_eq!(incl.shortfall, counted.shortfall);
    assert_eq!(incl.issued_short, plan.issued_short());

    let next = connect_plain(&mut prepared.chain, None);
    assert_eq!(
        next.draws.shortfall,
        counted.shortfall - u64::from(incl.issued_short),
        "the next block's shortfall loses issued_short"
    );

    pop_one(&mut prepared.chain);
    assert_eq!(draws_of(&prepared.chain, including).issued_short, 1);
    assert!(draws_of(&prepared.chain, h).revealed);
    assert_eq!(index_of(&prepared.chain, epoch).len(), 1);
    assert_eq!(
        prepared
            .chain
            .store
            .begin_read()
            .expect("read")
            .issued_digest(epoch, floor)
            .expect("digest"),
        digest,
        "pop of the next block leaves the admission"
    );

    pop_one(&mut prepared.chain);
    assert!(
        index_of(&prepared.chain, epoch).is_empty(),
        "pop removes the admitted draw"
    );
    assert!(!draws_of(&prepared.chain, h).revealed);
    assert!(
        draws_row(&prepared.chain, including).is_none(),
        "pop removes the admitting block's draw row"
    );
    assert_eq!(
        prepared
            .chain
            .store
            .begin_read()
            .expect("read")
            .bundle_references_at(including)
            .expect("read"),
        AtHeight::AboveTip,
        "pop removes the admitting block's section"
    );
    let restored =
        EpochFloor::<Settling>::under(prepared.chain.grown.height(), RULES.settlement_schedule());
    assert_eq!(
        prepared
            .chain
            .store
            .begin_read()
            .expect("read")
            .issued_digest(epoch, restored)
            .expect("digest"),
        IssuedDigest::ZERO,
        "pop of the admitting block restores the digest"
    );

    // Three issued draws of another pair, revealed below the drawing
    // block, are not short there. One whose reveal is the drawing block
    // itself still is. These rows are not part of a connect, so they are
    // planted after pop has been checked: a connect's pop would not
    // remove them.
    let drawable = drawable(&prepared);
    let other = (0..drawable.len())
        .find(|index| drawable.pair(*index) != Some(one.draws[0].pair))
        .expect("another pair");
    let pair = drawable.pair(other).expect("the index");
    let past_index = drawable.len();
    let out: Result<(), TestErr> = prepared.chain.store.write(|batch| {
        {
            let mut index = batch.open_insert_table(
                crate::schema::ARCHIVAL_ISSUED_DRAW,
                StoreInvariant::SettlementNotSound {
                    epoch,
                    observed: SettlementFault::IndexDrift,
                },
            )?;
            for j in 0..3 {
                let key =
                    IssuedDrawKey::new(epoch, pair.persona, pair.shard, h - BlockCount::ONE, j);
                index.insert(
                    key.key(),
                    shekyl_types::archival::IssuedDraw {
                        revealed_at: h - BlockCount::ONE,
                        passed: true,
                    }
                    .encoded()
                    .as_encoded(),
                )?;
            }
            let key = IssuedDrawKey::new(
                epoch,
                one.draws[0].pair.persona,
                one.draws[0].pair.shard,
                h,
                7,
            );
            index.insert(
                key.key(),
                shekyl_types::archival::IssuedDraw {
                    revealed_at: h,
                    passed: true,
                }
                .encoded()
                .as_encoded(),
            )?;
        }
        let view = batch.chain_view();
        let bundle_view = StoreBundleView::new(
            &view,
            &prepared.memo,
            including + BlockCount::ONE,
            RULES.settlement_schedule(),
        );
        assert!(
            !bundle_view.visibly_short(h, other).expect("the read"),
            "three passes below h are not short"
        );
        assert!(
            bundle_view
                .visibly_short(h, one.draws[0].index)
                .expect("the read"),
            "a draw revealed at h is still short at h"
        );
        Ok(())
    });
    out.expect("the short reads");

    let past: Result<(), TestErr> = prepared.chain.store.write(|batch| {
        let view = batch.chain_view();
        let bundle_view = StoreBundleView::new(
            &view,
            &prepared.memo,
            including + BlockCount::ONE,
            RULES.settlement_schedule(),
        );
        bundle_view.visibly_short(h, past_index)?;
        Ok(())
    });
    let past = past.expect_err("an index past D");
    let TestErr::Store(text) = past else {
        panic!("the batch did not fault: {past:?}");
    };
    assert!(
        text.contains("does not contain"),
        "an index past D is not a memo miss: {text}"
    );
}

/// Genesis answers its commitment, and a bundle that does not open it is
/// J33 rather than an unanswered view. The memo is filed for the height the
/// bundle is judged at, `2`, by admission's own filing step
/// (`remember_window_epochs`): genesis's epoch, whatever epoch the chain's
/// tip is in.
#[test]
fn a_bundle_for_genesis_is_refused_at_j33() {
    let chain = SlashedChain::build_with(
        "admit-genesis",
        WITNESS_PERSONAS,
        h_open(shifted(1)) - 2,
        no_draws,
    );
    let mut memo = DrawableMemo::new();
    let world = BundleWorld::with(BlockHeight::ZERO, BundleWorld::SEED, 0, &RULES);
    let (reference, body) = world.bundle(&[]);
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        shekyl_chain_rules::remember_window_epochs(
            &view,
            BlockHeight::from_raw(2),
            &RULES,
            &mut memo,
        )
        .expect("genesis's epoch files");
        let bundle_view = StoreBundleView::new(
            &view,
            &memo,
            BlockHeight::from_raw(2),
            RULES.settlement_schedule(),
        );
        let refs = [reference];
        let bodies = [body];
        let root = section_root(&refs).expect("one reference");
        let refused = judge_bundles(
            &refs,
            &bodies,
            &root,
            BlockHeight::from_raw(2),
            &bundle_view,
            &RULES,
            &shekyl_network::HARNESS_NETWORK_ID,
        )
        .expect_err("genesis does not open");
        assert!(
            matches!(
                refused,
                AdmissionFault::Bundle {
                    refused: BundleRefused::Invalid(BundleInvalid::Commitment),
                    ..
                }
            ),
            "{refused:?}"
        );
        assert_eq!(refused.row(), Some(shekyl_chain_rules::CenRow::J33));
        Ok(())
    });
    out.expect("the view answered");
}

/// An empty memo on a connected open is SI-35, not an absent set.
#[test]
fn a_memo_miss_is_the_sequencing_fault() {
    let mut chain = SlashedChain::build_with(
        "admit-memo",
        WITNESS_PERSONAS,
        h_open(shifted(1)) - 1,
        no_draws,
    );
    let mut filled = DrawableMemo::new();
    connect_plain(&mut chain, Some(&mut filled));
    let empty = DrawableMemo::new();
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let bundle_view = StoreBundleView::new(
            &view,
            &empty,
            BlockHeight::from_raw(1),
            RULES.settlement_schedule(),
        );
        bundle_view.drawable_epoch(SettlementEpoch::from_raw(shifted(0)))?;
        Ok(())
    });
    let TestErr::Store(text) = out.expect_err("a memo miss faults") else {
        panic!("the batch admitted");
    };
    assert!(text.contains("SI-35"), "{text}");
}

/// Settlement's index-vs-digest compare passes after the admission, and
/// fails once an index row is removed from under the digest.
#[test]
fn the_digest_check_closes_on_an_admitted_bundle() {
    let mut prepared = prepare("admit-digest");
    let (admitted, _) = admit(&mut prepared);
    assert_eq!(admitted.len(), 1);
    let deadline = RULES
        .settlement_schedule()
        .slash_deadline_height(shifted(2));
    while prepared.chain.grown.height().to_raw() < deadline {
        connect_plain(&mut prepared.chain, None);
    }
    let out: Result<(), TestErr> = prepared.chain.store.write(|batch| {
        let view = batch.chain_view();
        prepared
            .chain
            .grown
            .judge_empty_or_corrupt(&view, &RULES)?
            .expect("the index folds to the digest");
        Ok(())
    });
    out.expect("the pass settles");

    let mut tampered = prepare("admit-digest-tamper");
    let (admitted, _) = admit(&mut tampered);
    let draw = &admitted[0].draws[0];
    let epoch = RULES.settlement_schedule().epoch_at(drawing_height());
    let removed: Result<(), TestErr> = tampered.chain.store.write(|batch| {
        batch
            .open_remove_table(
                crate::schema::ARCHIVAL_ISSUED_DRAW,
                StoreInvariant::SettlementNotSound {
                    epoch,
                    observed: SettlementFault::IndexDrift,
                },
            )?
            .remove(
                IssuedDrawKey::new(
                    epoch,
                    draw.pair.persona,
                    draw.pair.shard,
                    drawing_height(),
                    0,
                )
                .key(),
            )?;
        Ok(())
    });
    removed.expect("the row is removed");
    while tampered.chain.grown.height().to_raw() < deadline {
        connect_plain(&mut tampered.chain, None);
    }
    let out: Result<(), TestErr> = tampered.chain.store.write(|batch| {
        let view = batch.chain_view();
        let corrupt = tampered
            .chain
            .grown
            .judge_empty_or_corrupt(&view, &RULES)?
            .expect_err("a missing row does not fold to the digest");
        assert_eq!(
            corrupt,
            Corrupt::SettlementIntegrity {
                epoch,
                check: SettlementCheck::IssuedIndexDigest,
            }
        );
        Ok(())
    });
    out.expect("the refusal");
}

/// Rick's C3 test (`SO-D12` 4b review, finding 1): admission runs after the
/// window's epochs are filed. The store is reopened — the memo is not
/// persisted, so it is cold — and the block one past epoch 3's open
/// carries a bundle for the last block of epoch 2. `validate` admits it
/// with no SI-35: its filing step put epoch 2's `D` in the memo before the
/// section's budget read it.
///
/// Red edit: drop `remember_window_epochs` from `rules::bundle_admission::admit`
/// — the store's bundle view misses epoch 2 and the batch faults SI-35.
#[test]
fn a_cold_memo_admits_a_previous_epoch_bundle_inside_the_window() {
    let schedule = RULES.settlement_schedule();
    let window = schedule
        .challenge_response_blocks()
        .expect("the harness schedule has a response window")
        .get();
    let h = BlockHeight::from_raw(h_open(shifted(3)) - 1);
    let h_incl = BlockHeight::from_raw(h_open(shifted(3)) + 1);
    assert!(h_incl.to_raw() - h.to_raw() <= window, "inside the window");
    assert_ne!(schedule.epoch_at(h), schedule.epoch_at(h_incl));

    let open = h_open(shifted(2));
    let mut chain =
        SlashedChain::build_with("cold-memo-admit", WITNESS_PERSONAS, open - 2, no_draws);
    join_witness_shard_set(&mut chain);
    let mut warm = DrawableMemo::new();
    while chain.grown.height() < h {
        connect_plain(&mut chain, Some(&mut warm));
    }
    let world = BundleWorld::with(h, BundleWorld::SEED, 0, &RULES);
    let commitment =
        DrawCommitment::from_bytes(draw_commit(&world.witness_public_key, &world.seed));
    connect_committed(&mut chain, &mut warm, commitment);
    connect_plain(&mut chain, Some(&mut warm));
    assert_eq!(chain.grown.height(), h_incl);

    let read = chain.store.begin_read().expect("read");
    let count = read
        .block_draws(h, BlockDrawsFloor::NONE)
        .expect("read")
        .expect("h wrote its draw row")
        .count;
    let support = u32::try_from(
        read.support_row(h, BlockDrawsFloor::NONE)
            .expect("read")
            .expect("h wrote its support row")
            .seats
            .len(),
    )
    .expect("a block seats fewer than 2^32 trees");
    drop(read);
    let world = BundleWorld::with(h, BundleWorld::SEED, count, &RULES);
    let (reference, body) = world.assemble_support(
        PassBitmap::from_passes(count, []).expect("no pass"),
        PassBitmap::from_passes(support, []).expect("no support pass"),
        &[],
    );

    chain.reopen();
    let mut cold = DrawableMemo::new();
    let txs = chain.grown.realise(&[]);
    let mut admitted = None;
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let judged = chain.grown.judge_listing_with_section(
            &view,
            &RULES,
            &txs,
            Some(&mut cold),
            std::slice::from_ref(&reference),
            vec![body],
        )?;
        admitted = Some(judged.block().admitted().len());
        batch.connect(judged, RULES)?;
        Ok(())
    });
    out.expect("a cold memo admits: the window's epochs are filed first");
    assert_eq!(admitted, Some(1));
    assert!(
        draws_of(&chain, h).revealed,
        "the previous epoch's bundle is admitted"
    );
}

/// Connect the next block carrying `reference` and `body` as its section.
fn connect_carrying(chain: &mut SlashedChain, reference: &BundleRef, body: &BundleBody) {
    let txs = chain.grown.realise(&[]);
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let judged = chain.grown.judge_listing_with_section(
            &view,
            &RULES,
            &txs,
            None,
            std::slice::from_ref(reference),
            vec![body.clone()],
        )?;
        batch.connect(judged, RULES)?;
        Ok(())
    });
    out.expect("the block admits the bundle");
}

fn queued_hs(chain: &SlashedChain) -> Vec<(BlockHeight, BlockHeight)> {
    chain
        .store
        .begin_read()
        .expect("read")
        .queued_bundles()
        .expect("the queue reads")
        .into_iter()
        .map(|entry| (entry.h, entry.queued.tip_height))
        .collect()
}

fn body_stored(chain: &SlashedChain, hash: &[u8; 32]) -> bool {
    chain
        .store
        .begin_read()
        .expect("read")
        .bundle_body(hash)
        .expect("the body table reads")
        .is_some()
}

/// SI-41's holders across a bundle's life (`bundle_holders.rs`). Queued,
/// the queue holds the body. Admitted, the block holds it and the entry
/// leaves. Popped, the bundle is back in the queue against the tip the pop
/// left. Admitted again, then buried past the undo retention, the body
/// goes: nothing holds it. Red edits: drop `hold_section`'s queue removal
/// (the entry stays after admission); drop `return_section` from `pop` (the
/// popped bundle is not queued); drop `sweep_section` (the body outlives
/// its last holder). The open's reconcile finds nothing to drop at each
/// step.
#[test]
fn a_bundle_body_is_held_by_the_queue_then_its_block_and_returns_on_pop() {
    let mut prepared = prepare("holders");
    let (reference, body) = produce(&prepared);
    let hash = *reference.prunable_hash();
    let h = drawing_height();
    let including = prepared.chain.grown.height();
    let tip_hash = prepared.chain.grown.tip();
    let tip_height = including - BlockCount::ONE;
    let queued: Result<(), TestErr> = prepared.chain.store.write(|batch| {
        batch.queue_bundle(&reference, &body, tip_height, tip_hash, 64)?;
        Ok(())
    });
    queued.expect("the bundle queues");
    assert_eq!(queued_hs(&prepared.chain), vec![(h, tip_height)]);
    assert!(body_stored(&prepared.chain, &hash));
    let reconcile = |chain: &SlashedChain| {
        let out: Result<crate::store::QueueReconciled, TestErr> = chain
            .store
            .write(|batch| Ok(batch.reconcile_bundle_queue()?));
        assert!(
            out.expect("the reconcile runs").is_clean(),
            "every body has a holder"
        );
    };
    reconcile(&prepared.chain);

    connect_carrying(&mut prepared.chain, &reference, &body);
    assert!(
        queued_hs(&prepared.chain).is_empty(),
        "the admitted entry leaves the queue"
    );
    assert!(body_stored(&prepared.chain, &hash), "the block holds it");
    reconcile(&prepared.chain);

    pop_one(&mut prepared.chain);
    assert_eq!(
        queued_hs(&prepared.chain),
        vec![(h, tip_height)],
        "the pop returns the bundle, against the tip it left"
    );
    assert!(body_stored(&prepared.chain, &hash));
    reconcile(&prepared.chain);

    connect_carrying(&mut prepared.chain, &reference, &body);
    assert!(queued_hs(&prepared.chain).is_empty());
    let retention = prepared.chain.store.horizons().undo_retention().to_raw();
    while prepared.chain.grown.height().to_raw() <= including.to_raw() + retention {
        assert!(
            body_stored(&prepared.chain, &hash),
            "held while its block is within the retention"
        );
        connect_plain(&mut prepared.chain, None);
    }
    assert!(
        !body_stored(&prepared.chain, &hash),
        "past the retention nothing holds it"
    );
    reconcile(&prepared.chain);
}
