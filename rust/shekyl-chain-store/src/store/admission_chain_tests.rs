// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Admission against a store chain (`SO-D12` increment 4a, §5).
//!
//! The bundle is the fixture producer's. The view that judges it is the
//! store's, so the commitment, the hashes, `D` and the issued counts are
//! the chain's.

use shekyl_archival_retention::{
    bundle_root, challenge_nonce, draw_commit, select_draw, BundleBody, BundleRef, DrawableEpoch,
    PassBitmap, PassStream,
};
use shekyl_chain_rules::harness::bundle::BundleWorld;
use std::collections::BTreeMap;

use shekyl_chain_rules::{
    admission_plan, judge_bundles, AdmissionFault, BlockDrawsFloor, BundleInvalid, BundleRefused,
    BundleView as _, Corrupt, DrawableMemo, EpochFloor, SettlementCheck, Settling,
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
use super::super::{SlashedChain, TestErr, RULES, WITNESS_PERSONAS};
use super::{h_open, no_draws, plant_witness_shard_set, witness_shard_slots};

/// Ten blocks after epoch 2 opens. With a shard set of the witness width,
/// this harness's schedule draws once here.
fn drawing_height() -> BlockHeight {
    BlockHeight::from_raw(h_open(2) + 10)
}

struct Linked {
    draws: BlockDraws,
    hash: BlockHash,
}

struct Prepared {
    chain: SlashedChain,
    memo: DrawableMemo,
    /// Hash of the block at `h_open(2)`.
    open_hash: BlockHash,
    /// Hash of the drawing block.
    hash: BlockHash,
    /// Hash of the block before it, the anchor.
    anchor_hash: BlockHash,
    /// The count row the drawing block stored.
    count: u32,
}

fn prepare(label: &str) -> Prepared {
    let open = h_open(2);
    let mut chain = SlashedChain::build_with(label, WITNESS_PERSONAS, open - 1, no_draws);
    // The joins are complete trees, so they are not in D. The planted set
    // has the witness width: the width this schedule draws once from, at
    // [`drawing_height`].
    plant_witness_shard_set(&mut chain);
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
    Prepared {
        chain,
        memo,
        open_hash: open_hash.expect("the open connected"),
        hash: linked.hash,
        anchor_hash,
        count,
    }
}

fn connect_plain(chain: &mut SlashedChain, memo: Option<&mut DrawableMemo>) -> Linked {
    let txs = chain.grown.realise(&[]);
    let mut linked = None;
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let judged = chain
            .grown
            .judge_listing_with_memo(&view, &RULES, &txs, memo)?;
        linked = Some(Linked {
            draws: judged.block().archival().draws(),
            hash: judged.block().block().hash(),
        });
        batch.connect(judged, RULES)?;
        Ok(())
    });
    out.expect("the block connects");
    linked.expect("the verdict")
}

fn connect_committed(
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
        let judged = judge_with_memo(&view, candidate, &RULES, Some(memo))?;
        linked = Some(Linked {
            draws: judged.block().archival().draws(),
            hash: judged.block().block().hash(),
        });
        let block = judged.block().block().clone();
        chain.grown.record(&block, &[]);
        batch.connect(judged, RULES)?;
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
    let selected = select_draw(
        &world.seed,
        prepared.hash.as_bytes(),
        0,
        drawable.len(),
        |_| Ok::<_, core::convert::Infallible>(true),
    )
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
    let nonce = challenge_nonce(&world.seed, prepared.hash.as_bytes(), 0, 0);
    let record = world.record_signed_by(
        &signer.keys().receipt_sign_sk,
        pair.shard.to_raw(),
        0,
        anchor,
        PassStream::Economy,
        &nonce,
    );
    let (reference, body) = world.assemble(
        PassBitmap::from_passes(prepared.count, [0]).expect("one pass"),
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
        let bundle_view =
            StoreBundleView::new(&view, &prepared.memo, height, RULES.settlement_schedule());
        let refs = [reference];
        let bodies = [body];
        let root = bundle_root(&refs).expect("one reference");
        let verdict = judge_bundles(&refs, &bodies, &root, height, &bundle_view, &RULES)
            .expect("the store view admits the fixture bundle");
        let txs = prepared.chain.grown.realise(&[]);
        let judged = prepared
            .chain
            .grown
            .judge_listing_with_memo(&view, &RULES, &txs, None)?;
        counted = Some(judged.block().archival().draws());
        batch.connect_admitting(judged, RULES, Some((&prepared.memo, &verdict)))?;
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
    prepared.chain.finish();
}

/// Genesis answers its commitment, and a bundle that does not open it is
/// J33 rather than an unanswered view.
#[test]
fn a_bundle_for_genesis_is_refused_at_j33() {
    let mut chain =
        SlashedChain::build_with("admit-genesis", WITNESS_PERSONAS, h_open(1) - 2, no_draws);
    let mut memo = DrawableMemo::new();
    connect_plain(&mut chain, Some(&mut memo));
    let world = BundleWorld::with(BlockHeight::ZERO, BundleWorld::SEED, 0, &RULES);
    let (reference, body) = world.bundle(&[]);
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let bundle_view = StoreBundleView::new(
            &view,
            &memo,
            BlockHeight::from_raw(2),
            RULES.settlement_schedule(),
        );
        let refs = [reference];
        let bodies = [body];
        let root = bundle_root(&refs).expect("one reference");
        let refused = judge_bundles(
            &refs,
            &bodies,
            &root,
            BlockHeight::from_raw(2),
            &bundle_view,
            &RULES,
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
    chain.finish();
}

/// An empty memo on a connected open is SI-35, not an absent set.
#[test]
fn a_memo_miss_is_the_sequencing_fault() {
    let mut chain =
        SlashedChain::build_with("admit-memo", WITNESS_PERSONAS, h_open(1) - 1, no_draws);
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
        bundle_view.drawable_epoch(SettlementEpoch::from_raw(0))?;
        Ok(())
    });
    let TestErr::Store(text) = out.expect_err("a memo miss faults") else {
        panic!("the batch admitted");
    };
    assert!(text.contains("SI-35"), "{text}");
    chain.finish();
}

/// Settlement's index-vs-digest compare passes after the admission, and
/// fails once an index row is removed from under the digest.
#[test]
fn the_digest_check_closes_on_an_admitted_bundle() {
    let mut prepared = prepare("admit-digest");
    let (admitted, _) = admit(&mut prepared);
    assert_eq!(admitted.len(), 1);
    let deadline = RULES.settlement_schedule().slash_deadline_height(2);
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
    prepared.chain.finish();

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
    tampered.chain.finish();
}

/// A fresh memo at an epoch's open still answers the previous epoch. The
/// window reaches it, and the count phase files it before admission reads.
#[test]
fn a_cold_memo_at_the_open_holds_the_prior_epoch() {
    let open = h_open(2);
    let mut chain = SlashedChain::build_with("cold-memo", WITNESS_PERSONAS, open - 1, no_draws);
    let mut memo = DrawableMemo::new();
    connect_plain(&mut chain, Some(&mut memo));
    let h_incl = chain.grown.height();
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let bundle_view = StoreBundleView::new(&view, &memo, h_incl, RULES.settlement_schedule());
        let drawable = bundle_view.drawable_epoch(SettlementEpoch::from_raw(1))?;
        assert!(drawable.is_some(), "the prior epoch was filed");
        Ok(())
    });
    out.expect("the prior epoch is in the memo");
    chain.finish();
}
