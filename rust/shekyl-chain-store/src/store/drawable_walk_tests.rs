// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The drawable set through the store (`SO-D12` increment 2): the digest
//! each open writes, the Release journal each Release writes, the walk that
//! rebuilds the set from them at a later tip, and the settlement check that
//! compares the two.
//!
//! The chain is the slash-scan harness's (the parent module): four
//! complete-tree personas join in epoch 0 under `SEB 100 / cap 50`, and
//! the padding credits close shard 0 inside epoch 0. Shard 0 is closed and
//! final from height `close + 50`. A complete tree is not in `D`
//! (`ARCHIVAL_SUPPORT_DRAW.md`), so `D(1)` and `D(2)` are empty. Two of
//! the personas release:
//!
//! - slot 3 at [`FIRST_RELEASE`], inside epoch 2 — above `h_open(2)`, so the
//!   walk for epoch 2 undoes it, and below `h_open(3)`, so epoch 3 does not
//!   hold the pair;
//! - slot 2 at [`h_open`]`(3)` itself — undone for epoch 2, and **applied**
//!   for epoch 3, whose open block it is in.
//!
//! The credits are slots 0 and 1's, so the two releasing personas never
//! served and CEN-J16's cooldown is vacuous for them. No draw is issued:
//! the check runs at every settlement whether anything was drawn or not.
//!
//! One test adds a compact bond, planted before epoch 2 opens
//! ([`compact_bond_chain`]), for the one tamper only a compact holding can
//! show: a slash row whose shard is altered to one the walk can restore.
//! The admission child ([`admission_chain_tests`]) plants a shard set of
//! the witness width ([`plant_witness_shard_set`]) before the same open:
//! that width is what this harness's schedule draws once from, at the
//! tenth block of the epoch, and a complete tree is not in the set.
//!
//! The rules-side arms — the undo of each event kind, the order, the
//! filters, a Reinstate — are `shekyl-chain-rules`' `drawable_tests.rs`, on
//! plain data. A slash inside an epoch is witnessed on this harness by
//! `the_window_passes_over_an_unobserved_epoch_and_counts_a_served_one`
//! (`settlement_slash_tests.rs`): its chain runs one epoch past the
//! epoch-`M` slash, whose complete-tree demotions sit above `h_open(M + 1)`,
//! and the settlement of `M + 1` checks the walk that undoes them.
//!
//! The count those rows feed (`SO-D12` increment 3) is
//! [`block_draws_chain_tests`]: a non-empty set's composition, the memo,
//! and the faults a drifted journal or a missing digest raises.

use shekyl_chain_rules::{
    drawable_epoch_walked_back, ChainView as _, DrawableEpoch, DrawableEpochFault, EpochFloor,
    ReleaseJournalFloor, Settling,
};
use shekyl_types::archival::{DrawableDigest, ReleasedRecord};

use crate::codec::BondRecord;

use super::*;

/// The first Release: slot 3, half way through epoch 2.
const FIRST_RELEASE: u64 = 250;
/// The persona released at [`FIRST_RELEASE`].
const FIRST: u32 = 3;
/// The persona released in epoch 3's open block.
const SECOND: u32 = 2;

fn h_open(epoch: u64) -> u64 {
    RULES.settlement_schedule().open_height(epoch)
}

/// Every complete-tree record's balance: the floor of one bond.
const BONDED: u64 = ARCHIVAL_BOND_FLOOR_ATOMIC;

/// What block `h` lists after the harness's own epoch-0 listing: the two
/// Releases, and nothing else.
fn releases_at(h: u64) -> Vec<Listed> {
    if h == FIRST_RELEASE {
        vec![Listed::Release {
            slot: FIRST,
            bonded_total: BONDED,
        }]
    } else if h == h_open(3) {
        vec![Listed::Release {
            slot: SECOND,
            bonded_total: BONDED,
        }]
    } else {
        Vec::new()
    }
}

fn no_draws(_: u64, _: u64) -> Option<&'static [bool]> {
    None
}

/// Connect the block at the chain's next height, listing `listed`.
fn connect(chain: &mut SlashedChain, listed: &[Listed]) {
    let txs = chain.grown.realise(listed);
    let grown = &mut chain.grown;
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let judged = grown.judge_listing(&view, &RULES, &txs)?;
        batch.connect(judged, RULES)?;
        Ok(())
    });
    out.expect("the block connects");
}

/// The chain through `through`, with the two Releases connected where
/// [`releases_at`] puts them.
fn released_chain(label: &str, through: u64) -> SlashedChain {
    let mut chain = SlashedChain::build_with(label, WITNESS_PERSONAS, FIRST_RELEASE - 1, no_draws);
    for h in FIRST_RELEASE..=through {
        connect(&mut chain, &releases_at(h));
    }
    chain
}

/// The walk for `epoch` over the committed chain, under the floors a
/// block connecting at `connecting` would read with. Read in a batch that
/// is aborted, so it writes nothing.
///
/// `connecting` is that block's height, not the height after it. The
/// settlement walk runs at the block that settles the epoch; the next
/// block's journal horizon has stepped past it (SI-28).
fn walked(store: &ChainStore, epoch: u64, connecting: BlockHeight) -> Option<DrawableEpoch> {
    let mut walked = None;
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let schedule = RULES.settlement_schedule();
        let slash = SlashLogFloor::under(connecting, schedule.blocks(), RULES.reorg_cap());
        let journal = ReleaseJournalFloor::of(
            EpochFloor::<Settling>::under(connecting, schedule),
            schedule,
        );
        walked = drawable_epoch_walked_back(
            &view,
            SettlementEpoch::from_raw(epoch),
            schedule,
            RULES.reorg_cap(),
            journal,
            slash,
        )
        .expect("the walk reads");
        Err(TestErr::Abort)
    });
    assert!(matches!(out, Err(TestErr::Abort)));
    walked
}

fn recorded(store: &ChainStore, epoch: u64) -> Option<DrawableDigest> {
    store
        .begin_read()
        .expect("read")
        .drawable_digest(SettlementEpoch::from_raw(epoch), EpochFloor::NONE)
        .expect("read")
}

fn personas_of(drawable: &DrawableEpoch) -> Vec<PCanonicalId> {
    (0..drawable.len())
        .map(|i| drawable.pair(i).expect("below len").persona)
        .collect()
}

/// **The two derivations agree at every height** from `h_open(E)` through
/// the pass that settles `E`, on a chain with a Release above the open and a
/// Release in the open block, for epochs 2 and 3. The digest the open
/// wrote (derivation 1, over the open block's post-state) is compared with
/// the walk at that block (derivation 2), under the floor the block
/// connected with. Both settlement passes, at `399` and `499`, run the
/// same comparison and connect.
///
/// The next block's journal horizon has stepped past the epoch this one
/// settled, so the walk is refused (SI-28) and is not a read the chain
/// makes. The rows remain until the boundary after that.
///
/// Both passes walk an empty set. The joins are complete trees, and a
/// complete tree is not in `D`. The releases are still journaled, and the
/// two derivations agree at every height.
///
/// Red edit: admit a complete tree to `D`. Either pass's set is then the
/// four joins, and the digests the opens wrote no longer match the walk.
#[test]
fn the_two_derivations_agree_at_every_height_across_releases() {
    let schedule = RULES.settlement_schedule();
    let settles_3 = schedule.slash_deadline_height(3);
    let mut chain =
        SlashedChain::build_with("drawable-agree", WITNESS_PERSONAS, h_open(2) - 1, no_draws);
    let mut epoch_2_at_pass = None;
    let mut epoch_3_at_pass = None;
    for h in h_open(2)..=settles_3 {
        connect(&mut chain, &releases_at(h));
        let connecting = BlockHeight::from_raw(h);
        for epoch in [2, 3] {
            if h < h_open(epoch) || !horizon_holds(connecting, epoch) {
                continue;
            }
            let walked =
                walked(&chain.store, epoch, connecting).expect("the epoch is inside the horizon");
            assert_eq!(
                Some(walked.digest()),
                recorded(&chain.store, epoch),
                "epoch {epoch} rebuilt at tip {h}"
            );
            if h == schedule.slash_deadline_height(epoch) {
                let personas = personas_of(&walked);
                if epoch == 2 {
                    epoch_2_at_pass = Some(personas);
                } else {
                    epoch_3_at_pass = Some(personas);
                }
            }
        }
    }
    let snap = chain.store.begin_read().expect("read");
    assert_eq!(
        snap.last_settled_slash_epoch().expect("read"),
        Some(SettlementEpoch::from_raw(3)),
        "both settlement passes ran their check and connected"
    );
    drop(snap);

    let epoch_2 = epoch_2_at_pass.expect("epoch 2's pass walked the set");
    assert!(
        epoch_2.is_empty(),
        "epoch 2's joins are complete trees, and a complete tree is not in D"
    );
    let epoch_3 = epoch_3_at_pass.expect("epoch 3's pass walked the set");
    assert!(
        epoch_3.is_empty(),
        "releasing a complete tree does not put one into D"
    );
    chain.finish();
}

/// Whether a block connecting at `connecting` may still walk `epoch`: the
/// walk starts one above `h_open`, and that start is inside the journal
/// horizon at `connecting`. The same comparison as the walk's own check.
fn horizon_holds(connecting: BlockHeight, epoch: u64) -> bool {
    let schedule = RULES.settlement_schedule();
    let Some(kept) = ReleaseJournalFloor::of(
        EpochFloor::<Settling>::under(connecting, schedule),
        schedule,
    )
    .height() else {
        return true;
    };
    // The scan starts at `h_open + 1`. That start is inside the horizon
    // when it is at or above `kept`. The last height has no row above it,
    // so it is not below the floor — the same comparison as
    // `scan_starts_below`, stated as the walk being allowed.
    let Some(start) = BlockHeight::from_raw(h_open(epoch)).checked_add(BlockCount::ONE) else {
        return true;
    };
    start >= kept
}

/// Each Release writes its record's pre-image under `(height, persona)`:
/// the record exactly as it stood, its complete tree included. A read
/// strictly above a height returns the rows above it in key order.
/// Red edit: journal the post-image.
#[test]
fn a_release_journals_the_record_it_replaced() {
    let chain = released_chain("drawable-journal", h_open(3));
    let snap = chain.store.begin_read().expect("read");
    let rows = snap
        .release_journal_after(BlockHeight::from_raw(h_open(2)), ReleaseJournalFloor::NONE)
        .expect("read");
    let heights: Vec<(u64, PCanonicalId)> = rows
        .iter()
        .map(|r| (r.height.to_raw(), r.persona))
        .collect();
    assert_eq!(
        heights,
        [
            (FIRST_RELEASE, Persona::at(FIRST).id()),
            (h_open(3), Persona::at(SECOND).id()),
        ]
    );
    for ReleasedRecord {
        persona, pre_image, ..
    } in &rows
    {
        assert!(pre_image.is_complete_tree(), "the pre-image holds the tree");
        assert_eq!(pre_image.bonded_total, AtomicUnits::from_raw(BONDED));
        let now = snap.bond_record(persona).expect("read").expect("kept");
        assert!(!now.is_complete_tree(), "the record at tip is emptied");
        assert_eq!(now.receipt_sign_pk, pre_image.receipt_sign_pk);
    }
    assert!(snap
        .release_journal_after(BlockHeight::from_raw(h_open(3)), ReleaseJournalFloor::NONE)
        .expect("read")
        .is_empty());
    drop(snap);
    chain.finish();
}

/// **A journal or a digest that changed after the open halts the
/// settlement pass**, through the validator's `Corrupt` and the store's
/// SI-29 or SI-30, and never as a verdict on the block. Each tamper is made
/// in the batch that then judges the settling block, on a chain of its
/// own: the refusal halts the writer. The walk is the real one over the
/// tampered rows. The same chain untampered settles the epoch: that is
/// [`the_two_derivations_agree_at_every_height_across_releases`].
///
/// - The pre-image of slot 3's Release, with its holdings emptied: epoch 2
///   loses a pair. Drift.
/// - The same pre-image with one byte of its receipt key changed (an edit
///   that still parses): the pairs are the same and the key is not. Drift.
/// - A slash row planted under slot 0, a complete tree at tip, as a
///   complete-tree demotion above the open: the record cannot have been
///   left by it. The walk refuses it.
/// - The digest cell itself. Drift.
/// - The digest removed. Missing.
#[test]
fn a_journal_that_changed_after_the_open_halts_the_settlement() {
    type Tamper = fn(&WriteBatch<'_, '_>) -> Result<(), StoreError>;
    let epoch = SettlementEpoch::from_raw(2);
    let settles = RULES.settlement_schedule().slash_deadline_height(2);

    fn pre_image(batch: &WriteBatch<'_, '_>) -> Result<BondRecord, StoreError> {
        let key = crate::ids::ReleaseJournalKey::new(
            BlockHeight::from_raw(FIRST_RELEASE),
            Persona::at(FIRST).id(),
        );
        Ok(batch
            .chain_view()
            .release_journal_after(
                BlockHeight::from_raw(FIRST_RELEASE - 1),
                ReleaseJournalFloor::NONE,
            )?
            .into_iter()
            .find(|r| r.persona == key.persona())
            .expect("journaled")
            .pre_image)
    }
    fn rewrite(batch: &WriteBatch<'_, '_>, record: &BondRecord) -> Result<(), StoreError> {
        let key = crate::ids::ReleaseJournalKey::new(
            BlockHeight::from_raw(FIRST_RELEASE),
            Persona::at(FIRST).id(),
        );
        batch
            .open_upsert_table(crate::schema::ARCHIVAL_RELEASE_JOURNAL)?
            .upsert(key.key(), record.encoded().as_encoded())?;
        Ok(())
    }
    fn holdings_emptied(batch: &WriteBatch<'_, '_>) -> Result<(), StoreError> {
        let mut record = pre_image(batch)?;
        record.holdings =
            shekyl_types::archival::Holdings::shard_set(Vec::new()).expect("the empty set");
        rewrite(batch, &record)
    }
    fn key_changed(batch: &WriteBatch<'_, '_>) -> Result<(), StoreError> {
        let mut record = pre_image(batch)?;
        let mut bytes = *record.receipt_sign_pk.as_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        // The last byte is the FN-DSA key's last coefficient bits. The
        // edit leaves a key for this persona's: were it not one, the walk
        // would refuse the record (`Construction`), not report drift, and
        // the case's expected `Corrupt` would not match.
        record.receipt_sign_pk = shekyl_types::archival::ReceiptSignPk::from_bytes(bytes);
        rewrite(batch, &record)
    }
    fn slash_planted(batch: &WriteBatch<'_, '_>) -> Result<(), StoreError> {
        let entry = SlashLogEntry {
            persona: Persona::at(0).id(),
            shard: ShardId::from_raw(0),
            epoch: SettlementEpoch::from_raw(1),
            holding: SlashedHolding::CompleteTree,
        };
        batch
            .open_upsert_table(crate::schema::ARCHIVAL_SLASH_LOG)?
            .upsert(
                crate::ids::SlashLogKey::new(BlockHeight::from_raw(FIRST_RELEASE + 1), 0).key(),
                entry.encoded().as_encoded(),
            )?;
        Ok(())
    }
    fn digest_changed(batch: &WriteBatch<'_, '_>) -> Result<(), StoreError> {
        batch
            .open_upsert_table(crate::schema::ARCHIVAL_DRAWABLE_DIGEST)?
            .upsert(
                2,
                DrawableDigest::from_bytes([0x5a; 32])
                    .encoded()
                    .as_encoded(),
            )?;
        Ok(())
    }
    fn digest_removed(batch: &WriteBatch<'_, '_>) -> Result<(), StoreError> {
        batch
            .open_remove_table(
                crate::schema::ARCHIVAL_DRAWABLE_DIGEST,
                StoreInvariant::TipMismatch,
            )?
            .remove(2)?;
        Ok(())
    }

    let drift = Corrupt::SettlementIntegrity {
        epoch,
        check: SettlementCheck::DrawableDrift,
    };
    // A complete tree is not in `D`, so its release pre-image and its
    // receipt key are not operands of the digest. Rewriting them lets the
    // pass settle. The slash row, the replaced digest and the removed
    // digest are still faults: the first cannot be undone onto a complete
    // tree, and the other two are the digest cell itself.
    for (label, tamper) in [
        ("holdings", holdings_emptied as Tamper),
        ("key", key_changed),
    ] {
        let chain = released_chain(&format!("drawable-tamper-{label}"), settles - 1);
        let out: Result<(), TestErr> = chain.store.write(|batch| {
            tamper(batch)?;
            let view = batch.chain_view();
            let Ok(_) = chain.grown.judge_empty_or_corrupt(&view, &RULES)? else {
                panic!("{label}: the pass refused a journal that is not in D");
            };
            Ok(())
        });
        out.expect("{label}: a complete tree's journal is not an operand of D");
        chain.finish();
    }
    let cases: [(&str, Tamper, Corrupt, &str); 3] = [
        (
            "slash",
            slash_planted,
            Corrupt::DrawableEpoch {
                epoch,
                why: DrawableEpochFault::SlashNotUndoable {
                    persona: Persona::at(0).id(),
                    shard: ShardId::from_raw(0),
                },
            },
            "cannot have left the record",
        ),
        (
            "digest",
            digest_changed,
            drift,
            "does not digest to archival_drawable_digest",
        ),
        (
            "removed",
            digest_removed,
            Corrupt::SettlementIntegrity {
                epoch,
                check: SettlementCheck::DrawableDigestMissing,
            },
            "holds no digest for epoch 2",
        ),
    ];
    for (label, tamper, expected, message) in cases {
        // A refusal latches the writer halt, so each case has its chain.
        let chain = released_chain(&format!("drawable-tamper-{label}"), settles - 1);
        let out: Result<(), TestErr> = chain.store.write(|batch| {
            tamper(batch)?;
            let view = batch.chain_view();
            let Err(corrupt) = chain.grown.judge_empty_or_corrupt(&view, &RULES)? else {
                panic!("{label}: the pass settled over a changed journal");
            };
            assert_eq!(corrupt, expected, "{label}");
            Err(batch.refuse_corrupt(corrupt).into())
        });
        let TestErr::Store(refused) = out.expect_err("the batch is refused") else {
            panic!("{label}: aborted, not refused");
        };
        assert!(refused.contains(message), "{label}: {refused}");
        chain.finish();
    }
}

/// **The digest is undone with the open that wrote it**: popping
/// `h_open(3)` removes epoch 3's digest and the Release journaled in that
/// block, and connecting the same block again writes the same digest and
/// the same row. Red edit: write either outside the journal.
#[test]
fn popping_an_open_removes_its_digest_and_reconnecting_writes_it_again() {
    let mut chain = released_chain("drawable-pop", h_open(3));
    let journal = |store: &ChainStore| {
        store
            .begin_read()
            .expect("read")
            .release_journal_after(
                BlockHeight::from_raw(h_open(3) - 1),
                ReleaseJournalFloor::NONE,
            )
            .expect("read")
    };
    let digest = recorded(&chain.store, 3).expect("the open wrote it");
    assert_eq!(journal(&chain.store).len(), 1, "slot 2's Release");

    let popped: Result<Popped, TestErr> = chain.store.write(|batch| Ok(batch.pop()?));
    assert_eq!(
        popped.expect("pops").height,
        BlockHeight::from_raw(h_open(3))
    );
    chain.grown.pop();
    assert_eq!(
        recorded(&chain.store, 3),
        None,
        "the digest went with the block"
    );
    assert!(journal(&chain.store).is_empty(), "and so did the row");
    assert!(
        recorded(&chain.store, 2).is_some(),
        "epoch 2's is untouched"
    );

    connect(&mut chain, &releases_at(h_open(3)));
    assert_eq!(recorded(&chain.store, 3), Some(digest));
    assert_eq!(journal(&chain.store).len(), 1);
    chain.finish();
}

/// A walk whose floor is above its open is refused at the enumerator, and
/// the store refuses the journal read beneath it (SI-28), as it refuses the
/// slash log's (SI-26). The two floors are separate: the journal's is the
/// settling family's horizon, the slash log's its own. Red edit: drop
/// either check.
#[test]
fn a_walk_below_the_floor_is_refused_and_so_is_the_read() {
    let chain = released_chain("drawable-floor", FIRST_RELEASE);
    let schedule = RULES.settlement_schedule();
    let slash = SlashLogFloor::under(
        BlockHeight::from_raw(
            SlashLogFloor::window(schedule.blocks(), RULES.reorg_cap())
                .expect("fits")
                .to_raw()
                + h_open(2)
                + 5,
        ),
        schedule.blocks(),
        RULES.reorg_cap(),
    );
    let slash_kept = slash.height().expect("a slash floor");
    assert!(slash_kept.to_raw() > h_open(2) + 1);
    // Oldest kept epoch 3: the journal of epoch 2 starts below it.
    let connecting = BlockHeight::from_raw(
        schedule.open_height(3 + shekyl_archival_retention::SLASH_GRACE_EPOCHS),
    );
    let journal = ReleaseJournalFloor::of(
        EpochFloor::<Settling>::under(connecting, schedule),
        schedule,
    );
    let journal_kept = journal.height().expect("a journal floor");
    assert!(journal_kept.to_raw() > h_open(2) + 1);
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let refused = drawable_epoch_walked_back(
            &view,
            SettlementEpoch::from_raw(2),
            schedule,
            RULES.reorg_cap(),
            journal,
            slash,
        );
        assert!(
            matches!(
                refused,
                Err(shekyl_chain_rules::ViewRead::Corrupt(
                    Corrupt::DrawableEpoch {
                        why: DrawableEpochFault::BelowFloor { .. },
                        ..
                    }
                ))
            ),
            "{refused:?}"
        );
        Err(TestErr::Abort)
    });
    assert!(matches!(out, Err(TestErr::Abort)));
    let snap = chain.store.begin_read().expect("read");
    let asked = BlockHeight::from_raw(h_open(2));
    let refused_journal = snap.release_journal_after(asked, journal).map(drop);
    assert!(
        matches!(
            refused_journal,
            Err(StoreError::InvariantViolated(StoreInvariant::ReleaseJournalReadBelowFloor { asked: a, floor: f }))
                if a == asked && f == journal_kept
        ),
        "{refused_journal:?}"
    );
    let log = snap.slash_log_rows_after(asked, slash).map(drop);
    assert!(
        matches!(
            log,
            Err(StoreError::InvariantViolated(StoreInvariant::SlashLogReadBelowFloor { asked: a, floor: f }))
                if a == asked && f == slash_kept
        ),
        "{log:?}"
    );
    drop(snap);
    chain.finish();
}

/// The first persona of a planted compact bond: a slot none of the
/// harness's joins uses. [`plant_witness_shard_set`] continues from here.
const COMPACT: u32 = 9;

/// Slots of [`plant_witness_shard_set`]: [`WITNESS_PERSONAS`] of them,
/// from [`COMPACT`]. The harness joins occupy `0..WITNESS_PERSONAS`.
fn witness_shard_slots() -> impl Iterator<Item = u32> {
    let width = u32::try_from(WITNESS_PERSONAS).expect("the witness width fits a slot");
    (0..width).map(|offset| COMPACT.checked_add(offset).expect("the planted slots fit"))
}

/// One compact bond holding shard 0, committed under `slot` outside any
/// block journal. A later pop does not remove it. The harness's joins are
/// complete trees, and a compact join needs a priced, closed and final
/// shard (CEN-J15); a planted record is the compact bond an open then
/// digests like any other.
fn plant_compact_bond_at(chain: &mut SlashedChain, slot: u32) {
    let persona = Persona::at(slot);
    let record = BondRecord {
        hybrid_pubkey: persona.identity(),
        bond_spend_pk: persona.bond_spend(),
        receipt_sign_pk: persona.receipt_key(),
        endpoint: [0xEE; 32],
        join_settlement_epoch: SettlementEpoch::from_raw(0),
        bonded_total: AtomicUnits::from_raw(BONDED),
        holdings: compact_holdings(&[0]),
        bad_intervals: Vec::new(),
        claimed_settlement_epochs: Vec::new(),
        first_paying_emission_height: None,
    };
    let planted: Result<(), TestErr> = chain.store.write(|batch| {
        batch
            .open_insert_table(
                crate::schema::ARCHIVAL_BOND,
                StoreInvariant::BondRecordNotFresh,
            )?
            .insert(*persona.id().as_bytes(), record.encoded().as_encoded())?;
        Ok(())
    });
    planted.expect("planted");
}

/// The one compact bond [`compact_bond_chain`] and the count tests share.
fn plant_compact_bond(chain: &mut SlashedChain) {
    plant_compact_bond_at(chain, COMPACT);
}

/// [`WITNESS_PERSONAS`] compact bonds, each holding shard 0. That width is
/// the set this harness's schedule draws once from at the tenth block of
/// an epoch. The joins are complete trees and contribute no pair.
fn plant_witness_shard_set(chain: &mut SlashedChain) {
    for slot in witness_shard_slots() {
        plant_compact_bond_at(chain, slot);
    }
}

/// The harness chain through `h_open(2) − 1`, with [`plant_compact_bond`]
/// applied before epoch 2 opens, then connected to `through`.
fn compact_bond_chain(label: &str, through: u64) -> SlashedChain {
    let mut chain = SlashedChain::build_with(label, WITNESS_PERSONAS, h_open(2) - 1, no_draws);
    plant_compact_bond(&mut chain);
    for _ in h_open(2)..=through {
        connect(&mut chain, &[]);
    }
    chain
}

fn compact_holdings(shards: &[u64]) -> shekyl_types::archival::Holdings {
    shekyl_types::archival::Holdings::shard_set(
        shards
            .iter()
            .map(|&shard| shekyl_types::archival::HeldShard {
                shard: ShardId::from_raw(shard),
                add_epoch: SettlementEpoch::from_raw(0),
            })
            .collect(),
    )
    .expect("distinct shards under the cap")
}

/// A slash of the compact bond's shard 0 above `h_open` of the epoch the
/// settling block connects in, as the store holds one: the record without
/// the shard and a log row naming the shard the slash took. `shard` is
/// what the row names. The count of that connecting block walks the same
/// range, so the row has to sit above that open too.
fn slash_compact_bond(batch: &WriteBatch<'_, '_>, shard: u64) -> Result<(), StoreError> {
    let persona = Persona::at(COMPACT).id();
    let mut record = batch
        .chain_view()
        .bond_record(&persona)?
        .expect("the compact bond");
    record.holdings = compact_holdings(&[]);
    batch
        .open_upsert_table(crate::schema::ARCHIVAL_BOND)?
        .upsert(*persona.as_bytes(), record.encoded().as_encoded())?;
    let entry = SlashLogEntry {
        persona,
        shard: ShardId::from_raw(shard),
        epoch: SettlementEpoch::from_raw(1),
        holding: SlashedHolding::Shard {
            add_epoch: SettlementEpoch::from_raw(0),
        },
    };
    batch
        .open_upsert_table(crate::schema::ARCHIVAL_SLASH_LOG)?
        .upsert(
            crate::ids::SlashLogKey::new(BlockHeight::from_raw(h_open(3) + 1), 0).key(),
            entry.encoded().as_encoded(),
        )?;
    Ok(())
}

/// **A slash-log row that names another shard, which the walk can still
/// restore, halts the settlement as drift.** Epoch 2 holds the compact
/// bond's `(P, 0)`. A slash of shard 0 above the open — the record emptied,
/// the row naming shard 0 — rebuilds the same set, and the settling block
/// judges clean. The same slash with its row altered to name shard 5
/// restores shard 5 instead: the record holds a shard it can take back,
/// so the walk completes, but shard 5 is not closed and final at the open
/// and `(P, 0)` is not restored, so the rebuilt set lacks the pair the
/// open digested. That is `SettlementCheck::DrawableDrift`, SI-30, and
/// never a verdict on the block.
///
/// Red edit: restore the row's shard without the digest comparison
/// (report `Ok` when the walk completes). The open digested one pair, and
/// the altered row restores none, so a length comparison does not hide it.
#[test]
fn a_slash_row_naming_another_shard_halts_the_settlement_as_drift() {
    let epoch = SettlementEpoch::from_raw(2);
    let settles = RULES.settlement_schedule().slash_deadline_height(2);
    let chain = compact_bond_chain("drawable-compact", settles - 1);
    let compact = Persona::at(COMPACT).id();
    // The settling block, one above this tip, is the walk's reader.
    let held = walked(&chain.store, 2, BlockHeight::from_raw(settles)).expect("opened");
    assert!(
        personas_of(&held).contains(&compact),
        "epoch 2 holds the compact bond's pair"
    );

    // The slash as the store would hold it: the settling block judges.
    let control: Result<(), TestErr> = chain.store.write(|batch| {
        slash_compact_bond(batch, 0)?;
        let view = batch.chain_view();
        assert!(
            chain.grown.judge_empty_or_corrupt(&view, &RULES)?.is_ok(),
            "an honest slash above the open rebuilds the same set"
        );
        Err(TestErr::Abort)
    });
    assert!(matches!(control, Err(TestErr::Abort)));

    // The same slash with the row's shard altered.
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        slash_compact_bond(batch, 5)?;
        let view = batch.chain_view();
        let Err(corrupt) = chain.grown.judge_empty_or_corrupt(&view, &RULES)? else {
            panic!("the pass settled over a slash row naming another shard");
        };
        assert_eq!(
            corrupt,
            Corrupt::SettlementIntegrity {
                epoch,
                check: SettlementCheck::DrawableDrift,
            }
        );
        Err(batch.refuse_corrupt(corrupt).into())
    });
    let TestErr::Store(refused) = out.expect_err("the batch is refused") else {
        panic!("aborted, not refused");
    };
    assert!(
        refused.contains("does not digest to archival_drawable_digest"),
        "{refused}"
    );
    chain.finish();
}

#[path = "block_draws_chain_tests.rs"]
mod block_draws_chain_tests;

#[path = "admission_chain_tests.rs"]
mod admission_chain_tests;
