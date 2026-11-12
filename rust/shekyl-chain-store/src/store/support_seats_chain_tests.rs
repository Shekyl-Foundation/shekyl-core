// Copyright (c) 2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The support schedule on a store chain (`SO-D12` 4b §5.1 item 3; S1).
//!
//! The chain is the slash witness's: its four joins are complete trees, and
//! shard 0 closes before they join (height 131, the captured shard fill),
//! so the trees are support members of every epoch whose open sees the
//! shard closed and final. The seats are the transition's, written by the
//! store's connect, and read back through the store's own view.
//!
//! Every epoch numbered in this file's prose is counted from the personas'
//! join epoch: "epoch 2" is `shifted(2)` ([`shifted`]), because the chain
//! loads the captured shard-fill prefix first and the personas join after it.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_retention::{
    bundle_root, draw_commit, DrawableEpoch, PassBitmap, SUPPORT_DRAWS_PER_EPOCH,
};
use shekyl_chain_rules::harness::bundle::BundleWorld;
use shekyl_chain_rules::{
    draw_targets, judge_bundles, BlockDrawsFloor, BundleView as _, DrawOrigin, DrawableMemo,
};
use shekyl_types::archival::{
    BlockDraws, DrawCommitment, SupportCarryAfter, SupportCount, SupportRow, SupportSeats,
};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, PCanonicalId};

use crate::codec::Canonical;

use super::super::super::StoreBundleView;
use super::super::{shifted, SlashedChain, TestErr, Under, RULES, WITNESS_PERSONAS};
use super::admission_chain_tests::{connect_committed, connect_plain};
use super::block_draws_chain_tests::{compose, pop_back};
use super::{h_open, no_draws};

fn seb() -> u64 {
    RULES.settlement_schedule().blocks().get()
}

fn window() -> u64 {
    RULES
        .settlement_schedule()
        .challenge_response_blocks()
        .expect("the witness schedule has a window")
        .get()
}

/// A member's epoch-relative seats, from the specification's formula
/// (`ARCHIVAL_SUPPORT_DRAW.md` §2) and not from the retention crate:
/// `r_i = (LE64(P[0..8]) mod span + ⌊i · span / c⌋) mod span`,
/// `span = SEB − W₂`.
fn specified_seats(persona: &PCanonicalId) -> BTreeSet<u64> {
    let span = seb() - window();
    let mut le = [0u8; 8];
    le.copy_from_slice(&persona.as_bytes()[..8]);
    let offset = u64::from_le_bytes(le) % span;
    let c = u64::from(SUPPORT_DRAWS_PER_EPOCH);
    (0..c).map(|i| (offset + i * span / c) % span).collect()
}

fn seat_row(chain: &SlashedChain, h: u64) -> Option<SupportSeats> {
    chain
        .store
        .begin_read()
        .expect("read")
        .support_row(BlockHeight::from_raw(h), BlockDrawsFloor::NONE)
        .expect("read")
        .map(|row| row.seats)
}

/// A chain connected from `h_open(shifted(1))` through `through` with one memo,
/// and each epoch's snapshot as its open filed it.
struct Seated {
    chain: SlashedChain,
    memo: DrawableMemo,
    snapshots: BTreeMap<u64, DrawableEpoch>,
    /// Every connected height's seat row, read right after it connected:
    /// the rows retire with the draw rows, so a later read can miss them.
    rows: BTreeMap<u64, SupportSeats>,
    /// Every connected height's count row, as its connect wrote it.
    draws: BTreeMap<u64, BlockDraws>,
    /// Every connected height's carry, as its row holds it, read right
    /// after it connected.
    carried: BTreeMap<u64, Carried>,
}

/// A block's `carry_after`, as counts.
type Carried = BTreeMap<PCanonicalId, u32>;

fn carried_at(chain: &SlashedChain, h: u64) -> Carried {
    chain
        .store
        .begin_read()
        .expect("read")
        .support_row(BlockHeight::from_raw(h), BlockDrawsFloor::NONE)
        .expect("read")
        .expect("a connected height has its row")
        .carry_after
        .as_slice()
        .iter()
        .map(|(persona, count)| (*persona, count.get()))
        .collect()
}

fn seated(label: &str, through: u64) -> Seated {
    seated_under(label, through, Under::BENCH)
}

/// [`seated`] on a chain built and connected under `under`.
fn seated_under(label: &str, through: u64, under: Under) -> Seated {
    let mut chain = SlashedChain::build_under(
        label,
        WITNESS_PERSONAS,
        h_open(shifted(1)) - 1,
        no_draws,
        under,
    );
    let mut memo = DrawableMemo::new();
    let mut snapshots = BTreeMap::new();
    let mut rows = BTreeMap::new();
    let mut draws = BTreeMap::new();
    let mut carried = BTreeMap::new();
    let schedule = RULES.settlement_schedule();
    for h in h_open(shifted(1))..=through {
        let linked = connect_plain(&mut chain, Some(&mut memo));
        rows.insert(
            h,
            seat_row(&chain, h).expect("a connected height has its row"),
        );
        draws.insert(h, linked.draws);
        let epoch = schedule.epoch_at(BlockHeight::from_raw(h));
        carried.insert(h, carried_at(&chain, h));
        if h == h_open(epoch.to_raw()) {
            let snapshot = memo
                .get(epoch, &linked.hash)
                .expect("the open filed its snapshot")
                .clone();
            snapshots.insert(epoch.to_raw(), snapshot);
        }
    }
    Seated {
        chain,
        memo,
        snapshots,
        rows,
        draws,
        carried,
    }
}

/// A tree's seats over an epoch when no seat is ever filed, written from
/// the specification's carry passage and not from the rules crate
/// (`ARCHIVAL_SUPPORT_DRAW.md` §2): the epoch-relative heights it sits at,
/// and what it is owed after each one. The spec states that a seat at `h`
/// is first seen unfiled at `h + W₂ + 1`, that it is owed again, capped at
/// `c`, and that an owed tree takes one seat on each later block below
/// `SEB − W₂` that its schedule does not seat. The spec does not say
/// whether the block at `h + W₂ + 1` can itself carry it. This oracle
/// follows the connect, which notes the close before that block seats, so
/// it can.
fn unfiled_seats(persona: &PCanonicalId) -> (BTreeSet<u64>, Vec<u32>) {
    let scheduled = specified_seats(persona);
    let span = seb() - window();
    let c = SUPPORT_DRAWS_PER_EPOCH;
    let mut seated = BTreeSet::new();
    let mut owed_after = Vec::new();
    let mut owed = 0u32;
    for relative in 0..seb() {
        if let Some(closed) = relative.checked_sub(window() + 1) {
            if seated.contains(&closed) {
                owed = (owed + 1).min(c);
            }
        }
        if scheduled.contains(&relative) {
            seated.insert(relative);
        } else if relative < span && owed > 0 {
            owed -= 1;
            seated.insert(relative);
        }
        owed_after.push(owed);
    }
    (seated, owed_after)
}

/// A tree's seats over an epoch are its `c` slots and the carry of every
/// one of them that went unfiled, at every archive width the chain passes
/// through: none while the archive at the open is empty (a complete tree
/// of an empty archive holds nothing to draw). No bundle is admitted on
/// this chain, so no seat is filed and the carry runs to its cap. Each
/// row's `carry_after` is what each tree is owed after that block, and the
/// next epoch's open steps from nothing. And the economy is unchanged by
/// any of it: a
/// complete tree is not in `D`, so every count row is the production
/// composition for an empty `D`. Red edits: spread the slots over
/// `0..SEB` in `support_slot` (the rows leave the specified slots); drop
/// the carry from the connect (the rows are the schedule alone); step an
/// open from the row before it (the epoch before's carry crosses); build a
/// roster at
/// width zero in `emit` (it does not compile: `SupportRoster`'s width is a
/// `NonZeroU64`); put a tree's pair into `D` (`D` is not empty, and the
/// count moves).
#[test]
fn a_trees_seats_over_an_epoch_are_its_c_slots_and_their_carry_at_each_width() {
    // Under the bench pair shard 0 (closed at height 131) is final at 181,
    // before the members' first open (height 200), so every epoch with
    // members has a closed shard. The late-final pair puts that open before
    // shard 0 is final (221): members at width 0, then width 1 at 300.
    let through = h_open(shifted(4)) - 1;
    let seated = seated_under("support-seats-epochs", through, Under::LATE_FINAL);
    let trees: BTreeSet<PCanonicalId> = (0..WITNESS_PERSONAS)
        .map(|slot| shekyl_harness_spender::Persona::at(u32::try_from(slot).expect("small")).id())
        .collect();
    let mut widths = BTreeSet::new();
    let mut with_members = 0;
    let mut carried_seats = 0;
    let mut lapses = 0;
    for (&epoch, snapshot) in &seated.snapshots {
        // No roster is the archive with no closed shard at the open; the
        // test reads it as width 0.
        let roster = snapshot.support_roster();
        let width = roster.map_or(0, |roster| roster.width().get());
        widths.insert(width);
        let members: BTreeSet<PCanonicalId> = roster
            .map(|roster| roster.members().iter().map(|(p, _)| *p).collect())
            .unwrap_or_default();
        let open = h_open(epoch);
        let mut seated_at: BTreeMap<PCanonicalId, BTreeSet<u64>> = BTreeMap::new();
        for relative in 0..seb() {
            let row = &seated.rows[&(open + relative)];
            for persona in row.as_slice() {
                seated_at.entry(*persona).or_default().insert(relative);
            }
        }
        assert_eq!(
            snapshot.len(),
            0,
            "epoch {epoch}: a complete tree is not in D"
        );
        let last = open + seb() - 1;
        let counted: Vec<BlockDraws> = (open..=last).map(|h| seated.draws[&h]).collect();
        assert_eq!(
            counted,
            compose(0, open, last),
            "epoch {epoch}: the count is an empty D's"
        );
        // The epoch before ended owing: its last row holds the carry, and
        // this open steps from nothing (`SO-D12r`). The per-tree check
        // below holds the open's row to the oracle started empty.
        if let Some(ended) = seated.carried.get(&(open - 1)) {
            lapses += usize::from(!ended.is_empty());
        }
        if roster.is_none() {
            assert!(seated_at.is_empty(), "epoch {epoch}: no roster, no seat");
            for relative in 0..seb() {
                let rows = &seated.carried[&(open + relative)];
                assert!(rows.is_empty(), "epoch {epoch}: no roster, no carry");
            }
            continue;
        }
        with_members += 1;
        assert_eq!(members, trees, "epoch {epoch}: the joins are the members");
        for tree in &trees {
            let (expected, owed_after) = unfiled_seats(tree);
            assert!(
                specified_seats(tree).is_subset(&expected),
                "the oracle seats every scheduled slot"
            );
            carried_seats += expected.len() - specified_seats(tree).len();
            assert_eq!(
                seated_at.get(tree),
                Some(&expected),
                "epoch {epoch}, width {width}: {tree:?} at its slots and their carry"
            );
            for (relative, owed) in (0u64..).zip(&owed_after) {
                let rows = &seated.carried[&(open + relative)];
                assert_eq!(
                    rows.get(tree).copied().unwrap_or(0),
                    *owed,
                    "epoch {epoch}, relative {relative}: {tree:?}'s carry row"
                );
            }
        }
    }
    assert!(
        with_members > 0,
        "the subject exists: an epoch with members"
    );
    assert!(
        carried_seats > 0,
        "the subject exists: a seat the carry added"
    );
    assert!(
        lapses > 0,
        "the subject exists: an epoch that ended owing, then opened empty"
    );
    assert!(
        widths.len() >= 2,
        "the chain passes through two archive widths: {widths:?}"
    );
}

/// The first height of `epoch` whose row seats someone.
fn first_seated(chain: &SlashedChain, epoch: u64) -> u64 {
    (h_open(epoch)..h_open(epoch + 1))
        .find(|&h| seat_row(chain, h).is_some_and(|row| !row.is_empty()))
        .expect("the epoch seats a tree")
}

/// A past block's roster reads as its row was written when it connected,
/// with each seat's key from its epoch's snapshot, after later blocks have
/// connected; the width is the snapshot's. Red edit: read the roster's row
/// at the view's `h_incl` instead of at `h` (that row is not yet written,
/// so the roster is the hole).
#[test]
fn a_past_blocks_roster_reads_as_written_at_connect() {
    let Seated {
        mut chain,
        mut memo,
        snapshots,
        ..
    } = seated("support-seats-roster", h_open(shifted(2)));
    let snapshot = snapshots[&shifted(2)].clone();
    let h = first_scheduled_after_open(&snapshot, shifted(2));
    // Connect up to the end of `h`'s window, so the view's `h_incl` is
    // the last height that can still admit `h`'s bundle.
    while chain.grown.height().to_raw() < h + window() {
        connect_plain(&mut chain, Some(&mut memo));
    }
    let h_incl = chain.grown.height();
    let row = seat_row(&chain, h).expect("the row");
    assert!(!row.is_empty(), "the subject exists: {h} seats a tree");
    let at = BlockHeight::from_raw(h);
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let bundle_view = StoreBundleView::new(&view, &memo, h_incl, RULES.settlement_schedule());
        assert_eq!(
            bundle_view.support_count(at).expect("read"),
            Some(u32::try_from(row.len()).expect("small"))
        );
        let roster = bundle_view
            .support_roster(at)
            .expect("read")
            .expect("a written row is a roster");
        let personas: Vec<PCanonicalId> = roster.iter().map(|seat| seat.persona).collect();
        assert_eq!(personas, row.as_slice());
        for seat in &roster {
            assert_eq!(
                Some(&seat.receipt_key),
                snapshot
                    .support_roster()
                    .and_then(|roster| roster.key(&seat.persona))
            );
        }
        assert_eq!(
            bundle_view.archive_width(at).expect("read"),
            snapshot
                .support_roster()
                .map(shekyl_archival_retention::SupportRoster::width)
        );
        Err(TestErr::Abort)
    });
    assert!(matches!(out, Err(TestErr::Abort)));
}

/// The first height after `epoch`'s open that its schedule seats a tree
/// at, from the snapshot the open filed.
fn first_scheduled_after_open(snapshot: &DrawableEpoch, epoch: u64) -> u64 {
    (h_open(epoch) + 1..h_open(epoch + 1))
        .find(|&h| {
            !shekyl_chain_rules::scheduled_seats(
                snapshot,
                BlockHeight::from_raw(h),
                RULES.settlement_schedule(),
            )
            .expect("the snapshot of the epoch's own height")
            .is_empty()
        })
        .expect("the epoch seats a tree after its open")
}

/// SI-43: a support row that is not one step of the carry from the row
/// before it halts the read. Five plants, each the row as written with one
/// half changed. In the seats: a stranger, a member the step does not
/// seat, a seated member the row drops (the three ways two strictly
/// increasing lists differ). In `carry_after`: a carried tree owed one
/// more than the step leaves, and a stranger carried. Red edits, each
/// reading as a roster: compare the seats only (the carry plants pass);
/// replace the seat equality with the two inclusions (the extra member
/// passes).
#[test]
fn a_support_row_that_is_not_one_step_of_the_carry_is_si_43() {
    /// What a case plants, and the persona the refusal must name.
    type Plant = dyn Fn(&SupportRow) -> (SupportRow, PCanonicalId);
    let stranger = PCanonicalId::from_bytes([0xEE; 32]);
    let members: Vec<PCanonicalId> = (0..WITNESS_PERSONAS)
        .map(|slot| shekyl_harness_spender::Persona::at(u32::try_from(slot).expect("small")).id())
        .collect();
    let with_seats = |row: &SupportRow, seats: Vec<PCanonicalId>| SupportRow {
        seats: SupportSeats::new(seats).expect("ascending"),
        carry_after: row.carry_after.clone(),
    };
    let with_carry = |row: &SupportRow, carry: Vec<(PCanonicalId, SupportCount)>| SupportRow {
        seats: row.seats.clone(),
        carry_after: SupportCarryAfter::new(carry).expect("ascending, each owed"),
    };
    let plant_stranger = move |row: &SupportRow| {
        let mut seats = row.seats.as_slice().to_vec();
        seats.push(stranger);
        seats.sort_unstable();
        (with_seats(row, seats), stranger)
    };
    let plant_extra = move |row: &SupportRow| {
        let extra = members
            .iter()
            .copied()
            .find(|persona| row.seats.as_slice().binary_search(persona).is_err())
            .expect("the first seated height does not seat every member");
        let mut seats = row.seats.as_slice().to_vec();
        seats.push(extra);
        seats.sort_unstable();
        (with_seats(row, seats), extra)
    };
    let plant_dropped = move |row: &SupportRow| {
        let missing = *row
            .seats
            .as_slice()
            .first()
            .expect("the subject seats someone");
        (with_seats(row, Vec::new()), missing)
    };
    let plant_owed_more = move |row: &SupportRow| {
        let mut carry = row.carry_after.as_slice().to_vec();
        let persona = match carry.first_mut() {
            Some((persona, owed)) => {
                *owed = SupportCount::new(owed.get() + 1);
                *persona
            }
            None => {
                let persona = *row
                    .seats
                    .as_slice()
                    .first()
                    .expect("the subject seats someone");
                carry.push((persona, SupportCount::new(1)));
                persona
            }
        };
        (with_carry(row, carry), persona)
    };
    let plant_carried_stranger = move |row: &SupportRow| {
        let mut carry = row.carry_after.as_slice().to_vec();
        carry.push((stranger, SupportCount::new(1)));
        carry.sort_unstable_by_key(|(persona, _)| *persona);
        (with_carry(row, carry), stranger)
    };
    let cases: [(&str, &Plant); 5] = [
        ("stranger", &plant_stranger),
        ("extra member", &plant_extra),
        ("dropped", &plant_dropped),
        ("owed more", &plant_owed_more),
        ("carried stranger", &plant_carried_stranger),
    ];
    for (n, (label, plant)) in cases.into_iter().enumerate() {
        // An SI-43 halts the writer, so each case has its chain.
        let Seated { chain, memo, .. } =
            seated(&format!("support-seats-si43-{n}"), h_open(shifted(2)) + 10);
        let h = first_seated(&chain, shifted(2));
        let at = BlockHeight::from_raw(h);
        let row = chain
            .store
            .begin_read()
            .expect("read")
            .support_row(at, BlockDrawsFloor::NONE)
            .expect("read")
            .expect("the row");
        let (planted, persona) = plant(&row);
        let out: Result<(), TestErr> = chain.store.write(|batch| {
            batch
                .open_upsert_table(crate::schema::ARCHIVAL_SUPPORT_BLOCK)?
                .upsert(h, planted.encoded().as_encoded())?;
            let view = batch.chain_view();
            let h_incl = chain.grown.height();
            let bundle_view =
                StoreBundleView::new(&view, &memo, h_incl, RULES.settlement_schedule());
            Ok(bundle_view.support_roster(at).map(|_| ())?)
        });
        let Err(TestErr::Store(refused)) = out else {
            panic!("{label}: the planted row read as a roster: {out:?}");
        };
        assert!(refused.contains("SI-43"), "{label}: {refused}");
        assert!(
            refused.contains("is not one step of the carry"),
            "{label}: {refused}"
        );
        assert!(
            refused.contains(&format!("{persona:?}")),
            "{label}: {refused}"
        );
    }
}

/// The step reads the carry `h − 1` left, not an earlier one. The read is
/// at a block that seated someone (so admission asks for its roster) and
/// whose carry before it differs from the carry two blocks back: the honest
/// row reads as a roster, every seat with its key. Red edit: read the carry
/// of `h − 2` in `one_step`. The step then differs from the row, and the
/// read halts on SI-43.
#[test]
fn a_roster_steps_from_the_carry_of_the_row_before_it() {
    let Seated {
        chain,
        memo,
        carried,
        ..
    } = seated("support-seats-step-from-h-1", h_open(shifted(3)) - 1);
    let tip = chain.grown.height().to_raw() - 1;
    let h = (h_open(shifted(2)) + 2..=tip)
        .find(|&h| {
            seat_row(&chain, h).is_some_and(|row| !row.is_empty())
                && carried[&(h - 1)] != carried[&(h - 2)]
        })
        .expect("the subject exists: a seated block whose carry before it moved");
    let at = BlockHeight::from_raw(h);
    let seats = seat_row(&chain, h).expect("the row");
    let out: Result<usize, TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let h_incl = chain.grown.height();
        let bundle_view = StoreBundleView::new(&view, &memo, h_incl, RULES.settlement_schedule());
        Ok(bundle_view
            .support_roster(at)?
            .expect("a connected block has a roster")
            .len())
    });
    assert_eq!(
        out.expect("the honest row is the step"),
        seats.len(),
        "every seat of block {h} has its key"
    );
}

/// A pop removes the block's seat row through the journal, and the
/// reconnect writes it back. Red edit: skip the seat row's entries in the
/// pop's undo replay (the row outlives its block, and the reconnect's
/// insert-once refuses as SI-40).
#[test]
fn a_pop_removes_the_seat_row_and_the_reconnect_restores_it() {
    let Seated {
        mut chain,
        mut memo,
        ..
    } = seated("support-seats-pop", h_open(shifted(2)) + 40);
    let h = first_seated(&chain, shifted(2));
    let tip = chain.grown.height().to_raw() - 1;
    let rows: Vec<Option<SupportSeats>> = (h..=tip).map(|at| seat_row(&chain, at)).collect();
    pop_back(&mut chain, tip - h + 1);
    for at in h..=tip {
        assert_eq!(seat_row(&chain, at), None, "{at}'s row went with its block");
    }
    for _ in h..=tip {
        connect_plain(&mut chain, Some(&mut memo));
    }
    let again: Vec<Option<SupportSeats>> = (h..=tip).map(|at| seat_row(&chain, at)).collect();
    assert_eq!(again, rows, "the reconnect writes the same rows");
    assert!(rows[0].as_ref().is_some_and(|row| !row.is_empty()));
}

/// The producer's support draws over the store's view are the verifier's
/// observations: same seats, same shards, same order, and the seats are
/// the block's row. The producer files every support bit clear, which the
/// verifier observes without a record. The two read one derivation, so
/// what this holds is the store view answering both alike. Red edit: answer
/// `support_count` with the epoch's member count instead of the row's
/// length (the verifier refuses the stated count against the roster).
#[test]
fn the_producers_support_draws_are_the_verifiers_observations() {
    let Seated {
        mut chain,
        mut memo,
        snapshots,
        ..
    } = seated("support-seats-twin", h_open(shifted(2)));
    let first =
        first_scheduled_after_open(&snapshots[&shifted(2)], shifted(2)) - h_open(shifted(2));
    // Connect to the block before the seated one, then the seated block
    // with a commitment the fixture producer holds the seed of.
    let h = BlockHeight::from_raw(h_open(shifted(2)) + first);
    while chain.grown.height() < h {
        connect_plain(&mut chain, Some(&mut memo));
    }
    let anchor_hash: BlockHash = chain.grown.tip();
    let mut world = BundleWorld::with(h, BundleWorld::SEED, 0, &RULES);
    let commitment =
        DrawCommitment::from_bytes(draw_commit(&world.witness_public_key, &world.seed));
    let linked = connect_committed(&mut chain, &mut memo, commitment);
    assert_eq!(linked.draws.count, 0, "no compact pair: no economy draw");
    let row = seat_row(&chain, h.to_raw()).expect("the row");
    assert!(
        !row.is_empty(),
        "the subject exists: the block seats a tree"
    );

    let h_incl = chain.grown.height();
    world.view.hashes.insert(h, linked.hash);
    world.view.hashes.insert(h - BlockCount::ONE, anchor_hash);
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let bundle_view = StoreBundleView::new(&view, &memo, h_incl, RULES.settlement_schedule());
        let targets = draw_targets(&bundle_view, h, &world.seed, &RULES).expect("the view answers");
        let support: Vec<_> = targets
            .draws
            .iter()
            .filter(|drawn| matches!(drawn.origin, DrawOrigin::Support))
            .collect();
        let personas: Vec<PCanonicalId> = support.iter().map(|d| d.persona).collect();
        assert_eq!(
            personas,
            row.as_slice(),
            "the producer dials the row's seats"
        );

        let issued = u32::try_from(row.len()).expect("small");
        let (reference, body) = world.assemble_support(
            PassBitmap::from_passes(0, []).expect("no economy draw"),
            PassBitmap::from_passes(issued, []).expect("every support bit clear"),
            &[],
        );
        let refs = [reference];
        let bodies = [body];
        let root = bundle_root(&refs).expect("one reference");
        let admitted = judge_bundles(
            &refs,
            &bodies,
            &root,
            h_incl,
            &bundle_view,
            &RULES,
            &shekyl_network::HARNESS_NETWORK_ID,
        )
        .expect("the store view admits the clear-bit bundle");
        let observed = &admitted[0].support;
        assert_eq!(observed.len(), support.len());
        for (target, seen) in support.iter().zip(observed) {
            assert_eq!(
                (target.draw, target.persona, target.shard),
                (seen.draw, seen.persona, seen.shard)
            );
            assert!(!seen.passed);
        }
        Err(TestErr::Abort)
    });
    assert!(matches!(out, Err(TestErr::Abort)));
}
