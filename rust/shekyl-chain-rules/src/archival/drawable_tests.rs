// Copyright (c) 2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The builder's emitter and its rewind, on plain data. Each test names the
//! edit that turns it red (rule 50). The walk over a real store — events
//! journaled by connected blocks, the two derivations compared at every
//! height, a perturbed journal halting the settlement pass — is the store's
//! (`shekyl-chain-store`, `drawable_walk_tests.rs`): this crate's harness
//! plants no bond state.

use std::sync::OnceLock;

use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa;
use shekyl_types::archival::{ReceiptSignPk, SlashLogEntry};
use shekyl_types::{ArchivalLength, SHARD_LENGTH};
use shekyl_units::AtomicUnits;

use super::*;
use crate::archival::closed_and_final;
use crate::harness::fixture::{recorded, root};
use crate::harness::MockChain;
use crate::rule_set::RuleSet;
use crate::view::RecordedBlock;

/// The height the rewind tests journal an event at, above the open they
/// rewind to (the rewind reads no open: its rows are already the ones
/// above it).
const AFTER_OPEN: BlockHeight = BlockHeight::from_raw(12);
/// A height below [`AFTER_OPEN`], for the test where two events' order
/// matters.
const EARLIER: BlockHeight = BlockHeight::from_raw(10);

const P1: PCanonicalId = PCanonicalId::from_bytes([0xa1; 32]);
const P2: PCanonicalId = PCanonicalId::from_bytes([0xa2; 32]);
const E1: SettlementEpoch = SettlementEpoch::from_raw(1);

/// A real receipt key per persona: the emitter parses them.
fn key(persona: PCanonicalId) -> ReceiptSignPk {
    static KEYS: OnceLock<[ReceiptSignPk; 2]> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        [1u8, 2].map(|n| {
            HybridEd25519FnDsa::keypair_from_seeds(&[n; 32], &[n + 100; 32])
                .expect("keygen")
                .0
                .to_receipt_sign_pk()
        })
    });
    keys[usize::from(persona == P2)].clone()
}

fn held(shards: &[u64], add_epoch: u64) -> Holdings {
    Holdings::shard_set(
        shards
            .iter()
            .map(|&shard| HeldShard {
                shard: ShardId::from_raw(shard),
                add_epoch: SettlementEpoch::from_raw(add_epoch),
            })
            .collect(),
    )
    .expect("distinct shards under the cap")
}

fn compact(persona: PCanonicalId, shards: &[u64], join: u64) -> (PCanonicalId, BondRecord) {
    (
        persona,
        BondRecord {
            hybrid_pubkey: vec![0xb1; 4],
            bond_spend_pk: vec![0xb5; 4],
            receipt_sign_pk: key(persona),
            endpoint: [0xe0; 32],
            join_settlement_epoch: SettlementEpoch::from_raw(join),
            bonded_total: AtomicUnits::from_raw(ARCHIVAL_BOND_FLOOR_ATOMIC * shards.len() as u64),
            holdings: held(shards, join),
            bad_intervals: Vec::new(),
            claimed_settlement_epochs: Vec::new(),
            first_paying_emission_height: None,
        },
    )
}

fn complete(persona: PCanonicalId, join: u64) -> (PCanonicalId, BondRecord) {
    let (id, mut record) = compact(persona, &[], join);
    record.holdings = Holdings::CompleteTree;
    record.bonded_total = AtomicUnits::from_raw(ARCHIVAL_BOND_FLOOR_ATOMIC);
    (id, record)
}

fn pair(persona: PCanonicalId, shard: u64) -> DrawablePair {
    DrawablePair {
        persona,
        shard: ShardId::from_raw(shard),
    }
}

fn pairs_of(drawable: &DrawableEpoch) -> Vec<DrawablePair> {
    (0..drawable.len())
        .map(|i| drawable.pair(i).expect("below len"))
        .collect()
}

fn emitted(
    epoch: SettlementEpoch,
    records: &[(PCanonicalId, BondRecord)],
    final_count: u64,
) -> Vec<DrawablePair> {
    let drawable =
        emit(epoch, records.iter().map(|(p, r)| (p, r)), final_count).expect("every key parses");
    pairs_of(&drawable)
}

fn released(height: BlockHeight, record: &(PCanonicalId, BondRecord)) -> ReleasedRecord {
    ReleasedRecord {
        height,
        persona: record.0,
        pre_image: record.1.clone(),
    }
}

fn slashed(
    height: BlockHeight,
    persona: PCanonicalId,
    shard: u64,
    took: SlashedHolding,
) -> LoggedSlash {
    LoggedSlash {
        height,
        entry: SlashLogEntry {
            persona,
            shard: ShardId::from_raw(shard),
            epoch: E1,
            holding: took,
        },
    }
}

fn holdings_of(at_open: &BTreeMap<PCanonicalId, BondRecord>, persona: PCanonicalId) -> &Holdings {
    &at_open
        .get(&persona)
        .expect("the persona's record")
        .holdings
}

/// **Height 0 issues nothing** (`SO-D12` increment 1, ruled 2026-10-10),
/// and neither does any other block of epoch 0.
///
/// The genesis block carries a `0x0C` commitment like every block, and no
/// reader treats it specially. It issues no draw for a reason that has
/// nothing to do with its commitment's value: the drawable set of epoch 0
/// is empty. A bond is drawable from the epoch after it joins, and no bond
/// joins before epoch 0, so every record is excluded, whatever it holds.
/// With `D = 0` the count rule gives zero draws at every block and the
/// selection has no pair to pick, so no draw index `j` exists at height 0
/// and no bundle's record can name one.
#[test]
fn height_zero_and_all_of_epoch_zero_issue_no_draw() {
    use shekyl_archival_retention::{
        draw_count, draw_horizon, select_draw, CHALLENGE_RESPONSE_BLOCKS, SETTLEMENT_EPOCH_BLOCKS,
    };
    // The earliest bonds there can be: joined in epoch 0, compact and
    // complete-tree, with every shard final.
    let records = [compact(P1, &[0, 1], 0), complete(P2, 0)];
    let set = emit(
        SettlementEpoch::from_raw(0),
        records.iter().map(|(p, r)| (p, r)),
        4,
    )
    .expect("no key is parsed for an excluded bond");
    assert!(set.is_empty(), "nothing is drawable in epoch 0");
    let d = set.len();

    // The shortfall is a sum over the set, so it is zero with it.
    let shortfall = 0;
    let mut carry = 0;
    for r in [
        0,
        1,
        SETTLEMENT_EPOCH_BLOCKS / 2,
        SETTLEMENT_EPOCH_BLOCKS - 1,
    ] {
        let horizon = draw_horizon(r, SETTLEMENT_EPOCH_BLOCKS, CHALLENGE_RESPONSE_BLOCKS);
        let (count, next) = draw_count(d, shortfall, horizon, SETTLEMENT_EPOCH_BLOCKS, carry)
            .expect("the schedule's epoch and horizon are non-zero");
        assert_eq!(count, 0, "no draw at block {r} of epoch 0");
        carry = next;
    }
    assert_eq!(carry, 0, "and no fraction accumulates toward one");

    // Whatever seed a block committed to, and whatever it hashes to, there
    // is no pair for a draw to select.
    const BLOCK_HASH: [u8; 32] = [0x22; 32];
    for seed in [[0u8; 32], [0x11; 32]] {
        assert_eq!(
            select_draw(&seed, &BLOCK_HASH, 0, d, |_| Ok::<_, ()>(true)),
            Ok(None)
        );
    }
}

#[test]
fn no_records_emit_the_empty_set() {
    assert!(emitted(E1, &[], 4).is_empty());
}

/// Pin 1. Red edit: `>` for `>=` in the join filter.
#[test]
fn a_bond_that_joined_in_e_is_drawable_from_the_next_epoch() {
    let records = [compact(P1, &[0], 1)];
    assert!(emitted(E1, &records, 4).is_empty());
    assert_eq!(
        emitted(SettlementEpoch::from_raw(2), &records, 4),
        [pair(P1, 0)]
    );
}

/// Pins 2 and 3 on a compact holding: a shard at or above the final count
/// is not yet closed and final at `h_open`, and the result is in canonical
/// order whatever the record order and the shard insertion order. Red edit:
/// drop the prefix filter, or keep insertion order.
#[test]
fn compact_holdings_keep_only_final_shards_and_sort_canonically() {
    let records = [compact(P2, &[2, 0], 0), compact(P1, &[1], 0)];
    assert_eq!(emitted(E1, &records, 2), [pair(P1, 1), pair(P2, 0)]);
}

/// Pin 2 on a complete tree: it expands to the closed-and-final prefix at
/// `h_open`, not to every shard and not to tip's registry. Red edit: expand
/// to a count read anywhere but the open.
#[test]
fn complete_tree_expands_the_closed_and_final_prefix() {
    assert_eq!(
        emitted(E1, &[complete(P1, 0)], 2),
        [pair(P1, 0), pair(P1, 1)]
    );
    assert!(emitted(E1, &[complete(P1, 0)], 0).is_empty());
}

/// A persona with no drawable pair contributes no key: its key is not
/// parsed and not hashed. Red edit: push every record's key.
#[test]
fn a_persona_without_a_drawable_pair_contributes_no_key() {
    let (persona, mut record) = compact(P1, &[5], 0);
    record.receipt_sign_pk =
        ReceiptSignPk::from_bytes([0; shekyl_types::archival::RECEIPT_SIGN_PK_LEN]);
    let records = [(persona, record), compact(P2, &[0], 0)];
    let drawable =
        emit(E1, records.iter().map(|(p, r)| (p, r)), 2).expect("the unparsable key is never read");
    assert_eq!(pairs_of(&drawable), [pair(P2, 0)]);
}

/// A drawable persona whose record holds bytes that are not a key is a
/// store defect, not a smaller set. Red edit: skip the persona.
#[test]
fn a_drawable_persona_whose_key_does_not_parse_is_a_fault() {
    let (persona, mut record) = compact(P1, &[0], 0);
    record.receipt_sign_pk =
        ReceiptSignPk::from_bytes([0; shekyl_types::archival::RECEIPT_SIGN_PK_LEN]);
    let records = [(persona, record)];
    assert_eq!(
        emit(E1, records.iter().map(|(p, r)| (p, r)), 1),
        Err(DrawableEpochFault::Construction(
            shekyl_archival_retention::DrawableEpochError::ReceiptKeyMalformed { persona: P1 }
        ))
    );
}

/// A Release above the open is undone by its pre-image. Red edit: skip the
/// journal.
#[test]
fn a_release_is_undone_by_its_pre_image() {
    let before = compact(P1, &[0, 1], 0);
    let mut at_tip = before.clone();
    at_tip.1.holdings = held(&[], 0);
    let at_open = rewind(
        vec![at_tip],
        vec![released(AFTER_OPEN, &before)],
        Vec::new(),
    )
    .expect("undoable");
    assert_eq!(holdings_of(&at_open, P1), &before.1.holdings);
}

/// A compact slash above the open gives the shard back with its add epoch.
/// Red edit: restore the shard with the slash's epoch instead.
#[test]
fn a_compact_slash_gives_the_shard_back_with_its_add_epoch() {
    let at_tip = compact(P1, &[0], 0);
    let at_open = rewind(
        vec![at_tip],
        Vec::new(),
        vec![slashed(
            AFTER_OPEN,
            P1,
            3,
            SlashedHolding::Shard {
                add_epoch: SettlementEpoch::from_raw(0),
            },
        )],
    )
    .expect("undoable");
    assert_eq!(holdings_of(&at_open, P1), &held(&[0, 3], 0));
}

/// A complete-tree demotion above the open restores the complete tree.
/// Red edit: undo it as a compact slash of the challenged shard.
#[test]
fn a_complete_tree_demotion_is_undone() {
    let (persona, mut record) = complete(P1, 0);
    record.holdings = held(&[], 0);
    let at_open = rewind(
        vec![(persona, record)],
        Vec::new(),
        vec![slashed(AFTER_OPEN, P1, 4, SlashedHolding::CompleteTree)],
    )
    .expect("undoable");
    assert_eq!(holdings_of(&at_open, P1), &Holdings::CompleteTree);
}

/// Events undo newest first. The persona was slashed of shard 3 at height
/// 10 and released at 12, so the Release's pre-image already lacks shard
/// 3, and the slash must be undone after it. Undoing the slash first would
/// put shard 3 on the tip record and then overwrite it with the pre-image.
/// Red edit: iterate oldest first.
#[test]
fn events_are_undone_newest_first() {
    let pre_release = compact(P1, &[1, 2], 0);
    let mut at_tip = pre_release.clone();
    at_tip.1.holdings = held(&[], 0);
    let at_open = rewind(
        vec![at_tip],
        vec![released(AFTER_OPEN, &pre_release)],
        vec![slashed(
            EARLIER,
            P1,
            3,
            SlashedHolding::Shard {
                add_epoch: SettlementEpoch::from_raw(0),
            },
        )],
    )
    .expect("undoable");
    assert_eq!(holdings_of(&at_open, P1), &held(&[1, 2, 3], 0));
}

/// At one height a Release connects before the slash pass, so the slash is
/// undone first. Here the two name different personas, and the order is
/// asserted on the sort key the walk uses. Red edit: rank the slash before
/// the Release.
#[test]
fn at_one_height_the_slash_pass_is_newer_than_the_inputs() {
    let release = Undo::Release(released(AFTER_OPEN, &compact(P1, &[0], 0)));
    let slash = Undo::Slash(slashed(AFTER_OPEN, P2, 0, SlashedHolding::CompleteTree));
    assert!(release.connected_at() < slash.connected_at());
}

/// A journal row with no record, and a slash that the record cannot have
/// been left by, are faults, never skipped rows. Red edit: `continue` on
/// either.
#[test]
fn rows_the_records_contradict_are_faults() {
    let release = released(AFTER_OPEN, &compact(P2, &[0], 0));
    assert_eq!(
        rewind(vec![compact(P1, &[0], 0)], vec![release], Vec::new()),
        Err(DrawableEpochFault::NoRecord { persona: P2 })
    );
    let shard_still_held = slashed(
        AFTER_OPEN,
        P1,
        0,
        SlashedHolding::Shard {
            add_epoch: SettlementEpoch::from_raw(0),
        },
    );
    assert_eq!(
        rewind(
            vec![compact(P1, &[0], 0)],
            Vec::new(),
            vec![shard_still_held]
        ),
        Err(DrawableEpochFault::SlashNotUndoable {
            persona: P1,
            shard: ShardId::from_raw(0),
        })
    );
    let demotion_of_a_non_empty_set = slashed(AFTER_OPEN, P1, 4, SlashedHolding::CompleteTree);
    assert_eq!(
        rewind(
            vec![compact(P1, &[0], 0)],
            Vec::new(),
            vec![demotion_of_a_non_empty_set]
        ),
        Err(DrawableEpochFault::SlashNotUndoable {
            persona: P1,
            shard: ShardId::from_raw(4),
        })
    );
}

/// An empty chain has no tip, and an epoch whose open is above the tip has
/// not opened: neither has a state to rebuild. Red edit: answer an empty
/// set, which is a value — the digest of the empty set — and not an
/// absence.
#[test]
fn a_walk_with_no_open_to_walk_back_to_is_none() {
    fn walk<'id, V: ChainView<'id>>(
        view: &V,
        epoch: u64,
    ) -> Result<Option<DrawableEpoch>, ViewRead<V::Fault>> {
        let rules = RuleSet::GENESIS;
        drawable_epoch_walked_back(
            view,
            SettlementEpoch::from_raw(epoch),
            rules.settlement_schedule(),
            rules.reorg_cap(),
            SlashLogFloor::NONE,
        )
    }
    MockChain::default().with_view(|view| {
        assert_eq!(walk(&view, 0).expect("no view fault"), None);
    });
    let chain = MockChain::default().push(recorded(1_000), root(0x11));
    chain.with_view(|view| {
        assert_eq!(
            walk(&view, 1).expect("the genesis epoch opens far above this tip"),
            None
        );
        assert!(walk(&view, 0)
            .expect("epoch 0 opened at genesis")
            .expect("and has a state")
            .is_empty());
    });
}

/// A walk that would start below the journals' floor is refused, never
/// answered from what is left. Red edit: drop the check, and the walk
/// reads a truncated journal as a complete one.
#[test]
fn a_walk_below_the_floor_is_refused() {
    let rules = RuleSet::GENESIS;
    let chain = MockChain::default().push(recorded(1_000), root(0x11));
    chain.with_view(|view| {
        let floor = SlashLogFloor::under(
            BlockHeight::from_raw(
                SlashLogFloor::window(rules.settlement_schedule().blocks(), rules.reorg_cap())
                    .expect("the window fits")
                    .to_raw()
                    + 5,
            ),
            rules.settlement_schedule().blocks(),
            rules.reorg_cap(),
        );
        assert_eq!(floor.height(), Some(BlockHeight::from_raw(5)));
        assert_eq!(
            drawable_epoch_walked_back(
                &view,
                SettlementEpoch::from_raw(0),
                rules.settlement_schedule(),
                rules.reorg_cap(),
                floor,
            ),
            Err(ViewRead::Corrupt(Corrupt::DrawableEpoch {
                epoch: SettlementEpoch::from_raw(0),
                why: DrawableEpochFault::BelowFloor {
                    h_open: BlockHeight::from_raw(0),
                    floor: BlockHeight::from_raw(5),
                },
            }))
        );
    });
}

/// The final count the emitter expands to is the closed-and-final
/// predicate at `h_open`, taken over every shard: on CEN-J15's two-shard
/// fold, shard 0 is closed and final at height 4 and shard 1 is not, and
/// the count is 1. Red edit: read the count at the connecting height
/// instead of `h_open + 1`.
#[test]
fn the_final_count_is_closed_and_final_at_the_open() {
    let w = SHARD_LENGTH.to_raw();
    let folds = [0, w, w + 3, 2 * w + 4, 2 * w + 4];
    let chain = folds
        .into_iter()
        .enumerate()
        .fold(MockChain::default(), |chain, (h, fold)| {
            chain.push(
                RecordedBlock {
                    cumulative_archival_len: ArchivalLength::from_raw(fold),
                    ..recorded(1_000 + h as u64)
                },
                root(0x11),
            )
        });
    let cap = BlockCount::from_raw(2);
    chain.with_view(|view| {
        let h_open = BlockHeight::from_raw(4);
        assert!(closed_and_final(&view, ShardId::from_raw(0), h_open, cap).unwrap());
        assert!(!closed_and_final(&view, ShardId::from_raw(1), h_open, cap).unwrap());
        assert_eq!(final_count_at_open(&view, h_open, cap).unwrap(), 1);
    });
}

/// **A Reinstate changes no holdings** (`SO-D12b` condition 1, §16.7), so
/// the walk has nothing to reverse for it. Driven through the transition's
/// own Reinstate arm on a compact record with an open bad interval: the
/// post-image holds what the pre-image held, and the drawable set built
/// from either is the same. A Reinstate whose post would restore a shard
/// the record does not hold is refused, so no Reinstate can restore one.
/// Red edit: let the arm write the post's shard list into the record, or
/// drop `HoldingsChanged` from `reinstate_connect`; the first assertion or
/// the last then fails, and the walk would have a third event to undo.
#[test]
fn a_reinstate_leaves_the_drawable_set_unchanged() {
    use shekyl_types::archival::BadInterval;
    use shekyl_wire::transaction::{BondPost, BondPostKind, Holdings as WireHoldings};
    use shekyl_wire::Input;

    use crate::archival::{Post, Transition};
    use crate::verdict::{Locus, TxSlot};

    let rules = RuleSet::GENESIS;
    let schedule = rules.settlement_schedule();
    let (persona, mut record) = compact(P1, &[0, 1], 0);
    record.bad_intervals = vec![BadInterval {
        start_epoch: 1,
        end_exclusive: BadInterval::OPEN_END,
    }];
    let reinstate = |shards: Vec<u64>| {
        Input::BondPost(Box::new(BondPost {
            hybrid_public_key: vec![0xb1; 4],
            p_canonical_id: persona,
            kind: BondPostKind::Other(shekyl_archival_retention::BondPostKind::Reinstate as u8),
            holdings: WireHoldings::ShardSetCompact(shards),
            bonded_total_atomic: record.bonded_total.to_raw(),
            bond_credit: 0,
            bond_debit: 0,
        }))
    };
    let locus = Locus::Input {
        slot: TxSlot::Listed(0),
        input: 0,
    };
    // A height in epoch 2, so the drawable set of epoch 2 is the one the
    // Reinstate connects inside.
    let at = BlockHeight::from_raw(schedule.open_height(2) + 1);
    let applied = |shards: Vec<u64>| {
        let mut transition = Transition::new(at, schedule, rules.reorg_cap());
        transition.posts.insert(
            persona,
            Post {
                record: record.clone(),
                write: None,
            },
        );
        let verdict = MockChain::default().with_view(|view| {
            transition
                .apply_input(&view, &reinstate(shards), locus)
                .expect("no view fault")
        });
        (verdict, transition.posts[&persona].record.clone())
    };

    let (verdict, after) = applied(vec![0, 1]);
    assert!(verdict.is_ok(), "the Reinstate connects");
    assert_ne!(
        after.bad_intervals, record.bad_intervals,
        "it closed the interval"
    );
    assert_eq!(after.holdings, record.holdings, "and wrote no holdings");
    let epoch = SettlementEpoch::from_raw(2);
    assert_eq!(
        emitted(epoch, &[(persona, after)], 2),
        emitted(epoch, &[(persona, record.clone())], 2)
    );

    let (verdict, _) = applied(vec![0, 1, 2]);
    assert!(
        verdict.is_err(),
        "a Reinstate that would restore a shard is refused"
    );
}
