// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for the send-journal block.
//!
//! A `#[path]` child of `send_journal_block::tests`, so `use super::*`
//! reaches the block's private items and the workflow file stays the
//! production module.

use super::*;

fn sample_record(state: SendState, lock_baseline: Option<u64>) -> SendRecord {
    SendRecord {
        dispatched_at_height: BlockHeight::from_raw(42),
        fee: 700,
        recipients: vec![SendRecipient {
            destination: SendDestination::Address("shekyl1example".to_owned()),
            amount: 7_000,
            rid: None,
        }],
        change_amount: 22_300,
        inputs: vec![SendInputRef {
            gindex: 11,
            amount: 30_000,
        }],
        lock_baseline,
        state,
        tx_bytes: None,
    }
}

/// State-set predicates are the single owner of retention / lock /
/// abandonability membership — keep them aligned with the design
/// tables (I-2 retention vs F14 lock re-application vs P3-4 edge
/// sources).
#[test]
fn send_state_set_predicates() {
    assert!(SendState::Dispatched.holds_tx_key_retention());
    assert!(SendState::PresumedDead.holds_tx_key_retention());
    assert!(SendState::Abandoned.holds_tx_key_retention());
    assert!(!SendState::Confirmed {
        height: BlockHeight::from_raw(1)
    }
    .holds_tx_key_retention());
    assert!(!SendState::TerminalRejected.holds_tx_key_retention());

    assert!(SendState::Dispatched.locks_carried_inputs());
    assert!(SendState::Abandoned.locks_carried_inputs());
    assert!(
        !SendState::PresumedDead.locks_carried_inputs(),
        "PresumedDead holds retention but never re-places locks"
    );
    assert!(!SendState::Confirmed {
        height: BlockHeight::from_raw(1)
    }
    .locks_carried_inputs());

    assert!(SendState::Dispatched.is_abandonable());
    assert!(SendState::PresumedDead.is_abandonable());
    assert!(!SendState::Abandoned.is_abandonable());
    assert!(!SendState::Confirmed {
        height: BlockHeight::from_raw(1)
    }
    .is_abandonable());
    assert!(!SendState::TerminalRejected.is_abandonable());
}

/// Round-trip through postcard preserves every field of every state.
#[test]
fn postcard_round_trips_all_states() {
    for (i, state) in [
        SendState::Dispatched,
        SendState::Confirmed {
            height: BlockHeight::from_raw(99),
        },
        SendState::TerminalRejected,
        SendState::PresumedDead,
        SendState::Abandoned,
    ]
    .into_iter()
    .enumerate()
    {
        let key = u8::try_from(i).expect("five variants fit in u8");
        let mut block = SendJournalBlock::empty();
        block.rows.insert([key; 32], sample_record(state, Some(43)));
        let bytes = postcard::to_allocvec(&block).expect("serialize");
        let back: SendJournalBlock = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(back, block);
    }
}

/// Discriminant-stability KAT — the concrete form of the A4
/// clause-(2) append-only pin. postcard encodes enum variants by
/// declaration index (varint); these bytes are the on-disk promise
/// that existing variants never move. Appending a new variant after
/// the tail leaves every pinned encoding untouched; a KAT failure
/// here means a reorder/removal — a broken promise, not a snapshot
/// to refresh.
#[test]
fn send_state_discriminants_are_pinned() {
    let pins: [(SendState, &[u8]); 5] = [
        (SendState::Dispatched, &[0]),
        // variant index 1, then height 99 as a varint
        (
            SendState::Confirmed {
                height: BlockHeight::from_raw(99),
            },
            &[1, 99],
        ),
        (SendState::TerminalRejected, &[2]),
        (SendState::PresumedDead, &[3]),
        // PR-SJ-3: appended after the v1 tail — the four pins above
        // are byte-identical to their v1 encodings, which is the
        // append-only promise this KAT exists to keep.
        (SendState::Abandoned, &[4]),
    ];
    for (state, expected) in pins {
        let bytes = postcard::to_allocvec(&state).expect("serialize");
        assert_eq!(
            bytes.as_slice(),
            expected,
            "SendState discriminant moved for {state:?} — append-only violated"
        );
    }
}

/// Discriminant-stability KAT for [`SendDestination`], the same
/// append-only promise as the `SendState` pins above: a new kind of
/// destination appends after `OwnPersonaFunding`, and these bytes
/// never move.
#[test]
fn send_destination_discriminants_are_pinned() {
    let pins: [(SendDestination, &[u8]); 2] = [
        // variant index 0, then the string's varint length and bytes
        (
            SendDestination::Address("ab".to_owned()),
            &[0, 2, b'a', b'b'],
        ),
        (SendDestination::OwnPersonaFunding, &[1]),
    ];
    for (destination, expected) in pins {
        let bytes = postcard::to_allocvec(&destination).expect("serialize");
        assert_eq!(
            bytes.as_slice(),
            expected,
            "SendDestination discriminant moved for {destination:?} — append-only violated"
        );
    }
}

/// A v1 block with no rows deserializes from its minimal encoding —
/// the forward-compat floor old files rest on.
#[test]
fn empty_block_round_trips() {
    let block = SendJournalBlock::empty();
    let bytes = postcard::to_allocvec(&block).expect("serialize");
    let back: SendJournalBlock = postcard::from_bytes(&bytes).expect("deserialize");
    assert_eq!(back.block_version, SEND_JOURNAL_BLOCK_VERSION);
    assert!(back.rows.is_empty());
}

/// Dispatch birth records the exact remainder as change; baseline
/// starts unset so re-derivation stays off until an accepting verdict.
#[test]
fn record_dispatched_computes_change_and_starts_unlocked() {
    let mut block = SendJournalBlock::empty();
    let txid = [7u8; 32];
    block.record_dispatched(
        txid,
        BlockHeight::from_raw(42),
        700,
        vec![SendRecipient {
            destination: SendDestination::Address("shekyl1example".to_owned()),
            amount: 7_000,
            rid: None,
        }],
        vec![SendInputRef {
            gindex: 11,
            amount: 30_000,
        }],
        vec![0xAA],
    );
    let row = &block.rows[&txid];
    assert_eq!(row.change_amount, 22_300);
    assert_eq!(row.lock_baseline, None);
    assert_eq!(row.state, SendState::Dispatched);
    assert!(block.stamp_lock_baseline(&txid, 43));
    assert_eq!(block.rows[&txid].lock_baseline, Some(43));
    block.mark_presumed_dead(&txid);
    assert_eq!(block.rows[&txid].state, SendState::PresumedDead);
    assert_eq!(block.rows[&txid].lock_baseline, None);
    // PresumedDead is terminal for the release path; a late confirm
    // un-presumes via the reconciler, not by re-stamping here.
    block.mark_presumed_dead(&txid);
    assert_eq!(
        block.rows[&txid].state,
        SendState::PresumedDead,
        "mark_presumed_dead is a no-op once already released"
    );
    // Re-birth path: undo removes; a later dispatch inserts fresh.
    block.undo_dispatch(&txid);
    assert!(!block.rows.contains_key(&txid));
    assert!(!block.stamp_lock_baseline(&txid, 1));
}

/// The P3-4 abandon edge: applies from `Dispatched` and
/// `PresumedDead`, is idempotent on `Abandoned`, refuses terminal
/// states, and **retains** the lock baseline (the carried-input
/// locks outlive the user's abandon until confirmed-absent evidence
/// releases them).
#[test]
fn mark_abandoned_edges_and_idempotency() {
    let mut block = SendJournalBlock::empty();
    assert_eq!(block.mark_abandoned(&[9u8; 32]), AbandonEdge::NotFound);

    // From Dispatched, baseline retained.
    let dispatched = [1u8; 32];
    block
        .rows
        .insert(dispatched, sample_record(SendState::Dispatched, Some(43)));
    assert_eq!(
        block.mark_abandoned(&dispatched),
        AbandonEdge::Applied {
            previous: SendState::Dispatched
        }
    );
    assert_eq!(block.rows[&dispatched].state, SendState::Abandoned);
    assert_eq!(
        block.rows[&dispatched].lock_baseline,
        Some(43),
        "abandon retains the baseline — locks release on evidence, not intent"
    );
    assert_eq!(
        block.mark_abandoned(&dispatched),
        AbandonEdge::AlreadyAbandoned,
        "second abandon is an idempotent no-op (SJ-DQ-8)"
    );

    // From PresumedDead (the watchdog already cleared the baseline).
    let dead = [2u8; 32];
    block
        .rows
        .insert(dead, sample_record(SendState::PresumedDead, None));
    assert_eq!(
        block.mark_abandoned(&dead),
        AbandonEdge::Applied {
            previous: SendState::PresumedDead
        }
    );
    assert_eq!(block.rows[&dead].state, SendState::Abandoned);

    // Terminal states refuse.
    let confirmed = [3u8; 32];
    block.rows.insert(
        confirmed,
        sample_record(
            SendState::Confirmed {
                height: BlockHeight::from_raw(99),
            },
            None,
        ),
    );
    assert_eq!(
        block.mark_abandoned(&confirmed),
        AbandonEdge::Forbidden {
            state: SendState::Confirmed {
                height: BlockHeight::from_raw(99)
            }
        }
    );
    let rejected = [4u8; 32];
    block
        .rows
        .insert(rejected, sample_record(SendState::TerminalRejected, None));
    assert_eq!(
        block.mark_abandoned(&rejected),
        AbandonEdge::Forbidden {
            state: SendState::TerminalRejected
        }
    );
}

/// The derived F14 lock set contains exactly the carried inputs of
/// baseline-stamped rows in re-application states: `Dispatched` and
/// `Abandoned` lock; `PresumedDead` (released — baseline `None` by
/// construction, planted here to prove the state predicate alone
/// also excludes), `Confirmed`, `TerminalRejected`, and un-stamped
/// rows do not.
#[test]
fn derive_in_flight_spend_locks_covers_exactly_the_locking_set() {
    let mut block = SendJournalBlock::empty();
    let dispatched = [1u8; 32];
    let abandoned = [2u8; 32];
    for (txid, state, baseline, gindex) in [
        (dispatched, SendState::Dispatched, Some(25), 100),
        (abandoned, SendState::Abandoned, Some(30), 101),
        ([3u8; 32], SendState::PresumedDead, Some(35), 102),
        (
            [4u8; 32],
            SendState::Confirmed {
                height: BlockHeight::from_raw(40),
            },
            Some(20),
            103,
        ),
        ([5u8; 32], SendState::TerminalRejected, Some(20), 104),
        ([6u8; 32], SendState::Dispatched, None, 105), // pre-verdict
    ] {
        let mut record = sample_record(state, baseline);
        record.inputs = vec![SendInputRef { gindex, amount: 1 }];
        block.rows.insert(txid, record);
    }

    let locks = block.spend_locks();
    assert_eq!(
        locks.len(),
        2,
        "exactly the baseline-stamped re-application rows lock"
    );
    for (gindex, txid, baseline) in [(100, dispatched, 25), (101, abandoned, 30)] {
        let lock = locks
            .get(shekyl_types::GlobalOutputIndex::from_raw(gindex))
            .unwrap_or_else(|| panic!("gindex {gindex} must be locked"));
        assert_eq!(lock.tx_hash.to_bytes(), txid);
        assert_eq!(
            lock.accepted_at_height,
            shekyl_types::BlockHeight::from_raw(baseline)
        );
    }
}

/// Derivation is deterministic and pure: two calls over the same
/// block yield identical maps, and a multi-input row locks each of
/// its carried inputs under its own txid.
#[test]
fn derive_in_flight_spend_locks_is_deterministic_and_covers_all_inputs() {
    let mut block = SendJournalBlock::empty();
    let txid = [7u8; 32];
    let mut record = sample_record(SendState::Dispatched, Some(50));
    record.inputs = vec![
        SendInputRef {
            gindex: 200,
            amount: 1,
        },
        SendInputRef {
            gindex: 201,
            amount: 2,
        },
    ];
    block.rows.insert(txid, record);

    let a = block.spend_locks();
    let b = block.spend_locks();
    assert_eq!(a, b, "derivation is pure");
    assert_eq!(a.len(), 2);
    for g in [200, 201] {
        let lock = a
            .get(shekyl_types::GlobalOutputIndex::from_raw(g))
            .unwrap_or_else(|| panic!("gindex {g} must be locked"));
        assert_eq!(lock.tx_hash.to_bytes(), txid);
        assert_eq!(
            lock.accepted_at_height,
            shekyl_types::BlockHeight::from_raw(50)
        );
    }
}

/// The watchdog's confirmed-absent release on an `Abandoned` row
/// clears the baseline (so the reconciler never re-locks released
/// inputs) but never overwrites the user-authored display state.
#[test]
fn presumed_dead_release_clears_abandoned_baseline_keeps_state() {
    let mut block = SendJournalBlock::empty();
    let txid = [5u8; 32];
    block
        .rows
        .insert(txid, sample_record(SendState::Abandoned, Some(43)));
    block.mark_presumed_dead(&txid);
    assert_eq!(block.rows[&txid].state, SendState::Abandoned);
    assert_eq!(block.rows[&txid].lock_baseline, None);
}

#[test]
fn mark_terminal_rejected_keeps_the_row() {
    let mut block = SendJournalBlock::empty();
    let txid = [8u8; 32];
    block.record_dispatched(
        txid,
        BlockHeight::from_raw(1),
        0,
        Vec::new(),
        vec![SendInputRef {
            gindex: 1,
            amount: 0,
        }],
        vec![0xAA],
    );
    block.mark_terminal_rejected(&txid);
    assert_eq!(block.rows[&txid].state, SendState::TerminalRejected);
    assert!(block.rows.contains_key(&txid));
    // Refused and never relayed: the saved bytes go with the verdict.
    assert_eq!(block.tx_bytes(&txid), None);
}

/// The row is born holding the exact bytes that leave for the daemon.
#[test]
fn record_dispatched_keeps_the_signed_bytes() {
    let mut block = SendJournalBlock::empty();
    let txid = [9u8; 32];
    block.record_dispatched(
        txid,
        BlockHeight::from_raw(3),
        0,
        Vec::new(),
        Vec::new(),
        vec![1, 2, 3],
    );
    assert_eq!(block.tx_bytes(&txid), Some(&[1u8, 2, 3][..]));
    assert_eq!(block.tx_bytes(&[0u8; 32]), None);
}

/// A `Dispatched` row with no verdict (the process ended between the
/// dispatch save and the verdict) is locked at its dispatch height;
/// rows that already carry a baseline, and rows in any other state,
/// are untouched.
#[test]
fn lock_unverdicted_dispatches_locks_only_baseline_less_dispatches() {
    let mut block = SendJournalBlock::empty();
    let mut unverdicted = sample_record(SendState::Dispatched, None);
    unverdicted.dispatched_at_height = BlockHeight::from_raw(17);
    block.rows.insert([1; 32], unverdicted);
    block
        .rows
        .insert([2; 32], sample_record(SendState::Dispatched, Some(30)));
    block
        .rows
        .insert([3; 32], sample_record(SendState::PresumedDead, None));
    block
        .rows
        .insert([4; 32], sample_record(SendState::Abandoned, None));

    assert_eq!(block.lock_unverdicted_dispatches(), 1);
    assert_eq!(block.rows[&[1; 32]].lock_baseline, Some(17));
    assert_eq!(block.rows[&[2; 32]].lock_baseline, Some(30));
    assert_eq!(block.rows[&[3; 32]].lock_baseline, None);
    assert_eq!(block.rows[&[4; 32]].lock_baseline, None);
    // The stamped row's inputs are now locked.
    assert!(block
        .spend_locks()
        .contains(shekyl_types::GlobalOutputIndex::from_raw(11)));
    // Idempotent: a second open stamps nothing.
    assert_eq!(block.lock_unverdicted_dispatches(), 0);
}

/// Pruning reads the row's state. A dispatched row with no baseline
/// (verdict pending) keeps its bytes, as does an abandoned one and a
/// confirmation shallower than the reorg margin.
#[test]
fn prune_settled_tx_bytes_follows_row_state() {
    let with_bytes = |state, baseline| {
        let mut row = sample_record(state, baseline);
        row.tx_bytes = Some(vec![0xBB]);
        row
    };
    let mut block = SendJournalBlock::empty();
    block
        .rows
        .insert([1; 32], with_bytes(SendState::Dispatched, None));
    block
        .rows
        .insert([2; 32], with_bytes(SendState::Dispatched, Some(5)));
    block
        .rows
        .insert([3; 32], with_bytes(SendState::Abandoned, Some(5)));
    block.rows.insert(
        [4; 32],
        with_bytes(
            SendState::Confirmed {
                height: BlockHeight::from_raw(95),
            },
            Some(5),
        ),
    );
    block.rows.insert(
        [5; 32],
        with_bytes(
            SendState::Confirmed {
                height: BlockHeight::from_raw(90),
            },
            Some(5),
        ),
    );
    block
        .rows
        .insert([6; 32], with_bytes(SendState::PresumedDead, None));
    block
        .rows
        .insert([7; 32], with_bytes(SendState::TerminalRejected, None));

    // Synced at 100, margin 10: the row confirmed at 90 is 10 deep
    // (settled), the one at 95 is 5 deep (a reorg can still undo it).
    let dropped = block.prune_settled_tx_bytes(BlockHeight::from_raw(100), 10);
    assert_eq!(dropped, 3);
    for kept in [[1; 32], [2; 32], [3; 32], [4; 32]] {
        assert!(block.tx_bytes(&kept).is_some(), "{:?} kept", kept[0]);
    }
    for gone in [[5; 32], [6; 32], [7; 32]] {
        assert!(block.tx_bytes(&gone).is_none(), "{:?} dropped", gone[0]);
    }
}
