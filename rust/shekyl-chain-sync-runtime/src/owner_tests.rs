// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's reply conversion, its end guard, and the local drain's
//! stop. The owner end to end is the loopback harness's
//! (`shekyl-p2p-harness`, `tests/chain_sync_loopback.rs`).

use shekyl_chain_ingest::service::{ArrivalTag, CannotFollow, Refusal, Reply};
use shekyl_chain_ingest::PopBeyondReorgCap;
use shekyl_chain_rules::{CenRow, InvalidBlock, Locus};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

use crate::outcome::{of_refusal, of_reply};
use shekyl_chain_sync::{Outcome, SyncState};

/// A refused offer reaches the model as the outcome its refusal names. A
/// dry bucket is `Throttled`, never `NoRoom`: the model takes the seat back
/// and asks for the body (2026-11-02, a node `behind` with every offer
/// throttled, each frozen as `NoRoom`). A bound span takes no token since
/// the same day (`shekyl_chain_ingest::service::BoundArrival`), and the
/// owner forgets its sampled room after any `NoRoom`, so a seat report
/// follows every refusal that waits for one ([`super::Owner::offer`]).
#[test]
fn every_door_refusal_has_an_outcome() {
    let cases = [
        (Refusal::NoRoom, true, 10, Some(100), Outcome::NoRoom),
        (Refusal::Throttled, true, 10, Some(100), Outcome::Throttled),
        (Refusal::Throttled, false, 10, None, Outcome::Throttled),
        (
            Refusal::StoreUnreadable,
            true,
            10,
            Some(100),
            Outcome::StoreUnreadable,
        ),
        (
            Refusal::Oversize,
            true,
            101,
            Some(100),
            Outcome::Oversize { invalidate: true },
        ),
        (
            Refusal::Oversize,
            false,
            101,
            Some(100),
            Outcome::Oversize { invalidate: false },
        ),
        (Refusal::Oversize, true, 100, Some(100), Outcome::Again),
        (Refusal::Oversize, true, 101, None, Outcome::Again),
    ];
    for (refusal, solicited, bytes, max, expected) in cases {
        assert_eq!(
            of_refusal(refusal, solicited, bytes, max),
            expected,
            "{refusal:?} solicited={solicited} bytes={bytes} max={max:?}"
        );
    }
}

#[test]
fn every_entry_reply_has_an_outcome() {
    let verdict = InvalidBlock::new(CenRow::B2, Locus::Block);
    let hash = BlockHash::from_bytes([7; 32]);
    let cases = [
        (
            Reply::Connected {
                height: BlockHeight::ZERO,
                hash,
            },
            Outcome::Connected {
                height: BlockHeight::ZERO,
            },
        ),
        (Reply::Refused(verdict), Outcome::Refused { verdict }),
        (Reply::Unlinked { at: hash }, Outcome::Unlinked { at: hash }),
        (Reply::AlreadyHeld, Outcome::Noted),
        (
            Reply::Held {
                height: BlockHeight::ZERO,
            },
            Outcome::Noted,
        ),
        (
            Reply::PromotionRefused {
                at: BlockHeight::ZERO,
                hash,
                refused: verdict,
            },
            Outcome::PromotionRefused {
                verdict,
                block: hash,
            },
        ),
        (
            Reply::MissingBodies {
                hash,
                indices: vec![1, 3],
            },
            Outcome::MissingBodies {
                indices: vec![1, 3],
            },
        ),
        (Reply::Cancelled { by: ArrivalTag(4) }, Outcome::Again),
        (Reply::Stopped, Outcome::Again),
        (
            Reply::BeyondCap(PopBeyondReorgCap {
                depth: BlockCount::ONE,
                cap: BlockCount::ONE,
            }),
            Outcome::BeyondCap,
        ),
        (
            Reply::Switched {
                demoted: Vec::new(),
                promoted: Vec::new(),
            },
            Outcome::Noted,
        ),
        (
            Reply::Switched {
                demoted: vec![(BlockHeight::from_raw(7), BlockHash::from_bytes([8; 32]))],
                promoted: vec![
                    (BlockHeight::from_raw(7), BlockHash::from_bytes([9; 32])),
                    (BlockHeight::from_raw(8), hash),
                ],
            },
            Outcome::Connected {
                height: BlockHeight::from_raw(8),
            },
        ),
        (
            Reply::CannotFollow(CannotFollow::BelowFloor {
                tip: BlockHeight::ZERO,
                floor: BlockHeight::ZERO,
            }),
            Outcome::Noted,
        ),
    ];
    for (reply, expected) in cases {
        assert_eq!(
            of_reply(reply.clone(), true, Some(hash)),
            expected,
            "{reply:?}"
        );
    }
}

/// A connect carries the height the block took, whether the body was
/// requested or announced: the relay is the model's to decide.
#[test]
fn a_connect_carries_its_height_however_the_body_arrived() {
    let height = BlockHeight::from_raw(12);
    let connected = Reply::Connected {
        height,
        hash: BlockHash::from_bytes([3; 32]),
    };
    assert_eq!(
        of_reply(
            connected.clone(),
            false,
            Some(BlockHash::from_bytes([3; 32]))
        ),
        Outcome::Connected { height }
    );
    assert_eq!(
        of_reply(connected, true, None),
        Outcome::Connected { height }
    );
}

/// A switch is a connect only when this arrival is the new tip. The model
/// then relays it by the connect's rule. Any other tip, an empty promotion,
/// or an offer the owner no longer holds, is noted.
#[test]
fn a_switch_is_a_connect_only_when_the_arrival_is_the_new_tip() {
    let arrival = BlockHash::from_bytes([7; 32]);
    let height = BlockHeight::from_raw(8);
    let switched = |tip: BlockHash| Reply::Switched {
        demoted: vec![(BlockHeight::from_raw(7), BlockHash::from_bytes([8; 32]))],
        promoted: vec![
            (BlockHeight::from_raw(7), BlockHash::from_bytes([9; 32])),
            (height, tip),
        ],
    };
    assert_eq!(
        of_reply(switched(arrival), true, Some(arrival)),
        Outcome::Connected { height }
    );
    assert_eq!(
        of_reply(switched(arrival), false, Some(arrival)),
        Outcome::Connected { height }
    );
    assert_eq!(
        of_reply(
            switched(BlockHash::from_bytes([9; 32])),
            true,
            Some(arrival)
        ),
        Outcome::Noted
    );
    assert_eq!(of_reply(switched(arrival), true, None), Outcome::Noted);
    assert_eq!(
        of_reply(
            Reply::Switched {
                demoted: Vec::new(),
                promoted: Vec::new(),
            },
            true,
            Some(arrival),
        ),
        Outcome::Noted
    );
}

/// Every exit publishes `NoView` and drops the sender, so the watch
/// closes on that state. Facts and the follower read a closed watch as
/// `NoView`; a reader that only borrows sees the publish. The same guard
/// reports how the task ended: the cause an exit set, a panic when none
/// did, and a stop when one was asked.
#[test]
fn an_owner_exit_publishes_no_view_and_reports_how_it_ended() {
    let (sender, mut seen) = tokio::sync::watch::channel(SyncState::Synced);
    let (ended_tx, ended) = tokio::sync::watch::channel(None);
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    let mut live = super::EndGuard {
        state: sender,
        ended: ended_tx.clone(),
        stop: stop.clone(),
        how: super::Ended::Failed(super::EndCause::Panicked),
    };
    assert_eq!(*seen.borrow(), SyncState::Synced);
    assert_eq!(*ended.borrow(), None, "a running owner has not ended");
    live.how = super::Ended::Failed(super::EndCause::PortClosed);
    drop(live);
    assert_eq!(*seen.borrow_and_update(), SyncState::NoView);
    assert!(
        seen.has_changed().is_err(),
        "the watch stayed open after the owner"
    );
    assert_eq!(
        *ended.borrow(),
        Some(super::Ended::Failed(super::EndCause::PortClosed))
    );
    // An unwind runs the guard with no exit's cause set: a panic.
    let (sender, _seen) = tokio::sync::watch::channel(SyncState::Synced);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = super::EndGuard {
            state: sender,
            ended: ended_tx.clone(),
            stop: stop.clone(),
            how: super::Ended::Failed(super::EndCause::Panicked),
        };
        panic!("the owner's task");
    }));
    assert!(unwound.is_err());
    assert_eq!(
        *ended.borrow(),
        Some(super::Ended::Failed(super::EndCause::Panicked))
    );
    // A task cancelled after a stop was asked (the owner's runtime shut
    // down under it) ended by the stop, not by a failure.
    stop_tx.send_replace(true);
    let (sender, mut stopped) = tokio::sync::watch::channel(SyncState::Synced);
    drop(super::EndGuard {
        state: sender,
        ended: ended_tx,
        stop,
        how: super::Ended::Failed(super::EndCause::Panicked),
    });
    assert_eq!(*ended.borrow(), Some(super::Ended::Stopped));
    assert_eq!(*stopped.borrow_and_update(), SyncState::NoView);
    assert!(stopped.has_changed().is_err());
}

/// A prove job that could not judge an item ends the owner, and the end
/// names the fault with its seeds: what `Node::ended()` carries as
/// `NodeEnd::Sync` and the daemon's stop line prints. The guard reports
/// that end as every other end.
///
/// The job's half is `executor_tests::an_item_under_another_seed_is_not_judged`.
/// No test drives a whole owner into this end: the model names one seed
/// per job by construction, and the executor's boundary is the production
/// one, so neither fault can be caused from outside the task. The drain
/// that stops on the fault is `an_unjudged_input_leaves_the_rest_unread`.
///
/// Red edit: have `EndCause`'s `Display` write `text()` for every cause:
/// the line loses the two seeds.
#[test]
fn an_unjudged_proof_is_an_end_that_names_its_fault() {
    use crate::executor::ProveFault;
    use shekyl_types::BlockHash;

    let asked = BlockHash::from_bytes([7; 32]);
    let lent = BlockHash::from_bytes([6; 32]);
    let cause = super::EndCause::ProofUnjudged(ProveFault::SeedNotLent { asked, lent });
    assert_eq!(
        cause.text(),
        "a header proof was asked under a seed its job did not borrow"
    );
    let line = cause.to_string();
    assert!(line.starts_with(cause.text()), "{line}");
    assert!(
        line.contains(&format!("{asked:?}")) && line.contains(&format!("{lent:?}")),
        "the end names both seeds: {line}"
    );
    let clock = super::EndCause::ProofUnjudged(ProveFault::ClockBeforeEpoch);
    assert_eq!(clock.to_string(), clock.text());
    assert_ne!(clock, cause, "the two faults are two ends");

    let (sender, _seen) = tokio::sync::watch::channel(SyncState::Synced);
    let (ended_tx, ended) = tokio::sync::watch::channel(None);
    let (_stop_tx, stop) = tokio::sync::watch::channel(false);
    drop(super::EndGuard {
        state: sender,
        ended: ended_tx,
        stop,
        how: super::Ended::Failed(cause),
    });
    assert_eq!(*ended.borrow(), Some(super::Ended::Failed(cause)));
}

/// An unjudged proof stops `pump_local` on that fault. The input queued
/// behind it stays queued, and the tip and latch watches stay unseen.
/// The closure is `end_of`, which `Owner::input` applies through.
/// Building an `Owner` would stand up the store, the door and the timer
/// for a drain that does not touch them.
///
/// Red edit: in `pump_local`, keep applying after `apply` returns
/// `Break`. The input behind the fault is consumed, or a watch is
/// marked seen.
#[test]
fn an_unjudged_input_leaves_the_rest_unread() {
    use std::ops::ControlFlow;

    use crate::executor::ProveFault;
    use shekyl_chain_store::codec::FollowingDegraded;
    use shekyl_types::BlockHash;

    let asked = BlockHash::from_bytes([7; 32]);
    let lent = BlockHash::from_bytes([6; 32]);
    let fault = ProveFault::SeedNotLent { asked, lent };
    let cause = super::EndCause::ProofUnjudged(fault);

    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();
    input_tx
        .send(super::Input::Unjudged(fault))
        .expect("the input queue is open");
    input_tx
        .send(super::Input::AlarmRefused)
        .expect("the input queue is open");

    let (_tip_tx, mut tips) =
        tokio::sync::watch::channel(shekyl_chain_ingest::TipChanged { seq: 0, tip: None });
    tips.mark_changed();
    let (_latch_tx, mut latch) = tokio::sync::watch::channel::<Option<FollowingDegraded>>(None);
    latch.mark_changed();

    let mut applied = false;
    let flow = super::pump_local(&mut input_rx, &mut tips, &mut latch, |input| {
        let kept = super::end_of(input)?;
        assert!(
            !matches!(kept, super::Input::Unjudged(_)),
            "an unjudged proof was applied"
        );
        applied = true;
        ControlFlow::Continue(())
    });

    match flow {
        ControlFlow::Break(end) => assert_eq!(end, cause),
        ControlFlow::Continue(_) => panic!("the drain applied past the fault"),
    }
    assert!(!applied, "an input behind the fault was applied");
    assert!(
        matches!(input_rx.try_recv(), Ok(super::Input::AlarmRefused)),
        "the input behind the fault was consumed"
    );
    assert!(
        tips.has_changed().expect("the tip watch is open"),
        "the tip watch was marked seen"
    );
    assert!(
        latch.has_changed().expect("the latch watch is open"),
        "the latch watch was marked seen"
    );
}
