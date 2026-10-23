// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The coordinator's own tests: claim admission, derived state, and one
//! header request.

use std::convert::Infallible;
use std::time::{Duration, Instant};

use core::num::NonZeroU128;

use shekyl_chain_rules::{
    AtHeight, CenRow, DifficultyRule, FakechainSchedule, HeaderRecord, HeaderView, InvalidBlock,
    Locus, RuleSet, Tip, Trust,
};
use shekyl_difficulty::{CumulativeDifficulty, GENESIS_DIFFICULTY};
use shekyl_draw_rng::RelayRng;
use shekyl_levin::BODIES_RESPONSE_BYTES;
use shekyl_peer_policy::SyncReply;
use shekyl_types::{AttestationRoot, BlockHash, BlockHeight, ChainCount, CurveTreeRoot};
use shekyl_wire::BlockHeader;

use super::{body_deadline, Command, Event, Outcome, Sync, SYNC_RATE_FLOOR};
use crate::{ClaimError, PayloadRefused, PeerClaim, SyncState};

struct NoDraw;

impl RelayRng for NoDraw {
    fn next_u64(&mut self) -> u64 {
        0
    }
}

struct Empty;

impl HeaderView<'static> for Empty {
    type Fault = Infallible;

    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        Ok(None)
    }

    fn header_at(&self, _: BlockHeight) -> Result<AtHeight<HeaderRecord>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct StoreDown;

struct Faults;

impl HeaderView<'static> for Faults {
    type Fault = StoreDown;

    fn tip(&self) -> Result<Option<Tip>, StoreDown> {
        Err(StoreDown)
    }

    fn header_at(&self, _: BlockHeight) -> Result<AtHeight<HeaderRecord>, StoreDown> {
        Err(StoreDown)
    }
}

fn issued(_: BlockHeight) -> RuleSet {
    RuleSet::GENESIS
}

fn open<R: Fn(BlockHeight) -> RuleSet>(sync: &mut Sync<u8, R>, session: u8) -> Vec<Command<u8>> {
    let mut out = Vec::new();
    sync.handle(
        Event::SessionOpened {
            session,
            transit: Duration::from_secs(30),
        },
        &Empty,
        std::time::Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the view answers");
    out
}

fn hint<R: Fn(BlockHeight) -> RuleSet>(
    sync: &mut Sync<u8, R>,
    peer: PeerClaim,
) -> Result<(), ClaimError<Infallible>> {
    let mut out = Vec::new();
    sync.claim(
        1,
        peer,
        &Empty,
        std::time::Instant::now(),
        &mut NoDraw,
        &mut out,
    )
}

fn claim(count: u64, work: u128) -> PeerClaim {
    PeerClaim {
        count: ChainCount::from_raw(count),
        work: CumulativeDifficulty::from_raw(work),
        top: BlockHash::NULL,
    }
}

#[test]
fn a_genesis_only_claim_is_admitted() {
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    // One block, target 1.
    assert_eq!(hint(&mut sync, claim(1, 1)), Ok(()));
    assert_eq!(sync.state(), SyncState::NoView);
}

#[test]
fn a_block_count_of_zero_is_refused() {
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    assert_eq!(
        hint(&mut sync, claim(0, 1)),
        Err(ClaimError::Refused(PayloadRefused::Height))
    );
    assert_eq!(
        hint(&mut sync, claim(0, 0)),
        Err(ClaimError::Refused(PayloadRefused::Height))
    );
}

#[test]
fn work_below_the_block_count_is_refused() {
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    assert_eq!(
        hint(&mut sync, claim(3, 2)),
        Err(ClaimError::Refused(PayloadRefused::Work))
    );
    assert_eq!(hint(&mut sync, claim(3, 3)), Ok(()));
}

/// Height 0 is target 1 under a fixed target, and each later block is
/// the fixed target. That sum is an honest claim.
#[test]
fn a_regtest_fixed_target_admits_an_honest_claim() {
    let fixed = NonZeroU128::new(7).expect("7");
    let rules = RuleSet::fakechain(Some(fixed), FakechainSchedule::PRODUCTION);
    let DifficultyRule::Fixed(target) = rules.difficulty() else {
        panic!("the regtest set names a fixed target");
    };
    let per_block = target.difficulty().to_raw();
    assert_eq!(per_block, 7);
    let count = 3u64;
    // Block 0 is `Target::GENESIS_BLOCK` (1) under Fixed, as under
    // every rule set. The two blocks above it are the fixed target.
    let work = 1 + u128::from(count - 1) * per_block;
    assert!(
        work < GENESIS_DIFFICULTY,
        "this chain's work is the fixed targets, not the DAA constant"
    );
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    assert_eq!(hint(&mut sync, claim(count, work)), Ok(()));
}

#[test]
fn a_claim_never_changes_the_state() {
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    let published = open(&mut sync, 1);
    assert!(published.iter().any(|command| matches!(
        command,
        Command::Publish {
            state: SyncState::Synced,
        }
    )));
    assert!(published
        .iter()
        .any(|command| matches!(command, Command::RequestComplement { session: 1 })));
    assert_eq!(sync.transit(1), Some(Duration::from_secs(30)));
    hint(&mut sync, claim(9_000, u128::MAX)).unwrap();
    assert_eq!(sync.state(), SyncState::Synced);
}

#[test]
fn the_last_session_closing_returns_to_no_view() {
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    open(&mut sync, 1);
    open(&mut sync, 2);
    let mut out = Vec::new();
    sync.handle(
        Event::SessionClosed { session: 1 },
        &Empty,
        std::time::Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the view answers");
    assert!(out.is_empty(), "one session still has a view");
    sync.handle(
        Event::SessionClosed { session: 2 },
        &Empty,
        std::time::Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the view answers");
    assert!(matches!(
        out.as_slice(),
        [Command::Publish {
            state: SyncState::NoView,
        }]
    ));
}

#[test]
fn a_short_fill_is_following_and_the_latch_does_not_withhold_synced() {
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    open(&mut sync, 1);
    let mut out = Vec::new();
    sync.handle(
        Event::Fill {
            frontier: BlockHeight::from_raw(4),
        },
        &Empty,
        std::time::Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the view answers");
    assert_eq!(
        sync.state(),
        SyncState::Following {
            verified_to: BlockHeight::from_raw(4),
        }
    );
    let published = out.len();
    sync.handle(
        Event::Latch { set: true },
        &Empty,
        std::time::Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the view answers");
    assert!(sync.alarm());
    assert_eq!(out.len(), published, "the latch is not the state");
    assert_eq!(
        sync.state(),
        SyncState::Following {
            verified_to: BlockHeight::from_raw(4),
        }
    );
    sync.handle(
        Event::Fill {
            frontier: BlockHeight::ZERO,
        },
        &Empty,
        std::time::Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the view answers");
    assert_eq!(sync.state(), SyncState::Synced);
}

#[test]
fn a_store_fault_reaches_the_caller() {
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    let mut out = Vec::new();
    let fault = sync
        .handle(
            Event::SessionOpened {
                session: 1,
                transit: Duration::from_secs(1),
            },
            &Faults,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect_err("tip's fault");
    assert_eq!(fault, StoreDown);
    assert!(out.is_empty(), "a failed read publishes nothing");

    struct HeaderFaults;
    impl HeaderView<'static> for HeaderFaults {
        type Fault = StoreDown;
        fn tip(&self) -> Result<Option<Tip>, StoreDown> {
            Ok(Some(Tip {
                height: BlockHeight::from_raw(0),
                hash: BlockHash::from_bytes([1; 32]),
            }))
        }
        fn header_at(&self, _: BlockHeight) -> Result<AtHeight<HeaderRecord>, StoreDown> {
            Err(StoreDown)
        }
    }
    let fault = sync
        .handle(
            Event::Tip {
                tip: Tip {
                    height: BlockHeight::from_raw(0),
                    hash: BlockHash::from_bytes([1; 32]),
                },
            },
            &HeaderFaults,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        )
        .expect_err("header_at's fault");
    assert_eq!(fault, StoreDown);
    assert!(out.is_empty());
}

#[test]
fn a_tip_is_read_from_the_chain() {
    struct One {
        work: CumulativeDifficulty,
    }

    impl HeaderView<'static> for One {
        type Fault = Infallible;

        fn tip(&self) -> Result<Option<Tip>, Infallible> {
            Ok(Some(Tip {
                height: BlockHeight::from_raw(3),
                hash: BlockHash::from_bytes([1; 32]),
            }))
        }

        fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Infallible> {
            if height != BlockHeight::from_raw(3) {
                return Ok(AtHeight::AboveTip);
            }
            Ok(AtHeight::Recorded(HeaderRecord {
                hash: BlockHash::from_bytes([1; 32]),
                header: BlockHeader {
                    major_version: 1,
                    minor_version: 0,
                    timestamp: 1,
                    previous: BlockHash::from_bytes([0; 32]),
                    nonce: 0,
                    curve_tree_root: CurveTreeRoot::from_bytes([0; 32]),
                    attestation_root: AttestationRoot::from_bytes([0; 32]),
                },
                cumulative_difficulty: self.work,
            }))
        }
    }

    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    open(&mut sync, 1);
    let mut out = Vec::new();
    sync.handle(
        Event::Tip {
            tip: Tip {
                height: BlockHeight::from_raw(3),
                hash: BlockHash::from_bytes([1; 32]),
            },
        },
        &One {
            work: CumulativeDifficulty::from_raw(50),
        },
        std::time::Instant::now(),
        &mut NoDraw,
        &mut out,
    )
    .expect("the view answers");
    // The local chain is the best chain, so the state stays synced.
    assert!(out.is_empty());
    assert_eq!(sync.state(), SyncState::Synced);
}

/// One header request extends `H*`. A second source waits until that
/// request's session closes, and then it is drawn.
#[test]
fn one_header_request_extends_the_frontier() {
    let mut sync = Sync::new(Trust::UNANCHORED, issued);
    open(&mut sync, 1);
    open(&mut sync, 2);
    let mut out = Vec::new();
    let mut rng = Words(vec![0, 0, 0]);
    sync.claim(
        1,
        claim(2, 2),
        &Empty,
        std::time::Instant::now(),
        &mut rng,
        &mut out,
    )
    .unwrap();
    assert_eq!(requests(&out), vec![1]);
    out.clear();
    sync.claim(
        2,
        claim(2, 3),
        &Empty,
        std::time::Instant::now(),
        &mut rng,
        &mut out,
    )
    .unwrap();
    assert!(requests(&out).is_empty(), "a request is already out");
    sync.handle(
        Event::SessionClosed { session: 1 },
        &Empty,
        std::time::Instant::now(),
        &mut rng,
        &mut out,
    )
    .unwrap();
    assert_eq!(requests(&out), vec![2]);
}

struct Words(Vec<u64>);

impl RelayRng for Words {
    fn next_u64(&mut self) -> u64 {
        self.0.remove(0)
    }
}

fn requests(out: &[Command<u8>]) -> Vec<u8> {
    out.iter()
        .filter_map(|command| match command {
            Command::RequestHeaders { session, .. } => Some(*session),
            _ => None,
        })
        .collect()
}

#[test]
fn a_body_deadline_is_the_body_budget_at_the_rate_floor() {
    let now = Instant::now();
    let transit = Duration::from_secs(7);
    let deadline = body_deadline(now, transit);
    let secs = BODIES_RESPONSE_BYTES / SYNC_RATE_FLOOR;
    assert_eq!(deadline, now + transit + Duration::from_secs(secs));
}

/// A refusal with no census row is not an outcome. An oversize solicited
/// body invalidates its header. An oversize announce does not. A solicited
/// connect does not relay.
#[test]
fn a_reply_names_its_own_outcome() {
    let at = BlockHash::from_bytes([1; 32]);
    let verdict = InvalidBlock::new(CenRow::G2, Locus::Block);
    assert_eq!(
        Outcome::from_reply(SyncReply::Refused, true, at, at, Vec::new(), None),
        None
    );
    assert_eq!(
        Outcome::from_reply(SyncReply::PromotionRefused, true, at, at, Vec::new(), None),
        None
    );
    assert_eq!(
        Outcome::from_reply(
            SyncReply::PromotionRefused,
            true,
            at,
            at,
            Vec::new(),
            Some(verdict)
        ),
        Some(Outcome::PromotionRefused { verdict, block: at })
    );
    assert_eq!(
        Outcome::from_reply(SyncReply::Refused, true, at, at, Vec::new(), Some(verdict)),
        Some(Outcome::Refused { verdict })
    );
    assert_eq!(
        Outcome::from_reply(SyncReply::Oversize, true, at, at, Vec::new(), None),
        Some(Outcome::Oversize { invalidate: true })
    );
    assert_eq!(
        Outcome::from_reply(SyncReply::Oversize, false, at, at, Vec::new(), None),
        Some(Outcome::Oversize { invalidate: false })
    );
    assert_eq!(
        Outcome::from_reply(SyncReply::Connected, true, at, at, Vec::new(), None),
        Some(Outcome::Connected { relay: false })
    );
}
