// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The machine. One owner, no clock of its own, no store.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use shekyl_chain_rules::{AtHeight, HeaderView, Tip, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::RelayRng;
use shekyl_types::BlockHeight;

use crate::claim::{self, PayloadRefused, PeerClaim};
use crate::state::SyncState;

/// What the connector hands the model.
#[derive(Clone, Copy, Debug)]
pub enum Event<K> {
    /// A handshake completed. `transit` is the connector's declared transit.
    SessionOpened {
        /// The session.
        session: K,
        /// The connector's declared transit.
        transit: Duration,
    },
    /// The session is gone.
    SessionClosed {
        /// The session.
        session: K,
    },
    /// The local tip changed.
    Tip {
        /// The tip the connector observed.
        tip: Tip,
    },
    /// The store's `following_degraded` latch.
    Latch {
        /// Whether the latch is set.
        set: bool,
    },
    /// PDM-Q5's backward-fill frontier.
    Fill {
        /// The descending frontier.
        frontier: BlockHeight,
    },
}

/// What the model asks the executor to do.
///
/// Commands that name a session arrive with the steps that send them.
/// Publishing the state does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// The derived state changed.
    Publish {
        /// The new state.
        state: SyncState,
    },
}

/// The chain the model has observed.
#[derive(Clone, Copy, Debug)]
struct Local {
    work: CumulativeDifficulty,
}

/// One session. Its claim is a hint and is not read by [`Sync::state`].
struct Session {
    transit: Duration,
    claim: Option<PeerClaim>,
}

/// The sync model.
pub struct Sync<K> {
    sessions: BTreeMap<K, Session>,
    /// A claim that arrived before its session opened.
    pending: BTreeMap<K, PeerClaim>,
    local: Option<Local>,
    /// The best verified work. The local chain, until a header tree holds more.
    best: CumulativeDifficulty,
    /// The fill's descending frontier. Genesis means the fill is done.
    fill_frontier: BlockHeight,
    /// The store's latch. Read, never published as the state.
    alarm: bool,
    trust: Trust,
}

impl<K> Sync<K>
where
    K: Copy + Ord + std::hash::Hash + std::fmt::Debug,
{
    /// Full verification starts the fill at genesis (`assumevalid = 0`).
    #[must_use]
    pub fn new(trust: Trust) -> Self {
        Self {
            sessions: BTreeMap::new(),
            pending: BTreeMap::new(),
            local: None,
            best: CumulativeDifficulty::ZERO,
            fill_frontier: BlockHeight::ZERO,
            alarm: false,
            trust,
        }
    }

    /// Record a hint. Refused only when the claim cannot be a chain.
    /// A recorded claim does not change [`Self::state`].
    ///
    /// # Errors
    ///
    /// [`PayloadRefused`] when the block count is 0, or the work is
    /// below that count.
    pub fn claim(&mut self, session: K, claim: PeerClaim) -> Result<(), PayloadRefused> {
        let claim = claim::admit(claim)?;
        if let Some(open) = self.sessions.get_mut(&session) {
            open.claim = Some(claim);
        } else {
            self.pending.insert(session, claim);
        }
        Ok(())
    }

    /// The derived state. A claim's value is not an input.
    #[must_use]
    pub fn state(&self) -> SyncState {
        if self.sessions.is_empty() {
            return SyncState::NoView;
        }
        let Some(local) = self.local else {
            return SyncState::NoView;
        };
        if self.best > local.work {
            return SyncState::Behind {
                have: local.work,
                best: self.best,
            };
        }
        if self.fill_frontier > self.checkpoint() {
            return SyncState::Following {
                verified_to: self.fill_frontier,
            };
        }
        SyncState::Synced
    }

    /// Whether the store's latch is set. It does not withhold [`SyncState::Synced`].
    #[must_use]
    pub const fn alarm(&self) -> bool {
        self.alarm
    }

    /// The transit the session opened with.
    #[must_use]
    pub fn transit(&self, session: K) -> Option<Duration> {
        self.sessions.get(&session).map(|s| s.transit)
    }

    /// Apply one event. `main` is the chain as of `now`. This step does
    /// not draw.
    pub fn handle<'id, H: HeaderView<'id>>(
        &mut self,
        event: Event<K>,
        main: &H,
        _now: Instant,
        _rng: &mut impl RelayRng,
        out: &mut Vec<Command>,
    ) {
        let before = self.state();
        match event {
            Event::SessionOpened { session, transit } => {
                let claim = self.pending.remove(&session);
                self.sessions.insert(session, Session { transit, claim });
                self.observe(main, None);
            }
            Event::SessionClosed { session } => {
                self.sessions.remove(&session);
                self.pending.remove(&session);
            }
            Event::Tip { tip } => self.observe(main, Some(tip.height)),
            Event::Latch { set } => self.alarm = set,
            Event::Fill { frontier } => self.fill_frontier = frontier,
        }
        let after = self.state();
        if after != before {
            out.push(Command::Publish { state: after });
        }
    }

    /// Full verification's checkpoint is genesis. The anchors are the
    /// validator's; the fill reads this height.
    fn checkpoint(&self) -> BlockHeight {
        let _anchors = self.trust.anchors();
        BlockHeight::ZERO
    }

    fn observe<'id, H: HeaderView<'id>>(&mut self, main: &H, at: Option<BlockHeight>) {
        let Ok(tip) = main.tip() else {
            return;
        };
        let Some(tip) = tip else {
            self.local = Some(Local {
                work: CumulativeDifficulty::ZERO,
            });
            self.best = CumulativeDifficulty::ZERO;
            return;
        };
        let height = at.unwrap_or(tip.height);
        let Ok(AtHeight::Recorded(record)) = main.header_at(height) else {
            return;
        };
        self.local = Some(Local {
            work: record.cumulative_difficulty,
        });
        self.best = record.cumulative_difficulty;
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::time::Duration;

    use core::num::NonZeroU128;

    use shekyl_chain_rules::{
        AtHeight, DifficultyRule, FakechainSchedule, HeaderRecord, HeaderView, RuleSet, Tip, Trust,
    };
    use shekyl_difficulty::{CumulativeDifficulty, GENESIS_DIFFICULTY};
    use shekyl_draw_rng::RelayRng;
    use shekyl_types::{AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot};
    use shekyl_wire::BlockHeader;

    use super::{Command, Event, Sync};
    use crate::{PayloadRefused, PeerClaim, SyncState};

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

    struct Faults;

    impl HeaderView<'static> for Faults {
        type Fault = ();

        fn tip(&self) -> Result<Option<Tip>, ()> {
            Err(())
        }

        fn header_at(&self, _: BlockHeight) -> Result<AtHeight<HeaderRecord>, ()> {
            Err(())
        }
    }

    fn open(sync: &mut Sync<u8>, session: u8) -> Vec<Command> {
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
        );
        out
    }

    fn claim(height: u64, work: u128) -> PeerClaim {
        PeerClaim {
            height: BlockHeight::from_raw(height),
            work: CumulativeDifficulty::from_raw(work),
        }
    }

    #[test]
    fn a_genesis_only_claim_is_admitted() {
        let mut sync = Sync::new(Trust::UNANCHORED);
        // One block, target 1.
        assert_eq!(sync.claim(1, claim(1, 1)), Ok(()));
        assert_eq!(sync.state(), SyncState::NoView);
    }

    #[test]
    fn a_block_count_of_zero_is_refused() {
        let mut sync = Sync::new(Trust::UNANCHORED);
        assert_eq!(sync.claim(1, claim(0, 1)), Err(PayloadRefused::Height));
        assert_eq!(sync.claim(1, claim(0, 0)), Err(PayloadRefused::Height));
    }

    #[test]
    fn work_below_the_block_count_is_refused() {
        let mut sync = Sync::new(Trust::UNANCHORED);
        assert_eq!(sync.claim(1, claim(3, 2)), Err(PayloadRefused::Work));
        assert_eq!(sync.claim(1, claim(3, 3)), Ok(()));
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
        let mut sync = Sync::new(Trust::UNANCHORED);
        assert_eq!(sync.claim(1, claim(count, work)), Ok(()));
    }

    #[test]
    fn a_claim_never_changes_the_state() {
        let mut sync = Sync::new(Trust::UNANCHORED);
        let published = open(&mut sync, 1);
        assert_eq!(
            published,
            vec![Command::Publish {
                state: SyncState::Synced,
            }]
        );
        assert_eq!(sync.transit(1), Some(Duration::from_secs(30)));
        sync.claim(1, claim(9_000, u128::MAX)).unwrap();
        assert_eq!(sync.state(), SyncState::Synced);
    }

    #[test]
    fn the_last_session_closing_returns_to_no_view() {
        let mut sync = Sync::new(Trust::UNANCHORED);
        open(&mut sync, 1);
        open(&mut sync, 2);
        let mut out = Vec::new();
        sync.handle(
            Event::SessionClosed { session: 1 },
            &Empty,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        );
        assert!(out.is_empty(), "one session still has a view");
        sync.handle(
            Event::SessionClosed { session: 2 },
            &Empty,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        );
        assert_eq!(
            out,
            vec![Command::Publish {
                state: SyncState::NoView,
            }]
        );
    }

    #[test]
    fn a_short_fill_is_following_and_the_latch_does_not_withhold_synced() {
        let mut sync = Sync::new(Trust::UNANCHORED);
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
        );
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
        );
        assert!(sync.alarm());
        assert_eq!(out.len(), published, "the latch is not the state");
        assert_eq!(
            sync.state(),
            SyncState::Following {
                verified_to: BlockHeight::from_raw(4),
            }
        );
    }

    #[test]
    fn a_store_fault_is_not_a_view() {
        let mut sync = Sync::new(Trust::UNANCHORED);
        let mut out = Vec::new();
        sync.handle(
            Event::SessionOpened {
                session: 1,
                transit: Duration::from_secs(1),
            },
            &Faults,
            std::time::Instant::now(),
            &mut NoDraw,
            &mut out,
        );
        assert_eq!(sync.state(), SyncState::NoView);
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

        let mut sync = Sync::new(Trust::UNANCHORED);
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
        );
        // The local chain is the best chain, so the state stays synced.
        assert!(out.is_empty());
        assert_eq!(sync.state(), SyncState::Synced);
    }
}
