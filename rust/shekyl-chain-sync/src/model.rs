// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The machine. One owner, no clock of its own, no store.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use shekyl_chain_rules::{AtHeight, Fault, FormedHeader, HeaderView, RuleSet, Tip, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_draw_rng::{bounded_uniform, RelayRng};
use shekyl_levin::RequestHeaders;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

use crate::claim::{self, PayloadRefused, PeerClaim};
use crate::locator::locator;
use crate::state::SyncState;
use crate::tree::HeaderTree;

/// Bytes per second assumed when a header request's deadline is set.
///
/// Assumption (CS-Q11): replaced by a measurement of header delivery on
/// the floor device. Not derived from the protocol.
const HEADERS_RATE_FLOOR: u64 = 1_024;

/// What the connector hands the model.
#[derive(Clone, Debug)]
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
    /// The header request's deadline passed.
    Deadline {
        /// The session the request was drawn for.
        session: K,
    },
    /// A header the executor proved. Judged here and, when it passes,
    /// recorded in the tree.
    Proven {
        /// The header `form_header` accepted. Boxed: the token is far
        /// larger than the other events.
        formed: Box<FormedHeader>,
    },
}

/// What the model asks the executor to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command<K> {
    /// The derived state changed.
    Publish {
        /// The new state.
        state: SyncState,
    },
    /// One header request extending `H*`. At most one is outstanding.
    RequestHeaders {
        /// The session drawn for this request.
        session: K,
        /// The sparse locator.
        request: RequestHeaders,
        /// When the response is late.
        deadline: Instant,
    },
}

/// The chain the model has observed.
#[derive(Clone, Copy, Debug)]
struct Local {
    height: Option<BlockHeight>,
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
    tree: HeaderTree,
    /// The best verified work: the local chain, or a heavier reachable tip.
    best: CumulativeDifficulty,
    /// The session a header request extending `H*` is waiting on.
    frontier: Option<K>,
    rules: fn(BlockHeight) -> RuleSet,
    /// The fill's descending frontier. Genesis means the fill is done.
    fill_frontier: BlockHeight,
    /// The store's latch. Read, never published as the state.
    alarm: bool,
    /// The posture `judge_header` is given. The fill's checkpoint does
    /// not read it: until slice 6 every posture is full.
    trust: Trust,
}

impl<K> Sync<K>
where
    K: Copy + Ord + std::hash::Hash + std::fmt::Debug,
{
    /// `trust` is the posture [`shekyl_chain_rules::judge_header`] is
    /// given. Until slice 6 every [`Trust`] is the full posture, so
    /// [`Self::checkpoint`] is genesis.
    #[must_use]
    pub fn new(trust: Trust) -> Self {
        Self {
            sessions: BTreeMap::new(),
            pending: BTreeMap::new(),
            local: None,
            tree: HeaderTree::default(),
            best: CumulativeDifficulty::ZERO,
            frontier: None,
            rules: |_| RuleSet::GENESIS,
            fill_frontier: BlockHeight::ZERO,
            alarm: false,
            trust,
        }
    }

    /// Record a hint. Refused only when the claim cannot be a chain.
    /// A recorded claim does not change [`Self::state`]. A claim that
    /// beats `H*` can start the one header request, whose locator is
    /// read from `main`.
    ///
    /// # Errors
    ///
    /// [`PayloadRefused`] when the block count is 0, or the work is
    /// below that count. The main view's fault, when the locator cannot
    /// be read.
    pub fn claim<'id, H: HeaderView<'id>>(
        &mut self,
        session: K,
        claim: PeerClaim,
        main: &H,
        now: Instant,
        rng: &mut impl RelayRng,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), ClaimError<H::Fault>> {
        let claim = claim::admit(claim).map_err(ClaimError::Refused)?;
        if let Some(open) = self.sessions.get_mut(&session) {
            open.claim = Some(claim);
        } else {
            self.pending.insert(session, claim);
        }
        self.plan(main, now, rng, out).map_err(ClaimError::View)?;
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
        if self.fill_frontier > Self::checkpoint() {
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

    /// Apply one event. `main` is the chain as of `now`.
    ///
    /// # Errors
    ///
    /// The main view's own fault. A store that cannot answer is not a
    /// chain, and it is not swallowed.
    pub fn handle<'id, H: HeaderView<'id>>(
        &mut self,
        event: Event<K>,
        main: &H,
        now: Instant,
        rng: &mut impl RelayRng,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        let before = self.state();
        match event {
            Event::SessionOpened { session, transit } => {
                let claim = self.pending.remove(&session);
                self.sessions.insert(session, Session { transit, claim });
                self.observe(main, None)?;
            }
            Event::SessionClosed { session } => {
                self.sessions.remove(&session);
                self.pending.remove(&session);
                if self.frontier == Some(session) {
                    self.frontier = None;
                }
            }
            Event::Tip { tip } => self.observe(main, Some(tip.height))?,
            Event::Latch { set } => self.alarm = set,
            Event::Fill { frontier } => self.fill_frontier = frontier,
            Event::Deadline { session } => {
                if self.frontier == Some(session) {
                    self.frontier = None;
                }
            }
            Event::Proven { formed } => self.adopt(main, &formed)?,
        }
        let after = self.state();
        if after != before {
            out.push(Command::Publish { state: after });
        }
        self.plan(main, now, rng, out)?;
        Ok(())
    }

    /// The fill's checkpoint. Genesis, because [`Trust`] has only the full
    /// posture until slice 6: there is no pinned checkpoint short of
    /// genesis for the fill to descend to.
    const fn checkpoint() -> BlockHeight {
        BlockHeight::ZERO
    }

    /// Read the main chain's work. `Err` is the view's fault and is
    /// returned. [`AtHeight::AboveTip`] is the view reporting that the
    /// height is not on the chain, which leaves the last observation.
    fn observe<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        at: Option<BlockHeight>,
    ) -> Result<(), H::Fault> {
        let Some(tip) = main.tip()? else {
            self.local = Some(Local {
                height: None,
                work: CumulativeDifficulty::ZERO,
            });
            self.reselect(main)?;
            return Ok(());
        };
        let height = at.unwrap_or(tip.height);
        if let AtHeight::Recorded(record) = main.header_at(height)? {
            self.local = Some(Local {
                height: Some(height),
                work: record.cumulative_difficulty,
            });
            self.reselect(main)?;
        }
        Ok(())
    }

    fn reselect<'id, H: HeaderView<'id>>(&mut self, main: &H) -> Result<(), H::Fault> {
        let Some(local) = self.local else {
            return Ok(());
        };
        let at = local
            .height
            .map_or(BlockHeight::ZERO, |height| height + BlockCount::ONE);
        let cap = (self.rules)(at).reorg_cap();
        self.best = self.tree.select(main, local.height, local.work, cap)?;
        Ok(())
    }

    fn adopt<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        formed: &FormedHeader,
    ) -> Result<(), H::Fault> {
        let judged =
            match shekyl_chain_rules::judge_header(formed, main, &formed.rule_set(), &self.trust) {
                Ok(Ok(judged)) => judged,
                Err(Fault::View(fault)) => return Err(fault),
                Ok(Err(_)) | Err(_) => return Ok(()),
            };
        self.tree.insert(judged);
        self.reselect(main)
    }

    /// At most one header request extends `H*`. It goes to a session
    /// whose claim beats `H*`, drawn uniformly, and the next is drawn
    /// only after this one is answered, late, or its session closes.
    fn plan<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        now: Instant,
        rng: &mut impl RelayRng,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        if self.frontier.is_some() || self.local.is_none() {
            return Ok(());
        }
        let sources: Vec<K> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.claim.is_some_and(|claim| claim.work > self.best))
            .map(|(session, _)| *session)
            .collect();
        if sources.is_empty() {
            return Ok(());
        }
        let last = u64::try_from(sources.len() - 1).unwrap_or(u64::MAX);
        let index = usize::try_from(bounded_uniform(rng, last)).unwrap_or(0);
        let Some(session) = sources.get(index).copied() else {
            return Ok(());
        };
        let ids = locator(&main_newest_first(main)?);
        let transit = self
            .sessions
            .get(&session)
            .map(|session| session.transit)
            .unwrap_or_default();
        self.frontier = Some(session);
        out.push(Command::RequestHeaders {
            session,
            deadline: header_deadline(now, transit, ids.len()),
            request: RequestHeaders { block_ids: ids },
        });
        Ok(())
    }
}

/// A refused hint, or the main view failing while the request is built.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimError<E> {
    /// The claim cannot be a chain.
    Refused(PayloadRefused),
    /// The main view could not be read.
    View(E),
}

fn header_deadline(now: Instant, transit: Duration, hashes: usize) -> Instant {
    let bytes = u64::try_from(hashes).unwrap_or(u64::MAX).saturating_mul(32);
    let secs = (bytes / HEADERS_RATE_FLOOR).max(1);
    now.checked_add(transit + Duration::from_secs(secs))
        .unwrap_or(now)
}

fn main_newest_first<'id, H: HeaderView<'id>>(main: &H) -> Result<Vec<BlockHash>, H::Fault> {
    let Some(tip) = main.tip()? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let mut height = tip.height;
    loop {
        let AtHeight::Recorded(record) = main.header_at(height)? else {
            break;
        };
        out.push(record.hash);
        let Some(below) = height.checked_sub_count(BlockCount::ONE) else {
            break;
        };
        height = below;
    }
    Ok(out)
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
    use shekyl_types::{AttestationRoot, BlockHash, BlockHeight, ChainCount, CurveTreeRoot};
    use shekyl_wire::BlockHeader;

    use super::{Command, Event, Sync};
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

    fn open(sync: &mut Sync<u8>, session: u8) -> Vec<Command<u8>> {
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

    fn hint(sync: &mut Sync<u8>, peer: PeerClaim) -> Result<(), ClaimError<Infallible>> {
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
        }
    }

    #[test]
    fn a_genesis_only_claim_is_admitted() {
        let mut sync = Sync::new(Trust::UNANCHORED);
        // One block, target 1.
        assert_eq!(hint(&mut sync, claim(1, 1)), Ok(()));
        assert_eq!(sync.state(), SyncState::NoView);
    }

    #[test]
    fn a_block_count_of_zero_is_refused() {
        let mut sync = Sync::new(Trust::UNANCHORED);
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
        let mut sync = Sync::new(Trust::UNANCHORED);
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
        let mut sync = Sync::new(Trust::UNANCHORED);
        assert_eq!(hint(&mut sync, claim(count, work)), Ok(()));
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
        hint(&mut sync, claim(9_000, u128::MAX)).unwrap();
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
    }

    #[test]
    fn a_store_fault_reaches_the_caller() {
        let mut sync = Sync::new(Trust::UNANCHORED);
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
        let mut sync = Sync::new(Trust::UNANCHORED);
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
                Command::Publish { .. } => None,
            })
            .collect()
    }
}
