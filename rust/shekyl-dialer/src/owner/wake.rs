// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One wake: settle the lists once, then recover, idle, or begin one test.
//!
//! A test whose next attempt is due runs before any new draw. The open
//! test lives on [`Attempts`](crate::attempts::Attempts); this module only
//! decides which wake makes it.

use shekyl_draw_rng::RelayRng;
use shekyl_peerlist::{
    white_diversity_floor, ConnectorId, NetworkAddress, Tick, WHITE_REFILL_LINE,
};

use super::address::LiveSessions;
use super::recovery;
use super::Shared;
use crate::bans::BanSnapshot;
use crate::candidate::CandidateFilter;
use crate::fill::{plan, Census, DialAim, DrawList};

/// Why a connector under its target dialed nothing on one wake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdleWhy {
    /// A dial is already in flight, so the fill draws nothing.
    InFlight,
    /// A test is waiting for its next attempt, and nothing else is drawable.
    RetryWaiting,
    /// The lists have nothing the fill can draw.
    NoCandidate,
    /// Gray or white holds addresses, and every one is filtered out.
    Filtered,
}

impl IdleWhy {
    fn reason(self) -> &'static str {
        match self {
            Self::InFlight => "a dial is in flight",
            Self::RetryWaiting => "a retry is waiting",
            Self::NoCandidate => "no candidate",
            Self::Filtered => "a filter holds every address",
        }
    }
}

/// Consecutive wakes of one [`IdleWhy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IdleWatch {
    why: IdleWhy,
    wakes: u32,
    warned: bool,
}

/// How many wakes a connector may sit under its target with nothing dialed
/// before the owner says so. One warning, then silence until the reason
/// changes, the connector draws, or it is no longer under its target.
const IDLE_WARN_WAKES: u32 = 60;

/// What one settled wake decided.
pub(super) enum Wake {
    /// Under the target, nothing in flight, and no drawable candidate.
    /// The caller re-admits the configured population and dials nothing.
    Recover,
    /// This wake dials nothing.
    Idle,
    /// An attempt was begun. The nonce is minted after the lists lock drops.
    Drawn {
        address: NetworkAddress,
        aim: DialAim,
    },
}

/// What the census says about an under-target wake that does not draw.
/// `None` when the connector is not under its target: the watch clears.
///
/// A waiting test is the reason only when nothing else is drawable. A
/// wake that has candidates and also has a test waiting keeps
/// [`IdleWhy::NoCandidate`]: the fill declined a candidate.
fn idle_if_undrawn(census: &Census, retry_waiting: bool, bound: usize) -> Option<IdleWhy> {
    if census.target == 0 || census.kept >= census.target {
        return None;
    }
    // `bound` is the connector's in-flight bound, the same number `plan`
    // reads. A test seam that raises it raises this check with it.
    if census.in_flight >= bound {
        return Some(IdleWhy::InFlight);
    }
    if census
        .white_candidates
        .saturating_add(census.gray_candidates)
        > 0
    {
        // The lists hold a drawable address and no rule took it.
        return Some(IdleWhy::NoCandidate);
    }
    if retry_waiting {
        return Some(IdleWhy::RetryWaiting);
    }
    if census.white.saturating_add(census.gray) > 0 {
        return Some(IdleWhy::Filtered);
    }
    Some(IdleWhy::NoCandidate)
}

/// Settle once, count once, and either recover, idle, or begin one attempt.
/// [`super::Dialer::choose`] has already returned when the connector cannot dial.
/// `bans` was copied out of the hub before the lists lock was taken.
pub(super) fn plan_wake<R: RelayRng + ?Sized>(
    shared: &mut Shared,
    bans: &mut BanSnapshot,
    connector: ConnectorId,
    live: &LiveSessions,
    now: Tick,
    rng: &mut R,
) -> Wake {
    let index = connector.index();
    let target = shared.targets[index];
    // Protocol data installed on the dialer. A test seam can raise it, and
    // the retry below and the draw further down both read this number.
    let bound = shared.bounds[index];
    // A test whose next attempt is due makes it now, ahead of any draw: the
    // address is still the outstanding draw, so nothing draws it twice.
    // The test moves from waiting to in flight inside `take_due`, so this
    // path cannot drop the test and leave the seat outstanding.
    if shared.attempts[index].in_flight() < bound {
        if let Some((address, aim)) = shared.attempts[index].take_due(now) {
            // Every wake reports to the recovery episode, this one too:
            // it drew the address of a test the episode may cover.
            let kept = shared.attempts[index].kept_count();
            recovery::report_wake(
                &mut shared.recovery[index],
                connector,
                kept,
                target,
                Some(&address),
            );
            note_idle(shared, connector, None);
            return Wake::Drawn { address, aim };
        }
    }
    let waiting = shared.attempts[index].has_waiting();
    let own = shared.own[index].clone();
    let exclusive = shared.exclusive.clone();
    let (wake, undrawn, kept) = {
        let Shared {
            lists, attempts, ..
        } = &mut *shared;
        let kept = attempts[index].kept_count();
        let in_flight = attempts[index].in_flight();
        let mut settled = lists.settle(connector, now, bans, &mut attempts[index], rng);
        let mut filter = CandidateFilter {
            own: &own,
            sessions: &live.addresses,
            outbound_hosts: &live.outbound_hosts,
            attempts: &attempts[index],
            bans: &mut *bans,
            now,
        };
        let mut eligible = |address: &NetworkAddress| {
            exclusive
                .as_ref()
                .is_none_or(|population| population.contains(address))
                && filter.admits(address)
        };
        let seats = settled.census(&mut eligible);
        let census = Census {
            kept,
            in_flight,
            target,
            white: seats.white,
            white_candidates: seats.white_candidates,
            gray: seats.gray,
            gray_candidates: seats.gray_candidates,
        };
        let undrawn = idle_if_undrawn(&census, waiting, bound);
        // Stranded: under the target, nothing in flight, nothing drawable.
        // The lists cannot yield another peer, so this wake re-admits and
        // dials nothing. One kept session is not a healthy connector
        // (dialer brief, "Recovery").
        let stranded = kept < target
            && in_flight == 0
            && !waiting
            && census.white_candidates == 0
            && census.gray_candidates == 0;
        let wake = if stranded {
            Wake::Recover
        } else {
            match plan(&census, white_diversity_floor(), WHITE_REFILL_LINE, bound) {
                None => {
                    tracing::debug!("{connector:?} wake: no rule applies ({census:?})");
                    Wake::Idle
                }
                Some(chosen) => {
                    let drawn = match chosen.list {
                        DrawList::Gray => settled.draw_gray(&mut eligible, rng),
                        DrawList::White => settled.draw_white(&mut eligible, rng),
                    };
                    match drawn {
                        Some(address) => Wake::Drawn {
                            address,
                            aim: chosen.aim,
                        },
                        None => {
                            tracing::debug!(
                                "{connector:?} wake: {:?} chose {:?}, nothing drawn ({census:?})",
                                chosen.rule,
                                chosen.list
                            );
                            Wake::Idle
                        }
                    }
                }
            }
        };
        (wake, undrawn, kept)
    };
    // `kept` is the count before this wake's dial. A session the previous
    // wake kept is visible here, including when this wake is stranded.
    let drawn = match &wake {
        Wake::Drawn { address, .. } => Some(address),
        Wake::Recover | Wake::Idle => None,
    };
    recovery::report_wake(&mut shared.recovery[index], connector, kept, target, drawn);
    let wake = match wake {
        Wake::Recover | Wake::Idle => wake,
        Wake::Drawn { address, aim } => {
            if shared.begin_or_release(connector, &address, aim) {
                Wake::Drawn { address, aim }
            } else {
                tracing::debug!("{connector:?} wake: {address:?} already has an attempt");
                Wake::Idle
            }
        }
    };
    let idle = match wake {
        Wake::Drawn { .. } => None,
        Wake::Recover | Wake::Idle => undrawn,
    };
    note_idle(shared, connector, idle);
    wake
}

/// Count an under-target wake that dialed nothing. The first time the
/// same reason reaches [`IDLE_WARN_WAKES`], say so once. A draw, a change
/// of reason, or leaving the under-target state clears the count.
fn note_idle(shared: &mut Shared, connector: ConnectorId, why: Option<IdleWhy>) {
    let slot = &mut shared.idle[connector.index()];
    let Some(why) = why else {
        *slot = None;
        return;
    };
    match slot {
        Some(watch) if watch.why == why => {
            watch.wakes = watch.wakes.saturating_add(1);
            if watch.wakes == IDLE_WARN_WAKES && !watch.warned {
                watch.warned = true;
                let reason = why.reason();
                tracing::warn!(
                    "{connector:?}: under its target for {IDLE_WARN_WAKES} wakes with nothing dialed: {reason}"
                );
            }
        }
        _ => {
            *slot = Some(IdleWatch {
                why,
                wakes: 1,
                warned: false,
            })
        }
    }
}
