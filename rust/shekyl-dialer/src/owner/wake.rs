// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One wake: settle the lists once, then recover, idle, or begin one test.
//!
//! A test whose next attempt is due runs before any new draw, unless its
//! host is already reached. The open test lives on
//! [`Attempts`](crate::attempts::Attempts); this module only decides which
//! wake makes it.

use std::collections::BTreeSet;

use shekyl_draw_rng::RelayRng;
use shekyl_peerlist::{
    white_diversity_floor, ConnectorId, NetworkAddress, Tick, WHITE_REFILL_LINE,
};

use super::recovery;
use super::Shared;
use crate::attempts::Attempts;
use crate::candidate::{host_occupied, CandidateFilter};
use crate::fill::{plan, Census, DialAim, DrawList};

/// Why a connector under its target dialed nothing on one wake.
///
/// Each is a state the connector leaves without the operator: a dial ends,
/// a cooldown passes, a session closes, a peer names a new address, or
/// recovery re-admits the configured ones. The report is an info line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdleWhy {
    /// A dial is in flight, and the bound is reached or nothing else is
    /// drawable.
    InFlight,
    /// A test is waiting for its next attempt, and nothing else is drawable.
    RetryWaiting,
    /// A candidate is drawable, and no fill rule takes it.
    FillDeclined,
    /// Neither list holds an address.
    NoAddress,
    /// The addresses the connector is not using are off the draw: cooling
    /// after a failed dial, or held by an excusal.
    OffDraw,
    /// Every address is a session, on a host the connector already reaches,
    /// or this node's own: the network is smaller than the target.
    InUse,
}

impl IdleWhy {
    fn reason(self) -> &'static str {
        match self {
            Self::InFlight => "a dial is in flight",
            Self::RetryWaiting => "a retry is waiting",
            Self::FillDeclined => "no fill rule takes the drawable addresses",
            Self::NoAddress => "it knows no address",
            Self::OffDraw => {
                "the addresses it is not using are cooling after a failed dial, or held by an excusal"
            }
            Self::InUse => {
                "every address it knows is connected, on a host it already reaches, or its own"
            }
        }
    }
}

/// Which reasons this under-target spell has already said.
///
/// One field per [`IdleWhy`], in the same order. A new reason does not
/// compile until it is named here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SaidReasons {
    in_flight: bool,
    retry_waiting: bool,
    fill_declined: bool,
    no_address: bool,
    off_draw: bool,
    in_use: bool,
}

impl SaidReasons {
    const fn contains(self, why: IdleWhy) -> bool {
        match why {
            IdleWhy::InFlight => self.in_flight,
            IdleWhy::RetryWaiting => self.retry_waiting,
            IdleWhy::FillDeclined => self.fill_declined,
            IdleWhy::NoAddress => self.no_address,
            IdleWhy::OffDraw => self.off_draw,
            IdleWhy::InUse => self.in_use,
        }
    }

    fn insert(&mut self, why: IdleWhy) {
        let slot = match why {
            IdleWhy::InFlight => &mut self.in_flight,
            IdleWhy::RetryWaiting => &mut self.retry_waiting,
            IdleWhy::FillDeclined => &mut self.fill_declined,
            IdleWhy::NoAddress => &mut self.no_address,
            IdleWhy::OffDraw => &mut self.off_draw,
            IdleWhy::InUse => &mut self.in_use,
        };
        *slot = true;
    }
}

/// One under-target spell: from the first wake under the target to the
/// first wake that is not. A draw ends a run of idle wakes, not the spell,
/// so a dead address that thaws and fails again does not repeat the line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IdleWatch {
    /// The current run of idle wakes with one reason, and its length.
    run: Option<(IdleWhy, u32)>,
    /// The reasons already said in this spell.
    said: SaidReasons,
}

/// How many consecutive wakes with one reason before the owner says so.
/// Each reason is said at most once per under-target spell.
const IDLE_REPORT_WAKES: u32 = 60;

/// What one wake did, for the idle report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WakeReport {
    /// The connector is not under its target: the spell ends.
    NotUnder,
    /// Under the target, and this wake began an attempt.
    Drew,
    /// Under the target, and nothing was dialed.
    Idle(IdleWhy),
}

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

/// Whether the connector is under its target. A target of zero is not.
fn under_target(kept: usize, target: usize) -> bool {
    target > 0 && kept < target
}

/// What the census says about an under-target wake that does not draw.
/// `None` when the connector is not under its target.
///
/// `off_draw` is the seats a hold keeps off the draw
/// ([`SeatCensus::off_draw`]): counted cooling and excusals. It is not
/// the session count. A dial in flight is the reason whenever nothing
/// else is drawable, below the bound too: its address is an outstanding
/// draw, not a filtered one. A waiting test is the reason only when
/// nothing else is drawable.
///
/// [`SeatCensus::off_draw`]: shekyl_peerlist::SeatCensus::off_draw
fn idle_if_undrawn(
    census: &Census,
    off_draw: usize,
    retry_waiting: bool,
    bound: usize,
) -> Option<IdleWhy> {
    if !under_target(census.kept, census.target) {
        return None;
    }
    let candidates = census
        .white_candidates
        .saturating_add(census.gray_candidates);
    // `bound` is the connector's in-flight bound, the same number `plan`
    // reads. A test seam that raises it raises this check with it.
    if census.in_flight >= bound || (census.in_flight > 0 && candidates == 0) {
        return Some(IdleWhy::InFlight);
    }
    if candidates > 0 {
        return Some(IdleWhy::FillDeclined);
    }
    if retry_waiting {
        return Some(IdleWhy::RetryWaiting);
    }
    if census.white.saturating_add(census.gray) == 0 {
        return Some(IdleWhy::NoAddress);
    }
    if off_draw > 0 {
        return Some(IdleWhy::OffDraw);
    }
    Some(IdleWhy::InUse)
}

/// The earliest due retry whose host is free, moved back to in flight.
///
/// A host that connected while the attempt waited is not dialed. That
/// wait stays where it is, with the same due, and a later wake asks
/// again. Another host whose retry is also due is the one this wake
/// makes. Nothing is recorded: no cooldown, no demotion, no `DialFailed`.
fn resume_unoccupied(
    attempts: &mut Attempts,
    sessions: &BTreeSet<NetworkAddress>,
    now: Tick,
) -> Option<(NetworkAddress, DialAim)> {
    let (address, _) = attempts
        .due(now)
        .into_iter()
        .find(|(address, _)| !host_occupied(sessions, attempts, &address.host()))?;
    let aim = attempts.resume(&address)?;
    Some((address, aim))
}

/// Settle once, count once, and either recover, idle, or begin one attempt.
/// [`super::Dialer::choose`] has already returned when the connector cannot dial.
pub(super) fn plan_wake<R: RelayRng + ?Sized>(
    shared: &mut Shared,
    connector: ConnectorId,
    sessions: &BTreeSet<NetworkAddress>,
    now: Tick,
    rng: &mut R,
) -> Wake {
    let index = connector.index();
    let target = shared.targets[index];
    // Protocol data installed on the dialer. A test seam can raise it, and
    // the retry below and the draw further down both read this number.
    let bound = shared.bounds[index];
    // A test whose next attempt is due makes it now, ahead of any draw,
    // when its host is free. The address stays the outstanding draw either
    // way, so nothing draws it twice. Resuming moves the test to in flight;
    // a host that is occupied leaves the wait untouched.
    if shared.attempts[index].in_flight() < bound {
        if let Some((address, aim)) = resume_unoccupied(&mut shared.attempts[index], sessions, now)
        {
            // Every wake reports to the recovery episode, this one too.
            let held = shared.attempts[index].held();
            recovery::report_wake(&mut shared.recovery[index], connector, held, target);
            let kept = shared.attempts[index].kept_count();
            let report = if under_target(kept, target) {
                WakeReport::Drew
            } else {
                WakeReport::NotUnder
            };
            note_idle(shared, connector, report, held, target);
            return Wake::Drawn { address, aim };
        }
    }
    let waiting = shared.attempts[index].has_waiting();
    let own = shared.own[index].clone();
    let exclusive = shared.exclusive.clone();
    let (wake, undrawn, held) = {
        let Shared {
            lists,
            attempts,
            pending,
            tor_link,
            ..
        } = &mut *shared;
        let kept = attempts[index].kept_count();
        let held = attempts[index].held();
        let in_flight = attempts[index].in_flight();
        let mut settled = lists.settle(connector, now, &mut attempts[index], rng);
        let filter = CandidateFilter {
            own: &own,
            sessions,
            attempts: &attempts[index],
        };
        // An address whose verdict waits is not drawn again. A gray one's
        // seat is still outstanding; a white one has no such state.
        let mut eligible = |address: &NetworkAddress| {
            exclusive
                .as_ref()
                .is_none_or(|population| population.contains(address))
                && filter.admits(address)
                && !pending
                    .iter()
                    .any(|verdict| verdict.outcome.address() == address)
        };
        let seats = settled.census(&mut eligible);
        tor_link.census(connector, seats.white.saturating_add(seats.gray));
        let census = Census {
            kept,
            in_flight,
            target,
            white: seats.white,
            white_candidates: seats.white_candidates,
            gray: seats.gray,
            gray_candidates: seats.gray_candidates,
        };
        let undrawn = idle_if_undrawn(&census, seats.off_draw, waiting, bound);
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
        (wake, undrawn, held)
    };
    // `held` is the sessions before this wake's dial. A session the
    // previous wake kept is visible here, including when this wake is
    // stranded.
    recovery::report_wake(&mut shared.recovery[index], connector, held, target);
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
    let report = match (&wake, undrawn) {
        (_, None) => WakeReport::NotUnder,
        (Wake::Drawn { .. }, Some(_)) => WakeReport::Drew,
        (Wake::Recover | Wake::Idle, Some(why)) => WakeReport::Idle(why),
    };
    note_idle(shared, connector, report, held, target);
    wake
}

/// Count an under-target wake that dialed nothing. The first time one
/// reason reaches [`IDLE_REPORT_WAKES`] consecutive wakes, say so, once in
/// this under-target spell. A draw or a change of reason restarts the
/// count. Only leaving the under-target state ends the spell.
fn note_idle(
    shared: &mut Shared,
    connector: ConnectorId,
    report: WakeReport,
    held: usize,
    target: usize,
) {
    let slot = &mut shared.idle[connector.index()];
    let why = match report {
        WakeReport::NotUnder => {
            *slot = None;
            return;
        }
        WakeReport::Drew => {
            if let Some(watch) = slot {
                watch.run = None;
            }
            return;
        }
        WakeReport::Idle(why) => why,
    };
    let watch = slot.get_or_insert(IdleWatch {
        run: None,
        said: SaidReasons::default(),
    });
    let wakes = match watch.run {
        Some((current, wakes)) if current == why => wakes.saturating_add(1),
        _ => 1,
    };
    watch.run = Some((why, wakes));
    if wakes == IDLE_REPORT_WAKES && !watch.said.contains(why) {
        watch.said.insert(why);
        let reason = why.reason();
        tracing::info!(
            "{connector:?}: holds {held} of its {target} target sessions and dialed nothing for {IDLE_REPORT_WAKES} wakes: {reason}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{idle_if_undrawn, IdleWhy, SaidReasons};
    use crate::fill::Census;

    const REASONS: [IdleWhy; 6] = [
        IdleWhy::InFlight,
        IdleWhy::RetryWaiting,
        IdleWhy::FillDeclined,
        IdleWhy::NoAddress,
        IdleWhy::OffDraw,
        IdleWhy::InUse,
    ];

    fn census(white: usize, gray: usize) -> Census {
        Census {
            kept: 1,
            in_flight: 0,
            target: 12,
            white,
            white_candidates: 0,
            gray,
            gray_candidates: 0,
        }
    }

    #[test]
    fn a_hold_off_the_draw_is_named_apart_from_an_address_in_use() {
        let seats = census(1, 0);
        assert_eq!(idle_if_undrawn(&seats, 1, false, 4), Some(IdleWhy::OffDraw));
        assert_eq!(idle_if_undrawn(&seats, 0, false, 4), Some(IdleWhy::InUse));
        assert_eq!(
            IdleWhy::OffDraw.reason(),
            "the addresses it is not using are cooling after a failed dial, or held by an excusal"
        );
    }

    #[test]
    fn each_reason_has_its_own_flag() {
        for why in REASONS {
            let mut said = SaidReasons::default();
            said.insert(why);
            for other in REASONS {
                assert_eq!(said.contains(other), other == why);
            }
        }
    }
}
