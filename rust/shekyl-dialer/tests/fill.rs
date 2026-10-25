// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fill rule (R1), as properties of `plan`.
//!
//! Each rule's condition is written out again here, in the words of the
//! dialer brief, and compared with `plan` over every census on a grid.
//! The model runs drive the real peer lists, so the sequence a node goes
//! through at first start and at restart is the one the lists allow.

use std::net::Ipv4Addr;

use shekyl_dialer::{plan, Census, DialAim, DrawList, FillRule, Plan};
use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::{
    white_diversity_floor, ConnectorId, DialOutcome, NetworkAddress, NoBans, Peerlist, RefusedSet,
    Source, Tick, WHITE_REFILL_LINE,
};

/// A small floor and refill line, so the grid crosses both.
const FLOOR: usize = 3;
const REFILL: usize = 5;
/// The bound the grid is read at: one dial in flight stops the wake. The
/// rules do not read the bound beyond that check.
const BOUND: usize = 1;

fn grid() -> Vec<Census> {
    let mut out = Vec::new();
    for kept in 0..=3 {
        for target in 0..=3 {
            for white in 0..=6 {
                for white_candidates in 0..=white {
                    for gray in 0..=4 {
                        for gray_candidates in 0..=gray {
                            out.push(Census {
                                kept,
                                in_flight: 0,
                                target,
                                white,
                                white_candidates,
                                gray,
                                gray_candidates,
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

/// The brief's four conditions, in its order, written independently of
/// `plan`'s code.
fn expected(c: &Census) -> Option<Plan> {
    if c.target == 0 {
        return None;
    }
    let white_holds_floor = c.white >= FLOOR && c.white_candidates > 0;
    let gray_holds_floor = c.gray >= FLOOR && c.gray_candidates > 0;
    let any = |rule, list, aim| Some(Plan { rule, list, aim });
    if c.kept == 0 {
        // (a) the next success is kept; the draw is (b)'s, then gray when
        // it holds a drawable address, otherwise white.
        return if white_holds_floor {
            any(FillRule::NoKeptSession, DrawList::White, DialAim::Keep)
        } else if gray_holds_floor || c.gray_candidates > 0 {
            any(FillRule::NoKeptSession, DrawList::Gray, DialAim::Keep)
        } else if c.white_candidates > 0 {
            any(FillRule::NoKeptSession, DrawList::White, DialAim::Keep)
        } else {
            None
        };
    }
    if c.kept < c.target && white_holds_floor {
        return any(FillRule::UnderTarget, DrawList::White, DialAim::Keep);
    }
    if c.kept < c.target && gray_holds_floor {
        return any(FillRule::UnderTarget, DrawList::Gray, DialAim::Keep);
    }
    if c.white < REFILL && c.gray_candidates > 0 {
        return any(FillRule::Refill, DrawList::Gray, DialAim::Confirm);
    }
    if c.kept < c.target && c.gray_candidates == 0 && c.white_candidates > 0 {
        return any(FillRule::GrayEmpty, DrawList::White, DialAim::Keep);
    }
    None
}

#[test]
fn each_rule_fires_exactly_in_its_condition() {
    let grid = grid();
    let mut seen = [0usize; 4];
    for census in &grid {
        let got = plan(census, FLOOR, REFILL, BOUND);
        assert_eq!(got, expected(census), "{census:?}");
        if let Some(plan) = got {
            seen[match plan.rule {
                FillRule::NoKeptSession => 0,
                FillRule::UnderTarget => 1,
                FillRule::Refill => 2,
                FillRule::GrayEmpty => 3,
            }] += 1;
        }
    }
    // Rule 47: the grid reaches every rule, so the comparison is not over
    // a set where one of them never fires.
    assert!(
        seen.iter().all(|n| *n > 0),
        "every rule fires on the grid: {seen:?}"
    );
}

#[test]
fn a_node_with_no_kept_session_keeps_its_next_success_whatever_the_list() {
    for census in grid() {
        if census.kept != 0 || census.target == 0 {
            continue;
        }
        let drawable = census.white_candidates > 0 || census.gray_candidates > 0;
        match plan(&census, FLOOR, REFILL, BOUND) {
            Some(plan) => {
                assert!(drawable);
                assert_eq!(plan.aim, DialAim::Keep, "{census:?}");
                assert_eq!(plan.rule, FillRule::NoKeptSession);
            }
            None => assert!(
                !drawable,
                "{census:?}: an address is drawable and nothing dials"
            ),
        }
    }
}

#[test]
fn a_keep_under_target_draws_only_a_list_at_or_above_the_floor() {
    for census in grid() {
        let Some(plan) = plan(&census, FLOOR, REFILL, BOUND) else {
            continue;
        };
        if plan.rule != FillRule::UnderTarget {
            continue;
        }
        assert!(census.kept >= 1 && census.kept < census.target);
        match plan.list {
            DrawList::White => assert!(census.white >= FLOOR, "{census:?}"),
            DrawList::Gray => assert!(census.gray >= FLOOR, "{census:?}"),
        }
    }
}

#[test]
fn a_confirm_never_takes_a_slot_and_never_runs_at_or_above_the_refill_line() {
    for census in grid() {
        let Some(plan) = plan(&census, FLOOR, REFILL, BOUND) else {
            continue;
        };
        if plan.aim != DialAim::Confirm {
            continue;
        }
        assert_eq!(plan.rule, FillRule::Refill);
        assert_eq!(plan.list, DrawList::Gray, "a confirm draws gray");
        assert!(census.white < REFILL, "{census:?}");
        assert!(census.gray_candidates > 0);
        assert!(census.kept >= 1, "with no kept session the dial is a keep");
    }
}

#[test]
fn at_or_over_the_target_no_dial_is_a_keep() {
    for census in grid() {
        if census.kept == 0 || census.kept < census.target {
            continue;
        }
        if let Some(plan) = plan(&census, FLOOR, REFILL, BOUND) {
            assert_eq!(plan.aim, DialAim::Confirm, "{census:?}");
        }
    }
}

#[test]
fn a_white_list_with_no_candidate_is_never_drawn() {
    for census in grid() {
        if let Some(plan) = plan(&census, FLOOR, REFILL, BOUND) {
            match plan.list {
                DrawList::White => assert!(census.white_candidates > 0, "{census:?}"),
                DrawList::Gray => assert!(census.gray_candidates > 0, "{census:?}"),
            }
        }
    }
    // Every white address is already an outbound session and white is
    // under the refill line: the wake draws gray, not a live white peer.
    let census = Census {
        kept: 2,
        in_flight: 0,
        target: 3,
        white: 4,
        white_candidates: 0,
        gray: 2,
        gray_candidates: 2,
    };
    assert_eq!(
        plan(&census, FLOOR, REFILL, BOUND).map(|p| p.list),
        Some(DrawList::Gray)
    );
}

#[test]
fn a_dial_in_flight_or_a_target_of_zero_dials_nothing() {
    for mut census in grid() {
        census.in_flight = BOUND;
        assert_eq!(plan(&census, FLOOR, REFILL, BOUND), None, "{census:?}");
        census.in_flight = 0;
        census.target = 0;
        assert_eq!(plan(&census, FLOOR, REFILL, BOUND), None, "{census:?}");
    }
}

// ---- model runs over the real peer lists -------------------------------

const TARGET: usize = 12;

fn at(seconds: u64) -> Tick {
    Tick::new(seconds * 1_000_000_000)
}

fn peer(n: u16) -> NetworkAddress {
    NetworkAddress::Ipv4 {
        ip: Ipv4Addr::new(11, 8, (n >> 8) as u8, (n & 0xff) as u8),
        port: 18080,
    }
}

/// One node's dialer state over the real lists. Every dial succeeds, and
/// a peer's reply adds nothing to gray, so the run shows what the rules
/// do with the population they start from.
struct Node {
    list: Peerlist,
    kept: Vec<NetworkAddress>,
    rng: SplitMix64,
    now: u64,
}

impl Node {
    fn with_gray(count: u16, seed: u64) -> Self {
        let mut rng = SplitMix64::new(seed);
        let mut list = Peerlist::new(RefusedSet::NON_GLOBAL);
        for n in 0..count {
            list.admit_gray(&peer(n), Source::Operator, at(0), &mut NoBans, &mut rng)
                .expect("admitted");
        }
        Self {
            list,
            kept: Vec::new(),
            rng,
            now: 0,
        }
    }

    fn census(&mut self) -> Census {
        let white = self.list.white_count(
            ConnectorId::Clearnet,
            at(self.now),
            &mut NoBans,
            &mut self.rng,
        );
        let gray = self.list.gray_count(ConnectorId::Clearnet);
        let live_white = self.kept.iter().filter(|a| self.list.is_white(a)).count();
        Census {
            kept: self.kept.len(),
            in_flight: 0,
            target: TARGET,
            white,
            white_candidates: white - live_white,
            gray,
            gray_candidates: gray,
        }
    }

    /// One wake: plan, draw, and a dial that succeeds. Returns the plan.
    fn wake(&mut self) -> Option<Plan> {
        self.now += 1;
        let census = self.census();
        let plan = plan(&census, white_diversity_floor(), WHITE_REFILL_LINE, 1)?;
        let address = match plan.list {
            DrawList::Gray => self
                .list
                .draw_gray(ConnectorId::Clearnet, &mut self.rng)
                .expect("the plan saw a gray candidate"),
            DrawList::White => loop {
                let drawn = self
                    .list
                    .draw_white(
                        ConnectorId::Clearnet,
                        at(self.now),
                        &mut NoBans,
                        &mut self.rng,
                    )
                    .expect("the plan saw a white candidate");
                if !self.kept.contains(&drawn) {
                    break drawn;
                }
            },
        };
        let outcome = match plan.aim {
            DialAim::Keep => {
                self.kept.push(address.clone());
                DialOutcome::SessionAccepted(address)
            }
            DialAim::Confirm => DialOutcome::Confirmed(address),
        };
        self.list.apply(&outcome, at(self.now), &mut self.rng);
        Some(plan)
    }
}

/// A brand-new node: gray is the compiled seeds and nothing else. It
/// keeps its first success and then confirms; it does not keep a second
/// seed while gray still holds one and no list has reached the floor.
#[test]
fn a_fresh_node_keeps_at_most_one_seed_before_a_list_reaches_the_floor() {
    for seed in 0..20 {
        let seeds = 6;
        let mut node = Node::with_gray(seeds, seed);
        let first = node.wake().expect("a seed is drawable");
        assert_eq!(first.rule, FillRule::NoKeptSession);
        assert_eq!(first.aim, DialAim::Keep);
        let mut keeps = 1;
        while node.list.gray_count(ConnectorId::Clearnet) > 0 {
            let plan = node.wake().expect("gray is drawable and white is thin");
            assert_eq!(plan.rule, FillRule::Refill, "seed {seed}");
            if plan.aim == DialAim::Keep {
                keeps += 1;
            }
        }
        assert_eq!(
            keeps, 1,
            "seed {seed}: one seed kept while the pool was thin"
        );
        assert_eq!(node.kept.len(), 1);
    }
}

/// A restarted node: gray only, and large. It keeps at its first success
/// and fills from gray, with no run of confirm dials before the first
/// kept session.
#[test]
fn a_restarted_node_keeps_at_its_first_success_and_fills_from_gray() {
    let reloaded = u16::try_from(white_diversity_floor() * 4).expect("small");
    let mut node = Node::with_gray(reloaded, 7);
    for n in 0..TARGET {
        let plan = node.wake().expect("gray is large");
        assert_eq!(plan.aim, DialAim::Keep, "dial {n} is kept");
        assert_eq!(plan.list, DrawList::Gray, "dial {n} fills from gray");
        let rule = if n == 0 {
            FillRule::NoKeptSession
        } else {
            FillRule::UnderTarget
        };
        assert_eq!(plan.rule, rule);
    }
    assert_eq!(node.kept.len(), TARGET);
}

/// Confirm-and-close ends: when white reaches the refill line, or when
/// gray empties, whichever is first. Each confirm takes one address out
/// of gray, so the count of confirms is bounded by what gray held.
#[test]
fn confirm_and_close_ends_at_the_refill_line_or_when_gray_empties() {
    // Gray large enough to carry white to the refill line.
    let mut node = Node::with_gray(200, 11);
    let mut confirms = 0;
    let mut wakes = 0;
    while let Some(plan) = node.wake() {
        wakes += 1;
        assert!(wakes < 1_000, "the fill did not stop");
        if plan.aim == DialAim::Confirm {
            confirms += 1;
        }
    }
    let white = node.census().white;
    assert_eq!(node.kept.len(), TARGET, "the keep slots are full");
    assert!(
        white >= WHITE_REFILL_LINE,
        "white reached the refill line: {white}"
    );
    assert!(confirms <= 200);
    assert!(
        node.list.gray_count(ConnectorId::Clearnet) > 0,
        "gray was not exhausted"
    );

    // Gray too small to reach the line: the confirms stop when it empties.
    let mut small = Node::with_gray(20, 13);
    let mut wakes = 0;
    while small.wake().is_some() {
        wakes += 1;
        assert!(wakes < 1_000, "the fill did not stop");
    }
    assert_eq!(small.list.gray_count(ConnectorId::Clearnet), 0);
    assert!(small.census().white < WHITE_REFILL_LINE);
}

/// A network smaller than the floor (genesis, a private testnet): once
/// gray is empty the node keeps from white, up to its target.
#[test]
fn with_gray_empty_and_under_target_the_keep_is_from_white() {
    let mut node = Node::with_gray(8, 17);
    let mut from_white = 0;
    let mut wakes = 0;
    while let Some(plan) = node.wake() {
        wakes += 1;
        assert!(wakes < 1_000);
        if plan.rule == FillRule::GrayEmpty {
            assert_eq!((plan.list, plan.aim), (DrawList::White, DialAim::Keep));
            from_white += 1;
        }
    }
    assert!(from_white > 0, "rule (d) ran");
    assert_eq!(
        node.kept.len(),
        8,
        "every peer of the small network is kept"
    );
}
