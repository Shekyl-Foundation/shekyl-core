// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DQ-T0.4 — the per-persona circuit-isolation measurement (the 2d-2 firewall's
//! network-axis proof).
//!
//! # The split (read before adding the live harness)
//!
//! This file holds the **pure trap-logic**: it takes the four circuit IDs the
//! serialized measurement captured — each *already confirmed present* — and decides
//! the verdict. It never waits on a socket, never spawns a net, never knows whether
//! the CircIDs came from a dev-box `tor` or a hermetic owned net. That isolation is
//! deliberate (per the harness-shape review):
//!
//! - **The verdict logic and the I/O wait sit on opposite sides of the seam.** The
//!   capture (dial → drain the event sink → read the attach-time CircID, with the
//!   M4 timeout) is the flaky, integration-lane part and lives in the live harness.
//!   By the time a [`CircId`] reaches here it exists; a *missing* CircID is an
//!   apparatus failure the harness raises before building [`Observations`], never a
//!   verdict — you can't construct `Observations` without all four.
//! - That split is what lets the verdict be **unit-tested deterministically**: feed
//!   it CircID quartets, assert the positive-control / invariant verdicts, no Tor.
//!
//! The live harness (serialized dials over a real SOCKS port, the warm-up
//! apparatus-assert, the owned-net behind its own module) lands next; it produces
//! `Observations` and calls [`evaluate`].

use shekyl_tor::control::CircId;

/// The four attach-time circuit IDs of the serialized measurement, each confirmed
/// present (the harness only builds this after capturing all four). All four dials
/// target the **same** address — that's what removes the target confound, and why
/// the harness must serialize them to attribute each CircID unambiguously.
struct Observations {
    /// `username_A`, first dial.
    a1: CircId,
    /// `username_A` again — the positive control (same username ⇒ same circuit).
    a2: CircId,
    /// `username_B` — a different persona.
    b: CircId,
    /// The no-auth principal model (the un-isolated baseline).
    principal: CircId,
}

/// The measurement verdict.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Positive control held *and* both isolation invariants held — the firewall's
    /// network axis is proven on this run.
    Pass,
    /// At least one check failed; the flags say which (so a failure names the broken
    /// property rather than just "not isolated").
    Fail {
        /// `a1 == a2` — same username routed over the same circuit. A miss here is
        /// usually circuit rotation (pin `MaxCircuitDirtiness`), not an isolation bug.
        positive_control: bool,
        /// `a1 != principal` — a persona's circuit differs from the principal's.
        invariant_b: bool,
        /// `a1 != b` — two distinct personas get distinct circuits.
        invariant_c: bool,
    },
}

/// Decide the verdict from four confirmed-present circuit IDs. Pure: equality
/// comparisons only, no I/O.
fn evaluate(o: &Observations) -> Verdict {
    // `a1` is persona A's circuit; the positive control confirms it is stable
    // (a1 == a2), so the invariants compare it against B and the principal.
    let positive_control = o.a1 == o.a2;
    let invariant_b = o.a1 != o.principal;
    let invariant_c = o.a1 != o.b;
    if positive_control && invariant_b && invariant_c {
        Verdict::Pass
    } else {
        Verdict::Fail {
            positive_control,
            invariant_b,
            invariant_c,
        }
    }
}

#[test]
fn all_disjoint_with_stable_persona_passes() {
    // A stable (a1==a2), and B + principal each on their own circuit.
    let obs = Observations {
        a1: CircId::new(100),
        a2: CircId::new(100),
        b: CircId::new(200),
        principal: CircId::new(300),
    };
    assert_eq!(evaluate(&obs), Verdict::Pass);
}

#[test]
fn unstable_persona_fails_the_positive_control_only() {
    // a1 != a2: the persona's own two dials took different circuits — the apparatus
    // (likely dirtiness rotation) is suspect, flagged distinctly from isolation.
    let obs = Observations {
        a1: CircId::new(100),
        a2: CircId::new(101),
        b: CircId::new(200),
        principal: CircId::new(300),
    };
    assert_eq!(
        evaluate(&obs),
        Verdict::Fail {
            positive_control: false,
            invariant_b: true,
            invariant_c: true,
        }
    );
}

#[test]
fn two_personas_sharing_a_circuit_fails_invariant_c() {
    // a1 == b: persona A and persona B landed on the same circuit — isolation broke.
    let obs = Observations {
        a1: CircId::new(100),
        a2: CircId::new(100),
        b: CircId::new(100),
        principal: CircId::new(300),
    };
    assert_eq!(
        evaluate(&obs),
        Verdict::Fail {
            positive_control: true,
            invariant_b: true,
            invariant_c: false,
        }
    );
}

#[test]
fn persona_sharing_the_principal_circuit_fails_invariant_b() {
    // a1 == principal: a persona is not isolated from the un-authed baseline.
    let obs = Observations {
        a1: CircId::new(100),
        a2: CircId::new(100),
        b: CircId::new(200),
        principal: CircId::new(100),
    };
    assert_eq!(
        evaluate(&obs),
        Verdict::Fail {
            positive_control: true,
            invariant_b: false,
            invariant_c: true,
        }
    );
}
