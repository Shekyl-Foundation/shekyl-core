// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the daemon's Dandelion++ **embargo timer**, backed by
//! `shekyl-relay-privacy` — RP-4 of `docs/design/DAEMON_RELAY_PRIVACY.md` §17.
//!
//! One call, no handle: the embargo distribution is node-local **policy** (relay
//! timing is not consensus), fixed for all nodes sharing the adopted parameters,
//! so there is no per-connection state to own.
//!
//! # The stem map used to live here too
//!
//! It was RP-2a's boundary: an opaque `StemMapHandle` that the C++
//! `net::dandelionpp::connection_map` wrapped, so `levin_notify` could keep its
//! map ABI while the logic moved to `stem_map.rs`. RP-3a took the whole relay
//! zone into Rust, and `shekyl-relay::Zone` now owns a `StemMap` **directly** —
//! no handle, no wrapper, no C ABI between them. The exports, the wrapper and
//! its gtests were retired together in that round rather than left as a second
//! path to the same map.
//!
//! The three §16.1 seam contracts went with them, but only two are moot: `update`
//! returning the exact re-arm predicate is now `Zone::update_stems` returning
//! `StemSetChange`, and `clone` being a deep copy died with the handle that
//! could be shallow-copied. **Index order with nils in position survived** — as
//! a pushed-array contract through RP-3a, then RP-3b's §20.3 inversion retired
//! the array itself: the binding now travels with each covert send, and a slot
//! going unbound crosses as its own per-channel decision. The property's
//! witnesses moved with it, into `shekyl-relay`'s
//! `covert_sends_carry_the_slots_own_peer_at_its_own_index` /
//! `an_unbound_channel_emits_nothing_and_shifts_no_other` (the decision) and
//! `relay_zone_ffi`'s `an_unbinding_slot_crosses_as_covert_unbind_at_its_index`
//! (the marshalling).

use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::{EmbargoTimer, PROPAGATION_FALSE_FAIL_ONE_IN};
use std::sync::OnceLock;

use crate::secure_relay_rng::SecureRelayRng;

// --- the embargo timer (RP-4, §17) --------------------------------------------

/// The adopted embargo timer, built once per process.
///
/// Unlike the stem map there is no handle: the embargo distribution is
/// node-local **policy** (not consensus), fixed for a given parameter set rather
/// than per-connection state. The table is immutable once built and its
/// construction is a pure recurrence over frozen parameters, so a singleton is
/// the whole of the state this boundary needs.
static EMBARGO: OnceLock<EmbargoTimer> = OnceLock::new();

fn embargo_timer() -> &'static EmbargoTimer {
    EMBARGO.get_or_init(|| EmbargoTimer::adopted(&DandelionParams::inherited()))
}

/// Draw one Dandelion++ embargo duration, in **seconds**.
///
/// This is the timer whose expiry fluffs a stem transaction the node has not
/// seen re-broadcast — the black-hole backstop. It replaces the inherited
/// `crypto::random_poisson_seconds{39s}` draw, which was wrong three ways
/// (§17): the 39 s did not follow from its own stated derivation (F-1), a
/// Poisson was drawn under a derivation assuming exponential survival, so the
/// backstop never fired (F-2), and the closed form substituted `E[K]` into an
/// expression in `K(K-1)` (F-3). The adopted timer is the exact discrete
/// survival solve — **144 s**, memoryless — and its table, not a
/// platform-defined `std::poisson_distribution`, *is* the distribution.
///
/// Seconds because the caller stores a whole-second `time_t` deadline. The
/// conversion rounds **up**: under-provisioning the embargo fluffs prematurely,
/// which is the privacy-losing direction (the D-5 asymmetry), so a truncation
/// that shaved up to 999 ms off every draw would err the wrong way.
///
/// **A 0 s draw is legitimate and intended.** A memoryless geometric has support
/// `{0, 1, 2, ...}`, so ~`1/(mean_ticks+1)` ≈ 0.17 % of draws are zero — the
/// distribution's minimum, honoured rather than clamped. That is a real change
/// from the inherited `Poisson(39 s)`, which produced 0 with probability
/// `e^-39` — effectively never — and it is *not* patched here: the table is the
/// distribution the survival solve derived and the golden vector pins, so
/// flooring it at the boundary would ship something other than what was derived
/// and tested. The preemption profile (§10) already prices this self-fluff.
///
/// What "zero" means downstream, stated precisely because it is easy to overread
/// as "fluffs this instant": the daemon stores whole-second deadlines, so a
/// zero draw resolves to the *earliest deadline that does not under-provision* —
/// the next second boundary (`cryptonote::detail::embargo_deadline`). The
/// deadline is never earlier than `now + draw`, uniformly and including at zero.
/// Rounding a zero draw *down* instead would place the deadline up to ~999 ms in
/// the past, which is under-provisioning by the same asymmetry this boundary
/// rounds up to avoid — a shorter embargo is the privacy-losing direction, and
/// that does not stop being true because the draw was small.
#[no_mangle]
pub extern "C" fn shekyl_dandelionpp_embargo_draw_seconds() -> u64 {
    let mut rng = SecureRelayRng;
    embargo_timer().deadline(0, &mut rng).div_ceil(1_000)
}

/// How long a sender must wait before a transaction it has still not seen may be
/// judged to have failed — **seconds**, derived from the embargo distribution.
///
/// A stem transaction is invisible to its sender until it fluffs, so this
/// deadline is a quantile of the embargo, not a free-standing timeout. It is
/// provisioned at [`PROPAGATION_FALSE_FAIL_ONE_IN`]: at most 1 in 100 embargoes
/// is still running when the verdict is reached.
///
/// The inherited wallet instead took `3/2 ×` the (wrong) 39 s mean. Two problems,
/// and the second outlives the first: a bare multiple of the mean is only the
/// ~78th percentile of a memoryless distribution, so roughly a fifth of
/// black-holed transactions were judged failed while their backstop was still
/// running — and a false verdict is not cosmetic, because the sender releases
/// the inputs it had reserved and may re-spend them. Carrying the `3/2` onto the
/// corrected 144 s mean would have preserved that defect exactly.
/// Derived once per process and cached: the quantile is a pure function of the
/// frozen parameter set, so re-walking the table per call would recompute an
/// answer that cannot change. Note what is *not* done — returning the
/// `ADOPTED_PROPAGATION_TIMEOUT_SECS` pin directly. The pin is a drift
/// guardrail, downstream of the derivation; shipping it as the value would put a
/// literal on the production path and demote the derivation to a test, which is
/// structurally the 39 s ghost this round removed. Deriving once costs one table
/// walk at first use and keeps the number downstream of its reason.
#[no_mangle]
pub extern "C" fn shekyl_dandelionpp_propagation_timeout_seconds() -> u64 {
    static TIMEOUT_SECS: OnceLock<u64> = OnceLock::new();
    *TIMEOUT_SECS.get_or_init(|| {
        u64::from(embargo_timer().judge_failed_after_secs(PROPAGATION_FALSE_FAIL_ONE_IN))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_relay_privacy::schedule::ADOPTED_PROPAGATION_TIMEOUT_SECS;

    #[test]
    fn embargo_boundary_hands_out_the_adopted_timer_not_the_inherited_39s() {
        // The wiring mistake this pins: reaching for `EmbargoTimer::inherited()`
        // (the 39 s ghost) instead of `adopted()` would compile, draw plausible
        // numbers, and silently reinstate F-1/F-2/F-3.
        let t = embargo_timer();
        assert_eq!(t.mean_secs(), 144, "the adopted exact-solve embargo");
        assert_ne!(
            t.mean_secs(),
            EmbargoTimer::inherited().mean_secs(),
            "must not be the inherited 39 s"
        );
        assert_eq!(
            t.distribution(),
            shekyl_relay_privacy::DelayFamily::Geometric,
            "memoryless — a Poisson here is F-2 reinstated"
        );
    }

    #[test]
    fn embargo_draws_match_the_adopted_distribution() {
        // What the boundary must preserve is the *distribution*, not a floor.
        // A memoryless geometric has support {0, 1, 2, ...}, so a 0 s draw is
        // legitimate and occurs at ~1/(mean_ticks+1) ≈ 0.17% — rare, and part
        // of the derived survival solve. Clamping it here would make shipped
        // behaviour diverge from the golden-vector-pinned table, which is the
        // exact class of defect §17 exists to remove; if a 0 draw were wrong it
        // would be wrong in the derivation, not at the seam.
        const N: u64 = 4096;
        let mut total = 0_u64;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..N {
            let s = shekyl_dandelionpp_embargo_draw_seconds();
            total += s;
            seen.insert(s);
        }
        let mean = total / N;
        // ~13 sigma of slack at this sample size: catches a wrong timer or a
        // collapsed RNG, never flakes on an honest one.
        assert!(
            (115..=175).contains(&mean),
            "draw mean {mean}s is not the adopted 144s distribution"
        );
        assert!(seen.len() > 1, "draws did not vary: {seen:?}");
    }

    #[test]
    fn propagation_timeout_boundary_hands_out_the_pinned_seconds() {
        // The wallet's failed-transfer wait is load-bearing (releases reserved
        // inputs). It must match the crate pin exactly — a "around 11 minutes"
        // bound would let the rate, table, or rounding drift the way F-1 did.
        assert_eq!(
            shekyl_dandelionpp_propagation_timeout_seconds(),
            u64::from(ADOPTED_PROPAGATION_TIMEOUT_SECS),
            "FFI timeout must equal ADOPTED_PROPAGATION_TIMEOUT_SECS ({ADOPTED_PROPAGATION_TIMEOUT_SECS})"
        );
        assert_eq!(
            embargo_timer().judge_failed_after_secs(PROPAGATION_FALSE_FAIL_ONE_IN),
            ADOPTED_PROPAGATION_TIMEOUT_SECS,
        );
    }

    // Note: the NIL-in-connection-list guard (read_ids) can't be unit-tested —
    // the debug_assert fires inside an `extern "C"` (nounwind) function under the
    // workspace's `panic = "abort"`, so it aborts rather than unwinds and
    // `#[should_panic]` can't catch it. The filter (`filter_map` dropping nil) is
    // correct by construction; valid-input behaviour is covered by the oracle.
}
