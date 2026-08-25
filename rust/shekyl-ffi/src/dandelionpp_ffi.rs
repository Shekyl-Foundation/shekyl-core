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
//! The three §16.1 seam contracts went with them: `update`'s re-arm predicate
//! died with the slot-push seam (post-§20.3 nothing re-points on a push —
//! `StemMap::update` still returns `StemSetChange` for its own tests, but the
//! zone no longer surfaces it), `clone` died with the handle that could be
//! shallow-copied, and **index order with nils in position** survived as a
//! pushed-array contract through RP-3a before §20.3 retired the array itself.
//! The binding now travels with each covert send, and a slot going unbound
//! crosses as its own per-channel decision. Witnesses live in `shekyl-relay`'s
//! `noise_sends_carry_the_slots_own_peer_at_its_own_index` /
//! `an_unbound_channel_emits_no_send_and_shifts_no_other` (the decision) and
//! `relay_zone_ffi`'s
//! `an_unbound_slots_due_ticks_cross_as_noise_unbind_at_its_index` (the
//! marshalling, including peer bytes).

use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::{EmbargoTimer, PROPAGATION_FALSE_FAIL_ONE_IN};
use shekyl_relay_privacy::RelayZone;
use std::sync::OnceLock;

use crate::secure_relay_rng::SecureRelayRng;

// --- the embargo timer (RP-4, §17) --------------------------------------------

/// The adopted embargo timers — **one per relay zone**, built once per process.
///
/// Unlike the stem map there is no handle: the embargo distribution is
/// node-local **policy** (not consensus), fixed for a given parameter set rather
/// than per-connection state. Each table is immutable once built and its
/// construction is a pure recurrence over frozen parameters, so a process-wide
/// array is the whole of the state this boundary needs.
///
/// It became an array rather than a single timer at §89.2. That is the only
/// structural change: the *distribution* is still policy, still frozen, and
/// still has no per-connection component — what varies is which frozen
/// parameter set applies, and the zone selects it.
///
/// One entry per *parameter class*, not per zone. Only `time_between_hop_ms`
/// varies and it takes two values, so a per-zone array would build and hold
/// three byte-identical ~443 KB anonymity tables for the life of the process.
/// [`DandelionParams::adopted_class`] owns the partition, so this cannot fall
/// out of step with the parameters it is caching.
static EMBARGO: OnceLock<[EmbargoTimer; DandelionParams::ADOPTED_CLASSES]> = OnceLock::new();

/// The embargo timer for one relay zone.
///
/// **One timer per zone since §89.2**, not one per process. `hop` is
/// transport-bound (§63.2's keeper) and §59's coherence keeps a stemming
/// transaction on the transport it entered, so the quantity is well-defined per
/// zone — and a single global would either under-provision the anonymity path
/// or charge clearnet a wait sized for a rendezvous it never touches.
///
/// Indexed by [`DandelionParams::adopted_class`], which is total over
/// `RelayZone` — every byte the boundary can decode selects a built timer.
fn embargo_timer(zone: RelayZone) -> &'static EmbargoTimer {
    // `adopted_for` rather than `inherited()`: the hop input carries the spec
    // machine's measured provenance (§80/§85.3) instead of the 2019-laptop
    // comment, now per zone. Clearnet is value-identical to before — the 190 s
    // pin below is unchanged — so clearnet sees a provenance cutover and
    // nothing else.
    let timers = EMBARGO.get_or_init(|| {
        DandelionParams::CLASS_REPRESENTATIVES
            .map(|class| EmbargoTimer::adopted(&DandelionParams::adopted_for(class)))
    });
    &timers[DandelionParams::adopted_class(zone)]
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
/// survival solve — **190 s**, memoryless (144 s before F-7 corrected the
/// `fluff_return_ms` input; §44) — and its table, not a
/// platform-defined `std::poisson_distribution`, *is* the distribution.
///
/// Seconds because the caller stores a whole-second `time_t` deadline. The
/// conversion rounds **up**: under-provisioning the embargo fluffs prematurely,
/// which is the privacy-losing direction (the D-5 asymmetry), so a truncation
/// that shaved up to 999 ms off every draw would err the wrong way.
///
/// **A 0 s draw is legitimate and intended.** A memoryless geometric has support
/// `{0, 1, 2, ...}`, so ~`1/(mean_ticks+1)` ≈ 0.13 % of draws are zero — the
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
/// the next second boundary (`cryptonote::detail::relay_deadline`). The
/// deadline is never earlier than `now + draw`, uniformly and including at zero.
/// Rounding a zero draw *down* instead would place the deadline up to ~999 ms in
/// the past, which is under-provisioning by the same asymmetry this boundary
/// rounds up to avoid — a shorter embargo is the privacy-losing direction, and
/// that does not stop being true because the draw was small.
///
/// # The `zone` argument (§89.2)
///
/// `zone` is `epee::net_utils::zone` as a byte — the network the transaction is
/// being embargoed *on*. Since §89 ruled that the anonymity zone stems, that is
/// no longer always clearnet. Callers pass `static_cast<uint8_t>(zone_->nzone)`.
///
/// **Anything outside `0..=3` resolves to `zone::invalid`, which is provisioned
/// as the worst case** — see [`RelayZone::from_ffi_u8`]. A miscast or corrupt
/// byte therefore costs black-hole recovery latency rather than embargo length;
/// the alternative (masking) would decode `5` to clearnet and silently draw the
/// shortest embargo.
#[no_mangle]
pub extern "C" fn shekyl_dandelionpp_embargo_draw_seconds(zone: u8) -> u64 {
    let mut rng = SecureRelayRng;
    embargo_timer(RelayZone::from_ffi_u8(zone))
        .deadline(0, &mut rng)
        .div_ceil(1_000)
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
/// corrected mean would have preserved that defect exactly.
/// Derived once per process and cached: the quantile is a pure function of the
/// frozen parameter set, so re-walking the table per call would recompute an
/// answer that cannot change. Note what is *not* done — returning the
/// `ADOPTED_PROPAGATION_TIMEOUT_SECS` pin directly. The pin is a drift
/// guardrail, downstream of the derivation; shipping it as the value would put a
/// literal on the production path and demote the derivation to a test, which is
/// structurally the 39 s ghost this round removed. Deriving once costs one table
/// walk at first use and keeps the number downstream of its reason.
///
/// # No zone parameter, though the embargo draw has one (§89.6)
///
/// **This whole export is a deletion target.** A wallet safety invariant — do
/// not un-reserve inputs while a spend might still land — should not be a
/// function of a relay-privacy constant, and the wallet has no way to verify
/// the relay timing of the daemon it is actually connected to. Giving it a zone
/// would ship a relay fact across the boundary so the wallet could re-derive a
/// daemon-side number: better synchronisation of a duplicate that should not
/// exist. The replacement is the wallet asking whether a transaction is still
/// in flight; §89.6 records it.
///
/// So this returns the **worst zone's** wait. That needs no machinery, which is
/// what makes it the cheapest thing to remove.
#[no_mangle]
pub extern "C" fn shekyl_dandelionpp_propagation_timeout_seconds() -> u64 {
    static TIMEOUT_SECS: OnceLock<u64> = OnceLock::new();
    *TIMEOUT_SECS.get_or_init(|| {
        u64::from(
            embargo_timer(RelayZone::Tor).judge_failed_after_secs(PROPAGATION_FALSE_FAIL_ONE_IN),
        )
    })
}

/// How long an **origin** waits before re-broadcasting its own still-unseen
/// transaction — **seconds**, per zone.
///
/// The pool's inherited re-broadcast loop escalates: this value is the base
/// wait, and each subsequent gap is the entry's age rounded to it, capped at
/// `MAX_RELAY_TIME`. This replaces `MIN_RELAY_TIME` as the **base** of that
/// escalation for a `relay_method::local` entry that has already been **sent**;
/// the shape of the escalation is unchanged, because repeated failure is a
/// reason to back off and inventing a second schedule shape is not what the
/// defect asks for.
///
/// An unsent `local` entry is not a caller. It exists because the engine's
/// fire-and-forget submit nudge may have missed, and this loop is its named
/// fallback — no stem was launched, so there is no completion to wait on and
/// the derived interval would be latency bought with nothing. The pool keeps
/// `MIN_RELAY_TIME` there; see `local_relay_base` in `tx_pool.cpp`.
///
/// # The quantile is derived, not chosen
///
/// [`shekyl_relay_privacy::params::origin_retry_one_in`] is
/// `1 / (1 - EMBARGO_FULL_TRAVEL_PROBABILITY)`: the
/// origin asks *"has my stem probably completed?"* at the confidence the
/// network already uses to answer it. On the adopted anonymity timer that is
/// the 1-in-10 survival quantile, **1148 s**, against a 346 s median — so the
/// retry no longer fires while most embargoes along its own stem are running,
/// which the shipped 300 s did.
///
/// # It provisions against an unobservable, and that is the honest framing
///
/// The case this retry rescues is a swallow at hop 1: the first stem peer
/// drops the transaction, no other node holds it, and **no embargo exists
/// anywhere to fire**. So there is no signal to wait for, and this number is a
/// bet on a distribution rather than a response to an event. That is what a
/// re-broadcast disarm predicate would fix (§92.5c item 1, not built) — until
/// it exists, this interval is doing both jobs: when to retry, and, by its
/// escalation, how long to keep trying.
///
/// # Zone argument
///
/// `zone` is `epee::net_utils::zone` as a byte, as elsewhere in this module.
/// A surviving `local` record **is** an anonymity origin — `originated_stays_
/// in_zone` moves a clearnet origin to `Stem` — and originated traffic carries
/// `origin_zone == invalid` because it did not arrive over anything. `invalid`
/// resolves to the anonymity parameter class (it is not clearnet), which is
/// the correct answer here and the fail-safe one: the longer wait.
/// # Cost
///
/// Cached per parameter class, like the timers themselves: the relay loop asks
/// once per `local` entry per pass, and the answer is a pure function of the
/// shipped parameters. Computing a survival quantile per entry per pass would
/// be work the pool lock is holding for no new information.
#[no_mangle]
pub extern "C" fn shekyl_dandelionpp_origin_retry_interval_seconds(zone: u8) -> u64 {
    static RETRY_SECS: OnceLock<[u64; DandelionParams::ADOPTED_CLASSES]> = OnceLock::new();
    let by_class = RETRY_SECS.get_or_init(|| {
        DandelionParams::CLASS_REPRESENTATIVES.map(|class| {
            u64::from(
                embargo_timer(class)
                    .judge_failed_after_secs(shekyl_relay_privacy::params::origin_retry_one_in()),
            )
        })
    });
    by_class[DandelionParams::adopted_class(RelayZone::from_ffi_u8(zone))]
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_relay_privacy::params::{origin_retry_one_in, EMBARGO_FULL_TRAVEL_PROBABILITY};
    use shekyl_relay_privacy::schedule::ADOPTED_PROPAGATION_TIMEOUT_SECS;

    /// The rate must be the reciprocal of alpha's residual, exactly.
    ///
    /// What edit reds this: move `EMBARGO_FULL_TRAVEL_PROBABILITY` to a value
    /// that is not `1 - 1/N` (0.93, say). The retry would then round to a rate
    /// that asks a different question than the network does, and the point of
    /// deriving it was that the two cannot drift apart.
    #[test]
    fn origin_retry_rate_is_the_reciprocal_of_alpha() {
        let one_in = origin_retry_one_in();
        assert_eq!(one_in, 10, "alpha = 0.90 gives a 1-in-10 residual");
        #[allow(clippy::cast_precision_loss)]
        let round_trip = 1.0 - 1.0 / one_in as f64;
        assert!(
            (round_trip - EMBARGO_FULL_TRAVEL_PROBABILITY).abs() < 1e-12,
            "alpha {EMBARGO_FULL_TRAVEL_PROBABILITY} is not expressible as an integer \
             1-in-N rate; the retry would ask a different question than the network"
        );
    }

    /// The defect this constant exists to fix, asserted rather than described.
    ///
    /// What edit reds it: revert the C++ caller to `MIN_RELAY_TIME`, or move
    /// the quantile below the median.
    #[test]
    fn the_origin_retry_clears_the_anonymity_embargo_median() {
        let anon = shekyl_dandelionpp_origin_retry_interval_seconds(RelayZone::Tor.as_u8());
        let median = u64::from(embargo_timer(RelayZone::Tor).judge_failed_after_secs(2));
        assert!(
            anon > median,
            "an origin must not re-emit inside its own zone's embargo median: \
             interval {anon} s against median {median} s"
        );
        assert_eq!(
            anon, 1_148,
            "the 1-in-10 quantile of the adopted anonymity timer"
        );
        assert!(
            anon > 300,
            "MIN_RELAY_TIME (300 s) is the value this replaces and is below the median"
        );
    }

    /// The exported interval is the divisor of the pool's rounding grid, so
    /// zero would be a SIGFPE in the relay loop, under the pool lock.
    ///
    /// A C++ runtime guard could not be the instrument here: the value has no
    /// runtime inputs — it is a pure function of shipped constants, solved
    /// once and cached — so a `base == 0` branch could never fire and would be
    /// decorative by rule 50's test. The regression it would be guarding
    /// against is a *source* change, which this catches at build time and
    /// loudly, instead of silently substituting a different retry policy in a
    /// running daemon.
    ///
    /// The bound is the pool's own `MIN_RELAY_TIME` rather than zero, because
    /// that is the real invariant: this constant exists because 300 s was too
    /// EAGER for an origin, so a parameter change that pushed any class below
    /// 300 s would re-create the defect in the direction the PR fixed. Zero-
    /// safety falls out of it.
    ///
    /// What edit reds it: lower `EMBARGO_FULL_TRAVEL_PROBABILITY` far enough
    /// that the quantile drops under the floor, or shrink an embargo timer.
    #[test]
    fn every_parameter_class_clears_the_pool_floor() {
        // `MIN_RELAY_TIME`, `src/cryptonote_core/tx_pool.cpp` — quoted here
        // rather than shared, because a cross-language tripwire is the only
        // job this literal has.
        const POOL_MIN_RELAY_TIME_SECS: u64 = 300;
        for zone in DandelionParams::CLASS_REPRESENTATIVES {
            let secs = shekyl_dandelionpp_origin_retry_interval_seconds(zone.as_u8());
            assert!(
                secs > POOL_MIN_RELAY_TIME_SECS,
                "{zone:?}: {secs} s is at or below the pool floor                  ({POOL_MIN_RELAY_TIME_SECS} s) this constant exists to raise;                  at 0 it would divide by zero in get_relay_delay"
            );
        }
    }

    /// `invalid` — what an originated entry actually carries — must resolve to
    /// the anonymity wait, not the clearnet one.
    #[test]
    fn an_unknown_origin_zone_gets_the_longer_wait() {
        let invalid = shekyl_dandelionpp_origin_retry_interval_seconds(RelayZone::Invalid.as_u8());
        let anon = shekyl_dandelionpp_origin_retry_interval_seconds(RelayZone::Tor.as_u8());
        let clear = shekyl_dandelionpp_origin_retry_interval_seconds(RelayZone::Public.as_u8());
        assert_eq!(
            invalid, anon,
            "origin-unknown provisions at the anonymity class"
        );
        assert!(
            anon > clear,
            "the anonymity wait must exceed the clearnet one"
        );
    }

    #[test]
    fn embargo_boundary_hands_out_the_adopted_timer_not_the_inherited_39s() {
        // The wiring mistake this pins: reaching for `EmbargoTimer::inherited()`
        // (the 39 s ghost) instead of `adopted()` would compile, draw plausible
        // numbers, and silently reinstate F-1/F-2/F-3.
        let t = embargo_timer(RelayZone::Public);
        assert_eq!(
            t.mean_secs(),
            190,
            "the adopted exact-solve embargo at the F-7-corrected fluff_return_ms \
             (was 144 s when F was measured under the wrong fluff rule)"
        );
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
    fn the_boundary_hands_out_a_different_timer_per_zone() {
        // The §89.2 wiring mistake this pins: selecting the clearnet timer for
        // every zone would compile, draw plausible numbers, and silently
        // under-provision the anonymity path — the privacy-losing direction,
        // and invisible because 190 s is a perfectly reasonable-looking answer.
        let clearnet = embargo_timer(RelayZone::Public).mean_secs();
        assert_eq!(clearnet, 190);
        for zone in [RelayZone::Tor, RelayZone::I2p, RelayZone::Invalid] {
            let anon = embargo_timer(zone).mean_secs();
            assert_eq!(
                anon, 499,
                "{zone:?} must draw the anonymity embargo derived from the \
                 interim rendezvous hop"
            );
            assert!(
                anon > clearnet,
                "{zone:?} embargo ({anon}s) must exceed clearnet's ({clearnet}s)"
            );
        }
    }

    #[test]
    fn an_out_of_domain_zone_byte_draws_the_longer_embargo() {
        // Masking would send 5 to Public. The boundary must not let a corrupt
        // byte buy the shortest embargo.
        for raw in [4_u8, 5, 6, 200, 255] {
            assert_eq!(
                embargo_timer(RelayZone::from_ffi_u8(raw)).mean_secs(),
                embargo_timer(RelayZone::Tor).mean_secs(),
                "raw zone byte {raw} must be provisioned as the worst case"
            );
        }
    }

    #[test]
    fn embargo_draws_match_the_adopted_distribution() {
        // What the boundary must preserve is the *distribution*, not a floor.
        // A memoryless geometric has support {0, 1, 2, ...}, so a 0 s draw is
        // legitimate and occurs at ~1/(mean_ticks+1) ≈ 0.13% — rare, and part
        // of the derived survival solve. Clamping it here would make shipped
        // behaviour diverge from the golden-vector-pinned table, which is the
        // exact class of defect §17 exists to remove; if a 0 draw were wrong it
        // would be wrong in the derivation, not at the seam.
        const N: u64 = 4096;
        let mut total = 0_u64;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..N {
            let s = shekyl_dandelionpp_embargo_draw_seconds(RelayZone::Public.as_u8());
            total += s;
            seen.insert(s);
        }
        let mean = total / N;
        // ~13 sigma of slack at this sample size: catches a wrong timer or a
        // collapsed RNG, never flakes on an honest one. Band re-centred on the
        // F-7-corrected mean of 190 s (was 144 s), same relative slack — the
        // band is a wrong-timer detector, not a second pin on the value, which
        // `mean_secs()` above already holds exactly.
        assert!(
            (152..=231).contains(&mean),
            "draw mean {mean}s is not the adopted distribution"
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

        // Worst-zone, not clearnet: the wallet cannot know which zone its
        // transaction took, so the one wait it gets must clear them all.
        // Under-waiting un-reserves the inputs of a live transaction (§89.6).
        for zone in [RelayZone::Public, RelayZone::I2p, RelayZone::Tor] {
            assert!(
                shekyl_dandelionpp_propagation_timeout_seconds()
                    >= u64::from(
                        embargo_timer(zone).judge_failed_after_secs(PROPAGATION_FALSE_FAIL_ONE_IN)
                    ),
                "{zone:?}'s embargo outlasts the single shipped wait"
            );
        }
    }

    // Note: the NIL-in-connection-list guard (read_ids) can't be unit-tested —
    // the debug_assert fires inside an `extern "C"` (nounwind) function under the
    // workspace's `panic = "abort"`, so it aborts rather than unwinds and
    // `#[should_panic]` can't catch it. The filter (`filter_map` dropping nil) is
    // correct by construction; valid-input behaviour is covered by the oracle.
}
