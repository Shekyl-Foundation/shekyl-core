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
//! `covert_sends_carry_the_slots_own_peer_at_its_own_index` /
//! `an_unbound_channel_emits_no_send_and_shifts_no_other` (the decision) and
//! `relay_zone_ffi`'s
//! `an_unbound_slots_due_ticks_cross_as_covert_unbind_at_its_index` (the
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
/// the next second boundary (`cryptonote::detail::embargo_deadline`). The
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

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_relay_privacy::schedule::ADOPTED_PROPAGATION_TIMEOUT_SECS;

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
