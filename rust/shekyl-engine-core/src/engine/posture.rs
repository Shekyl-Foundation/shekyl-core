// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Daemon-posture selection (2d-2 SP-T2, DQ-T2.3) — the **no-silent-③** invariant.
//!
//! The scan loop reaches its daemon in one of three postures
//! (`ARCHIVAL_BOND_2D2_SP_T2_FETCH.md` §5): ① a local node, ② your own remote
//! node over Tor, ③ a **third-party** daemon over Tor. ③ is **actively
//! discouraged** — it carries the §5 residual list (scan-pattern +
//! height-trajectory fingerprints, arrival-synchronized fetching, an averageable
//! timing residual). The mission-#1 property this module pins: **the system can
//! never *silently* land a user in ③.**
//!
//! That is enforced structurally, not by convention (§2b build invariant 3):
//! - [`Posture`] has **no `Default`** and no `From<Config>` that could *infer* a
//!   posture — a posture is only ever *named*, never defaulted-into. So ③ is
//!   unreachable without an explicit, informed decision at the choice site.
//! - [`select`] takes the operator's *optional* choice and a local-reachability
//!   result and returns a `Result`. The one dangerous case — **no choice made,
//!   and the local node is unreachable** — is an [`PostureError`], **not** a
//!   fallback value: the system *refuses* rather than "helpfully" degrading to a
//!   remote/third-party node so the wallet "still works."
//!
//! The [`select`] adversarial test asserts that refusal, so a future
//! convenience-fallback (the "the wallet shouldn't just break" reflex) **breaks
//! the test** — the tripwire that keeps "discouraged" real rather than
//! aspirational. Mapping a resolved [`Posture`] to a concrete `BlockSource`
//! (① → `DaemonBlockSource`, ②/③ → `PBlockSource`) is the later scan-loop wiring
//! slice, which owns the config source + the per-`P` connection plumbing; this
//! module is only the *decision*, which SP-5's wiring cannot invalidate.

/// A resolved daemon posture — the scan loop acts on exactly one.
///
/// **No `Default`** by design: a posture is chosen, never defaulted-into. Adding
/// a `Default` (or any inference of ③) would reintroduce the silent-③ path this
/// type exists to forbid.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)] // consumer is the scan-loop wiring slice; the invariant test ships now.
pub(crate) enum Posture {
    /// ① Your own node on this machine (loopback). The privacy default — nothing
    /// leaves the box.
    Local,
    /// ② Your own node on your own remote server, reached over `P`'s Tor circuit.
    OwnRemote { base_url: String },
    /// ③ A **third-party** daemon over Tor. **Discouraged** — reachable only by
    /// being *named* here (never inferred/defaulted). The choice site (config /
    /// UX) must surface the §5 residuals at the point of selection.
    ThirdParty { base_url: String },
}

/// Why a posture could not be resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum PostureError {
    /// No posture was chosen **and** the local node is unreachable. The system
    /// **refuses** here — it does not fall back to a remote/third-party daemon.
    /// A dead local node is an error the user sees, never a silent re-posture.
    NoChoiceAndLocalUnreachable,
}

/// Resolve the daemon posture from the operator's (optional) explicit choice and
/// whether the local node is reachable.
///
/// The **only** paths to a remote/third-party posture are an *explicit*
/// `Some(OwnRemote | ThirdParty)`. Absence of a choice defaults to the local
/// node **iff** it is reachable; if it is not, this **errors** rather than
/// degrading to a remote node — the no-silent-③ invariant. Do not add a
/// `(None, false) => Ok(remote…)` arm: that is the convenience-fallback the
/// adversarial test forbids.
#[allow(dead_code)]
pub(crate) fn select(
    choice: Option<Posture>,
    local_reachable: bool,
) -> Result<Posture, PostureError> {
    match (choice, local_reachable) {
        // An explicit choice is honored — including ③, which is an informed,
        // named decision (never inferred).
        (Some(posture), _) => Ok(posture),
        // No choice + a reachable local node → your own node (the default).
        (None, true) => Ok(Posture::Local),
        // No choice + an unreachable local node → REFUSE. Never a remote fallback.
        (None, false) => Err(PostureError::NoChoiceAndLocalUnreachable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absence_of_choice_plus_local_unreachable_refuses_never_degrades_to_remote() {
        // The mission-#1 no-silent-③ tripwire. If a future "helpful fallback"
        // makes this `Ok(OwnRemote | ThirdParty)` — the "the wallet shouldn't
        // just break" reflex — this assertion fails. Breaking IS correct here: a
        // user must never be silently scanned against a remote daemon they did
        // not choose.
        assert_eq!(
            select(None, false),
            Err(PostureError::NoChoiceAndLocalUnreachable),
        );
    }

    #[test]
    fn absence_of_choice_with_a_reachable_local_node_defaults_to_your_own_node() {
        assert_eq!(select(None, true), Ok(Posture::Local));
    }

    #[test]
    fn third_party_is_reachable_only_when_explicitly_named() {
        // ③ requires an explicit, named choice — it is never inferred. Honored
        // when named (an informed decision), and reachable no other way.
        let named = Posture::ThirdParty {
            base_url: "http://example.onion:18081".to_string(),
        };
        assert_eq!(select(Some(named.clone()), true), Ok(named));

        // Neither no-choice path can ever yield ③.
        assert_ne!(select(None, true), Ok(third_party()));
        assert!(select(None, false).is_err());
    }

    #[test]
    fn an_explicit_choice_overrides_local_reachability_both_ways() {
        // A named remote is honored even when local is up (the operator meant it);
        // a named local is honored even when the probe says unreachable (the
        // choice is authoritative — the fetch will surface a dead node as an
        // error, not a re-posture).
        let remote = Posture::OwnRemote {
            base_url: "http://example.onion:18081".to_string(),
        };
        assert_eq!(select(Some(remote.clone()), true), Ok(remote));
        assert_eq!(select(Some(Posture::Local), false), Ok(Posture::Local));
    }

    fn third_party() -> Posture {
        Posture::ThirdParty {
            base_url: "http://example.onion:18081".to_string(),
        }
    }
}
