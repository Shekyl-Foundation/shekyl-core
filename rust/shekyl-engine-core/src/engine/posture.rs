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
//!   and the local node is unreachable** — is a [`PostureError`], **not** a
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
//!
//! ## Two postures, deliberately different types (SP-T4a)
//!
//! This module also carries the **broadcast** posture ([`BroadcastPosture`] /
//! [`select_broadcast`]), and it is a *narrower* type than the fetch [`Posture`]
//! **on purpose**: it has **no `ThirdParty` variant at all**. Fetch-③ is
//! allowed-with-disclosure — a *continuous, statistical, unavoidable* leak (you
//! cannot not-scan; a third-party daemon learns only the shape of your scanning).
//! Broadcast-③ is forbidden — a *discrete, categorical, avoidable* first-seen-
//! origin leak (one broadcast hands the first-receiving daemon a permanent,
//! on-chain-anchored origin fact about a `P`-bound artifact). The allow/forbid
//! line tracks continuous-statistical-unavoidable vs. discrete-categorical-
//! avoidable, and the asymmetry is encoded in the **types** so a "unify the two
//! selectors for symmetry" refactor cannot silently re-enable broadcast-③
//! (`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md` §2 axis 3 / §3 invariant B).

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

// ============================================================================
// Broadcast posture (SP-T4a) — the write side, a *narrower* type by design.
// ============================================================================

/// A resolved **broadcast** posture — where `P` submits a signed transaction.
///
/// **Deliberately a narrower type than the fetch [`Posture`]: no `ThirdParty`
/// variant at all** (SP-T4a; `ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md` §2 axis 3 /
/// §3 invariant B). Broadcast-③ would hand the first-receiving daemon a
/// permanent, on-chain-anchored **first-seen-origin** fact about a `P`-bound
/// artifact (the bond vin) — a discrete, categorical leak that defeats the
/// unlinkability property directly, where fetch-③ only erodes it statistically.
/// A broadcast is rare, so the convenience of going through a stranger is worth
/// almost nothing; security-over-features (`00-mission` #1) forbids it. Encoding
/// the forbid in the **type** means a symmetry refactor cannot silently re-enable
/// broadcast-③ — it would have to *add the variant back*, visibly.
///
/// **No `Default`**, same as [`Posture`]: a posture is chosen, never
/// defaulted-into.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)] // consumer is the broadcast-wiring slice; the invariant tests ship now.
pub(crate) enum BroadcastPosture {
    /// ① Your own node on this machine (loopback). The privacy default — the
    /// broadcast originates on your own box, so no stranger sees it first.
    Local,
    /// ② Your own node on your own remote server, reached over `P`'s Tor circuit.
    ///
    /// **Trust-on-user-assertion — the wallet cannot verify node ownership.** An
    /// onion address carries no proof that it is *yours*, and "is this `base_url`
    /// my own node" is not a type-checkable property. So the forbid on ③ closes
    /// the *system-selected* third-party path structurally, but it **cannot** stop
    /// a user from putting a *third party's* onion here (by mistake, or for
    /// convenience) — which reopens the exact first-seen-origin leak. The choice
    /// site (config / UX) MUST therefore disclose at the point of entry: *this
    /// must be a node you control; pointing it at a third party defeats the
    /// broadcast firewall — first-seen-origin is a permanent, categorical link.*
    ///
    /// **rule-21 reopen.** *Reopening criteria* (observable, substrate-anchored):
    /// a field report of an `OwnRemote` pointed at a third party (a mislabel
    /// incident); OR a testnet/audit measurement that the mislabel rate under the
    /// config-point disclosure exceeds threshold; OR the clearnet-`OwnRemote`
    /// residual (a clearnet `base_url` exits Tor at an exit relay — see the
    /// `DaemonUrl` obligation) surfacing in a privacy audit. *Re-evaluation shape*:
    /// a design round on the config/UX slice (2c owns the config source) decides
    /// whether to add an **authenticated** `OwnRemote` — a client-auth onion /
    /// proof-of-ownership makes "my own node" type-checkable and closes this
    /// structurally. Until a listed trigger fires, the disclosure is the accepted
    /// mitigation; the authenticated path is out of scope now, named so a future
    /// maintainer can tell whether the criteria are met without re-deriving this
    /// reasoning. (Tracked in `FOLLOWUPS.md`.)
    OwnRemote { base_url: String },
}

/// Why a broadcast posture could not be resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum BroadcastPostureError {
    /// No posture was chosen **and** the local node is unreachable. The system
    /// **refuses** — it never falls back to a remote node the user did not name,
    /// and can never fall back to a third party (the type has no such variant).
    NoChoiceAndLocalUnreachable,
}

/// Resolve the **broadcast** posture from the operator's (optional) explicit
/// choice and whether the local node is reachable.
///
/// Same refusal discipline as [`select`] — no choice + unreachable local →
/// error, never a silent remote — and structurally stronger on ③: the choice
/// type ([`BroadcastPosture`]) *cannot represent* a third party, so there is no
/// ③ arm to write and no ③ a caller could name.
#[allow(dead_code)]
pub(crate) fn select_broadcast(
    choice: Option<BroadcastPosture>,
    local_reachable: bool,
) -> Result<BroadcastPosture, BroadcastPostureError> {
    match (choice, local_reachable) {
        // An explicit choice is honored (only ① or ② are representable).
        (Some(posture), _) => Ok(posture),
        // No choice + a reachable local node → your own node (the default).
        (None, true) => Ok(BroadcastPosture::Local),
        // No choice + an unreachable local node → REFUSE. Never a remote fallback.
        (None, false) => Err(BroadcastPostureError::NoChoiceAndLocalUnreachable),
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

    // ── Broadcast posture (SP-T4a) ──

    #[test]
    fn broadcast_absence_of_choice_plus_local_unreachable_refuses() {
        // Same no-silent-remote refusal as fetch; a dead local node is an error the
        // user sees, never a silent re-posture — and never to a third party, which
        // the type cannot even represent.
        assert_eq!(
            select_broadcast(None, false),
            Err(BroadcastPostureError::NoChoiceAndLocalUnreachable),
        );
    }

    #[test]
    fn broadcast_absence_of_choice_with_reachable_local_defaults_to_own_node() {
        assert_eq!(select_broadcast(None, true), Ok(BroadcastPosture::Local));
    }

    #[test]
    fn broadcast_named_own_remote_is_honored_both_ways() {
        // A named remote is honored even when local is up; a named local is honored
        // even when the probe says unreachable (the choice is authoritative — a
        // dead node surfaces as an error, not a re-posture).
        let remote = BroadcastPosture::OwnRemote {
            base_url: "http://example.onion:18081".to_string(),
        };
        assert_eq!(select_broadcast(Some(remote.clone()), true), Ok(remote));
        assert_eq!(
            select_broadcast(Some(BroadcastPosture::Local), false),
            Ok(BroadcastPosture::Local)
        );
    }

    #[test]
    fn broadcast_posture_has_no_third_party_variant() {
        // The forbid, as a compile-fence: this exhaustive match names EVERY
        // `BroadcastPosture` variant. Adding a `ThirdParty` (the "unify the two
        // selectors for symmetry" reflex) makes it non-exhaustive → a compile error
        // that forces the change to confront the first-seen-origin leak, never a
        // silent re-enable of broadcast-③. Fence by *enumeration* (distinct arm
        // bodies, no `_ =>` catch-all) so a new variant cannot slip through.
        fn variant_name(p: &BroadcastPosture) -> &'static str {
            match p {
                BroadcastPosture::Local => "local",
                // NO `ThirdParty` arm — the variant does not exist. Do not add one.
                BroadcastPosture::OwnRemote { .. } => "own-remote",
            }
        }
        assert_eq!(variant_name(&BroadcastPosture::Local), "local");
        assert_eq!(
            variant_name(&BroadcastPosture::OwnRemote {
                base_url: "http://example.onion:18081".to_string(),
            }),
            "own-remote"
        );
    }
}
