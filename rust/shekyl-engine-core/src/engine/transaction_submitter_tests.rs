// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Submit-path tests: the transport-agnostic verdict → outcome →
//! error-class mapping regressions (`DAEMON_SUBMIT_VERDICT.md` §2.1 /
//! §2.5, exercised directly against `SubmitVerdict` values — no live
//! daemon), plus the per-`P` `PTransactionSubmitter`'s
//! ambiguous-failure + username-non-leak proof (SP-T4a).
use super::*;
use shekyl_rpc_client::PoolRelay;

/// Every identity-bearing verdict maps 1:1 and carries the locally
/// computed hash — never a daemon-supplied id.
#[test]
fn verdicts_map_structurally() {
    let hash = TxHash::from_bytes([7u8; 32]);
    assert_eq!(
        submit_outcome_from_verdict(&SubmitVerdict::Accepted, hash),
        TxSubmitOutcome::Submitted { hash }
    );
    for relay in [
        PoolRelay::Held,
        PoolRelay::HeldOverdue,
        PoolRelay::Published,
        PoolRelay::Untracked,
    ] {
        assert_eq!(
            submit_outcome_from_verdict(&SubmitVerdict::AlreadyInPool { relay }, hash),
            TxSubmitOutcome::AlreadyInPool { hash, relay },
            "the relay state passes through; the wallet does not judge it"
        );
    }
    assert_eq!(
        submit_outcome_from_verdict(&SubmitVerdict::AlreadyInChain { height: 42 }, hash),
        TxSubmitOutcome::AlreadyInChain { hash, height: 42 },
        "the F40 height passes through the projection untouched"
    );
    assert_eq!(
        submit_outcome_from_verdict(
            &SubmitVerdict::Rejected {
                cause: RejectCause::Malformed,
                row: None,
            },
            hash
        ),
        TxSubmitOutcome::Rejected {
            cause: RejectCause::Malformed,
            row: None,
        }
    );
}

/// All three identity-bearing outcomes resolve `Ok`, split by
/// lock-lifecycle disposition (§2.5): a fresh accept and a
/// pool-resident duplicate share the `Broadcast` **variant**
/// (network-exposed, F14 lock placed) and differ only in the
/// inform-only [`BroadcastKind`] the Engine surface projects; a
/// mined duplicate is the distinct `AlreadyInChain` (F40: lock
/// placed too, baselined at the carried `height`, which routes the
/// release path). All carry the locally computed hash.
#[test]
fn identity_outcomes_resolve_ok_split_by_disposition() {
    let hash = TxHash::from_bytes([9u8; 32]);
    assert_eq!(
        outcome_to_result(TxSubmitOutcome::Submitted { hash }).expect("identity outcome"),
        SubmitSuccess::Broadcast {
            hash,
            kind: BroadcastKind::Accepted,
        }
    );
    for relay in [
        PoolRelay::Held,
        PoolRelay::HeldOverdue,
        PoolRelay::Published,
        PoolRelay::Untracked,
    ] {
        assert_eq!(
            outcome_to_result(TxSubmitOutcome::AlreadyInPool { hash, relay })
                .expect("identity outcome"),
            SubmitSuccess::Broadcast {
                hash,
                kind: BroadcastKind::AlreadyInPool,
            },
            "pool-resident duplicate drops the relay state: {relay:?}"
        );
    }
    assert_eq!(
        outcome_to_result(TxSubmitOutcome::AlreadyInChain { hash, height: 77 })
            .expect("identity outcome"),
        SubmitSuccess::AlreadyInChain { hash, height: 77 }
    );
}

/// Terminal causes (release + rebuild recourse) map to
/// `DaemonRejectedTerminal` with the matching kind.
#[test]
fn terminal_causes_map_to_terminal_kinds() {
    for (cause, expected) in [
        (RejectCause::Malformed, TerminalErrorKind::Malformed),
        (RejectCause::FeeTooLow, TerminalErrorKind::FeeTooLow),
        (
            RejectCause::DoubleSpendConflict,
            TerminalErrorKind::DoubleSpend,
        ),
        (RejectCause::Unrecognized, TerminalErrorKind::Unrecognized),
    ] {
        let err = outcome_to_result(TxSubmitOutcome::Rejected { cause, row: None })
            .expect_err("terminal cause");
        assert!(
            matches!(err, SubmitterError::RejectedTerminal { kind } if kind == expected),
            "cause {cause:?} must map to terminal kind {expected:?}, got {err:?}"
        );
    }
}

/// Retryable causes (reservation preserved, resubmit after the
/// per-cause wait) map to `DaemonRejectedRetryable`.
#[test]
fn retryable_causes_map_to_retryable_class() {
    for (cause, expected) in [
        (RejectCause::StaleRoot, RetryableRejectCause::StaleRoot),
        (
            RejectCause::ReferenceTooRecent,
            RetryableRejectCause::ReferenceTooRecent,
        ),
        (
            RejectCause::ReferenceNotFound,
            RetryableRejectCause::ReferenceNotFound,
        ),
    ] {
        let err = outcome_to_result(TxSubmitOutcome::Rejected { cause, row: None })
            .expect_err("retryable cause");
        assert!(
            matches!(
                err,
                SubmitterError::RejectedRetryable { cause: got } if got == expected
            ),
            "cause {cause:?} must map to retryable {expected:?}, got {err:?}"
        );
    }
}

/// SP-T4a axis 4 + invariant (a): a broadcast whose **transport** fails
/// surfaces as [`SubmitterError::Ambiguous`] — we cannot know whether it
/// propagated, so it is *not* a retryable transient — and the error rendering
/// must never leak the SOCKS username. No Tor: a closed SOCKS port (`:1`)
/// refuses immediately, so the `spawn_blocking` bridge + error mapping run
/// fast. The tx bytes are a serialized synthetic coinbase — valid wire, so the
/// submitter reaches the transport rather than short-circuiting on the local
/// parse guard (which would return `Malformed`, a different arm).
#[tokio::test(flavor = "multi_thread")]
async fn broadcast_over_a_dead_proxy_is_a_username_free_ambiguous_error() {
    use shekyl_p_transport::TorSocksEndpoint;
    use shekyl_types::PCanonicalId;

    use crate::engine::test_support::make_synthetic_block;

    let mut tx_bytes = Vec::new();
    make_synthetic_block(0, shekyl_types::BlockHash::NULL)
        .block
        .miner_transaction
        .write(&mut tx_bytes)
        .expect("serialize synthetic coinbase to canonical wire");

    let persona = PCanonicalId::from_bytes([5u8; 32]);
    // A parallel client for the same persona: `derive_socks_user` is
    // deterministic, so its username equals the one the submitter's
    // internally-built transport carries.
    let username = PTorClient::for_persona(&persona, &TorSocksEndpoint::loopback(1))
        .expect("proxy config is well-formed")
        .username()
        .as_str()
        .to_owned();
    let submitter = PTransactionSubmitter::for_persona(
        persona,
        &TorSocksEndpoint::loopback(1),
        "http://127.0.0.1:18081".to_string(),
    )
    .expect("proxy config is well-formed");

    let err = submitter
        .submit(tx_bytes)
        .await
        .expect_err("a dead SOCKS proxy must fail the broadcast");
    assert!(
        matches!(err, SubmitterError::Ambiguous { .. }),
        "a broadcast transport failure is ambiguous (maybe-propagated), never a \
         retryable transient: expected Ambiguous, got {err:?}"
    );
    assert!(
        !format!("{err}").contains(&username),
        "invariant (a): a submit error must never render the SOCKS username"
    );
}

/// The local parse-guard: unparseable bytes are a build-path defect that
/// **never reaches the network** — `submit` short-circuits to
/// `RejectedTerminal { Malformed }` *before* any transport. This guards
/// the arm the dead-proxy test deliberately routes around (it feeds valid wire
/// to reach the transport). The dead SOCKS port (`:1`) is the tell: if a
/// refactor let the guard fall through to the network, the outcome would be
/// `Ambiguous`, not `Malformed` — so the assertion distinguishes
/// "guarded before the wire" from "reached it" (and a swap to the panicking
/// `canonical_tx_id` would panic here instead of returning).
#[tokio::test(flavor = "multi_thread")]
async fn broadcast_of_unparseable_bytes_is_a_local_malformed_never_reaching_the_network() {
    use shekyl_p_transport::TorSocksEndpoint;
    use shekyl_types::PCanonicalId;

    let submitter = PTransactionSubmitter::for_persona(
        PCanonicalId::from_bytes([3u8; 32]),
        &TorSocksEndpoint::loopback(1),
        "http://127.0.0.1:18081".to_string(),
    )
    .expect("proxy config is well-formed");

    let err = submitter
        .submit(b"not a canonical shekyl-wire transaction".to_vec())
        .await
        .expect_err("unparseable bytes must fail");
    assert!(
        matches!(
            err,
            SubmitterError::RejectedTerminal {
                kind: TerminalErrorKind::Malformed
            }
        ),
        "a build-path defect is a local Malformed terminal, never a transport \
         outcome (would be Ambiguous if the guard fell through): got {err:?}"
    );
}

// ── Posture→submitter dispatch (SP-T4a §3.1) ──

/// Canonical-wire tx bytes for dispatch tests: a serialized synthetic
/// coinbase, so the `DaemonTransactionSubmitter` debug hash-consistency
/// guard and the per-`P` parse guard are both satisfied.
fn wire_tx_bytes() -> Vec<u8> {
    use crate::engine::test_support::make_synthetic_block;

    let mut tx_bytes = Vec::new();
    make_synthetic_block(0, shekyl_types::BlockHash::NULL)
        .block
        .miner_transaction
        .write(&mut tx_bytes)
        .expect("serialize synthetic coinbase to canonical wire");
    tx_bytes
}

fn dead_proxy_socks() -> shekyl_p_transport::TorSocksEndpoint {
    // A closed SOCKS port (`:1`): loopback refuses immediately, so the ②
    // arm's transport path is exercised fast with no Tor and no timeout.
    shekyl_p_transport::TorSocksEndpoint::loopback(1)
}

/// The choke point's routing guard, both directions of the fence: a
/// `Local` posture resolves to the ① principal arm, and an `OwnRemote`
/// posture resolves to the ② per-`P` arm — **never** the principal
/// submitter (the first-seen-origin leak the dispatch closes). Fence by
/// enumeration: the match names every variant, no catch-all, so a new
/// arm cannot slip through unasserted.
#[tokio::test]
async fn choke_point_routes_each_posture_to_its_own_arm() {
    use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};

    let persona = PCanonicalId::from_bytes([11u8; 32]);
    let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));

    fn arm_name<D>(submitter: &BroadcastSubmitter<D>) -> &'static str {
        match submitter {
            BroadcastSubmitter::Local(_) => "local",
            BroadcastSubmitter::PerP(_) => "per-p",
        }
    }

    let local = BroadcastSubmitter::for_posture(
        BroadcastPosture::Local,
        persona,
        Arc::clone(&daemon),
        &dead_proxy_socks(),
    )
    .expect("① construction is infallible");
    assert_eq!(arm_name(&local), "local");

    let remote = BroadcastSubmitter::for_posture(
        BroadcastPosture::OwnRemote {
            base_url: "http://127.0.0.1:18081".to_string(),
        },
        persona,
        daemon,
        &dead_proxy_socks(),
    )
    .expect("proxy config is well-formed");
    assert_eq!(
        arm_name(&remote),
        "per-p",
        "②→PerP, never the principal submitter (§3.1 part 2 routing guard)"
    );
}

/// Match-delegation through the ① arm reaches the wrapped principal
/// submitter: a `P`-bound submit over the `Local` posture lands on the
/// wallet's own daemon (conceded observer) and resolves `Broadcast`,
/// with no pairing constraint on this arm by design.
#[tokio::test]
async fn local_arm_delegates_bound_bytes_to_the_principal_daemon() {
    use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};

    let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
    let submitter = BroadcastSubmitter::for_posture(
        BroadcastPosture::Local,
        PCanonicalId::from_bytes([13u8; 32]),
        Arc::clone(&daemon),
        &dead_proxy_socks(),
    )
    .expect("① construction is infallible");

    let bytes = wire_tx_bytes();
    let expected = canonical_tx_id(&bytes);
    let success = submitter
        .submit_bound(PBoundBytes::bind_for_test(
            PCanonicalId::from_bytes([14u8; 32]),
            bytes,
        ))
        .await
        .expect("loopback submit succeeds");
    assert_eq!(
        success,
        SubmitSuccess::Broadcast {
            hash: expected,
            kind: BroadcastKind::Accepted,
        }
    );
    assert_eq!(daemon.submitted_count(), 1);
}

/// The §3.1 part 4 pairing check on the ② arm: matched bytes pass the
/// choke point and reach `P`'s transport (the dead proxy proves the
/// delegation got that far — `Ambiguous`, not a pre-flight refusal).
#[tokio::test(flavor = "multi_thread")]
async fn per_p_arm_dispatches_matched_bytes_over_p_s_own_circuit() {
    use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};

    let persona = PCanonicalId::from_bytes([17u8; 32]);
    let submitter = BroadcastSubmitter::for_posture(
        BroadcastPosture::OwnRemote {
            base_url: "http://127.0.0.1:18081".to_string(),
        },
        persona,
        Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED)),
        &dead_proxy_socks(),
    )
    .expect("proxy config is well-formed");

    let err = submitter
        .submit_bound(PBoundBytes::bind_for_test(persona, wire_tx_bytes()))
        .await
        .expect_err("a dead SOCKS proxy must fail the broadcast");
    assert!(
        matches!(
            err,
            BroadcastSubmitError::Submit(SubmitterError::Ambiguous { .. })
        ),
        "matched pairing must delegate to the transport (whose dead proxy is \
         ambiguous), never be refused pre-flight: got {err:?}"
    );
}

/// The pairing check refuses a cross-persona dispatch **before any
/// transport** — the `validate_handle` discipline's loud half: in a
/// debug build the mismatch is a panic (the fail-closed
/// `PersonaMismatch` return is the release-build behavior of the same
/// guard). The dead proxy is the tell: if the check fell through to the
/// wire, the outcome would be an `Ambiguous` error, not this panic.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "submit_bound: bytes bound to")]
async fn per_p_arm_refuses_cross_persona_bytes_before_any_transport() {
    use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};

    let submitter = BroadcastSubmitter::for_posture(
        BroadcastPosture::OwnRemote {
            base_url: "http://127.0.0.1:18081".to_string(),
        },
        PCanonicalId::from_bytes([19u8; 32]),
        Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED)),
        &dead_proxy_socks(),
    )
    .expect("proxy config is well-formed");

    // A *different* persona's bytes: the §3.1 part 4 equality check must
    // fire (panic, in this debug build) before the transport is reached —
    // this `expect_err` is never evaluated.
    submitter
        .submit_bound(PBoundBytes::bind_for_test(
            PCanonicalId::from_bytes([23u8; 32]),
            wire_tx_bytes(),
        ))
        .await
        .expect_err("unreachable in a debug build: the pairing check panics first");
}
