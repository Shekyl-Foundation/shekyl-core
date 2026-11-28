// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Submit-path tests: the transport-agnostic verdict → outcome →
//! error-class mapping regressions (`DAEMON_SUBMIT_VERDICT.md` §2.1 /
//! §2.5, exercised directly against `Verdict` values — no live
//! daemon), and the wallet submitter's persona and durability checks.
use super::*;
use shekyl_engine_file::Durability;
use shekyl_rpc_client::Publication;

/// A test hand-off. The test names [`Durability::Confirmed`] because it
/// exercises the transport, not the seal.
fn confirmed_for_test(bound: PBoundBytes) -> BoundForSend {
    BoundForSend::Fresh(bound, Durability::Confirmed)
}

/// Every identity-bearing verdict maps 1:1 and carries the locally
/// computed hash — never a daemon-supplied id.
#[test]
fn verdicts_map_structurally() {
    let hash = TxHash::from_bytes([7u8; 32]);
    assert_eq!(
        submit_outcome_from_verdict(&Verdict::Accepted, hash),
        TxSubmitOutcome::Submitted { hash }
    );
    for relay in [
        Publication::Held,
        Publication::Overdue,
        Publication::Public,
        Publication::Untracked,
    ] {
        assert_eq!(
            submit_outcome_from_verdict(&Verdict::AlreadyInPool { publication: relay }, hash),
            TxSubmitOutcome::AlreadyInPool { hash, relay },
            "the relay state passes through; the wallet does not judge it"
        );
    }
    assert_eq!(
        submit_outcome_from_verdict(
            &Verdict::AlreadyInChain {
                mined_height: shekyl_rpc_types::kinds::Height(42)
            },
            hash
        ),
        TxSubmitOutcome::AlreadyInChain { hash, height: 42 },
        "the F40 height passes through the projection untouched"
    );
    assert_eq!(
        submit_outcome_from_verdict(
            &Verdict::Rejected {
                cause: Rejection::Malformed,
            },
            hash
        ),
        TxSubmitOutcome::Rejected {
            cause: Rejection::Malformed,
        }
    );
}

/// **The consensus row rides inside its cause** (IG-Q76): a
/// `consensus-rule` refusal names the row, and the wallet carries it to the
/// terminal kind whole. A row this wallet cannot carry whole is the
/// fail-safe `Unrecognized`, never a truncated name.
///
/// The edit that turns this red is `submitter_error_from_cause` ignoring the
/// cause's payload.
#[test]
fn a_consensus_refusal_carries_its_row() {
    let hash = TxHash::from_bytes([3u8; 32]);
    let refused = |row: &str| {
        let verdict = Verdict::Rejected {
            cause: Rejection::ConsensusRule(shekyl_rpc_types::kinds::Text(row.to_owned())),
        };
        outcome_to_result(submit_outcome_from_verdict(&verdict, hash)).expect_err("a refusal")
    };
    assert!(
        matches!(
            refused("CEN-J15"),
            SubmitterError::RejectedTerminal {
                kind: TerminalErrorKind::ConsensusRule { row }
            } if row.as_str() == "CEN-J15"
        ),
        "the row reaches the terminal kind"
    );
    assert!(matches!(
        refused("CEN-A-NAME-LONGER-THAN-SIXTEEN"),
        SubmitterError::RejectedTerminal {
            kind: TerminalErrorKind::Unrecognized
        }
    ));
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
        Publication::Held,
        Publication::Overdue,
        Publication::Public,
        Publication::Untracked,
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
        (Rejection::Malformed, TerminalErrorKind::Malformed),
        (Rejection::FeeTooLow, TerminalErrorKind::FeeTooLow),
        (
            Rejection::DoubleSpendConflict,
            TerminalErrorKind::DoubleSpend,
        ),
        (Rejection::Unrecognized, TerminalErrorKind::Unrecognized),
    ] {
        let err = outcome_to_result(TxSubmitOutcome::Rejected {
            cause: cause.clone(),
        })
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
        (Rejection::StaleRoot, RetryableRejectCause::StaleRoot),
        (
            Rejection::ReferenceTooRecent,
            RetryableRejectCause::ReferenceTooRecent,
        ),
        (
            Rejection::ReferenceUnknown,
            RetryableRejectCause::ReferenceNotFound,
        ),
    ] {
        let err = outcome_to_result(TxSubmitOutcome::Rejected {
            cause: cause.clone(),
        })
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

#[tokio::test]
async fn local_arm_delegates_bound_bytes_to_the_principal_daemon() {
    use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};

    let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
    let submitter =
        BroadcastSubmitter::for_wallet(PCanonicalId::from_bytes([14; 32]), Arc::clone(&daemon));

    let bytes = wire_tx_bytes();
    let expected = canonical_tx_id(&bytes);
    let success = submitter
        .submit_bound(confirmed_for_test(PBoundBytes::bind_for_test(
            PCanonicalId::from_bytes([14u8; 32]),
            bytes,
        )))
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

#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "submit_bound: bytes bound to")
)]
async fn wallet_refuses_cross_persona_bytes_before_any_transport() {
    use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};

    let (submitter_persona, bytes_persona) = (
        PCanonicalId::from_bytes([19u8; 32]),
        PCanonicalId::from_bytes([23u8; 32]),
    );
    let submitter = BroadcastSubmitter::for_wallet(
        submitter_persona,
        Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED)),
    );

    // A *different* persona's bytes: the §3.1 part 4 equality check must
    // fire before the transport is reached: a panic in a debug build, the
    // fail-closed refusal in a release build.
    let err = submitter
        .submit_bound(confirmed_for_test(PBoundBytes::bind_for_test(
            bytes_persona,
            wire_tx_bytes(),
        )))
        .await
        .expect_err("the pairing check refuses before any transport");
    assert!(
        matches!(
            err,
            BroadcastSubmitError::PersonaMismatch { bytes_persona: bytes, submitter_persona: submitter }
                if bytes == bytes_persona && submitter == submitter_persona
        ),
        "release refuses fail-closed, naming both personas: got {err:?}"
    );
}
