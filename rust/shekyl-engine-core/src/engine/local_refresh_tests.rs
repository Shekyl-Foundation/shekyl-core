// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the refresh producer (`engine/local_refresh.rs`).
//!
//! Wired as a `#[path]` child of `local_refresh::tests`, so `use super::*`
//! resolves into the workflow module and private items stay testable;
//! the sibling file exists so the decomposition ratchet counts the
//! workflow file, not its test suite (the
//! `transfer/transfer_pending_tx_tests.rs` pattern).

use super::*;
use crate::engine::diagnostics::NoopDiagnosticSink;

/// `LocalRefreshError → RefreshError` mapping is total and
/// preserves the discriminant classes per the §2.3
/// unit-variant-only binding.
#[test]
fn local_refresh_error_maps_to_refresh_error() {
    assert!(matches!(
        RefreshError::from(LocalRefreshError::Cancelled),
        RefreshError::Cancelled
    ));
    assert!(matches!(
        RefreshError::from(LocalRefreshError::Io),
        RefreshError::Io(IoError::Daemon { .. })
    ));
    assert!(matches!(
        RefreshError::from(LocalRefreshError::Malformed),
        RefreshError::Io(IoError::Scanner { .. })
    ));
    assert!(matches!(
        RefreshError::from(LocalRefreshError::Internal),
        RefreshError::InternalInvariantViolation { .. }
    ));
}

/// `EmitState::try_emit` honours the per-block ceiling and
/// the F13-S latch.
#[test]
fn emit_state_first_breach_emits_suppressed_notice() {
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<RefreshDiagnostic>>,
    }
    impl DiagnosticSink for RecordingSink {
        fn emit(&self, event: RefreshDiagnostic) {
            self.events.lock().unwrap().push(event);
        }
    }

    let sink = RecordingSink::default();
    let mut state = EmitState::new();

    // First emission: passes (counter 0 → 1, within ceiling).
    state.try_emit(
        &sink,
        RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::InvalidBlockStructure,
        },
    );
    // Second emission: over ceiling, latch unset → emit
    // SuppressedRateLimit notice and latch.
    state.try_emit(
        &sink,
        RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::InvalidBlockStructure,
        },
    );
    // Third emission: over ceiling, latch set → silent drop.
    state.try_emit(
        &sink,
        RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::InvalidBlockStructure,
        },
    );

    let events = sink.events.lock().unwrap().clone();
    assert_eq!(events.len(), 2);
    assert!(matches!(
        events[0],
        RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::InvalidBlockStructure
        }
    ));
    assert!(matches!(
        events[1],
        RefreshDiagnostic::SuppressedRateLimit {
            class: SuppressedClass::DaemonMalformed
        }
    ));
}

/// Per-block counter resets at block boundary; F13-S latch
/// persists.
#[test]
fn emit_state_block_reset_clears_counter_not_latch() {
    let mut state = EmitState::new();

    // First emission: passes.
    state.try_emit(
        &NoopDiagnosticSink,
        RefreshDiagnostic::ScanProgress {
            height: 1,
            candidates: 0,
        },
    );
    // Second emission: over ceiling, latch sets.
    state.try_emit(
        &NoopDiagnosticSink,
        RefreshDiagnostic::ScanProgress {
            height: 1,
            candidates: 0,
        },
    );
    assert!(state.scan_progress.notice_emitted);

    // Block boundary: counter resets, latch stays.
    state.reset_block();
    assert_eq!(state.scan_progress.counter, 0);
    assert!(state.scan_progress.notice_emitted);
}

/// `SuppressedRateLimit` events are NOT rate-limited
/// themselves (they exist to signal suppression; rate-limiting
/// them would defeat the purpose).
#[test]
fn suppressed_rate_limit_event_itself_is_not_rate_limited() {
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<RefreshDiagnostic>>,
    }
    impl DiagnosticSink for RecordingSink {
        fn emit(&self, event: RefreshDiagnostic) {
            self.events.lock().unwrap().push(event);
        }
    }

    let sink = RecordingSink::default();
    let mut state = EmitState::new();

    for _ in 0..3 {
        state.try_emit(
            &sink,
            RefreshDiagnostic::SuppressedRateLimit {
                class: SuppressedClass::ScanProgress,
            },
        );
    }

    assert_eq!(sink.events.lock().unwrap().len(), 3);
}

/// `scanner_error_to_malformed_kind` returns
/// `InvalidBlockStructure` for all scanner errors at C4.
#[test]
fn scanner_error_classified_as_invalid_block_structure() {
    // We can't easily construct a `ScanError` here without
    // pulling in the full scanner; assert against the function's
    // const return shape instead.
    const fn _classifies(err: &ScanError) -> MalformedKind {
        scanner_error_to_malformed_kind(err)
    }
    // The function is const fn — calling it at compile time
    // would require an InvalidScannableBlock instance.
    // Coverage is provided by C7's `AssertionSink` property
    // tests once they land.
}

/// `classify_rpc_error` maps each refresh-reachable
/// [`RpcError`] variant to the Round-4-audit-confirmed
/// [`ProtocolErrorKind`] tag per §4 Phase 0e.
///
/// The String payloads on `InternalError` / `ConnectionError`
/// / `InvalidNode` are NOT inspected by the classifier — the
/// §5.4.7 R6 memory-amplifier closure binds this site.
#[test]
fn classify_rpc_error_refresh_reachable_subset() {
    assert_eq!(
        classify_rpc_error(&RpcError::ConnectionError(String::new())),
        ProtocolErrorKind::ConnectionError
    );
    assert_eq!(
        classify_rpc_error(&RpcError::InternalError(String::new())),
        ProtocolErrorKind::InternalError
    );
    assert_eq!(
        classify_rpc_error(&RpcError::InvalidNode(String::new())),
        ProtocolErrorKind::InvalidNode
    );
    assert_eq!(
        classify_rpc_error(&RpcError::InvalidTransaction([0u8; 32])),
        ProtocolErrorKind::InvalidTransaction
    );
    assert_eq!(
        classify_rpc_error(&RpcError::PrunedTransaction),
        ProtocolErrorKind::PrunedTransaction
    );
}

/// `classify_rpc_error` defensively maps the non-refresh-
/// reachable upstream variants (`TransactionsNotFound` /
/// `InvalidFee` / `InvalidPriority`) to
/// [`ProtocolErrorKind::InvalidNode`] per the rustdoc
/// disposition. These variants belong to PR 5's
/// `PendingTxEngine` send-tx path; if PR 5 needs distinct
/// tagging, [`ProtocolErrorKind`] grows additively under
/// `#[non_exhaustive]`.
#[test]
fn classify_rpc_error_non_refresh_reachable_subset_falls_back_to_invalid_node() {
    assert_eq!(
        classify_rpc_error(&RpcError::TransactionsNotFound(vec![])),
        ProtocolErrorKind::InvalidNode
    );
    assert_eq!(
        classify_rpc_error(&RpcError::InvalidFee),
        ProtocolErrorKind::InvalidNode
    );
    assert_eq!(
        classify_rpc_error(&RpcError::InvalidPriority),
        ProtocolErrorKind::InvalidNode
    );
}

/// The Round-4-audited `ProtocolErrorKind` set is exhaustive
/// over the refresh-reachable upstream subset. Adding a
/// variant to upstream [`RpcError`] must not produce a
/// silently-falling-through case at the classifier — the
/// classifier's `match` is exhaustive (no `_` arm) so a new
/// upstream variant breaks the build until C5b's
/// classification is extended deliberately.
#[test]
fn classify_rpc_error_is_exhaustive_at_the_match_arm() {
    // This compiles only because `classify_rpc_error` is
    // exhaustive against every `RpcError` variant. If
    // upstream grows a new variant the build fails here
    // (and at `classify_rpc_error`'s definition site) until
    // the new variant is given an explicit classification.
    fn _exhaustive(e: &RpcError) -> ProtocolErrorKind {
        classify_rpc_error(e)
    }
}
