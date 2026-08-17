// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit suite for the diagnostics surface (`engine/diagnostics.rs`).
//!
//! Extracted to a `#[path]` sibling so the engine-decomposition ratchet
//! measures the workflow file rather than its tests — the pattern the
//! conf records for `merge_tests.rs` / `pending_tests.rs`.

//! Sink-construction and projection-stability smoke tests.
//!
//! Behavioral coverage (`AssertionSink` / `PanickingSink`
//! property tests; emission/return coherence pin) lands in
//! C7 against the C4 producer body. C2's tests only verify
//! that the bucket projections are stable at the variant
//! boundaries that F9 names — the contract pins (§5.4.8 #5
//! per-class emission budget; §5.4.6 emission/return
//! coherence) are exercised end-to-end in C7.

use super::*;

#[test]
fn elapsed_bucket_thresholds_match_f9_contract() {
    assert_eq!(elapsed_bucket(Duration::from_millis(0)), "<100ms");
    assert_eq!(elapsed_bucket(Duration::from_millis(99)), "<100ms");
    assert_eq!(elapsed_bucket(Duration::from_millis(100)), "100ms-1s");
    assert_eq!(elapsed_bucket(Duration::from_millis(999)), "100ms-1s");
    assert_eq!(elapsed_bucket(Duration::from_secs(1)), ">1s");
    assert_eq!(elapsed_bucket(Duration::from_secs(60)), ">1s");
}

#[test]
fn depth_bucket_thresholds_match_f9_contract() {
    assert_eq!(depth_bucket(0), "1");
    assert_eq!(depth_bucket(1), "1");
    assert_eq!(depth_bucket(2), "2-10");
    assert_eq!(depth_bucket(10), "2-10");
    assert_eq!(depth_bucket(11), ">10");
    assert_eq!(depth_bucket(u32::MAX), ">10");
}

#[test]
fn candidates_bucket_thresholds_match_f9_contract() {
    assert_eq!(candidates_bucket(0), "none");
    assert_eq!(candidates_bucket(1), "few");
    assert_eq!(candidates_bucket(9), "few");
    assert_eq!(candidates_bucket(10), "many");
    assert_eq!(candidates_bucket(usize::MAX), "many");
}

#[test]
fn noop_sink_swallows_every_audited_variant() {
    let sink = NoopDiagnosticSink::new();
    sink.emit(RefreshDiagnostic::DaemonMalformed {
        kind: MalformedKind::InvalidBlockStructure,
    });
    sink.emit(RefreshDiagnostic::DaemonMalformed {
        kind: MalformedKind::ExcessiveOutputs,
    });
    sink.emit(RefreshDiagnostic::DaemonTimeout {
        op: DaemonOp::GetHeight,
        elapsed: Duration::from_millis(250),
    });
    sink.emit(RefreshDiagnostic::DaemonProtocolError {
        kind: ProtocolErrorKind::ConnectionError,
    });
    sink.emit(RefreshDiagnostic::ReorgObserved {
        fork_height: 12345,
        depth: 3,
    });
    sink.emit(RefreshDiagnostic::ScanProgress {
        height: 99999,
        candidates: 0,
    });
    sink.emit(RefreshDiagnostic::SuppressedRateLimit {
        class: SuppressedClass::ScanProgress,
    });
}

#[test]
fn tracing_sink_does_not_panic_on_any_audited_variant() {
    // The tracing-subscriber installation is global and
    // managed by upstream test harnesses; this test just
    // confirms each match arm completes without panicking
    // when invoked with a representative payload from each
    // variant. F9 projection-stability is verified by the
    // bucket-threshold tests above.
    let sink = TracingDiagnosticSink::new();
    sink.emit(RefreshDiagnostic::DaemonMalformed {
        kind: MalformedKind::UnsupportedProtocolVersion,
    });
    sink.emit(RefreshDiagnostic::DaemonMalformed {
        kind: MalformedKind::ExcessiveOutputs,
    });
    sink.emit(RefreshDiagnostic::DaemonTimeout {
        op: DaemonOp::FetchScannableBlock,
        elapsed: Duration::from_millis(1500),
    });
    sink.emit(RefreshDiagnostic::DaemonProtocolError {
        kind: ProtocolErrorKind::InternalError,
    });
    sink.emit(RefreshDiagnostic::ReorgObserved {
        fork_height: 1,
        depth: 11,
    });
    sink.emit(RefreshDiagnostic::ScanProgress {
        height: 0,
        candidates: 50,
    });
    sink.emit(RefreshDiagnostic::SuppressedRateLimit {
        class: SuppressedClass::DaemonProtocolError,
    });
}

// ------------------------------------------------------------------------
// C7 smoke tests — AssertionSink / PanickingSink
// ------------------------------------------------------------------------
//
// These are construction-and-trigger smoke tests; the full
// §5.4.6 emission/return coherence and producer-panic-safety
// properties land as proptest-driven coverage in
// `local_refresh.rs` and as the hybrid retry test in
// `refresh.rs`. The smoke tests below verify the sinks' own
// contract: AssertionSink records in FIFO order, PanickingSink
// panics only on matched triggers.

#[test]
fn assertion_sink_records_events_in_emission_order() {
    let sink = AssertionSink::new();
    assert_eq!(sink.count(), 0);
    sink.emit(RefreshDiagnostic::DaemonProtocolError {
        kind: ProtocolErrorKind::ConnectionError,
    });
    sink.emit(RefreshDiagnostic::DaemonMalformed {
        kind: MalformedKind::InvalidBlockStructure,
    });
    sink.emit(RefreshDiagnostic::ScanProgress {
        height: 42,
        candidates: 3,
    });
    assert_eq!(sink.count(), 3);
    let recorded = sink.recorded();
    assert!(matches!(
        recorded[0],
        RefreshDiagnostic::DaemonProtocolError {
            kind: ProtocolErrorKind::ConnectionError
        }
    ));
    assert!(matches!(
        recorded[1],
        RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::InvalidBlockStructure
        }
    ));
    assert!(matches!(
        recorded[2],
        RefreshDiagnostic::ScanProgress {
            height: 42,
            candidates: 3
        }
    ));
}

#[test]
fn assertion_sink_recorded_clones_buffer_without_draining() {
    let sink = AssertionSink::new();
    sink.emit(RefreshDiagnostic::ScanProgress {
        height: 1,
        candidates: 0,
    });
    let snap1 = sink.recorded();
    let snap2 = sink.recorded();
    assert_eq!(snap1.len(), 1);
    assert_eq!(snap2.len(), 1);
    assert_eq!(sink.count(), 1);
}

#[test]
fn panicking_sink_any_fires_on_first_emission() {
    let sink = PanickingSink::new(PanickingSinkTrigger::Any);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sink.emit(RefreshDiagnostic::ScanProgress {
            height: 1,
            candidates: 0,
        });
    }));
    assert!(result.is_err(), "Any trigger must panic on emit");
}

#[test]
fn panicking_sink_on_daemon_malformed_only_fires_on_matched_class() {
    let sink = PanickingSink::new(PanickingSinkTrigger::OnDaemonMalformed);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sink.emit(RefreshDiagnostic::ScanProgress {
            height: 1,
            candidates: 0,
        });
        sink.emit(RefreshDiagnostic::DaemonProtocolError {
            kind: ProtocolErrorKind::ConnectionError,
        });
    }));
    assert!(
        result.is_ok(),
        "OnDaemonMalformed must NOT fire on ScanProgress or DaemonProtocolError"
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sink.emit(RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::InvalidBlockStructure,
        });
    }));
    assert!(
        result.is_err(),
        "OnDaemonMalformed must fire on DaemonMalformed emit"
    );
}

#[test]
fn panicking_sink_on_protocol_error_only_fires_on_matched_class() {
    let sink = PanickingSink::new(PanickingSinkTrigger::OnDaemonProtocolError);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sink.emit(RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::InvalidBlockStructure,
        });
    }));
    assert!(
        result.is_ok(),
        "OnDaemonProtocolError must NOT fire on DaemonMalformed"
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sink.emit(RefreshDiagnostic::DaemonProtocolError {
            kind: ProtocolErrorKind::InternalError,
        });
    }));
    assert!(
        result.is_err(),
        "OnDaemonProtocolError must fire on DaemonProtocolError emit"
    );
}

#[test]
fn panicking_sink_on_scan_progress_only_fires_on_matched_class() {
    let sink = PanickingSink::new(PanickingSinkTrigger::OnScanProgress);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sink.emit(RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::InvalidBlockStructure,
        });
    }));
    assert!(
        result.is_ok(),
        "OnScanProgress must NOT fire on DaemonMalformed"
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sink.emit(RefreshDiagnostic::ScanProgress {
            height: 7,
            candidates: 0,
        });
    }));
    assert!(result.is_err(), "OnScanProgress must fire on ScanProgress");
}
