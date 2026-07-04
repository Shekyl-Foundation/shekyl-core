// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wire-contract round-trip + frozen-representation tests
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md` §10 item 1, first leg).
//!
//! The JSON strings pinned here ARE the wire format: a daemon and a wallet
//! agree byte-for-byte on these representations or they do not interoperate.
//! A failing pin means the wire contract moved — which, once the contract is
//! frozen (§8 freeze rule), is a coordinated wire-version bump per the §2.3
//! schema-evolution rule, never an incidental edit.

use shekyl_rpc_types::{RejectCause, SubmitTransactionRequest, SubmitVerdict};

/// Every verdict variant, with its frozen wire representation.
fn frozen_corpus() -> Vec<(SubmitVerdict, &'static str)> {
    vec![
        (SubmitVerdict::Accepted, r#"{"verdict":"accepted"}"#),
        (
            SubmitVerdict::AlreadyInPool,
            r#"{"verdict":"already_in_pool"}"#,
        ),
        (
            SubmitVerdict::AlreadyInChain,
            r#"{"verdict":"already_in_chain"}"#,
        ),
        (
            SubmitVerdict::Rejected {
                cause: RejectCause::Malformed,
            },
            r#"{"verdict":"rejected","cause":"malformed"}"#,
        ),
        (
            SubmitVerdict::Rejected {
                cause: RejectCause::FeeTooLow,
            },
            r#"{"verdict":"rejected","cause":"fee_too_low"}"#,
        ),
        (
            SubmitVerdict::Rejected {
                cause: RejectCause::DoubleSpendConflict,
            },
            r#"{"verdict":"rejected","cause":"double_spend_conflict"}"#,
        ),
        (
            SubmitVerdict::Rejected {
                cause: RejectCause::StaleRoot,
            },
            r#"{"verdict":"rejected","cause":"stale_root"}"#,
        ),
        (
            SubmitVerdict::Rejected {
                cause: RejectCause::ReferenceTooRecent,
            },
            r#"{"verdict":"rejected","cause":"reference_too_recent"}"#,
        ),
        (
            SubmitVerdict::Rejected {
                cause: RejectCause::ReferenceNotFound,
            },
            r#"{"verdict":"rejected","cause":"reference_not_found"}"#,
        ),
        // `Unrecognized` is deserialize-side only in the protocol (a daemon
        // never authors it), but the type can express it and its
        // representation is part of the frozen surface.
        (
            SubmitVerdict::Rejected {
                cause: RejectCause::Unrecognized,
            },
            r#"{"verdict":"rejected","cause":"unrecognized"}"#,
        ),
    ]
}

#[test]
fn every_verdict_serializes_to_its_frozen_representation() {
    for (verdict, frozen) in frozen_corpus() {
        let got = serde_json::to_string(&verdict).expect("serialize verdict");
        assert_eq!(got, frozen, "wire representation drifted for {verdict:?}");
    }
}

#[test]
fn every_verdict_round_trips_through_its_wire_bytes() {
    for (verdict, frozen) in frozen_corpus() {
        let parsed: SubmitVerdict = serde_json::from_str(frozen)
            .unwrap_or_else(|e| panic!("frozen form of {verdict:?} must parse: {e}"));
        assert_eq!(parsed, verdict, "round-trip mismatch for {frozen}");
    }
}

#[test]
fn tag_position_is_not_load_bearing() {
    // Internally-tagged deserialization buffers content, so a daemon-side
    // serializer that emits fields in a different order (a different JSON
    // library, a proxy re-encoding) still parses. The *canonical* order is
    // pinned by the frozen corpus; this pins tolerance of the other order.
    let parsed: SubmitVerdict =
        serde_json::from_str(r#"{"cause":"stale_root","verdict":"rejected"}"#)
            .expect("tag-last form must parse");
    assert_eq!(
        parsed,
        SubmitVerdict::Rejected {
            cause: RejectCause::StaleRoot
        }
    );
}

#[test]
fn rejected_without_a_cause_is_a_deserialization_error() {
    // A `rejected` with no cause is not actionable — the wallet cannot pick a
    // disposition row. It lands in the `Err` arm (transport-equivalent
    // ambiguity → TTL-resubmit), never in a default cause.
    assert!(serde_json::from_str::<SubmitVerdict>(r#"{"verdict":"rejected"}"#).is_err());
}

#[test]
fn request_round_trips_and_requires_tx_blob() {
    let req = SubmitTransactionRequest {
        tx_blob: "00ff10".into(),
    };
    let json = serde_json::to_string(&req).expect("serialize request");
    assert_eq!(json, r#"{"tx_blob":"00ff10"}"#, "request wire form drifted");
    let parsed: SubmitTransactionRequest = serde_json::from_str(&json).expect("parse request");
    assert_eq!(parsed, req);

    // Missing tx_blob is a malformed request, not an empty submit.
    assert!(serde_json::from_str::<SubmitTransactionRequest>("{}").is_err());
}
