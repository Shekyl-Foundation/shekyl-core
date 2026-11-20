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
//! schema-evolution rule, never an incidental edit. Under 4.0 the tags and
//! cause keys are kebab case, a cause is one key with its payload or
//! `null`, and the bytes are base64 (IG-Q76, IG-Q86).

use shekyl_rpc_types::kinds::{Bytes, Height, Text};
use shekyl_rpc_types::wire::tx::{Publication, Rejection, TxBody, Verdict};

fn rejected(cause: Rejection) -> Verdict {
    Verdict::Rejected { cause }
}

/// Every verdict variant, with its frozen wire representation.
fn frozen_corpus() -> Vec<(Verdict, &'static str)> {
    vec![
        (Verdict::Accepted, r#"{"verdict":"accepted"}"#),
        (
            Verdict::AlreadyInPool {
                publication: Publication::Held,
            },
            r#"{"verdict":"already-in-pool","publication":"held"}"#,
        ),
        (
            Verdict::AlreadyInPool {
                publication: Publication::Overdue,
            },
            r#"{"verdict":"already-in-pool","publication":"overdue"}"#,
        ),
        (
            Verdict::AlreadyInPool {
                publication: Publication::Public,
            },
            r#"{"verdict":"already-in-pool","publication":"public"}"#,
        ),
        (
            Verdict::AlreadyInPool {
                publication: Publication::Untracked,
            },
            r#"{"verdict":"already-in-pool","publication":"untracked"}"#,
        ),
        (
            Verdict::AlreadyInChain {
                mined_height: Height(1_234_567),
            },
            r#"{"verdict":"already-in-chain","mined_height":1234567}"#,
        ),
        (
            rejected(Rejection::Malformed),
            r#"{"verdict":"rejected","cause":{"malformed":null}}"#,
        ),
        (
            rejected(Rejection::FeeTooLow),
            r#"{"verdict":"rejected","cause":{"fee-too-low":null}}"#,
        ),
        (
            rejected(Rejection::DoubleSpendConflict),
            r#"{"verdict":"rejected","cause":{"double-spend-conflict":null}}"#,
        ),
        (
            rejected(Rejection::StaleRoot),
            r#"{"verdict":"rejected","cause":{"stale-root":null}}"#,
        ),
        (
            rejected(Rejection::ReferenceTooRecent),
            r#"{"verdict":"rejected","cause":{"reference-too-recent":null}}"#,
        ),
        (
            rejected(Rejection::ReferenceUnknown),
            r#"{"verdict":"rejected","cause":{"reference-unknown":null}}"#,
        ),
        // A consensus row refused at the pool's commit: the row is the
        // cause's payload.
        (
            rejected(Rejection::ConsensusRule(Text("CEN-J15".to_owned()))),
            r#"{"verdict":"rejected","cause":{"consensus-rule":"CEN-J15"}}"#,
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
        let parsed: Verdict = serde_json::from_str(frozen)
            .unwrap_or_else(|e| panic!("frozen form of {verdict:?} must parse: {e}"));
        assert_eq!(parsed, verdict, "round-trip mismatch for {frozen}");
    }
}

#[test]
fn unrecognized_has_no_wire_form() {
    // `Unrecognized` is read-side only: a daemon never authors it, so the
    // type refuses to write it rather than invent a key for it.
    assert!(serde_json::to_string(&rejected(Rejection::Unrecognized)).is_err());
}

#[test]
fn tag_position_is_not_load_bearing() {
    // Internally-tagged deserialization buffers content, so a daemon-side
    // serializer that emits fields in a different order (a different JSON
    // library, a proxy re-encoding) still parses. The *canonical* order is
    // pinned by the frozen corpus; this pins tolerance of the other order.
    let parsed: Verdict =
        serde_json::from_str(r#"{"cause":{"stale-root":null},"verdict":"rejected"}"#)
            .expect("tag-last form must parse");
    assert_eq!(parsed, rejected(Rejection::StaleRoot));
}

#[test]
fn already_in_pool_without_a_publication_is_a_deserialization_error() {
    assert!(serde_json::from_str::<Verdict>(r#"{"verdict":"already-in-pool"}"#).is_err());
}

#[test]
fn rejected_without_a_cause_is_a_deserialization_error() {
    // A `rejected` with no cause is not actionable — the wallet cannot pick a
    // disposition row. It lands in the `Err` arm (transport-equivalent
    // ambiguity → TTL-resubmit), never in a default cause.
    assert!(serde_json::from_str::<Verdict>(r#"{"verdict":"rejected"}"#).is_err());
}

#[test]
fn a_cause_is_one_key_and_a_bare_cause_carries_no_payload() {
    // Two keys is not a cause, a bare key is not a cause, and a payload on
    // a cause that carries none is not that cause: each is an Err, the
    // ambiguous arm, never a guess at which key was meant.
    for json in [
        r#"{"verdict":"rejected","cause":{"malformed":null,"stale-root":null}}"#,
        r#"{"verdict":"rejected","cause":{}}"#,
        r#"{"verdict":"rejected","cause":"fee-too-low"}"#,
        r#"{"verdict":"rejected","cause":{"fee-too-low":1}}"#,
    ] {
        assert!(serde_json::from_str::<Verdict>(json).is_err(), "{json}");
    }
}

#[test]
fn request_round_trips_and_requires_its_body() {
    let req = TxBody {
        body: Bytes(vec![0x00, 0xff, 0x10]),
    };
    let json = serde_json::to_string(&req).expect("serialize request");
    assert_eq!(json, r#"{"body":"AP8Q"}"#, "request wire form drifted");
    let parsed: TxBody = serde_json::from_str(&json).expect("parse request");
    assert_eq!(parsed, req);

    // A missing body is a malformed request, not an empty submit; hex is
    // not the bytes' form.
    assert!(serde_json::from_str::<TxBody>("{}").is_err());
    assert!(serde_json::from_str::<TxBody>(r#"{"body":"00ff1"}"#).is_err());
}
