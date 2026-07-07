// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Version-skew tests (`docs/design/DAEMON_SUBMIT_VERDICT.md` §2.3, §10
//! item 1) — the three behaviors that make wallet/daemon deploy-order safe.
//!
//! Wallet and daemon are released together but not deployed atomically. These
//! tests simulate an **older wallet build** (this crate) receiving JSON from
//! a **newer daemon build** (hand-written JSON exercising each evolution
//! vector), and pin the §2.3 asymmetry:
//!
//! - skew A: unknown `cause` → [`RejectCause::Unrecognized`] (fail-safe:
//!   definitely-not-relayed → release + one-shot rebuild);
//! - skew B: unknown `verdict` tag → deserialization error → the client's
//!   `Err` arm (ambiguous → TTL-resubmit);
//! - skew C: unknown *fields* inside known variants are tolerated;
//! - skew D: a **missing required field** on a known variant (a field-less
//!   `already_in_chain` from a pre-F40 daemon) → deserialization error →
//!   the `Err` arm (the §2.3 third-category asymmetry, pinned so the
//!   post-genesis optional-with-default rule has a test to flip).
//!
//! The asymmetry is deliberate: an unknown rejection *cause* still proves
//! "not in pool, not in chain" (the shape the wallet can act on), while an
//! unknown top-level *tag* is a disposition the wallet cannot name — acting
//! on it would be guessing. The F38 authoring rule (additive rejections go
//! under `RejectCause`, never as new top-level tags) keeps daemons on the
//! safe side of this runtime behavior; these tests pin the runtime side.

use shekyl_rpc_types::{RejectCause, SubmitVerdict};

#[test]
fn skew_a_unknown_cause_degrades_to_unrecognized() {
    // A future daemon added a RejectCause variant this build has never heard
    // of (the F38-sanctioned evolution path).
    let parsed: SubmitVerdict =
        serde_json::from_str(r#"{"verdict":"rejected","cause":"archival_bond_slot_contended"}"#)
            .expect("unknown cause must still deserialize (fail-safe, not Err)");
    assert_eq!(
        parsed,
        SubmitVerdict::Rejected {
            cause: RejectCause::Unrecognized
        },
        "unknown cause must land on Unrecognized, never on a known cause"
    );
}

#[test]
fn skew_a_holds_for_arbitrary_cause_strings() {
    // Not just plausible future names: any string that is not a known cause
    // takes the same path — including the empty string and near-misses of
    // known tags (case, whitespace). Near-misses MUST NOT fuzzy-match: a
    // cause is a contract token, not a hint.
    for cause in ["", "MALFORMED", "fee_too_low ", "fee-too-low", "unknown"] {
        let json = format!(r#"{{"verdict":"rejected","cause":"{cause}"}}"#);
        let parsed: SubmitVerdict = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("cause {cause:?} must deserialize fail-safe: {e}"));
        assert_eq!(
            parsed,
            SubmitVerdict::Rejected {
                cause: RejectCause::Unrecognized
            },
            "cause {cause:?} must degrade to Unrecognized"
        );
    }
}

#[test]
fn skew_b_unknown_verdict_tag_is_a_deserialization_error() {
    // A future daemon added a top-level verdict tag (the breaking-change
    // path F38 reserves for non-rejection dispositions). An older wallet
    // must land in the Err arm — TTL-resubmit — not misread the verdict.
    for json in [
        r#"{"verdict":"quarantined"}"#,
        r#"{"verdict":"accepted_pending_bond","hold_blocks":30}"#,
        r#"{"verdict":""}"#,
    ] {
        assert!(
            serde_json::from_str::<SubmitVerdict>(json).is_err(),
            "unknown verdict tag must be an error (ambiguous, TTL-resubmit): {json}"
        );
    }
}

#[test]
fn skew_c_unknown_fields_inside_known_variants_are_tolerated() {
    // A future daemon added an informational field to a known variant
    // (additive evolution that must not break older wallets — no
    // deny_unknown_fields anywhere on the contract types).
    let parsed: SubmitVerdict = serde_json::from_str(
        r#"{"verdict":"accepted","pool_position":3,"advisory":{"relay_zones":["clearnet"]}}"#,
    )
    .expect("unknown fields inside a known variant must be ignored");
    assert_eq!(parsed, SubmitVerdict::Accepted);

    let parsed: SubmitVerdict = serde_json::from_str(
        r#"{"verdict":"rejected","cause":"fee_too_low","fee_floor_atomic":12345}"#,
    )
    .expect("unknown sibling fields next to a known cause must be ignored");
    assert_eq!(
        parsed,
        SubmitVerdict::Rejected {
            cause: RejectCause::FeeTooLow
        }
    );
}

#[test]
fn skew_d_field_less_already_in_chain_is_a_deserialization_error() {
    // F40 (§2.3 third-category rule): `height` is a *required* field on
    // `already_in_chain`. A field-less form — an older (pre-F40) daemon —
    // must land in the Err arm (TTL-resubmit), never in a defaulted height:
    // a defaulted 0 would route the wallet's release path (targeted
    // re-scan at height 0) off a value the daemon never asserted.
    // Pre-genesis this Err arm is a non-event (wallet and daemon release
    // together); post-genesis the field must become optional-with-default,
    // and this is the test that flips.
    assert!(
        serde_json::from_str::<SubmitVerdict>(r#"{"verdict":"already_in_chain"}"#).is_err(),
        "field-less already_in_chain must be a deserialization error"
    );
}

#[test]
fn skew_a_and_c_compose() {
    // Both evolutions at once: an unknown cause carrying unknown payload
    // fields. Still fail-safe, still Unrecognized.
    let parsed: SubmitVerdict = serde_json::from_str(
        r#"{"verdict":"rejected","cause":"tx_graph_policy","policy_id":"p-7","retry_after":600}"#,
    )
    .expect("unknown cause + unknown fields must deserialize fail-safe");
    assert_eq!(
        parsed,
        SubmitVerdict::Rejected {
            cause: RejectCause::Unrecognized
        }
    );
}

#[test]
fn unrecognized_never_appears_on_the_authoring_side_of_a_known_cause() {
    // Serialization of Unrecognized exists (the type is honest about its
    // wire form), but no *known* cause may serialize to a string that a
    // fresh deserialize maps to Unrecognized — i.e. the known-cause set
    // round-trips onto itself, so the catch-all only ever captures genuinely
    // foreign tags.
    let known = [
        RejectCause::Malformed,
        RejectCause::FeeTooLow,
        RejectCause::DoubleSpendConflict,
        RejectCause::StaleRoot,
        RejectCause::ReferenceTooRecent,
        RejectCause::ReferenceNotFound,
    ];
    for cause in known {
        let json = serde_json::to_string(&cause).expect("serialize cause");
        let back: RejectCause = serde_json::from_str(&json).expect("parse cause");
        assert_eq!(
            back, cause,
            "known cause {json} must round-trip onto itself"
        );
    }
}
