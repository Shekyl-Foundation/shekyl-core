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
//! - skew A: unknown `cause` key → [`Rejection::Unrecognized`] (fail-safe:
//!   definitely-not-relayed → release + one-shot rebuild);
//! - skew B: unknown `verdict` tag → deserialization error → the client's
//!   `Err` arm (ambiguous → TTL-resubmit);
//! - skew C: unknown *fields* inside known variants are tolerated;
//! - skew D: a **missing required field** on a known variant (a field-less
//!   `already_in_chain` from a pre-F40 daemon) → deserialization error →
//!   the `Err` arm (the §2.3 third-category asymmetry, pinned so the
//!   post-genesis optional-with-default rule has a test to flip).
//!
//! Under 4.0 a verdict is tagged by `verdict` in kebab case and a cause is
//! one key, its payload or `null` (IG-Q76, IG-Q86).
//!
//! The asymmetry is deliberate: an unknown rejection *cause* still proves
//! "not in pool, not in chain" (the shape the wallet can act on), while an
//! unknown top-level *tag* is a disposition the wallet cannot name — acting
//! on it would be guessing. The F38 authoring rule (additive rejections go
//! under `Rejection`, never as new top-level tags) keeps daemons on the
//! safe side of this runtime behavior; these tests pin the runtime side.

use shekyl_rpc_types::kinds::Text;
use shekyl_rpc_types::wire::tx::{Rejection, Verdict};

fn rejected(cause: Rejection) -> Verdict {
    Verdict::Rejected { cause }
}

#[test]
fn skew_a_unknown_cause_degrades_to_unrecognized() {
    // A future daemon added a cause this build has never heard of (the
    // F38-sanctioned evolution path).
    let parsed: Verdict = serde_json::from_str(
        r#"{"verdict":"rejected","cause":{"archival-bond-slot-contended":null}}"#,
    )
    .expect("unknown cause must still deserialize (fail-safe, not Err)");
    assert_eq!(
        parsed,
        rejected(Rejection::Unrecognized),
        "unknown cause must land on Unrecognized, never on a known cause"
    );
}

#[test]
fn skew_a_holds_for_arbitrary_cause_keys() {
    // Not just plausible future names: any key that is not a known cause
    // takes the same path — including the empty key and near-misses of
    // known keys (case, whitespace, the 3.x snake case). Near-misses MUST
    // NOT fuzzy-match: a cause is a contract token, not a hint.
    for cause in ["", "MALFORMED", "fee-too-low ", "fee_too_low", "unknown"] {
        let json = format!(r#"{{"verdict":"rejected","cause":{{"{cause}":null}}}}"#);
        let parsed: Verdict = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("cause {cause:?} must deserialize fail-safe: {e}"));
        assert_eq!(
            parsed,
            rejected(Rejection::Unrecognized),
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
        r#"{"verdict":"accepted-pending-bond","hold_blocks":30}"#,
        r#"{"verdict":""}"#,
        // The 3.x spelling of a known tag is not that tag.
        r#"{"verdict":"already_in_pool","publication":"held"}"#,
    ] {
        assert!(
            serde_json::from_str::<Verdict>(json).is_err(),
            "unknown verdict tag must be an error (ambiguous, TTL-resubmit): {json}"
        );
    }
}

#[test]
fn skew_c_unknown_fields_inside_known_variants_are_tolerated() {
    // A future daemon added an informational field to a known variant
    // (additive evolution that must not break older wallets — no
    // deny_unknown_fields on the verdict).
    let parsed: Verdict = serde_json::from_str(
        r#"{"verdict":"accepted","pool_position":3,"advisory":{"relay_zones":["clearnet"]}}"#,
    )
    .expect("unknown fields inside a known variant must be ignored");
    assert_eq!(parsed, Verdict::Accepted);

    let parsed: Verdict = serde_json::from_str(
        r#"{"verdict":"rejected","cause":{"fee-too-low":null},"fee_floor":"12345"}"#,
    )
    .expect("unknown sibling fields next to a known cause must be ignored");
    assert_eq!(parsed, rejected(Rejection::FeeTooLow));
}

#[test]
fn skew_d_field_less_already_in_chain_is_a_deserialization_error() {
    // F40 (§2.3 third-category rule): `mined_height` is a *required* field
    // on `already-in-chain`. A field-less form must land in the Err arm
    // (TTL-resubmit), never in a defaulted height: a defaulted 0 would
    // route the wallet's release path (targeted re-scan at height 0) off a
    // value the daemon never asserted. Pre-genesis this Err arm is a
    // non-event (wallet and daemon release together); post-genesis the
    // field must become optional-with-default, and this is the test that
    // flips.
    assert!(
        serde_json::from_str::<Verdict>(r#"{"verdict":"already-in-chain"}"#).is_err(),
        "field-less already-in-chain must be a deserialization error"
    );
}

#[test]
fn skew_a_and_c_compose() {
    // Both evolutions at once: an unknown cause carrying a payload, beside
    // an unknown sibling field. Still fail-safe, still Unrecognized.
    let parsed: Verdict = serde_json::from_str(
        r#"{"verdict":"rejected","cause":{"tx-graph-policy":{"policy":"p-7"}},"retry_after":600}"#,
    )
    .expect("unknown cause + unknown fields must deserialize fail-safe");
    assert_eq!(parsed, rejected(Rejection::Unrecognized));
}

#[test]
fn unrecognized_never_appears_on_the_authoring_side_of_a_known_cause() {
    // No *known* cause may serialize to a key that a fresh deserialize maps
    // to Unrecognized — the known-cause set round-trips onto itself, so
    // the catch-all only ever captures foreign keys. Unrecognized itself
    // has no wire form: a daemon names its cause.
    let known = [
        Rejection::Malformed,
        Rejection::FeeTooLow,
        Rejection::DoubleSpendConflict,
        Rejection::StaleRoot,
        Rejection::ReferenceTooRecent,
        Rejection::ReferenceUnknown,
        Rejection::ConsensusRule(Text("CEN-J15".to_owned())),
    ];
    for cause in known {
        let json = serde_json::to_string(&cause).expect("serialize cause");
        let back: Rejection = serde_json::from_str(&json).expect("parse cause");
        assert_eq!(
            back, cause,
            "known cause {json} must round-trip onto itself"
        );
    }
    assert!(serde_json::to_string(&Rejection::Unrecognized).is_err());
}

/// Version skew across the major (RK-Q11, RK-D25): a 3.70 daemon's
/// `get_version` result, the one 3.x reply kept from the retired corpus
/// (`vectors/rpc/README.md`), is refused on the wire axis by this build's
/// version-first read, before its 3.x shape is decoded. The client names
/// both versions; it does not report an unreadable reply.
///
/// Red edit: decode the reply strictly before comparing the version.
#[test]
fn a_3x_daemon_is_refused_on_the_wire_axis_before_its_shape_is_read() {
    let reply: serde_json::Value =
        serde_json::from_str(include_str!("vectors/rpc/get_version_synced_v47.json"))
            .expect("the kept 3.x reply is JSON");
    assert_eq!(
        shekyl_rpc_types::daemon_rpc_version(&reply).expect("its version reads"),
        (3 << 16) | 70,
        "the kept reply is 3.70's"
    );
    let refusal = shekyl_rpc_types::IdentityExpectation::exact(shekyl_rpc_types::Network::Mainnet)
        .read(&reply)
        .expect_err("a 3.x daemon is not this build");
    assert_eq!(
        refusal.mismatch,
        shekyl_rpc_types::IdentityMismatch::Wire {
            ours: shekyl_rpc_types::version::CORE_RPC_VERSION,
            theirs: (3 << 16) | 70,
        }
    );
    assert_eq!(
        refusal.evidence, None,
        "a version mismatch, not a parse failure"
    );
}
