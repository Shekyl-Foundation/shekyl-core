// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where the proofs are verified (`CHAIN_RULES_CRATE.md` §4.6, 2026-10-16):
//! every verification that needs no store runs in `form`, and `validate`
//! — the view-bound stage inside the write transaction — compares claims
//! and verifies nothing. Held on a real spend over a real store, with the
//! rules crate's thread-local probes, on this test's own thread: `form`'s
//! deltas are positive (the probe's subject exists, rule 47) and
//! `validate`'s are zero.
//!
//! Red check: re-add a verify to `validate`'s reference path (or route
//! `judge_reference` through `I15::verify`) and the zero assertion fails;
//! drop the verify from `judge_proofs` and the positive assertion fails.

use shekyl_chain_rules::{probes, validate, RuleSet, Trust};

use super::connect_fixtures::{formed, priced, Grown, Listed};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;

/// Fee the matured coinbase pays; not a consensus figure.
const FEE: u64 = 1_000;

#[test]
fn validate_verifies_no_proof_and_no_signature_and_form_verifies_both() {
    let path = tmp("verify-site");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let mut grown = Grown::new();
    // Coinbase-only blocks until one coinbase has matured for a spend.
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        while grown.matured().is_empty() {
            let judged = grown.judge_listing(&view, &RuleSet::GENESIS, &[])?;
            batch.connect(judged, RuleSet::GENESIS)?;
        }
        Ok(())
    });
    out.expect("the prefix connects");

    // Built over the committed chain, before the batch that judges it.
    let candidate = grown.next(&store, &[Listed::Spend { fee: FEE }]);
    let txs = candidate.transactions.clone();
    assert_eq!(candidate.proof_references().len(), 1, "one reference named");
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        // Priced against the view it is judged on, as every fixture
        // candidate is (`judge_under`'s docs; CEN-F18).
        let candidate = priced(&view, candidate)?;

        let before = (probes::fcmp_verifies(), probes::signature_verifies());
        let formed = formed(&view, candidate)?;
        let after_form = (probes::fcmp_verifies(), probes::signature_verifies());
        assert!(
            after_form.0 > before.0,
            "form verified the spend's membership proof (CEN-I15): {before:?} → {after_form:?}"
        );
        assert!(
            after_form.1 > before.1,
            "form verified the spend's signature (CEN-I18): {before:?} → {after_form:?}"
        );
        assert!(
            formed
                .verified_reference(shekyl_chain_rules::TxSlot::Listed(0))
                .is_some(),
            "the token carries what the proof was verified against"
        );

        let valid = match validate(formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED) {
            Ok(Ok(valid)) => valid,
            other => panic!("the spend connects: {other:?}"),
        };
        let after_validate = (probes::fcmp_verifies(), probes::signature_verifies());
        assert_eq!(
            after_validate, after_form,
            "validate verified nothing: no proof, no signature"
        );
        grown.record(valid.block().block(), &txs);
        batch.connect(valid, RuleSet::GENESIS)?;
        Ok(())
    });
    out.expect("the spending block connects");
    drop(store);
    cleanup(&path);
}
