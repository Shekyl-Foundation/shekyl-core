// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `connect` takes the in-force [`RuleSet`](shekyl_chain_rules::RuleSet) by
//! value (DRS-E2 RD-Q10). Fakechain `Fixed` reuses `RuleSetId::GENESIS`, so
//! these two tests pin that the belt compares sets, not ids.

use shekyl_chain_rules::{form, validate, FormAttempt, RuleSet, RuleSetId, Trust};
use shekyl_types::BlockHash;

use super::connect_fixtures::{candidate, facts, FixtureSubstrate};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::RuleSetInForce;
use crate::schema::HF_VERSIONS;

#[test]
fn a_fakechain_verdict_connects_when_the_fakechain_set_is_in_force() {
    // RD-F13: with `in_force: RuleSetId`, no id resolved to a `Fixed` set and
    // a Fakechain verdict could never connect. The caller now hands the set
    // itself (RD-Q10), and the path exists.
    let seven = RuleSet::fakechain(core::num::NonZeroU128::new(7), shekyl_chain_rules::D_MAX);
    let path = tmp("connect-fakechain-in-force");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let cand = candidate(0, BlockHash::NULL, Vec::new());
        let formed = match form(
            cand,
            &seven,
            &FixtureSubstrate,
            BlockHash::NULL,
            FormAttempt::FIRST,
        ) {
            Ok(Ok(formed)) => formed,
            other => panic!("stateless stage: {other:?}"),
        };
        let valid = match validate(formed, &view, &seven, &Trust::UNANCHORED) {
            Ok(Ok(valid)) => valid,
            other => panic!("view stage: {other:?}"),
        };
        Ok(batch.connect(valid, facts(0, 0), seven)?)
    });
    out.expect("a Fakechain verdict connects under the Fakechain set");
    // The CEN-B3 belt recorded the id — which is GENESIS's, and is not the
    // set (the caveat at the belt).
    let snap = store.begin_read().expect("read");
    let recorded: RuleSetInForce = snap
        .open_table(HF_VERSIONS)
        .expect("sealed")
        .get(0u64)
        .expect("read")
        .expect("row")
        .value()
        .decode()
        .expect("decodes");
    assert_eq!(recorded, RuleSetInForce(RuleSetId::GENESIS));
    assert_eq!(seven.id(), RuleSetId::GENESIS, "the id is not the set");
    cleanup(&path);
}

#[test]
fn a_fakechain_verdict_is_refused_under_genesis_in_force() {
    // Same id, different set: `fakechain(7)` reuses `RuleSetId::GENESIS`.
    // An id-only check would accept the fixed-target work as public-network
    // GENESIS work; compared by value, `connect` refuses.
    let seven = RuleSet::fakechain(core::num::NonZeroU128::new(7), shekyl_chain_rules::D_MAX);
    let path = tmp("connect-fakechain");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let cand = candidate(0, BlockHash::NULL, Vec::new());
        let formed = match form(
            cand,
            &seven,
            &FixtureSubstrate,
            BlockHash::NULL,
            FormAttempt::FIRST,
        ) {
            Ok(Ok(formed)) => formed,
            other => panic!("stateless stage: {other:?}"),
        };
        let valid = match validate(formed, &view, &seven, &Trust::UNANCHORED) {
            Ok(Ok(valid)) => valid,
            other => panic!("view stage: {other:?}"),
        };
        Ok(batch.connect(valid, facts(0, 0), RuleSet::GENESIS)?)
    });
    let want = StoreCannot::RuleSetNotInForce {
        height: 0,
        judged: Box::new(seven),
        in_force: Box::new(RuleSet::GENESIS),
    };
    assert_eq!(out, Err(TestErr::Store(StoreError::from(want).to_string())));
    cleanup(&path);
}
