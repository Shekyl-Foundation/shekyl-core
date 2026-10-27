// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The positive control: the program beside this one, judged over the
//! batch's own view, compiles. Compiled, not run.

use shekyl_chain_rules::{validate, RuleSet, StructurallyValid, Trust};
use shekyl_chain_store::store::{ChainStore, StoreError};

#[allow(dead_code)]
fn program(store: &ChainStore, formed: StructurallyValid) -> Result<(), StoreError> {
    store.write(|batch| {
        let view = batch.chain_view();
        let valid = validate(formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED)
            .unwrap()
            .unwrap();
        batch.connect(valid, RuleSet::GENESIS).map(|_| ())
    })
}

fn main() {}
