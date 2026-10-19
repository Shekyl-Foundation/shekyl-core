// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A verdict judged over the pool decorator does not connect: the store's
//! `connect` takes a verdict branded with the batch's own view, and
//! `ChainValid<PoolView<BatchView>>` is not `ChainValid<BatchView>`.

use shekyl_chain_rules::{validate, RuleSet, StructurallyValid, Trust};
use shekyl_chain_store::store::{ChainStore, StoreError};
use shekyl_mempool::{KeyImages, PoolView};

#[allow(dead_code)]
fn program(store: &ChainStore, formed: StructurallyValid) -> Result<(), StoreError> {
    store.write(|batch| {
        let view = batch.chain_view();
        let pool = KeyImages::default();
        let judged = PoolView::new(&view, &pool);
        let valid = validate(formed, &judged, &RuleSet::GENESIS, &Trust::UNANCHORED)
            .unwrap()
            .unwrap();
        batch.connect(valid, RuleSet::GENESIS).map(|_| ())
    })
}

fn main() {}
