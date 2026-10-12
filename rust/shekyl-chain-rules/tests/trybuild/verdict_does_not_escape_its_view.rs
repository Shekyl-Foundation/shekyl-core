// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The verdict inherits the view's brand. Judged against `inner`, it cannot
//! be connected under `outer`: the inner brand cannot leave its closure
//! (`E0521`). This is what stops a verdict minted in one store transaction
//! from being connected in another.

#[path = "stub_view.rs"]
mod stub;

use shekyl_chain_rules::{validate, RuleSet, Trust};
use stub::{connect, formed, with_view};

fn main() {
    with_view(|outer| {
        with_view(|inner| {
            let valid = validate(formed(), &inner, &RuleSet::GENESIS, &Trust::UNANCHORED)
                .unwrap()
                .unwrap();
            connect(&outer, valid); // judged against `inner`: does not compile
        })
    });
}
