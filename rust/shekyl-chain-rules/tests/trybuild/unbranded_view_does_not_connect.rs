// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The verdict inherits the view's type as well as its brand. An unbranded
//! view that implements `ChainView` for every `'id` still cannot satisfy
//! `connect`: it mints `ChainValid<'id, Evil>`, not
//! `ChainValid<'id, View<'id>>` (`E0308`). Borrowing the lifetime is not
//! being the view.

#[path = "stub_view.rs"]
mod stub;

use shekyl_chain_rules::{validate, RuleSet, Trust};
use stub::{connect, formed, with_view, Evil, Stub};

fn main() {
    with_view(|view| {
        let evil: Evil = Stub(());
        let valid = validate(formed(), &evil, &RuleSet::GENESIS, &Trust::UNANCHORED)
            .unwrap()
            .unwrap();
        connect(&view, valid); // ChainValid<Evil> ≠ ChainValid<View>
    });
}
