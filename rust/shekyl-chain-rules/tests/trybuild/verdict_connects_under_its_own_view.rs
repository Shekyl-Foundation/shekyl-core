// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The positive control for the two `compile_fail` fixtures beside it: a
//! verdict judged against a view **does** connect under that same view.
//! Without this, a stub that no longer implements `ChainView` would make
//! the other two fail to compile for a reason that has nothing to do with
//! the brand, and their snapshots would be the only thing noticing.
//!
//! Compiled, not run: `program` is never called, since `formed()` has no
//! block to hand back.

#[path = "stub_view.rs"]
mod stub;

use shekyl_chain_rules::{validate, RuleSet, Trust};
use stub::{connect, formed, with_view};

#[allow(dead_code)]
fn program() {
    with_view(|view| {
        let valid = validate(formed(), &view, &RuleSet::GENESIS, &Trust::UNANCHORED)
            .unwrap()
            .unwrap();
        connect(&view, valid);
    });
}

fn main() {}
