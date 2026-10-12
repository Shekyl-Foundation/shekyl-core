// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `AltValid<'id, A>` is not `AltValid<'id, B>`.
//!
//! The store's `insert_alt_block` names its `AltView`. A verdict minted
//! against any other view — this stand-in, a second store — does not
//! unify with that argument. Same belt as `ChainValid` (G4): the view
//! type is the brand, and the trait cannot be sealed because the store,
//! a downstream crate, is the implementor.

use shekyl_chain_rules::AltValid;

struct StoreAlt;
struct OtherAlt;

fn insert_into_store(_: AltValid<'static, StoreAlt>) {}

/// Diverges. The value is never built — the fields are private — and the
/// call below is still type-checked.
fn judged_elsewhere() -> AltValid<'static, OtherAlt> {
    loop {}
}

fn main() {
    insert_into_store(judged_elsewhere());
}
