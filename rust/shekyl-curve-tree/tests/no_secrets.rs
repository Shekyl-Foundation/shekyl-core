// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Structural no-secrets invariant for the public surface.
//!
//! Every public type in `shekyl-curve-tree` carries only public on-chain
//! material and is therefore `Copy`. A secret-bearing type would be
//! non-`Copy` (it must wipe on drop, per `35-secure-memory.mdc`), so
//! `Copy` is a compile-time witness that no secret rides in these types.
//! If a future change makes one of these non-`Copy`, that is a signal a
//! secret has leaked into the curve-tree client — it belongs behind the
//! engine boundary (`36-secret-locality.mdc`), not here.

use shekyl_curve_tree::{LeafEntry, OutputIdentity, ReferenceBlock, TargetKind};

fn assert_copy<T: Copy>() {}

#[test]
fn public_types_are_non_secret_copy() {
    assert_copy::<TargetKind>();
    assert_copy::<OutputIdentity>();
    assert_copy::<LeafEntry>();
    assert_copy::<ReferenceBlock>();
}
