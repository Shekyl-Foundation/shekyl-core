// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The support-stream preimage pins.
//!
//! The economy vectors stay in [`super`]. These are the figures a support
//! bit adds: the twelve-draw commitment and root with support draw 0 set,
//! and the two root preimages this encoding must not revive. Produced by
//! `docs/test_vectors/RPC_CHANNEL_NAMES_V1/generate.py`, whose `cshake256`
//! shares no code with this crate. Do not recompute them here.

use super::{
    body, bundle_commitment, hex, kept_at, records_bytes, root, vector_refs, BundleKept, BundleRef,
    PassBitmap, H, SEED,
};

/// The twelve-draw vector with support draw 0 also set. The support
/// bitmap is one byte, bit 0.
fn twelve_with_one_support() -> BundleKept {
    BundleKept {
        h: H,
        seed: SEED,
        passes: PassBitmap::new(12, &[0x01, 0x0A]).expect("twelve draws"),
        support: PassBitmap::from_passes(1, [0]).expect("support draw 0"),
    }
}

/// The commitment covers the support count and its bitmap. Red edit:
/// leave the support count out of `BundleKept::encode`.
#[test]
fn a_support_bit_is_in_the_commitment_preimage() {
    let three = records_bytes(3);
    let supported = twelve_with_one_support();
    assert_eq!(
        hex(&bundle_commitment(&supported, &three)),
        "f626f6c4af284f660f45679bd3c8126f9d3ddc914e80f3649ca9ad020f31a16d"
    );
    assert_ne!(
        bundle_commitment(&kept_at(H, 12, &[0x01, 0x0A]), &three),
        bundle_commitment(&supported, &three),
        "a support bit is in the preimage"
    );
}

/// The header root covers the support count and its bitmap. Red edit:
/// leave the support count out of a reference.
#[test]
fn a_support_bit_is_in_the_root_preimage() {
    let supported = BundleRef::new(twelve_with_one_support(), body(3).prunable_hash());
    assert_eq!(
        hex(&root(std::slice::from_ref(&supported))),
        "88824ae7bd5dec403bcfc29f02abf4ecc83358e5b2d20f69051d3aa54736a532"
    );
    let (first, second) = vector_refs();
    let base = root(&[first.clone(), second.clone()]);
    let ph = *first.prunable_hash();
    assert_ne!(
        base,
        root(&[BundleRef::new(twelve_with_one_support(), ph), second]),
        "a support bit is in the preimage"
    );
}

/// The root preimages from before the support count are not this encoding.
/// The figures are the two controls the support-count encoding replaced.
/// Red edit: drop the support count from a reference.
#[test]
fn the_pre_support_root_preimage_is_not_this_encoding() {
    let (first, second) = vector_refs();
    assert_ne!(
        hex(&root(&[first.clone(), second])),
        "1db7631e56a63be2081de642b80c1401e19f90f51fcc4f3ab4206e614c4316f4",
        "n counts references, not bytes"
    );
    assert_ne!(
        hex(&root(std::slice::from_ref(&first))),
        "ccceabe7d4795393ca05afc36ca0c35b0dbfac365eff1f47c4c6fcec4edbc04c",
        "n is hashed"
    );
}
