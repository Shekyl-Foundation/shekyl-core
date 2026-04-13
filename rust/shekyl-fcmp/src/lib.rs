// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl FCMP++ wrapper crate.
//!
//! Wraps the upstream `shekyl-fcmp-plus-plus` crate with Shekyl-specific
//! extensions: 4-scalar curve tree leaves `{O.x, I.x, C.x, H(pqc_pk)}`,
//! Shekyl domain separators, and per-output PQC commitment integration.

#![deny(unsafe_code)]

pub mod leaf;
pub mod tree;
pub mod proof;
#[cfg(feature = "multisig")]
pub mod frost_sal;
#[cfg(feature = "multisig")]
pub mod frost_dkg;

pub use leaf::{PqcLeafScalar, ShekylLeaf};
pub use tree::{
    TreeOp, HashGrowResult, HashTrimResult, LayerUpdate,
    SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH, HELIOS_CHUNK_WIDTH, LEAF_CHUNK_SCALARS,
    ed25519_point_to_selene_scalar, construct_leaf,
};
pub use proof::{ShekylFcmpProof, ProveError, VerifyError, ProveResult, ProveInput, BranchLayer};
#[cfg(feature = "multisig")]
pub use proof::ProveInputLeafChunk;

pub use shekyl_fcmp_plus_plus::{Input, Output};
pub use shekyl_fcmp_plus_plus::sal::SpendAuthAndLinkability;

/// Domain separator for Shekyl's PQC leaf hash: H(pqc_pk) -> 4th scalar.
pub const DOMAIN_PQC_LEAF: &[u8] = b"shekyl-pqc-leaf";

/// Domain separator for KEM shared-secret derivation.
pub const DOMAIN_KEM_V1: &[u8] = b"shekyl-kem-v1";

/// Maximum inputs per FCMP++ transaction (bounds proof gen time and tx size).
pub const MAX_INPUTS: usize = 8;

/// Maximum tree depth the protocol supports.
///
/// With Selene chunk width 38 and Helios chunk width 18, a depth-24 tree
/// can index over 10^30 outputs -- far beyond any realistic anonymity set
/// even at Bitcoin-scale adoption. This bound prevents unreasonable
/// resource consumption during proving and caps proof size.
pub const MAX_TREE_DEPTH: u8 = 24;
