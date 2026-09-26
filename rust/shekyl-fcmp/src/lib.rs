// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl FCMP++ wrapper crate.
//!
//! Wraps the first-party `shekyl-fcmp-proofs` crate (the FCMP++ SAL/membership
//! proof system) with Shekyl-specific extensions: 4-scalar curve tree leaves
//! `{O.x, I.x, C.x, CM.x}`, Shekyl domain separators, and per-output PQC
//! leaf-commitment integration.

#![deny(unsafe_code)]

#[cfg(feature = "multisig")]
pub mod frost_dkg;
#[cfg(feature = "multisig")]
pub mod frost_sal;
pub mod leaf;
pub mod proof;
pub mod tree;

pub use leaf::{PqcKeyScalar, PqcLeafScalar, ShekylLeaf};
#[cfg(feature = "multisig")]
pub use proof::ProveInputLeafChunk;
pub use proof::{BranchLayer, ProveError, ProveInput, ProveResult, ShekylFcmpProof, VerifyError};
pub use tree::{
    construct_leaf, ed25519_point_to_selene_scalar, HashGrowResult, HashTrimResult, LayerUpdate,
    TreeOp, HELIOS_CHUNK_WIDTH, LEAF_CHUNK_SCALARS, SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH,
};

pub use shekyl_fcmp_proofs::sal::SpendAuthAndLinkability;
pub use shekyl_fcmp_proofs::{Input, Output};

// Consensus domain constants live in `shekyl-crypto-pq` (SA-3a): the PQC
// leaf-key customization at `shekyl_crypto_pq::leaf_commitment::DOMAIN_PQC_LEAF_KEY`,
// the KEM salt at `shekyl_crypto_pq::kem::KEM_DOMAIN_SALT`.
pub use shekyl_crypto_pq::leaf_commitment::PQC_LEAF_ENTRY_LEN;

/// Maximum inputs per FCMP++ transaction (bounds proof gen time and tx size).
pub const MAX_INPUTS: usize = 8;

/// Maximum tree depth the protocol supports.
///
/// With Selene chunk width 38 and Helios chunk width 18, a depth-24 tree
/// can index over 10^30 outputs -- far beyond any realistic anonymity set
/// even at Bitcoin-scale adoption. This bound prevents unreasonable
/// resource consumption during proving and caps proof size.
pub const MAX_TREE_DEPTH: u8 = 24;
