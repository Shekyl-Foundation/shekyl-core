// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl FCMP++ wrapper crate.
//!
//! Wraps the upstream `monero-fcmp-plus-plus` crate with Shekyl-specific
//! extensions: 4-scalar curve tree leaves `{O.x, I.x, C.x, H(pqc_pk)}`,
//! Shekyl domain separators, and per-output PQC commitment integration.

#![deny(unsafe_code)]

pub mod leaf;
pub mod tree;
pub mod proof;

pub use leaf::{PqcLeafScalar, ShekylLeaf};
pub use tree::{
    TreeOp, HashGrowResult, HashTrimResult, LayerUpdate,
    SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH, HELIOS_CHUNK_WIDTH, LEAF_CHUNK_SCALARS,
    ed25519_point_to_selene_scalar, construct_leaf,
};
pub use proof::{ShekylFcmpProof, ProveError, VerifyError};

/// Domain separator for Shekyl's PQC leaf hash: H(pqc_pk) -> 4th scalar.
pub const DOMAIN_PQC_LEAF: &[u8] = b"shekyl-pqc-leaf";

/// Domain separator for KEM shared-secret derivation.
pub const DOMAIN_KEM_V1: &[u8] = b"shekyl-kem-v1";

/// Domain separator for per-output PQC keypair derivation.
pub const DOMAIN_PQC_OUTPUT: &[u8] = b"shekyl-pqc-output";

/// Maximum inputs per FCMP++ transaction (bounds proof gen time and tx size).
pub const MAX_INPUTS: usize = 8;
