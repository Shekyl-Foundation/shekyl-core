// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet-side FCMP++ curve-tree client.
//!
//! Reconstructs the FCMP++ output curve tree locally from synced blocks
//! and assembles membership paths for spends — without revealing which
//! output a wallet is proving against (the privacy reason the path is
//! assembled client-side rather than fetched, `00-mission.mdc` priority
//! 2). The reconstructed root must byte-equal the consensus root the
//! daemon commits in each block header, so the derivation replicates the
//! daemon's leaf-stream logic bit-exactly.
//!
//! ## Layering
//!
//! This is a lean, public-material-only crate. It depends on
//! `shekyl-fcmp` (the curve-tree composition primitives, shared with the
//! daemon through FFI) and `shekyl-oxide` (consensus maturity constants).
//! It deliberately does **not** depend on `shekyl-scanner`: the
//! `tx_extra 0x07` parse is owned by `shekyl_scanner::extra::Extra` and
//! runs at the block-decode boundary ([`client`], CT-3); this crate
//! consumes the parsed blob and owns only the post-parse validation
//! ([`recon::extract_leaf_hashes`]). No secret material enters this
//! crate (`35-secure-memory.mdc`, `36-secret-locality.mdc`).
//!
//! ## Modules (see `docs/design/CURVE_TREE_CLIENT.md`)
//!
//! - [`types`]: public data types (no secrets).
//! - [`recon`]: block-derived leaf reconstruction — the S1 index rule,
//!   the leaf-skip predicate, `tx_extra 0x07` validation, `h_pqc`
//!   fallback, maturity, drain order, and the Round-1 root oracle
//!   (`build_layers`). Pinned against `docs/design/CT2_DRAIN_ORDER.md`.
//! - [`store`]: frozen sub-root (`R_k`) cache / `build_upper_layers` hot
//!   path (CT-1, gated behind the CT-2 KAT baseline).
//! - [`assemble`]: membership-path assembly (CT-4).
//! - [`client`]: orchestration over synced blocks (CT-3).

#![deny(unsafe_code)]

pub mod assemble;
pub mod client;
pub mod recon;
pub mod store;
pub mod types;

pub use client::{BlockLeaves, ClientError, CurveTreeClient, RawOutput, TxLeafInputs};
pub use types::{
    AssembledPath, ChunkLeaf, LeafEntry, OutputIdentity, ReferenceBlock, TargetKind, TreeContext,
};
