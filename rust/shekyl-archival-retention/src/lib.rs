//! Archival serve-credit verification primitives.
//!
//! Consensus-facing replay of epoch challenges and Merkle openings to frozen
//! segment sub-roots `R_k`, per
//! [`docs/design/ARCHIVAL_RETENTION_GATE2.md`](../../docs/design/ARCHIVAL_RETENTION_GATE2.md).
//!
//! # Crate posture
//!
//! - **Verify-only at genesis.** Challenge derivation, path replay, and leaf-index
//!   checks live here; vin deserialization and LMDB bit writes land in consensus /
//!   engine crates (gate-2 §10).
//! - **Public material only.** Leaf bytes and path siblings are on-chain public
//!   inputs; no secrets in this crate (`35-secure-memory.mdc`).
//!
//! # Public surface
//!
//! - [`challenge`] — `challenge_leaf_index`, `challenge_fire_height`, domain labels.
//! - [`path`] — [`SegmentPathOpening`], [`verify_segment_path`] (requires the
//!   Selene leaf-layer chunk scalars for the challenged output's parent node).
//! - [`constants`] — genesis-pinned challenge counts and seal offset.
//! - [`wire`] — byte-exact `txin_archival_serve_credit_response` encode/decode.
//!
//! KAT: `tests/fixtures/gate2_serve_credit_kat_v1.json` (regenerate with
//! `cargo test -p shekyl-archival-retention regenerate_gate2_kat_fixture -- --ignored`).

#![deny(unsafe_code)]

pub mod bond_wire;
pub mod challenge;
pub mod constants;
pub mod error;
pub mod hash;
pub mod id;
pub mod path;
pub mod wire;

pub use challenge::{
    challenge_fire_height, challenge_leaf_index, challenge_seal_height,
    CHALLENGE_FIRE_CUSTOMIZATION, CHALLENGE_LEAF_CUSTOMIZATION,
    SERVE_CREDIT_RESPONSE_CUSTOMIZATION,
};
pub use constants::{
    CHALLENGES_PER_EPOCH, CHALLENGE_BEACON_SEAL_BLOCKS, CHALLENGE_RESOLUTION_BLOCKS,
    CHALLENGE_RESPONSE_BLOCKS, SETTLEMENT_EPOCH_BLOCKS,
};
pub use error::VerifyError;
pub use path::{verify_leaf_index, verify_segment_path, SegmentPathOpening};
pub use bond_wire::{
    encode_holdings_descriptor, ArchivalBondPostVin, BondPostKind, HoldingsDescriptor, HoldingsKind,
    BOND_POST_SIG_CUSTOMIZATION, VIN_TYPE_ARCHIVAL_BOND_POST,
};
pub use id::{p_canonical_id_from_hybrid_pubkey, P_CANONICAL_ID_CUSTOMIZATION};
pub use wire::{
    encode_path, ArchivalServeCreditResponse, WireError, VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE,
};
