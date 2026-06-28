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

pub mod bond_floor;
pub mod bond_post;
pub mod bond_rct_balance;
pub mod bond_wire;
pub mod challenge;
pub mod claimed_epochs;
pub mod consensus_state;
pub mod conservation;
pub mod constants;
pub mod error;
pub mod hash;
pub mod id;
pub mod path;
pub mod reward_arithmetic;
pub mod serve_eligibility;
pub mod wire;

pub use bond_floor::{
    bond_floor, ARCHIVAL_BOND_FLOOR_ATOMIC, ARCHIVAL_REORG_DEPTH_BLOCKS,
    ARCHIVAL_REWARD_AGE_WEIGHT_MILLI, ARCHIVAL_REWARD_PLATEAU_VALUE_MILLI,
    ARCHIVAL_REWARD_PLATEAU_WORK_MILLI, MAX_CLAIM_AGE_W,
};
pub use bond_post::{verify_join_market_bond_post, BondPostError};
pub use bond_rct_balance::{verify_bond_post_rct_balance, BondRctBalanceError};
pub use bond_wire::{
    encode_holdings_descriptor, ArchivalBondPostVin, BondPostKind, HoldingsDescriptor,
    HoldingsKind, BOND_POST_SIG_CUSTOMIZATION, VIN_TYPE_ARCHIVAL_BOND_POST,
};
pub use challenge::{
    challenge_fire_height, challenge_leaf_index, challenge_seal_height,
    CHALLENGE_FIRE_CUSTOMIZATION, CHALLENGE_LEAF_CUSTOMIZATION,
    SERVE_CREDIT_RESPONSE_CUSTOMIZATION,
};
pub use claimed_epochs::{
    claim_window_floor, claimed_epochs_check_and_set, claimed_epochs_contains,
    epoch_is_claim_expired, ClaimedEpochsError, MAX_CLAIMED_EPOCH_ENTRIES,
};
pub use consensus_state::{
    epoch_close_compute, epoch_close_due_at_height, good_through, market_member_at_epoch,
    prune_below_epoch_at_height, r_market_count, settlement_epoch_at_height, shard_age_milli,
    shard_work_milli, sigma_work_milli, BadInterval, CreditIndexOutOfRange, CreditPair,
    EpochCloseBond, EpochCloseInputs, EpochCloseResult, EpochCloseShard, ServeCreditRow,
    FOUNDATION_EXCLUDED_FROM_MARKET,
};
pub use conservation::{verify_conservation_snapshot, ConservationError, ConservationSnapshot};
pub use constants::{
    CHALLENGES_PER_EPOCH, CHALLENGE_BEACON_SEAL_BLOCKS, CHALLENGE_RESOLUTION_BLOCKS,
    CHALLENGE_RESPONSE_BLOCKS, SETTLEMENT_EPOCH_BLOCKS,
};
pub use error::VerifyError;
pub use id::{p_canonical_id_from_hybrid_pubkey, P_CANONICAL_ID_CUSTOMIZATION};
pub use path::{verify_leaf_index, verify_segment_path, SegmentPathOpening};
pub use reward_arithmetic::{
    curve_milli, g_age_milli, mul_div_floor, reward_share_floor, scarcity_milli, BandedCurveParams,
    WORK_MILLI_SCALE,
};
pub use serve_eligibility::serve_credit_epoch_ok;
pub use wire::{
    encode_path, ArchivalServeCreditResponse, WireError, VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE,
};
