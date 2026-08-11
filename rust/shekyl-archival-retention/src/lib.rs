//! Archival serve-credit and credit-wire verification primitives.
//!
//! Consensus-facing replay of epoch challenges and Merkle openings to frozen
//! segment sub-roots `R_k`, per
//! [`docs/design/ARCHIVAL_RETENTION_GATE2.md`](../../docs/design/ARCHIVAL_RETENTION_GATE2.md),
//! plus the TJ-B step 3 **credit-wire** logic core
//! ([`docs/design/ARCHIVAL_CREDIT_WIRE.md`](../../docs/design/ARCHIVAL_CREDIT_WIRE.md)):
//! settlement fold and admission wire (header / nonce / root / pass verify).
//!
//! # Crate posture
//!
//! - **Verify-only at genesis.** Challenge derivation, path replay, and leaf-index
//!   checks live here; vin deserialization and LMDB bit writes land in consensus /
//!   engine crates (gate-2 §10). Credit-wire C++ block format + FFI land in Plan B.
//! - **Public material only.** Leaf bytes and path siblings are on-chain public
//!   inputs; no secrets in this crate (`35-secure-memory.mdc`).
//!
//! # Public surface
//!
//! - [`challenge`] — `challenge_leaf_index`, `challenge_fire_height`, domain labels.
//! - [`challenge_assignment`] — exact-min derived assignment urn
//!   ([`ChallengeUrn`], [`assign_epoch`]); pure, no wire surface.
//! - [`path`] — [`SegmentPathOpening`], [`verify_segment_path`] (requires the
//!   Selene leaf-layer chunk scalars for the challenged output's parent node).
//! - [`constants`] — genesis-pinned challenge counts and seal offset.
//! - [`wire`] — byte-exact `txin_archival_serve_credit_response` encode/decode.
//! - [`attestation`] — settlement fold over challenge outcome counts (`settle_epoch`, absolute-2).
//! - [`attestation_wire`] — header, nonce, `PassRecord`, root, pass verify.
//!
//! KAT: `tests/fixtures/gate2_serve_credit_kat_v1.json` (regenerate with
//! `cargo test -p shekyl-archival-retention regenerate_gate2_kat_fixture -- --ignored`);
//! credit-wire vectors in `tests/attestation_wire_kat.rs`.

#![deny(unsafe_code)]

pub mod admission;
pub mod attestation;
pub mod attestation_wire;
pub mod bond_connect;
pub mod bond_ct_balance;
pub mod bond_duration;
pub mod bond_floor;
pub mod bond_post;
pub mod bond_wire;
pub mod challenge;
pub mod challenge_assignment;
pub mod claimed_epochs;
pub mod consensus_state;
pub mod conservation;
pub mod constants;
pub mod distinct;
pub mod emission_kat_shape;
pub mod emission_verify;
pub mod emission_wire;
pub mod error;
pub mod failure_window;
pub mod hash;
pub mod id;
pub mod path;
pub mod release_cooldown;
pub mod reward_arithmetic;
pub mod segment_freeze;
pub mod serve_credit_decisions;
pub mod serve_eligibility;
pub mod wire;

pub use admission::codes as admission_codes;
pub use admission::{
    admission_code_cstr, admission_code_static_str, check_admission, check_admission_of,
    credited_work_at_admission, parent_state_shards_from_gather, AdmissionError, AdmissionShard,
    ParentStateHoldings, ADMISSION_MIN_WORK_MILLI,
};
pub use attestation::{settle_epoch, AttestationKind, EpochSettlement, SERVE_THRESHOLD_PASSES};
pub use attestation_wire::{
    attestation_nonce, attestation_root, empty_attestation_root,
    pass_records_from_headers_and_witness, verify_pass_countersignature, AttestationHeader,
    AttestationHeaderError, BlockAttestationWitness, PassRecord, WitnessError, WitnessPairingError,
    ATTESTATION_HEADER_LEN, ATTESTATION_NONCE_CUSTOMIZATION, ATTESTATION_ROOT_CUSTOMIZATION,
    MAX_ATTESTATION_RECORDS, MAX_ATTESTATION_WITNESS_BYTES, WITNESS_PREFIX_LEN,
};
pub use bond_connect::{
    clean_interval_close, holdings_update_add_connect, holdings_update_drop_connect,
    holdings_update_pop, is_clean_interval_close, rebond_connect, rebond_pop,
    slash_open_interval_to_append, unbond_connect, unbond_pop, HoldingsUpdateAddConnect,
    HoldingsUpdateConnectError, HoldingsUpdateDropConnect, HoldingsUpdatePopError, RebondConnect,
    RebondConnectError, RebondPopError, UnbondConnect, UnbondConnectError, UnbondPopError,
    MAX_BOND_BAD_INTERVALS,
};
pub use bond_ct_balance::{verify_bond_post_ct_balance, BondCtBalanceError, BondTerm};
pub use bond_duration::{bond_duration, ShardAgeAtAdd};
pub use bond_floor::{
    bond_floor, ARCHIVAL_BOND_FLOOR_ATOMIC, ARCHIVAL_REORG_DEPTH_BLOCKS,
    ARCHIVAL_REWARD_AGE_WEIGHT_MILLI, BOND_DURATION_AGE_SCALE, BOND_DURATION_BASE_EPOCHS,
    MAX_CLAIM_AGE_W, RELEASE_COOLDOWN_EPOCHS,
};
pub use bond_post::{
    bond_post_block_unique, verify_holdings_update_add, verify_holdings_update_drop,
    verify_join_market_bond_post, verify_rebond_bond_post, verify_unbond_bond_post, BondPostError,
};
pub use bond_wire::{
    encode_holdings_descriptor, ArchivalBondPostVin, BondPostKind, HoldingsDescriptor,
    HoldingsKind, ShardSet, ShardSetError, HYBRID_PUBKEY_CANONICAL_BYTES, MAX_HOLDINGS_SHARDS,
    VIN_TYPE_ARCHIVAL_BOND_POST,
};
pub use challenge::{
    challenge_fire_height, challenge_leaf_index, challenge_seal_height, challenge_seal_on_chain,
    CHALLENGE_FIRE_CUSTOMIZATION, CHALLENGE_LEAF_CUSTOMIZATION,
    SERVE_CREDIT_RESPONSE_CUSTOMIZATION,
};
pub use challenge_assignment::{
    assign_epoch, AssignmentError, ChallengeUrn, DrawablePair, FeedError,
    CHALLENGE_ASSIGNMENT_CUSTOMIZATION,
};
pub use claimed_epochs::{
    claim_window_floor, claimed_epochs_check_and_set, claimed_epochs_contains,
    emission_block_claims_unique, epoch_is_claim_expired, epoch_is_not_settled, ClaimedEpochsError,
    MAX_CLAIMED_EPOCH_ENTRIES,
};
pub use consensus_state::{
    as_of_e_served_work, credited_work_milli, epoch_close_compute, epoch_close_due_at_height,
    epoch_close_height, good_through, last_settled_epoch_as_of_parent, market_member_at_epoch,
    prune_below_epoch_at_height, r_market_count, settlement_epoch_at_height, shard_age_milli,
    shard_contribution_micro, shard_work_micro, sigma_work_milli, BadInterval,
    CreditIndexOutOfRange, CreditPair, EpochCloseBond, EpochCloseInputs, EpochCloseResult,
    EpochCloseShard, ServeCreditRow, ServedWork, FOUNDATION_EXCLUDED_FROM_MARKET,
};
pub use conservation::{verify_conservation_snapshot, ConservationError, ConservationSnapshot};
pub use constants::{
    arm_settlement_epoch_override_for_regtest, effective_settlement_epoch_blocks,
    parse_settlement_epoch_override, settlement_epoch_blocks_overridden,
    settlement_epoch_override_ignored, settlement_epoch_override_present,
    SettlementEpochOverrideError, CHALLENGES_PER_PAIR_PER_EPOCH, CHALLENGE_BEACON_SEAL_BLOCKS,
    CHALLENGE_RESOLUTION_BLOCKS, CHALLENGE_RESPONSE_BLOCKS, SETTLEMENT_EPOCH_BLOCKS,
};
pub use emission_kat_shape::{EmissionKatShape, EMISSION_KAT_SHAPE};
pub use emission_verify::{
    claimant_reward_share, emission_vin_verify, emission_vin_verify_auth,
    emission_vin_verify_backing, emission_vin_verify_claims, epoch_is_before_join, AuthVerified,
    BackingVerified, ClaimantBondRecord, ClaimantShare, ClaimantShareError, ClaimsVerified,
    EmissionEpochSource, EmissionVerified, EmissionVerifyContext, EmissionVerifyError,
};
// The emission error is re-exported under a disambiguated name: the bare
// `WireError` at this root is wire.rs's (serve-credit) type, and bond_wire's is
// deliberately not re-exported — a crate-root import must not silently resolve
// to the wrong module's error.
pub use emission_wire::{
    ArchivalRewardEmissionVin, EmissionAuthMsgs, EmissionAuthRole, MembershipOnlyBacking,
    RewardCommit, ShardWorkEntry, WireError as EmissionWireError, WorkEpochClaim,
    EMISSION_AUTH_BACKING_CUSTOMIZATION, EMISSION_AUTH_CLAIM_CUSTOMIZATION,
    MAX_BACKING_PROOF_BYTES, MAX_SETTLEMENT_EPOCHS_PER_EMISSION, VIN_TYPE_ARCHIVAL_REWARD_EMISSION,
};
pub use error::VerifyError;
pub use failure_window::{
    failure_window_slashable, BaselineObservation, FailureWindowError, FAILURE_WINDOW_M,
    FAILURE_WINDOW_N, FAILURE_WINDOW_SERVE_BUDGET,
};
pub use id::{p_canonical_id_from_hybrid_pubkey, P_CANONICAL_ID_CUSTOMIZATION};
pub use path::{verify_leaf_index, verify_segment_path, SegmentPathOpening};
pub use release_cooldown::{release_cooldown_elapsed, whole_record_last_served};
pub use reward_arithmetic::{
    curve_milli, g_age_milli, mul_div_floor, reward_share_floor, scarcity_micro,
    work_milli_from_micro, BandedCurveParams, WORK_MICRO_PER_MILLI, WORK_MICRO_SCALE,
    WORK_MILLI_SCALE,
};
pub use segment_freeze::{
    challenge_leaf_chunk_bounds, frozen_segment_count, LeafChunkBounds, SEGMENT_LEAF_COUNT,
};
pub use serve_credit_decisions::{
    serve_credit_block_key, serve_credit_block_unique, serve_credit_gate_decision,
    serve_credit_key_be, serve_credit_preblock_duplicate, BlockUniqueVerdict, GateReject,
    GateVerdict, ServeCreditGateInputs, SERVE_CREDIT_KEY_LEN,
};
pub use serve_eligibility::serve_credit_epoch_ok;
pub use wire::{
    encode_path, ArchivalServeCreditResponse, WireError, VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE,
};
