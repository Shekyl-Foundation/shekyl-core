//! Archival retention's consensus primitives: the bond records and their
//! wire, the secret draw, the bundle a block carries and its admission
//! inputs, the settlement fold, the emission claim, and the pass transcript
//! a persona's receipt key signs (`ARCHIVAL_SERVE_CREDIT_SPEC.md`).
//!
//! # Crate posture
//!
//! - **Pure, verify-side.** Nothing here reads a store or writes one: the
//!   validator (`shekyl-chain-rules`) and the store (`shekyl-chain-store`)
//!   call these functions with the values they hold.
//! - **Public material only.** Every input is on-chain public data; no
//!   secrets in this crate (`35-secure-memory.mdc`).
//!
//! # Public surface (selected)
//!
//! - [`drawable_pair`] — one drawable `(P, s)` pair. The public urn that
//!   scheduled these pairs is deleted; the secret draw replaces it.
//! - [`constants`] — genesis-pinned challenge counts and seal offset.
//! - [`wire`] — the exact-length rule the bond-post and emission readers
//!   share.
//! - [`secret_draw`] — the secret draw: selection, the `0x0C` commitment,
//!   the challenge nonce, the bundle commitment, and the count rule
//!   (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §4, §5.2, §7.3).
//! - [`bundle`] — the bundle: the pass bitmap, the kept and prunable parts,
//!   the reference a block carries, the bundle commitment, the prunable
//!   hash, the header root, and the section budget
//!   (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7), read by bundle admission in
//!   `shekyl-chain-rules`.
//! - [`drawable_epoch`] — one epoch's drawable pairs and each persona's
//!   receipt key, as one value (§9.6). The name is [`DrawableEpoch`], not a
//!   snapshot: `shekyl-chain-rules` already calls its emission gather
//!   `EpochSnapshot`.
//! - [`settlement_select`] — settlement's fold: three counted draws by beacon, the pair's
//!   row, and the issued-draw digest term.
//! - [`pass_anchor`] — the pass transcript and the receipt verify
//!   ([`verify_receipt_transcript`]).
//! - [`shard_view_hash`] — `SV-D1`'s view hash of a `W`-byte shard: the
//!   streaming [`ShardViewHasher`] over each in-domain transaction's prunable
//!   region and `pqc_auths`. Not a verification digest; never a skeleton row.
//!
//! KAT: pass-transcript vectors in `tests/pass_transcript_kat.rs`.

#![deny(unsafe_code)]

pub mod admission;
pub mod bond_connect;
pub mod bond_ct_balance;
pub mod bond_duration;
pub mod bond_floor;
pub mod bond_post;
pub mod bond_wire;
pub mod bundle;
pub mod claimed_epochs;
pub mod consensus_state;
pub mod conservation;
pub mod constants;
pub mod debit_auth;
pub mod distinct;
pub mod drawable_epoch;
pub mod drawable_pair;
pub mod emission_auth;
pub mod emission_kat_shape;
pub mod emission_verify;
pub mod emission_wire;
pub mod failure_window;
pub mod hash;
pub mod held_at_height;
pub mod id;
pub mod params;
pub mod pass_anchor;
pub mod release_cooldown;
pub mod reward_arithmetic;
pub mod secret_draw;
pub mod segment_freeze;
pub mod settlement_select;
pub mod shard_coverage;
pub mod shard_view_hash;
pub mod support_draw;
pub mod wire;

pub use admission::codes as admission_codes;
pub use admission::{
    admission_code_cstr, admission_code_static_str, check_admission, check_admission_of,
    credited_work_at_admission, parent_state_shards_from_gather, AdmissionError, AdmissionShard,
    ParentStateHoldings, ADMISSION_MIN_WORK_MILLI,
};
pub use bond_connect::{
    clean_interval_close, is_clean_interval_close, reinstate_connect, release_connect,
    slash_open_interval_to_append, ReinstateConnect, ReinstateConnectError, ReleaseConnect,
    ReleaseConnectError, MAX_BOND_BAD_INTERVALS,
};
pub use bond_ct_balance::{
    verify_bond_post_ct_balance, BondCtBalanceError, BondTerm, BondTermError,
};
pub use bond_duration::{bond_duration, ShardAgeAtAdd};
pub use bond_floor::{
    bond_floor, ARCHIVAL_BOND_FLOOR_ATOMIC, ARCHIVAL_PASS_ANCHOR_LAG_BLOCKS,
    ARCHIVAL_REORG_DEPTH_BLOCKS, ARCHIVAL_REWARD_AGE_WEIGHT_MILLI, BOND_DURATION_AGE_SCALE,
    BOND_DURATION_BASE_EPOCHS, MAX_CLAIM_AGE_W, RELEASE_COOLDOWN_EPOCHS,
};
pub use bond_post::{
    bond_post_block_unique, bond_post_funding_floor_met, release_pre_cooldown_guards,
    release_vin_statics, verify_join_market_bond_post, verify_reinstate_bond_post,
    verify_release_bond_post, BondPostError,
};
pub use bond_wire::{
    encode_holdings_descriptor, ArchivalBondPostVin, BondKind, BondPostKind, HoldingsDescriptor,
    HoldingsKind, HoldingsKindScan, LastServedScan, ShardSet, ShardSetError,
    WireError as BondWireError, ENDPOINT_BYTES, HYBRID_PUBKEY_CANONICAL_BYTES, MAX_HOLDINGS_SHARDS,
    VIN_TYPE_ARCHIVAL_BOND_POST,
};
pub use bundle::{
    assemble_bundle, bundle_charge, bundle_commitment, bundle_prunable_hash, bundle_root,
    empty_bundle_root, section_budget, section_d_max, sign_bundle_commitment, BodyRefused,
    BundleBody, BundleKept, BundleRecord, BundleRef, BundleWireError, CarriedBodies, PassBitmap,
    SectionBudget, TooManyReferences, BUNDLE_COMMITMENT, BUNDLE_KEPT_FIXED_LEN,
    BUNDLE_PRUNABLE_CUSTOMIZATION, BUNDLE_RECORD_LEN, BUNDLE_REF_FIXED_LEN,
    BUNDLE_ROOT_CUSTOMIZATION, BUNDLE_SEED_LEN, BUNDLE_SIGNATURE_LEN, BUNDLE_WITNESS_KEY_LEN,
    BUNDLE_WITNESS_LEN,
};
pub use claimed_epochs::{
    claim_window_floor, claimed_epochs_check_and_set, claimed_epochs_contains,
    emission_block_claims_unique, epoch_is_claim_expired, epoch_is_not_settled, ClaimedEpochsError,
    MAX_CLAIMED_EPOCH_ENTRIES,
};
pub use consensus_state::{
    as_of_e_served_work, credited_work_milli, epoch_close_compute, epoch_close_due_at_height,
    epoch_close_height, good_through, last_settled_epoch_as_of_parent, prune_below_epoch_at_height,
    r_market_count, settlement_epoch_at_height, settlement_epoch_last_block,
    settlement_epoch_open_height, shard_age_milli, shard_contribution_micro, shard_work_micro,
    sigma_work_milli, BadInterval, CreditIndexOutOfRange, CreditPair, EpochCloseBond,
    EpochCloseInputs, EpochCloseResult, EpochCloseShard, ServeCreditRow, ServedWork,
    SettlementEpochBlocks, SettlementSchedule, ShardClose, ShardCloseWire,
    FOUNDATION_EXCLUDED_FROM_MARKET,
};
pub use conservation::{verify_conservation_snapshot, ConservationError, ConservationSnapshot};
pub use constants::{
    arm_settlement_epoch_override, arm_settlement_epoch_override_for_regtest,
    check_settlement_epoch_override, effective_archival_reorg_depth_blocks,
    effective_settlement_epoch_blocks, parse_reorg_cap_override, parse_settlement_epoch_override,
    settlement_epoch_override_floor, settlement_epoch_override_ignored,
    settlement_epoch_override_present, SettlementEpochOverrideError, CHALLENGE_RESPONSE_BLOCKS,
    SETTLEMENT_EPOCH_BLOCKS, SLASH_GRACE_EPOCHS,
};
pub use debit_auth::{
    cold_authority_pin, debit_auth_pin, requires_cold_authority, ColdAuthorityError, DebitAuthError,
};
pub use drawable_epoch::{
    DrawableEpoch, DrawableEpochError, SupportRoster, DRAWABLE_EPOCH_DIGEST_CUSTOMIZATION,
};
pub use drawable_pair::DrawablePair;
pub use emission_kat_shape::{EmissionKatShape, EMISSION_KAT_SHAPE};
pub use emission_verify::{
    claimant_reward_share, emission_vin_verify, emission_vin_verify_auth,
    emission_vin_verify_backing, emission_vin_verify_claims, emission_vin_verify_claims_under,
    epoch_is_before_join, AuthVerified, BackingVerified, ClaimantBondRecord, ClaimantShare,
    ClaimantShareError, ClaimsVerified, EmissionEpochSource, EmissionVerified,
    EmissionVerifyContext, EmissionVerifyError,
};
pub use pass_anchor::{
    anchor_depth_covers_response_window, pass_countersignature_message, pass_delivery_digest,
    pass_request_header_bytes, response_window_outrunning_anchor, verify_receipt_transcript,
    PassDeliveryHasher, PassRequestHeader, PassStream, PassTranscript, ReceiptRefused,
    PASS_ANCHOR_DEPTH_BLOCKS, PASS_ANCHOR_HASH_LEN, PASS_ANCHOR_HEIGHT_LEN, PASS_ANCHOR_LAG_BLOCKS,
    PASS_COUNTERSIGNATURE_MESSAGE_LEN, PASS_DELIVERY_DIGEST_CUSTOMIZATION,
    PASS_DELIVERY_DIGEST_LEN, PASS_NONCE_LEN, PASS_REQUEST_HEADER_LEN,
};
pub use shekyl_types::archival::{ReceiptSignPk, RECEIPT_SIGN_PK_LEN};
// The emission and bond-post errors are re-exported under disambiguated names,
// so no crate-root `WireError` resolves to the wrong module's error.
pub use emission_wire::{
    ArchivalRewardEmissionVin, EmissionAuthMsgs, EmissionAuthRole, MembershipOnlyBacking,
    RewardCommit, ShardWorkEntry, WireError as EmissionWireError, WorkEpochClaim,
    EMISSION_AUTH_BACKING, EMISSION_AUTH_CLAIM, MAX_BACKING_PROOF_BYTES,
    MAX_SETTLEMENT_EPOCHS_PER_EMISSION, VIN_TYPE_ARCHIVAL_REWARD_EMISSION,
};
pub use failure_window::{
    failure_window_slashable, settlement_retention_floor, settlement_window_slashable,
    BaselineObservation, FailureWindowError, FAILURE_WINDOW_M, FAILURE_WINDOW_N,
    FAILURE_WINDOW_N_GATHER_BOUND, FAILURE_WINDOW_SERVE_BUDGET, SETTLEMENT_RETENTION_EPOCHS,
    SLASH_SETTLEMENT_TIP_LAG_EPOCHS, WINDOW_MIN_OBSERVATION_PER_MILLE,
};
pub use held_at_height::holds_shard_at;
pub use id::{p_canonical_id_from_hybrid_pubkey, P_CANONICAL_ID_CUSTOMIZATION};
pub use params::{archival_params, ArchivalParams, ArchivalParamsError};
pub use release_cooldown::{release_cooldown_elapsed, whole_record_last_served};
pub use reward_arithmetic::{
    curve_milli, g_age_milli, mul_div_floor, reward_share_floor, scarcity_micro,
    work_milli_from_micro, BandedCurveParams, WORK_MICRO_PER_MILLI, WORK_MICRO_SCALE,
    WORK_MILLI_SCALE,
};
pub use secret_draw::{
    challenge_nonce, draw_commit, draw_count, draw_horizon, draw_target, select_draw, DrawTarget,
    SelectedDraw, CHALLENGE_NONCE_CUSTOMIZATION, CHALLENGE_READS, DRAW_ATTEMPTS,
    DRAW_COMMIT_CUSTOMIZATION, DRAW_CUSTOMIZATION,
};
pub use segment_freeze::SEGMENT_LEAF_COUNT;
pub use shard_coverage::{
    join_scarcity_micro, order_shard_coverage, ShardCoverageIn, ShardCoverageOut,
};
pub use shard_view_hash::{
    shard_view_hash, ArchivalTx, ShardViewHasher, SHARD_VIEW_HASH_CUSTOMIZATION,
};
pub use support_draw::{
    select_support_shard, settle_support, support_challenge_nonce, support_counted, support_offset,
    support_seated_at, support_slot, support_span, SupportSettlementKey, SupportUnissued,
    SUPPORT_CHALLENGE_NONCE_CUSTOMIZATION, SUPPORT_DRAWS_PER_EPOCH, SUPPORT_DRAW_CUSTOMIZATION,
    SUPPORT_SELECT_SHARD,
};
