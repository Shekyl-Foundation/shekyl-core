// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet-side FCMP++ curve-tree client.
//!
//! Reconstructs the FCMP++ output curve tree locally from synced blocks
//! and assembles membership paths for spends — without telling the daemon
//! which output a wallet is proving against (`00-mission.mdc` priority 2).
//! Client-side assembly closes the *query* channel: a fetched path names
//! the output to the daemon. The *on-chain* channel — `PL-D1`, where the
//! pre-`PL-D3` leaf's 4th scalar republished a value every spend reveals
//! (`docs/design/FCMP_SPEND_LINKABILITY.md`) — is closed by `PL-D3`'s
//! blinded leaf commitment, opened in-circuit. An output-blind spend needs
//! both closed, so assembly stays client-side. The reconstructed
//! root must byte-equal the consensus root the
//! daemon commits in each block header, so the derivation replicates the
//! daemon's leaf-stream logic bit-exactly.
//!
//! ## Layering
//!
//! This is a lean, public-material-only crate. It depends on
//! `shekyl-fcmp` (the curve-tree composition primitives, shared with the
//! daemon through FFI) and `shekyl-consensus` (consensus maturity constants).
//! It deliberately does **not** depend on `shekyl-scanner`: the
//! `tx_extra 0x07` parse is owned by `shekyl_scanner::extra::Extra` and
//! runs at the block-decode boundary ([`client`], CT-3); this crate
//! consumes the parsed blob and owns only the post-parse validation
//! ([`recon::extract_leaf_commitments`]). No secret material enters this
//! crate (`35-secure-memory.mdc`, `36-secret-locality.mdc`).
//!
//! ## Modules (see `docs/design/CURVE_TREE_CLIENT.md`)
//!
//! - [`types`]: public data types (no secrets).
//! - [`recon`]: block-derived leaf reconstruction — the S1 index rule,
//!   the leaf-skip predicate, `tx_extra 0x07` validation (refusal on a
//!   bad payload or point, no fallback), maturity, drain order, and the
//!   Round-1 root oracle (`build_layers`). Pinned against
//!   `docs/design/CT2_DRAIN_ORDER.md`.
//! - [`store`]: frozen sub-root (`R_k`) cache / `build_upper_layers` hot
//!   path (CT-1, gated behind the CT-2 KAT baseline).
//! - [`assemble`]: membership-path assembly (CT-4).
//! - [`client`]: orchestration over synced blocks (CT-3).
//! - [`reference`](mod@reference): reference-block selection + proof
//!   validity-horizon arithmetic (§5), pure functions over heights.
//! - [`serving_route`]: the archival serving route's shared grammar —
//!   virtual port, route, header set, request-header codec — read by
//!   both `shekyl-p-serve` and `shekyl-p-fetch` so neither depends on
//!   the other (`SF-D4`). The onion hostname is not grammar: it lives
//!   in `shekyl-onion-v3`, typed on the daemon as
//!   `shekyl-p-fetch::ServingEndpoint`.

#![deny(unsafe_code)]

pub mod assemble;
pub mod client;
pub mod recon;
pub mod reference;
pub mod segment;
pub mod served_frame;
pub mod serving_route;
pub mod store;
pub mod types;

pub use client::{
    BlockLeaves, ClientError, CurveTreeClient, RawOutput, TxLeafInputs, WriterRecovery,
};
pub use reference::{
    proof_expired, proof_submittable, reference_block_age, select_reference_height,
    should_reanchor, two_sided_reference_height, TwoSidedRefusal, PROOF_VALIDITY_HORIZON,
    REBUILD_AT, REFERENCE_BLOCK_MAX_AGE, REFERENCE_BLOCK_MIN_AGE, REF_ANCHOR_AGE,
};
pub use segment::{
    leaves_per_segment, outputs_per_node, segment_freeze_eligible, SegmentId, LEAF_BYTES,
    SEGMENT_FREEZE_REORG_MARGIN_BLOCKS, SEGMENT_LAYER_J, SPENDABLE_AGE_BLOCKS,
};
pub use served_frame::{ServedFrameError, ServedFrameField, ServedFrameHeader};
pub use store::{
    mixed_composition_root, recompute_segment_r_k, FrozenSegmentBody, FrozenSegmentRecord,
    LeafStore, MixedRootError, PostureDeclaration, SegmentPin, ServingReader, StoreError,
};
pub use types::{
    AssembleInput, AssembledPath, BlockHash, BlockHeight, ChunkLeaf, CommitmentBytes,
    CurveTreeRoot, Gindex, LeafEntry, OneTimePubkey, OutputIdentity, ReferenceBlock, TargetKind,
    TreeContext, TreePosition,
};
