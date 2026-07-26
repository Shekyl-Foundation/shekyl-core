// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pure-Rust mirrors of the three C++ serve-credit consensus decisions
//! (`ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md`; FOLLOWUPS V3.0
//! serve-credit equivalence-audit item).
//!
//! **These functions are audit mirrors, not the decision sites.** The live
//! decisions stay in C++ (`src/cryptonote_core/blockchain.cpp`) until the
//! V3.1 flip; the mirrors reproduce them *as-is* over marshaled inputs so the
//! standing equivalence KAT (`tests/serve_credit_equivalence_kat.rs`, shared
//! fixture `serve_credit_equivalence_kat_v1.json`) can prove behavioral
//! equivalence and hold it against drift. Mirror-then-fix discipline (audit
//! doc §4): a divergence is fixed in C++ first, then re-proven here — the
//! mirror never "improves" the C++ behavior.
//!
//! The three decision sites, at the pinned substrate commit `ca8edce6b`:
//!
//! - **D-SC-A** — per-tx `(P, shard, E)` dedup against pre-block LMDB state
//!   (`blockchain.cpp:4247`; key type `ArchivalServeCreditKey`,
//!   `shekyl_types.h:405–412`, **big-endian** `u64` fields).
//! - **D-SC-B** — the full per-tx acceptance gate
//!   (`check_archival_serve_credit_input`, `blockchain.cpp:4224–4396`),
//!   mirrored **wide**: the ordered predicate sequence returns the first
//!   failing branch. A reorder is a behavior change; the ordering is audited.
//! - **D-SC-C** — block-level cross-tx `(P, shard, E)` uniqueness
//!   (`blockchain.cpp:4889–4910`; keyed with `ArchivalServeCreditKey` — the
//!   same **big-endian** encoding D-SC-A persists, since the SCE-1 unify
//!   commit replaced the original native-endian `memcpy` key, audit doc §6).
//!
//! Single-source rule (audit doc §2.2): predicates that already exist in Rust
//! are *called*, never re-implemented — [`serve_credit_epoch_ok`] (step 4),
//! [`challenge_fire_height`] (step 8), [`challenge_leaf_chunk_bounds`]
//! (step 11). The crypto/path/sig verify (step 14) is already Rust and
//! already KAT'd (gate-2); it enters as a marshaled boolean, not re-audited
//! here.

use std::collections::BTreeSet;

use crate::challenge::{challenge_fire_height, challenge_seal_on_chain};
use crate::segment_freeze::challenge_leaf_chunk_bounds;
use crate::serve_eligibility::serve_credit_epoch_ok;
use crate::wire::{
    MAX_BRANCH_SCALARS, MAX_PATH_LAYERS_PER_KIND, VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE,
};

/// Byte length of the `(P, shard, E)` composite key — both the persistent
/// LMDB key (D-SC-A) and the in-block key (D-SC-C) are
/// `P_id[32] ‖ u64 ‖ u64`.
pub const SERVE_CREDIT_KEY_LEN: usize = 48;

// ─── D-SC-A — per-tx (P, shard, E) dedup vs pre-block LMDB ────────────────

/// The persistent LMDB serve-credit key, byte-for-byte as C++
/// `ArchivalServeCreditKey` builds it (`shekyl_types.h:405–412`):
/// `P_id[32] ‖ BE64(shard_id) ‖ BE64(settlement_epoch)`.
///
/// Big-endian is load-bearing for the LMDB table's sort order
/// (`db_lmdb.cpp:1657–1659`: composite keys are multi-field big-endian byte
/// arrays, never native-endian integers).
#[must_use]
pub fn serve_credit_key_be(
    p_canonical_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
) -> [u8; SERVE_CREDIT_KEY_LEN] {
    let mut key = [0u8; SERVE_CREDIT_KEY_LEN];
    key[..32].copy_from_slice(p_canonical_id);
    key[32..40].copy_from_slice(&shard_id.to_be_bytes());
    key[40..48].copy_from_slice(&settlement_epoch.to_be_bytes());
    key
}

/// D-SC-A verdict: is this `(P, shard, E)` already credited in the pre-block
/// state? Mirrors `blockchain.cpp:4247`
/// (`m_db->has_archival_serve_credit_bit`) with the LMDB read modeled as a
/// membership probe over the marshaled pre-block key set — the I/O stays
/// C++; the key construction and the membership verdict are the decision.
///
/// `true` = duplicate (the C++ rejects: "Duplicate archival serve-credit for
/// (P, shard, E)").
#[must_use]
pub fn serve_credit_preblock_duplicate(
    preblock_keys: &BTreeSet<[u8; SERVE_CREDIT_KEY_LEN]>,
    p_canonical_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
) -> bool {
    preblock_keys.contains(&serve_credit_key_be(
        p_canonical_id,
        shard_id,
        settlement_epoch,
    ))
}

// ─── D-SC-B — the full per-tx acceptance gate (wide mirror) ────────────────

/// Marshaled inputs for [`serve_credit_gate_decision`] — exactly the values
/// the C++ has in hand at each predicate of
/// `check_archival_serve_credit_input` (audit doc §2.2 table). LMDB reads and
/// the wire round-trip stay C++-side; their *results* arrive here as data.
#[derive(Clone, Debug)]
pub struct ServeCreditGateInputs<'a> {
    /// The vin's `(P, shard, E)` identity triple.
    pub p_canonical_id: [u8; 32],
    /// Shard id from the vin.
    pub shard_id: u64,
    /// Settlement epoch from the vin.
    pub settlement_epoch: u64,
    /// Step 1 (`:4224–4245`): per-branch scalar counts of `path.c1_layers`
    /// (the layer count is the slice length).
    pub c1_branch_scalar_counts: &'a [usize],
    /// Step 1: per-branch scalar counts of `path.c2_layers`.
    pub c2_branch_scalar_counts: &'a [usize],
    /// Step 2 (`:4247`, D-SC-A): result of the pre-block
    /// `has_archival_serve_credit_bit` read.
    pub preblock_present: bool,
    /// Step 3 (`:4254`): `get_archival_bond_hybrid_pubkey` succeeded.
    pub bond_substrate_present: bool,
    /// Step 4 (`:4260`): `archival_bond_join_epoch(P)`.
    pub join_epoch: u64,
    /// Step 5 (`:4269`): `archival_bond_good_through(P, E)`.
    pub good_through: bool,
    /// Step 6 (`:4279`): the block-connect height the gate runs at.
    pub current_height: u64,
    /// `H_open` — C++ derives via `shekyl_archival_epoch_open_height(E)`;
    /// marshaled, not re-derived (the derivation is already Rust behind that
    /// FFI).
    pub h_open: u64,
    /// `H_close` — C++ derives via `shekyl_archival_epoch_close_height(E)`.
    pub h_close: u64,
    /// Step 7 (`:4288`): the seal-block hash iff
    /// `get_block_hash_from_height(H_seal)` succeeded. With the seal-on-chain
    /// guard (step 6b) rejecting the not-yet-committed case first, `None` here is
    /// a load that threw at a *committed* height — genuine DB corruption, not a
    /// future epoch.
    pub seal_hash: Option<[u8; 32]>,
    /// Step 9 (`:4312`): `archival_bond_holds_shard(P, shard, H_fire)`.
    ///
    /// At the pinned substrate this accessor is already the WS-1-corrected
    /// **as-of-`H_fire` reconstruction** (`db_lmdb.cpp`, landed with PR
    /// #269), not a tip read — the mirror snapshots the corrected behavior
    /// on purpose (audit doc §5, step-9 substrate note). The HoldingsUpdate
    /// slice extended the reconstruction for mutable holdings (P2B-7 Pin
    /// 4/5): a tip-held compact shard answers held only for heights in
    /// epochs strictly after its v6 add-epoch (the per-shard `E_add + 1`
    /// rule — the partial add epoch is forfeited for credit and challenge
    /// alike), and a voluntarily dropped shard answers not-held everywhere
    /// (grace-tail keeps no drop interval). The reconstruction stays
    /// C++-side marshaling; its boundaries are audited through seeded-state
    /// verdict vectors on the C++ leg.
    pub held_at_fire: bool,
    /// Step 10 (`:4321`): `get_archival_shard_segment_at_height` succeeded.
    pub registry_present_at_fire: bool,
    /// Step 11 (`:4336`): the challenged leaf index from the vin.
    pub leaf_index_in_segment: u64,
    /// Step 12 (`:4353`): `get_curve_tree_leaf_chunk` succeeded.
    pub leaf_chunk_ok: bool,
    /// Step 13 (`:4363`): the vin `do_serialize` round-trip succeeded.
    pub wire_serialize_ok: bool,
    /// Step 13 (`:4371`): first byte of the serialized vin (`None` = empty
    /// wire; the C++ folds empty and wrong-tag into one branch).
    pub wire_first_byte: Option<u8>,
    /// Step 14 (`:4387`): `shekyl_archival_verify_serve_credit_vin` returned
    /// OK. Already Rust + gate-2 KAT'd; provided as a bool, not re-audited.
    pub verify_ok: bool,
}

/// The first failing branch of the gate — one variant per C++ `MERROR_VER`
/// reject at the pinned substrate commit `ca8edce6b`, in gate order. The KAT
/// asserts the *variant*, not the log text (audit doc §5: no log-parsing;
/// the expected-reason column is authored by source inspection).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateReject {
    /// `:4227` — "path layer count exceeds bound".
    PathLayerCountExceedsBound,
    /// `:4234` — "c1 branch scalar count exceeds bound".
    C1BranchScalarCountExceedsBound,
    /// `:4242` — "c2 branch scalar count exceeds bound".
    C2BranchScalarCountExceedsBound,
    /// `:4249` — "Duplicate archival serve-credit for (P, shard, E)"
    /// (D-SC-A composing in as step 2).
    DuplicatePreBlock,
    /// `:4256` — "bond record substrate not available for P_id".
    BondSubstrateMissing,
    /// `:4263` — settlement epoch before `E_first = join_epoch + 1`.
    EpochBeforeEFirst,
    /// `:4271` — "P not good_through at epoch E".
    NotGoodThrough,
    /// `:4281` — "past credit deadline H_close".
    PastCreditDeadline,
    /// `blockchain.cpp` — "seal block … at or beyond chain height … (not yet
    /// committed)". The Rust-authoritative seal-on-chain guard
    /// ([`challenge_seal_on_chain`]) added after the pinned substrate: a
    /// future-epoch `settlement_epoch` puts `H_seal` at or beyond the tip, so it
    /// is rejected before the seal read (between the deadline, step 6, and the
    /// seal load, step 7). The C++ calls the same predicate through
    /// `shekyl_archival_challenge_seal_on_chain`.
    SealBlockNotYetCommitted,
    /// `:4292` — "cannot load seal block hash at height H_seal".
    SealHashUnavailable,
    /// `:4308` — "challenge fire height derivation failed"
    /// (`H_fire == 0 || H_fire > H_close`). Defensive dead branch: unreachable
    /// through live C++ (step 7's seal load shields the saturating-overflow
    /// epochs) and, since the seal-on-chain guard (step 6b) landed, unreachable
    /// through this mirror too — reaching step 8 needs `H_seal < current_height
    /// <= H_close`, which forces `H_fire <= H_close`, and a degenerate epoch
    /// (`H_close <= H_seal`) is caught by step 6b first (`B-13` pins that
    /// interception). No vector reaches this branch; it is retained only to
    /// mirror the C++ structure, and the §5 FFI-reopen criterion is not
    /// triggered by it.
    FireHeightDerivationFailed,
    /// `:4314` — "shard not in bond holdings at H_fire" (the WS-1 site).
    ShardNotHeldAtFire,
    /// `:4323` — "shard registry substrate not available at H_fire".
    ShardRegistryUnavailableAtFire,
    /// `:4339` — "challenged leaf index out of segment range".
    LeafIndexOutOfSegmentRange,
    /// `:4355` — "leaf chunk read failed" (registry/tree disagreement).
    LeafChunkReadFailed,
    /// `:4365` — "failed to serialize vin for FFI verify".
    VinSerializeFailed,
    /// `:4373` — "unexpected vin wire tag" (empty wire folds in here).
    UnexpectedVinWireTag,
    /// `:4391` — "FFI verify failed".
    FfiVerifyFailed,
}

/// Verdict of the wide D-SC-B gate mirror.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateVerdict {
    /// The vin passes every predicate (`check_archival_serve_credit_input`
    /// returns `true`).
    Accept,
    /// The first failing predicate, in gate order.
    Reject(GateReject),
}

impl GateVerdict {
    /// The consensus-relevant `bool` — the whole of what the C++ contract
    /// exposes (audit doc §5 leg-responsibility split).
    #[must_use]
    pub fn accepted(&self) -> bool {
        matches!(self, GateVerdict::Accept)
    }
}

/// D-SC-B wide mirror: `check_archival_serve_credit_input`
/// (`blockchain.cpp:4219–4396`) as the ordered predicate sequence over
/// marshaled inputs, returning the **first failing branch** or `Accept`.
///
/// The ordering is itself the audited artifact — it must match the C++
/// top-to-bottom, and the C++ gate carries a guard comment naming the
/// equivalence fixture so a reorder trips a signal at the edit site.
#[must_use]
pub fn serve_credit_gate_decision(inputs: &ServeCreditGateInputs<'_>) -> GateVerdict {
    use GateReject as R;
    use GateVerdict::Reject;

    // Step 1 (:4224–4245): path-shape bounds — layer counts first (one
    // combined condition in the C++), then the c1 branch loop, then c2.
    if inputs.c1_branch_scalar_counts.len() > MAX_PATH_LAYERS_PER_KIND
        || inputs.c2_branch_scalar_counts.len() > MAX_PATH_LAYERS_PER_KIND
    {
        return Reject(R::PathLayerCountExceedsBound);
    }
    if inputs
        .c1_branch_scalar_counts
        .iter()
        .any(|&n| n > MAX_BRANCH_SCALARS)
    {
        return Reject(R::C1BranchScalarCountExceedsBound);
    }
    if inputs
        .c2_branch_scalar_counts
        .iter()
        .any(|&n| n > MAX_BRANCH_SCALARS)
    {
        return Reject(R::C2BranchScalarCountExceedsBound);
    }

    // Step 2 (:4247): D-SC-A dedup vs pre-block LMDB state.
    if inputs.preblock_present {
        return Reject(R::DuplicatePreBlock);
    }

    // Step 3 (:4254): bond-record substrate present for P.
    if !inputs.bond_substrate_present {
        return Reject(R::BondSubstrateMissing);
    }

    // Step 4 (:4261): epoch-ok — the *same* Rust predicate the C++ calls
    // through `shekyl_archival_serve_credit_epoch_ok`, never re-derived.
    if !serve_credit_epoch_ok(inputs.settlement_epoch, inputs.join_epoch) {
        return Reject(R::EpochBeforeEFirst);
    }

    // Step 5 (:4269): good_through at E.
    if !inputs.good_through {
        return Reject(R::NotGoodThrough);
    }

    // Step 6 (:4279): credit deadline.
    if inputs.current_height > inputs.h_close {
        return Reject(R::PastCreditDeadline);
    }

    // Step 6b: seal-on-chain — the same Rust predicate the C++ calls through
    // `shekyl_archival_challenge_seal_on_chain`, called directly here (one
    // source, no re-derivation). A future-epoch input whose `H_seal` is at or
    // beyond the tip is rejected before the seal load below, which can then only
    // fail on genuine corruption.
    if !challenge_seal_on_chain(inputs.h_open, inputs.current_height) {
        return Reject(R::SealBlockNotYetCommitted);
    }

    // Step 7 (:4288): seal block hash loadable at H_seal.
    let Some(seal_hash) = inputs.seal_hash else {
        return Reject(R::SealHashUnavailable);
    };

    // Step 8 (:4297–4310): H_fire derivation — the same Rust function the
    // C++ calls through `shekyl_archival_challenge_fire_height` — plus the
    // (0, H_close] guard shared with the slash-eligibility consumer (WS-1
    // h_fire symmetry).
    let h_fire = challenge_fire_height(
        inputs.h_open,
        inputs.h_close,
        &seal_hash,
        &inputs.p_canonical_id,
        inputs.shard_id,
        inputs.settlement_epoch,
    );
    if h_fire == 0 || h_fire > inputs.h_close {
        return Reject(R::FireHeightDerivationFailed);
    }

    // Step 9 (:4312): holds-shard-at-H_fire (WS-1 as-of read; see the
    // `held_at_fire` field docs for the corrected-substrate note).
    if !inputs.held_at_fire {
        return Reject(R::ShardNotHeldAtFire);
    }

    // Step 10 (:4321): shard-registry substrate at H_fire.
    if !inputs.registry_present_at_fire {
        return Reject(R::ShardRegistryUnavailableAtFire);
    }

    // Step 11 (:4336): leaf-chunk bounds — the same Rust function the C++
    // calls through `shekyl_archival_challenge_leaf_chunk_bounds`.
    if challenge_leaf_chunk_bounds(inputs.shard_id, inputs.leaf_index_in_segment).is_none() {
        return Reject(R::LeafIndexOutOfSegmentRange);
    }

    // Step 12 (:4353): leaf-chunk read.
    if !inputs.leaf_chunk_ok {
        return Reject(R::LeafChunkReadFailed);
    }

    // Step 13 (:4360–4375): vin wire round-trip + tag pin (empty wire folds
    // into the tag branch, as in the C++).
    if !inputs.wire_serialize_ok {
        return Reject(R::VinSerializeFailed);
    }
    if inputs.wire_first_byte != Some(VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE) {
        return Reject(R::UnexpectedVinWireTag);
    }

    // Step 14 (:4387): crypto/path/sig FFI verify — already Rust, already
    // gate-2 KAT'd; a marshaled bool here.
    if !inputs.verify_ok {
        return Reject(R::FfiVerifyFailed);
    }

    GateVerdict::Accept
}

// ─── D-SC-C — block-level (P, shard, E) uniqueness ─────────────────────────

/// The in-block serve-credit key, byte-for-byte as the C++ block pass builds
/// it: since the SCE-1 unify commit (audit doc §6) the block pass keys with
/// `ArchivalServeCreditKey` — the same **big-endian** encoding as the
/// persistent D-SC-A key — so this delegates to [`serve_credit_key_be`].
///
/// **Finding SCE-1** (audit doc §6), for the record: pre-unify the C++ built
/// a native-endian `memcpy` key here, the *other* encoding of the same
/// logical key. Equivalence was proven against those bytes first
/// (mirror-then-fix); the decision-invariance fuzz target established the
/// verdict does not depend on the encoding, which is what licensed the unify
/// as behavior-preserving.
#[must_use]
pub fn serve_credit_block_key(
    p_canonical_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
) -> [u8; SERVE_CREDIT_KEY_LEN] {
    serve_credit_key_be(p_canonical_id, shard_id, settlement_epoch)
}

/// Verdict of the block-level uniqueness pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockUniqueVerdict {
    /// No `(P, shard, E)` appears twice across the block's serve-credit
    /// vins.
    Unique,
    /// The first triple (in block/tx/vin iteration order) whose key was
    /// already in the set — the C++ rejects the block on first collision.
    DuplicateAt {
        /// Index into the input slice of the colliding triple.
        index: usize,
    },
}

/// D-SC-C mirror: the block-level cross-tx `(P, shard, E)` uniqueness pass
/// (`blockchain.cpp:4889–4910`) as a pure function over the **ordered** list
/// of triples extracted from the block's serve-credit vins.
///
/// First-collision-wins, exactly as the C++ returns on the first
/// `insert().second == false`. (The C++ set is an `unordered_set`; only
/// membership is decision-relevant, so the mirror's set type is free.)
#[must_use]
pub fn serve_credit_block_unique(triples: &[([u8; 32], u64, u64)]) -> BlockUniqueVerdict {
    let mut block_serve_credits = BTreeSet::new();
    for (index, (p_canonical_id, shard_id, settlement_epoch)) in triples.iter().enumerate() {
        let key = serve_credit_block_key(p_canonical_id, *shard_id, *settlement_epoch);
        if !block_serve_credits.insert(key) {
            return BlockUniqueVerdict::DuplicateAt { index };
        }
    }
    BlockUniqueVerdict::Unique
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: [u8; 32] = [0xA7; 32];

    /// An accepting input set: epoch 100 of the pinned formulas
    /// (`H_open = 1_000_000`, `H_close = 1_009_999`), all substrate probes
    /// green. Per-branch tests flip exactly one field.
    fn accepting_inputs() -> ServeCreditGateInputs<'static> {
        ServeCreditGateInputs {
            p_canonical_id: P,
            shard_id: 3,
            settlement_epoch: 100,
            c1_branch_scalar_counts: &[38, 38],
            c2_branch_scalar_counts: &[38],
            preblock_present: false,
            bond_substrate_present: true,
            join_epoch: 50,
            good_through: true,
            current_height: 1_005_000,
            h_open: 1_000_000,
            h_close: 1_009_999,
            seal_hash: Some([0xB4; 32]),
            held_at_fire: true,
            registry_present_at_fire: true,
            leaf_index_in_segment: 12,
            leaf_chunk_ok: true,
            wire_serialize_ok: true,
            wire_first_byte: Some(VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE),
            verify_ok: true,
        }
    }

    #[test]
    fn key_be_matches_archival_serve_credit_key_layout() {
        // shekyl_types.h:405–412 — P ‖ BE64(shard) ‖ BE64(E).
        let key = serve_credit_key_be(&P, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
        assert_eq!(&key[..32], &P);
        assert_eq!(&key[32..40], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            &key[40..48],
            &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
        );
    }

    #[test]
    fn block_key_is_unified_onto_the_be_key() {
        // Post-SCE-1-unify (audit doc §6): the block pass keys with
        // ArchivalServeCreditKey, so D-SC-C's key IS D-SC-A's key —
        // P ‖ BE64(shard) ‖ BE64(E), one encoding for the logical triple.
        let key = serve_credit_block_key(&P, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
        assert_eq!(
            key,
            serve_credit_key_be(&P, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718)
        );
        assert_eq!(&key[32..40], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn preblock_duplicate_is_membership_over_be_keys() {
        let mut preblock = BTreeSet::new();
        assert!(!serve_credit_preblock_duplicate(&preblock, &P, 3, 100));
        preblock.insert(serve_credit_key_be(&P, 3, 100));
        assert!(serve_credit_preblock_duplicate(&preblock, &P, 3, 100));
        // Field-swapped triples do not collide.
        assert!(!serve_credit_preblock_duplicate(&preblock, &P, 100, 3));
    }

    #[test]
    fn gate_accepts_the_green_path() {
        assert_eq!(
            serve_credit_gate_decision(&accepting_inputs()),
            GateVerdict::Accept
        );
        assert!(serve_credit_gate_decision(&accepting_inputs()).accepted());
    }

    #[test]
    fn gate_step1_bounds_fire_in_cpp_order() {
        let too_many_layers = vec![1usize; MAX_PATH_LAYERS_PER_KIND + 1];
        let mut inputs = accepting_inputs();
        inputs.c1_branch_scalar_counts = &too_many_layers;
        assert_eq!(
            serve_credit_gate_decision(&inputs),
            GateVerdict::Reject(GateReject::PathLayerCountExceedsBound)
        );

        let fat_branch = [MAX_BRANCH_SCALARS + 1];
        let mut inputs = accepting_inputs();
        inputs.c1_branch_scalar_counts = &fat_branch;
        assert_eq!(
            serve_credit_gate_decision(&inputs),
            GateVerdict::Reject(GateReject::C1BranchScalarCountExceedsBound)
        );

        let mut inputs = accepting_inputs();
        inputs.c2_branch_scalar_counts = &fat_branch;
        assert_eq!(
            serve_credit_gate_decision(&inputs),
            GateVerdict::Reject(GateReject::C2BranchScalarCountExceedsBound)
        );

        // Ordering fidelity inside step 1: a fat c1 branch AND a fat c2
        // branch reports c1 (the C++ loops c1 first).
        let mut inputs = accepting_inputs();
        inputs.c1_branch_scalar_counts = &fat_branch;
        inputs.c2_branch_scalar_counts = &fat_branch;
        assert_eq!(
            serve_credit_gate_decision(&inputs),
            GateVerdict::Reject(GateReject::C1BranchScalarCountExceedsBound)
        );
    }

    #[test]
    fn gate_rejects_each_branch_at_its_step() {
        // (mutator, expected reason) — one row per marshaled-bool branch, in
        // gate order; each mutation flips exactly one field of the green
        // path.
        type Mutator = fn(&mut ServeCreditGateInputs<'static>);
        let rows: &[(Mutator, GateReject)] = &[
            (|i| i.preblock_present = true, GateReject::DuplicatePreBlock),
            (
                |i| i.bond_substrate_present = false,
                GateReject::BondSubstrateMissing,
            ),
            (|i| i.join_epoch = 100, GateReject::EpochBeforeEFirst),
            (|i| i.good_through = false, GateReject::NotGoodThrough),
            (
                |i| i.current_height = 1_010_000,
                GateReject::PastCreditDeadline,
            ),
            (
                // current_height == H_open ≤ H_seal: seal block not yet on chain.
                |i| i.current_height = i.h_open,
                GateReject::SealBlockNotYetCommitted,
            ),
            (|i| i.seal_hash = None, GateReject::SealHashUnavailable),
            (|i| i.held_at_fire = false, GateReject::ShardNotHeldAtFire),
            (
                |i| i.registry_present_at_fire = false,
                GateReject::ShardRegistryUnavailableAtFire,
            ),
            (
                |i| i.leaf_index_in_segment = u64::MAX,
                GateReject::LeafIndexOutOfSegmentRange,
            ),
            (|i| i.leaf_chunk_ok = false, GateReject::LeafChunkReadFailed),
            (
                |i| i.wire_serialize_ok = false,
                GateReject::VinSerializeFailed,
            ),
            (
                |i| i.wire_first_byte = Some(0x07),
                GateReject::UnexpectedVinWireTag,
            ),
            (
                |i| i.wire_first_byte = None,
                GateReject::UnexpectedVinWireTag,
            ),
            (|i| i.verify_ok = false, GateReject::FfiVerifyFailed),
        ];
        for (mutate, want) in rows {
            let mut inputs = accepting_inputs();
            mutate(&mut inputs);
            assert_eq!(
                serve_credit_gate_decision(&inputs),
                GateVerdict::Reject(*want)
            );
        }
    }

    #[test]
    fn gate_first_failing_branch_wins_across_steps() {
        // Two red predicates: the earlier one (dedup, step 2) must be the
        // reported reason, not the later (good_through, step 5).
        let mut inputs = accepting_inputs();
        inputs.preblock_present = true;
        inputs.good_through = false;
        assert_eq!(
            serve_credit_gate_decision(&inputs),
            GateVerdict::Reject(GateReject::DuplicatePreBlock)
        );
    }

    #[test]
    fn gate_seal_on_chain_boundary_is_h_seal() {
        // current_height == H_seal: the seal block index is one past the tip
        // (chain_height is the block count), so it is not yet on chain and the
        // gate rejects; + 1 puts the seal on chain and the gate proceeds.
        let h_seal = crate::challenge::challenge_seal_height(accepting_inputs().h_open);
        let mut inputs = accepting_inputs();
        inputs.current_height = h_seal;
        assert_eq!(
            serve_credit_gate_decision(&inputs),
            GateVerdict::Reject(GateReject::SealBlockNotYetCommitted)
        );
        inputs.current_height = h_seal + 1;
        assert_eq!(serve_credit_gate_decision(&inputs), GateVerdict::Accept);
    }

    #[test]
    fn gate_credit_deadline_boundary_is_h_close_inclusive() {
        // current_height == H_close accepts (`>` in the C++), + 1 rejects.
        let mut inputs = accepting_inputs();
        inputs.current_height = inputs.h_close;
        assert_eq!(serve_credit_gate_decision(&inputs), GateVerdict::Accept);
        inputs.current_height = inputs.h_close + 1;
        assert_eq!(
            serve_credit_gate_decision(&inputs),
            GateVerdict::Reject(GateReject::PastCreditDeadline)
        );
    }

    #[test]
    fn gate_seal_on_chain_shields_the_fire_guard() {
        // The degenerate epoch that used to reach the step-8 fire guard
        // (H_close == H_open, so H_close < H_seal) is now intercepted by the
        // seal-on-chain guard (step 6b): any current_height passing the deadline
        // (<= H_close) is necessarily <= H_seal, so the seal is not yet on chain.
        // The fire-guard branch (see `GateReject::FireHeightDerivationFailed`
        // docs) is thereby unreachable through the gate — this pins the shield.
        let mut inputs = accepting_inputs();
        inputs.h_close = inputs.h_open; // H_close < H_seal (= H_open + seal lag)
        inputs.current_height = inputs.h_open;
        assert_eq!(
            serve_credit_gate_decision(&inputs),
            GateVerdict::Reject(GateReject::SealBlockNotYetCommitted)
        );
    }

    #[test]
    fn gate_epoch_ok_is_the_shared_predicate() {
        // E == join_epoch + 1 accepts; E == join_epoch rejects — the exact
        // serve_credit_epoch_ok boundary, resolved through the one shared
        // function.
        let mut inputs = accepting_inputs();
        inputs.join_epoch = inputs.settlement_epoch - 1;
        assert_eq!(serve_credit_gate_decision(&inputs), GateVerdict::Accept);
        inputs.join_epoch = inputs.settlement_epoch;
        assert_eq!(
            serve_credit_gate_decision(&inputs),
            GateVerdict::Reject(GateReject::EpochBeforeEFirst)
        );
    }

    #[test]
    fn block_unique_accepts_distinct_triples() {
        let triples = [(P, 1, 100), (P, 2, 100), (P, 1, 101), ([0x11; 32], 1, 100)];
        assert_eq!(
            serve_credit_block_unique(&triples),
            BlockUniqueVerdict::Unique
        );
        assert_eq!(serve_credit_block_unique(&[]), BlockUniqueVerdict::Unique);
    }

    #[test]
    fn block_unique_reports_first_collision_index() {
        // (P,1,100) recurs at indices 2 and 4; the verdict is the *first*
        // recurrence (index 2), matching the C++ return-on-first-insert-fail.
        let triples = [
            (P, 1, 100),
            (P, 2, 100),
            (P, 1, 100),
            (P, 3, 100),
            (P, 1, 100),
        ];
        assert_eq!(
            serve_credit_block_unique(&triples),
            BlockUniqueVerdict::DuplicateAt { index: 2 }
        );
    }

    #[test]
    fn block_unique_field_swap_is_not_a_collision() {
        // (shard, E) = (1, 100) vs (100, 1): distinct keys; a mirror bug
        // that compared fields loosely would fail here.
        let triples = [(P, 1, 100), (P, 100, 1)];
        assert_eq!(
            serve_credit_block_unique(&triples),
            BlockUniqueVerdict::Unique
        );
    }
}
