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
//!   (`check_archival_serve_credit_input`; key type `ArchivalPairEpochKey`,
//!   **big-endian** `u64` fields). The C++ read is
//!   `archival_serve_credit_pass_count > 0` over that 48-byte prefix
//!   (`PC-D4`: the 56-byte ledger key is per-challenge and is a different
//!   type).
//! - **D-SC-B** — the full per-tx acceptance gate
//!   (`check_archival_serve_credit_input`), mirrored **wide**: the ordered
//!   predicate sequence returns the first failing branch. A reorder is a
//!   behavior change; the ordering is audited.
//! - **D-SC-C** — block-level cross-tx `(P, shard, E)` uniqueness
//!   (`handle_block_to_main_chain`; keyed with `ArchivalPairEpochKey` — the
//!   same **big-endian** encoding D-SC-A persists, since the SCE-1 unify
//!   commit replaced the original native-endian `memcpy` key, audit doc §6).
//!   The block is common-mode inside one block, so this pass did not widen
//!   with the ledger.
//!
//! Single-source rule (audit doc §2.2): predicates that already exist in Rust
//! are *called*, never re-implemented — [`serve_credit_epoch_ok`] (step 4),
//! [`challenge_seal_on_chain`] (step 6b), [`challenge_leaf_chunk_bounds`]
//! (step 11). The crypto/path/sig verify (step 14) is already Rust and
//! already KAT'd (gate-2); it enters as a marshaled boolean, not re-audited
//! here.

use std::collections::BTreeSet;

use crate::challenge::challenge_seal_on_chain;
use crate::segment_freeze::challenge_leaf_chunk_bounds;
use crate::serve_eligibility::serve_credit_epoch_ok;

/// Byte length of C++ `ArchivalPairEpochKey`: `P ‖ BE64(shard) ‖ BE64(E)`.
/// D-SC-A (prefix membership) and D-SC-C (in-block uniqueness) use this
/// encoding because those decisions are pair-epoch-wide while the beacon
/// still issues one challenge. Settlement and slash-applied share it.
pub const PAIR_EPOCH_KEY_LEN: usize = 48;

/// Byte length of C++ `ArchivalServeCreditKey`: the pair-epoch prefix plus
/// `BE64(block_height)`. This is the ledger row. It is not the D-SC-A/C key.
pub const SERVE_CREDIT_KEY_LEN: usize = 56;

// ─── D-SC-A — per-tx (P, shard, E) dedup vs pre-block LMDB ────────────────

/// The pair-epoch key, byte-for-byte as C++ `ArchivalPairEpochKey` builds it:
/// `P_id[32] ‖ BE64(shard_id) ‖ BE64(settlement_epoch)`.
///
/// Big-endian is load-bearing for the LMDB table's sort order (composite keys
/// are multi-field big-endian byte arrays, never native-endian integers).
#[must_use]
pub fn pair_epoch_key_be(
    p_canonical_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
) -> [u8; PAIR_EPOCH_KEY_LEN] {
    let mut key = [0u8; PAIR_EPOCH_KEY_LEN];
    key[..32].copy_from_slice(p_canonical_id);
    key[32..40].copy_from_slice(&shard_id.to_be_bytes());
    key[40..48].copy_from_slice(&settlement_epoch.to_be_bytes());
    key
}

/// The serve-credit ledger key, byte-for-byte as C++ `ArchivalServeCreditKey`
/// builds it: [`pair_epoch_key_be`] plus `BE64(block_height)`. Composed, not
/// re-encoded, matching `shekyl_types.h`.
#[must_use]
pub fn serve_credit_key_be(
    p_canonical_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
    block_height: u64,
) -> [u8; SERVE_CREDIT_KEY_LEN] {
    let mut key = [0u8; SERVE_CREDIT_KEY_LEN];
    key[..PAIR_EPOCH_KEY_LEN].copy_from_slice(&pair_epoch_key_be(
        p_canonical_id,
        shard_id,
        settlement_epoch,
    ));
    key[PAIR_EPOCH_KEY_LEN..].copy_from_slice(&block_height.to_be_bytes());
    key
}

/// D-SC-A verdict: is this `(P, shard, E)` already credited in the pre-block
/// state? Mirrors the dedup in `check_archival_serve_credit_input`, with the
/// LMDB read modeled as a membership probe over the marshaled pre-block key
/// set — the I/O stays C++; the key construction and the membership verdict
/// are the decision.
///
/// **`PC-D4`: the C++ read is now
/// `archival_serve_credit_pass_count(P, s, E) > 0`, not
/// `has_archival_serve_credit_bit`.** This mirror named the latter until
/// 2026-08-24, after the gate had stopped calling it. The VERDICT is
/// identical — which is precisely why the description drifted without a
/// single vector going red: an equivalence fixture pins what the gate decides,
/// never what it reads. The key stays 48-byte pair-epoch here because the
/// dedup does.
///
/// `true` = duplicate (the C++ rejects: "Duplicate archival serve-credit for
/// (P, shard, E)").
#[must_use]
pub fn serve_credit_preblock_duplicate(
    preblock_keys: &BTreeSet<[u8; PAIR_EPOCH_KEY_LEN]>,
    p_canonical_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
) -> bool {
    preblock_keys.contains(&pair_epoch_key_be(
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
pub struct ServeCreditGateInputs {
    /// The vin's `(P, shard, E)` identity triple.
    pub p_canonical_id: [u8; 32],
    /// Shard id from the vin.
    pub shard_id: u64,
    /// Settlement epoch from the vin.
    pub settlement_epoch: u64,
    /// Step 0 (RF-D1 / rule 40): the opaque vin parsed through the Rust codec
    /// (`shekyl_archival_serve_credit_extract`). Every structural bound on the
    /// record -- branch-layer counts and widths, leg lengths -- is the codec's
    /// and surfaces through step 14's FFI verify, not as C++ pre-checks: the
    /// path-bound rejects the gate used to carry are gone because C++ no
    /// longer reads the path.
    pub vin_parsed: bool,
    /// Step 0b: this vin's pruned record is non-empty and within
    /// `ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES` (the one size check C++ keeps,
    /// as a transport ceiling).
    pub pruned_record_in_bounds: bool,
    /// Step 2 (D-SC-A): does the pre-block state already hold a pass for this
    /// pair-epoch — `archival_serve_credit_pass_count(P, s, E) > 0` on the C++
    /// side (`PC-D4`; it was `has_archival_serve_credit_bit` before the ledger
    /// key widened, and the field name predates that).
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
    /// Step 11: the registry's `segment_leaf_count` at `H_fire`. The challenged
    /// index is DERIVED from it (RF-D6: `challenge_leaf_index`), never read
    /// off the vin; the C++ calls the same derivation through
    /// `shekyl_archival_challenge_leaf_index`, which refuses a zero geometry.
    pub segment_leaf_count: u64,

    /// Step 11 (`PC-D3`): `block_hash(h−1)` of the block this record rides in.
    ///
    /// **Verifier-supplied, never transported.** `PC-D2` makes the block
    /// implicit — the record arrives in its own producer's block — so consensus
    /// reads this from the block it is already validating rather than from a
    /// field the prover populated. A prover-supplied hash would be a `PC-D1`
    /// violation of exactly the `RF-D8` shape this round refuses.
    ///
    /// The hash and not the height: `RF-D5`'s nonce already binds this same
    /// term, so the record keeps **one** block reference instead of two that
    /// could diverge.
    pub prev_block_hash: [u8; 32],
    /// Step 12 (`:4353`): `get_curve_tree_leaf_chunk` succeeded.
    pub leaf_chunk_ok: bool,
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
    /// "serve-credit vin did not parse" (step 0, RF-D1).
    VinUnparseable,
    /// "pruned record size out of bounds" (step 0b, RF-D1).
    PrunedRecordSizeOutOfBounds,
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
    /// `:4314` — "shard not in bond holdings at H_fire" (the WS-1 site).
    ShardNotHeldAtFire,
    /// `:4323` — "shard registry substrate not available at H_fire".
    ShardRegistryUnavailableAtFire,
    /// "leaf index derivation refused" -- a zero registry geometry (RF-D6).
    LeafIndexDerivationRefused,
    /// "challenged leaf index out of segment range". With the index DERIVED
    /// (`< segment_leaf_count`), reachable when the registry's count exceeds
    /// `SEGMENT_LEAF_COUNT` -- or when the global position
    /// `shard_id * SEGMENT_LEAF_COUNT + index` overflows `u64` (a far-end
    /// `shard_id`; the bounds arithmetic is checked, not silently wrapping).
    /// Kept because the C++ keeps the check.
    LeafIndexOutOfSegmentRange,
    /// `:4355` — "leaf chunk read failed" (registry/tree disagreement).
    LeafChunkReadFailed,
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
pub fn serve_credit_gate_decision(inputs: &ServeCreditGateInputs) -> GateVerdict {
    use GateReject as R;
    use GateVerdict::Reject;

    // Step 0 (RF-D1): the opaque vin parsed through the Rust codec.
    if !inputs.vin_parsed {
        return Reject(R::VinUnparseable);
    }
    // Step 0b (RF-D1): this vin's pruned record is within the transport ceiling.
    if !inputs.pruned_record_in_bounds {
        return Reject(R::PrunedRecordSizeOutOfBounds);
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
    if inputs.seal_hash.is_none() {
        return Reject(R::SealHashUnavailable);
    }

    // Step 8 (:4297–4310): the C++ derives H_fire here (via
    // `shekyl_archival_challenge_fire_height`) for the "at H_fire" reads below,
    // but it carries no decision — H_fire is in (0, H_close] for every
    // well-formed epoch, so the range guard that once lived here is gone (see
    // `challenge_fire_height`'s reopen criterion). The mirror does not reproduce
    // the derivation because it is not decision-relevant; the reads arrive as
    // marshaled bools (`held_at_fire`, `registry_present_at_fire`).

    // Step 9 (:4312): holds-shard-at-H_fire (WS-1 as-of read; see the
    // `held_at_fire` field docs for the corrected-substrate note).
    if !inputs.held_at_fire {
        return Reject(R::ShardNotHeldAtFire);
    }

    // Step 10 (:4321): shard-registry substrate at H_fire.
    if !inputs.registry_present_at_fire {
        return Reject(R::ShardRegistryUnavailableAtFire);
    }

    // Step 11 (RF-D6): the challenged index is DERIVED -- the same function the
    // C++ calls through `shekyl_archival_challenge_leaf_index`, which refuses a
    // zero geometry -- then the leaf-chunk bounds over it, as the C++ calls
    // through `shekyl_archival_challenge_leaf_chunk_bounds`.
    if inputs.segment_leaf_count == 0 {
        return Reject(R::LeafIndexDerivationRefused);
    }
    // `PC-D3`: the same refusal the C++ path takes. `check_archival_serve_credit_input`
    // calls `shekyl_archival_challenge_leaf_index`, which answers
    // `ERR_PREVHASH_UNPOPULATED` for an all-zero hash and rejects the vin — so a
    // mirror that derived an index from it would disagree with production on an
    // input production refuses. Both arms land on the same verdict here because
    // the C++ reports both through one "leaf index derivation refused" branch.
    if inputs.prev_block_hash == [0u8; 32] {
        return Reject(R::LeafIndexDerivationRefused);
    }
    let leaf_index = crate::challenge::challenge_leaf_index(
        &inputs.p_canonical_id,
        inputs.shard_id,
        inputs.settlement_epoch,
        &inputs.prev_block_hash,
        inputs.segment_leaf_count,
    );
    if challenge_leaf_chunk_bounds(inputs.shard_id, u64::from(leaf_index)).is_none() {
        return Reject(R::LeafIndexOutOfSegmentRange);
    }

    // Step 12 (:4353): leaf-chunk read.
    if !inputs.leaf_chunk_ok {
        return Reject(R::LeafChunkReadFailed);
    }

    // (The former step 13 -- re-serialise the typed vin and pin its tag -- is
    // gone with the typed vin: the blob is passed to the FFI as-is, and the
    // tag is the serializer guard's, enforced at tx parse, before any gate.)

    // Step 14 (:4387): crypto/path/sig FFI verify — already Rust, already
    // gate-2 KAT'd; a marshaled bool here.
    if !inputs.verify_ok {
        return Reject(R::FfiVerifyFailed);
    }

    GateVerdict::Accept
}

// ─── D-SC-C — block-level (P, shard, E) uniqueness ─────────────────────────

/// The in-block uniqueness key, byte-for-byte as the C++ block pass builds
/// it: `ArchivalPairEpochKey`. Delegates to [`pair_epoch_key_be`].
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
) -> [u8; PAIR_EPOCH_KEY_LEN] {
    pair_epoch_key_be(p_canonical_id, shard_id, settlement_epoch)
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
    // The path-bound tests that lived beside these (layer count, c1/c2 branch
    // width, c1-before-c2 order) were RETIRED with the C++ pre-checks they
    // mirrored: under RF-D1 the path is inside the pruned record, which C++
    // does not read, so those bounds are the Rust parser's and surface through
    // the FFI verify (vectors B-02..B-05 now expect `FfiVerifyFailed`).
    fn accepting_inputs() -> ServeCreditGateInputs {
        ServeCreditGateInputs {
            p_canonical_id: P,
            shard_id: 3,
            settlement_epoch: 100,
            vin_parsed: true,
            pruned_record_in_bounds: true,
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
            segment_leaf_count: 25_992,
            // A non-zero stand-in block. Zero is REFUSED at the FFI boundary
            // (`SHEKYL_ARCHIVAL_VERIFY_ERR_PREVHASH_UNPOPULATED`), so an
            // accepting fixture must not use it -- an all-zero default here
            // would make every branch test start from an input the real gate
            // rejects.
            prev_block_hash: [0x6D; 32],
            leaf_chunk_ok: true,
            verify_ok: true,
        }
    }

    #[test]
    fn key_be_matches_archival_pair_epoch_key_layout() {
        // ArchivalPairEpochKey — P ‖ BE64(shard) ‖ BE64(E).
        let key = pair_epoch_key_be(&P, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
        assert_eq!(&key[..32], &P);
        assert_eq!(&key[32..40], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            &key[40..48],
            &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
        );
    }

    #[test]
    fn serve_credit_key_is_pair_epoch_plus_height() {
        let pair = pair_epoch_key_be(&P, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
        let key = serve_credit_key_be(
            &P,
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
        );
        assert_eq!(key.len(), SERVE_CREDIT_KEY_LEN);
        assert_eq!(&key[..PAIR_EPOCH_KEY_LEN], &pair);
        assert_eq!(
            &key[48..56],
            &[0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28]
        );
    }

    #[test]
    fn block_key_is_unified_onto_the_be_key() {
        // Post-SCE-1-unify (audit doc §6): D-SC-C's key IS D-SC-A's key —
        // ArchivalPairEpochKey, one encoding for the logical triple.
        let key = serve_credit_block_key(&P, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
        assert_eq!(
            key,
            pair_epoch_key_be(&P, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718)
        );
        assert_eq!(&key[32..40], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn preblock_duplicate_is_membership_over_be_keys() {
        let mut preblock = BTreeSet::new();
        assert!(!serve_credit_preblock_duplicate(&preblock, &P, 3, 100));
        preblock.insert(pair_epoch_key_be(&P, 3, 100));
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
    fn gate_rejects_each_branch_at_its_step() {
        // (mutator, expected reason) — one row per marshaled-bool branch, in
        // gate order; each mutation flips exactly one field of the green
        // path.
        type Mutator = fn(&mut ServeCreditGateInputs);
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
            (|i| i.vin_parsed = false, GateReject::VinUnparseable),
            (
                |i| i.pruned_record_in_bounds = false,
                GateReject::PrunedRecordSizeOutOfBounds,
            ),
            (|i| i.held_at_fire = false, GateReject::ShardNotHeldAtFire),
            (
                |i| i.registry_present_at_fire = false,
                GateReject::ShardRegistryUnavailableAtFire,
            ),
            (
                |i| i.segment_leaf_count = 0,
                GateReject::LeafIndexDerivationRefused,
            ),
            (
                // PC-D3: the all-zero unpopulated sentinel. Same verdict as a
                // zero geometry because the C++ reports both through one
                // "leaf index derivation refused" branch -- and the mirror
                // must agree with the gate on an input the gate REFUSES, not
                // only on the ones it derives from. Without this the mirror
                // derived an index here while
                // `shekyl_archival_challenge_leaf_index` rejected the vin.
                |i| i.prev_block_hash = [0u8; 32],
                GateReject::LeafIndexDerivationRefused,
            ),
            (
                // A registry geometry larger than a segment derives an index
                // the chunk arithmetic refuses -- the one way this reject
                // stays reachable with the index derived.
                |i| i.segment_leaf_count = u64::MAX,
                GateReject::LeafIndexOutOfSegmentRange,
            ),
            (|i| i.leaf_chunk_ok = false, GateReject::LeafChunkReadFailed),
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
