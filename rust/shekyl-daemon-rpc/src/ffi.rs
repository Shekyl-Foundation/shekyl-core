// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Raw C FFI declarations matching `src/rpc/core_rpc_ffi.h` and
//! `src/rpc/daemon_submit_ffi.h`.

use std::os::raw::c_char;

#[repr(C)]
pub struct CoreRpcHandle {
    _opaque: [u8; 0],
}

// ── Submit shims (src/rpc/daemon_submit_ffi.h) ─────────────────────────────

/// Per-key-image conflict descriptor values (§4.1).
pub const SHEKYL_SUBMIT_KI_FREE: u8 = 0;
pub const SHEKYL_SUBMIT_KI_OWN_TX: u8 = 1;
pub const SHEKYL_SUBMIT_KI_OTHER: u8 = 2;

/// Shim return codes (shared by snapshot and commit).
pub const SHEKYL_SUBMIT_OK: i32 = 0;
pub const SHEKYL_SUBMIT_RACED: i32 = 1;
pub const SHEKYL_SUBMIT_PRUNED_ON_INSERT: i32 = 2;
pub const SHEKYL_SUBMIT_INTERNAL_FAULT: i32 = -1;

/// POD fact snapshot (`shekyl_submit_facts_ffi`) — same-build ABI (§4.5),
/// layout pinned by the const asserts below (mirroring the C++
/// static_asserts) plus the bidirectional runtime round-trip test.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmitFactsFfi {
    pub in_pool: u8,
    pub in_chain: u8,
    pub ref_block_found: u8,
    pub tree_depth: u8,
    /// Pool-resident at the `legacy` (broadcast-visible) relay category —
    /// the publicly disclosable presence fact. `in_pool` is at the wider
    /// `all` category (includes Dandelion++-embargoed `local`/stem state);
    /// the two differ exactly for an embargoed tx, and the engine discloses
    /// the narrower fact to a foreign caller so the submit endpoint is not a
    /// stem-presence oracle (§3.1 identity-category pin).
    pub in_pool_broadcast: u8,
    /// The §8.7.1 BP3 record probe ran (the caller passed a bond
    /// `p_canonical_id`, or the commit re-derived one from the blob's
    /// bond-post vin). Gates the validity of `bond_record_exists`.
    pub bond_record_probed: u8,
    /// An archival bond record exists for the probed `p_canonical_id`
    /// (`get_archival_bond_hybrid_pubkey`). Valid iff
    /// `bond_record_probed`; zeroed otherwise.
    pub bond_record_exists: u8,
    /// The §8.7.2 E6 claim-slot probe ran (the caller passed the emission
    /// `(p_canonical_id, epochs)`, or the commit re-derived them from the
    /// blob's emission vin). Gates `emission_claim_conflict`.
    pub emission_probed: u8,
    /// The claimant record is gone OR a claimed epoch overlaps the
    /// record's claimed set. Valid iff `emission_probed`; Rust classifies
    /// (`DoubleSpendConflict`).
    pub emission_claim_conflict: u8,
    pub reserved: [u8; 7],
    pub ref_height: u64,
    pub root: [u8; 32],
    pub fee_per_byte: u64,
    pub fee_quantization_mask: u64,
    pub weight_limit: u64,
    pub chain_height: u64,
    /// Main-chain height of the block containing the submitted txid — the
    /// F40 confirming-block height, read under the same lock scope as
    /// `in_chain` so the pair cannot be racy (§4.1). Valid iff `in_chain`;
    /// zeroed otherwise.
    pub in_chain_height: u64,
}

impl SubmitFactsFfi {
    /// All-zero snapshot for out-parameter initialization.
    pub const fn zeroed() -> Self {
        Self {
            in_pool: 0,
            in_chain: 0,
            ref_block_found: 0,
            tree_depth: 0,
            in_pool_broadcast: 0,
            bond_record_probed: 0,
            bond_record_exists: 0,
            emission_probed: 0,
            emission_claim_conflict: 0,
            reserved: [0; 7],
            ref_height: 0,
            root: [0; 32],
            fee_per_byte: 0,
            fee_quantization_mask: 0,
            weight_limit: 0,
            chain_height: 0,
            in_chain_height: 0,
        }
    }
}

// §4.5 layout pins — the Rust twins of daemon_submit_ffi.cpp's
// static_asserts. A drift on either side fails that side's build.
const _: () = assert!(std::mem::size_of::<SubmitFactsFfi>() == 96);
const _: () = assert!(std::mem::align_of::<SubmitFactsFfi>() == 8);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, in_pool) == 0);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, in_chain) == 1);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, ref_block_found) == 2);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, tree_depth) == 3);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, in_pool_broadcast) == 4);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, bond_record_probed) == 5);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, bond_record_exists) == 6);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, emission_probed) == 7);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, emission_claim_conflict) == 8);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, reserved) == 9);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, ref_height) == 16);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, root) == 24);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, fee_per_byte) == 56);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, fee_quantization_mask) == 64);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, weight_limit) == 72);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, chain_height) == 80);
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, in_chain_height) == 88);

// ── §8.7.2 emission fact marshal (rows E6/E7) ──────────────────────────────
// Mirrors of `daemon_submit_ffi.h`'s emission PODs; the row shapes are the
// `shekyl_ffi.h` gather rows (`shekyl_archival_epoch_close_*`) the block
// path already marshals — one C definition, mirrored per Rust boundary
// (shekyl-ffi's twins carry the same layout; both sides are same-build ABI).

/// `shekyl_archival_epoch_close_bond`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ArchivalEpochCloseBondFfi {
    pub join_settlement_epoch: u64,
    /// Flattened `(start_epoch, end_exclusive)` pairs; `2 × len` u64s.
    pub bad_intervals_ptr: *const u64,
    /// Pair count (not u64 count).
    pub bad_intervals_len: usize,
    pub is_foundation_complete_tree: u8,
}

/// `shekyl_archival_epoch_close_shard`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ArchivalEpochCloseShardFfi {
    pub shard_id: u64,
    pub freeze_height: u64,
    pub has_segment: u8,
}

/// `shekyl_archival_credit_pair`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ArchivalCreditPairFfi {
    pub bond_idx: usize,
    pub shard_idx: usize,
}

/// `shekyl_submit_emission_bond_ffi` (row E6).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SubmitEmissionBondFfi {
    pub join_settlement_epoch: u64,
    pub holdings_kind: u8,
    pub shard_ids: *const u64,
    pub shard_ids_len: usize,
    pub claimed_epochs: *const u64,
    pub claimed_epochs_len: usize,
}

/// `shekyl_submit_emission_snapshot_ffi` (row E7).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SubmitEmissionSnapshotFfi {
    pub has_budget_row: u8,
    pub settlement_epoch: u64,
    pub close_block_height: u64,
    pub sigma_work_milli: u64,
    pub budget_atomic: u64,
    /// `usize::MAX` = claimant has no serve-credit row in `E`.
    pub claimant_bond_idx: usize,
    pub bonds: *const ArchivalEpochCloseBondFfi,
    pub bonds_len: usize,
    pub shards: *const ArchivalEpochCloseShardFfi,
    pub shards_len: usize,
    pub credit_pairs: *const ArchivalCreditPairFfi,
    pub credit_pairs_len: usize,
}

/// `shekyl_submit_emission_facts_ffi`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SubmitEmissionFactsFfi {
    pub bond_present: u8,
    pub bond: SubmitEmissionBondFfi,
    pub snapshots: *const SubmitEmissionSnapshotFfi,
    pub snapshots_len: usize,
}

/// Opaque C++-owned buffer holder (`shekyl_submit_emission_facts_handle`).
#[repr(C)]
pub struct SubmitEmissionFactsHandle {
    _opaque: [u8; 0],
}

// ── §8.7.1.1 Unbond fact marshal (rows UB2/UB3/UB4/UB6/UB7) ────────────────
// Mirrors of `daemon_submit_ffi.h`'s Unbond PODs.

/// Which archival-bond question the Phase-B probe asks
/// (`SHEKYL_SUBMIT_BOND_PROBE_JOIN`): the record must be **absent**.
pub const SHEKYL_SUBMIT_BOND_PROBE_JOIN: u8 = 0;
/// (`SHEKYL_SUBMIT_BOND_PROBE_UNBOND`): the record must be **present**, and
/// its contents are verify operands.
pub const SHEKYL_SUBMIT_BOND_PROBE_UNBOND: u8 = 1;

/// `shekyl_submit_unbond_record_ffi`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SubmitUnbondRecordFfi {
    pub bonded_total_atomic: u64,
    pub bad_interval_count: usize,
    pub bond_spend_pk: *const u8,
    pub bond_spend_pk_len: usize,
    pub holdings_kind: u8,
    /// Which accessor produced `per_shard_last_served`
    /// (`SHEKYL_ARCHIVAL_LAST_SERVED_SCAN_*`). Echoed by the gather and
    /// pinned Rust-side against `holdings_kind`.
    pub last_served_scan: u8,
    pub per_shard_last_served: *const u64,
    pub per_shard_last_served_len: usize,
}

/// `shekyl_submit_unbond_facts_ffi`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SubmitUnbondFactsFfi {
    pub record_present: u8,
    pub record: SubmitUnbondRecordFfi,
    /// The slash watermark **as stored**; `u64::MAX` is the "nothing settled
    /// yet" sentinel, normalised once in `ffi_shim`.
    pub last_settled_slash_epoch: u64,
}

/// Opaque C++-owned buffer holder (`shekyl_submit_unbond_facts_handle`).
#[repr(C)]
pub struct SubmitUnbondFactsHandle {
    _opaque: [u8; 0],
}

// ── RPC facts shims (src/rpc/rpc_facts_ffi.h; DAEMON_RPC_KV_CUTOVER.md §3.2) ──

/// `shekyl_rpc_chain_tip` succeeded / the facts POD is filled.
pub const SHEKYL_RPC_FACTS_OK: i32 = 0;
/// Null handle or null out pointer.
pub const SHEKYL_RPC_FACTS_ERR_NULL: i32 = -1;
/// The core is not initialized.
pub const SHEKYL_RPC_FACTS_ERR_NOT_READY: i32 = -2;
/// A core / P2P read threw inside the shim; logged there, reported here —
/// never an unwind across the C ABI.
pub const SHEKYL_RPC_FACTS_ERR_INTERNAL: i32 = -3;
/// The store reported a height it cannot produce the block for — a
/// data-integrity fault of this daemon, distinct from a read that threw.
pub const SHEKYL_RPC_FACTS_ERR_INCONSISTENT: i32 = -4;

/// Twin of `shekyl_rpc_chain_tip_facts`. Layout pinned both directions by
/// `tests/unit_tests/rpc_facts_ffi_roundtrip.cpp` via
/// `shekyl_rpc_chain_tip_facts_rust_{fill,check}`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainTipFactsFfi {
    /// Top block height + 1.
    pub chain_height: u64,
    pub top_hash: [u8; 32],
    /// Raw core target height (the synchronized rule is the handler's).
    pub target_height: u64,
    pub synchronized: u8,
    pub release_build: u8,
    pub reserved: [u8; 6],
}

/// Twin of `shekyl_rpc_block_hash_facts` (RK-2). Layout pinned both
/// directions by `tests/unit_tests/rpc_facts_ffi_roundtrip.cpp` via
/// `shekyl_rpc_block_hash_facts_rust_{fill,check}`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHashFactsFfi {
    pub hash: [u8; 32],
    /// Chain height at the moment of the read (top block height + 1).
    pub chain_height: u64,
    /// `0` when `height` was at or past `chain_height` — `hash` is then zero.
    pub found: u8,
    pub reserved: [u8; 7],
}

/// Twin of `shekyl_rpc_block_entry`: one block of a by-height answer. Every
/// pointer borrows memory owned by the opaque owner the export returns.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockEntryFfi {
    pub block: *const u8,
    pub block_len: usize,
    pub txs: *const *const u8,
    pub tx_lens: *const usize,
    pub tx_count: usize,
}

const _: () = assert!(std::mem::size_of::<BlockEntryFfi>() == 40);
const _: () = assert!(std::mem::offset_of!(BlockEntryFfi, block) == 0);
const _: () = assert!(std::mem::offset_of!(BlockEntryFfi, block_len) == 8);
const _: () = assert!(std::mem::offset_of!(BlockEntryFfi, txs) == 16);
const _: () = assert!(std::mem::offset_of!(BlockEntryFfi, tx_lens) == 24);
const _: () = assert!(std::mem::offset_of!(BlockEntryFfi, tx_count) == 32);

/// Twin of `shekyl_rpc_block_payload`: the variable-length half of a
/// block's facts. Every pointer borrows memory owned by the opaque owner the
/// export returns, and is invalid the moment `shekyl_rpc_block_free` runs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlockPayloadFfi {
    pub blob: *const u8,
    pub blob_len: usize,
    pub json: *const std::os::raw::c_char,
    pub json_len: usize,
    /// `tx_hashes_len * 32` contiguous bytes.
    pub tx_hashes: *const u8,
    /// Number of hashes, not bytes.
    pub tx_hashes_len: usize,
}

// The C++ half of this twin is in tests/unit_tests/rpc_facts_ffi_roundtrip.cpp.
// Pointers have no seed value to fill and compare, so the layout itself is
// what gets pinned: a field reordered or widened on one side and not the
// other is what turns the unsafe reads below into reads of foreign memory.
const _: () = assert!(std::mem::size_of::<BlockPayloadFfi>() == 48);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, blob) == 0);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, blob_len) == 8);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, json) == 16);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, json_len) == 24);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, tx_hashes) == 32);
const _: () = assert!(std::mem::offset_of!(BlockPayloadFfi, tx_hashes_len) == 40);

impl Default for BlockPayloadFfi {
    fn default() -> Self {
        Self {
            blob: std::ptr::null(),
            blob_len: 0,
            json: std::ptr::null(),
            json_len: 0,
            tx_hashes: std::ptr::null(),
            tx_hashes_len: 0,
        }
    }
}

/// Twin of `shekyl_rpc_block_header_facts` (RK-3).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeaderFactsFfi {
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub miner_tx_hash: [u8; 32],
    pub curve_tree_root: [u8; 32],
    pub attestation_root: [u8; 32],
    pub pow_hash: [u8; 32],
    pub height: u64,
    pub depth: u64,
    pub chain_height: u64,
    pub timestamp: u64,
    pub difficulty_lo: u64,
    pub difficulty_hi: u64,
    pub cumulative_difficulty_lo: u64,
    pub cumulative_difficulty_hi: u64,
    pub reward: u64,
    pub block_weight: u64,
    pub long_term_weight: u64,
    pub num_txes: u64,
    pub nonce: u32,
    pub major_version: u8,
    pub minor_version: u8,
    pub orphan_status: u8,
    pub pow_hash_filled: u8,
    pub found: u8,
    pub reserved: [u8; 7],
}

impl BlockHeaderFactsFfi {
    pub(crate) const fn zeroed() -> Self {
        Self {
            hash: [0; 32],
            prev_hash: [0; 32],
            miner_tx_hash: [0; 32],
            curve_tree_root: [0; 32],
            attestation_root: [0; 32],
            pow_hash: [0; 32],
            height: 0,
            depth: 0,
            chain_height: 0,
            timestamp: 0,
            difficulty_lo: 0,
            difficulty_hi: 0,
            cumulative_difficulty_lo: 0,
            cumulative_difficulty_hi: 0,
            reward: 0,
            block_weight: 0,
            long_term_weight: 0,
            num_txes: 0,
            nonce: 0,
            major_version: 0,
            minor_version: 0,
            orphan_status: 0,
            pow_hash_filled: 0,
            found: 0,
            reserved: [0; 7],
        }
    }
}

/// Twin of `shekyl_rpc_hardfork_entry`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardforkEntryFfi {
    pub version: u8,
    pub reserved: [u8; 7],
    pub height: u64,
}

extern "C" {
    pub fn shekyl_rpc_chain_tip(h: *mut CoreRpcHandle, out: *mut ChainTipFactsFfi) -> i32;
    /// Fills a C++-owned view of the hard-fork schedule; release the owner
    /// with `shekyl_rpc_hardforks_free`.
    pub fn shekyl_rpc_hardforks(
        h: *mut CoreRpcHandle,
        out: *mut *const HardforkEntryFfi,
        out_len: *mut usize,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_hardforks_free(owner: *mut std::ffi::c_void);
    pub fn shekyl_rpc_block_hash_at(
        h: *mut CoreRpcHandle,
        height: u64,
        out: *mut BlockHashFactsFfi,
    ) -> i32;
    /// A whole block by hash (32 bytes) or, with `block_hash` null, by
    /// height. On OK with `found == 1` the payload borrows memory owned by
    /// `*out_owner`, which must be released with `shekyl_rpc_block_free`.
    pub fn shekyl_rpc_block_at(
        h: *mut CoreRpcHandle,
        block_hash: *const u8,
        height: u64,
        fill_pow_hash: u8,
        out_header: *mut BlockHeaderFactsFfi,
        out_payload: *mut BlockPayloadFfi,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_block_free(owner: *mut std::ffi::c_void);
    /// Global output indices of one transaction. `out_found` is 0 when no
    /// such transaction exists; on OK the view is valid until
    /// `shekyl_rpc_tx_output_indices_free`.
    pub fn shekyl_rpc_tx_output_indices(
        h: *mut CoreRpcHandle,
        txid: *const u8,
        out: *mut *const u64,
        out_len: *mut usize,
        out_found: *mut u8,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_tx_output_indices_free(owner: *mut std::ffi::c_void);
    /// Blocks at the given heights, in order. `out_ok` is 0 when a height
    /// could not be read, with `out_failed_height` naming it.
    pub fn shekyl_rpc_blocks_by_height(
        h: *mut CoreRpcHandle,
        heights: *const u64,
        heights_len: usize,
        out: *mut *const BlockEntryFfi,
        out_len: *mut usize,
        out_failed_height: *mut u64,
        out_ok: *mut u8,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_blocks_by_height_free(owner: *mut std::ffi::c_void);
    pub fn shekyl_rpc_block_header_at(
        h: *mut CoreRpcHandle,
        height: u64,
        fill_pow_hash: u8,
        out: *mut BlockHeaderFactsFfi,
    ) -> i32;
}

extern "C" {
    pub fn core_rpc_ffi_create(rpc_server_ptr: *mut std::ffi::c_void) -> *mut CoreRpcHandle;
    pub fn core_rpc_ffi_destroy(h: *mut CoreRpcHandle);

    /// §55: relay stem-outcome tallies as a JSON array. Caller frees.
    ///
    /// **Transit, not structure** — the tallies are Rust's (the relay zone
    /// owns them) and this consumer is Rust; the hop out to C++ and back
    /// exists only because C++ `net_node` owns the zone handles' lifetime.
    /// It disappears with the p2p migration, at which point this crate reads
    /// the zone directly. Do not build on the round trip.
    pub fn core_rpc_ffi_stem_tallies(h: *mut CoreRpcHandle) -> *mut std::os::raw::c_char;

    pub fn core_rpc_ffi_json_endpoint(
        h: *mut CoreRpcHandle,
        uri: *const c_char,
        body_json: *const c_char,
    ) -> *mut c_char;

    pub fn core_rpc_ffi_json_rpc(
        h: *mut CoreRpcHandle,
        method: *const c_char,
        params_json: *const c_char,
    ) -> *mut c_char;

    pub fn core_rpc_ffi_free_string(s: *mut c_char);

    // Submit shims (daemon_submit_ffi.h §4.1–§4.3). Contracts documented on
    // the C++ declarations; `FfiSubmitShim` is the only caller.
    #[allow(clippy::too_many_arguments)]
    pub fn shekyl_submit_snapshot_facts(
        h: *mut CoreRpcHandle,
        txid: *const u8,
        key_images: *const u8,
        n_key_images: usize,
        reference_block: *const u8,
        bond_p_canonical_id: *const u8,
        bond_probe_kind: u8,
        emission_p_canonical_id: *const u8,
        emission_epochs: *const u64,
        n_emission_epochs: usize,
        out_emission: *mut *mut SubmitEmissionFactsHandle,
        out_unbond: *mut *mut SubmitUnbondFactsHandle,
        out_facts: *mut SubmitFactsFfi,
        out_ki_conflicts: *mut u8,
    ) -> i32;

    pub fn shekyl_submit_emission_facts_view(
        h: *const SubmitEmissionFactsHandle,
    ) -> *const SubmitEmissionFactsFfi;

    pub fn shekyl_submit_emission_facts_free(h: *mut SubmitEmissionFactsHandle);

    pub fn shekyl_submit_unbond_facts_view(
        h: *const SubmitUnbondFactsHandle,
    ) -> *const SubmitUnbondFactsFfi;

    pub fn shekyl_submit_unbond_facts_free(h: *mut SubmitUnbondFactsHandle);

    #[allow(clippy::too_many_arguments)]
    pub fn shekyl_submit_commit_tx(
        h: *mut CoreRpcHandle,
        blob: *const u8,
        blob_len: usize,
        txid: *const u8,
        tx_weight: u64,
        fee: u64,
        cert_ref_block: *const u8,
        cert_ref_height: u64,
        cert_root: *const u8,
        out_fresh_facts: *mut SubmitFactsFfi,
        out_fresh_ki_conflicts: *mut u8,
        n_key_images: usize,
    ) -> i32;

    pub fn shekyl_submit_relay_tx(h: *mut CoreRpcHandle, txid: *const u8) -> i32;

    // The §4.5 round-trip test hooks (C++ `shekyl_submit_facts_test_*`) are
    // deliberately not declared here: the bidirectional layout test is
    // C++-driven (tests/unit_tests/daemon_submit_ffi_roundtrip.cpp), which
    // calls the Rust twins exported from ffi_exports.rs. No Rust caller of
    // the C++ hooks exists.
}

/// Link-time stubs for the crate's **unit** tests only.
///
/// The lib test binary links no C++ archive, and GNU ld resolves every
/// symbol a retained function references — the console's remote-arm tests
/// reach `FfiChainFacts` through the same function as the live arm, so the
/// five symbols that path names must exist. Each stub is the "no core here"
/// answer: a null handle or the NULL error code. Only symbols a unit test
/// actually retains are stubbed; a new one shows up as a link error, never
/// as a silently-stubbed production path. Integration tests (`tests/*.rs`)
/// link the lib without `cfg(test)` and see none of this.
#[cfg(test)]
mod unit_test_link_stubs {
    use super::*;

    #[no_mangle]
    pub extern "C" fn core_rpc_ffi_create(_p: *mut std::ffi::c_void) -> *mut CoreRpcHandle {
        std::ptr::null_mut()
    }
    #[no_mangle]
    pub extern "C" fn core_rpc_ffi_destroy(_h: *mut CoreRpcHandle) {}
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_chain_tip(
        _h: *mut CoreRpcHandle,
        _out: *mut ChainTipFactsFfi,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_hardforks(
        _h: *mut CoreRpcHandle,
        _out: *mut *const HardforkEntryFfi,
        _out_len: *mut usize,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_hardforks_free(_owner: *mut std::ffi::c_void) {}
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_block_at(
        _h: *mut CoreRpcHandle,
        _block_hash: *const u8,
        _height: u64,
        _fill_pow_hash: u8,
        _out_header: *mut BlockHeaderFactsFfi,
        _out_payload: *mut BlockPayloadFfi,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_block_free(_owner: *mut std::ffi::c_void) {}
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_tx_output_indices(
        _h: *mut CoreRpcHandle,
        _txid: *const u8,
        _out: *mut *const u64,
        _out_len: *mut usize,
        _out_found: *mut u8,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_tx_output_indices_free(_owner: *mut std::ffi::c_void) {}
    #[no_mangle]
    #[allow(clippy::too_many_arguments)]
    pub extern "C" fn shekyl_rpc_blocks_by_height(
        _h: *mut CoreRpcHandle,
        _heights: *const u64,
        _heights_len: usize,
        _out: *mut *const BlockEntryFfi,
        _out_len: *mut usize,
        _out_failed_height: *mut u64,
        _out_ok: *mut u8,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_blocks_by_height_free(_owner: *mut std::ffi::c_void) {}
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_block_hash_at(
        _h: *mut CoreRpcHandle,
        _height: u64,
        _out: *mut BlockHashFactsFfi,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_block_header_at(
        _h: *mut CoreRpcHandle,
        _height: u64,
        _fill_pow_hash: u8,
        _out: *mut BlockHeaderFactsFfi,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
}
