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
    /// The probed record's bonded total; valid iff `bond_record_probed` and
    /// the probe was [`SHEKYL_SUBMIT_BOND_PROBE_UNBOND`].
    ///
    /// Presence does not move when a persona exits — `apply_archival_unbond`
    /// rewrites the row with a zero bonded total rather than deleting it — so
    /// the debit arm's Phase-D re-check reads the balance instead.
    pub bond_record_bonded_total: u64,
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
            bond_record_bonded_total: 0,
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
const _: () = assert!(std::mem::size_of::<SubmitFactsFfi>() == 104);
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
const _: () = assert!(std::mem::offset_of!(SubmitFactsFfi, bond_record_bonded_total) == 96);
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
    /// 1 = the gather did NOT run the per-shard scan, so the slice is
    /// empty-because-**unread** rather than empty-because-never-served.
    /// Folding it would give the permissive "never served" cooldown answer,
    /// so a consumer must refuse rather than fold.
    ///
    /// **Says nothing about authorization.** The gather skips whenever a
    /// pre-scan guard shows the scan cannot change the answer: an already-known
    /// txid, a failed debit pin, a zero balance, a balance the vin's
    /// `bond_debit` no longer matches, or a full bad-interval log. Inferring
    /// "the pin failed" from this byte was true of an earlier revision and is
    /// not true now; the reasons are listed on `fill_unbond_facts_locked`,
    /// which owns them.
    pub last_served_scan_skipped: u8,
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

/// Twin of `shekyl_rpc_tx_entry`: one requested transaction's answer (RK-4c),
/// indexed by request position. Every pointer borrows memory owned by the
/// opaque owner the export returns, and is invalid the moment
/// `shekyl_rpc_transactions_free` runs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TxEntryFfi {
    pub pruned: *const u8,
    pub pruned_len: usize,
    pub prunable: *const u8,
    pub prunable_len: usize,
    pub output_indices: *const u64,
    pub output_indices_len: usize,
    pub block_height: u64,
    pub block_timestamp: u64,
    pub received_timestamp: u64,
    pub prunable_hash: [u8; 32],
    /// 0 = not found, 1 = chain, 2 = pool.
    pub where_found: u8,
    pub pruned_flag: u8,
    pub double_spend_seen: u8,
    pub relayed: u8,
    pub reserved: [u8; 4],
}

const _: () = assert!(std::mem::size_of::<TxEntryFfi>() == 112);
const _: () = assert!(std::mem::align_of::<TxEntryFfi>() == 8);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, pruned) == 0);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, pruned_len) == 8);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, prunable) == 16);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, prunable_len) == 24);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, output_indices) == 32);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, output_indices_len) == 40);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, block_height) == 48);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, block_timestamp) == 56);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, received_timestamp) == 64);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, prunable_hash) == 72);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, where_found) == 104);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, pruned_flag) == 105);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, double_spend_seen) == 106);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, relayed) == 107);
const _: () = assert!(std::mem::offset_of!(TxEntryFfi, reserved) == 108);

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

/// Twin of `shekyl_rpc_hard_fork_facts` (RK-5b).
///
/// **Two versions, named apart.** `queried_version` is what the voting fields
/// describe — the caller's, or the resolved next-fork version when the caller
/// asked with none. `active_version` is the chain's current fork. The C++ this
/// replaces reported the second under the name `version` while the voting
/// fields described the first, and echoed nothing of the query.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardForkFactsFfi {
    pub earliest_height: u64,
    pub window: u32,
    pub votes: u32,
    pub threshold: u32,
    pub state: u32,
    pub queried_version: u8,
    pub active_version: u8,
    pub voting: u8,
    pub enabled: u8,
    pub reserved: [u8; 4],
}

/// Twin of `shekyl_rpc_fee_estimate_facts` (RK-5b).
///
/// `fees` is fixed at four because the estimator produces exactly four tiers
/// (Fl, Fn, Fm, Fh). `fee_count` reports how many it actually wrote, so a
/// change to that contract is a refusal rather than a shorter answer read as
/// a base fee.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeEstimateFactsFfi {
    pub fees: [u64; 4],
    pub quantization_mask: u64,
    pub fee_count: u8,
    pub reserved: [u8; 7],
}

const _: () = assert!(std::mem::size_of::<HardForkFactsFfi>() == 32);
const _: () = assert!(std::mem::offset_of!(HardForkFactsFfi, earliest_height) == 0);
const _: () = assert!(std::mem::offset_of!(HardForkFactsFfi, window) == 8);
const _: () = assert!(std::mem::offset_of!(HardForkFactsFfi, votes) == 12);
const _: () = assert!(std::mem::offset_of!(HardForkFactsFfi, threshold) == 16);
const _: () = assert!(std::mem::offset_of!(HardForkFactsFfi, state) == 20);
const _: () = assert!(std::mem::offset_of!(HardForkFactsFfi, queried_version) == 24);
const _: () = assert!(std::mem::offset_of!(HardForkFactsFfi, active_version) == 25);
const _: () = assert!(std::mem::offset_of!(HardForkFactsFfi, voting) == 26);
const _: () = assert!(std::mem::offset_of!(HardForkFactsFfi, enabled) == 27);
const _: () = assert!(std::mem::offset_of!(HardForkFactsFfi, reserved) == 28);

const _: () = assert!(std::mem::size_of::<FeeEstimateFactsFfi>() == 48);
const _: () = assert!(std::mem::offset_of!(FeeEstimateFactsFfi, fees) == 0);
const _: () = assert!(std::mem::offset_of!(FeeEstimateFactsFfi, quantization_mask) == 32);
const _: () = assert!(std::mem::offset_of!(FeeEstimateFactsFfi, fee_count) == 40);
const _: () = assert!(std::mem::offset_of!(FeeEstimateFactsFfi, reserved) == 41);

/// Twin of `shekyl_rpc_net_stats_facts` (RK-5a). Layout pinned both
/// directions by `tests/unit_tests/rpc_facts_ffi_roundtrip.cpp` via
/// `shekyl_rpc_net_stats_facts_rust_{fill,check}`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetStatsFactsFfi {
    /// Unix seconds; the core's start.
    pub start_time: u64,
    pub total_packets_in: u64,
    pub total_bytes_in: u64,
    pub total_packets_out: u64,
    pub total_bytes_out: u64,
}

/// Twin of `shekyl_rpc_connection_facts` (RK-5a).
///
/// Raw, absolute values: the wire's elapsed quantities and rates are derived
/// from these against the `now` that `shekyl_rpc_connections` reports beside
/// the list. Pointers have no seed value, so this one is pinned by **layout**
/// — size and every offset, asserted on both sides.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectionFactsFfi {
    /// `network_address::str()`: "host:port" for ipv4, the onion for tor.
    pub address: *const u8,
    pub address_len: usize,
    /// `network_address::host_str()`: the host alone.
    pub host: *const u8,
    pub host_len: usize,
    pub peer_id: u64,
    pub connection_id: [u8; 16],
    /// Unix seconds.
    pub started: u64,
    pub last_recv: u64,
    pub last_send: u64,
    /// Bytes, absolute.
    pub recv_count: u64,
    pub send_count: u64,
    /// Bytes/s, raw — the clamp to an integer is this side's job.
    pub current_speed_down: f64,
    pub current_speed_up: f64,
    /// The peer's claimed blockchain height.
    pub height: u64,
    pub support_flags: u32,
    pub pruning_seed: u32,
    pub port: u16,
    /// `cryptonote_connection_context::state`.
    pub state: u8,
    /// epee type id: 1 ipv4, 2 ipv6, 4 tor, …
    pub address_type: u8,
    pub incoming: u8,
    pub localhost: u8,
    pub local_ip: u8,
    pub reserved: [u8; 9],
}

/// Twin of `shekyl_rpc_sync_span_facts` (RK-5a). Pinned by layout.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SyncSpanFactsFfi {
    /// `network_address::str()` of the span's origin.
    pub remote_address: *const u8,
    pub remote_address_len: usize,
    pub start_block_height: u64,
    pub nblocks: u64,
    /// Bytes held for this span.
    pub size: u64,
    pub connection_id: [u8; 16],
    /// Bytes/s.
    pub rate: f32,
    /// 0..1; the wire carries 100x this.
    pub speed_fraction: f32,
    /// Whether the span's blocks have arrived, as opposed to being requested
    /// and still outstanding.
    pub filled: u8,
    pub reserved: [u8; 7],
}

/// Twin of `shekyl_rpc_peer_facts` (RK-5a). Pinned by layout.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PeerFactsFfi {
    /// Already resolved per address arm by the adapter — the ip string for
    /// ipv4, `host_str()` for ipv6, the whole `str()` for anything else.
    pub host: *const u8,
    pub host_len: usize,
    pub id: u64,
    pub last_seen: u64,
    /// The ipv4 address with its four octets in **network** order, as
    /// `ipv4_network_address::ip()` returns it; 0 for every other arm.
    pub ip: u32,
    pub pruning_seed: u32,
    /// 0 for the address arms that carry none.
    pub port: u16,
    /// 1 = white list, 0 = gray.
    pub white: u8,
    /// Filled unconditionally; applying `include_blocked` is this side's job.
    pub blocked: u8,
    pub reserved: [u8; 4],
}

// RK-5a layout pins. `ConnectionFactsFfi`, `SyncSpanFactsFfi` and
// `PeerFactsFfi` carry pointers, so there is no fill/check twin to catch a
// disagreement — these asserts and their `static_assert` counterparts in
// `tests/unit_tests/rpc_facts_ffi_roundtrip.cpp` are the whole pin.
const _: () = assert!(std::mem::size_of::<NetStatsFactsFfi>() == 40);

const _: () = assert!(std::mem::size_of::<ConnectionFactsFfi>() == 144);
const _: () = assert!(std::mem::align_of::<ConnectionFactsFfi>() == 8);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, address) == 0);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, address_len) == 8);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, host) == 16);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, host_len) == 24);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, peer_id) == 32);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, connection_id) == 40);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, started) == 56);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, last_recv) == 64);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, last_send) == 72);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, recv_count) == 80);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, send_count) == 88);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, current_speed_down) == 96);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, current_speed_up) == 104);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, height) == 112);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, support_flags) == 120);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, pruning_seed) == 124);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, port) == 128);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, state) == 130);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, address_type) == 131);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, incoming) == 132);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, localhost) == 133);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, local_ip) == 134);
const _: () = assert!(std::mem::offset_of!(ConnectionFactsFfi, reserved) == 135);

const _: () = assert!(std::mem::size_of::<SyncSpanFactsFfi>() == 72);
const _: () = assert!(std::mem::align_of::<SyncSpanFactsFfi>() == 8);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, remote_address) == 0);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, remote_address_len) == 8);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, start_block_height) == 16);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, nblocks) == 24);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, size) == 32);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, connection_id) == 40);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, rate) == 56);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, speed_fraction) == 60);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, filled) == 64);
const _: () = assert!(std::mem::offset_of!(SyncSpanFactsFfi, reserved) == 65);

const _: () = assert!(std::mem::size_of::<PeerFactsFfi>() == 48);
const _: () = assert!(std::mem::align_of::<PeerFactsFfi>() == 8);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, host) == 0);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, host_len) == 8);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, id) == 16);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, last_seen) == 24);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, ip) == 32);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, pruning_seed) == 36);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, port) == 40);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, white) == 42);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, blocked) == 43);
const _: () = assert!(std::mem::offset_of!(PeerFactsFfi, reserved) == 44);

extern "C" {
    pub fn shekyl_rpc_hard_fork_info(
        h: *mut CoreRpcHandle,
        requested_version: u8,
        out: *mut HardForkFactsFfi,
    ) -> i32;
    pub fn shekyl_rpc_fee_estimate(
        h: *mut CoreRpcHandle,
        grace_blocks: u64,
        out: *mut FeeEstimateFactsFfi,
    ) -> i32;
    /// The grace-blocks ceiling the estimator asserts on. Handle-free.
    pub fn shekyl_rpc_fee_grace_blocks_max() -> u64;
    pub fn shekyl_rpc_net_stats(h: *mut CoreRpcHandle, out: *mut NetStatsFactsFfi) -> i32;
    /// Fills a C++-owned view of the live p2p connections plus the single
    /// instant they were read at; release the owner with
    /// `shekyl_rpc_connections_free`.
    pub fn shekyl_rpc_connections(
        h: *mut CoreRpcHandle,
        out_now: *mut u64,
        out: *mut *const ConnectionFactsFfi,
        out_len: *mut usize,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_connections_free(owner: *mut std::ffi::c_void);
    /// The block-download queue plus the stripe this node wants next; release
    /// the owner with `shekyl_rpc_sync_spans_free`.
    pub fn shekyl_rpc_sync_spans(
        h: *mut CoreRpcHandle,
        out_next_needed_pruning_stripe: *mut u32,
        out: *mut *const SyncSpanFactsFfi,
        out_len: *mut usize,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_sync_spans_free(owner: *mut std::ffi::c_void);
    /// White then gray peerlist entries in one array, discriminated by
    /// `white`; release the owner with `shekyl_rpc_peer_list_free`.
    pub fn shekyl_rpc_peer_list(
        h: *mut CoreRpcHandle,
        public_only: u8,
        out: *mut *const PeerFactsFfi,
        out_len: *mut usize,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_peer_list_free(owner: *mut std::ffi::c_void);
    /// The two compile-time p2p peerlist capacities. Takes no handle and
    /// cannot fail.
    pub fn shekyl_rpc_peerlist_limits(out_white: *mut u32, out_gray: *mut u32);
    /// The stripe label for a span's start height. Takes no handle, so the
    /// console can call it on the remote arm too.
    pub fn shekyl_rpc_span_pruning_seed(start_block_height: u64) -> u32;
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

    /// Transactions by hash, answered per request slot (RK-4c). `txids` is
    /// `txids_len * 32` bytes; `out_chain_height` is the tip, read once for
    /// the whole gather. On OK the rows borrow memory owned by `*out_owner`,
    /// released with `shekyl_rpc_transactions_free`.
    pub fn shekyl_rpc_transactions(
        h: *mut CoreRpcHandle,
        txids: *const u8,
        txids_len: usize,
        include_sensitive: u8,
        out: *mut *const TxEntryFfi,
        out_len: *mut usize,
        out_chain_height: *mut u64,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_transactions_free(owner: *mut std::ffi::c_void);

    /// epee's JSON rendering of one transaction (RK-D11). No handle, no lock.
    pub fn shekyl_rpc_tx_to_json(
        blob: *const u8,
        blob_len: usize,
        pruned: u8,
        out: *mut *const std::os::raw::c_char,
        out_len: *mut usize,
        out_owner: *mut *mut std::ffi::c_void,
    ) -> i32;
    pub fn shekyl_rpc_tx_json_free(owner: *mut std::ffi::c_void);

    /// Key images, answered per request slot: `out_status` is a caller-owned
    /// array of `count` bytes (0 unspent, 1 chain, 2 pool). Fixed size, so no
    /// owner.
    pub fn shekyl_rpc_key_images_spent(
        h: *mut CoreRpcHandle,
        key_images: *const u8,
        count: usize,
        out_status: *mut u8,
    ) -> i32;
    pub fn shekyl_rpc_block_header_at(
        h: *mut CoreRpcHandle,
        block_hash: *const u8,
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
        bond_auth_pubkey: *const u8,
        bond_auth_pubkey_len: usize,
        bond_debit: u64,
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
    pub extern "C" fn core_rpc_ffi_json_endpoint(
        _h: *mut CoreRpcHandle,
        _uri: *const std::os::raw::c_char,
        _body: *const std::os::raw::c_char,
    ) -> *mut std::os::raw::c_char {
        std::ptr::null_mut()
    }
    #[no_mangle]
    pub extern "C" fn core_rpc_ffi_free_string(_s: *mut std::os::raw::c_char) {}
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_hard_fork_info(
        _h: *mut CoreRpcHandle,
        _requested_version: u8,
        _out: *mut HardForkFactsFfi,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_fee_estimate(
        _h: *mut CoreRpcHandle,
        _grace_blocks: u64,
        _out: *mut FeeEstimateFactsFfi,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_fee_grace_blocks_max() -> u64 {
        0
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_net_stats(
        _h: *mut CoreRpcHandle,
        _out: *mut NetStatsFactsFfi,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_connections(
        _h: *mut CoreRpcHandle,
        _out_now: *mut u64,
        _out: *mut *const ConnectionFactsFfi,
        _out_len: *mut usize,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_connections_free(_owner: *mut std::ffi::c_void) {}
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_sync_spans(
        _h: *mut CoreRpcHandle,
        _out_stripe: *mut u32,
        _out: *mut *const SyncSpanFactsFfi,
        _out_len: *mut usize,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_sync_spans_free(_owner: *mut std::ffi::c_void) {}
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_peer_list(
        _h: *mut CoreRpcHandle,
        _public_only: u8,
        _out: *mut *const PeerFactsFfi,
        _out_len: *mut usize,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_peer_list_free(_owner: *mut std::ffi::c_void) {}
    // The two constant exports have no "no core here" answer to give, and no
    // unit test may take an answer from them: they exist to carry C++
    // configuration, so a stub returning zero would let a renderer's test
    // silently agree with a value the daemon does not hold. Zero is written
    // anyway — `print_pl_stats` divides by the limit and guards zero — but no
    // unit test calls these paths, and the console e2e exercises the real
    // ones.
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_peerlist_limits(out_white: *mut u32, out_gray: *mut u32) {
        // SAFETY: the caller passes two writable u32 slots or nulls.
        unsafe {
            if !out_white.is_null() {
                out_white.write(0);
            }
            if !out_gray.is_null() {
                out_gray.write(0);
            }
        }
    }
    #[no_mangle]
    pub extern "C" fn shekyl_rpc_span_pruning_seed(_start_block_height: u64) -> u32 {
        0
    }
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
    pub extern "C" fn shekyl_rpc_transactions(
        _h: *mut super::CoreRpcHandle,
        _txids: *const u8,
        _txids_len: usize,
        _include_sensitive: u8,
        _out: *mut *const super::TxEntryFfi,
        _out_len: *mut usize,
        _out_chain_height: *mut u64,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        super::SHEKYL_RPC_FACTS_ERR_NULL
    }

    #[no_mangle]
    pub extern "C" fn shekyl_rpc_transactions_free(_owner: *mut std::ffi::c_void) {}

    #[no_mangle]
    pub extern "C" fn shekyl_rpc_tx_to_json(
        _blob: *const u8,
        _blob_len: usize,
        _pruned: u8,
        _out: *mut *const std::os::raw::c_char,
        _out_len: *mut usize,
        _out_owner: *mut *mut std::ffi::c_void,
    ) -> i32 {
        super::SHEKYL_RPC_FACTS_ERR_NULL
    }

    #[no_mangle]
    pub extern "C" fn shekyl_rpc_tx_json_free(_owner: *mut std::ffi::c_void) {}

    #[no_mangle]
    pub extern "C" fn shekyl_rpc_key_images_spent(
        _h: *mut super::CoreRpcHandle,
        _key_images: *const u8,
        _count: usize,
        _out_status: *mut u8,
    ) -> i32 {
        super::SHEKYL_RPC_FACTS_ERR_NULL
    }
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
        _block_hash: *const u8,
        _height: u64,
        _fill_pow_hash: u8,
        _out: *mut BlockHeaderFactsFfi,
    ) -> i32 {
        SHEKYL_RPC_FACTS_ERR_NULL
    }
}
