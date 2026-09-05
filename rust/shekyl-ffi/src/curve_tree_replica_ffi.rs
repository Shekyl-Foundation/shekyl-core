// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for a curve-tree **replica**: an in-process, ephemeral
//! [`CurveTreeClient`] that the C++ test generator
//! (`tests/core_tests/chaingen.cpp`) drives to compute the
//! `curve_tree_root` a block header must carry.
//!
//! Why a generator needs it: a block's header commits to the curve-tree
//! state at the block's own height — after its parent connected, before its
//! own drain (`FCMP_PLUS_PLUS.md` §5, CEN-I12) — and the daemon checks that
//! commitment at admission on every nettype (CEN-B5). The daemon computes
//! the state in its store as blocks connect; the generator builds blocks
//! before any store exists, so it needs the same state machine. This
//! crate's client is that machine, and its parity with the daemon's store is
//! KAT-pinned (`shekyl-curve-tree/tests/recon_kat.rs`). Every generated block
//! that connects is therefore a live parity check between the two
//! implementations, at every height, on every core test.
//!
//! Contract (mirrors the client's): blocks are ingested in strictly
//! consecutive height order from `0`; transactions in C++ order, coinbase
//! first; [`shekyl_curve_tree_replica_next_block_root`] is the state at chain
//! height `tip + 1` — what a block built on the tip commits to, and what the
//! daemon's `get_curve_tree_root()` reports once the tip has connected. A
//! fresh replica reports the empty-tree sentinel: the genesis header.
//! Forks: [`shekyl_curve_tree_replica_rollback_to_fork`] keeps heights
//! `0..=fork_height`; a different genesis needs a new replica.
//!
//! Every failure returns `false` and logs the client error; nothing is
//! silently substituted, because a substituted root would surface as a
//! rejected block ten or sixty blocks later with no pointer back here.
//!
//! Cost: `next_block_root` is a producer-side read, not a hot path. On any
//! chain with coinbases a bucket matures at every height past the first
//! window, so past height 60 it rebuilds the tree from the client's in-memory
//! entries on every call -- linear in the drained leaves per header, quadratic
//! over a generated chain. Fine for the hundreds of blocks a core test
//! builds; a generator run over thousands of blocks should be measured.
//!
//! Not a daemon surface: nothing in `src/` outside the test tree calls it.

use shekyl_curve_tree::client::{BlockLeaves, CurveTreeClient, RawOutput, TxLeafInputs};
use shekyl_curve_tree::types::{BlockHeight, TargetKind};

/// One output's leaf-relevant facts, as the C++ side decodes them from a
/// `cryptonote::transaction` (`vout[i]` + `ct_signatures.outPk[i].mask`).
/// Layout pinned by the matching definition in `src/shekyl/shekyl_ffi.h`.
#[repr(C)]
pub struct ShekylCurveTreeReplicaOutput {
    /// Compressed Ed25519 output public key (`O`).
    pub output_key: [u8; 32],
    /// Amount commitment (`C`); ignored when `has_commitment == 0`.
    pub commitment: [u8; 32],
    /// `0` when the output has no `outPk` slot (leaf-ineligible, still
    /// consumes a global output index), `1` otherwise.
    pub has_commitment: u8,
    /// Output target kind: `0` = `txout_to_tagged_key`, `1` = `txout_to_key`,
    /// `2` = any other variant (not a leaf candidate). Anything else is
    /// rejected.
    pub target_kind: u8,
}

/// One transaction's leaf inputs in `vout` order.
#[repr(C)]
pub struct ShekylCurveTreeReplicaTx {
    /// `1` for the block's coinbase, `0` otherwise (decides maturity).
    pub is_miner: u8,
    /// `1` when the transaction carries a `tx_extra` `0x07` leaf-hash tag.
    pub has_leaf_hash_blob: u8,
    /// The raw `0x07` payload (`leaf_hash_blob_len` bytes); ignored when
    /// `has_leaf_hash_blob == 0`.
    pub leaf_hash_blob: *const u8,
    pub leaf_hash_blob_len: usize,
    /// `n_outputs` entries in `vout` order.
    pub outputs: *const ShekylCurveTreeReplicaOutput,
    pub n_outputs: usize,
}

// Layout pins, mirrored by the static_asserts in `src/shekyl/shekyl_ffi.h`
// (rule 40): a drift here is silent -- wrong roots, a block rejected sixty
// heights later, no pointer back.
const _: () = assert!(std::mem::offset_of!(ShekylCurveTreeReplicaOutput, output_key) == 0);
const _: () = assert!(std::mem::offset_of!(ShekylCurveTreeReplicaOutput, commitment) == 32);
const _: () = assert!(std::mem::offset_of!(ShekylCurveTreeReplicaOutput, has_commitment) == 64);
const _: () = assert!(std::mem::offset_of!(ShekylCurveTreeReplicaOutput, target_kind) == 65);
const _: () = assert!(std::mem::size_of::<ShekylCurveTreeReplicaOutput>() == 66);
const PTR: usize = std::mem::size_of::<usize>();
const _: () = assert!(std::mem::offset_of!(ShekylCurveTreeReplicaTx, is_miner) == 0);
const _: () = assert!(std::mem::offset_of!(ShekylCurveTreeReplicaTx, has_leaf_hash_blob) == 1);
const _: () = assert!(std::mem::offset_of!(ShekylCurveTreeReplicaTx, leaf_hash_blob) == PTR);
const _: () =
    assert!(std::mem::offset_of!(ShekylCurveTreeReplicaTx, leaf_hash_blob_len) == 2 * PTR);
const _: () = assert!(std::mem::offset_of!(ShekylCurveTreeReplicaTx, outputs) == 3 * PTR);
const _: () = assert!(std::mem::offset_of!(ShekylCurveTreeReplicaTx, n_outputs) == 4 * PTR);
const _: () = assert!(std::mem::size_of::<ShekylCurveTreeReplicaTx>() == 5 * PTR);

/// Opaque replica handle.
pub struct ShekylCurveTreeReplica {
    client: CurveTreeClient,
}

/// Create an empty replica (no blocks ingested). Returns null if the
/// ephemeral store cannot be opened. Free with
/// [`shekyl_curve_tree_replica_free`].
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_replica_new() -> *mut ShekylCurveTreeReplica {
    match CurveTreeClient::try_new() {
        Ok(client) => Box::into_raw(Box::new(ShekylCurveTreeReplica { client })),
        Err(err) => {
            tracing::error!("curve-tree replica: cannot open ephemeral store: {err:?}");
            std::ptr::null_mut()
        }
    }
}

/// Destroy a replica. `replica` must be null or a pointer returned by
/// [`shekyl_curve_tree_replica_new`] that has not been freed.
///
/// # Safety
/// See above; double-free is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_replica_free(replica: *mut ShekylCurveTreeReplica) {
    if !replica.is_null() {
        // SAFETY: the caller's contract — a live pointer from `_new`.
        drop(unsafe { Box::from_raw(replica) });
    }
}

/// Borrow a slice from a (pointer, len) pair, tolerating a null pointer when
/// `len == 0` (an empty `std::vector` may hand over null).
unsafe fn borrow<'a, T>(ptr: *const T, len: usize) -> Option<&'a [T]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non-null with `len` valid, initialized elements per the
    // caller's contract; the borrow does not outlive the FFI call.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// One decoded transaction before the borrowing `TxLeafInputs` view is built:
/// `(is_miner, leaf-hash blob, outputs)`.
type DecodedTx<'a> = (bool, Option<&'a [u8]>, Vec<RawOutput>);

fn target_kind(raw: u8) -> Option<TargetKind> {
    match raw {
        0 => Some(TargetKind::TaggedKey),
        1 => Some(TargetKind::Key),
        2 => Some(TargetKind::Other),
        _ => None,
    }
}

/// Ingest one block at `height` (strictly `tip + 1`, or `0` for a fresh
/// replica). `txs` holds `n_txs` transactions in block order, coinbase first.
/// Returns `false` (and logs) on a null pointer, an unknown target kind, or
/// any client error — a non-consecutive height included.
///
/// # Safety
/// `replica` is a live handle; `txs` points to `n_txs` initialized entries
/// whose inner pointers are valid for their stated lengths for the duration
/// of the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_replica_ingest_block(
    replica: *mut ShekylCurveTreeReplica,
    height: u64,
    txs: *const ShekylCurveTreeReplicaTx,
    n_txs: usize,
) -> bool {
    if replica.is_null() {
        tracing::error!("curve-tree replica: ingest on a null handle");
        return false;
    }
    // SAFETY: caller contract — live handle, `n_txs` entries.
    let (replica, raw_txs) = unsafe {
        let Some(raw_txs) = borrow(txs, n_txs) else {
            tracing::error!("curve-tree replica: null tx array with n_txs = {n_txs}");
            return false;
        };
        (&mut *replica, raw_txs)
    };

    // Two passes because `TxLeafInputs` borrows the `RawOutput` slices: decode
    // every tx's outputs first, then build the borrowing views.
    let mut decoded: Vec<DecodedTx<'_>> = Vec::with_capacity(raw_txs.len());
    for (ti, tx) in raw_txs.iter().enumerate() {
        // SAFETY: caller contract on the inner pointers.
        let (blob, outs) = unsafe {
            let blob = if tx.has_leaf_hash_blob != 0 {
                let Some(b) = borrow(tx.leaf_hash_blob, tx.leaf_hash_blob_len) else {
                    tracing::error!("curve-tree replica: tx {ti} has a null leaf-hash blob");
                    return false;
                };
                Some(b)
            } else {
                None
            };
            let Some(outs) = borrow(tx.outputs, tx.n_outputs) else {
                tracing::error!("curve-tree replica: tx {ti} has a null output array");
                return false;
            };
            (blob, outs)
        };
        let mut outputs = Vec::with_capacity(outs.len());
        for (oi, o) in outs.iter().enumerate() {
            let Some(target) = target_kind(o.target_kind) else {
                tracing::error!(
                    "curve-tree replica: tx {ti} output {oi} has unknown target kind {}",
                    o.target_kind
                );
                return false;
            };
            outputs.push(RawOutput {
                output_key: o.output_key,
                commitment: (o.has_commitment != 0).then_some(o.commitment),
                target,
            });
        }
        decoded.push((tx.is_miner != 0, blob, outputs));
    }
    let views: Vec<TxLeafInputs<'_>> = decoded
        .iter()
        .map(|(is_miner, blob, outputs)| TxLeafInputs {
            is_miner: *is_miner,
            leaf_hash_blob: *blob,
            outputs,
        })
        .collect();

    match replica.client.ingest_block(BlockLeaves {
        height: BlockHeight(height),
        txs: &views,
    }) {
        Ok(()) => true,
        Err(err) => {
            tracing::error!("curve-tree replica: ingest of height {height} failed: {err:?}");
            false
        }
    }
}

/// Roll back so that heights `0..=fork_height` remain ingested. Returns
/// `false` (and logs) on a null handle, an above-tip request, or a client
/// error; on the poisoned-client failure mode the handle is unusable and
/// must be freed (the client's CT-5 poison contract).
///
/// # Safety
/// `replica` is a live handle.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_replica_rollback_to_fork(
    replica: *mut ShekylCurveTreeReplica,
    fork_height: u64,
) -> bool {
    if replica.is_null() {
        tracing::error!("curve-tree replica: rollback on a null handle");
        return false;
    }
    // SAFETY: caller contract.
    let replica = unsafe { &mut *replica };
    match replica.client.rollback_to_fork(BlockHeight(fork_height)) {
        Ok(()) => true,
        Err(err) => {
            tracing::error!("curve-tree replica: rollback to {fork_height} failed: {err:?}");
            false
        }
    }
}

/// The ingested tip height. Returns `false` when no block has been ingested
/// (`out_height` untouched) or on a null pointer.
///
/// # Safety
/// `replica` is a live handle; `out_height` is a valid, writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_replica_tip_height(
    replica: *const ShekylCurveTreeReplica,
    out_height: *mut u64,
) -> bool {
    if replica.is_null() || out_height.is_null() {
        return false;
    }
    // SAFETY: caller contract.
    let replica = unsafe { &*replica };
    match replica.client.ingested_tip_height() {
        Some(tip) => {
            // SAFETY: caller contract on `out_height`.
            unsafe { *out_height = tip.0 };
            true
        }
        None => false,
    }
}

/// The `curve_tree_root` a block built on the current tip must carry: the
/// tree state at chain height `tip + 1`. For a fresh replica, the empty-tree
/// sentinel (the genesis header). Returns `false` (and logs) on a null
/// pointer or a client error.
///
/// # Safety
/// `replica` is a live handle; `out_root` is a valid, writable 32-byte
/// buffer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_replica_next_block_root(
    replica: *const ShekylCurveTreeReplica,
    out_root: *mut [u8; 32],
) -> bool {
    if replica.is_null() || out_root.is_null() {
        tracing::error!("curve-tree replica: next_block_root with a null pointer");
        return false;
    }
    // SAFETY: caller contract.
    let replica = unsafe { &*replica };
    match replica.client.next_block_root() {
        Ok(root) => {
            // SAFETY: caller contract on `out_root`.
            unsafe { *out_root = root };
            true
        }
        Err(err) => {
            tracing::error!("curve-tree replica: next_block_root failed: {err:?}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A leaf-eligible output: both points must be canonical, prime-order and
    /// non-identity or the leaf builder skips the output (no leaf entry, no
    /// tip after a rollback to a leafless genesis). The Ed25519 basepoint
    /// serves for both.
    fn tagged() -> ShekylCurveTreeReplicaOutput {
        let mut g = [0x66u8; 32];
        g[0] = 0x58;
        ShekylCurveTreeReplicaOutput {
            output_key: g,
            commitment: g,
            has_commitment: 1,
            target_kind: 0,
        }
    }

    fn coinbase(outs: &[ShekylCurveTreeReplicaOutput]) -> ShekylCurveTreeReplicaTx {
        ShekylCurveTreeReplicaTx {
            is_miner: 1,
            has_leaf_hash_blob: 0,
            leaf_hash_blob: std::ptr::null(),
            leaf_hash_blob_len: 0,
            outputs: outs.as_ptr(),
            n_outputs: outs.len(),
        }
    }

    /// The replica reports the empty-tree sentinel before any block, ingests
    /// consecutive heights, refuses a gap, rolls back, and re-ingests.
    #[test]
    fn replica_lifecycle_through_the_ffi() {
        let r = shekyl_curve_tree_replica_new();
        assert!(!r.is_null());
        let mut root = [0u8; 32];
        let sentinel = shekyl_fcmp::tree::selene_hash_init();
        unsafe {
            assert!(shekyl_curve_tree_replica_next_block_root(
                r,
                std::ptr::addr_of_mut!(root)
            ));
            assert_eq!(root, sentinel, "fresh replica is the empty tree");
            let mut tip = u64::MAX;
            assert!(!shekyl_curve_tree_replica_tip_height(
                r,
                std::ptr::addr_of_mut!(tip)
            ));

            let o0 = [tagged()];
            let t0 = [coinbase(&o0)];
            assert!(shekyl_curve_tree_replica_ingest_block(r, 0, t0.as_ptr(), 1));
            assert!(shekyl_curve_tree_replica_tip_height(
                r,
                std::ptr::addr_of_mut!(tip)
            ));
            assert_eq!(tip, 0);
            // Gap: height 2 after 0 is refused, tip unchanged.
            assert!(!shekyl_curve_tree_replica_ingest_block(
                r,
                2,
                t0.as_ptr(),
                1
            ));
            assert!(shekyl_curve_tree_replica_tip_height(
                r,
                std::ptr::addr_of_mut!(tip)
            ));
            assert_eq!(tip, 0);
            assert!(shekyl_curve_tree_replica_ingest_block(r, 1, t0.as_ptr(), 1));
            assert!(shekyl_curve_tree_replica_rollback_to_fork(r, 0));
            assert!(shekyl_curve_tree_replica_tip_height(
                r,
                std::ptr::addr_of_mut!(tip)
            ));
            assert_eq!(tip, 0);
            assert!(shekyl_curve_tree_replica_ingest_block(r, 1, t0.as_ptr(), 1));
            // Unknown target kind is refused, not mapped.
            let bad = [ShekylCurveTreeReplicaOutput {
                target_kind: 9,
                ..tagged()
            }];
            let tb = [coinbase(&bad)];
            assert!(!shekyl_curve_tree_replica_ingest_block(
                r,
                2,
                tb.as_ptr(),
                1
            ));
            // Null handle never dereferences.
            assert!(!shekyl_curve_tree_replica_next_block_root(
                std::ptr::null(),
                std::ptr::addr_of_mut!(root)
            ));
            shekyl_curve_tree_replica_free(r);
            shekyl_curve_tree_replica_free(std::ptr::null_mut());
        }
    }
}
