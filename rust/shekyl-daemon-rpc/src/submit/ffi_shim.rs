// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The production [`SubmitStateShim`]: a thin marshalling layer over the
//! three C++ FFI shims (`src/rpc/daemon_submit_ffi.h`,
//! `docs/design/DAEMON_SUBMIT_VERDICT.md` §4).
//!
//! Zero verdict logic lives here, matching the C++ side's contract: this
//! module converts pointers and PODs, and every C++ return code maps onto
//! the seam types the engine already classifies ([`SubmitFacts`],
//! [`CommitOutcome`], [`ShimFault`]). A descriptor byte outside the
//! documented `SHEKYL_SUBMIT_KI_*` set is a contract violation and maps to
//! the internal-fault arm — never a guessed fact.

use std::sync::Arc;

use shekyl_types::{BlockHash, BlockHeight, TxHash};

use crate::core::CoreRpc;
use crate::ffi;
use crate::submit::certificate::VerificationCertificate;
use crate::submit::facts::{
    CommitOutcome, KeyImageConflict, ReferenceFacts, ShimFault, SubmitFacts, SubmitStateShim,
    TxMeta,
};

/// Production shim over the `shekyl_submit_*` FFI, sharing the daemon's
/// [`CoreRpc`] handle. All three calls block on the C++ side (short lock
/// scopes); the transport dispatches submissions via `spawn_blocking`.
pub struct FfiSubmitShim {
    core: Arc<CoreRpc>,
}

impl FfiSubmitShim {
    /// Shim over the daemon's live core handle.
    pub fn new(core: Arc<CoreRpc>) -> Self {
        Self { core }
    }
}

/// Convert the POD snapshot + conflict array into the engine's fact type.
/// `Err(())` on a descriptor byte outside the documented set (contract
/// violation; callers map to their internal-fault arm).
fn facts_from_ffi(pod: &ffi::SubmitFactsFfi, ki: &[u8]) -> Result<SubmitFacts, ()> {
    let key_image_conflicts = ki
        .iter()
        .map(|&b| match b {
            ffi::SHEKYL_SUBMIT_KI_FREE => Ok(KeyImageConflict::Free),
            ffi::SHEKYL_SUBMIT_KI_OWN_TX => Ok(KeyImageConflict::OwnTx),
            ffi::SHEKYL_SUBMIT_KI_OTHER => Ok(KeyImageConflict::Other),
            _ => Err(()),
        })
        .collect::<Result<Vec<_>, ()>>()?;

    let reference = (pod.ref_block_found != 0).then(|| ReferenceFacts {
        height: BlockHeight::from_raw(pod.ref_height),
        root: pod.root,
        tree_depth: pod.tree_depth,
    });

    Ok(SubmitFacts {
        in_pool: pod.in_pool != 0,
        in_pool_broadcast: pod.in_pool_broadcast != 0,
        // in_chain_height is valid iff in_chain (§4.1) — the Option encodes
        // the validity gate so the engine cannot read an unset height.
        in_chain: (pod.in_chain != 0).then(|| BlockHeight::from_raw(pod.in_chain_height)),
        key_image_conflicts,
        reference,
        fee_per_byte: pod.fee_per_byte,
        fee_quantization_mask: pod.fee_quantization_mask,
        weight_limit: pod.weight_limit,
        chain_height: BlockHeight::from_raw(pod.chain_height),
    })
}

/// A slice's data pointer, or NULL when the slice is empty. The C++ submit
/// shims accept a NULL key-image pointer **iff** the matching count is 0
/// (their bad-args guard is `n > 0 && !ptr`); an empty slice's `as_ptr()` is a
/// dangling non-null sentinel that would satisfy `!ptr == false` and silently
/// bypass that guard. Single-sourced because a review round (81dea974d) had to
/// fix this same contract at two call sites at once.
fn const_ptr_or_null<T>(slice: &[T]) -> *const T {
    if slice.is_empty() {
        std::ptr::null()
    } else {
        slice.as_ptr()
    }
}

/// Mutable counterpart of [`const_ptr_or_null`] for out-parameter arrays.
fn mut_ptr_or_null<T>(slice: &mut [T]) -> *mut T {
    if slice.is_empty() {
        std::ptr::null_mut()
    } else {
        slice.as_mut_ptr()
    }
}

impl SubmitStateShim for FfiSubmitShim {
    fn snapshot_facts(
        &self,
        txid: &TxHash,
        key_images: &[[u8; 32]],
        reference_block: &BlockHash,
    ) -> Result<SubmitFacts, ShimFault> {
        let mut pod = ffi::SubmitFactsFfi::zeroed();
        let mut ki_conflicts = vec![0u8; key_images.len()];

        // SAFETY: txid/reference_block are 32-byte references; key_images is
        // a flat array of n × 32 bytes (contiguous by `[[u8; 32]]` layout);
        // out pointers are sized above; the handle is live for the daemon's
        // lifetime (CoreRpc's contract). The key-image in/out pointers honor
        // the null-iff-empty contract via the ptr helpers (see their docs).
        let rc = unsafe {
            ffi::shekyl_submit_snapshot_facts(
                self.core.raw_handle(),
                txid.as_bytes().as_ptr(),
                const_ptr_or_null(key_images).cast::<u8>(),
                key_images.len(),
                reference_block.as_bytes().as_ptr(),
                &mut pod,
                mut_ptr_or_null(ki_conflicts.as_mut_slice()),
            )
        };

        if rc != ffi::SHEKYL_SUBMIT_OK {
            tracing::error!(rc, "submit snapshot shim returned fault");
            return Err(ShimFault);
        }
        facts_from_ffi(&pod, &ki_conflicts).map_err(|()| {
            tracing::error!("submit snapshot shim returned unknown key-image descriptor");
            ShimFault
        })
    }

    fn commit(
        &self,
        blob: &[u8],
        txid: &TxHash,
        meta: &TxMeta,
        cert: &VerificationCertificate,
        expected: &SubmitFacts,
    ) -> CommitOutcome {
        let n_key_images = expected.key_image_conflicts.len();
        let mut fresh_pod = ffi::SubmitFactsFfi::zeroed();
        let mut fresh_ki = vec![0u8; n_key_images];

        // SAFETY: blob points at blob_len bytes; txid/cert hashes are
        // 32-byte references; out pointers are sized above (the C++ side
        // release-checks its blob-derived key-image count against
        // n_key_images before writing). The fresh-KI out pointer honors the
        // null-iff-empty contract via `mut_ptr_or_null` (see its doc).
        let rc = unsafe {
            ffi::shekyl_submit_commit_tx(
                self.core.raw_handle(),
                blob.as_ptr(),
                blob.len(),
                txid.as_bytes().as_ptr(),
                meta.weight,
                meta.fee,
                cert.reference_block().as_bytes().as_ptr(),
                cert.ref_height().to_raw(),
                cert.root().as_ptr(),
                &mut fresh_pod,
                mut_ptr_or_null(fresh_ki.as_mut_slice()),
                n_key_images,
            )
        };

        match rc {
            ffi::SHEKYL_SUBMIT_OK => CommitOutcome::Committed,
            ffi::SHEKYL_SUBMIT_PRUNED_ON_INSERT => CommitOutcome::PrunedOnInsert,
            ffi::SHEKYL_SUBMIT_RACED => match facts_from_ffi(&fresh_pod, &fresh_ki) {
                Ok(fresh) => CommitOutcome::Raced(fresh),
                Err(()) => {
                    tracing::error!("submit commit shim returned unknown key-image descriptor");
                    CommitOutcome::InternalFault
                }
            },
            _ => {
                tracing::error!(rc, "submit commit shim returned fault");
                CommitOutcome::InternalFault
            }
        }
    }

    fn relay(&self, txid: &TxHash) {
        // SAFETY: txid is a 32-byte reference; the handle is live.
        let rc = unsafe {
            ffi::shekyl_submit_relay_tx(self.core.raw_handle(), txid.as_bytes().as_ptr())
        };
        if rc != ffi::SHEKYL_SUBMIT_OK {
            // Fire and forget by design (§4.3): the nudge is latency; the
            // Dandelion++ embargo + periodic relay loop are the guarantee.
            tracing::debug!(rc, %txid, "post-commit relay nudge missed (periodic loop owns it)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod_with(ref_found: u8) -> ffi::SubmitFactsFfi {
        ffi::SubmitFactsFfi {
            in_pool: 1,
            in_chain: 0,
            ref_block_found: ref_found,
            tree_depth: 9,
            in_pool_broadcast: 0,
            reserved: [0; 3],
            ref_height: 150,
            root: [0xAA; 32],
            fee_per_byte: 7,
            fee_quantization_mask: 10,
            weight_limit: 149_400,
            chain_height: 200,
            in_chain_height: 0,
        }
    }

    // §4.5 "every conflict-descriptor arm": the POD→facts conversion the
    // production shim runs on both the snapshot and the Raced legs.
    #[test]
    fn descriptor_arms_convert_and_unknown_bytes_fault() {
        let facts = facts_from_ffi(
            &pod_with(1),
            &[
                ffi::SHEKYL_SUBMIT_KI_FREE,
                ffi::SHEKYL_SUBMIT_KI_OWN_TX,
                ffi::SHEKYL_SUBMIT_KI_OTHER,
            ],
        )
        .expect("documented arms convert");
        assert_eq!(
            facts.key_image_conflicts,
            vec![
                KeyImageConflict::Free,
                KeyImageConflict::OwnTx,
                KeyImageConflict::Other
            ]
        );
        assert!(facts.in_pool);
        assert_eq!(facts.in_chain, None);
        assert!(!facts.in_pool_broadcast, "pod broadcast byte 0 → false");

        // in_chain = 1 gates the F40 height into the Some arm.
        let mut chain_pod = pod_with(1);
        chain_pod.in_chain = 1;
        chain_pod.in_chain_height = 180;
        let chain_facts = facts_from_ffi(&chain_pod, &[]).expect("converts");
        assert_eq!(chain_facts.in_chain, Some(BlockHeight::from_raw(180)));

        // in_pool_broadcast converts independently of in_pool (the foreign-
        // disclosure fact).
        let mut broadcast_pod = pod_with(1);
        broadcast_pod.in_pool_broadcast = 1;
        let broadcast_facts = facts_from_ffi(&broadcast_pod, &[]).expect("converts");
        assert!(broadcast_facts.in_pool_broadcast);
        let reference = facts.reference.expect("ref_block_found = 1");
        assert_eq!(reference.height, BlockHeight::from_raw(150));
        assert_eq!(reference.root, [0xAA; 32]);
        assert_eq!(reference.tree_depth, 9);
        assert_eq!(facts.chain_height, BlockHeight::from_raw(200));

        // A byte outside the documented set is a contract violation, not a
        // guessed fact.
        assert!(facts_from_ffi(&pod_with(1), &[3]).is_err());
    }

    #[test]
    fn unknown_reference_maps_to_none() {
        let facts = facts_from_ffi(&pod_with(0), &[]).expect("converts");
        assert_eq!(facts.reference, None);
        assert!(facts.key_image_conflicts.is_empty());
    }
}
