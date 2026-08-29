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

use shekyl_types::{BlockHash, BlockHeight, ChainCount, TxHash};

use crate::core::CoreRpc;
use crate::ffi;
use crate::submit::certificate::VerificationCertificate;
use crate::submit::facts::{
    BondProbe, CommitOutcome, EmissionBondFacts, EmissionCloseBondFacts, EmissionCreditPairFacts,
    EmissionEpochSnapshotFacts, EmissionFacts, EmissionShardFacts, KeyImageConflict,
    ReferenceFacts, ShimFault, SubmitFacts, SubmitStateShim, TxMeta, UnbondFacts,
    UnbondRecordFacts,
};
use shekyl_archival_retention::{
    BadInterval, HoldingsDescriptor, HoldingsKind, LastServedScan, ShardSet,
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
        chain_height: ChainCount::from_raw(pod.chain_height),
        // bond_record_exists is valid iff the BP3 probe ran (§8.7.1) —
        // same validity-gate shape as in_chain_height.
        bond_record_exists: (pod.bond_record_probed != 0).then_some(pod.bond_record_exists != 0),
        // Filled by the caller from the §8.7.1.1 handle (variable-size, so
        // it travels beside the POD) — the same shape as `emission`.
        unbond: None,
        // The E6/E7 fact bundle is converted separately by the snapshot
        // path (it rides a C++-owned handle, not the POD); the fresh-facts
        // path carries only the E6 re-check bit.
        emission: None,
        emission_claim_conflict: (pod.emission_probed != 0)
            .then_some(pod.emission_claim_conflict != 0),
    })
}

/// Convert the §8.7.1.1 Unbond fact view into owned facts.
///
/// # Safety
///
/// `view` and every pointer reachable from it must be valid for the whole
/// call (the C++ handle's contract: buffers live until
/// `shekyl_submit_unbond_facts_free`). `Err(())` on a marshal-shape
/// violation — an unknown holdings kind, an unknown scan discriminant, or a
/// scan that does not match the record's holdings kind. Every one of those
/// is a contract fault, never a guessed fact: the scan mismatch in
/// particular fails **permissively** if believed (an empty slice folds to
/// "never served", which lets the release cooldown elapse for a record that
/// has been serving), so it is refused here rather than folded.
unsafe fn unbond_facts_from_ffi(view: &ffi::SubmitUnbondFactsFfi) -> Result<UnbondFacts, ()> {
    let record = if view.record_present != 0 {
        let r = &view.record;
        let holdings_kind = HoldingsKind::from_u8(r.holdings_kind).map_err(|_| ())?;
        let gathered_scan = match r.last_served_scan {
            0 => LastServedScan::HeldShards,
            1 => LastServedScan::AllShards,
            _ => return Err(()),
        };
        let bond_spend_pk = if r.bond_spend_pk_len == 0 {
            Vec::new()
        } else if r.bond_spend_pk.is_null() {
            return Err(());
        } else {
            unsafe { std::slice::from_raw_parts(r.bond_spend_pk, r.bond_spend_pk_len) }.to_vec()
        };
        let per_shard_last_served = if r.per_shard_last_served_len == 0 {
            Vec::new()
        } else if r.per_shard_last_served.is_null() {
            return Err(());
        } else {
            unsafe {
                std::slice::from_raw_parts(r.per_shard_last_served, r.per_shard_last_served_len)
            }
            .to_vec()
        };
        // The row-UB4 pin lives in the constructor: a record whose gather
        // ran the wrong accessor is unconstructable, so nothing downstream
        // can fold a permissively-empty slice.
        Some(
            UnbondRecordFacts::new(
                r.bonded_total_atomic,
                r.bad_interval_count,
                bond_spend_pk,
                holdings_kind,
                gathered_scan,
                per_shard_last_served,
            )
            .map_err(|_| ())?,
        )
    } else {
        None
    };
    Ok(UnbondFacts {
        record,
        // The one place the C++ storage sentinel is normalised (§8.7.1.1
        // row UB6): `u64::MAX` is `get_archival_last_slash_epoch`'s initial
        // value, never a settled epoch.
        last_settled_slash_epoch: (view.last_settled_slash_epoch != u64::MAX)
            .then_some(view.last_settled_slash_epoch),
    })
}

/// Copy the C++-owned §8.7.2 E6/E7 fact bundle into owned facts.
///
/// # Safety
///
/// `view` and every pointer reachable from it must be valid for the whole
/// call (the C++ handle's contract: buffers live until
/// `shekyl_submit_emission_facts_free`). `Err(())` on a marshal-shape
/// violation (an invalid holdings kind or shard set) — a contract fault,
/// never a guessed fact.
unsafe fn emission_facts_from_ffi(view: &ffi::SubmitEmissionFactsFfi) -> Result<EmissionFacts, ()> {
    // Null-iff-empty, enforced fail-closed: a non-zero length behind a NULL
    // pointer is a malformed handle (a C++ marshal defect), rejected as a
    // contract fault rather than dereferenced (the same guard shape as the
    // FFI crate's flat_commitment_keys).
    unsafe fn slice<'a, T>(ptr: *const T, len: usize) -> Result<&'a [T], ()> {
        if len == 0 {
            Ok(&[])
        } else if ptr.is_null() {
            Err(())
        } else {
            Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
        }
    }
    let bond = if view.bond_present == 0 {
        None
    } else {
        let kind = HoldingsKind::from_u8(view.bond.holdings_kind).map_err(|_| ())?;
        let shard_ids =
            ShardSet::new(unsafe { slice(view.bond.shard_ids, view.bond.shard_ids_len) }?.to_vec())
                .map_err(|_| ())?;
        Some(EmissionBondFacts {
            join_settlement_epoch: view.bond.join_settlement_epoch,
            holdings: HoldingsDescriptor { kind, shard_ids },
            claimed_settlement_epochs: unsafe {
                slice(view.bond.claimed_epochs, view.bond.claimed_epochs_len)
            }?
            .to_vec(),
        })
    };
    let raw_snaps = unsafe { slice(view.snapshots, view.snapshots_len) }?;
    let mut snapshots = Vec::with_capacity(raw_snaps.len());
    for snap in raw_snaps {
        let mut bonds = Vec::with_capacity(snap.bonds_len);
        for b in unsafe { slice(snap.bonds, snap.bonds_len) }? {
            bonds.push(EmissionCloseBondFacts {
                join_settlement_epoch: b.join_settlement_epoch,
                is_foundation_complete_tree: b.is_foundation_complete_tree != 0,
                bad_intervals: unsafe {
                    // Flattened (start, end_exclusive) pairs: 2 × len u64s;
                    // the pair count is C++-supplied, so the doubling is
                    // checked — overflow is a malformed handle, rejected
                    // fail-closed like the null case.
                    slice(
                        b.bad_intervals_ptr,
                        b.bad_intervals_len.checked_mul(2).ok_or(())?,
                    )
                }?
                .chunks_exact(2)
                .map(|pair| BadInterval {
                    start_epoch: pair[0],
                    end_exclusive: pair[1],
                })
                .collect(),
            });
        }
        let shards = unsafe { slice(snap.shards, snap.shards_len) }?
            .iter()
            .map(|sh| EmissionShardFacts {
                shard_id: sh.shard_id,
                has_segment: sh.has_segment != 0,
                freeze_height: sh.freeze_height,
            })
            .collect();
        let credit_pairs = unsafe { slice(snap.credit_pairs, snap.credit_pairs_len) }?
            .iter()
            .map(|cp| EmissionCreditPairFacts {
                bond_idx: cp.bond_idx,
                shard_idx: cp.shard_idx,
            })
            .collect();
        snapshots.push(EmissionEpochSnapshotFacts {
            has_budget_row: snap.has_budget_row != 0,
            settlement_epoch: snap.settlement_epoch,
            close_block_height: snap.close_block_height,
            sigma_work_milli: snap.sigma_work_milli,
            budget_atomic: snap.budget_atomic,
            claimant_bond_idx: (snap.claimant_bond_idx != usize::MAX)
                .then_some(snap.claimant_bond_idx),
            bonds,
            shards,
            credit_pairs,
        });
    }
    Ok(EmissionFacts { bond, snapshots })
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
        bond_probe: Option<BondProbe<'_>>,
        emission_probe: Option<(&[u8; 32], &[u64])>,
    ) -> Result<SubmitFacts, ShimFault> {
        let mut pod = ffi::SubmitFactsFfi::zeroed();
        let mut ki_conflicts = vec![0u8; key_images.len()];
        let mut emission_handle: *mut ffi::SubmitEmissionFactsHandle = std::ptr::null_mut();
        let mut unbond_handle: *mut ffi::SubmitUnbondFactsHandle = std::ptr::null_mut();
        let bond_probe_kind = match bond_probe {
            Some(BondProbe::Unbond(_)) => ffi::SHEKYL_SUBMIT_BOND_PROBE_UNBOND,
            // The C++ side ignores the byte when no id is passed.
            Some(BondProbe::Join(_)) | None => ffi::SHEKYL_SUBMIT_BOND_PROBE_JOIN,
        };

        // SAFETY: txid/reference_block are 32-byte references; key_images is
        // a flat array of n × 32 bytes (contiguous by `[[u8; 32]]` layout);
        // bond_p_canonical_id is a 32-byte reference or NULL (the C++ side
        // probes iff non-null); out pointers are sized above; the handle is
        // live for the daemon's lifetime (CoreRpc's contract). The key-image
        // in/out pointers honor the null-iff-empty contract via the ptr
        // helpers (see their docs).
        let rc = unsafe {
            ffi::shekyl_submit_snapshot_facts(
                self.core.raw_handle(),
                txid.as_bytes().as_ptr(),
                const_ptr_or_null(key_images).cast::<u8>(),
                key_images.len(),
                reference_block.as_bytes().as_ptr(),
                bond_probe.map_or(std::ptr::null(), |probe| probe.p_canonical_id().as_ptr()),
                bond_probe_kind,
                emission_probe.map_or(std::ptr::null(), |(id, _)| id.as_ptr()),
                emission_probe.map_or(std::ptr::null(), |(_, epochs)| const_ptr_or_null(epochs)),
                emission_probe.map_or(0, |(_, epochs)| epochs.len()),
                &raw mut emission_handle,
                &raw mut unbond_handle,
                &raw mut pod,
                mut_ptr_or_null(ki_conflicts.as_mut_slice()),
            )
        };

        if rc != ffi::SHEKYL_SUBMIT_OK {
            tracing::error!(rc, "submit snapshot shim returned fault");
            return Err(ShimFault);
        }
        // Copy-then-free posture: the E6/E7 bundle is converted to owned
        // facts inside this frame (the handle's buffers are valid until the
        // free below); every early return after this point must free, so
        // conversion happens first and the free is unconditional.
        let emission = if let Some((_, epochs)) = emission_probe {
            let converted = unsafe {
                ffi::shekyl_submit_emission_facts_view(emission_handle)
                    .as_ref()
                    .ok_or(())
                    .and_then(|view| emission_facts_from_ffi(view))
            };
            unsafe { ffi::shekyl_submit_emission_facts_free(emission_handle) };
            match converted {
                Ok(facts) if facts.snapshots.len() == epochs.len() => Some(facts),
                Ok(_) => {
                    tracing::error!("submit snapshot shim mis-aligned the emission snapshots");
                    return Err(ShimFault);
                }
                Err(()) => {
                    tracing::error!("submit snapshot shim returned a malformed emission bundle");
                    return Err(ShimFault);
                }
            }
        } else {
            None
        };
        // Same copy-then-free posture for the §8.7.1.1 bundle.
        let unbond = if matches!(bond_probe, Some(BondProbe::Unbond(_))) {
            let converted = unsafe {
                ffi::shekyl_submit_unbond_facts_view(unbond_handle)
                    .as_ref()
                    .ok_or(())
                    .and_then(|view| unbond_facts_from_ffi(view))
            };
            unsafe { ffi::shekyl_submit_unbond_facts_free(unbond_handle) };
            match converted {
                Ok(facts) => Some(facts),
                Err(()) => {
                    tracing::error!("submit snapshot shim returned a malformed unbond bundle");
                    return Err(ShimFault);
                }
            }
        } else {
            None
        };
        // The probe contracts: requested ⇒ answered. A silently skipped
        // probe would fault later as an engine ShimContract; catch it at
        // the boundary it broke.
        if bond_probe.is_some() && pod.bond_record_probed == 0 {
            tracing::error!("submit snapshot shim skipped the requested bond-record probe");
            return Err(ShimFault);
        }
        // Two DB reads answer "does a record exist for this id" — the POD's
        // pubkey probe and the bundle's record load — under one lock scope.
        // They cannot legitimately disagree; a disagreement is a storage
        // inconsistency, and reading past it would verify an Unbond against
        // half a record.
        if let Some(bundle) = unbond.as_ref() {
            if bundle.record.is_some() != (pod.bond_record_exists != 0) {
                tracing::error!(
                    bundle_present = bundle.record.is_some(),
                    pod_exists = pod.bond_record_exists != 0,
                    "submit snapshot shim disagreed with itself about the bond record"
                );
                return Err(ShimFault);
            }
        }
        if emission_probe.is_some() && pod.emission_probed == 0 {
            tracing::error!("submit snapshot shim skipped the requested emission probe");
            return Err(ShimFault);
        }
        let mut facts = facts_from_ffi(&pod, &ki_conflicts).map_err(|()| {
            tracing::error!("submit snapshot shim returned unknown key-image descriptor");
            ShimFault
        })?;
        facts.emission = emission;
        facts.unbond = unbond;
        Ok(facts)
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
                &raw mut fresh_pod,
                mut_ptr_or_null(fresh_ki.as_mut_slice()),
                n_key_images,
            )
        };

        match rc {
            ffi::SHEKYL_SUBMIT_OK => CommitOutcome::Committed,
            ffi::SHEKYL_SUBMIT_PRUNED_ON_INSERT => CommitOutcome::PrunedOnInsert,
            ffi::SHEKYL_SUBMIT_RACED => match facts_from_ffi(&fresh_pod, &fresh_ki) {
                Ok(fresh) => CommitOutcome::Raced(Box::new(fresh)),
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
            bond_record_probed: 0,
            bond_record_exists: 0,
            emission_probed: 0,
            emission_claim_conflict: 0,
            reserved: [0; 7],
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
        assert_eq!(facts.chain_height, ChainCount::from_raw(200));

        // A byte outside the documented set is a contract violation, not a
        // guessed fact.
        assert!(facts_from_ffi(&pod_with(1), &[3]).is_err());

        // The BP3 probe pair converts under the same validity-gate shape
        // as in_chain_height: unset probe → None (exists byte ignored),
        // probed → Some(exists).
        assert_eq!(facts.bond_record_exists, None);
        let mut probed_pod = pod_with(1);
        probed_pod.bond_record_probed = 1;
        assert_eq!(
            facts_from_ffi(&probed_pod, &[])
                .expect("converts")
                .bond_record_exists,
            Some(false)
        );
        probed_pod.bond_record_exists = 1;
        assert_eq!(
            facts_from_ffi(&probed_pod, &[])
                .expect("converts")
                .bond_record_exists,
            Some(true)
        );
    }

    #[test]
    fn unknown_reference_maps_to_none() {
        let facts = facts_from_ffi(&pod_with(0), &[]).expect("converts");
        assert_eq!(facts.reference, None);
        assert!(facts.key_image_conflicts.is_empty());
    }
}
