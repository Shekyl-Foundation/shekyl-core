// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handler's sync reads, each over one snapshot of the node's chain
//! (`DRS_X_STORE_FLIP.md` DX-Q1). A sync decision never reads two tips.
//!
//! The short history and the supplement are the C++ algorithms, moved:
//! the history is the tip, then ten predecessors, then powers of two, then
//! genesis; the supplement is the first shared block and up to 10 000
//! hashes after it, including that block.

use shekyl_chain_rules::AtHeight;
use shekyl_chain_store::codec::BlockInfo;
use shekyl_chain_store::store::{AtIndex, ChainStore, Prunable, ReadSnapshot};
use shekyl_mempool::Pool;
use shekyl_types::{BlockHash, BlockHeight, TxHash};
use shekyl_wire::Transaction;

use crate::legacy_types::ShekylBuffer;
use crate::legacy_util::{
    arr32_from_ptr, bounded_capacity, slice_from_ptr, slice_from_typed_ptr_mut,
};
use crate::pool_ffi::{with_pool, with_store};

/// How many hashes a chain-entry reply carries, including the split.
const SUPPLEMENT_LIMIT: u64 = 10_000;

/// The chain has the block on its main chain.
pub const SHEKYL_CORE_MAIN: i32 = 0;
/// The chain holds the block as an alternative.
pub const SHEKYL_CORE_ALT: i32 = 1;
/// The chain does not hold the block.
pub const SHEKYL_CORE_ABSENT: i32 = 2;

fn halves(wide: u128) -> (u64, u64) {
    (
        u64::try_from(wide & u128::from(u64::MAX)).unwrap_or(0),
        u64::try_from(wide >> 64).unwrap_or(0),
    )
}
const OK: i32 = 0;
const REFUSED: i32 = 1;
const FAULT: i32 = -1;
const UNBOUND: i32 = -2;

fn count_on(snap: &ReadSnapshot<'_>) -> Result<u64, ()> {
    let tip = snap.tip().map_err(|_| ())?;
    Ok(match tip.recorded {
        None => 0,
        Some(recorded) => recorded.height.to_raw().checked_add(1).ok_or(())?,
    })
}

fn info_on(snap: &ReadSnapshot<'_>, height: u64) -> Result<Option<BlockInfo>, ()> {
    match snap
        .block_info(BlockHeight::from_raw(height))
        .map_err(|_| ())?
    {
        AtHeight::Recorded(info) => Ok(Some(info)),
        AtHeight::AboveTip => Ok(None),
    }
}

/// The short chain history. `count` is the chain's block count. `hash_at`
/// is the block at that height index.
fn short_history(
    count: u64,
    mut hash_at: impl FnMut(u64) -> Option<[u8; 32]>,
) -> Option<Vec<[u8; 32]>> {
    if count == 0 {
        return Some(Vec::new());
    }
    let mut ids = Vec::new();
    let mut saw_genesis = false;
    let mut offset = 1u64;
    let mut step = 0u64;
    let mut multiplier = 1u64;
    while offset < count {
        let height = count - offset;
        ids.push(hash_at(height)?);
        if height == 0 {
            saw_genesis = true;
        }
        if step < 10 {
            offset = offset.checked_add(1)?;
        } else {
            multiplier = multiplier.checked_mul(2)?;
            offset = offset.checked_add(multiplier)?;
        }
        step += 1;
    }
    if !saw_genesis {
        ids.push(hash_at(0)?);
    }
    Some(ids)
}

fn buffer_of(bytes: Vec<u8>) -> ShekylBuffer {
    if bytes.is_empty() {
        ShekylBuffer::null()
    } else {
        ShekylBuffer::from_vec(bytes)
    }
}

/// The chain's block count. `0` and the count written, [`UNBOUND`] with no
/// door, [`FAULT`] when the store cannot be read.
///
/// # Safety
///
/// `out_count` is writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_core_height(out_count: *mut u64) -> i32 {
    if out_count.is_null() {
        return FAULT;
    }
    let Some(count) = with_store(|store| {
        let snap = store.begin_read().map_err(|_| ())?;
        count_on(&snap)
    }) else {
        return UNBOUND;
    };
    match count {
        Ok(count) => {
            out_count.write(count);
            OK
        }
        Err(()) => FAULT,
    }
}

/// The top block: its height index and its hash. An empty chain writes
/// height 0 and a zero hash and returns [`REFUSED`].
///
/// # Safety
///
/// `out_height` is writable. `out_hash` is 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_core_top(out_height: *mut u64, out_hash: *mut u8) -> i32 {
    if out_height.is_null() || out_hash.is_null() {
        return FAULT;
    }
    let Some(read) = with_store(|store| {
        let snap = store.begin_read().map_err(|_| ())?;
        let count = count_on(&snap)?;
        if count == 0 {
            return Ok(None);
        }
        let height = count - 1;
        let info = info_on(&snap, height)?.ok_or(())?;
        Ok(Some((height, info.hash.to_bytes())))
    }) else {
        return UNBOUND;
    };
    match read {
        Ok(Some((height, hash))) => {
            out_height.write(height);
            let Some(slot) = slice_from_typed_ptr_mut(out_hash, 32) else {
                return FAULT;
            };
            slot.copy_from_slice(&hash);
            OK
        }
        Ok(None) => {
            out_height.write(0);
            let Some(slot) = slice_from_typed_ptr_mut(out_hash, 32) else {
                return FAULT;
            };
            slot.fill(0);
            REFUSED
        }
        Err(()) => FAULT,
    }
}

/// The hash at `height`. [`REFUSED`] above the tip.
///
/// # Safety
///
/// `out_hash` is 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_core_hash_at(height: u64, out_hash: *mut u8) -> i32 {
    if out_hash.is_null() {
        return FAULT;
    }
    let Some(read) = with_store(|store| {
        let snap = store.begin_read().map_err(|_| ())?;
        info_on(&snap, height)
    }) else {
        return UNBOUND;
    };
    match read {
        Ok(Some(info)) => {
            let Some(slot) = slice_from_typed_ptr_mut(out_hash, 32) else {
                return FAULT;
            };
            slot.copy_from_slice(&info.hash.to_bytes());
            OK
        }
        Ok(None) => REFUSED,
        Err(()) => FAULT,
    }
}

/// Where `hash` sits. Writes [`SHEKYL_CORE_MAIN`], [`SHEKYL_CORE_ALT`], or
/// [`SHEKYL_CORE_ABSENT`].
///
/// # Safety
///
/// `hash` is 32 readable bytes. `out_where` is writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_core_have_block(hash: *const u8, out_where: *mut i32) -> i32 {
    if hash.is_null() || out_where.is_null() {
        return FAULT;
    }
    let Some(bytes) = arr32_from_ptr(hash) else {
        return FAULT;
    };
    let id = BlockHash::from_bytes(bytes);
    let Some(read) = with_store(|store| -> Result<i32, ()> {
        let snap = store.begin_read().map_err(|_| ())?;
        if snap.height_of(&id).map_err(|_| ())?.is_some() {
            return Ok(SHEKYL_CORE_MAIN);
        }
        if snap.has_alt_block(&id).map_err(|_| ())? {
            return Ok(SHEKYL_CORE_ALT);
        }
        Ok(SHEKYL_CORE_ABSENT)
    }) else {
        return UNBOUND;
    };
    match read {
        Ok(where_) => {
            out_where.write(where_);
            OK
        }
        Err(()) => FAULT,
    }
}

/// The cumulative difficulty at `height`, low 64 bits then high.
///
/// # Safety
///
/// `out_lo` and `out_hi` are writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_core_cumulative_difficulty(
    height: u64,
    out_lo: *mut u64,
    out_hi: *mut u64,
) -> i32 {
    if out_lo.is_null() || out_hi.is_null() {
        return FAULT;
    }
    let Some(read) = with_store(|store| {
        let snap = store.begin_read().map_err(|_| ())?;
        info_on(&snap, height)
    }) else {
        return UNBOUND;
    };
    match read {
        Ok(Some(info)) => {
            let (lo, hi) = halves(info.cumulative_difficulty.to_raw());
            out_lo.write(lo);
            out_hi.write(hi);
            OK
        }
        Ok(None) => REFUSED,
        Err(()) => FAULT,
    }
}

/// The short chain history, tip first, as `32 * n` bytes, and the chain's
/// block count.
///
/// # Safety
///
/// `hashes` and `out_count` are writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_core_short_history(
    hashes: *mut ShekylBuffer,
    out_count: *mut u64,
) -> i32 {
    if hashes.is_null() || out_count.is_null() {
        return FAULT;
    }
    let Some(read) = with_store(|store| -> Result<(u64, Vec<[u8; 32]>), ()> {
        let snap = store.begin_read().map_err(|_| ())?;
        let count = count_on(&snap)?;
        let ids = short_history(count, |height| {
            info_on(&snap, height)
                .ok()
                .flatten()
                .map(|info| info.hash.to_bytes())
        })
        .ok_or(())?;
        Ok((count, ids))
    }) else {
        return UNBOUND;
    };
    match read {
        Ok((count, ids)) => {
            let bytes = ids.into_iter().flatten().collect();
            hashes.write(buffer_of(bytes));
            out_count.write(count);
            OK
        }
        Err(()) => FAULT,
    }
}

/// The blocks this chain has after the first hash in `ids` it also holds.
/// `ids` is the peer's history, newest first, genesis last. Writes the
/// hashes and weights from the split, inclusive, up to 10 000.
///
/// # Safety
///
/// `ids` is readable for `id_count * 32` bytes when the count is nonzero.
/// The out pointers are writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_core_supplement(
    ids: *const u8,
    id_count: usize,
    hashes: *mut ShekylBuffer,
    weights: *mut ShekylBuffer,
    out_start: *mut u64,
    out_total: *mut u64,
    out_diff_lo: *mut u64,
    out_diff_hi: *mut u64,
) -> i32 {
    if hashes.is_null()
        || weights.is_null()
        || out_start.is_null()
        || out_total.is_null()
        || out_diff_lo.is_null()
        || out_diff_hi.is_null()
        || (ids.is_null() && id_count != 0)
    {
        return FAULT;
    }
    let Some(nbytes) = id_count.checked_mul(32) else {
        return FAULT;
    };
    let Some(raw) = slice_from_ptr(ids, nbytes) else {
        return FAULT;
    };
    let Some(read) = with_store(|store| supplement(store, raw)) else {
        return UNBOUND;
    };
    match read {
        Ok(Some(answer)) => {
            hashes.write(buffer_of(answer.hashes));
            weights.write(buffer_of(answer.weights));
            out_start.write(answer.start);
            out_total.write(answer.total);
            out_diff_lo.write(answer.diff_lo);
            out_diff_hi.write(answer.diff_hi);
            OK
        }
        Ok(None) => REFUSED,
        Err(()) => FAULT,
    }
}

struct Supplement {
    hashes: Vec<u8>,
    weights: Vec<u8>,
    start: u64,
    total: u64,
    diff_lo: u64,
    diff_hi: u64,
}

fn supplement(store: &ChainStore, ids: &[u8]) -> Result<Option<Supplement>, ()> {
    if ids.is_empty() || !ids.len().is_multiple_of(32) {
        return Ok(None);
    }
    let snap = store.begin_read().map_err(|_| ())?;
    let count = count_on(&snap)?;
    if count == 0 {
        return Ok(None);
    }
    let genesis = info_on(&snap, 0)?.ok_or(())?;
    let last = &ids[ids.len() - 32..];
    if last != genesis.hash.to_bytes() {
        return Ok(None);
    }
    let mut split = None;
    for chunk in ids.chunks(32) {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(chunk);
        if let Some(height) = snap
            .height_of(&BlockHash::from_bytes(bytes))
            .map_err(|_| ())?
        {
            split = Some(height.to_raw());
            break;
        }
    }
    let Some(start) = split else {
        return Ok(None);
    };
    let span = count.saturating_sub(start).min(SUPPLEMENT_LIMIT);
    let Ok(budget) = usize::try_from(SUPPLEMENT_LIMIT) else {
        return Err(());
    };
    let Some(mut hashes) = bounded_capacity(
        (span as usize).saturating_mul(32),
        1,
        budget.saturating_mul(32),
    ) else {
        return Err(());
    };
    let Some(mut weights) = bounded_capacity(
        (span as usize).saturating_mul(8),
        1,
        budget.saturating_mul(8),
    ) else {
        return Err(());
    };
    for height in start..start + span {
        let info = info_on(&snap, height)?.ok_or(())?;
        hashes.extend_from_slice(&info.hash.to_bytes());
        weights.extend_from_slice(&info.weight.to_raw().to_le_bytes());
    }
    let tip = info_on(&snap, count - 1)?.ok_or(())?;
    let (diff_lo, diff_hi) = halves(tip.cumulative_difficulty.to_raw());
    Ok(Some(Supplement {
        hashes,
        weights,
        start,
        total: count,
        diff_lo,
        diff_hi,
    }))
}

/// Wire bytes, attestation witness (empty when the block stored none),
/// whether it is an alternative, and its weight.
type BlockBody = (Vec<u8>, Vec<u8>, bool, u64);

/// A block the chain holds.
fn block_bytes(snap: &ReadSnapshot<'_>, id: &BlockHash) -> Result<Option<BlockBody>, ()> {
    if let Some(height) = snap.height_of(id).map_err(|_| ())? {
        let blob = match snap.block_blob(height).map_err(|_| ())? {
            AtHeight::Recorded(raw) => raw.into_wire_bytes(),
            AtHeight::AboveTip => return Err(()),
        };
        let witness = match snap.attestation_witness_at(height).map_err(|_| ())? {
            AtHeight::Recorded(Some(bytes)) => bytes,
            AtHeight::Recorded(None) | AtHeight::AboveTip => Vec::new(),
        };
        let weight = match snap.block_info(height).map_err(|_| ())? {
            AtHeight::Recorded(info) => info.weight.to_raw(),
            AtHeight::AboveTip => return Err(()),
        };
        return Ok(Some((blob, witness, false, weight)));
    }
    if let Some(alt) = snap.alt_block(id).map_err(|_| ())? {
        let witness = alt.attestation_witness().unwrap_or(&[]).to_vec();
        let weight = alt.block_weight().to_raw();
        return Ok(Some((alt.block().serialize(), witness, true, weight)));
    }
    Ok(None)
}

/// The chain's wire bytes for `id`, when this node still holds the prunable
/// region. `None` is not on the chain, or the region was discarded.
fn chain_tx(snap: &ReadSnapshot<'_>, id: &TxHash) -> Result<Option<Vec<u8>>, ()> {
    let Some(record) = snap.tx_record(id).map_err(|_| ())? else {
        return Ok(None);
    };
    let AtIndex::Recorded(prunable) = snap.tx_prunable(record.location.id).map_err(|_| ())? else {
        return Ok(None);
    };
    let Prunable::Retained(segment) = prunable else {
        return Ok(None);
    };
    Ok(record.wire_bytes(segment))
}

fn pool_tx(pool: &Pool, id: &TxHash) -> Option<Vec<u8>> {
    // Shown only. Resolving a stem body would tell the asker this node
    // holds it (PR2-Q4, `Pool::shown_body`).
    pool.shown_body(id).map(Transaction::serialize)
}

/// `hash`'s block. [`OK`] when the chain holds it: `blob` is the wire
/// bytes, `witness` is empty when the block carries none, `out_alt` is
/// nonzero for an alternative, and `out_weight` is the block's weight.
/// [`SHEKYL_CORE_ABSENT`] when it does not. The witness is the block's own,
/// so an alternative's witness is not read off the main chain's height.
///
/// # Safety
///
/// `hash` is 32 readable bytes. The buffers and the two outs are writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_core_block(
    hash: *const u8,
    blob: *mut ShekylBuffer,
    witness: *mut ShekylBuffer,
    out_alt: *mut i32,
    out_weight: *mut u64,
) -> i32 {
    if hash.is_null()
        || blob.is_null()
        || witness.is_null()
        || out_alt.is_null()
        || out_weight.is_null()
    {
        return FAULT;
    }
    let Some(bytes) = arr32_from_ptr(hash) else {
        return FAULT;
    };
    let id = BlockHash::from_bytes(bytes);
    let Some(read) = with_store(|store| -> Result<Option<BlockBody>, ()> {
        let snap = store.begin_read().map_err(|_| ())?;
        block_bytes(&snap, &id)
    }) else {
        return UNBOUND;
    };
    match read {
        Ok(Some((block, witness_bytes, alt, weight))) => {
            blob.write(buffer_of(block));
            witness.write(buffer_of(witness_bytes));
            out_alt.write(i32::from(alt));
            out_weight.write(weight);
            OK
        }
        Ok(None) => SHEKYL_CORE_ABSENT,
        Err(()) => FAULT,
    }
}

/// The transactions `hashes` names, in order. Each record is a `u8` (`0`
/// missing, `1` held) and, when held, a little-endian `u32` length and the
/// wire bytes. A chain record whose prunable region was discarded is missing
/// unless the pool still shows the transaction. A stem entry stays missing.
///
/// # Safety
///
/// `hashes` is readable for `count * 32` bytes when `count` is nonzero.
/// `out` is writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_core_txs(
    hashes: *const u8,
    count: usize,
    out: *mut ShekylBuffer,
) -> i32 {
    if out.is_null() || (hashes.is_null() && count != 0) {
        return FAULT;
    }
    let Some(nbytes) = count.checked_mul(32) else {
        return FAULT;
    };
    let Some(raw) = slice_from_ptr(hashes, nbytes) else {
        return FAULT;
    };
    let Some(read) = with_store(|store| -> Result<Vec<Option<Vec<u8>>>, ()> {
        let snap = store.begin_read().map_err(|_| ())?;
        let Some(mut found) = bounded_capacity(count, 32, raw.len()) else {
            return Err(());
        };
        for chunk in raw.chunks(32) {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(chunk);
            found.push(chain_tx(&snap, &TxHash::from_bytes(bytes))?);
        }
        Ok(found)
    }) else {
        return UNBOUND;
    };
    let mut found = match read {
        Ok(found) => found,
        Err(()) => return FAULT,
    };
    let missing: Vec<TxHash> = found
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.is_none())
        .map(|(index, _)| {
            let mut bytes = [0u8; 32];
            let start = index * 32;
            bytes.copy_from_slice(&raw[start..start + 32]);
            TxHash::from_bytes(bytes)
        })
        .collect();
    if !missing.is_empty() {
        let Some(pooled) = with_pool(|pool| {
            missing
                .iter()
                .map(|id| pool_tx(pool, id))
                .collect::<Vec<_>>()
        }) else {
            return UNBOUND;
        };
        let mut from_pool = pooled.into_iter();
        for slot in &mut found {
            if slot.is_none() {
                *slot = from_pool.next().flatten();
            }
        }
    }
    let mut packed = Vec::new();
    for slot in found {
        match slot {
            None => packed.push(0),
            Some(bytes) => {
                let Ok(len) = u32::try_from(bytes.len()) else {
                    return FAULT;
                };
                packed.push(1);
                packed.extend_from_slice(&len.to_le_bytes());
                packed.extend_from_slice(&bytes);
            }
        }
    }
    out.write(buffer_of(packed));
    OK
}

#[cfg(test)]
mod tests {
    use super::short_history;

    #[test]
    fn the_short_history_is_the_tip_then_steps_then_genesis() {
        let hashes: Vec<[u8; 32]> = (0..20).map(|n| [n; 32]).collect();
        let ids = short_history(20, |height| {
            usize::try_from(height)
                .ok()
                .and_then(|index| hashes.get(index).copied())
        })
        .expect("fits");
        assert_eq!(ids[0], [19; 32]);
        assert_eq!(*ids.last().expect("genesis"), [0; 32]);
        assert!(ids.windows(2).all(|pair| pair[0][0] > pair[1][0]));
    }

    #[test]
    fn an_empty_chain_has_no_history() {
        let ids = short_history(0, |_| None).expect("empty");
        assert!(ids.is_empty());
    }
}
