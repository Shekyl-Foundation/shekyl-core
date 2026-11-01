// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handler's sync reads, marshalled over one snapshot of the node's
//! chain (`DRS_X_STORE_FLIP.md` DX-Q1). A sync decision never reads two tips.
//!
//! The history, the chain entry, and the block reads are
//! [`shekyl_chain_sync_runtime::chain_entry`]. A transaction is
//! [`shekyl_mempool::resolve_shown`]: the chain record, then the pool's
//! shown body, under one snapshot held across the pool lock.
//!
//! # Deleter (the join rule, `DRS_X_STORE_FLIP.md` FLIP-Q5)
//!
//! Every export here answers the C++ protocol handler's sync half, and
//! chain sync's cutover (CS-5) deletes that caller and these exports with
//! it: `shekyl_core_height`, `shekyl_core_top`, `shekyl_core_hash_at`,
//! `shekyl_core_have_block`, `shekyl_core_cumulative_difficulty`,
//! `shekyl_core_short_history`, `shekyl_core_supplement`,
//! `shekyl_core_block`, `shekyl_core_txs`. None has a second caller.

use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_store::store::StoreError;
use shekyl_chain_sync::SyncState;
use shekyl_chain_sync_runtime::chain_entry::{self, BlockPlace, ChainSupplement, EntryFault};
use shekyl_chain_sync_runtime::router::Routed;
use shekyl_mempool::resolve_shown;
use shekyl_seam::Hub;
use shekyl_types::{BlockHash, BlockHeight, TxHash};
use tokio::sync::{mpsc, oneshot, watch};

use crate::legacy_types::ShekylBuffer;
use crate::legacy_util::{
    arr32_from_ptr, bounded_capacity, slice_from_ptr, slice_from_typed_ptr_mut,
};
use crate::pool_ffi::{with_snapshot_and_pool, with_store};

/// What the node leaves for the seam's bind (CS-5 §2): the sender its
/// chain-sync owner reads routed messages from, and the one-shot the owner
/// waits on for the hub.
struct Attach {
    router: mpsc::UnboundedSender<Routed>,
    hub: oneshot::Sender<Arc<Hub>>,
}

static ATTACH: Mutex<Option<Attach>> = Mutex::new(None);

/// Chain sync's published state, as the node holds it.
static STATE: Mutex<Option<watch::Receiver<SyncState>>> = Mutex::new(None);

/// Leave the node's chain-sync owner for the seam's bind
/// ([`crate::seam_ffi::shekyl_seam_bind`]), which attaches the Levin router
/// to `router` and sends the hub it mints down `hub`, and install the
/// node's sync state for [`shekyl_node_is_synchronized`]. A second install
/// replaces the first, whose owner then sees its hub sender dropped.
///
/// # Deleter
///
/// Slice 4, with the bind, when the hub becomes the node's: the node then
/// hands its owner the hub directly (CS-Q9's slice-4 table). The state
/// goes with [`shekyl_node_is_synchronized`]'s reader.
pub fn install(
    router: mpsc::UnboundedSender<Routed>,
    hub: oneshot::Sender<Arc<Hub>>,
    state: watch::Receiver<SyncState>,
) {
    *ATTACH.lock().unwrap_or_else(PoisonError::into_inner) = Some(Attach { router, hub });
    *STATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(state);
}

/// Clear what [`install`] left. A slot no bind took drops the owner's hub
/// sender, so an owner still waiting for its hub ends, and the state reads
/// as not synchronized.
pub fn uninstall() {
    ATTACH.lock().unwrap_or_else(PoisonError::into_inner).take();
    STATE.lock().unwrap_or_else(PoisonError::into_inner).take();
}

/// 1 when chain sync reads `Synced`, 0 otherwise (CS-5 §3): what the
/// shell's `core::is_synchronized` answers for the transaction relay.
///
/// `Following` is not synchronized for relay's purposes (CS-Q2 step 8): a
/// node following a chain it cannot verify does not fluff into it. No
/// node, and a node whose state watch has closed, read 0.
///
/// # Deleter
///
/// RD, with `levin_notify` and the shell's `i_core_events`.
#[no_mangle]
pub extern "C" fn shekyl_node_is_synchronized() -> u8 {
    let state = STATE.lock().unwrap_or_else(PoisonError::into_inner);
    let synced = state
        .as_ref()
        .is_some_and(|state| state.has_changed().is_ok() && *state.borrow() == SyncState::Synced);
    u8::from(synced)
}

/// Take what the node left, once. The production seam is bound once per
/// process (`zone_server.h`'s `bind_seam`). A later bind, such as a test's
/// rebind after a clear, finds nothing and builds a pass-through router.
pub(crate) fn take() -> Option<(mpsc::UnboundedSender<Routed>, oneshot::Sender<Arc<Hub>>)> {
    ATTACH
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .map(|attach| (attach.router, attach.hub))
}

/// The chain has the block on its main chain.
pub const SHEKYL_CORE_MAIN: i32 = 0;
/// The chain holds the block as an alternative.
pub const SHEKYL_CORE_ALT: i32 = 1;
/// The chain does not hold the block.
pub const SHEKYL_CORE_ABSENT: i32 = 2;

const OK: i32 = 0;
const REFUSED: i32 = 1;
const FAULT: i32 = -1;
const UNBOUND: i32 = -2;

fn halves(wide: u128) -> (u64, u64) {
    (
        u64::try_from(wide & u128::from(u64::MAX)).unwrap_or(0),
        u64::try_from(wide >> 64).unwrap_or(0),
    )
}

fn buffer_of(bytes: Vec<u8>) -> ShekylBuffer {
    if bytes.is_empty() {
        ShekylBuffer::null()
    } else {
        ShekylBuffer::from_vec(bytes)
    }
}

fn opened<T>(read: Option<Result<T, EntryFault>>) -> Result<T, i32> {
    match read {
        None => Err(UNBOUND),
        Some(Ok(value)) => Ok(value),
        Some(Err(_)) => Err(FAULT),
    }
}

fn opened_store<T>(read: Option<Result<T, StoreError>>) -> Result<T, i32> {
    match read {
        None => Err(UNBOUND),
        Some(Ok(value)) => Ok(value),
        Some(Err(_)) => Err(FAULT),
    }
}

/// # Safety
///
/// `out_hash` is 32 writable bytes, the export's contract.
unsafe fn write_hash(out_hash: *mut u8, hash: &[u8; 32]) -> i32 {
    let Some(slot) = slice_from_typed_ptr_mut(out_hash, 32) else {
        return FAULT;
    };
    slot.copy_from_slice(hash);
    OK
}

fn locator_hashes(raw: &[u8]) -> Vec<BlockHash> {
    raw.chunks_exact(32)
        .map(|chunk| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(chunk);
            BlockHash::from_bytes(bytes)
        })
        .collect()
}

struct PackedSupplement {
    hashes: Vec<u8>,
    weights: Vec<u8>,
    start: u64,
    total: u64,
    diff_lo: u64,
    diff_hi: u64,
}

fn pack_supplement(answer: &ChainSupplement) -> PackedSupplement {
    let hashes = answer
        .blocks
        .iter()
        .flat_map(|block| block.hash.as_bytes().iter().copied())
        .collect();
    let weights = answer
        .blocks
        .iter()
        .flat_map(|block| block.weight.to_raw().to_le_bytes())
        .collect();
    let (diff_lo, diff_hi) = halves(answer.tip_cumulative_difficulty.to_raw());
    PackedSupplement {
        hashes,
        weights,
        start: answer.start.to_raw(),
        total: answer.chain_count.to_raw(),
        diff_lo,
        diff_hi,
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
    let count = match opened(with_store(chain_entry::chain_count)) {
        Ok(count) => count,
        Err(code) => return code,
    };
    out_count.write(count.to_raw());
    OK
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
    let top = match opened(with_store(chain_entry::chain_top)) {
        Ok(top) => top,
        Err(code) => return code,
    };
    match top {
        Some((height, hash)) => {
            out_height.write(height.to_raw());
            write_hash(out_hash, hash.as_bytes())
        }
        None => {
            out_height.write(0);
            if write_hash(out_hash, &[0u8; 32]) != OK {
                return FAULT;
            }
            REFUSED
        }
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
    let hash = match opened(with_store(|store| {
        chain_entry::hash_at(store, BlockHeight::from_raw(height))
    })) {
        Ok(hash) => hash,
        Err(code) => return code,
    };
    match hash {
        Some(hash) => write_hash(out_hash, hash.as_bytes()),
        None => REFUSED,
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
    let place = match opened(with_store(|store| chain_entry::block_place(store, &id))) {
        Ok(place) => place,
        Err(code) => return code,
    };
    let where_ = match place {
        BlockPlace::Main => SHEKYL_CORE_MAIN,
        BlockPlace::Alternative => SHEKYL_CORE_ALT,
        BlockPlace::Absent => SHEKYL_CORE_ABSENT,
    };
    out_where.write(where_);
    OK
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
    let difficulty = match opened(with_store(|store| {
        chain_entry::cumulative_difficulty_at(store, BlockHeight::from_raw(height))
    })) {
        Ok(difficulty) => difficulty,
        Err(code) => return code,
    };
    let Some(difficulty) = difficulty else {
        return REFUSED;
    };
    let (lo, hi) = halves(difficulty.to_raw());
    out_lo.write(lo);
    out_hi.write(hi);
    OK
}

/// The short chain history, tip first, as `32 * n` bytes, and the chain's
/// block count. An empty chain writes the null hash and a count of 0.
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
    let history = match opened(with_store(chain_entry::short_history)) {
        Ok(history) => history,
        Err(code) => return code,
    };
    let (count, ids) = history;
    let bytes = ids.into_iter().flatten().collect();
    hashes.write(buffer_of(bytes));
    out_count.write(count.to_raw());
    OK
}

/// The blocks this chain has after the first hash in `ids` it also holds.
/// `ids` is the peer's history, newest first, genesis last. Writes the
/// hashes and weights from the split, inclusive, up to the chain-entry limit.
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
    if raw.is_empty() || !raw.len().is_multiple_of(32) {
        return REFUSED;
    }
    let locator = locator_hashes(raw);
    let answer = match opened(with_store(|store| chain_entry::supplement(store, &locator))) {
        Ok(answer) => answer,
        Err(code) => return code,
    };
    let Some(answer) = answer else {
        return REFUSED;
    };
    let packed = pack_supplement(&answer);
    hashes.write(buffer_of(packed.hashes));
    weights.write(buffer_of(packed.weights));
    out_start.write(packed.start);
    out_total.write(packed.total);
    out_diff_lo.write(packed.diff_lo);
    out_diff_hi.write(packed.diff_hi);
    OK
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
    let held = match opened(with_store(|store| chain_entry::held_block(store, &id))) {
        Ok(held) => held,
        Err(code) => return code,
    };
    let Some(held) = held else {
        return SHEKYL_CORE_ABSENT;
    };
    blob.write(buffer_of(held.wire));
    witness.write(buffer_of(held.witness));
    out_alt.write(i32::from(held.alternative));
    out_weight.write(held.weight.to_raw());
    OK
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
    let Some(found) = bounded_capacity::<Option<Vec<u8>>>(count, 32, raw.len()) else {
        return FAULT;
    };
    let found = match opened_store(with_snapshot_and_pool(|snap, pool| {
        let mut found = found;
        for chunk in raw.chunks_exact(32) {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(chunk);
            found.push(resolve_shown(snap, pool, &TxHash::from_bytes(bytes))?);
        }
        Ok(found)
    })) {
        Ok(found) => found,
        Err(code) => return code,
    };
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
mod state_tests {
    use super::*;
    use shekyl_types::ChainCount;

    /// The export answers 1 for `Synced` only: `Following` is not
    /// synchronized for relay's purposes, and neither is a node that is
    /// behind or has no view. No node installed, and a node uninstalled,
    /// read 0.
    #[test]
    fn the_node_is_synchronized_only_while_chain_sync_reads_synced() {
        let _seam = crate::seam_ffi::seam_bind_lock().lock();
        uninstall();
        assert_eq!(shekyl_node_is_synchronized(), 0, "no node");
        let (state_tx, state) = watch::channel(SyncState::NoView);
        let (router, _routed) = mpsc::unbounded_channel();
        let (hub, _hub) = oneshot::channel();
        install(router, hub, state);
        let cases = [
            (SyncState::NoView, 0),
            (
                SyncState::Behind {
                    have: shekyl_difficulty::CumulativeDifficulty::from_raw(1),
                    best: shekyl_difficulty::CumulativeDifficulty::from_raw(2),
                    target: ChainCount::from_raw(2),
                },
                0,
            ),
            (
                SyncState::Following {
                    verified_to: BlockHeight::from_raw(1),
                },
                0,
            ),
            (SyncState::Synced, 1),
        ];
        for (published, expected) in cases {
            state_tx.send_replace(published);
            assert_eq!(shekyl_node_is_synchronized(), expected, "{published:?}");
        }
        uninstall();
        assert_eq!(shekyl_node_is_synchronized(), 0, "uninstalled");
    }
}
