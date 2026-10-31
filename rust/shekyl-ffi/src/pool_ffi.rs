// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The protocol handler's door into the node's one pool
//! (`DRS_X_STORE_FLIP.md` DX-Q5).
//!
//! Step 1 of the door runs before the pool lock (`Pool::admit_judged`).
//! A peer is told about shown entries only (PR2-Q4, DX-F6). Membership,
//! which the relay asks, includes an entry still in stem.
//!
//! The composition root installs the door with [`install`] and the same
//! departure hook the tip follower and `flush_txpool` call. Each departure
//! releases the relay's responsibility for that transaction.
//!
//! # Deleter (the join rule, `DRS_X_STORE_FLIP.md` FLIP-Q5)
//!
//! Every export here answers the C++ protocol handler's transaction routes
//! and `levin_notify`, and RD deletes those callers and these exports with
//! them: `shekyl_pool_admit`, `shekyl_pool_has`, `shekyl_pool_hashes`,
//! `shekyl_pool_complement`, `shekyl_pool_fluffed`.
//! The one Rust-to-C++ entry beside them, `shekyl_shell_relay_local` (the
//! shell hands a committed transaction to `levin_notify`), is RD's too.

use std::sync::{Arc, Mutex, MutexGuard};

use shekyl_chain_ingest::ChainRules;
use shekyl_chain_rules::{AdmissionPolicy, HeaderView, Tip};
use shekyl_chain_store::store::{ChainStore, ReadSnapshot, SnapshotView, StoreError};
use shekyl_mempool::{stateless, Admission, Duplicate, Judged, Pool, PoolFault};
use shekyl_types::{TxHash, UnixSeconds};
use shekyl_wire::Transaction;

use crate::legacy_types::ShekylBuffer;
use crate::legacy_util::{arr32_from_ptr, slice_from_ptr};

/// The door admitted it. The handler relays this blob.
pub const SHEKYL_POOL_ADMITTED: i32 = 0;
/// Already in the pool or on the chain. The session stays; nothing is relayed.
pub const SHEKYL_POOL_HELD: i32 = 1;
/// The bytes are not a transaction this chain can admit. The session closes.
pub const SHEKYL_POOL_REFUSED_FORM: i32 = 2;
/// Refused by policy or by this chain's state. The session stays.
pub const SHEKYL_POOL_REFUSED_STATE: i32 = 3;
/// The door could not judge. The session stays; the fault is ours.
pub const SHEKYL_POOL_FAULT: i32 = -1;
/// No door is installed.
pub const SHEKYL_POOL_UNBOUND: i32 = -2;

/// Told when transactions leave the pool: eviction, a reconcile, a flush.
pub type Departed = Arc<dyn Fn(&[TxHash]) + Send + Sync>;

/// Told when the relay marks a held entry shown (`Pool::fluffed`): the tip
/// follower rebuilds the posted job at this tip (`DRS_X_STORE_FLIP.md` Q9).
pub type Shown = Arc<dyn Fn() + Send + Sync>;

struct Installed {
    store: Arc<ChainStore>,
    pool: Arc<Mutex<Pool>>,
    rules: ChainRules,
    policy: AdmissionPolicy,
    departed: Departed,
    shown: Shown,
}

static DOOR: Mutex<Option<Installed>> = Mutex::new(None);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install the node's pool. A second install replaces the first.
pub fn install(
    store: Arc<ChainStore>,
    pool: Arc<Mutex<Pool>>,
    rules: ChainRules,
    policy: AdmissionPolicy,
    departed: Departed,
    shown: Shown,
) {
    *lock(&DOOR) = Some(Installed {
        store,
        pool,
        rules,
        policy,
        departed,
        shown,
    });
}

/// Clear the door. Later admits read [`SHEKYL_POOL_UNBOUND`].
pub fn uninstall() {
    *lock(&DOOR) = None;
}

/// Tell the departure hook which ids left the pool: the relay zone forgets
/// their relay state (`relay_zone_ffi::note_departed`).
pub fn note_left(ids: &[TxHash]) {
    let Some(hook) = lock(&DOOR).as_ref().map(|door| Arc::clone(&door.departed)) else {
        return;
    };
    if !ids.is_empty() {
        hook(ids);
    }
}

/// The relay's fluff event: the pool shows `id` and the tip follower
/// rebuilds the posted job (`DRS_X_STORE_FLIP.md` Q9).
///
/// [`SHEKYL_POOL_UNBOUND`] with no door, [`SHEKYL_POOL_FAULT`] on a
/// pool-file fault, `0` otherwise. Idempotent: already-shown is `0`.
pub fn note_shown(id: TxHash) -> i32 {
    let shown = lock(&DOOR).as_ref().map(|door| Arc::clone(&door.shown));
    let Some(result) = with_pool_mut(|pool| pool.fluffed(&id)) else {
        return SHEKYL_POOL_UNBOUND;
    };
    match result {
        Ok(true) => {
            if let Some(shown) = shown {
                shown();
            }
            0
        }
        Ok(false) => 0,
        Err(_) => SHEKYL_POOL_FAULT,
    }
}

fn now() -> UnixSeconds {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    UnixSeconds::from_raw(secs)
}

/// The installed chain, for the sync reads (`chain_sync_ffi`).
pub(crate) fn with_store<R>(f: impl FnOnce(&ChainStore) -> R) -> Option<R> {
    let door = door()?;
    Some(f(&door.store))
}

/// One snapshot and the pool, the snapshot taken first.
///
/// The ingest writer does not take the pool lock inside the store
/// write, so this is the same order as the window's pool read and
/// [`admit_one`]: the transaction answer is one chain and one pool,
/// not two reads a block apart.
pub(crate) fn with_snapshot_and_pool<R>(
    f: impl FnOnce(&ReadSnapshot<'_>, &Pool) -> Result<R, StoreError>,
) -> Option<Result<R, StoreError>> {
    let door = door()?;
    let snap = match door.store.begin_read() {
        Ok(snap) => snap,
        Err(error) => return Some(Err(error)),
    };
    let pool = lock(&door.pool);
    Some(f(&snap, &pool))
}

pub(crate) fn with_pool_mut<R>(f: impl FnOnce(&mut Pool) -> R) -> Option<R> {
    let door = door()?;
    let mut pool = lock(&door.pool);
    Some(f(&mut pool))
}

fn door() -> Option<Installed> {
    // Arcs and Copy fields: the lock does not span the admission.
    let guard = lock(&DOOR);
    guard.as_ref().map(|door| Installed {
        store: Arc::clone(&door.store),
        pool: Arc::clone(&door.pool),
        rules: door.rules,
        policy: door.policy,
        departed: Arc::clone(&door.departed),
        shown: Arc::clone(&door.shown),
    })
}

fn parse(blob: &[u8]) -> Option<Transaction> {
    let tx = Transaction::from_bytes(blob).ok()?;
    if tx.serialize() != blob || tx.validate().is_err() || tx.is_coinbase() {
        return None;
    }
    if tx.prefix.unlock_time != 0 {
        return None;
    }
    Some(tx)
}

fn admit_one(door: &Installed, tx: Transaction) -> i32 {
    let snap = match door.store.begin_read() {
        Ok(snap) => snap,
        Err(_) => return SHEKYL_POOL_FAULT,
    };
    let view = SnapshotView::new(&snap);
    let tip = match HeaderView::tip(&view) {
        Ok(tip) => tip,
        Err(_) => return SHEKYL_POOL_FAULT,
    };
    let height = Tip::connecting_height(tip.as_ref());
    let rule_set = door.rules.in_force(height);
    let prior = match stateless(&tx, &view, &rule_set, None) {
        Ok(Ok(pass)) => Some(pass),
        Ok(Err(_)) => return SHEKYL_POOL_REFUSED_FORM,
        Err(_) => return SHEKYL_POOL_FAULT,
    };
    let outcome = {
        let mut pool = lock(&door.pool);
        pool.admit_judged(tx, prior, now(), &view, &rule_set, &door.policy)
    };
    match outcome {
        Ok(Admission::Admitted { evicted }) => {
            note_left(&evicted);
            SHEKYL_POOL_ADMITTED
        }
        Ok(Admission::Duplicate(Duplicate::InPool | Duplicate::OnChain)) => SHEKYL_POOL_HELD,
        Ok(Admission::Refused(Judged::Stateless(_))) => SHEKYL_POOL_REFUSED_FORM,
        Ok(Admission::Refused(_) | Admission::PoolFull) => SHEKYL_POOL_REFUSED_STATE,
        Err(PoolFault::Chain(_) | PoolFault::TipMoved { .. } | PoolFault::Store(_)) => {
            SHEKYL_POOL_FAULT
        }
    }
}

/// Admit one peer blob. See the `SHEKYL_POOL_*` results.
///
/// # Safety
///
/// `blob` is readable for `len` bytes when `len` is nonzero. A null `blob`
/// with `len == 0` is an empty blob and is refused as form.
#[no_mangle]
pub unsafe extern "C" fn shekyl_pool_admit(blob: *const u8, len: usize) -> i32 {
    let Some(door) = door() else {
        return SHEKYL_POOL_UNBOUND;
    };
    if blob.is_null() && len != 0 {
        return SHEKYL_POOL_FAULT;
    }
    let Some(bytes) = slice_from_ptr(blob, len) else {
        return SHEKYL_POOL_FAULT;
    };
    let Some(tx) = parse(bytes) else {
        return SHEKYL_POOL_REFUSED_FORM;
    };
    admit_one(&door, tx)
}

/// `1` when the pool holds `hash`, stem included. `0` when it does not.
/// [`SHEKYL_POOL_UNBOUND`] or [`SHEKYL_POOL_FAULT`] otherwise.
///
/// # Safety
///
/// `hash` points at 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_pool_has(hash: *const u8) -> i32 {
    let Some(door) = door() else {
        return SHEKYL_POOL_UNBOUND;
    };
    if hash.is_null() {
        return SHEKYL_POOL_FAULT;
    }
    let Some(bytes) = arr32_from_ptr(hash) else {
        return SHEKYL_POOL_FAULT;
    };
    let id = TxHash::from_bytes(bytes);
    let pool = lock(&door.pool);
    i32::from(pool.relay_view().record(&id).is_some())
}

fn hash_bytes(sensitive: bool, pool: &Pool) -> Vec<u8> {
    let view = pool.relay_view();
    if sensitive {
        view.entries()
            .flat_map(|entry| entry.id.to_bytes())
            .collect()
    } else {
        pool.peer_sync().flat_map(|(id, _)| id.to_bytes()).collect()
    }
}

/// Shown hashes, or every held hash when `sensitive` is nonzero. `out` is
/// `32 * n` bytes, freed with `shekyl_buffer_free`. `0` on success.
///
/// # Safety
///
/// `out` is a writable [`ShekylBuffer`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_pool_hashes(sensitive: u8, out: *mut ShekylBuffer) -> i32 {
    let Some(door) = door() else {
        return SHEKYL_POOL_UNBOUND;
    };
    if out.is_null() {
        return SHEKYL_POOL_FAULT;
    }
    let pool = lock(&door.pool);
    let bytes = hash_bytes(sensitive != 0, &pool);
    drop(pool);
    let buffer = if bytes.is_empty() {
        ShekylBuffer::null()
    } else {
        ShekylBuffer::from_vec(bytes)
    };
    out.write(buffer);
    0
}

/// Shown bodies whose hash is not in `known` (`known_count` hashes of 32
/// bytes). `out` is a sequence of little-endian `u32` lengths and the
/// bytes, freed with `shekyl_buffer_free`.
///
/// # Safety
///
/// `known` is readable for `known_count * 32` bytes when the count is
/// nonzero. `out` is a writable [`ShekylBuffer`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_pool_complement(
    known: *const u8,
    known_count: usize,
    out: *mut ShekylBuffer,
) -> i32 {
    let Some(door) = door() else {
        return SHEKYL_POOL_UNBOUND;
    };
    if out.is_null() || (known.is_null() && known_count != 0) {
        return SHEKYL_POOL_FAULT;
    }
    let known_bytes = if known_count == 0 {
        &[]
    } else {
        let Some(nbytes) = known_count.checked_mul(32) else {
            return SHEKYL_POOL_FAULT;
        };
        let Some(bytes) = slice_from_ptr(known, nbytes) else {
            return SHEKYL_POOL_FAULT;
        };
        bytes
    };
    let pool = lock(&door.pool);
    let mut packed = Vec::new();
    for (id, tx) in pool.peer_sync() {
        let hash = id.to_bytes();
        let held = known_bytes.chunks(32).any(|chunk| chunk == hash);
        if held {
            continue;
        }
        let blob = tx.serialize();
        let Ok(len) = u32::try_from(blob.len()) else {
            return SHEKYL_POOL_FAULT;
        };
        packed.extend_from_slice(&len.to_le_bytes());
        packed.extend_from_slice(&blob);
    }
    drop(pool);
    let buffer = if packed.is_empty() {
        ShekylBuffer::null()
    } else {
        ShekylBuffer::from_vec(packed)
    };
    out.write(buffer);
    0
}

/// The relay fluffed `hash`: the pool shows it. `0` done, [`SHEKYL_POOL_FAULT`]
/// on a pool-file fault, [`SHEKYL_POOL_UNBOUND`] with no door.
///
/// # Safety
///
/// `hash` is 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_pool_fluffed(hash: *const u8) -> i32 {
    if hash.is_null() {
        return SHEKYL_POOL_FAULT;
    }
    let Some(bytes) = arr32_from_ptr(hash) else {
        return SHEKYL_POOL_FAULT;
    };
    let id = TxHash::from_bytes(bytes);
    note_shown(id)
}

#[cfg(test)]
mod tests {
    use shekyl_types::TxHash;

    use super::{note_shown, shekyl_pool_admit, SHEKYL_POOL_UNBOUND};

    #[test]
    fn an_admit_with_no_door_is_unbound() {
        super::uninstall();
        assert_eq!(
            unsafe { shekyl_pool_admit(std::ptr::null(), 0) },
            SHEKYL_POOL_UNBOUND
        );
    }

    #[test]
    fn a_shown_note_with_no_door_is_unbound() {
        super::uninstall();
        assert_eq!(note_shown(TxHash::from_bytes([0; 32])), SHEKYL_POOL_UNBOUND);
    }
}
