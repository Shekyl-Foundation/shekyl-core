// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the Dandelion++ stem map (`shekyl-relay-privacy`'s
//! [`StemMap`]) — RP-2a of `docs/design/DAEMON_RELAY_PRIVACY.md`.
//!
//! This is the opaque-handle boundary the C++ `net::dandelionpp::connection_map`
//! forwards to once its ~210 lines of logic move to Rust. The C++ class keeps
//! its ABI (so `levin_notify` and the `dandelionpp_map` gtests compile
//! unchanged) and becomes a thin handle-wrapper over `*mut StemMapHandle`; the
//! logic lives here and in `stem_map.rs`. See §16/§16.1 of the design doc.
//!
//! # Ownership and threading
//!
//! Every map call site in `levin_notify` is `\pre` inside the zone strand, so a
//! handle is single-threaded by external serialisation and carries no internal
//! lock. The handle owns a **cryptographically-secure** [`SecureRelayRng`]
//! (OS entropy), matching the C++ `crypto::random_device` the ported logic
//! used — never the deterministic `SplitMix64` the measurement suite draws from.
//!
//! # The three seam-consumption contracts (§16.1)
//!
//! - [`shekyl_dandelionpp_map_update`] returns the **exact re-arm predicate**
//!   (`StemSetChange::needs_rearm`), not "the connection set differed."
//! - `map_clone` is a **deep** copy; the C++ wrapper's copy-ctor/assign must
//!   route through it (and delete the shallow defaults) or two wrappers share
//!   one handle and the epoch swap corrupts the live map.
//! - [`shekyl_dandelionpp_map_snapshot`] returns **every** slot in index order,
//!   nils included (`None` → nil-uuid), because a consumer indexes the parallel
//!   noise channel by position.

use shekyl_relay_privacy::rng::RelayRng;
use shekyl_relay_privacy::stem_map::{ConnectionId, StemMap};
use std::slice;

/// The nil UUID (`boost::uuids::nil_uuid()`) the C++ used as an absent-slot and
/// local-origin sentinel. At the boundary it maps to Rust's `None`; it never
/// re-enters Rust as a "valid" [`ConnectionId`].
const NIL: [u8; 16] = [0u8; 16];

/// Production RNG for the map: a CSPRNG reading OS entropy each draw, matching
/// the C++ `crypto::random_device` / `crypto::rand_idx` the ported logic used.
struct SecureRelayRng;

impl RelayRng for SecureRelayRng {
    fn next_u64(&mut self) -> u64 {
        use rand::RngCore;
        rand::rngs::OsRng.next_u64()
    }
}

/// Opaque map handle. C only ever holds `*mut StemMapHandle`; the fields are
/// never read across the boundary.
pub struct StemMapHandle {
    map: StemMap,
    rng: SecureRelayRng,
}

// --- byte-layout helpers (16-byte Boost UUIDs) --------------------------------

/// Read `n` consecutive 16-byte ids into `ConnectionId`s. A null/zero input is
/// an empty set.
///
/// # Safety
/// `ids` must point to at least `n * 16` readable bytes (or be null with `n == 0`).
unsafe fn read_ids(ids: *const u8, n: usize) -> Vec<ConnectionId> {
    if n == 0 || ids.is_null() {
        return Vec::new();
    }
    let bytes = slice::from_raw_parts(ids, n * 16);
    (0..n)
        .map(|i| {
            let mut b = [0u8; 16];
            b.copy_from_slice(&bytes[i * 16..i * 16 + 16]);
            ConnectionId::from_bytes(b)
        })
        .collect()
}

/// Read one 16-byte id, mapping the nil sentinel to `None`.
///
/// # Safety
/// `p` must point to 16 readable bytes.
unsafe fn read_source(p: *const u8) -> Option<ConnectionId> {
    if p.is_null() {
        return None;
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(slice::from_raw_parts(p, 16));
    if b == NIL {
        None
    } else {
        Some(ConnectionId::from_bytes(b))
    }
}

/// Write one 16-byte id.
///
/// # Safety
/// `dst` must point to 16 writable bytes.
unsafe fn write_id(dst: *mut u8, src: &[u8; 16]) {
    std::ptr::copy_nonoverlapping(src.as_ptr(), dst, 16);
}

// --- the six exports ----------------------------------------------------------

/// Construct a map over `ids` (`n` × 16 bytes), keeping at most `stems` slots.
/// Mirrors the C++ `connection_map{out_connections, stems}` constructor.
///
/// # Safety
/// `ids` must point to `n * 16` readable bytes (or be null with `n == 0`). The
/// returned handle must be released with [`shekyl_dandelionpp_map_free`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_new(
    ids: *const u8,
    n: usize,
    stems: usize,
) -> *mut StemMapHandle {
    let conns = read_ids(ids, n);
    let mut rng = SecureRelayRng;
    let map = StemMap::new(conns, stems, &mut rng);
    Box::into_raw(Box::new(StemMapHandle { map, rng }))
}

/// Deep-copy a handle — the C++ `connection_map::clone()` / copy-constructor.
/// The copy and the original diverge; nothing is shared.
///
/// # Safety
/// `handle` must be a live pointer from [`shekyl_dandelionpp_map_new`] /
/// [`shekyl_dandelionpp_map_clone`]. The returned handle must be freed.
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_clone(
    handle: *const StemMapHandle,
) -> *mut StemMapHandle {
    let h = &*handle;
    Box::into_raw(Box::new(StemMapHandle {
        map: h.map.clone(),
        rng: SecureRelayRng,
    }))
}

/// Merge `ids` (`n` × 16 bytes) into the map. Returns `true` iff the live stem
/// set changed — the **exact** C++ `update` predicate the caller gates channel
/// re-arm on (a slot dropped/emptied, or the map grew), not "the set differed".
///
/// # Safety
/// `handle` must be live; `ids` must point to `n * 16` readable bytes (or be
/// null with `n == 0`).
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_update(
    handle: *mut StemMapHandle,
    ids: *const u8,
    n: usize,
) -> bool {
    let h = &mut *handle;
    let conns = read_ids(ids, n);
    h.map.update(conns, &mut h.rng).needs_rearm()
}

/// Resolve the stem peer for `source` (16 bytes; nil = locally originated),
/// writing it into `out` (16 bytes). Returns `true` if a stem was assigned;
/// on `false` the caller must fluff and `out` is left nil. Mutates the map
/// (source→slot pinning), as the C++ `get_stem` does.
///
/// # Safety
/// `handle` must be live; `source` and `out` must each point to 16 bytes
/// (readable / writable respectively).
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_get_stem(
    handle: *mut StemMapHandle,
    source: *const u8,
    out: *mut u8,
) -> bool {
    let h = &mut *handle;
    let src = read_source(source);
    match h.map.stem_for(src, &mut h.rng) {
        Some(id) => {
            write_id(out, id.as_bytes());
            true
        }
        None => {
            write_id(out, &NIL);
            false
        }
    }
}

/// Snapshot the stem slots in index order into `buf` (`cap` × 16 bytes), writing
/// the nil UUID for an emptied slot. Returns the slot count (which may exceed
/// the live count and [`shekyl_dandelionpp_map_live_stems`]). If `cap` is below
/// the slot count nothing is written and the needed count is returned, so a
/// caller can size with `(buf = null, cap = 0)` then fill.
///
/// Order and nils are load-bearing: `levin_notify` indexes a parallel noise
/// channel by slot position (§16.1).
///
/// # Safety
/// `handle` must be live; if `cap >= slot count`, `buf` must point to
/// `cap * 16` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_snapshot(
    handle: *const StemMapHandle,
    buf: *mut u8,
    cap: usize,
) -> usize {
    let h = &*handle;
    let slots = h.map.slots();
    let count = slots.len();
    if cap < count {
        return count;
    }
    for (i, slot) in slots.iter().enumerate() {
        let bytes = slot.map_or(NIL, |id| *id.as_bytes());
        write_id(buf.add(i * 16), &bytes);
    }
    count
}

/// Number of stem slots backed by a live peer — the C++ `connection_map::size()`
/// (non-nil count), distinct from the total slot count `map_snapshot` returns.
///
/// # Safety
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_live_stems(handle: *const StemMapHandle) -> usize {
    (*handle).map.live_stems()
}

/// Free a handle. Null is a no-op; a handle must be freed exactly once.
///
/// # Safety
/// `handle` must be a pointer from `map_new`/`map_clone` not yet freed, or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_free(handle: *mut StemMapHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = byte;
        b
    }

    /// Flatten `n` ids into the contiguous `n*16` buffer the C++ hands us.
    fn flatten(ids: &[[u8; 16]]) -> Vec<u8> {
        ids.iter().flatten().copied().collect()
    }

    unsafe fn snapshot(h: *const StemMapHandle) -> Vec<[u8; 16]> {
        let count = shekyl_dandelionpp_map_snapshot(h, std::ptr::null_mut(), 0);
        let mut buf = vec![0u8; count * 16];
        let got = shekyl_dandelionpp_map_snapshot(h, buf.as_mut_ptr(), count);
        assert_eq!(got, count);
        (0..count)
            .map(|i| {
                let mut b = [0u8; 16];
                b.copy_from_slice(&buf[i * 16..i * 16 + 16]);
                b
            })
            .collect()
    }

    #[test]
    fn new_snapshot_and_free_roundtrip() {
        unsafe {
            let ids: Vec<[u8; 16]> = (1..=6).map(id).collect();
            let flat = flatten(&ids);
            let h = shekyl_dandelionpp_map_new(flat.as_ptr(), ids.len(), 3);
            assert_eq!(shekyl_dandelionpp_map_live_stems(h), 3);
            let slots = snapshot(h);
            assert_eq!(slots.len(), 3, "three stem slots");
            for s in &slots {
                assert!(ids.contains(s), "snapshot slot is one of the inputs");
            }
            shekyl_dandelionpp_map_free(h);
        }
    }

    /// Micro-test (4): the update bool is the re-arm predicate, not "differed".
    #[test]
    fn update_returns_the_rearm_predicate_not_set_difference() {
        unsafe {
            let ids: Vec<[u8; 16]> = (1..=5).map(id).collect();
            let flat = flatten(&ids);
            let h = shekyl_dandelionpp_map_new(flat.as_ptr(), ids.len(), 2);
            // Re-present the same set: no stem dropped, map already at width →
            // false, even though `current` is a different vector object.
            assert!(
                !shekyl_dandelionpp_map_update(h, flat.as_ptr(), ids.len()),
                "re-arm must not fire when the live stem set is unchanged"
            );
            // Drop everything → the live set changes → true.
            assert!(
                shekyl_dandelionpp_map_update(h, std::ptr::null(), 0),
                "dropping every stem must report a change"
            );
            shekyl_dandelionpp_map_free(h);
        }
    }

    /// Micro-test (5), Rust side: clone deep-copies — updating one handle does
    /// not touch the other. (The C++ wrapper's deleted shallow copy-ctor is the
    /// compile-time half of this guard.)
    #[test]
    fn clone_is_a_deep_copy_that_diverges() {
        unsafe {
            let ids: Vec<[u8; 16]> = (1..=4).map(id).collect();
            let flat = flatten(&ids);
            let a = shekyl_dandelionpp_map_new(flat.as_ptr(), ids.len(), 2);
            let b = shekyl_dandelionpp_map_clone(a);
            let before = snapshot(b);
            // Drop all of `a`'s stems; `b` must be untouched.
            assert!(shekyl_dandelionpp_map_update(a, std::ptr::null(), 0));
            assert_eq!(shekyl_dandelionpp_map_live_stems(a), 0);
            assert_eq!(snapshot(b), before, "clone shared state with the original");
            assert_eq!(shekyl_dandelionpp_map_live_stems(b), 2);
            shekyl_dandelionpp_map_free(a);
            shekyl_dandelionpp_map_free(b);
        }
    }

    /// Micro-test (6): snapshot preserves slot order including nils, so a
    /// positional index maps to the same connection the C++ iterator did.
    #[test]
    fn snapshot_preserves_slot_order_including_nils() {
        unsafe {
            // 3 peers, 2 stems → one spare. Drop one live stem offering only the
            // other: a slot is emptied with no candidate, so it stays nil in
            // position — the snapshot must keep that hole, not compact it.
            let ids: Vec<[u8; 16]> = (1..=3).map(id).collect();
            let flat = flatten(&ids);
            let h = shekyl_dandelionpp_map_new(flat.as_ptr(), ids.len(), 2);
            let live = snapshot(h);
            assert_eq!(live.len(), 2);
            let keep = live[1];
            let keep_flat = flatten(&[keep]);
            assert!(shekyl_dandelionpp_map_update(h, keep_flat.as_ptr(), 1));
            let after = snapshot(h);
            assert_eq!(after.len(), 2, "slot count (span) is unchanged");
            assert_eq!(
                after.iter().filter(|s| **s == NIL).count(),
                1,
                "the emptied slot stays nil in position, not compacted away"
            );
            assert!(after.contains(&keep), "the surviving stem kept its slot");
            assert_eq!(shekyl_dandelionpp_map_live_stems(h), 1);
            shekyl_dandelionpp_map_free(h);
        }
    }
}
