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
    // Contract: `ids` is null only when `n == 0`. A null with `n > 0` is a caller
    // bug — catch it in debug; stay UB-free in release by returning the empty set
    // rather than forming a slice from null.
    debug_assert!(n == 0 || !ids.is_null(), "read_ids: null ids with n > 0");
    // `n * 16` must not overflow the address space: a huge `n` from a buggy or
    // hostile C caller would otherwise form an undersized slice and read out of
    // bounds. Overflow, a null pointer, or `n == 0` all degrade to the empty set.
    let byte_len = n.checked_mul(16);
    debug_assert!(byte_len.is_some(), "read_ids: n * 16 overflows usize");
    let byte_len = match byte_len {
        Some(len) if len != 0 && !ids.is_null() => len,
        _ => return Vec::new(),
    };
    let bytes = slice::from_raw_parts(ids, byte_len);
    (0..n)
        .filter_map(|i| {
            let mut b = [0u8; 16];
            b.copy_from_slice(&bytes[i * 16..i * 16 + 16]);
            // NIL is the absent-slot / local-origin sentinel; it must never enter
            // the map as a live peer (a nil "peer" would snapshot back as nil
            // bytes and be indistinguishable from an empty slot). A caller
            // including it in the connection list is a bug: catch it in debug,
            // drop it in release.
            let is_nil = b == NIL;
            debug_assert!(!is_nil, "read_ids: NIL uuid in the connection list");
            if is_nil {
                None
            } else {
                Some(ConnectionId::from_bytes(b))
            }
        })
        .collect()
}

/// Interpret 16 source bytes: the nil sentinel means locally originated
/// (`None`), any other value is a peer id.
///
/// Safe by construction — only the nil *bytes* encode local origin, and a null
/// pointer cannot reach here because the boundary rejects it
/// (see [`shekyl_dandelionpp_map_get_stem`]).
fn source_from_bytes(bytes: [u8; 16]) -> Option<ConnectionId> {
    if bytes == NIL {
        None
    } else {
        Some(ConnectionId::from_bytes(bytes))
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
/// Mirrors the C++ `connection_map{out_connections, stems}` constructor. Returns
/// null if `stems == usize::MAX` (the C++ error sentinel), matching the wrapper's
/// `throw` rather than aborting across the FFI.
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
    // `usize::MAX` is `select_stem`'s error sentinel in the C++ map, and
    // `vec![0; usize::MAX]` in `StemMap::new` would abort — reject it at the
    // boundary. The C++ wrapper throws before reaching here; this defends direct
    // C callers.
    if stems == usize::MAX {
        return std::ptr::null_mut();
    }
    let conns = read_ids(ids, n);
    let mut rng = SecureRelayRng;
    let map = StemMap::new(conns, stems, &mut rng);
    Box::into_raw(Box::new(StemMapHandle { map, rng }))
}

/// Deep-copy a handle — the C++ `connection_map::clone()` / copy-constructor.
/// The copy and the original diverge; nothing is shared. A null `handle`
/// (moved-from wrapper) returns null.
///
/// # Safety
/// `handle` must be null or a live pointer from [`shekyl_dandelionpp_map_new`] /
/// [`shekyl_dandelionpp_map_clone`]. The returned handle must be freed.
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_clone(
    handle: *const StemMapHandle,
) -> *mut StemMapHandle {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let h = &*handle;
    Box::into_raw(Box::new(StemMapHandle {
        map: h.map.clone(),
        rng: SecureRelayRng,
    }))
}

/// Merge `ids` (`n` × 16 bytes) into the map. Returns `true` iff the live stem
/// set changed — the **exact** C++ `update` predicate the caller gates channel
/// re-arm on (a slot dropped/emptied, or the map grew), not "the set differed".
/// A null `handle` returns `false`.
///
/// # Safety
/// `handle` must be null or live; `ids` must point to `n * 16` readable bytes
/// (or be null with `n == 0`).
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_update(
    handle: *mut StemMapHandle,
    ids: *const u8,
    n: usize,
) -> bool {
    if handle.is_null() {
        return false;
    }
    let h = &mut *handle;
    let conns = read_ids(ids, n);
    h.map.update(conns, &mut h.rng).needs_rearm()
}

/// Resolve the stem peer for `source` (16 bytes; nil = locally originated),
/// writing it into `out` (16 bytes). Returns `true` if a stem was assigned;
/// on `false` the caller must fluff and `out` is left nil. Mutates the map
/// (source→slot pinning), as the C++ `get_stem` does. A null `handle`, `source`
/// or `out` returns `false` (writing nil into `out` when `out` is non-null):
/// local origin is the nil *bytes*, never a null pointer, so a null `source`
/// fails closed instead of being routed as a local transaction.
///
/// # Safety
/// `handle` must be null or live; `source` and `out` must each be null or point
/// to 16 bytes (readable / writable respectively).
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_get_stem(
    handle: *mut StemMapHandle,
    source: *const u8,
    out: *mut u8,
) -> bool {
    if out.is_null() {
        return false;
    }
    if handle.is_null() {
        write_id(out, &NIL);
        return false;
    }
    // Past here `source` is actually interpreted. It is 16 readable bytes by
    // contract; only the nil *bytes* encode local origin, never a null pointer.
    // A null here is a caller bug — fail closed rather than routing it as a
    // local-origin transaction, which would pin that entry and bump a usage
    // count (mutating the map on a bug). Caught in debug, safe in release.
    debug_assert!(!source.is_null(), "map_get_stem: null source pointer");
    if source.is_null() {
        write_id(out, &NIL);
        return false;
    }
    let h = &mut *handle;
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(slice::from_raw_parts(source, 16));
    match h.map.stem_for(source_from_bytes(bytes), &mut h.rng) {
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
/// caller can size with `(buf = null, cap = 0)` then fill — or, when the caller
/// knows the configured stem width (a hard upper bound on slot count), pass that
/// as `cap` and fill in one call. A null `handle` returns `0`.
///
/// Order and nils are load-bearing: `levin_notify` indexes a parallel noise
/// channel by slot position (§16.1).
///
/// # Safety
/// `handle` must be null or live; if `cap >= slot count` and `count > 0`,
/// `buf` must point to `cap * 16` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_snapshot(
    handle: *const StemMapHandle,
    buf: *mut u8,
    cap: usize,
) -> usize {
    if handle.is_null() {
        return 0;
    }
    let h = &*handle;
    let slots = h.map.slots();
    let count = slots.len();
    if cap < count {
        return count;
    }
    if count == 0 {
        return 0;
    }
    if buf.is_null() {
        // cap >= count > 0 but no buffer: refuse to write; still report count.
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
/// A null `handle` returns `0`.
///
/// # Safety
/// `handle` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn shekyl_dandelionpp_map_live_stems(handle: *const StemMapHandle) -> usize {
    if handle.is_null() {
        return 0;
    }
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
    /// Arms: unchanged-at-width → false; drop → true; grow/backfill → true
    /// (DAEMON_RELAY_PRIVACY.md §16 acceptance).
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

            // Grow/backfill arm: construct under-width, then offer enough peers
            // to fill → true (a stem set change, not a mere set-difference).
            let under: Vec<[u8; 16]> = (1..=1).map(id).collect();
            let under_flat = flatten(&under);
            let h = shekyl_dandelionpp_map_new(under_flat.as_ptr(), under.len(), 2);
            assert_eq!(
                shekyl_dandelionpp_map_live_stems(h),
                1,
                "one peer against width 2 leaves a hole"
            );
            let fill: Vec<[u8; 16]> = (1..=3).map(id).collect();
            let fill_flat = flatten(&fill);
            assert!(
                shekyl_dandelionpp_map_update(h, fill_flat.as_ptr(), fill.len()),
                "growing/backfilling under-capacity must re-arm"
            );
            assert_eq!(shekyl_dandelionpp_map_live_stems(h), 2);
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

    /// Null handle is a safe no-op on every export (moved-from C++ wrapper).
    #[test]
    fn null_handle_is_a_safe_no_op() {
        unsafe {
            assert!(shekyl_dandelionpp_map_clone(std::ptr::null()).is_null());
            assert!(!shekyl_dandelionpp_map_update(
                std::ptr::null_mut(),
                std::ptr::null(),
                0
            ));
            let mut out = [0xAAu8; 16];
            assert!(!shekyl_dandelionpp_map_get_stem(
                std::ptr::null_mut(),
                std::ptr::null(),
                out.as_mut_ptr()
            ));
            assert_eq!(out, NIL);
            assert_eq!(
                shekyl_dandelionpp_map_snapshot(std::ptr::null(), std::ptr::null_mut(), 0),
                0
            );
            assert_eq!(shekyl_dandelionpp_map_live_stems(std::ptr::null()), 0);
            shekyl_dandelionpp_map_free(std::ptr::null_mut()); // no-op
        }
    }

    /// Caller that knows the configured stem width can fill in one snapshot call.
    #[test]
    fn snapshot_fills_in_one_call_when_cap_is_stem_width() {
        unsafe {
            let ids: Vec<[u8; 16]> = (1..=4).map(id).collect();
            let flat = flatten(&ids);
            let stems = 3usize;
            let h = shekyl_dandelionpp_map_new(flat.as_ptr(), ids.len(), stems);
            let mut buf = vec![0u8; stems * 16];
            let count = shekyl_dandelionpp_map_snapshot(h, buf.as_mut_ptr(), stems);
            assert_eq!(count, 3);
            // Under-filled: one peer, width 3 → one slot written, count 1.
            shekyl_dandelionpp_map_free(h);
            let one = flatten(&[id(1)]);
            let h = shekyl_dandelionpp_map_new(one.as_ptr(), 1, stems);
            let count = shekyl_dandelionpp_map_snapshot(h, buf.as_mut_ptr(), stems);
            assert_eq!(count, 1, "slot span is under width when under-filled");
            shekyl_dandelionpp_map_free(h);
        }
    }

    #[test]
    fn map_new_rejects_the_max_stems_sentinel() {
        // `usize::MAX` is the C++ error sentinel; `map_new` must return null
        // rather than let `StemMap::new` abort on `vec![0; usize::MAX]`.
        unsafe {
            let h = shekyl_dandelionpp_map_new(std::ptr::null(), 0, usize::MAX);
            assert!(h.is_null(), "usize::MAX stems must return null, not abort");
            shekyl_dandelionpp_map_free(h); // null free is a no-op
        }
    }

    // Note: the NIL-in-connection-list guard (read_ids) can't be unit-tested —
    // the debug_assert fires inside an `extern "C"` (nounwind) function under the
    // workspace's `panic = "abort"`, so it aborts rather than unwinds and
    // `#[should_panic]` can't catch it. The filter (`filter_map` dropping nil) is
    // correct by construction; valid-input behaviour is covered by the oracle.
}
