// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Credit-wire attestation admission verify (ARCHIVAL_CREDIT_WIRE.md §3–§4).

use shekyl_archival_retention::{
    attestation_root, pass_records_from_headers_and_witness, verify_pass_countersignature,
    AttestationHeader, AttestationKind, BlockAttestationWitness, PassAnchorWindow,
    PassAnchorWindowError, PassCountersignatureError, ATTESTATION_HEADER_LEN,
    HYBRID_PUBKEY_CANONICAL_BYTES, MAX_ATTESTATION_RECORDS, PASS_ANCHOR_HASH_LEN,
};
use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_types::BlockHeight;

use crate::legacy_util::slice_from_typed_ptr;

// ── Credit-wire attestation admission verify (Phase 2, ARCHIVAL_CREDIT_WIRE.md §3–§4) ──
//
// The consensus recompute-and-compare that replaces #398's interim `check_attestation_root`
// (which asserted `b.attestation_root == empty_attestation_root()`). ALL logic is here in Rust
// (rule 20, daemon clause): C++ reads LMDB by keys step-1 names, fills the ctx with raw bytes,
// and obeys the verdict — it parses nothing and decides nothing. Byte-identity of the recomputed
// root is by construction (this calls the same `attestation_root` the producer did), not by two
// implementations matching; the residual risk is marshaling, and each verdict code below makes a
// marshaling failure a distinct, self-describing reject rather than a silent misdiagnosis.

/// Success — the block's attestation set verifies against the mined `attestation_root`.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK: u8 = 0;
/// A required pointer was null.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR: u8 = 1;
/// The witness bytes did not decode (too short, count over cap, length mismatch, malformed
/// signature) OR the witness signature count did not match the block's pass headers.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_WITNESS: u8 = 2;
/// The kept-header blob was not a whole number of 49-byte records, or a record's kind byte was
/// neither miss nor pass.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_HEADERS: u8 = 3;
/// The header-record count exceeds `MAX_ATTESTATION_RECORDS` — checked FIRST, before any
/// per-record parse work proportional to the count.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CAP_EXCEEDED: u8 = 4;
/// The recomputed `attestation_root` does not equal the mined header field. Signatures are NOT
/// evaluated at this point — the marshaling-drift diagnostic (look at the header blob / witness
/// C++ passed), distinct from a genuine signature failure.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH: u8 = 5;
/// A pass record's countersignature genuinely failed, or its `p_id` is not the supplied pubkey's
/// canonical id — a forgery signal, distinct from a marshaling slip.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_COUNTERSIG_INVALID: u8 = 6;
/// A pass record names a `p_id` with no bond record (C++ passed the empty-pubkey marker).
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BOND_ABSENT: u8 = 7;
// Code 8 (`ERR_CBKEY_UNREADABLE`) is **RETIRED**, never reused. It reported that
// C++ could not read the coinbase `vout[0]` key the v1 nonce bound; `SF-D8`
// (2026-09-13) removed `cb_out_key` from the signed message, so the ctx no
// longer carries it and nothing can emit the code. Deleted per rule 23
// (a REJECTED symbol leaves the namespace entry, not the constant).
/// The `(p_id, pubkey)` pairs do not correspond EXACTLY to the parsed pass-`p_id` set (a pair with
/// no pass record, a pass `p_id` with no pair, or a duplicate pair `p_id`) — a C++/Rust parse
/// disagreement between step-1 and step-2.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH: u8 = 9;
/// A pair's pubkey length is neither 0 (bond-absent) nor `HYBRID_PUBKEY_CANONICAL_BYTES` — a
/// truncated/oversized buffer, NOT diagnosed as a bad signature.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_PUBKEY: u8 = 10;
/// C++ could not read the kept-header blob because the coinbase `tx_extra` failed to parse.
/// Unreadable headers are NOT the empty set: the `attestation_root` commitment over the kept
/// headers is unverifiable, and the settlement scan later reads those same coinbase bytes — so
/// the block is rejected loudly rather than admitted as if it committed zero records.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_HEADERS_UNREADABLE: u8 = 11;
// Code 12 (`ERR_PREVHASH_UNPOPULATED`) is **RETIRED**, never reused. It refused
// an all-zero `prev_block_hash` — the v1 nonce's anchor term — when a record
// would consume it. `SF-D8` (2026-09-13) replaced that term with a requester
// anchor the verifier resolves against a window of chain hashes keyed off the
// predecessor **height**, for which no sentinel exists: `0` is block 1's real
// predecessor height. A caller that forgets to populate `predecessor_height`
// fails closed anyway — the window it implies holds the wrong hashes (or does
// not exist), so every record is refused; there is no silent-accept path for
// the field to guard.
/// The anchor-hash table does not have the LENGTH the predecessor height implies: `L + 1` hashes
/// at or above the threshold, none below it. A marshaling slip on the C++ side (the caller sized
/// the table without asking [`shekyl_archival_pass_anchor_window`]) — checked on EVERY block,
/// records or not, so the drift is loud on the first block after it appears rather than on the
/// first block that carries a pass record. This is a shape check only: the verifier receives the
/// hashes, not the height they were filled from, so a right-length table filled from the wrong
/// base is indistinguishable here and surfaces as `..._ERR_COUNTERSIG_INVALID` on the first
/// record that consumes a differing hash (fail-closed, mis-diagnosed). The C++ fill derives its
/// base from step 0's `first`, so the two heights come from one call.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_ANCHOR_TABLE: u8 = 13;
/// A pass record's carried `anchor_height` lies outside the block's admission window
/// `[h − depth − L, h − depth]` — a stale or pre-fetched read (`SF-D8`). No hash exists to check
/// against, so no signature is evaluated; distinct from a genuine signature failure.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ANCHOR_OUT_OF_WINDOW: u8 = 14;
/// The block carries a pass record but its predecessor height is below
/// `PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT` (`depth + L`): no anchor window exists that early, so no
/// pass can be admitted — the genesis boundary. First settlement is at 10 000, so nothing is lost.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BELOW_ANCHOR_THRESHOLD: u8 = 15;

/// One `(p_id, hybrid pubkey)` pair C++ resolved for a distinct pass `p_id` that step-1 named.
/// `pubkey_len == 0` is the bond-absent marker; `== HYBRID_PUBKEY_CANONICAL_BYTES` is a key; any
/// other length is `..._ERR_MALFORMED_PUBKEY`. The pubkey is a property of `P`, so ONE pair serves
/// every pass record with this `p_id`.
#[repr(C)]
pub struct ShekylArchivalPidPubkey {
    pub p_id: [u8; 32],
    pub pubkey_ptr: *const u8,
    pub pubkey_len: usize,
}

/// Consensus context for [`shekyl_archival_verify_attestation`], filled by C++ after its LMDB
/// reads. `headers` is the RAW 49-byte-record `tx_extra` blob — Rust splits and parses it
/// (untrusted input, rule 20 #3); `headers_readable == 0` means C++ could not parse the coinbase
/// `tx_extra` at all (→ `..._ERR_HEADERS_UNREADABLE`, never misread as the committed empty set).
///
/// `SF-D8` (2026-09-13) removed the v1 nonce's inputs from this struct: the coinbase `vout[0]`
/// key and its readability flag, and the single predecessor **hash**. The v2 countersignature
/// binds `nonce ‖ anchor_height ‖ anchor_hash ‖ shard_id`, where the anchor is a block the
/// requester chose within `[h − depth − L, h − depth]`; the chain-state the verifier needs is the
/// predecessor height plus the connecting chain's hash at each height of that window.
#[repr(C)]
pub struct ShekylArchivalAttestationVerifyCtx {
    pub attestation_root: [u8; 32],
    /// `h` — the **validated** height of the block this block connects to.
    ///
    /// Must be the predecessor the block is actually being connected to (main chain: the
    /// current top height; alt chain: the alt parent's height), never a header-claimed value —
    /// an unvalidated header field is producer-chosen. It keys the anchor window: admission
    /// accepts anchor heights in `[h − depth − L, h − depth]` and looks each up in
    /// `anchor_hashes`. There is no unpopulated sentinel because `0` is a legitimate value
    /// (block 1's predecessor); a forgotten field fails closed — the implied window holds the
    /// wrong hashes or does not exist, so every record is refused.
    pub predecessor_height: u64,
    /// The connecting chain's block hash at each height of the anchor window, ascending:
    /// `anchor_hashes[i]` is the hash at `first + i`, where `(first, len)` is what
    /// [`shekyl_archival_pass_anchor_window`] returned for `predecessor_height`. Filled from the
    /// chain the block is being connected to — the main chain, or the alt chain **above the fork
    /// point** — so a block validated on an alt chain sees that chain's anchors. Exactly `L + 1`
    /// entries at or above the threshold, exactly `0` below it (`shekyl_archival_pass_anchor_window`
    /// writes `(0, 0)` there and returns `OK`); any other shape is
    /// `..._ERR_MALFORMED_ANCHOR_TABLE`, checked on every block.
    pub anchor_hashes_ptr: *const [u8; PASS_ANCHOR_HASH_LEN],
    pub anchor_hashes_len: usize,
    pub headers_readable: u8,
    pub headers_ptr: *const u8,
    pub headers_len: usize,
    pub pairs_ptr: *const ShekylArchivalPidPubkey,
    pub pairs_len: usize,
}

/// Verify a block's attestation set against its mined `attestation_root` (Phase 2 admission).
///
/// `witness` is the opaque `count ‖ (nonce ‖ anchor_height_le ‖ signature)*` blob
/// (`connect.attestation_witness`); an empty blob is the zero-record set. Returns a
/// `SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_*` code; C++ rejects on any non-`OK`.
///
/// # Safety
/// `ctx_ptr` must be valid; `witness_ptr` and the ctx's `headers`/`pairs` (and each pair's
/// `pubkey`) must each point to `len` valid bytes, or be null iff the corresponding `len == 0`.
/// `ctx.anchor_hashes_ptr` must point to `ctx.anchor_hashes_len` valid, readable `[u8; 32]`
/// entries, or be null iff `anchor_hashes_len == 0`; a non-null pointer with a shorter backing
/// allocation is UB the length check cannot catch (it compares `len` against the window shape,
/// not against the allocation).
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_verify_attestation(
    witness_ptr: *const u8,
    witness_len: usize,
    ctx_ptr: *const ShekylArchivalAttestationVerifyCtx,
) -> u8 {
    if ctx_ptr.is_null() || (witness_ptr.is_null() && witness_len != 0) {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR;
    }
    let ctx = unsafe { &*ctx_ptr };

    // C++ never improvises the unreadable-headers verdict.
    if ctx.headers_readable == 0 {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_HEADERS_UNREADABLE;
    }

    // 0. Anchor window shape — O(1), checked on EVERY block so a marshaling drift in the table
    //    C++ fills is loud immediately, not on the first block that happens to carry a pass
    //    record. Below the threshold no window exists and the table must be empty; at or above
    //    it the table must be exactly `L + 1` hashes for `[h − depth − L, h − depth]`.
    //    The table is a typed `[u8; 32]` array, so it goes through the typed seam
    //    (`slice_from_typed_ptr`: zero-length → empty, null → refuse, `isize::MAX` byte bound),
    //    not a bare `from_raw_parts` — the SA-R-7 ratchet (`tests/ffi_boundary_ratchet.rs`)
    //    pins this file's raw-read count and would flag a new raw site.
    let Some(anchor_hashes): Option<&[[u8; PASS_ANCHOR_HASH_LEN]]> =
        (unsafe { slice_from_typed_ptr(ctx.anchor_hashes_ptr, ctx.anchor_hashes_len) })
    else {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR;
    };
    let window: Option<PassAnchorWindow> = match PassAnchorWindow::from_table(
        BlockHeight::from_raw(ctx.predecessor_height),
        anchor_hashes,
    ) {
        Ok(w) => Some(w),
        Err(PassAnchorWindowError::BelowThreshold { .. }) if anchor_hashes.is_empty() => None,
        Err(_) => return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_ANCHOR_TABLE,
    };

    // 1. Header blob: cap FIRST (structural, before per-record work), then parse ONCE. The parsed
    //    records are carried through coverage / recompute / countersig — never re-parsed.
    let headers: &[u8] = if ctx.headers_len == 0 {
        &[]
    } else if ctx.headers_ptr.is_null() {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR;
    } else {
        unsafe { std::slice::from_raw_parts(ctx.headers_ptr, ctx.headers_len) }
    };
    if !headers.len().is_multiple_of(ATTESTATION_HEADER_LEN) {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_HEADERS;
    }
    if headers.len() / ATTESTATION_HEADER_LEN > MAX_ATTESTATION_RECORDS {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CAP_EXCEEDED;
    }
    let mut parsed_headers = Vec::with_capacity(headers.len() / ATTESTATION_HEADER_LEN);
    for chunk in headers.chunks_exact(ATTESTATION_HEADER_LEN) {
        match AttestationHeader::from_canonical_bytes(chunk) {
            Ok(h) => parsed_headers.push(h),
            Err(_) => return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_HEADERS,
        }
    }

    // 2. Witness. An empty blob is the zero-signature set; any non-empty blob must decode exactly.
    let witness = if witness_len == 0 {
        BlockAttestationWitness { passes: Vec::new() }
    } else {
        let witness_bytes = unsafe { std::slice::from_raw_parts(witness_ptr, witness_len) };
        match BlockAttestationWitness::from_canonical_bytes(witness_bytes) {
            Ok(w) => w,
            Err(_) => return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_WITNESS,
        }
    };

    // 3. Pair pass headers (tx_extra order) with the witness entries. A count mismatch is a
    //    malformed witness for this block. Parsed ONCE above — carried through below.
    let records = match pass_records_from_headers_and_witness(&parsed_headers, &witness) {
        Ok(r) => r,
        Err(_) => return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_WITNESS,
    };

    // 4. Validate + collect the (p_id, pubkey) pairs; reject a duplicate pair p_id. `None` is the
    //    bond-absent marker; a wrong pubkey length is malformed, never a bad-signature verdict.
    let pairs: &[ShekylArchivalPidPubkey] = if ctx.pairs_len == 0 {
        &[]
    } else if ctx.pairs_ptr.is_null() {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR;
    } else {
        unsafe { std::slice::from_raw_parts(ctx.pairs_ptr, ctx.pairs_len) }
    };
    let mut resolved: Vec<([u8; 32], Option<HybridPublicKey>)> = Vec::with_capacity(pairs.len());
    for pair in pairs {
        if resolved.iter().any(|(pid, _)| *pid == pair.p_id) {
            return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH; // duplicate pair p_id
        }
        let pk = if pair.pubkey_len == 0 {
            None // bond-absent marker
        } else if pair.pubkey_len == HYBRID_PUBKEY_CANONICAL_BYTES {
            if pair.pubkey_ptr.is_null() {
                return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR;
            }
            let bytes = unsafe { std::slice::from_raw_parts(pair.pubkey_ptr, pair.pubkey_len) };
            match HybridPublicKey::from_canonical_bytes(bytes) {
                Ok(k) => Some(k),
                Err(_) => return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_PUBKEY,
            }
        } else {
            return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_PUBKEY;
        };
        resolved.push((pair.p_id, pk));
    }

    // 5. Coverage: the pair set must equal the parsed pass-p_id set EXACTLY (one pair per distinct
    //    p_id serves every record with that p_id). Every pair names a pass record, and every pass
    //    record has a pair. With duplicate pairs already rejected, these two subset checks give
    //    set-equality and close the step-1/step-2 independent-parse gap.
    if resolved
        .iter()
        .any(|(pid, _)| !records.iter().any(|r| r.p_id == *pid))
    {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH; // a pair with no pass record
    }
    if records
        .iter()
        .any(|r| !resolved.iter().any(|(pid, _)| *pid == r.p_id))
    {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH; // a pass p_id with no pair
    }

    // 6. Recompute the root and compare — signatures NOT evaluated here (marshaling-drift gate).
    //    `attestation_root` cannot fail over signatures that already decoded from the witness.
    let recomputed = match attestation_root(&records) {
        Ok(root) => root,
        Err(_) => return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_WITNESS,
    };
    if recomputed != ctx.attestation_root {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH;
    }

    // 7. Per-pass countersignature — only after the root agrees. Each record's carried nonce and
    //    anchor height, the connecting chain's hash at that height (one indexed lookup in the
    //    window), and the record's own shard_id form the SF-D8 transcript; the record's p_id must
    //    be the paired pubkey's canonical id. Below the anchor threshold there is no window, so
    //    a block with any pass record is refused there (genesis boundary).
    if records.is_empty() {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK;
    }
    let Some(window) = window else {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BELOW_ANCHOR_THRESHOLD;
    };
    for record in &records {
        let (_, pk) = resolved
            .iter()
            .find(|(pid, _)| *pid == record.p_id)
            .expect("coverage guarantees a pair for every pass p_id");
        let Some(pk) = pk else {
            return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BOND_ABSENT;
        };
        match verify_pass_countersignature(&window, pk, record) {
            Ok(()) => {}
            Err(PassCountersignatureError::AnchorOutOfWindow { .. }) => {
                return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ANCHOR_OUT_OF_WINDOW;
            }
            Err(
                PassCountersignatureError::PIdMismatch
                | PassCountersignatureError::InvalidSignature,
            ) => {
                return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_COUNTERSIG_INVALID;
            }
        }
    }

    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
}

/// Step 0: the table shape C++ must fill for a block connecting to `predecessor_height`.
///
/// Always returns `OK` (or `NULL_PTR`): writes `(first, L + 1)` when a window exists, or
/// `(0, 0)` below the genesis threshold. `ERR_BELOW_ANCHOR_THRESHOLD` is a verify verdict
/// only — this sizer has zero authority over block validity. Step 2 re-derives the window
/// and rejects any other table shape.
///
/// # Safety
/// `out_first_height` and `out_len` must be valid, writable pointers.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_pass_anchor_window(
    predecessor_height: u64,
    out_first_height: *mut u64,
    out_len: *mut usize,
) -> u8 {
    if out_first_height.is_null() || out_len.is_null() {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR;
    }
    match PassAnchorWindow::shape_for_predecessor(BlockHeight::from_raw(predecessor_height)) {
        Some((first, len)) => unsafe {
            *out_first_height = first.to_raw();
            *out_len = len;
        },
        None => unsafe {
            *out_first_height = 0;
            *out_len = 0;
        },
    }
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
}

/// Name the distinct pass `p_id`s in a block's attestation headers (Phase 2 admission, step 1).
///
/// The C++ shim calls this to learn *which* archival-bond pubkeys it must read from LMDB before it
/// can build the [`ShekylArchivalAttestationVerifyCtx`] pairs for
/// [`shekyl_archival_verify_attestation`]. It parses the same `tx_extra` header blob (49-byte
/// [`AttestationHeader`] records), keeps only `kind = Pass` (a miss carries no countersignature, so
/// no bond to read), and writes the **distinct** pass `p_id`s to `out` (dedup order unspecified).
///
/// This step has **zero authority**: it decides no block validity. If it under- or over-reports,
/// step 2 re-derives the authoritative pass-`p_id` set from the *same* headers and rejects the
/// coverage mismatch (`ERR_PUBKEY_SET_MISMATCH`) — a loud verdict, never a silent wrong-key read.
/// It emits only the `{OK, ERR_NULL_PTR, ERR_MALFORMED_HEADERS, ERR_CAP_EXCEEDED}` subset of the
/// shared verdict family; the caller sizes `out` at `MAX_ATTESTATION_RECORDS`, so the same cap-first
/// bound that step 2 applies makes an output overflow structurally impossible (still guarded).
/// `*out_len` is written on every non-null-`out_len` return (0 on error).
///
/// # Safety
/// `out_len` must be a valid `*mut usize`. `out_ptr` must point to `out_cap` writable `[u8; 32]`
/// slots (or be null iff no pass record is found). `headers_ptr` must point to `headers_len` valid
/// bytes, or be null iff `headers_len == 0`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_attestation_pass_p_ids(
    headers_ptr: *const u8,
    headers_len: usize,
    out_ptr: *mut [u8; 32],
    out_cap: usize,
    out_len: *mut usize,
) -> u8 {
    if out_len.is_null() {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR;
    }
    unsafe {
        *out_len = 0; // defined even on the error returns below
    }

    // Same cap-first / multiple-of / parse discipline as step 2, so the two agree on what "malformed
    // headers" and "too many records" mean over the identical blob.
    let headers: &[u8] = if headers_len == 0 {
        &[]
    } else if headers_ptr.is_null() {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR;
    } else {
        unsafe { std::slice::from_raw_parts(headers_ptr, headers_len) }
    };
    if !headers.len().is_multiple_of(ATTESTATION_HEADER_LEN) {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_HEADERS;
    }
    if headers.len() / ATTESTATION_HEADER_LEN > MAX_ATTESTATION_RECORDS {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CAP_EXCEEDED;
    }

    let mut distinct: Vec<[u8; 32]> = Vec::new();
    for chunk in headers.chunks_exact(ATTESTATION_HEADER_LEN) {
        let header = match AttestationHeader::from_canonical_bytes(chunk) {
            Ok(h) => h,
            Err(_) => return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_HEADERS,
        };
        if header.kind != AttestationKind::Pass {
            continue; // miss records have no countersignature — no bond to read
        }
        if !distinct.contains(&header.p_id) {
            distinct.push(header.p_id);
        }
    }

    // Belt-and-suspenders: cap-first already bounds records ≤ MAX_ATTESTATION_RECORDS and the caller
    // sizes `out` there, so this cannot fire unless C++ under-sized the buffer.
    if distinct.len() > out_cap {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CAP_EXCEEDED;
    }
    if !distinct.is_empty() {
        if out_ptr.is_null() {
            return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR;
        }
        let out = unsafe { std::slice::from_raw_parts_mut(out_ptr, distinct.len()) };
        out.copy_from_slice(&distinct);
    }
    unsafe {
        *out_len = distinct.len();
    }
    SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
}
