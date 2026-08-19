// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Credit-wire attestation admission verify (ARCHIVAL_CREDIT_WIRE.md §3–§4).

use shekyl_archival_retention::{
    attestation_root, pass_records_from_headers_and_witness, verify_pass_countersignature,
    AttestationHeader, AttestationKind, BlockAttestationWitness, ATTESTATION_HEADER_LEN,
    HYBRID_PUBKEY_CANONICAL_BYTES, MAX_ATTESTATION_RECORDS,
};
use shekyl_crypto_pq::signature::HybridPublicKey;

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
/// evaluated at this point — the marshaling-drift diagnostic (look at the header blob / cb_out_key
/// C++ passed), distinct from a genuine signature failure.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH: u8 = 5;
/// A pass record's countersignature genuinely failed, or its `p_id` is not the supplied pubkey's
/// canonical id — a forgery signal, distinct from a marshaling slip.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_COUNTERSIG_INVALID: u8 = 6;
/// A pass record names a `p_id` with no bond record (C++ passed the empty-pubkey marker).
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BOND_ABSENT: u8 = 7;
/// C++ could not read the coinbase `vout[0]` output pubkey the nonce binds.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CBKEY_UNREADABLE: u8 = 8;
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
/// `prev_block_hash` was all-zeros — the unpopulated-field sentinel.
///
/// **Distinguishable on purpose.** Folding this into a generic malformed-ctx
/// verdict would tell the next reader the *record* was bad; this code tells them
/// the *field* was never filled in, which is the only way that value arises.
///
/// **Why there is no `prev_block_hash_readable` flag** (`RF-D5`, ruled
/// 2026-08-19), stated here because the asymmetry with `cb_out_key_readable`
/// reads like an oversight otherwise:
/// - `cb_out_key_readable` models a state that **can genuinely occur** —
///   extracting the coinbase output key requires parsing the coinbase tx, which
///   can fail on a malformed one.
/// - `prev_block_hash` is the connecting block's own header field. A verifier
///   that has a block has parsed its header, so an "unreadable" arm here could
///   **never legitimately fire** — and a check that cannot fire is worse than no
///   check, because it reads as protective. On a frozen surface that is permanent.
/// - A flag would not buy the property anyway: the hazard is an *unpopulated*
///   field, and the flag is itself caller-populated, so a caller that forgets the
///   hash equally forgets the flag. What makes it fail-closed is
///   zero-initialisation — and zero-rejection gets that without a second field
///   the caller must get right.
/// - **All-zeros is a sound sentinel only where a record consumes the anchor**,
///   which is where the check lives. The reasoning first recorded here — *"a real
///   block hash under RandomX has leading zeros, never thirty-two"* — was **wrong**:
///   `prev_id` is the block *object* hash, not the RandomX PoW value, so no
///   difficulty target constrains it. And the genesis block's `prev_id` **is**
///   all-zeros, while genesis does reach this path (`top_block_hash()` returns
///   `null_hash` on an empty chain, so `add_new_block` routes it to
///   `handle_block_to_main_chain`). Gating on the ctx unconditionally would have
///   **rejected genesis and prevented chain initialisation**. Scoped to
///   record-bearing blocks — all of which are at height ≥ 1 with a real
///   predecessor hash — all-zeros is again unreachable except by a caller that
///   failed to populate the field.
pub const SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PREVHASH_UNPOPULATED: u8 = 12;

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
/// reads. `cb_out_key` is the coinbase `vout[0]` output pubkey the nonce binds (consensus rule:
/// the attestation binds `vout[0]`, not an arbitrary output); `cb_out_key_readable == 0` means C++
/// could not read it (→ `..._ERR_CBKEY_UNREADABLE`, never garbage). `headers` is the RAW
/// 49-byte-record `tx_extra` blob — Rust splits and parses it (untrusted input, rule 20 #3);
/// `headers_readable == 0` means C++ could not parse the coinbase `tx_extra` at all
/// (→ `..._ERR_HEADERS_UNREADABLE`, never misread as the committed empty set).
#[repr(C)]
pub struct ShekylArchivalAttestationVerifyCtx {
    pub attestation_root: [u8; 32],
    pub cb_out_key: [u8; 32],
    /// `block_hash(h−1)` — the connecting block's **validated** predecessor hash.
    ///
    /// Must be the predecessor the block is actually being connected to, not
    /// `prev_id` as supplied in the header: an unvalidated header field is
    /// producer-chosen, which is exactly the property `r` was deleted for having.
    /// All-zeros is rejected as the unpopulated-field sentinel
    /// (`..._ERR_PREVHASH_UNPOPULATED`); there is deliberately no readability
    /// flag, and the reasoning is on that constant.
    pub prev_block_hash: [u8; 32],
    pub cb_out_key_readable: u8,
    pub headers_readable: u8,
    pub headers_ptr: *const u8,
    pub headers_len: usize,
    pub pairs_ptr: *const ShekylArchivalPidPubkey,
    pub pairs_len: usize,
}

/// Verify a block's attestation set against its mined `attestation_root` (Phase 2 admission).
///
/// `witness` is the opaque `count ‖ pass-signatures` blob (`connect.attestation_witness`); an
/// empty blob is the zero-record set (the pre-cutover state). Returns a
/// `SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_*` code; C++ rejects on any non-`OK`.
///
/// # Safety
/// `ctx_ptr` must be valid; `witness_ptr` and the ctx's `headers`/`pairs` (and each pair's
/// `pubkey`) must each point to `len` valid bytes, or be null iff the corresponding `len == 0`.
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

    // C++ never improvises the unreadable-coinbase or unreadable-headers verdicts.
    if ctx.cb_out_key_readable == 0 {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CBKEY_UNREADABLE;
    }
    if ctx.headers_readable == 0 {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_HEADERS_UNREADABLE;
    }

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
        BlockAttestationWitness {
            pass_signatures: Vec::new(),
        }
    } else {
        let witness_bytes = unsafe { std::slice::from_raw_parts(witness_ptr, witness_len) };
        match BlockAttestationWitness::from_canonical_bytes(witness_bytes) {
            Ok(w) => w,
            Err(_) => return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_WITNESS,
        }
    };

    // 3. Pair pass headers (tx_extra order) with the witness signatures. A count mismatch is a
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

    // 7. Per-pass countersignature — only after the root agrees.
    // The nonce's anchor term, checked HERE rather than with the other ctx gates:
    // all-zeros is refused only when a countersignature will actually be verified
    // against it.
    //
    // **The genesis block is why.** `prev_id` is the block *object* hash, not the
    // RandomX PoW value, so nothing about mining excludes an all-zero block id —
    // and the genesis block's `prev_id` **is** all-zeros by construction. Genesis
    // reaches this path: `top_block_hash()` returns `null_hash` on an empty chain,
    // so `bl.prev_id == get_tail_id()` holds and `add_new_block` routes genesis to
    // `handle_block_to_main_chain`. Gating on the ctx would have rejected genesis
    // and the chain could never have initialised.
    //
    // Scoping the check to "a record will consume this" is not a genesis
    // special-case; it is checking the value where it is load-bearing. With no
    // pass records no nonce is computed, so the anchor is read by nothing and
    // enforcing it there would be asserting on a value the code never uses. Every
    // block that *does* carry a record is at height ≥ 1, whose `prev_id` is a real
    // predecessor hash — so within this scope all-zeros remains unreachable except
    // by a caller that failed to populate the field, which is exactly what the
    // sentinel is for.
    if !records.is_empty() && ctx.prev_block_hash == [0u8; 32] {
        return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PREVHASH_UNPOPULATED;
    }

    for record in &records {
        let (_, pk) = resolved
            .iter()
            .find(|(pid, _)| *pid == record.p_id)
            .expect("coverage guarantees a pair for every pass p_id");
        let Some(pk) = pk else {
            return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BOND_ABSENT;
        };
        if !verify_pass_countersignature(&ctx.prev_block_hash, &ctx.cb_out_key, pk, record) {
            return SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_COUNTERSIG_INVALID;
        }
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
