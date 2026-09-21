// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Attestation-admission FFI pins (extracted from the former monofile).
//!
//! Whole-file test module: `#![cfg(test)]` self-declares so the production
//! debug-macro lint (and similar scanners) treat KAT `println!` as test-only,
//! matching the monofile's pre-split `#[cfg(test)]` gate.

#![cfg(test)]

use super::*;
use shekyl_archival_retention::{
    attestation_root, empty_attestation_root, p_canonical_id_from_hybrid_pubkey,
    pass_countersignature_message, AttestationHeader, AttestationKind, BlockAttestationWitness,
    PassRecord, PassWitness, ATTESTATION_HEADER_LEN, MAX_ATTESTATION_RECORDS,
    PASS_ANCHOR_DEPTH_BLOCKS, PASS_ANCHOR_HASH_LEN, PASS_ANCHOR_LAG_BLOCKS,
    PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT, PASS_ANCHOR_WINDOW_LEN, PASS_NONCE_LEN,
};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridSecretKey, SignatureScheme};
use shekyl_types::BlockHeight;

const SHARD: u64 = 42;
const EPOCH: u64 = 1000;
/// The connecting block's validated predecessor height `h`, comfortably above the anchor
/// threshold: its window is `[h − depth − L, h − depth]`.
const HEIGHT: u64 = 7777;
/// The requester's anchor: `tip − depth` at request time, which lands at the top of the window
/// for a block whose predecessor is `HEIGHT`.
const ANCHOR: u64 = HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();
/// The requester-random nonce the pass record carries (SF-D8). Fixed here so each test perturbs
/// exactly one field.
const NONCE: [u8; PASS_NONCE_LEN] = [7u8; PASS_NONCE_LEN];

/// A deterministic stand-in for the connecting chain: the block hash at `height`. The verifier
/// never reads a chain — the test plays C++ and fills the window table from this.
fn chain_hash(height: u64) -> [u8; PASS_ANCHOR_HASH_LEN] {
    let mut h = [0u8; PASS_ANCHOR_HASH_LEN];
    h[..8].copy_from_slice(&height.to_le_bytes());
    h[8] = 0xF1;
    h
}

/// The table C++ fills for a block whose predecessor is `predecessor_height`, sized by asking
/// [`shekyl_archival_pass_anchor_window`] — the same round trip the daemon makes. Empty below
/// the threshold.
fn window_table(predecessor_height: u64) -> Vec<[u8; PASS_ANCHOR_HASH_LEN]> {
    let mut first = 0u64;
    let mut len = 0usize;
    let code = unsafe {
        shekyl_archival_pass_anchor_window(predecessor_height, &raw mut first, &raw mut len)
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
    if len == 0 {
        assert_eq!(first, 0);
        return Vec::new();
    }
    (0..len as u64).map(|i| chain_hash(first + i)).collect()
}

struct Scenario {
    witness: Vec<u8>,
    headers: Vec<u8>,
    pubkey: Vec<u8>,
    p_id: [u8; 32],
    root: [u8; 32],
}

fn real_p() -> (Vec<u8>, [u8; 32], HybridSecretKey) {
    let (pk, sk) = HybridEd25519MlDsa
        .generate_ephemeral_keypair_for_tests()
        .expect("keypair");
    let pubkey = pk.to_canonical_bytes().expect("pk bytes");
    let p_id = *p_canonical_id_from_hybrid_pubkey(&pubkey).as_bytes();
    (pubkey, p_id, sk)
}

/// A one-pass-record block whose record is signed by `signing_sk` but claims
/// `claimed_p_id` / `claimed_pubkey`. Signer == claimed P → valid; a different key → the root
/// still recomputes (it commits the sig bytes) but the countersig fails against P's key.
fn one_pass(
    signing_sk: &HybridSecretKey,
    claimed_p_id: [u8; 32],
    claimed_pubkey: Vec<u8>,
) -> Scenario {
    let msg = pass_countersignature_message(
        &NONCE,
        BlockHeight::from_raw(ANCHOR),
        &chain_hash(ANCHOR),
        SHARD,
    );
    let sig = HybridEd25519MlDsa
        .sign(
            signing_sk,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION,
            &msg,
        )
        .expect("sign");
    let record = PassRecord {
        p_id: claimed_p_id,
        shard_id: SHARD,
        settlement_epoch: EPOCH,
        nonce: NONCE,
        anchor_height: BlockHeight::from_raw(ANCHOR),
        signature: sig.clone(),
    };
    let header = AttestationHeader {
        p_id: claimed_p_id,
        shard_id: SHARD,
        settlement_epoch: EPOCH,
        kind: AttestationKind::Pass,
    };
    Scenario {
        witness: BlockAttestationWitness {
            passes: vec![PassWitness {
                nonce: NONCE,
                anchor_height: BlockHeight::from_raw(ANCHOR),
                signature: sig,
            }],
        }
        .to_canonical_bytes()
        .expect("witness bytes"),
        headers: header.to_canonical_bytes().to_vec(),
        pubkey: claimed_pubkey,
        p_id: claimed_p_id,
        root: attestation_root(std::slice::from_ref(&record)).expect("root"),
    }
}

fn pair(p_id: [u8; 32], pubkey: &[u8]) -> ShekylArchivalPidPubkey {
    ShekylArchivalPidPubkey {
        p_id,
        pubkey_ptr: if pubkey.is_empty() {
            std::ptr::null()
        } else {
            pubkey.as_ptr()
        },
        pubkey_len: pubkey.len(),
    }
}

/// FFI verify over explicit bytes/pairs so each test perturbs one field. All slices are kept
/// alive by the caller for the duration of the call.
fn call(root: [u8; 32], headers: &[u8], witness: &[u8], pairs: &[ShekylArchivalPidPubkey]) -> u8 {
    call_at_height(HEIGHT, root, headers, witness, pairs)
}

/// Same as [`call`] but with the predecessor height chosen, for the tests that vary it. The
/// anchor table is filled the way C++ fills it — from the chain, for exactly that height.
fn call_at_height(
    predecessor_height: u64,
    root: [u8; 32],
    headers: &[u8],
    witness: &[u8],
    pairs: &[ShekylArchivalPidPubkey],
) -> u8 {
    let table = window_table(predecessor_height);
    call_with_table(predecessor_height, &table, root, headers, witness, pairs)
}

/// The fully explicit form: the caller supplies the anchor table, for the tests that perturb it.
fn call_with_table(
    predecessor_height: u64,
    table: &[[u8; PASS_ANCHOR_HASH_LEN]],
    root: [u8; 32],
    headers: &[u8],
    witness: &[u8],
    pairs: &[ShekylArchivalPidPubkey],
) -> u8 {
    let ctx = ShekylArchivalAttestationVerifyCtx {
        attestation_root: root,
        predecessor_height,
        anchor_hashes_ptr: if table.is_empty() {
            std::ptr::null()
        } else {
            table.as_ptr()
        },
        anchor_hashes_len: table.len(),
        headers_readable: 1,
        headers_ptr: if headers.is_empty() {
            std::ptr::null()
        } else {
            headers.as_ptr()
        },
        headers_len: headers.len(),
        pairs_ptr: if pairs.is_empty() {
            std::ptr::null()
        } else {
            pairs.as_ptr()
        },
        pairs_len: pairs.len(),
    };
    unsafe {
        shekyl_archival_verify_attestation(
            if witness.is_empty() {
                std::ptr::null()
            } else {
                witness.as_ptr()
            },
            witness.len(),
            &raw const ctx,
        )
    }
}

#[test]
fn valid_block_verifies() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey)];
    assert_eq!(
        call(s.root, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
    );
}

#[test]
fn empty_block_verifies_against_empty_root() {
    // No headers, empty witness, no pairs — the pre-cutover state, reproduced.
    assert_eq!(
        call(empty_attestation_root(), &[], &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
    );
}

/// The reject half of interim-equivalence. The interim `check_attestation_root` rejects a block
/// whose mined `attestation_root != empty_attestation_root()`. Over the empty (pre-cutover)
/// block shape the new verify recomputes `attestation_root(&[]) == empty_attestation_root()`
/// (identical by construction) and must reject a non-empty mined root the same way. With the
/// accept case above, this reproduces the interim EXACTLY on the empty shape — the claim that
/// licenses deleting it (distinct from the populated pinned fixture that licenses the verify).
#[test]
fn empty_block_nonempty_root_is_root_mismatch() {
    let mut wrong = empty_attestation_root();
    wrong[0] ^= 0x01;
    assert_eq!(
        call(wrong, &[], &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH
    );
}

/// The one deliberate divergence from the interim, pinned so the equivalence claim stays honest.
/// The interim ignores the witness, so an empty-root block carrying unsolicited witness bytes
/// (a peer can attach them via `entry.attestation_witness`) is ACCEPTED. The new verify pairs
/// pass headers (0) against witness signatures (>0) and rejects the count mismatch as
/// MALFORMED_WITNESS. Reject is the intended tightening — garbage witness bytes are never
/// accepted or stored, consistent with the exact witness-size cap. Pre-genesis there are no old
/// nodes, so the stricter rule costs nothing. Equivalence therefore holds on empty-WITNESS
/// blocks (the only shape that exists pre-cutover); on unsolicited witness bytes the new verify
/// is strictly stricter.
#[test]
fn empty_headers_nonempty_witness_is_malformed_witness() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey); // reused only for a real one-signature witness
    assert_eq!(
        call(empty_attestation_root(), &[], &s.witness, &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_WITNESS
    );
}

#[test]
fn wrong_mined_root_is_root_mismatch() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey)];
    let mut wrong = s.root;
    wrong[0] ^= 0x01;
    assert_eq!(
        call(wrong, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH
    );
}

#[test]
fn forged_signature_is_countersig_invalid() {
    let (pubkey, p_id, _sk) = real_p();
    let (_other_pk, other_sk) = HybridEd25519MlDsa
        .generate_ephemeral_keypair_for_tests()
        .unwrap();
    // Signed by other_sk, claims real P: root recomputes (same sig bytes), countersig fails.
    let s = one_pass(&other_sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey)];
    assert_eq!(
        call(s.root, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_COUNTERSIG_INVALID
    );
}

#[test]
fn missing_bond_is_bond_absent() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &[])]; // empty pubkey == bond-absent marker
    assert_eq!(
        call(s.root, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BOND_ABSENT
    );
}

#[test]
fn wrong_pubkey_length_is_malformed_pubkey() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let short = vec![0u8; 10]; // neither 0 nor HYBRID_PUBKEY_CANONICAL_BYTES
    let pairs = [pair(s.p_id, &short)];
    assert_eq!(
        call(s.root, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_PUBKEY
    );
}

#[test]
fn extra_pair_is_set_mismatch() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey), pair([0xEE; 32], &s.pubkey)]; // extra pair, no pass record
    assert_eq!(
        call(s.root, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH
    );
}

#[test]
fn missing_pair_is_set_mismatch() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    assert_eq!(
        call(s.root, &s.headers, &s.witness, &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH
    );
}

#[test]
fn duplicate_pair_is_set_mismatch() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey), pair(s.p_id, &s.pubkey)]; // same p_id twice
    assert_eq!(
        call(s.root, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH
    );
}

#[test]
fn header_count_over_cap_is_cap_exceeded() {
    let big = vec![0u8; (MAX_ATTESTATION_RECORDS + 1) * ATTESTATION_HEADER_LEN];
    assert_eq!(
        call(empty_attestation_root(), &big, &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CAP_EXCEEDED
    );
}

#[test]
fn non_multiple_header_blob_is_malformed_headers() {
    let bad = vec![0u8; ATTESTATION_HEADER_LEN + 1];
    assert_eq!(
        call(empty_attestation_root(), &bad, &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_HEADERS
    );
}

#[test]
fn bad_kind_byte_is_malformed_headers() {
    let mut hdr = vec![0u8; ATTESTATION_HEADER_LEN];
    hdr[ATTESTATION_HEADER_LEN - 1] = 2; // kind neither miss(0) nor pass(1)
    assert_eq!(
        call(empty_attestation_root(), &hdr, &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_HEADERS
    );
}

#[test]
fn truncated_witness_is_malformed_witness() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey)];
    let short = &s.witness[..s.witness.len() - 1];
    assert_eq!(
        call(s.root, &s.headers, short, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_WITNESS
    );
}

#[test]
fn sig_count_not_matching_pass_headers_is_malformed_witness() {
    // One pass header, empty witness (0 sigs) → pairing count mismatch (before recompute).
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey)];
    assert_eq!(
        call(s.root, &s.headers, &[], &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_WITNESS
    );
}

/// The second (and last) deliberate divergence from the interim, and the only one that fires on
/// a shape the inherited consensus treats as valid: a coinbase `tx_extra` that fails to parse.
/// The interim never reads the extra, so it accepts such a block iff its mined root is the
/// empty root. But unreadable headers are NOT the committed empty set -- attestation-shaped
/// bytes could ride an unparseable extra outside the `attestation_root` commitment, and the
/// settlement scan later reads those same coinbase bytes, so admission-vs-settlement must not
/// disagree about them. C++ flags the parse failure (`headers_readable == 0`) and the verify
/// rejects with HEADERS_UNREADABLE -- loud failure over graceful misreading (rule 16's
/// pre-genesis inversion), pinned here so the tightening stays deliberate.
#[test]
fn unreadable_headers_is_headers_unreadable() {
    let table = window_table(HEIGHT);
    let ctx = ShekylArchivalAttestationVerifyCtx {
        attestation_root: empty_attestation_root(),
        predecessor_height: HEIGHT,
        anchor_hashes_ptr: table.as_ptr(),
        anchor_hashes_len: table.len(),
        headers_readable: 0,
        headers_ptr: std::ptr::null(),
        headers_len: 0,
        pairs_ptr: std::ptr::null(),
        pairs_len: 0,
    };
    let r = unsafe { shekyl_archival_verify_attestation(std::ptr::null(), 0, &raw const ctx) };
    assert_eq!(r, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_HEADERS_UNREADABLE);
}

#[test]
fn null_ctx_is_null_ptr() {
    let w = [0u8; 40];
    let r = unsafe { shekyl_archival_verify_attestation(w.as_ptr(), w.len(), std::ptr::null()) };
    assert_eq!(r, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR);
}

// Pins the Rust side of the verdict-code family to its literals. shekyl_ffi.h's
// SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_* #defines are hand-matched to these (rule 25); a drift
// on either side breaks its own pin. Only OK == 0 is consensus-relevant.
#[test]
fn verdict_codes_are_pinned() {
    assert_eq!(SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK, 0);
    assert_eq!(SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR, 1);
    assert_eq!(SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_WITNESS, 2);
    assert_eq!(SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_HEADERS, 3);
    assert_eq!(SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CAP_EXCEEDED, 4);
    assert_eq!(SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH, 5);
    assert_eq!(SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_COUNTERSIG_INVALID, 6);
    assert_eq!(SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BOND_ABSENT, 7);
    // 8 (CBKEY_UNREADABLE) and 12 (PREVHASH_UNPOPULATED) are RETIRED by SF-D8 — no constant,
    // numbers never reused; see the code table in attestation.rs.
    assert_eq!(
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH,
        9
    );
    assert_eq!(SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_PUBKEY, 10);
    assert_eq!(
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_HEADERS_UNREADABLE,
        11
    );
    assert_eq!(
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_ANCHOR_TABLE,
        13
    );
    assert_eq!(
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ANCHOR_OUT_OF_WINDOW,
        14
    );
    assert_eq!(
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BELOW_ANCHOR_THRESHOLD,
        15
    );
}

// ---- step 1: shekyl_archival_attestation_pass_p_ids -------------------------------------

fn hdr_bytes(p_id: [u8; 32], kind: AttestationKind) -> Vec<u8> {
    AttestationHeader {
        p_id,
        shard_id: SHARD,
        settlement_epoch: EPOCH,
        kind,
    }
    .to_canonical_bytes()
    .to_vec()
}

/// Drive step 1 over a header blob with a caller `out_cap`; returns the verdict and (on `OK`)
/// the written p_ids. `out` is physically `MAX_ATTESTATION_RECORDS` so a small `out_cap` tests
/// the buffer-bound, not the physical size.
fn pass_ids(headers: &[u8], out_cap: usize) -> (u8, Vec<[u8; 32]>) {
    let mut out = vec![[0u8; 32]; MAX_ATTESTATION_RECORDS];
    let mut n = 0usize;
    let code = unsafe {
        shekyl_archival_attestation_pass_p_ids(
            if headers.is_empty() {
                std::ptr::null()
            } else {
                headers.as_ptr()
            },
            headers.len(),
            out.as_mut_ptr(),
            out_cap,
            &raw mut n,
        )
    };
    let got = if code == SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK {
        out[..n].to_vec()
    } else {
        Vec::new()
    };
    (code, got)
}

#[test]
fn pass_ids_empty_is_ok_empty() {
    let (code, ids) = pass_ids(&[], MAX_ATTESTATION_RECORDS);
    assert_eq!(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
    assert!(ids.is_empty());
}

#[test]
fn pass_ids_excludes_miss_and_dedups() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let mut blob = hdr_bytes(a, AttestationKind::Pass);
    blob.extend(hdr_bytes(b, AttestationKind::Miss)); // miss: no bond to read
    blob.extend(hdr_bytes(a, AttestationKind::Pass)); // duplicate p_id
    let (code, ids) = pass_ids(&blob, MAX_ATTESTATION_RECORDS);
    assert_eq!(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
    assert_eq!(ids, vec![a]);
}

#[test]
fn pass_ids_returns_all_distinct_pass() {
    let a = [1u8; 32];
    let c = [3u8; 32];
    let mut blob = hdr_bytes(a, AttestationKind::Pass);
    blob.extend(hdr_bytes(c, AttestationKind::Pass));
    let (code, ids) = pass_ids(&blob, MAX_ATTESTATION_RECORDS);
    assert_eq!(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&a) && ids.contains(&c));
}

#[test]
fn pass_ids_not_multiple_is_malformed() {
    let (code, _) = pass_ids(&[0u8; ATTESTATION_HEADER_LEN + 1], MAX_ATTESTATION_RECORDS);
    assert_eq!(
        code,
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_HEADERS
    );
}

#[test]
fn pass_ids_bad_kind_byte_is_malformed() {
    let mut blob = vec![0u8; ATTESTATION_HEADER_LEN];
    blob[ATTESTATION_HEADER_LEN - 1] = 2; // kind neither miss(0) nor pass(1)
    let (code, _) = pass_ids(&blob, MAX_ATTESTATION_RECORDS);
    assert_eq!(
        code,
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_HEADERS
    );
}

#[test]
fn pass_ids_over_max_records_is_cap_exceeded() {
    let blob = vec![0u8; (MAX_ATTESTATION_RECORDS + 1) * ATTESTATION_HEADER_LEN];
    let (code, _) = pass_ids(&blob, MAX_ATTESTATION_RECORDS);
    assert_eq!(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CAP_EXCEEDED);
}

#[test]
fn pass_ids_output_too_small_is_cap_exceeded() {
    let a = [1u8; 32];
    let c = [3u8; 32];
    let mut blob = hdr_bytes(a, AttestationKind::Pass);
    blob.extend(hdr_bytes(c, AttestationKind::Pass));
    let (code, _) = pass_ids(&blob, 1); // two distinct, buffer bound of 1
    assert_eq!(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CAP_EXCEEDED);
}

#[test]
fn pass_ids_null_out_len_is_null_ptr() {
    let code = unsafe {
        shekyl_archival_attestation_pass_p_ids(
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR);
}

/// `predecessor_height == 0` with **no pass records** verifies OK. Genesis reaches this path
/// (`top_block_hash()` is `null_hash` on an empty chain, so `add_new_block` routes genesis through
/// `handle_block_to_main_chain` → `verify_block_attestation`), and block 1's predecessor height is
/// a real `0`. Below the anchor threshold no window exists, so C++ passes an empty table (what
/// `shekyl_archival_pass_anchor_window` told it) and a record-less block is fine.
#[test]
fn height_zero_with_no_records_verifies_ok() {
    assert_eq!(
        call_at_height(0, empty_attestation_root(), &[], &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK,
        "genesis (predecessor height 0, zero records) must verify; rejecting it halts the \
         chain at initialisation"
    );
}

/// The window is keyed off the predecessor height, so a valid record presented under a different
/// connecting height is refused — by the class the height difference produces. One block later
/// the anchor is still inside the window (that is what `L ≥ 2` buys an honest fetch spanning a
/// block boundary) and the same chain hash sits at that height, so it still verifies; `L + 1`
/// blocks later the anchor has aged out (`ANCHOR_OUT_OF_WINDOW`); and an unpopulated height reads
/// as `0`, below the threshold, where any pass record is `BELOW_ANCHOR_THRESHOLD` — the reason
/// v2 needs no unpopulated sentinel.
#[test]
fn predecessor_height_moves_the_window() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey)];
    for later in 1..=PASS_ANCHOR_LAG_BLOCKS.to_raw() {
        assert_eq!(
            call_at_height(HEIGHT + later, s.root, &s.headers, &s.witness, &pairs),
            SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK,
            "anchor still inside the window {later} block(s) later"
        );
    }
    assert_eq!(
        call_at_height(
            HEIGHT + PASS_ANCHOR_LAG_BLOCKS.to_raw() + 1,
            s.root,
            &s.headers,
            &s.witness,
            &pairs
        ),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ANCHOR_OUT_OF_WINDOW
    );
    assert_eq!(
        call_at_height(HEIGHT - 1, s.root, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ANCHOR_OUT_OF_WINDOW,
        "an anchor above the window (P signed for a block that did not yet exist) is refused"
    );
    assert_eq!(
        call_at_height(0, s.root, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_BELOW_ANCHOR_THRESHOLD,
        "an unpopulated height must fail closed"
    );
}

/// The chain hash the verifier reads is the connecting chain's, not the requester's claim: the
/// same record verified against a window whose hash at the anchor height differs (a fork above the
/// fork point, or a fabricated header hash) is a countersignature failure — the record carries no
/// hash, so nothing but the signature can disagree.
#[test]
fn different_chain_hash_at_anchor_is_countersig_invalid() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey)];
    let mut table = window_table(HEIGHT);
    let idx = usize::try_from(
        ANCHOR - (HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw() - PASS_ANCHOR_LAG_BLOCKS.to_raw()),
    )
    .expect("window index fits usize");
    table[idx][9] ^= 0x01;
    assert_eq!(
        call_with_table(HEIGHT, &table, s.root, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_COUNTERSIG_INVALID
    );
    // Perturbing a DIFFERENT height's hash leaves this record alone — one indexed lookup.
    let mut other = window_table(HEIGHT);
    other[0][9] ^= 0x01;
    assert_eq!(
        call_with_table(HEIGHT, &other, s.root, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
    );
}

/// The anchor table's shape is checked on EVERY block, records or not: a wrong-length table at or
/// above the threshold, or a non-empty table below it, is `MALFORMED_ANCHOR_TABLE` — the
/// marshaling-drift verdict, so a C++ that sized the table wrong is loud on its first block rather
/// than on the first block that carries a pass record.
#[test]
fn anchor_table_shape_is_checked_on_every_block() {
    let full = window_table(HEIGHT);
    assert_eq!(full.len(), PASS_ANCHOR_WINDOW_LEN);
    let short = &full[..PASS_ANCHOR_WINDOW_LEN - 1];
    assert_eq!(
        call_with_table(HEIGHT, short, empty_attestation_root(), &[], &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_ANCHOR_TABLE
    );
    let mut long = full.clone();
    long.push(chain_hash(0));
    assert_eq!(
        call_with_table(HEIGHT, &long, empty_attestation_root(), &[], &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_ANCHOR_TABLE
    );
    assert_eq!(
        call_with_table(HEIGHT, &[], empty_attestation_root(), &[], &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_ANCHOR_TABLE,
        "an empty table at a height that has a window is malformed, not 'no records'"
    );
    // Below the threshold the only right shape is empty.
    assert_eq!(
        call_with_table(
            PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT.to_raw() - 1,
            &full,
            empty_attestation_root(),
            &[],
            &[],
            &[]
        ),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_ANCHOR_TABLE
    );
    assert_eq!(
        call_with_table(
            PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT.to_raw() - 1,
            &[],
            empty_attestation_root(),
            &[],
            &[],
            &[]
        ),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
    );
}

/// Step 0's threshold, pinned at both sides through the FFI: `depth + L − 1` has no window,
/// `depth + L` has one starting at height 0 — the genesis boundary, the same 723 / 724 pair the
/// retention crate pins.
#[test]
fn anchor_window_threshold_is_pinned_at_723_and_724() {
    assert_eq!(PASS_ANCHOR_MIN_PREDECESSOR_HEIGHT.to_raw(), 724);
    let mut first = 99u64;
    let mut len = 99usize;
    let below = unsafe { shekyl_archival_pass_anchor_window(723, &raw mut first, &raw mut len) };
    assert_eq!(below, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
    assert_eq!((first, len), (0, 0));
    let at = unsafe { shekyl_archival_pass_anchor_window(724, &raw mut first, &raw mut len) };
    assert_eq!(at, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
    assert_eq!((first, len), (0, PASS_ANCHOR_WINDOW_LEN));
    let far = unsafe { shekyl_archival_pass_anchor_window(HEIGHT, &raw mut first, &raw mut len) };
    assert_eq!(far, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
    assert_eq!(
        (first, len),
        (
            HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw() - PASS_ANCHOR_LAG_BLOCKS.to_raw(),
            PASS_ANCHOR_WINDOW_LEN
        )
    );
    let null =
        unsafe { shekyl_archival_pass_anchor_window(HEIGHT, std::ptr::null_mut(), &raw mut len) };
    assert_eq!(null, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR);
}

/// The witness nonce is committed by the root (`nonce ‖ signature` per entry), so a swapped nonce
/// is a ROOT_MISMATCH before any signature is evaluated — the marshaling-drift gate fires first.
#[test]
fn tampered_witness_nonce_is_root_mismatch() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey)];
    let mut w = s.witness.clone();
    w[8] ^= 0x01; // first nonce byte, after the 8-byte count prefix
    assert_eq!(
        call(s.root, &s.headers, &w, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH
    );
}

#[test]
fn pass_ids_null_headers_nonzero_len_is_null_ptr() {
    let mut out = [[0u8; 32]; 4];
    let mut n = 0usize;
    let code = unsafe {
        shekyl_archival_attestation_pass_p_ids(
            std::ptr::null(),
            ATTESTATION_HEADER_LEN,
            out.as_mut_ptr(),
            out.len(),
            &raw mut n,
        )
    };
    assert_eq!(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_NULL_PTR);
    assert_eq!(n, 0);
}

/// The step-1/step-2 contract: the p_ids step 1 names are EXACTLY the pairs step 2 requires.
/// Build the ctx from step 1's output and step 2 must verify `OK` — the pairs-not-positional
/// coverage agreement, end to end across both FFI halves.
#[test]
fn pass_ids_feeds_step2_coverage() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let (code, ids) = pass_ids(&s.headers, MAX_ATTESTATION_RECORDS);
    assert_eq!(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
    assert_eq!(ids, vec![s.p_id]);
    let pairs: Vec<_> = ids.iter().map(|id| pair(*id, &s.pubkey)).collect();
    assert_eq!(
        call(s.root, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
    );
}

/// The deterministic SF-D8 v2 fixture, shared with `shekyl-archival-retention`'s
/// `attestation_wire_kat.rs` and the C++ cross-language test
/// (`tests/unit_tests/archival_attestation_verify.cpp`), which reads the same file. Rule-50
/// oracle tier: **self-pinned (3)** — a drift tripwire, not a KAT, hence `pinned_*` names
/// throughout. Regenerated only by the armed regenerator in
/// `shekyl-archival-retention/tests/attestation_wire_kat.rs` (rule 50 decision-log citation).
const V2_FIXTURE: &str = include_str!(
    "../../../shekyl-archival-retention/tests/fixtures/attestation_pass_countersignature_v2_pinned.json"
);

fn fixture() -> serde_json::Value {
    serde_json::from_str(V2_FIXTURE).expect("fixture parses")
}

fn fixture_hex(kat: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(kat[key].as_str().unwrap_or_else(|| panic!("{key} missing")))
        .unwrap_or_else(|_| panic!("{key} not hex"))
}

fn fixture_32(kat: &serde_json::Value, key: &str) -> [u8; 32] {
    fixture_hex(kat, key).try_into().expect("32 bytes")
}

/// The pinned vector verifies through the FFI exactly as it does through the retention crate:
/// this is the C ABI half of the cross-language pin — the same bytes the C++ test marshals through
/// the `#[repr(C)]` mirrors must reach `OK` here first.
#[test]
fn pinned_v2_fixture_verifies_through_ffi() {
    let kat = fixture();
    let headers = fixture_hex(&kat, "header_hex");
    let witness = fixture_hex(&kat, "witness_hex");
    let pubkey = fixture_hex(&kat, "hybrid_public_key_hex");
    let p_id = fixture_32(&kat, "p_id_hex");
    let root = fixture_32(&kat, "attestation_root_hex");
    let height = kat["predecessor_height"].as_u64().expect("height");
    let first = kat["anchor_window_first_height"].as_u64().expect("first");
    let table: Vec<[u8; PASS_ANCHOR_HASH_LEN]> = kat["anchor_window_hashes_hex"]
        .as_array()
        .expect("window table")
        .iter()
        .map(|v| {
            hex::decode(v.as_str().expect("hex"))
                .expect("hex")
                .try_into()
                .expect("32 bytes")
        })
        .collect();
    // The fixture's table is the one step 0 asks C++ for.
    let mut got_first = 0u64;
    let mut got_len = 0usize;
    let code =
        unsafe { shekyl_archival_pass_anchor_window(height, &raw mut got_first, &raw mut got_len) };
    assert_eq!(code, SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK);
    assert_eq!((got_first, got_len), (first, table.len()));
    assert_eq!(
        p_id,
        *p_canonical_id_from_hybrid_pubkey(&pubkey).as_bytes(),
        "fixture p_id is the fixture pubkey's canonical id"
    );
    let pairs = [pair(p_id, &pubkey)];
    assert_eq!(
        call_with_table(height, &table, root, &headers, &witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
    );
    // Every SF-D8 term is load-bearing at the FFI boundary too: the chain hash at the anchor
    // height (a fork or a fabricated header), the window (a stale anchor), and the root.
    let anchor = kat["anchor_height"].as_u64().expect("anchor");
    let mut forked = table.clone();
    forked[usize::try_from(anchor - first).expect("window index fits usize")][0] ^= 0x01;
    assert_eq!(
        call_with_table(height, &forked, root, &headers, &witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_COUNTERSIG_INVALID
    );
    let aged: Vec<_> = (0..table.len() as u64)
        .map(|i| chain_hash(first + PASS_ANCHOR_LAG_BLOCKS.to_raw() + 1 + i))
        .collect();
    assert_eq!(
        call_with_table(
            height + PASS_ANCHOR_LAG_BLOCKS.to_raw() + 1,
            &aged,
            root,
            &headers,
            &witness,
            &pairs
        ),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ANCHOR_OUT_OF_WINDOW
    );
    let mut wrong_root = root;
    wrong_root[0] ^= 0x01;
    assert_eq!(
        call_with_table(height, &table, wrong_root, &headers, &witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH
    );
}
