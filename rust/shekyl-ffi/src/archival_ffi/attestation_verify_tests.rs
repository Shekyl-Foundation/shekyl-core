// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Attestation-admission FFI pins (extracted from the former monofile).

use super::*;
use shekyl_archival_retention::{
    attestation_nonce, attestation_root, empty_attestation_root, p_canonical_id_from_hybrid_pubkey,
    AttestationHeader, AttestationKind, BlockAttestationWitness, PassRecord,
    ATTESTATION_HEADER_LEN, MAX_ATTESTATION_RECORDS,
};
use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, HybridSecretKey, SignatureScheme};

const SHARD: u64 = 42;
const EPOCH: u64 = 1000;
const R: [u8; 32] = [7u8; 32];
const CB: [u8; 32] = [9u8; 32];

struct Scenario {
    witness: Vec<u8>,
    headers: Vec<u8>,
    pubkey: Vec<u8>,
    p_id: [u8; 32],
    root: [u8; 32],
}

fn real_p() -> (Vec<u8>, [u8; 32], HybridSecretKey) {
    let (pk, sk) = HybridEd25519MlDsa.keypair_generate().expect("keypair");
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
    let nonce = attestation_nonce(&R, &CB, &claimed_p_id, SHARD, EPOCH);
    let sig = HybridEd25519MlDsa.sign(signing_sk, &nonce).expect("sign");
    let record = PassRecord {
        p_id: claimed_p_id,
        shard_id: SHARD,
        settlement_epoch: EPOCH,
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
            r: R,
            pass_signatures: vec![sig],
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
fn call(
    root: [u8; 32],
    cb_readable: u8,
    headers: &[u8],
    witness: &[u8],
    pairs: &[ShekylArchivalPidPubkey],
) -> u8 {
    let ctx = ShekylArchivalAttestationVerifyCtx {
        attestation_root: root,
        cb_out_key: CB,
        cb_out_key_readable: cb_readable,
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
        call(s.root, 1, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
    );
}

#[test]
fn empty_block_verifies_against_empty_root() {
    // No headers, empty witness, no pairs — the pre-cutover state, reproduced.
    assert_eq!(
        call(empty_attestation_root(), 1, &[], &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
    );
}

/// The reject half of interim-equivalence. The interim `check_attestation_root` rejects a block
/// whose mined `attestation_root != empty_attestation_root()`. Over the empty (pre-cutover)
/// block shape the new verify recomputes `attestation_root(&[]) == empty_attestation_root()`
/// (identical by construction) and must reject a non-empty mined root the same way. With the
/// accept case above, this reproduces the interim EXACTLY on the empty shape — the claim that
/// licenses deleting it (distinct from the populated KAT that licenses the verify).
#[test]
fn empty_block_nonempty_root_is_root_mismatch() {
    let mut wrong = empty_attestation_root();
    wrong[0] ^= 0x01;
    assert_eq!(
        call(wrong, 1, &[], &[], &[]),
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
        call(empty_attestation_root(), 1, &[], &s.witness, &[]),
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
        call(wrong, 1, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_ROOT_MISMATCH
    );
}

#[test]
fn forged_signature_is_countersig_invalid() {
    let (pubkey, p_id, _sk) = real_p();
    let (_other_pk, other_sk) = HybridEd25519MlDsa.keypair_generate().unwrap();
    // Signed by other_sk, claims real P: root recomputes (same sig bytes), countersig fails.
    let s = one_pass(&other_sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey)];
    assert_eq!(
        call(s.root, 1, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_COUNTERSIG_INVALID
    );
}

#[test]
fn missing_bond_is_bond_absent() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &[])]; // empty pubkey == bond-absent marker
    assert_eq!(
        call(s.root, 1, &s.headers, &s.witness, &pairs),
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
        call(s.root, 1, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_PUBKEY
    );
}

#[test]
fn extra_pair_is_set_mismatch() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey), pair([0xEE; 32], &s.pubkey)]; // extra pair, no pass record
    assert_eq!(
        call(s.root, 1, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH
    );
}

#[test]
fn missing_pair_is_set_mismatch() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    assert_eq!(
        call(s.root, 1, &s.headers, &s.witness, &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH
    );
}

#[test]
fn duplicate_pair_is_set_mismatch() {
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    let pairs = [pair(s.p_id, &s.pubkey), pair(s.p_id, &s.pubkey)]; // same p_id twice
    assert_eq!(
        call(s.root, 1, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH
    );
}

#[test]
fn header_count_over_cap_is_cap_exceeded() {
    let big = vec![0u8; (MAX_ATTESTATION_RECORDS + 1) * ATTESTATION_HEADER_LEN];
    assert_eq!(
        call(empty_attestation_root(), 1, &big, &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CAP_EXCEEDED
    );
}

#[test]
fn non_multiple_header_blob_is_malformed_headers() {
    let bad = vec![0u8; ATTESTATION_HEADER_LEN + 1];
    assert_eq!(
        call(empty_attestation_root(), 1, &bad, &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_HEADERS
    );
}

#[test]
fn bad_kind_byte_is_malformed_headers() {
    let mut hdr = vec![0u8; ATTESTATION_HEADER_LEN];
    hdr[ATTESTATION_HEADER_LEN - 1] = 2; // kind neither miss(0) nor pass(1)
    assert_eq!(
        call(empty_attestation_root(), 1, &hdr, &[], &[]),
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
        call(s.root, 1, &s.headers, short, &pairs),
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
        call(s.root, 1, &s.headers, &[], &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_WITNESS
    );
}

/// The second deliberate divergence from the interim, on the same empty shape. The
/// interim never reads the coinbase, so it accepts an empty-root block whose `vout[0]` is
/// unreadable and leaves the rejection to `prevalidate_miner_transaction`; the verify checks the
/// C++-supplied cb-key-readable flag up front and rejects with CBKEY_UNREADABLE. Like the witness
/// divergence this only fires on an already-invalid block (a valid coinbase always has a readable
/// key `vout[0]`), so no valid block's verdict changes -- the verify is merely strictly stricter,
/// failing fast where the interim deferred.
#[test]
fn unreadable_coinbase_key_is_cbkey_unreadable() {
    assert_eq!(
        call(empty_attestation_root(), 0, &[], &[], &[]),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CBKEY_UNREADABLE
    );
}

/// The third (and last) deliberate divergence from the interim, and the only one that fires on
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
    let ctx = ShekylArchivalAttestationVerifyCtx {
        attestation_root: empty_attestation_root(),
        cb_out_key: CB,
        cb_out_key_readable: 1,
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
    assert_eq!(SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_CBKEY_UNREADABLE, 8);
    assert_eq!(
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_PUBKEY_SET_MISMATCH,
        9
    );
    assert_eq!(SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_MALFORMED_PUBKEY, 10);
    assert_eq!(
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_ERR_HEADERS_UNREADABLE,
        11
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
        call(s.root, 1, &s.headers, &s.witness, &pairs),
        SHEKYL_ARCHIVAL_ATTESTATION_VERIFY_OK
    );
}

/// Emits a frozen valid one-pass vector for the cross-language C++ KAT
/// (tests/unit_tests/archival_attestation_verify.cpp), which feeds these exact bytes back through
/// the C-side structs and asserts the same verdicts — the check that the C++ `#[repr(C)]` mirrors
/// marshal identically to the Rust definitions. `#[ignore]`d because it asserts nothing; it is a
/// generator. The C++ vectors are a captured snapshot (the keypair is random); regenerate and
/// re-paste only if the genesis-frozen wire format changes:
///   cargo test -p shekyl-ffi emit_attestation_verify_kat -- --ignored --nocapture
#[test]
#[ignore]
fn emit_attestation_verify_kat() {
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    let (pubkey, p_id, sk) = real_p();
    let s = one_pass(&sk, p_id, pubkey);
    println!("KAT head* = {}", hex(&s.headers));
    println!("KAT witn* = {}", hex(&s.witness));
    println!("KAT pubk* = {}", hex(&s.pubkey));
    println!("KAT p_id* = {}", hex(&s.p_id));
    println!("KAT root* = {}", hex(&s.root));
    println!("KAT cbky* = {}", hex(&CB));
}
