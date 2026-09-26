// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use crate::attestation::AttestationKind;
use crate::id::p_canonical_id_from_hybrid_pubkey;
use crate::pass_anchor::{
    pass_countersignature_message, PassAnchorWindow, PASS_ANCHOR_HEIGHT_LEN,
    PASS_ANCHOR_LAG_BLOCKS, PASS_ANCHOR_WINDOW_LEN, PASS_NONCE_LEN,
};
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, HybridSignature, SignatureScheme,
};
use shekyl_types::BlockHeight;

const H: u64 = 5000;

fn bh(n: u64) -> BlockHeight {
    BlockHeight::from_raw(n)
}

fn keypair() -> (HybridPublicKey, HybridSecretKey) {
    HybridEd25519MlDsa
        .generate_ephemeral_keypair_for_tests()
        .expect("keypair generates")
}

fn att_sign(sk: &HybridSecretKey, msg: &[u8]) -> HybridSignature {
    HybridEd25519MlDsa
        .sign(
            sk,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION,
            msg,
        )
        .expect("attestation sign")
}

fn p_id_of(pubkey: &HybridPublicKey) -> [u8; 32] {
    let bytes = pubkey.to_canonical_bytes().expect("canonical pubkey");
    *p_canonical_id_from_hybrid_pubkey(&bytes).as_bytes()
}

fn chain_hash(height: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&height.to_le_bytes());
    h[8] = 0xC4;
    h
}

fn window_at(predecessor_height: u64) -> PassAnchorWindow {
    let pred = bh(predecessor_height);
    let (first, len) = PassAnchorWindow::shape_for_predecessor(pred).expect("window");
    let hashes: Vec<_> = (0..len as u64)
        .map(|i| chain_hash(first.to_raw() + i))
        .collect();
    PassAnchorWindow::from_table(pred, &hashes).expect("table sized to the window")
}

fn pass_record(
    p_id: [u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
    nonce: [u8; PASS_NONCE_LEN],
    anchor_height: BlockHeight,
    signature: HybridSignature,
) -> PassRecord {
    PassRecord {
        p_id,
        shard_id,
        settlement_epoch,
        nonce,
        anchor_height,
        signature,
    }
}

fn signed_pass(
    sk: &HybridSecretKey,
    p_id: [u8; 32],
    nonce: [u8; PASS_NONCE_LEN],
    anchor_height: BlockHeight,
    shard_id: u64,
    settlement_epoch: u64,
) -> PassRecord {
    let sig = att_sign(
        sk,
        &pass_countersignature_message(
            &nonce,
            anchor_height,
            &chain_hash(anchor_height.to_raw()),
            shard_id,
        ),
    );
    pass_record(p_id, shard_id, settlement_epoch, nonce, anchor_height, sig)
}

#[test]
fn header_bytes_roundtrip_and_reject_malformed() {
    for kind in [AttestationKind::Pass, AttestationKind::Miss] {
        let h = AttestationHeader {
            p_id: [7u8; 32],
            shard_id: 42,
            settlement_epoch: 1000,
            kind,
        };
        let bytes = h.to_canonical_bytes();
        assert_eq!(bytes.len(), ATTESTATION_HEADER_LEN);
        assert_eq!(AttestationHeader::from_canonical_bytes(&bytes), Ok(h));
    }
    assert_eq!(
        AttestationHeader::from_canonical_bytes(&[0u8; 10]),
        Err(AttestationHeaderError::WrongLength(10))
    );
    let mut bad = AttestationHeader {
        p_id: [7u8; 32],
        shard_id: 42,
        settlement_epoch: 1000,
        kind: AttestationKind::Pass,
    }
    .to_canonical_bytes();
    bad[48] = 2;
    assert_eq!(
        AttestationHeader::from_canonical_bytes(&bad),
        Err(AttestationHeaderError::BadKind(2))
    );
}

#[test]
fn pass_record_to_header_is_always_pass() {
    let (_pk, sk) = keypair();
    let sig = att_sign(&sk, b"x");
    let rec = pass_record([1u8; 32], 2, 3, [0u8; 32], bh(4), sig);
    assert_eq!(rec.to_header().kind, AttestationKind::Pass);
}

#[test]
fn pass_record_message_matches_free_function() {
    let (_pk, sk) = keypair();
    let sig = att_sign(&sk, b"n");
    let rec = pass_record([3u8; 32], 4, 5, [9u8; 32], bh(77), sig);
    let hash = [0xDDu8; 32];
    assert_eq!(
        rec.countersignature_message(&hash),
        pass_countersignature_message(&rec.nonce, bh(77), &hash, rec.shard_id)
    );
}

#[test]
fn a_valid_countersignature_verifies_and_a_wrong_key_or_term_fails() {
    let (pubkey, secret) = keypair();
    let p_id = p_id_of(&pubkey);
    let nonce = [0x11u8; 32];
    let anchor = H - 720;
    let rec = signed_pass(&secret, p_id, nonce, bh(anchor), 42, 1000);
    let w = window_at(H);

    assert_eq!(verify_pass_countersignature(&w, &pubkey, &rec), Ok(()));

    let mut other = rec.clone();
    other.shard_id = 43;
    assert_eq!(
        verify_pass_countersignature(&w, &pubkey, &other),
        Err(PassCountersignatureError::InvalidSignature)
    );
    let mut swapped_nonce = rec.clone();
    swapped_nonce.nonce = [0x22u8; 32];
    assert_eq!(
        verify_pass_countersignature(&w, &pubkey, &swapped_nonce),
        Err(PassCountersignatureError::InvalidSignature)
    );
    let mut moved_anchor = rec.clone();
    moved_anchor.anchor_height = bh(anchor - 1);
    assert_eq!(
        verify_pass_countersignature(&w, &pubkey, &moved_anchor),
        Err(PassCountersignatureError::InvalidSignature)
    );
    let mut other_epoch = rec.clone();
    other_epoch.settlement_epoch = 1001;
    assert_eq!(
        verify_pass_countersignature(&w, &pubkey, &other_epoch),
        Ok(())
    );

    let foreign = signed_pass(&secret, [0xABu8; 32], nonce, bh(anchor), 42, 1000);
    assert_eq!(
        verify_pass_countersignature(&w, &pubkey, &foreign),
        Err(PassCountersignatureError::PIdMismatch)
    );
}

#[test]
fn a_fabricated_anchor_hash_fails_against_the_chains_hash() {
    let (pubkey, secret) = keypair();
    let p_id = p_id_of(&pubkey);
    let anchor = H - 722;
    let lied = att_sign(
        &secret,
        &pass_countersignature_message(&[0x55u8; 32], bh(anchor), &[0xFFu8; 32], 42),
    );
    let rec = pass_record(p_id, 42, 1000, [0x55u8; 32], bh(anchor), lied);
    assert_eq!(
        verify_pass_countersignature(&window_at(H), &pubkey, &rec),
        Err(PassCountersignatureError::InvalidSignature)
    );
}

#[test]
fn anchor_window_bounds_are_inclusive_and_out_of_window_is_typed() {
    let (pubkey, secret) = keypair();
    let p_id = p_id_of(&pubkey);
    let w = window_at(H);

    for anchor in [w.first(), w.last()] {
        let rec = signed_pass(&secret, p_id, [0x66u8; 32], anchor, 7, 1000);
        assert_eq!(verify_pass_countersignature(&w, &pubkey, &rec), Ok(()));
    }
    for anchor in [bh(w.first().to_raw() - 1), bh(w.last().to_raw() + 1)] {
        let rec = signed_pass(&secret, p_id, [0x66u8; 32], anchor, 7, 1000);
        assert_eq!(
            verify_pass_countersignature(&w, &pubkey, &rec),
            Err(PassCountersignatureError::AnchorOutOfWindow {
                anchor_height: anchor,
                first: w.first(),
                last: w.last(),
            })
        );
    }

    let anchor = H - 720;
    let rec = signed_pass(&secret, p_id, [0x77u8; 32], bh(anchor), 7, 1000);
    for h in H..=H + PASS_ANCHOR_LAG_BLOCKS.to_raw() {
        assert_eq!(
            verify_pass_countersignature(&window_at(h), &pubkey, &rec),
            Ok(()),
            "anchor {anchor} must verify at predecessor {h}"
        );
    }
    assert!(matches!(
        verify_pass_countersignature(&window_at(H - 1), &pubkey, &rec),
        Err(PassCountersignatureError::AnchorOutOfWindow { .. })
    ));
    assert!(matches!(
        verify_pass_countersignature(
            &window_at(H + PASS_ANCHOR_LAG_BLOCKS.to_raw() + 1),
            &pubkey,
            &rec
        ),
        Err(PassCountersignatureError::AnchorOutOfWindow { .. })
    ));
}

#[test]
fn a_signature_over_one_shard_cannot_be_replayed_against_another() {
    let (pubkey, secret) = keypair();
    let p_id = p_id_of(&pubkey);
    let nonce = [0x33u8; 32];
    let anchor = H - 721;
    let served = signed_pass(&secret, p_id, nonce, bh(anchor), 42, 1000);
    let replayed = pass_record(p_id, 43, 1000, nonce, bh(anchor), served.signature.clone());
    let w = window_at(H);
    assert_eq!(verify_pass_countersignature(&w, &pubkey, &served), Ok(()));
    assert_eq!(
        verify_pass_countersignature(&w, &pubkey, &replayed),
        Err(PassCountersignatureError::InvalidSignature)
    );
}

#[test]
fn v1_domain_signature_does_not_verify_under_v2() {
    let (pubkey, secret) = keypair();
    let p_id = p_id_of(&pubkey);
    let nonce = [0x44u8; 32];
    let anchor = H - 720;
    let msg = pass_countersignature_message(&nonce, bh(anchor), &chain_hash(anchor), 42);
    let v1_sig = HybridEd25519MlDsa
        .sign(&secret, b"shekyl/archival-attestation-scheme-v1", &msg)
        .expect("sign");
    let rec = pass_record(p_id, 42, 1000, nonce, bh(anchor), v1_sig);
    assert_eq!(
        verify_pass_countersignature(&window_at(H), &pubkey, &rec),
        Err(PassCountersignatureError::InvalidSignature)
    );
    assert_eq!(
        shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION,
        b"shekyl/archival-attestation-scheme-v2"
    );
}

#[test]
fn attestation_root_is_defined_empty_order_independent_and_pairing_committed() {
    let empty = attestation_root(&[]).unwrap();
    assert_eq!(empty, attestation_root(&[]).unwrap());

    let (_pk, sk) = keypair();
    let s1 = att_sign(&sk, b"a");
    let s2 = att_sign(&sk, b"b");
    let (n1, n2) = ([1u8; 32], [2u8; 32]);
    let (a1, a2) = (bh(4276), bh(4277));
    let r1 = pass_record([7u8; 32], 42, 1000, n1, a1, s1.clone());
    let r2 = pass_record([7u8; 32], 43, 1000, n2, a2, s2.clone());

    assert_ne!(attestation_root(std::slice::from_ref(&r1)).unwrap(), empty);

    let ab = attestation_root(&[r1.clone(), r2.clone()]).unwrap();
    let ba = attestation_root(&[r2.clone(), r1.clone()]).unwrap();
    assert_eq!(ab, ba);

    let swapped = attestation_root(&[
        pass_record(
            r1.p_id,
            r1.shard_id,
            r1.settlement_epoch,
            n1,
            a1,
            s2.clone(),
        ),
        pass_record(
            r2.p_id,
            r2.shard_id,
            r2.settlement_epoch,
            n2,
            a2,
            s1.clone(),
        ),
    ])
    .unwrap();
    assert_ne!(ab, swapped);

    let nonce_swapped = attestation_root(&[
        pass_record(
            r1.p_id,
            r1.shard_id,
            r1.settlement_epoch,
            n2,
            a1,
            s1.clone(),
        ),
        pass_record(
            r2.p_id,
            r2.shard_id,
            r2.settlement_epoch,
            n1,
            a2,
            s2.clone(),
        ),
    ])
    .unwrap();
    assert_ne!(ab, nonce_swapped);

    let anchor_swapped = attestation_root(&[
        pass_record(r1.p_id, r1.shard_id, r1.settlement_epoch, n1, a2, s1),
        pass_record(r2.p_id, r2.shard_id, r2.settlement_epoch, n2, a1, s2),
    ])
    .unwrap();
    assert_ne!(ab, anchor_swapped);
}

#[test]
fn witness_roundtrips_including_empty() {
    let (_pk, sk) = keypair();
    let s0 = att_sign(&sk, b"w0");
    let s1 = att_sign(&sk, b"w1");
    let w = BlockAttestationWitness {
        passes: vec![
            PassWitness {
                nonce: [5u8; 32],
                anchor_height: bh(0x0102_0304_0506_0708),
                signature: s0,
            },
            PassWitness {
                nonce: [6u8; 32],
                anchor_height: bh(4277),
                signature: s1,
            },
        ],
    };
    let bytes = w.to_canonical_bytes().unwrap();
    assert_eq!(bytes.len(), WITNESS_PREFIX_LEN + 2 * WITNESS_ENTRY_LEN);
    assert_eq!(&bytes[0..WITNESS_PREFIX_LEN], &2u64.to_le_bytes());
    assert_eq!(
        &bytes[WITNESS_PREFIX_LEN..WITNESS_PREFIX_LEN + PASS_NONCE_LEN],
        &[5u8; 32]
    );
    assert_eq!(
        &bytes[WITNESS_PREFIX_LEN + PASS_NONCE_LEN..WITNESS_PREFIX_LEN + PASS_NONCE_LEN + 8],
        &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
    );
    assert_eq!(
        BlockAttestationWitness::from_canonical_bytes(&bytes).unwrap(),
        w
    );

    let empty = BlockAttestationWitness { passes: vec![] };
    let eb = empty.to_canonical_bytes().unwrap();
    assert_eq!(eb.len(), WITNESS_PREFIX_LEN);
    assert_eq!(
        BlockAttestationWitness::from_canonical_bytes(&eb).unwrap(),
        empty
    );
}

#[test]
fn witness_decode_rejects_malformed() {
    let (_pk, sk) = keypair();
    let s0 = att_sign(&sk, b"w");
    let good = BlockAttestationWitness {
        passes: vec![PassWitness {
            nonce: [0u8; 32],
            anchor_height: bh(1),
            signature: s0,
        }],
    }
    .to_canonical_bytes()
    .unwrap();
    const SIG_START: usize = WITNESS_PREFIX_LEN + PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN;

    assert!(matches!(
        BlockAttestationWitness::from_canonical_bytes(&[0u8; WITNESS_PREFIX_LEN - 1]),
        Err(WitnessError::TooShort(n)) if n == WITNESS_PREFIX_LEN - 1
    ));

    let mut short_body = Vec::new();
    short_body.extend_from_slice(&1u64.to_le_bytes());
    assert!(matches!(
        BlockAttestationWitness::from_canonical_bytes(&short_body),
        Err(WitnessError::LengthMismatch {
            count: 1,
            got: WITNESS_PREFIX_LEN,
            ..
        })
    ));

    for skip in [
        PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN,
        PASS_ANCHOR_HEIGHT_LEN,
    ] {
        let mut stale = Vec::new();
        stale.extend_from_slice(&1u64.to_le_bytes());
        stale.extend_from_slice(&good[WITNESS_PREFIX_LEN + skip..]);
        assert!(matches!(
            BlockAttestationWitness::from_canonical_bytes(&stale),
            Err(WitnessError::LengthMismatch { count: 1, .. })
        ));
    }

    let mut over = Vec::new();
    over.extend_from_slice(&((MAX_ATTESTATION_RECORDS as u64) + 1).to_le_bytes());
    assert!(matches!(
        BlockAttestationWitness::from_canonical_bytes(&over),
        Err(WitnessError::CountExceedsCap(n)) if n == MAX_ATTESTATION_RECORDS as u64 + 1
    ));

    let mut corrupt = good.clone();
    corrupt[SIG_START] ^= 0xFF;
    assert!(matches!(
        BlockAttestationWitness::from_canonical_bytes(&corrupt),
        Err(WitnessError::Signature { index: 0, .. })
    ));
}

#[test]
fn witness_encode_rejects_over_cap() {
    let (_pk, sk) = keypair();
    let sig = att_sign(&sk, b"x");
    let over = BlockAttestationWitness {
        passes: vec![
            PassWitness {
                nonce: [0u8; 32],
                anchor_height: bh(0),
                signature: sig,
            };
            MAX_ATTESTATION_RECORDS + 1
        ],
    };
    assert!(matches!(
        over.to_canonical_bytes(),
        Err(WitnessError::CountExceedsCap(n)) if n == (MAX_ATTESTATION_RECORDS as u64) + 1
    ));
}

#[test]
fn pairing_zips_pass_headers_and_reproduces_the_root() {
    let (pk, sk) = keypair();
    let p_id = p_id_of(&pk);
    let w = window_at(H);
    let (n_a, n_b) = ([0xA0u8; 32], [0xB0u8; 32]);
    let (a_a, a_b) = (H - 720, H - 723);
    let rec_a = signed_pass(&sk, p_id, n_a, bh(a_a), 10, 1000);
    let rec_b = signed_pass(&sk, p_id, n_b, bh(a_b), 20, 1000);

    let headers = vec![
        AttestationHeader {
            p_id,
            shard_id: 10,
            settlement_epoch: 1000,
            kind: AttestationKind::Pass,
        },
        AttestationHeader {
            p_id,
            shard_id: 99,
            settlement_epoch: 1000,
            kind: AttestationKind::Miss,
        },
        AttestationHeader {
            p_id,
            shard_id: 20,
            settlement_epoch: 1000,
            kind: AttestationKind::Pass,
        },
    ];
    let entry = |r: &PassRecord| PassWitness {
        nonce: r.nonce,
        anchor_height: r.anchor_height,
        signature: r.signature.clone(),
    };
    let witness = BlockAttestationWitness {
        passes: vec![entry(&rec_a), entry(&rec_b)],
    };

    let records = pass_records_from_headers_and_witness(&headers, &witness).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!((records[0].nonce, records[0].anchor_height), (n_a, bh(a_a)));
    assert_eq!((records[1].nonce, records[1].anchor_height), (n_b, bh(a_b)));
    for rec in &records {
        assert_eq!(verify_pass_countersignature(&w, &pk, rec), Ok(()));
    }
    let direct = attestation_root(&[rec_a.clone(), rec_b.clone()]).unwrap();
    assert_eq!(attestation_root(&records).unwrap(), direct);

    let short_witness = BlockAttestationWitness {
        passes: vec![entry(&rec_a)],
    };
    assert_eq!(
        pass_records_from_headers_and_witness(&headers, &short_witness).unwrap_err(),
        WitnessPairingError {
            pass_headers: 2,
            signatures: 1
        }
    );

    let swapped_witness = BlockAttestationWitness {
        passes: vec![entry(&rec_b), entry(&rec_a)],
    };
    let swapped = pass_records_from_headers_and_witness(&headers, &swapped_witness).unwrap();
    assert_ne!(attestation_root(&swapped).unwrap(), direct);
    assert!(swapped
        .iter()
        .all(|rec| verify_pass_countersignature(&w, &pk, rec).is_err()));
}

#[test]
fn window_len_matches_type() {
    assert_eq!(PASS_ANCHOR_WINDOW_LEN, 5);
}
