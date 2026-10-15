// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The derived-weight batch verify (`derived.rs`; CEN-H19, ruling R3): the
//! seed's encoding and its pin, that it commits to every byte the batch
//! equation reads, that the RNG it seeds feeds the per-proof weights and
//! nothing else, and the batch's verdicts.

use rand_core::{CryptoRng, OsRng, RngCore};

use curve25519_dalek::scalar::Scalar;

use shekyl_curve_io::CompressedPoint;
use shekyl_curve_primitives::Commitment;

use crate::{
    batch_verifier::BatchVerifier, batch_weights_seed, verify_batch, BatchEntry, Bulletproof,
    BATCH_WEIGHTS_CUSTOMIZATION,
};

/// A proof that parses and is not a proof: every field a distinct byte
/// pattern, the scalars' top byte zero so each stays reduced, seven L/R
/// rounds (the two-output layout). The seed reads bytes, never validity, so
/// fixed bytes pin it without pinning the prover.
fn synthetic_proof(tag: u8) -> Bulletproof {
    let rounds = 7u8;
    let mut bytes = Vec::new();
    for field in 0..3u8 {
        bytes.extend_from_slice(&[tag ^ (0x10 + field); 32]);
    }
    for field in 0..3u8 {
        let mut scalar = [tag ^ (0x20 + field); 32];
        scalar[31] = 0;
        bytes.extend_from_slice(&scalar);
    }
    for side in [0x40u8, 0x60] {
        bytes.push(rounds);
        for round in 0..rounds {
            bytes.extend_from_slice(&[tag ^ (side + round); 32]);
        }
    }
    let proof = Bulletproof::read_plus(&mut bytes.as_slice()).expect("the synthetic proof parses");
    assert_eq!(proof.serialize(), bytes, "the synthetic proof round-trips");
    proof
}

fn synthetic_commitments(tag: u8) -> Vec<CompressedPoint> {
    vec![
        CompressedPoint([tag ^ 0x81; 32]),
        CompressedPoint([tag ^ 0x82; 32]),
    ]
}

/// A real two-output proof and its commitments.
fn real_entry() -> (Bulletproof, Vec<CompressedPoint>) {
    let openings = (0..2)
        .map(|_| Commitment::new(Scalar::random(&mut OsRng), OsRng.next_u64()))
        .collect::<Vec<_>>();
    let proof = Bulletproof::prove_plus(&mut OsRng, openings.clone()).expect("proves");
    let commitments = openings
        .iter()
        .map(|c| CompressedPoint::from(c.calculate().compress()))
        .collect();
    (proof, commitments)
}

/// A proof that parses, is sane, and fails its equation: bit 0 of `r1`'s
/// low byte flipped (offset 96, after `A ‖ A1 ‖ B`). Every point still
/// decompresses and the scalar stays reduced, so the batch accumulates it
/// and the multiscalar multiplication is what refuses.
fn broken(proof: &Bulletproof) -> Bulletproof {
    let mut bytes = proof.serialize();
    bytes[96] ^= 1;
    Bulletproof::read_plus(&mut bytes.as_slice()).expect("a low-bit flip stays reduced")
}

/// The determinism KAT: the seed of a fixed two-entry batch — a block's two
/// transactions — pinned, and equal to the documented preimage hashed by
/// hand. The hand-built preimage holds the encoding to its doc; the hex holds
/// both to the bytes a node computed when this landed.
#[test]
fn the_seed_of_a_fixed_batch_is_pinned() {
    let proofs = [synthetic_proof(0x00), synthetic_proof(0xA5)];
    let commitments = [synthetic_commitments(0x00), synthetic_commitments(0xA5)];
    let batch = [
        BatchEntry {
            proof: &proofs[0],
            commitments: &commitments[0],
        },
        BatchEntry {
            proof: &proofs[1],
            commitments: &commitments[1],
        },
    ];

    let mut preimage = 2u32.to_le_bytes().to_vec();
    for (proof, commitments) in proofs.iter().zip(&commitments) {
        let bytes = proof.serialize();
        preimage.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
        preimage.extend_from_slice(&bytes);
        preimage.extend_from_slice(&2u32.to_le_bytes());
        for commitment in commitments {
            preimage.extend_from_slice(&commitment.0);
        }
    }
    let seed = batch_weights_seed(&batch);
    assert_eq!(
        seed,
        shekyl_crypto_hash::cshake256_32(BATCH_WEIGHTS_CUSTOMIZATION, &preimage),
        "the seed is cSHAKE256 over the documented preimage"
    );
    assert_eq!(
        seed,
        hex_literal::hex!("e2c81e104a62bb61838fffff3d5a9a8f12203160c1d59307ed06a29598c099d9"),
        "the seed's bytes moved: a preimage change is a new domain (-v2), not a re-pin"
    );
    assert_eq!(
        batch_weights_seed(&[]),
        hex_literal::hex!("a19ca46f3a99b35cb504d7bc1a983af5e98199e77b6fc1e38d4873b42fb78c7e"),
        "the empty batch's seed"
    );
}

/// The seed commits to every proof byte: each bit-0 flip that still parses
/// moves it, and the only flips that do not parse are the two L/R length
/// varints' — asserted, so the test cannot pass by skipping. (`L`'s length
/// flipped to six misaligns the rest; `R`'s flipped to six parses, leaving a
/// round unread, and still moves the seed, because the seed reads the
/// re-serialized proof.)
#[test]
fn every_proof_byte_moves_the_seed() {
    let proof = synthetic_proof(0x3C);
    let commitments = synthetic_commitments(0x3C);
    let baseline = batch_weights_seed(&[BatchEntry {
        proof: &proof,
        commitments: &commitments,
    }]);
    let bytes = proof.serialize();
    let lengths = [6 * 32, 6 * 32 + 1 + 7 * 32];
    for at in 0..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[at] ^= 1;
        let Ok(moved) = Bulletproof::read_plus(&mut flipped.as_slice()) else {
            assert!(
                lengths.contains(&at),
                "proof byte {at} flipped does not parse"
            );
            continue;
        };
        assert_ne!(
            batch_weights_seed(&[BatchEntry {
                proof: &moved,
                commitments: &commitments,
            }]),
            baseline,
            "proof byte {at} is not committed to"
        );
    }
}

/// The seed commits to every commitment byte, in every position.
#[test]
fn every_commitment_byte_moves_the_seed() {
    let proof = synthetic_proof(0x5A);
    let commitments = synthetic_commitments(0x5A);
    let baseline = batch_weights_seed(&[BatchEntry {
        proof: &proof,
        commitments: &commitments,
    }]);
    for which in 0..commitments.len() {
        for at in 0..32 {
            let mut moved = commitments.clone();
            moved[which].0[at] ^= 1;
            assert_ne!(
                batch_weights_seed(&[BatchEntry {
                    proof: &proof,
                    commitments: &moved,
                }]),
                baseline,
                "commitment {which} byte {at} is not committed to"
            );
        }
    }
}

/// Batch order is committed to: the same two entries swapped are another
/// seed (the fold passes block order — transaction order, then proof order).
#[test]
fn batch_order_moves_the_seed() {
    let proofs = [synthetic_proof(0x01), synthetic_proof(0x02)];
    let commitments = [synthetic_commitments(0x01), synthetic_commitments(0x02)];
    let entry = |i: usize| BatchEntry {
        proof: &proofs[i],
        commitments: &commitments[i],
    };
    assert_ne!(
        batch_weights_seed(&[entry(0), entry(1)]),
        batch_weights_seed(&[entry(1), entry(0)])
    );
}

/// Counts the bytes drawn from the RNG it wraps.
struct Counting<R> {
    inner: R,
    drawn: usize,
}

impl<R: RngCore> RngCore for Counting<R> {
    fn next_u32(&mut self) -> u32 {
        self.drawn += 4;
        self.inner.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.drawn += 8;
        self.inner.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.drawn += dest.len();
        self.inner.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.drawn += dest.len();
        self.inner.try_fill_bytes(dest)
    }
}

impl<R: CryptoRng> CryptoRng for Counting<R> {}

/// R3's premise, held: the verify path draws exactly one weight per proof
/// (`Scalar::random`, 64 bytes, `plus/weighted_inner_product.rs`) and reads
/// the RNG for nothing else — for a valid proof and for a broken one, whose
/// weight is drawn before its sanity checks so draw `k` is proof `k`'s.
#[test]
fn the_rng_feeds_one_weight_per_proof_and_nothing_else() {
    let (good, commitments) = real_entry();
    let bad = broken(&good);
    let mut rng = Counting {
        inner: OsRng,
        drawn: 0,
    };
    let mut verifier = BatchVerifier::new();
    for (k, proof) in [&good, &bad, &good].into_iter().enumerate() {
        assert!(proof.batch_verify(&mut rng, &mut verifier, &commitments));
        assert_eq!(rng.drawn, 64 * (k + 1), "proof {k} drew one 64-byte weight");
    }
}

/// The verdicts: valid proofs pass alone and together, an empty batch
/// passes, and one broken proof among valid ones fails the batch while each
/// valid proof still passes as a batch of one — the locus search's premise.
#[test]
fn one_broken_proof_fails_the_batch_and_only_itself_alone() {
    let entries = (0..3).map(|_| real_entry()).collect::<Vec<_>>();
    let bad = broken(&entries[1].0);
    fn batch<'a>(
        proofs: [&'a Bulletproof; 3],
        entries: &'a [(Bulletproof, Vec<CompressedPoint>)],
    ) -> Vec<BatchEntry<'a>> {
        proofs
            .into_iter()
            .zip(entries)
            .map(|(proof, (_, commitments))| BatchEntry { proof, commitments })
            .collect()
    }

    assert!(verify_batch(&[]), "the empty batch");
    let good = batch([&entries[0].0, &entries[1].0, &entries[2].0], &entries);
    assert!(verify_batch(&good), "three valid proofs");
    for entry in &good {
        assert!(verify_batch(core::slice::from_ref(entry)), "each alone");
    }

    let mixed = batch([&entries[0].0, &bad, &entries[2].0], &entries);
    assert!(!verify_batch(&mixed), "one broken proof fails the batch");
    let alone: Vec<bool> = mixed
        .iter()
        .map(|entry| verify_batch(core::slice::from_ref(entry)))
        .collect();
    assert_eq!(alone, [true, false, true], "and only it fails alone");
}

/// A proof that is not sane — a point that does not decompress — fails the
/// batch before the multiscalar multiplication, and fails alone.
#[test]
fn an_insane_proof_fails_the_batch_and_alone() {
    let (good, commitments) = real_entry();
    let mut bytes = good.serialize();
    // `A`'s y-coordinate set to 2: no point on the curve has it.
    bytes[..32].copy_from_slice(&{
        let mut y = [0u8; 32];
        y[0] = 2;
        y
    });
    let insane = Bulletproof::read_plus(&mut bytes.as_slice()).expect("points are read raw");
    assert!(CompressedPoint(bytes[..32].try_into().unwrap())
        .decompress()
        .is_none());
    let entry = |proof| BatchEntry {
        proof,
        commitments: &commitments,
    };
    assert!(!verify_batch(&[entry(&good), entry(&insane)]));
    assert!(!verify_batch(&[entry(&insane)]));
    assert!(verify_batch(&[entry(&good)]));
}
