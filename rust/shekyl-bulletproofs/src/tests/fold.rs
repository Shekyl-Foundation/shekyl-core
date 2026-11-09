// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The verifier adds `Â`'s terms into the batch instead of evaluating `Â`
//! (`AggregateRangeStatement::A_hat_terms`). This holds the folded verifier
//! to the eager one it replaced (`verify_eager`, test-only), verdict for
//! verdict, on valid batches and on tampered ones.
//!
//! The adversary is a bug that makes the verifier accept a bad proof, which
//! is inflation. So every case records *where* each verifier decided: refused
//! before the multiscalar multiplication (a point that does not decompress, a
//! length the statement refuses), or accepted or rejected by it. The two must
//! agree on that, not only on the boolean, and the sweep must have seen
//! acceptances and rejections at the multiscalar multiplication, or it graded
//! nothing (rule 47).

use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};

use curve25519_dalek::scalar::Scalar;

use shekyl_curve_io::CompressedPoint;
use shekyl_curve_primitives::Commitment;

use crate::{
    batch_verifier::BatchVerifier, batch_weights_seed, plus::AggregateRangeStatement, verify_batch,
    BatchEntry, Bulletproof,
};

/// Where a verifier decided a batch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Verdict {
    /// A proof was refused before the multiscalar multiplication.
    Refused,
    /// The multiscalar multiplication summed to the identity.
    Accepted,
    /// The multiscalar multiplication did not.
    Rejected,
}

/// `verify_batch`, with the per-proof step chosen: the shipped fold, or the
/// eager oracle. Same weights (the batch's own seed), same order.
fn run(batch: &[(Bulletproof, Vec<CompressedPoint>)], eager: bool) -> Verdict {
    let entries = entries(batch);
    let mut rng = ChaCha20Rng::from_seed(batch_weights_seed(&entries));
    let mut verifier = BatchVerifier::new();
    for (proof, commitments) in batch {
        let Some(points) = commitments
            .iter()
            .map(CompressedPoint::decompress)
            .collect::<Option<Vec<_>>>()
        else {
            return Verdict::Refused;
        };
        let Some(statement) = AggregateRangeStatement::new(&points) else {
            return Verdict::Refused;
        };
        let Bulletproof::Plus(proof) = proof;
        let sane = if eager {
            statement.verify_eager(&mut rng, &mut verifier.plus, proof.clone())
        } else {
            statement.verify(&mut rng, &mut verifier.plus, proof.clone())
        };
        if !sane {
            return Verdict::Refused;
        }
    }
    if verifier.verify() {
        Verdict::Accepted
    } else {
        Verdict::Rejected
    }
}

fn entries(batch: &[(Bulletproof, Vec<CompressedPoint>)]) -> Vec<BatchEntry<'_>> {
    batch
        .iter()
        .map(|(proof, commitments)| BatchEntry { proof, commitments })
        .collect()
}

/// What the sweep saw.
#[derive(Default, Debug)]
pub(super) struct Tally {
    pub(super) accepted: usize,
    pub(super) rejected: usize,
    pub(super) refused: usize,
}

impl Tally {
    /// Runs `batch` through both verifiers and through `verify_batch`, and
    /// requires all three to agree.
    pub(super) fn check(
        &mut self,
        what: &str,
        batch: &[(Bulletproof, Vec<CompressedPoint>)],
    ) -> Verdict {
        let folded = run(batch, false);
        let eager = run(batch, true);
        assert_eq!(
            folded, eager,
            "{what}: the fold and the eager oracle disagree"
        );
        assert_eq!(
            verify_batch(&entries(batch)),
            folded == Verdict::Accepted,
            "{what}: verify_batch disagrees with the folded steps it is made of"
        );
        match folded {
            Verdict::Accepted => self.accepted += 1,
            Verdict::Rejected => self.rejected += 1,
            Verdict::Refused => self.refused += 1,
        }
        folded
    }
}

/// A valid proof over `m` random commitments.
pub(super) fn entry(m: usize) -> (Bulletproof, Vec<CompressedPoint>) {
    let openings = (0..m)
        .map(|_| Commitment::new(Scalar::random(&mut OsRng), OsRng.next_u64()))
        .collect::<Vec<_>>();
    let proof = Bulletproof::prove_plus(&mut OsRng, openings.clone()).expect("proves");
    let commitments = openings
        .iter()
        .map(|c| CompressedPoint::from(c.calculate().compress()))
        .collect();
    (proof, commitments)
}

fn flip_point(point: &mut CompressedPoint, bit: usize) {
    point.0[bit / 8] ^= 1 << (bit % 8);
}

fn flip_scalar(scalar: &mut Scalar, bit: usize) {
    let mut bytes = scalar.to_bytes();
    bytes[bit / 8] ^= 1 << (bit % 8);
    *scalar = Scalar::from_bytes_mod_order(bytes);
}

/// Every field of the proof, by name, with one bit flipped.
fn tampered(proof: &Bulletproof, bit: usize) -> Vec<(String, Bulletproof)> {
    let Bulletproof::Plus(p) = proof;
    let mut out = Vec::new();
    let mut push = |name: String, edit: &dyn Fn(&mut crate::plus::AggregateRangeProof)| {
        let mut q = p.clone();
        edit(&mut q);
        out.push((name, Bulletproof::Plus(q)));
    };
    push("A".into(), &|q| flip_point(&mut q.A, bit));
    push("wip.A".into(), &|q| flip_point(&mut q.wip.A, bit));
    push("wip.B".into(), &|q| flip_point(&mut q.wip.B, bit));
    push("r_answer".into(), &|q| {
        flip_scalar(&mut q.wip.r_answer, bit)
    });
    push("s_answer".into(), &|q| {
        flip_scalar(&mut q.wip.s_answer, bit)
    });
    push("delta_answer".into(), &|q| {
        flip_scalar(&mut q.wip.delta_answer, bit)
    });
    for i in 0..p.wip.L.len() {
        push(format!("L[{i}]"), &|q| flip_point(&mut q.wip.L[i], bit));
        push(format!("R[{i}]"), &|q| flip_point(&mut q.wip.R[i], bit));
    }
    out
}

/// Bits flipped in each field: the low bit, bits in the middle, and the
/// top bit of a point's y-coordinate (its sign bit is 255).
const BITS: [usize; 4] = [0, 9, 130, 254];

#[test]
fn valid_proofs_alone_and_in_mixed_batches() {
    let mut tally = Tally::default();
    let proofs = (1..=16).map(entry).collect::<Vec<_>>();
    for (m, one) in proofs.iter().enumerate() {
        let verdict = tally.check(
            &format!("{} outputs alone", m + 1),
            core::slice::from_ref(one),
        );
        assert_eq!(
            verdict,
            Verdict::Accepted,
            "a valid proof at {} outputs",
            m + 1
        );
    }
    assert_eq!(
        tally.check("all sixteen shapes in one batch", &proofs),
        Verdict::Accepted
    );
    // Mixed batches: shapes that share generator prefixes of different lengths.
    for picks in [
        &[0usize, 15][..],
        &[1, 2, 3],
        &[15, 0, 7, 8],
        &[4, 4, 4, 4, 4],
    ] {
        let batch = picks.iter().map(|&i| proofs[i].clone()).collect::<Vec<_>>();
        assert_eq!(
            tally.check(&format!("batch {picks:?}"), &batch),
            Verdict::Accepted
        );
    }
    assert_eq!(tally.rejected + tally.refused, 0);
}

#[test]
fn one_flipped_bit_in_each_field() {
    let mut tally = Tally::default();
    for m in [1, 2, 3, 16] {
        let (proof, commitments) = entry(m);
        for bit in BITS {
            for (field, bad) in tampered(&proof, bit) {
                let verdict = tally.check(
                    &format!("{m} outputs, {field} bit {bit}"),
                    &[(bad, commitments.clone())],
                );
                assert_ne!(
                    verdict,
                    Verdict::Accepted,
                    "{m} outputs, {field} bit {bit} accepted"
                );
            }
        }
    }
    // The scalars always reach the multiscalar multiplication; most points do.
    assert!(
        tally.rejected > 0,
        "no tampered proof reached the multiexp: {tally:?}"
    );
    assert_eq!(tally.accepted, 0);
    eprintln!("field flips: {tally:?}");
}

#[test]
fn commitments_altered_swapped_dropped_or_added() {
    let mut tally = Tally::default();
    for m in [1, 2, 3, 16] {
        let (proof, commitments) = entry(m);
        let mut cases: Vec<(String, Vec<CompressedPoint>)> = Vec::new();
        for i in 0..m {
            for bit in BITS {
                let mut c = commitments.clone();
                flip_point(&mut c[i], bit);
                cases.push((format!("commitment {i} bit {bit}"), c));
            }
            let mut c = commitments.clone();
            c[i] = CompressedPoint::from(
                Commitment::new(Scalar::random(&mut OsRng), OsRng.next_u64())
                    .calculate()
                    .compress(),
            );
            cases.push((format!("commitment {i} replaced"), c));
            let mut c = commitments.clone();
            c.remove(i);
            if !c.is_empty() {
                cases.push((format!("commitment {i} dropped"), c));
            }
        }
        if m >= 2 {
            let mut c = commitments.clone();
            c.swap(0, m - 1);
            cases.push(("first and last swapped".into(), c));
        }
        let mut c = commitments.clone();
        c.push(commitments[0]);
        cases.push(("one commitment added".into(), c));
        for (what, c) in cases {
            let verdict = tally.check(&format!("{m} outputs, {what}"), &[(proof.clone(), c)]);
            assert_ne!(verdict, Verdict::Accepted, "{m} outputs, {what} accepted");
        }
    }
    assert!(
        tally.rejected > 0,
        "no altered commitment reached the multiexp: {tally:?}"
    );
    assert_eq!(tally.accepted, 0);
    eprintln!("commitment edits: {tally:?}");
}

#[test]
fn one_invalid_proof_at_every_position() {
    let mut tally = Tally::default();
    let shapes = [1, 2, 16, 3, 2, 8, 2, 4];
    let valid = shapes.iter().map(|&m| entry(m)).collect::<Vec<_>>();
    for position in 0..valid.len() {
        for (field, bit) in [
            ("r_answer", 0),
            ("s_answer", 130),
            ("delta_answer", 9),
            ("A", 0),
        ] {
            let mut batch = valid.clone();
            let (_, bad) = tampered(&batch[position].0, bit)
                .into_iter()
                .find(|(name, _)| name == field)
                .expect("the field exists");
            batch[position].0 = bad;
            let verdict = tally.check(&format!("{field} bit {bit} at position {position}"), &batch);
            assert_ne!(verdict, Verdict::Accepted);
        }
        // And the batch is accepted again once the proof is restored.
        assert_eq!(tally.check("restored", &valid), Verdict::Accepted);
    }
    assert!(tally.rejected > 0, "{tally:?}");
    assert!(tally.accepted > 0, "{tally:?}");
    eprintln!("one invalid among valid: {tally:?}");
}
