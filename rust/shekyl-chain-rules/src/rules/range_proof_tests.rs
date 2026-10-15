// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-H19's fold over a candidate, held without a view: the verdict is a
//! function of the listed bodies alone (`range_proof.rs`). The bodies are
//! the fixture spend with its commitments and proof replaced — real proofs
//! made here over the commitments they carry, or a fixed synthetic proof
//! where the subject is the seed's bytes. A spend the rules crate builds is
//! refused at CEN-I13 on any view, so a block of them cannot reach this fold
//! through `validate`; the fold's witness through the production stack is
//! the driven two-spend block in `shekyl-chain-ingest`
//! (`scenario_spend_tests`), with a wallet-signed proof flipped before
//! signing.

use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use shekyl_bulletproofs::{batch_weights_seed, BatchEntry, Bulletproof};
use shekyl_curve_primitives::Commitment;
use shekyl_wire::{BpPlus, Ct, Transaction};

use super::gather;
use crate::census::CenRow;
use crate::harness::fixture::{candidate, listed, serve_credit_only};
use crate::rules::tx::H19;
use crate::verdict::{InvalidBlock, Locus, TxSlot};

/// The fixture spend with `proof` over `commitments` in place of its filler.
fn carrying(seed: u8, proof: &Bulletproof, commitments: &[[u8; 32]]) -> Transaction {
    let mut tx = listed([seed; 32]);
    let Ct::Fcmp {
        base,
        prunable: Some(prunable),
        ..
    } = &mut tx.ct
    else {
        unreachable!("the fixture spend carries a prunable region");
    };
    base.commitments = commitments.to_vec();
    prunable.bulletproofs =
        vec![BpPlus::from_bytes(&proof.serialize()).expect("a proof's bytes are a wire Bp+")];
    tx
}

/// A spend carrying a real two-output proof over its own commitments.
fn proven(seed: u8) -> (Transaction, Bulletproof, Vec<[u8; 32]>) {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let openings = (0..2)
        .map(|_| Commitment::new(Scalar::random(&mut rng), rng.next_u64()))
        .collect::<Vec<_>>();
    let commitments: Vec<[u8; 32]> = openings
        .iter()
        .map(|c| c.calculate().compress().to_bytes())
        .collect();
    let proof = Bulletproof::prove_plus(&mut rng, openings).expect("two outputs prove");
    (carrying(seed, &proof, &commitments), proof, commitments)
}

fn valid(seed: u8) -> Transaction {
    proven(seed).0
}

/// A spend whose proof parses, is sane, and fails its equation: bit 0 of
/// `r1`'s low byte (offset 96) flipped — every point still decompresses and
/// the scalar stays reduced, so only the multiscalar multiplication can
/// refuse it.
fn broken(seed: u8) -> Transaction {
    let (_, proof, commitments) = proven(seed);
    let mut bytes = proof.serialize();
    bytes[96] ^= 1;
    let proof = Bulletproof::read_plus(&mut bytes.as_slice()).expect("still reduced");
    carrying(seed, &proof, &commitments)
}

/// A spend whose proof does not reassemble: `r1` unreduced. The wire reads
/// it (the wire does not reduce scalars); `BpPlus::to_bulletproof` refuses.
fn unreassemblable(seed: u8) -> Transaction {
    let mut tx = valid(seed);
    if let Ct::Fcmp {
        prunable: Some(prunable),
        ..
    } = &mut tx.ct
    {
        prunable.bulletproofs[0].r1 = [0xFF; 32];
        assert!(prunable.bulletproofs[0].to_bulletproof().is_none());
    }
    tx
}

fn refused_at(listed: Vec<Transaction>, slot: TxSlot) {
    assert_eq!(
        H19::verify_block(&candidate(listed)),
        Err(InvalidBlock::new(CenRow::H19, Locus::Tx { slot })),
    );
}

/// A block with nothing to range-prove passes, so the row records on every
/// coinbase-only block (`ChainValid::mint` requires it once `implemented`):
/// no listed body, and a serve credit, which carries no proof by mandate.
#[test]
fn h19_passes_a_block_with_no_proofs() {
    assert_eq!(H19::verify_block(&candidate(Vec::new())), Ok(()));
    assert_eq!(
        H19::verify_block(&candidate(vec![serve_credit_only([7; 32])])),
        Ok(())
    );
}

/// Valid proofs pass in one batch, beside a body with none.
#[test]
fn h19_passes_valid_proofs_in_one_batch() {
    assert_eq!(
        H19::verify_block(&candidate(vec![
            valid(1),
            serve_credit_only([7; 32]),
            valid(2),
            valid(3),
        ])),
        Ok(())
    );
}

/// One broken proof among good ones fails the batch, and the locus walk
/// names its transaction — wherever it sits.
#[test]
fn h19_refuses_one_broken_proof_among_good_ones_at_its_slot() {
    refused_at(vec![valid(1), broken(2), valid(3)], TxSlot::Listed(1));
    refused_at(vec![broken(1), valid(2), valid(3)], TxSlot::Listed(0));
    refused_at(vec![valid(1), valid(2), broken(3)], TxSlot::Listed(2));
}

/// The refusal is the first bad transaction in block order whichever way
/// its proof is bad: an equation failure ahead of an unreassemblable proof
/// is named, and the reverse; the rules crate's own filler proof (unreduced
/// scalars) is refused at its slot too.
#[test]
fn h19_names_the_first_bad_transaction_whichever_way_its_proof_is_bad() {
    refused_at(
        vec![valid(1), broken(2), unreassemblable(3)],
        TxSlot::Listed(1),
    );
    refused_at(
        vec![valid(1), unreassemblable(2), broken(3)],
        TxSlot::Listed(1),
    );
    refused_at(vec![listed([9; 32]), valid(2)], TxSlot::Listed(0));
}

/// A proof whose point does not decompress is sane-checked out of the
/// batch, and named.
#[test]
fn h19_refuses_a_proof_whose_point_does_not_decompress() {
    let mut tx = valid(2);
    if let Ct::Fcmp {
        prunable: Some(prunable),
        ..
    } = &mut tx.ct
    {
        // y = 2 is on no point of the curve.
        let mut y = [0u8; 32];
        y[0] = 2;
        prunable.bulletproofs[0].a = y;
    }
    refused_at(vec![valid(1), tx], TxSlot::Listed(1));
}

/// A commitment the proof does not cover — the first output's, swapped for
/// the second's — is the proof's failure: the batch reads the commitments as
/// carried.
#[test]
fn h19_refuses_a_proof_over_commitments_it_does_not_cover() {
    let (_, proof, mut commitments) = proven(4);
    commitments.swap(0, 1);
    refused_at(
        vec![valid(1), carrying(4, &proof, &commitments)],
        TxSlot::Listed(1),
    );
}

/// A fixed synthetic proof: every field a distinct pattern, the scalars'
/// top byte zero so each stays reduced, seven rounds (two outputs). The
/// seed reads bytes, never validity.
fn synthetic(tag: u8) -> Transaction {
    let mut bp = BpPlus {
        a: [tag ^ 0x10; 32],
        a1: [tag ^ 0x11; 32],
        b: [tag ^ 0x12; 32],
        r1: [tag ^ 0x20; 32],
        s1: [tag ^ 0x21; 32],
        d1: [tag ^ 0x22; 32],
        l: (0..7).map(|k| [tag ^ (0x40 + k); 32]).collect(),
        r: (0..7).map(|k| [tag ^ (0x60 + k); 32]).collect(),
    };
    bp.r1[31] = 0;
    bp.s1[31] = 0;
    bp.d1[31] = 0;
    let proof = bp.to_bulletproof().expect("reduced scalars reassemble");
    carrying(tag, &proof, &[[tag ^ 0x81; 32], [tag ^ 0x82; 32]])
}

/// The determinism KAT at the block: the seed the fold derives for a fixed
/// candidate — two listed transactions and a serve credit between them,
/// which contributes nothing — pinned. The two synthetic proofs and their
/// commitments are byte-for-byte `shekyl-bulletproofs`' KAT batch
/// (`tests/derived.rs`, `the_seed_of_a_fixed_batch_is_pinned`), so the pin
/// is that crate's: the fold's batch is exactly the documented two-entry
/// batch, in block order. The same two bodies swapped are another seed.
#[test]
fn h19_the_seed_of_a_fixed_block_is_pinned() {
    let seed_of = |listed: Vec<Transaction>| {
        let gathered = gather(&candidate(listed)).expect("one proof per body");
        let entries: Vec<BatchEntry<'_>> = gathered
            .iter()
            .map(|tx| tx.entry().expect("reassembled"))
            .collect();
        batch_weights_seed(&entries)
    };
    let block = vec![synthetic(0x00), serve_credit_only([7; 32]), synthetic(0xA5)];
    assert_eq!(
        seed_of(block),
        [
            0xe2, 0xc8, 0x1e, 0x10, 0x4a, 0x62, 0xbb, 0x61, 0x83, 0x8f, 0xff, 0xff, 0x3d, 0x5a,
            0x9a, 0x8f, 0x12, 0x20, 0x31, 0x60, 0xc1, 0xd5, 0x93, 0x07, 0xed, 0x06, 0xa2, 0x95,
            0x98, 0xc0, 0x99, 0xd9,
        ],
        "the fold's batch moved: block order, one entry per proof, commitments as carried"
    );
    assert_ne!(
        seed_of(vec![synthetic(0x00), synthetic(0xA5)]),
        seed_of(vec![synthetic(0xA5), synthetic(0x00)]),
    );
}
