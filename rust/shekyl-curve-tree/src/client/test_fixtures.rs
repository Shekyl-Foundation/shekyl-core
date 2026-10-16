// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Leaf fixtures for the client's tests.
//!
//! Every leaf the default helpers produce is distinct from every other, in
//! each of `O`, `I`, `C` and `CM`. A tree over identical leaves has the same
//! root and the same paths under any permutation of them, so a test built on
//! such a tree passes an implementation that drains, chunks or assembles in
//! the wrong order. [`leaves_pairwise_distinct`] is the property, and
//! `default_fixture_leaves_are_pairwise_distinct` holds the default path to
//! it.
//!
//! A point is `Hp(seed)` over [`fixture_seed`], which encodes
//! `(role, height, index)`. The crate already depends on
//! [`shekyl_fcmp::tree::key_image_generator`], it clears the cofactor so the
//! output is prime-order and passes the `CM` admission rule, and it takes the
//! whole `(u64, u32)` key. `k·G` would give algebraic distinctness, but it
//! needs a curve dependency this crate's tests do not have. Here the roles
//! are separated by the seed, and the self-test checks that no scalar of one
//! leaf equals any scalar of another.
//!
//! The generators are pure functions of `(height, index)`. The rollback and
//! restart tests feed two clients the same heights and compare them, so a
//! counter or an RNG here would make those two chains differ.
//!
//! [`uniform_coinbase_raw`] and [`uniform_leaf_blob`] are the identical-leaf
//! fixture, kept for the tests that need one. Each use says why.

use std::collections::HashMap;

use super::{BlockLeaves, CurveTreeClient, RawOutput, TxLeafInputs};
use crate::types::{
    BlockHeight, CommitmentBytes, LeafEntry, OneTimePubkey, OutputIdentity, TargetKind,
};

/// Which of an output's three published points a seed is for.
#[derive(Clone, Copy)]
enum Role {
    OutputKey = 1,
    Commitment = 2,
    LeafCommitment = 3,
}

/// `tag(16) ‖ role(1) ‖ height(8, LE) ‖ index(4, LE) ‖ 0(3)`.
fn fixture_seed(role: Role, height: u64, index: usize) -> [u8; 32] {
    let index = u32::try_from(index).expect("fixture output index fits u32");
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(b"ct-test-leaf-v1\0");
    seed[16] = role as u8;
    seed[17..25].copy_from_slice(&height.to_le_bytes());
    seed[25..29].copy_from_slice(&index.to_le_bytes());
    seed
}

fn fixture_point(role: Role, height: u64, index: usize) -> [u8; 32] {
    shekyl_fcmp::tree::key_image_generator(&fixture_seed(role, height, index))
}

/// The output at `index` in the block at `height`. `index` counts across the
/// block's transactions, so two outputs of one block never share it.
pub(crate) fn raw_output_at(height: u64, index: usize) -> RawOutput {
    RawOutput {
        output_key: OneTimePubkey::from_bytes(fixture_point(Role::OutputKey, height, index)),
        commitment: Some(CommitmentBytes::from_bytes(fixture_point(
            Role::Commitment,
            height,
            index,
        ))),
        target: TargetKind::TaggedKey,
    }
}

/// [`raw_output_at`] with its `CM` resolved, as `recon` takes an output.
pub(crate) fn output_identity_at(height: u64, index: usize) -> OutputIdentity {
    let raw = raw_output_at(height, index);
    OutputIdentity {
        output_key: raw.output_key,
        commitment: raw.commitment,
        cm: fixture_point(Role::LeafCommitment, height, index),
        target: raw.target,
    }
}

/// Outputs `0..n` of the block at `height`.
pub(crate) fn raw_outputs_at(height: u64, n: usize) -> Vec<RawOutput> {
    (0..n).map(|index| raw_output_at(height, index)).collect()
}

/// The conforming `0x07` entry (`CM ‖ record`) of the output
/// [`raw_output_at`] returns for the same arguments.
pub(crate) fn leaf_entry_at(height: u64, index: usize) -> [u8; 64] {
    let mut entry = [0x07u8; 64];
    entry[..32].copy_from_slice(&fixture_point(Role::LeafCommitment, height, index));
    entry
}

/// One `0x07` entry per output, for outputs `0..n` of the block at `height`
/// (`PL-D3`).
pub(crate) fn leaf_blob_at(height: u64, n: usize) -> Vec<u8> {
    (0..n)
        .flat_map(|index| leaf_entry_at(height, index))
        .collect()
}

/// Standard Ed25519 basepoint, compressed.
const ED25519_BASEPOINT: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// The same output every time: `O` and `C` are both the basepoint.
///
/// A chain of these has identical leaves, and no test over it can see an
/// ordering defect. Use [`raw_output_at`] unless the test is about that.
pub(crate) fn uniform_coinbase_raw() -> RawOutput {
    RawOutput {
        output_key: OneTimePubkey::from_bytes(ED25519_BASEPOINT),
        commitment: Some(CommitmentBytes::from_bytes(ED25519_BASEPOINT)),
        target: TargetKind::TaggedKey,
    }
}

/// `n` copies of one conforming `0x07` entry. The pair of
/// [`uniform_coinbase_raw`].
pub(crate) fn uniform_leaf_blob(n: usize) -> Vec<u8> {
    let mut entry = [0x07u8; 64];
    entry[..32].copy_from_slice(&shekyl_fcmp::tree::key_image_generator(&[1u8; 32]));
    (0..n).flat_map(|_| entry).collect()
}

/// One coinbase tx carrying a per-output `0x07` blob of `n` × 64 bytes.
pub(crate) fn coinbase_block<'a>(
    outputs: &'a [RawOutput],
    blob: &'a [u8],
) -> Vec<TxLeafInputs<'a>> {
    vec![TxLeafInputs {
        is_miner: true,
        tx_hash: None,
        leaf_entry_blob: Some(blob),
        outputs,
    }]
}

/// Ingest one coinbase block at `height` carrying `outputs`. The `0x07` blob
/// is [`leaf_blob_at`] for `height`.
pub(crate) fn ingest_outputs_at(client: &mut CurveTreeClient, height: u64, outputs: &[RawOutput]) {
    let blob = leaf_blob_at(height, outputs.len());
    let txs = coinbase_block(outputs, &blob);
    client
        .ingest_block(BlockLeaves {
            height: BlockHeight::from_raw(height),
            txs: &txs,
        })
        .unwrap();
}

/// Ingest consecutive single-coinbase blocks at heights `from..=to` — the
/// production chain shape (every real block carries a coinbase).
pub(crate) fn ingest_coinbase_blocks(client: &mut CurveTreeClient, from: u64, to: u64) {
    for height in from..=to {
        ingest_outputs_at(client, height, &raw_outputs_at(height, 1));
    }
}

/// The four columns of a leaf, in the order `construct_leaf` writes them.
const LEAF_COLUMNS: [&str; 4] = ["O.x", "I.x", "C.x", "CM.x"];

/// `Ok` when no scalar of any leaf equals any scalar of another leaf, and no
/// two published points of the corpus are equal.
///
/// The scalars are what the tree hashes, so they are what is compared. Each
/// is a Wei25519 x-coordinate, which `P` and `-P` share: two distinct
/// compressed points can still give one scalar, and a comparison of the
/// compressed bytes alone would not see it. All four columns go into one
/// set, so a leaf whose `O` is another leaf's `C` is a collision too. That
/// is the case a swapped `O` and `C` needs.
///
/// `Err` names the first collision.
pub(crate) fn leaves_pairwise_distinct(entries: &[LeafEntry]) -> Result<(), String> {
    let mut scalars: HashMap<[u8; 32], (usize, &str)> = HashMap::new();
    let mut points: HashMap<[u8; 32], (usize, &str)> = HashMap::new();
    for (position, entry) in entries.iter().enumerate() {
        for (column, limb) in LEAF_COLUMNS.iter().zip(entry.leaf.chunks_exact(32)) {
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(limb);
            if let Some((other, other_column)) = scalars.insert(scalar, (position, column)) {
                return Err(format!(
                    "leaf {position} {column} equals leaf {other} {other_column}"
                ));
            }
        }
        let commitment = entry
            .identity
            .commitment
            .ok_or_else(|| format!("leaf {position} has no commitment"))?;
        let published = [
            ("O", *entry.identity.output_key.as_bytes()),
            (
                "I",
                shekyl_fcmp::tree::key_image_generator(entry.identity.output_key.as_bytes()),
            ),
            ("C", *commitment.as_bytes()),
            ("CM", entry.identity.cm),
        ];
        for (name, point) in published {
            if let Some((other, other_name)) = points.insert(point, (position, name)) {
                return Err(format!(
                    "leaf {position} {name} equals leaf {other} {other_name}"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recon::{collect_block_leaves, TxOutputs};

    /// Heights the widest fixture in the crate reaches, with room. The ring
    /// and capture fixtures run past 700 blocks.
    const CORPUS_HEIGHTS: u64 = 1024;
    /// More than any slot of the oracle's output schedule.
    const CORPUS_OUTPUTS_PER_BLOCK: usize = 6;

    /// Leaves for `heights` blocks of `per_block` outputs, built by the
    /// production collector. `with` edits each identity before it is built.
    fn corpus(
        heights: u64,
        per_block: usize,
        with: impl Fn(&mut OutputIdentity),
    ) -> Vec<LeafEntry> {
        let mut entries = Vec::new();
        let mut next_gindex = 0;
        for height in 0..heights {
            let identities: Vec<OutputIdentity> = (0..per_block)
                .map(|index| {
                    let mut identity = output_identity_at(height, index);
                    with(&mut identity);
                    identity
                })
                .collect();
            let txs = [TxOutputs {
                is_miner: true,
                outputs: &identities,
            }];
            next_gindex = collect_block_leaves(
                BlockHeight::from_raw(height),
                &txs,
                next_gindex,
                &mut entries,
            )
            .expect("construct_leaf accepts every fixture point")
            .next_gindex;
        }
        entries
    }

    /// Every generated point passes the admission rule `CM` is held to:
    /// canonical, prime-order, not the identity. `O` and `C` are held to it
    /// here too, so no fixture leaf depends on a torsion component.
    #[test]
    fn fixture_points_are_canonical_prime_order() {
        for height in 0..64 {
            for index in 0..CORPUS_OUTPUTS_PER_BLOCK {
                for role in [Role::OutputKey, Role::Commitment, Role::LeafCommitment] {
                    let point = fixture_point(role, height, index);
                    assert!(
                        shekyl_crypto_pq::leaf_commitment::pqc_leaf_point_valid(&point).is_some(),
                        "role {} at ({height}, {index}) is not a canonical prime-order point",
                        role as u8
                    );
                }
            }
        }
    }

    #[test]
    fn default_fixture_leaves_are_pairwise_distinct() {
        let entries = corpus(CORPUS_HEIGHTS, CORPUS_OUTPUTS_PER_BLOCK, |_| {});
        assert_eq!(
            entries.len(),
            usize::try_from(CORPUS_HEIGHTS).expect("fits usize") * CORPUS_OUTPUTS_PER_BLOCK,
            "every fixture output must build a leaf"
        );
        assert_eq!(leaves_pairwise_distinct(&entries), Ok(()));
    }

    /// The chain the ingest helpers build, read back from the client.
    #[test]
    fn ingested_default_chain_holds_pairwise_distinct_leaves() {
        let mut client = CurveTreeClient::new();
        ingest_coinbase_blocks(&mut client, 0, 3);
        for height in 4..=8u64 {
            ingest_outputs_at(&mut client, height, &raw_outputs_at(height, 3));
        }
        assert_eq!(client.entries.len(), 4 + 5 * 3);
        assert_eq!(leaves_pairwise_distinct(&client.entries), Ok(()));
    }

    /// The identical-leaf chain fails the property. Uses the uniform helpers
    /// because that chain is the subject.
    #[test]
    fn uniform_chain_fails_the_distinctness_property() {
        let mut client = CurveTreeClient::new();
        for height in 0..3u64 {
            let outputs = [uniform_coinbase_raw(), uniform_coinbase_raw()];
            let blob = uniform_leaf_blob(outputs.len());
            let txs = coinbase_block(&outputs, &blob);
            client
                .ingest_block(BlockLeaves {
                    height: BlockHeight::from_raw(height),
                    txs: &txs,
                })
                .unwrap();
        }
        assert_eq!(client.entries.len(), 6);
        assert!(leaves_pairwise_distinct(&client.entries).is_err());
    }

    /// One role made constant is enough to fail, for each role. `I` has no
    /// case of its own: it is `Hp(O)`, so it is constant exactly when `O` is.
    #[test]
    fn a_single_constant_role_fails_the_distinctness_property() {
        let uniform = uniform_coinbase_raw();
        let mut uniform_cm = [0u8; 32];
        uniform_cm.copy_from_slice(&uniform_leaf_blob(1)[..32]);

        let constant_o = corpus(3, 2, |identity| identity.output_key = uniform.output_key);
        let constant_c = corpus(3, 2, |identity| identity.commitment = uniform.commitment);
        let constant_cm = corpus(3, 2, |identity| identity.cm = uniform_cm);

        for (role, entries) in [("O", constant_o), ("C", constant_c), ("CM", constant_cm)] {
            assert_eq!(entries.len(), 6);
            assert!(
                leaves_pairwise_distinct(&entries).is_err(),
                "a constant {role} was not reported"
            );
        }
    }

    /// `O` of one leaf used as `C` of another is a collision, though each
    /// column on its own stays distinct.
    #[test]
    fn a_point_shared_across_roles_fails_the_distinctness_property() {
        let entries = corpus(3, 2, |_| {});
        let mut crossed = entries.clone();
        let borrowed = crossed[0].leaf[..32].to_vec();
        crossed[1].leaf[64..96].copy_from_slice(&borrowed);
        assert_eq!(leaves_pairwise_distinct(&entries), Ok(()));
        assert!(leaves_pairwise_distinct(&crossed).is_err());
    }
}
