// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `ScannableBlock` → per-block leaf set decode (CT-5 §3.2, R1-Q3).
//!
//! The curve tree contains **every** on-chain output, not just the
//! wallet-owned ones the scanner recovers. This module decodes a parsed
//! [`ScannableBlock`] into the full per-block leaf set
//! ([`OwnedTxLeaves`](crate::scan::OwnedTxLeaves)) that the producer carries
//! on [`ScanResult`](crate::scan::ScanResult) and the merge feeds to the
//! [`CurveTreeActor`](super::curve_tree_actor) for ingest.
//!
//! # Consensus drain order (highest inheritance-risk surface — R1-Q3)
//!
//! The decode reproduces the daemon's leaf-insertion order exactly
//! (`CT2_DRAIN_ORDER.md`, parent §6): transactions in C++ order — the
//! **coinbase first**, then non-miner transactions in block-list order — and
//! outputs within each in `vout` order. Per-output facts mirror the proven
//! scanner primitives rather than re-deriving consensus rules:
//!
//! - **`output_key`** is the on-chain compressed key verbatim
//!   (`Output::key`); the client's `construct_leaf` is the shared FFI
//!   primitive that decides validity, so x-extraction cannot diverge from the
//!   daemon (`CT2_DRAIN_ORDER.md` §3.2).
//! - **`commitment`** is `proofs.base.commitments[o]` — the same access
//!   [`shekyl_scanner`]'s `scan_transaction` uses (`scan.rs`). `None` when the
//!   output has no commitment slot, which makes it leaf-ineligible (the C++
//!   skip (b), `recon::try_build_leaf`).
//! - **`target`** is classified from the on-chain output tag exactly as
//!   `Output::write` emits it (staked_key > tagged_key > key); the parser
//!   admits only those three tags, so [`TargetKind::Other`] is unreachable
//!   here (it exists only for daemon leaf-set parity).
//! - **`leaf_hash_blob`** is the `tx_extra 0x07` payload verbatim; a
//!   malformed/absent extra yields `None`, which the client resolves to the
//!   zero `h_pqc` fallback per the daemon's `extract_leaf_hashes` `{}` path
//!   (`recon.rs`). The decode does not error on a malformed extra — it mirrors
//!   the fallback.
//!
//! # X7 — buffer bounded by the consensus output ceiling, before allocation
//!
//! The full-leaf-set buffer (E4) is daemon-controlled in size. Per X7
//! (CT-5 §5.1 / §6) it is bounded by the consensus per-transaction output
//! ceiling ([`shekyl_scanner::MAX_OUTPUTS`]) **before** the per-tx output
//! `Vec` is allocated, not by the daemon's received blob length. The producer
//! also runs an excessive-outputs pre-pass before calling the decode
//! (`local_refresh.rs`), so this gate is defense-in-depth; both are exercised
//! by tests.

use shekyl_curve_tree::{RawOutput, TargetKind};
use shekyl_oxide::transaction::{Output, Pruned, Transaction};
use shekyl_rpc::ScannableBlock;
use shekyl_scanner::{Extra, MAX_OUTPUTS};

use crate::scan::OwnedTxLeaves;

/// Why a `ScannableBlock` could not be decoded into a leaf set.
///
/// The only failure mode is the X7 buffer bound: a transaction whose output
/// count exceeds the consensus ceiling is rejected before its leaf buffer is
/// allocated. Every other per-output condition (absent commitment slot,
/// malformed `0x07` extra) is a *valid* decode outcome the daemon also
/// tolerates, not an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// A transaction's `outputs.len()` exceeds [`shekyl_scanner::MAX_OUTPUTS`]
    /// (the FCMP++ per-tx output ceiling). Rejected *before* allocating the
    /// per-tx leaf buffer (X7).
    ExcessiveOutputs {
        /// Whether the offending transaction is the coinbase.
        is_miner: bool,
        /// The offending output count.
        count: usize,
    },
}

/// Decode a parsed block into its full per-block leaf set, in consensus drain
/// order (coinbase first, then non-miner transactions in block-list order).
///
/// Mirrors the scanner's pruning conversion of the coinbase
/// (`scan.rs`: `Transaction::<Pruned>::from(block.miner_transaction())`) so
/// commitment access is uniform across the coinbase and the already-pruned
/// non-miner transactions.
pub(crate) fn decode_block_leaves(
    scannable: &ScannableBlock,
) -> Result<Vec<OwnedTxLeaves>, DecodeError> {
    let miner = Transaction::<Pruned>::from(scannable.block.miner_transaction().clone());
    let mut txs = Vec::with_capacity(1 + scannable.transactions.len());
    txs.push(decode_tx(&miner, true)?);
    for tx in &scannable.transactions {
        txs.push(decode_tx(tx, false)?);
    }
    Ok(txs)
}

/// Decode one transaction's leaf inputs in `vout` order.
fn decode_tx(tx: &Transaction<Pruned>, is_miner: bool) -> Result<OwnedTxLeaves, DecodeError> {
    let prefix = tx.prefix();

    // X7: bound the per-tx leaf buffer by the consensus output ceiling
    // *before* allocating it, not by the daemon's blob length.
    let count = prefix.outputs.len();
    if count > MAX_OUTPUTS {
        return Err(DecodeError::ExcessiveOutputs { is_miner, count });
    }

    // `tx_extra 0x07` leaf-hash blob, verbatim. A malformed or absent extra
    // yields `None` — the client resolves that to the zero `h_pqc` fallback
    // (the daemon's `extract_leaf_hashes` `{}` path), so we mirror the
    // fallback rather than erroring.
    let leaf_hash_blob = Extra::read(&mut prefix.extra.as_slice())
        .ok()
        .and_then(|extra| extra.pqc_leaf_hashes().map(<[u8]>::to_vec));

    // On-chain commitments live in `proofs.base` (uniform across pruned/full —
    // the same access the scanner uses). `None` per output (slot absent) makes
    // that output leaf-ineligible (`recon::try_build_leaf` (b)).
    let commitments = match tx {
        Transaction::V3 {
            proofs: Some(proofs),
            ..
        } => Some(&proofs.base.commitments),
        _ => None,
    };

    let outputs = prefix
        .outputs
        .iter()
        .enumerate()
        .map(|(o, output)| RawOutput {
            output_key: output.key.to_bytes(),
            commitment: commitments.and_then(|c| c.get(o)).map(|c| c.0),
            target: classify_target(output),
        })
        .collect();

    Ok(OwnedTxLeaves {
        is_miner,
        leaf_hash_blob,
        outputs,
    })
}

/// Classify an output's target exactly as the on-chain tag was written
/// (`transaction.rs` `Output::write`): staked_key (tag 4) takes precedence,
/// then tagged_key (tag 3, has a view tag), else key (tag 2).
///
/// The parser admits only tags 2/3/4, so [`TargetKind::Other`] is unreachable
/// from a parsed block — it exists in [`shekyl_curve_tree`] only for daemon
/// leaf-set parity if the daemon ever indexes an unknown target.
fn classify_target(output: &Output) -> TargetKind {
    if let Some(meta) = output.staking {
        // Tier B (CT-5d). `lock_blocks` is resolved against `shekyl-staking`
        // (the single source of truth for the tier table) — mirroring the FFI
        // `shekyl_stake_lock_blocks`: an out-of-range tier resolves to `0`,
        // the daemon's invalid-tier fallback.
        let lock_blocks = shekyl_staking::tiers::tier_by_id(meta.lock_tier)
            .map(|t| t.lock_blocks)
            .unwrap_or(0);
        TargetKind::StakedKey { lock_blocks }
    } else if output.view_tag.is_some() {
        TargetKind::TaggedKey
    } else {
        TargetKind::Key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_oxide::block::{Block, BlockHeader};
    use shekyl_oxide::fcmp::{EncryptedAmount, EncryptedLabel, ProofBase, PrunedProofs};
    use shekyl_oxide::io::CompressedPoint;
    use shekyl_oxide::transaction::{Input, StakingMeta, Timelock, TransactionPrefix};
    use shekyl_scanner::ExtraField;

    fn zero_enc_amount() -> EncryptedAmount {
        EncryptedAmount {
            amount: [0u8; 8],
            amount_tag: 0,
        }
    }

    fn zero_enc_label() -> EncryptedLabel {
        EncryptedLabel {
            label: [0u8; 8],
            label_tag: 0,
        }
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn hex_to_32(s: &str) -> [u8; 32] {
        let v = hex_to_vec(s);
        assert_eq!(v.len(), 32, "expected 32 bytes, got {}", v.len());
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    /// Build a `txout_to_tagged_key` (tag 3) RCT output for the given key.
    fn tagged_output(key: [u8; 32]) -> Output {
        Output {
            amount: None,
            key: CompressedPoint(key),
            view_tag: Some(0),
            staking: None,
        }
    }

    /// Build a pruned V2 transaction carrying `outputs`, a `0x07` leaf-hash
    /// blob, and one commitment per supplied `commitments` entry.
    fn pruned_tx(
        outputs: Vec<Output>,
        commitments: Vec<[u8; 32]>,
        leaf_hash_blob: Option<Vec<u8>>,
    ) -> Transaction<Pruned> {
        let n = outputs.len();
        let extra = leaf_hash_blob
            .map(|blob| ExtraField::PqcLeafHashes(blob).serialize())
            .unwrap_or_default();
        let prefix = TransactionPrefix {
            additional_timelock: Timelock::None,
            inputs: vec![Input::Gen(0)],
            outputs,
            extra,
        };
        Transaction::V3 {
            prefix,
            proofs: Some(PrunedProofs {
                base: ProofBase {
                    fee: 0,
                    encrypted_amounts: (0..n).map(|_| zero_enc_amount()).collect(),
                    encrypted_labels: (0..n).map(|_| zero_enc_label()).collect(),
                    commitments: commitments.into_iter().map(CompressedPoint).collect(),
                },
            }),
        }
    }

    /// R1-Q3 decode KAT: the engine-path `ScannableBlock` decode must
    /// reproduce the `ct2_tier_a.json` oracle's per-output leaf inputs
    /// (`output_key`, `commitment`, `target`) and the `0x07` blob, for every
    /// coinbase in every chain. Those RawOutput rows are exactly what
    /// `shekyl-curve-tree`'s `recon_kat` then proves reconstruct the consensus
    /// root; the full root match through the engine refresh path is CT-5a
    /// commit 6. The fixture is the same oracle, sourced cross-crate so the
    /// two KATs cannot drift.
    #[test]
    fn decode_reproduces_ct2_tier_a_leaf_inputs() {
        const FIXTURE: &str =
            include_str!("../../../shekyl-curve-tree/tests/fixtures/ct2_tier_a.json");
        let f: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture parses");

        let chains = f["chains"].as_array().expect("chains array");
        assert!(!chains.is_empty(), "fixture has at least one chain");

        let mut blocks_checked = 0usize;
        for chain in chains {
            let name = chain["name"].as_str().unwrap_or("<unnamed>");
            for block in chain["blocks"].as_array().expect("blocks array") {
                let mt = &block["miner_tx"];
                let blob = hex_to_vec(mt["pqc_leaf_hashes"].as_str().expect("0x07 blob hex"));

                let rows = mt["outputs"].as_array().expect("outputs array");
                let mut outputs = Vec::with_capacity(rows.len());
                let mut commitments = Vec::new();
                for row in rows {
                    let key = hex_to_32(row["output_key"].as_str().expect("O hex"));
                    let target = row["target"].as_str().expect("target");
                    let out = match target {
                        "tagged_key" => tagged_output(key),
                        "key" => Output {
                            amount: None,
                            key: CompressedPoint(key),
                            view_tag: None,
                            staking: None,
                        },
                        other => panic!("unexpected Tier-A target kind: {other}"),
                    };
                    outputs.push(out);
                    // Tier-A coinbase outputs all carry commitments (no slot
                    // gaps), so the commitment vec aligns 1:1 with outputs.
                    let c = row["commitment"]
                        .as_str()
                        .unwrap_or_else(|| panic!("Tier-A row missing commitment in chain {name}"));
                    commitments.push(hex_to_32(c));
                }

                let tx = pruned_tx(outputs, commitments.clone(), Some(blob.clone()));
                let decoded = decode_tx(&tx, true).expect("coinbase decodes");

                assert!(decoded.is_miner, "coinbase is_miner");
                assert_eq!(
                    decoded.leaf_hash_blob.as_deref(),
                    Some(blob.as_slice()),
                    "chain {name}: 0x07 blob carried verbatim",
                );
                assert_eq!(
                    decoded.outputs.len(),
                    rows.len(),
                    "chain {name}: every output decoded, in order",
                );
                for (i, (row, got)) in rows.iter().zip(&decoded.outputs).enumerate() {
                    let key = hex_to_32(row["output_key"].as_str().unwrap());
                    assert_eq!(got.output_key, key, "chain {name} out {i}: output_key");
                    assert_eq!(
                        got.commitment,
                        Some(commitments[i]),
                        "chain {name} out {i}: commitment from proofs.base",
                    );
                    let expect_target = match row["target"].as_str().unwrap() {
                        "tagged_key" => TargetKind::TaggedKey,
                        "key" => TargetKind::Key,
                        _ => unreachable!(),
                    };
                    assert_eq!(got.target, expect_target, "chain {name} out {i}: target");
                }
                blocks_checked += 1;
            }
        }
        assert!(blocks_checked > 0, "fixture exercised at least one block");
    }

    #[test]
    fn classify_target_matches_on_chain_tag() {
        // tag 2: no view tag, no staking -> Key.
        let key = Output {
            amount: None,
            key: CompressedPoint([1u8; 32]),
            view_tag: None,
            staking: None,
        };
        assert_eq!(classify_target(&key), TargetKind::Key);

        // tag 3: view tag present -> TaggedKey.
        assert_eq!(
            classify_target(&tagged_output([2u8; 32])),
            TargetKind::TaggedKey
        );

        // tag 4: staking present -> StakedKey with the tier-resolved lock.
        let staked = Output {
            amount: Some(100),
            key: CompressedPoint([3u8; 32]),
            view_tag: Some(0),
            staking: Some(StakingMeta { lock_tier: 0 }),
        };
        let expected = shekyl_staking::tiers::tier_by_id(0).unwrap().lock_blocks;
        assert_eq!(
            classify_target(&staked),
            TargetKind::StakedKey {
                lock_blocks: expected
            },
        );
    }

    #[test]
    fn absent_commitment_slot_is_leaf_ineligible_none() {
        // Two outputs, one commitment: the second output has no slot, so its
        // decoded commitment is None (the C++ skip (b)).
        let outputs = vec![tagged_output([4u8; 32]), tagged_output([5u8; 32])];
        let tx = pruned_tx(outputs, vec![[9u8; 32]], None);
        let decoded = decode_tx(&tx, false).expect("decodes");
        assert_eq!(decoded.outputs[0].commitment, Some([9u8; 32]));
        assert_eq!(decoded.outputs[1].commitment, None);
    }

    #[test]
    fn malformed_or_absent_extra_yields_no_blob() {
        let tx = pruned_tx(vec![tagged_output([6u8; 32])], vec![[1u8; 32]], None);
        let decoded = decode_tx(&tx, true).expect("decodes");
        assert_eq!(decoded.leaf_hash_blob, None);
    }

    #[test]
    fn excessive_outputs_rejected_before_alloc() {
        // X7 DoD: a transaction past the consensus output ceiling is rejected
        // before its leaf buffer is allocated.
        let n = MAX_OUTPUTS + 1;
        // Key content is irrelevant: the X7 gate rejects on count before any
        // per-output work, so a constant key keeps the test free of casts.
        let outputs: Vec<Output> = (0..n).map(|_| tagged_output([0u8; 32])).collect();
        let tx = pruned_tx(outputs, vec![[0u8; 32]; n], None);
        assert_eq!(
            decode_tx(&tx, false),
            Err(DecodeError::ExcessiveOutputs {
                is_miner: false,
                count: n
            }),
        );
    }

    #[test]
    fn block_decode_orders_coinbase_first() {
        // Coinbase (proofs: None, one output) then one non-miner pruned tx.
        let header = BlockHeader {
            hardfork_version: 1,
            hardfork_signal: 0,
            timestamp: 1,
            previous: [0u8; 32],
            nonce: 0,
            curve_tree_root: [0u8; 32],
        };
        let miner_prefix = TransactionPrefix {
            additional_timelock: Timelock::None,
            inputs: vec![Input::Gen(1)],
            outputs: vec![tagged_output([7u8; 32])],
            extra: vec![],
        };
        let miner_tx = Transaction::V3 {
            prefix: miner_prefix,
            proofs: None,
        };
        let block = Block::new(header, miner_tx, vec![]).expect("coinbase-only block");
        let non_miner = pruned_tx(vec![tagged_output([8u8; 32])], vec![[3u8; 32]], None);
        let scannable = ScannableBlock {
            block,
            transactions: vec![non_miner],
            output_index_for_first_ringct_output: None,
        };

        let decoded = decode_block_leaves(&scannable).expect("decodes");
        assert_eq!(decoded.len(), 2, "coinbase + one non-miner tx");
        assert!(decoded[0].is_miner, "coinbase first");
        assert!(!decoded[1].is_miner, "non-miner second");
        assert_eq!(decoded[0].outputs[0].output_key, [7u8; 32]);
        assert_eq!(decoded[1].outputs[0].output_key, [8u8; 32]);
    }
}
