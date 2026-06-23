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
//! Inputs are [`shekyl_wire`] types — the canonical, spec-faithful wire parse
//! (`GENESIS_TX_WIRE_FORMAT.md`). The leaf extraction is the same access the
//! [`shekyl_scanner`] scan path uses, so the two cannot diverge.
//!
//! # Consensus drain order (highest inheritance-risk surface — R1-Q3)
//!
//! The decode reproduces the daemon's leaf-insertion order exactly
//! (`CT2_DRAIN_ORDER.md`, parent §6): transactions in C++ order — the
//! **coinbase first**, then non-miner transactions in block-list order — and
//! outputs within each in `vout` order. Per-output facts mirror the proven
//! scanner primitives rather than re-deriving consensus rules:
//!
//! - **`output_key`** is the on-chain one-time key verbatim
//!   ([`shekyl_wire::Output::key`]); the client's `construct_leaf` is the
//!   shared FFI primitive that decides validity, so x-extraction cannot
//!   diverge from the daemon (`CT2_DRAIN_ORDER.md` §3.2).
//! - **`commitment`** is `base.commitments[o]`. The committed base
//!   ([`CtBase`](shekyl_wire::CtBase)) is present for **both** the coinbase
//!   ([`Ct::Null`](shekyl_wire::Ct::Null)) and spends
//!   ([`Ct::Fcmp`](shekyl_wire::Ct::Fcmp)) — the coinbase `Null` ct carries a
//!   real committed base (`enc_amounts`/`enc_labels`/`outPk`, GENESIS §9.6/§9.9),
//!   which the legacy parse dropped — so commitment access is uniform. `None`
//!   per output (slot absent) makes that output leaf-ineligible (the C++ skip
//!   (b), `recon::try_build_leaf`).
//! - **`target`** is [`TargetKind::TaggedKey`] for every output: genesis admits
//!   only `txout_to_tagged_key` ([`shekyl_wire`]'s sole [`Output`] shape,
//!   GENESIS §9.5), so the other [`TargetKind`]s are unreachable here (they
//!   exist in [`shekyl_curve_tree`] only for daemon leaf-set parity).
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
use shekyl_scanner::{Extra, ScannableBlock, MAX_OUTPUTS};
use shekyl_wire::{Ct, Output, Transaction};

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
/// The committed base is present on the coinbase ([`Ct::Null`]) and on spends
/// ([`Ct::Fcmp`]) alike, so commitment access is uniform across the miner
/// transaction and the non-miner transactions.
pub(crate) fn decode_block_leaves(
    scannable: &ScannableBlock,
) -> Result<Vec<OwnedTxLeaves>, DecodeError> {
    let mut txs = Vec::with_capacity(1 + scannable.transactions.len());
    txs.push(decode_tx(&scannable.block.miner_transaction, true)?);
    for tx in &scannable.transactions {
        txs.push(decode_tx(tx, false)?);
    }
    Ok(txs)
}

/// Decode one transaction's leaf inputs in `vout` order.
fn decode_tx(tx: &Transaction, is_miner: bool) -> Result<OwnedTxLeaves, DecodeError> {
    let prefix = &tx.prefix;

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
    let leaf_hash_blob = {
        let mut extra_bytes = prefix.extra.as_slice();
        Extra::read(&mut extra_bytes)
            .ok()
            .and_then(|extra| extra.pqc_leaf_hashes().map(<[u8]>::to_vec))
    };

    // On-chain commitments live in the committed base, present uniformly across
    // the coinbase (`Ct::Null`) and spends (`Ct::Fcmp`) — the same access the
    // scanner uses. `None` per output (slot absent) makes that output
    // leaf-ineligible (`recon::try_build_leaf` (b)).
    let commitments = match &tx.ct {
        Ct::Null(base) | Ct::Fcmp { base, .. } => &base.commitments,
    };

    let outputs = prefix
        .outputs
        .iter()
        .enumerate()
        .map(|(o, output)| RawOutput {
            output_key: output.key,
            commitment: commitments.get(o).copied(),
            target: classify_target(output),
        })
        .collect();

    Ok(OwnedTxLeaves {
        is_miner,
        leaf_hash_blob,
        outputs,
    })
}

/// Classify an output's curve-tree target.
///
/// `GENESIS_TX_WIRE_FORMAT.md` §9.5: `txout_to_tagged_key`
/// ([`TAG_OUTPUT_TAGGED_KEY`](shekyl_wire::TAG_OUTPUT_TAGGED_KEY)) is the
/// **sole** genesis output type, so every parsed [`Output`] classifies as a
/// tagged key. [`TargetKind::Key`], [`TargetKind::StakedKey`], and
/// [`TargetKind::Other`] remain in [`shekyl_curve_tree`] only for daemon
/// leaf-set parity.
///
/// Reversion clause (`21-reversion-clause-discipline.mdc`): if a future hard
/// fork reintroduces a staked-key or bare-key output tag to the wire format,
/// [`shekyl_wire::Output`] grows a tag discriminant and this function
/// dispatches on it again.
fn classify_target(_output: &Output) -> TargetKind {
    TargetKind::TaggedKey
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_scanner::ExtraField;
    use shekyl_wire::{Block, BlockHeader, CtBase, Input, TxPrefix};

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

    /// Build a `txout_to_tagged_key` output for the given key (the sole genesis
    /// output shape).
    fn tagged_output(key: [u8; 32]) -> Output {
        Output {
            amount: 0,
            key,
            view_tag: 0,
        }
    }

    /// Build a transaction carrying `outputs`, a `0x07` leaf-hash blob, and the
    /// supplied `commitments` in its committed base.
    ///
    /// Uses the coinbase [`Ct::Null`] shape: the decode reads only the
    /// committed base, which `Null` and `Fcmp` share, so this exercises the
    /// uniform-base extraction without constructing a full FCMP++ prunable
    /// proof. `enc_amounts`/`enc_labels` are sized to the output count (the
    /// decode ignores them); `commitments` is passed through verbatim so a
    /// short vector exercises the absent-slot path.
    fn null_tx(
        outputs: Vec<Output>,
        commitments: Vec<[u8; 32]>,
        leaf_hash_blob: Option<Vec<u8>>,
    ) -> Transaction {
        let n = outputs.len();
        let extra = leaf_hash_blob
            .map(|blob| ExtraField::PqcLeafHashes(blob).serialize())
            .unwrap_or_default();
        Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::Gen(0)],
                outputs,
                extra,
            },
            ct: Ct::Null(CtBase {
                enc_amounts: vec![[0u8; 9]; n],
                enc_labels: vec![[0u8; 9]; n],
                commitments,
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
                    // Genesis wire models only `txout_to_tagged_key`; the
                    // Tier-A oracle is all tagged-key coinbase outputs.
                    let target = row["target"].as_str().expect("target");
                    assert_eq!(
                        target, "tagged_key",
                        "chain {name}: genesis wire models only txout_to_tagged_key",
                    );
                    outputs.push(tagged_output(key));
                    // Tier-A coinbase outputs all carry commitments (no slot
                    // gaps), so the commitment vec aligns 1:1 with outputs.
                    let c = row["commitment"]
                        .as_str()
                        .unwrap_or_else(|| panic!("Tier-A row missing commitment in chain {name}"));
                    commitments.push(hex_to_32(c));
                }

                let tx = null_tx(outputs, commitments.clone(), Some(blob.clone()));
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
                        "chain {name} out {i}: commitment from committed base",
                    );
                    assert_eq!(
                        got.target,
                        TargetKind::TaggedKey,
                        "chain {name} out {i}: target",
                    );
                }
                blocks_checked += 1;
            }
        }
        assert!(blocks_checked > 0, "fixture exercised at least one block");
    }

    #[test]
    fn classify_target_is_tagged_key_at_genesis() {
        // Genesis wire models only `txout_to_tagged_key`, so every output
        // classifies as a tagged key regardless of its key/view_tag/amount
        // content.
        assert_eq!(
            classify_target(&tagged_output([1u8; 32])),
            TargetKind::TaggedKey
        );
        assert_eq!(
            classify_target(&Output {
                amount: 100,
                key: [3u8; 32],
                view_tag: 7,
            }),
            TargetKind::TaggedKey,
        );
    }

    #[test]
    fn absent_commitment_slot_is_leaf_ineligible_none() {
        // Two outputs, one commitment: the second output has no slot, so its
        // decoded commitment is None (the C++ skip (b)).
        let outputs = vec![tagged_output([4u8; 32]), tagged_output([5u8; 32])];
        let tx = null_tx(outputs, vec![[9u8; 32]], None);
        let decoded = decode_tx(&tx, false).expect("decodes");
        assert_eq!(decoded.outputs[0].commitment, Some([9u8; 32]));
        assert_eq!(decoded.outputs[1].commitment, None);
    }

    #[test]
    fn malformed_or_absent_extra_yields_no_blob() {
        let tx = null_tx(vec![tagged_output([6u8; 32])], vec![[1u8; 32]], None);
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
        let tx = null_tx(outputs, vec![[0u8; 32]; n], None);
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
        // Coinbase (one output) then one non-miner tx.
        let header = BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1,
            previous: [0u8; 32],
            nonce: 0,
            curve_tree_root: [0u8; 32],
        };
        let miner_tx = null_tx(vec![tagged_output([7u8; 32])], vec![[0u8; 32]], None);
        let block = Block {
            header,
            miner_transaction: miner_tx,
            transaction_hashes: vec![],
        };
        let non_miner = null_tx(vec![tagged_output([8u8; 32])], vec![[3u8; 32]], None);
        let scannable = ScannableBlock {
            block,
            transactions: vec![non_miner],
            first_output_index: None,
        };

        let decoded = decode_block_leaves(&scannable).expect("decodes");
        assert_eq!(decoded.len(), 2, "coinbase + one non-miner tx");
        assert!(decoded[0].is_miner, "coinbase first");
        assert!(!decoded[1].is_miner, "non-miner second");
        assert_eq!(decoded[0].outputs[0].output_key, [7u8; 32]);
        assert_eq!(decoded[1].outputs[0].output_key, [8u8; 32]);
    }
}
