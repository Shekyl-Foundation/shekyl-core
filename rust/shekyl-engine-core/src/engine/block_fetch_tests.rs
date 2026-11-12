// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the block/transaction fetch boundary (`engine/block_fetch.rs`).
//!
//! Wired as a `#[path]` child of `block_fetch::tests`, so `use super::*`
//! resolves into the fetch module and its private parsers stay testable; the
//! sibling file exists so the decomposition ratchet counts the workflow file
//! rather than its suite (the `proofs_tests` / `transfer` pattern this
//! repository already uses).

use super::*;
use crate::engine::test_support::{conforming_coinbase_extra, conforming_pqc_extra};
use core::future::Future;
use shekyl_rpc_types::wire::shared::{Archived, ArchivedState};

use shekyl_types::{
    ArchivalLength, AttestationRoot, BlockHash, CurveTreeRoot, PqcAuthHash, PrunableHash, TxHash,
};
use shekyl_wire::block::MAX_BLOCK_BLOB_SIZE;
use shekyl_wire::transaction::{MAX_TX_SIZE, UNLOCK_TIME_BLOCK_SENTINEL};
use shekyl_wire::{BlockHeader, Ct, CtBase, Input, Output, SkeletonTx, Transaction, TxPrefix};

/// A skeleton over `unprunable` with null operands: what the daemon serves
/// for a spend whose prunable region and `pqc_auths` are both empty, which
/// is most fixtures below. The shape tests exercise the bytes; the binding
/// tests exercise the operands through `bind_block_txs`.
fn skeleton(unprunable: &[u8]) -> SkeletonTx {
    SkeletonTx {
        unprunable: unprunable.to_vec(),
        prunable_hash: PrunableHash::from_bytes([0u8; 32]),
        pqc_auth_hash: None,
        archival_len: ArchivalLength::ZERO,
    }
}

/// The skeleton the daemon serves for **any** body, with the body's own
/// operands: the pruned segment plus the three values `txid_parts` measures
/// on the discardable regions — the same construction the store's
/// `skeleton_of` performs from its rows. Returns the body's txid beside it.
fn served_skeleton(tx: &Transaction) -> (SkeletonTx, TxHash) {
    let segments = tx.write_segments().expect("Vec write is infallible");
    let parts = tx.txid_parts();
    (
        SkeletonTx {
            unprunable: segments.pruned,
            prunable_hash: parts.prunable_hash,
            pqc_auth_hash: parts.pqc_auth_hash,
            archival_len: parts.archival_len,
        },
        parts.hash,
    )
}

/// Bind a skeleton to its own txid, so the shape gates downstream of the
/// binding can be exercised; when the bytes do not even parse the binding
/// is asked for the null id and refuses on the parse instead.
fn bind_own(skeleton: &SkeletonTx) -> Result<BoundTx, RpcError> {
    let own = skeleton.txid().unwrap_or(TxHash::from_bytes([0u8; 32]));
    bind_skeleton(skeleton, own)
}

/// A block's `tx` slots under `prune`, every one the item.
fn slots(txs: Vec<BlockTx>) -> Vec<OrArchived<BlockTx>> {
    txs.into_iter().map(OrArchived::Item).collect()
}

/// A daemon that answers every request with one fixed document, and keeps
/// the last request it was sent, so a test can hand the consumer a reply
/// the wire permits but the contract does not, and read what was asked.
#[derive(Clone)]
struct CannedDaemon {
    reply: std::sync::Arc<Vec<u8>>,
    asked: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl CannedDaemon {
    fn new(reply: Vec<u8>) -> Self {
        Self {
            reply: std::sync::Arc::new(reply),
            asked: std::sync::Arc::default(),
        }
    }
}

impl Rpc for CannedDaemon {
    fn post(
        &self,
        _route: &str,
        body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        *self.asked.lock().expect("not poisoned") = body;
        let doc = self.reply.clone();
        async move { Ok(doc.as_ref().clone()) }
    }
}

/// **A refusal is not evidence, even when it comes with a body.**
///
/// A JSON-RPC 2.0 reply carries exactly one of `result` and `error`. A
/// daemon that answers both — a refusal beside a complete, plausible block
/// — is answering with neither, and the fetch refuses the document rather
/// than read the block out of it. Without that rule this call **succeeds**
/// and scans a block the daemon declined to vouch for.
#[tokio::test]
async fn a_refusal_carrying_a_body_is_refused_not_parsed() {
    let block = coinbase_block(3);
    let document = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": served_block(&block, &[], 7),
        "error": {
            "code": -32004,
            "message": "not ready",
            "data": {"code": "daemon.unready", "parameter": {}, "message": "not ready"},
        },
    });
    let rpc = CannedDaemon::new(serde_json::to_vec(&document).expect("serializes"));
    let err = default_fetch_scannable_block(&rpc, 3)
        .await
        .expect_err("a refusal must not be accepted as a block");
    assert!(
        format!("{err}").contains("neither one result nor one error"),
        "the document must be refused as a whole: {err}"
    );
}

/// `block_show`'s reply for `block`: its bytes, `tx` as served, and the
/// first output's global index.
fn served_block(block: &Block, tx: &[OrArchived<BlockTx>], output_index: u64) -> serde_json::Value {
    let header = serde_json::json!({
        "height": block.number().expect("a block with a coinbase"),
        "hash": "00".repeat(32), "parent": "00".repeat(32), "version_major": 1,
        "version_minor": 0, "time": 0, "nonce": 0, "orphan": false, "depth": 0,
        "difficulty": "0x1", "difficulty_cumulative": "0x1", "reward": "0",
        "weight": 0, "weight_longterm": null, "tx_count": 0,
        "pow": null, "coinbase": "00".repeat(32), "curve_root": "00".repeat(32),
        "attestation_root": "00".repeat(32),
    });
    serde_json::json!({
        "header": header,
        "body": Bytes(block.serialize()),
        "tx": tx,
        "output_index": output_index,
    })
}

/// **One `block_show` is the whole fetch.** The request is `block_show` by
/// height under `prune`; the reply's bytes become the block, its `tx` the
/// bound bodies, and its `output_index` the first global output index.
///
/// The edit that turns this red is the fetch asking for the whole form, or
/// dropping the reply's `output_index`.
#[tokio::test]
async fn the_fetch_is_one_block_show_under_prune() {
    let block = coinbase_block(3);
    let rpc = CannedDaemon::new(crate::engine::test_support::result_envelope(&served_block(
        &block,
        &[],
        41,
    )));
    let scannable = default_fetch_scannable_block(&rpc, 3)
        .await
        .expect("a served block fetches");
    assert_eq!(scannable.block.number(), Some(3));
    assert!(scannable.transactions.is_empty());
    assert_eq!(scannable.first_output_index, Some(41));

    let asked = rpc.asked.lock().expect("not poisoned").clone();
    assert_eq!(
        crate::engine::test_support::requested_method(&asked),
        crate::engine::test_support::method_name::<wire::BlockShow>()
    );
    assert_eq!(
        crate::engine::test_support::requested_params(&asked),
        serde_json::json!({"height": 3, "pow": false, "prune": true})
    );
}

/// A coinbase-only block at `number` with one tagged-key output whose
/// `Null` ct carries a committed base (the shape the legacy parse dropped).
fn coinbase_block(number: u64) -> Block {
    Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1,
            previous: BlockHash::NULL,
            nonce: 0,
            curve_tree_root: CurveTreeRoot::from_bytes([0u8; 32]),
            attestation_root: AttestationRoot::from_bytes(
                shekyl_archival_retention::empty_attestation_root(),
            ),
        },
        miner_transaction: Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::Gen(number)],
                outputs: vec![Output {
                    amount: 0,
                    key: [1u8; 32],
                    view_tag: 0,
                }],
                extra: conforming_coinbase_extra(1),
            },
            ct: Ct::Null(CtBase {
                enc_amounts: vec![[7u8; 9]],
                enc_labels: vec![[9u8; 9]],
                commitments: vec![[2u8; 32]],
            }),
        },
        transaction_hashes: vec![],
    }
}

#[test]
fn parse_block_blob_accepts_coinbase_null_with_committed_base() {
    // Regression anchor for the shekyl-oxide → shekyl-wire migration: a
    // coinbase whose `Null` ct carries a committed base (enc_amounts /
    // enc_labels / outPk per GENESIS §9.6) must parse. The legacy
    // shekyl-oxide `Block::read` dropped the coinbase committed base and
    // rejected live daemon blocks as `InvalidNode("invalid block")`.
    let block = coinbase_block(5);
    let parsed = parse_block_blob(&block.serialize(), 5).expect("coinbase-with-base parses");
    assert_eq!(parsed.number(), Some(5));
    match &parsed.miner_transaction.ct {
        Ct::Null(base) => {
            assert_eq!(base.commitments.len(), 1, "committed base preserved");
            assert_eq!(base.enc_amounts.len(), 1);
            assert_eq!(base.enc_labels.len(), 1);
        }
        other => panic!("coinbase ct must be Null, got {other:?}"),
    }
}

#[test]
fn parse_block_blob_rejects_height_mismatch() {
    let block = coinbase_block(5);
    assert!(matches!(
        parse_block_blob(&block.serialize(), 6),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn parse_block_blob_rejects_garbage() {
    assert!(matches!(
        parse_block_blob(&[], 0),
        Err(RpcError::InvalidNode(_))
    ));
    assert!(matches!(
        parse_block_blob(&[0x00, 0xff], 0),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn bind_skeleton_round_trips_and_rejects_trailing() {
    // A pruned non-miner spend: ToKey (key-image) input, 2 outputs (the anti-deanon
    // minimum), prunable proof + pqc_auths dropped — round-trips through from_bytes.
    let tx = pruned_spend_tx(0);
    let mut bytes = Vec::new();
    tx.write(&mut bytes).expect("Vec write is infallible");
    let bound = bind_own(&skeleton(&bytes)).expect("pruned tx round trips");
    assert_eq!(bound.tx().prefix.outputs.len(), 2);
    assert_eq!(bound.txid(), pruned_id(&tx));

    let mut trailing = bytes.clone();
    trailing.push(0xAB);
    assert!(matches!(
        bind_own(&skeleton(&trailing)),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn bind_skeleton_rejects_coinbase_shaped() {
    // A block's `tx` and `tx_list` carry only non-miner txs (the coinbase is
    // embedded in the block's bytes and parsed there). A coinbase served here — whether a clean
    // `[gen] + Null` coinbase or the non-canonical `gen + Fcmp` mix — must be
    // rejected, never fed to the scanner (it would otherwise carry a cleartext
    // `gen` reward output the wallet has no business ingesting from this path).
    let real_coinbase = Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::Gen(7)],
            outputs: vec![Output {
                amount: 0,
                key: [1u8; 32],
                view_tag: 0,
            }],
            extra: conforming_coinbase_extra(1),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[0u8; 9]],
            enc_labels: vec![[0u8; 9]],
            commitments: vec![[2u8; 32]],
        }),
    };
    // A valid coinbase passes the context-free validator, then is_coinbase rejects it.
    assert!(real_coinbase.validate_context_free_pruned().is_ok());
    assert!(matches!(
        bind_own(&skeleton(&real_coinbase.serialize())),
        Err(RpcError::InvalidNode(_))
    ));

    // The non-canonical `gen + Fcmp` mix is rejected by the validator itself
    // (a coinbase must carry a Null ct, §2.5).
    let gen_fcmp = Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::Gen(7)],
            outputs: vec![Output {
                amount: 0,
                key: [1u8; 32],
                view_tag: 0,
            }],
            extra: conforming_coinbase_extra(1),
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: BlockHash::NULL,
            base: CtBase {
                enc_amounts: vec![[0u8; 9]],
                enc_labels: vec![[0u8; 9]],
                commitments: vec![[2u8; 32]],
            },
            pqc_auths: vec![],
            prunable: None,
        },
    };
    assert!(gen_fcmp.validate_context_free_pruned().is_err());
    assert!(matches!(
        bind_own(&skeleton(&gen_fcmp.serialize())),
        Err(RpcError::InvalidTransaction(_))
    ));
}

#[test]
fn bind_skeleton_rejects_single_output_spend() {
    // A non-miner spend (key-image input) must have >= 2 outputs (anti-deanon,
    // GENESIS §10); a 1-output spend is non-canonical, so the untrusted-daemon
    // ingestion boundary rejects it rather than handing the scanner phantom state.
    let mut tx = pruned_spend_tx(0);
    tx.prefix.outputs.truncate(1);
    if let Ct::Fcmp { base, .. } = &mut tx.ct {
        base.enc_amounts.truncate(1);
        base.enc_labels.truncate(1);
        base.commitments.truncate(1);
    }
    assert!(matches!(
        bind_own(&skeleton(&tx.serialize())),
        Err(RpcError::InvalidTransaction(_))
    ));
}

/// A valid pruned non-miner spend: a `ToKey` key-image input, **2 outputs** (the
/// anti-deanonymization minimum the ingestion validator enforces), with the prunable
/// proof + pqc_auths dropped. The shared fixture for the `bind_skeleton` /
/// `bind_block_txs` tests; `unlock_time` is varied for the block-height-only gate.
fn pruned_spend_tx(unlock_time: u64) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: vec![],
                key_image: [0x42u8; 32],
            }],
            outputs: vec![
                Output {
                    amount: 0,
                    key: [1u8; 32],
                    view_tag: 0,
                },
                Output {
                    amount: 0,
                    key: [3u8; 32],
                    view_tag: 1,
                },
            ],
            extra: conforming_pqc_extra(2),
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: BlockHash::NULL,
            base: CtBase {
                enc_amounts: vec![[0u8; 9], [0u8; 9]],
                enc_labels: vec![[0u8; 9], [0u8; 9]],
                commitments: vec![[2u8; 32], [3u8; 32]],
            },
            pqc_auths: vec![],
            prunable: None,
        },
    }
}

/// The bytes of a valid pruned non-miner tx that `bind_skeleton` accepts.
///
/// Its hash is **not** irrelevant — `bind_block_txs` binds the body to the
/// requested txid, so a caller must label this body with [`pruned_id`]'s
/// derivation rather than a chosen constant. A fixture that invents a hash is
/// staging the substitution the binding exists to reject.
fn pruned_tx_bytes() -> Vec<u8> {
    pruned_spend_tx(0).serialize()
}

/// The hash a pruned fixture body actually has, given the fixtures' all-zero
/// `prunable_hash` and zero `archival_size`. Deriving it rather than picking
/// a label is the point: the binding refuses an invented one.
fn pruned_id(tx: &Transaction) -> TxHash {
    skeleton(&tx.serialize())
        .txid()
        .expect("the fixtures parse as skeletons")
}

/// A **whole** non-miner spend: [`pruned_spend_tx`] with the discardable
/// regions restored — one aggregated Bp+, one pseudo-out per `ToKey` input,
/// one `pqc_auths` slot per input — so its txid is 4-part and its skeleton
/// carries all three operands. Proof bytes are zeroed placeholders: the
/// tests here read the body's shape and identity, not proof math.
fn full_spend_tx() -> Transaction {
    use shekyl_wire::transaction::{PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN};
    use shekyl_wire::{BpPlus, PqcAuth, Prunable};

    let mut tx = pruned_spend_tx(0);
    let Ct::Fcmp {
        pqc_auths,
        prunable,
        ..
    } = &mut tx.ct
    else {
        unreachable!("pruned_spend_tx is Fcmp by construction");
    };
    *pqc_auths = vec![PqcAuth {
        auth_version: 1,
        scheme_id: 1,
        flags: 0,
        hybrid_public_key: vec![0u8; PQC_HYBRID_SINGLE_KEY_LEN],
        hybrid_signature: vec![0u8; PQC_HYBRID_SINGLE_SIG_LEN],
    }];
    *prunable = Some(Prunable {
        // Spend fixture: no pass records (RF-D1).
        serve_credit_pruned: Vec::new(),
        bulletproofs: vec![BpPlus {
            a: [0; 32],
            a1: [0; 32],
            b: [0; 32],
            r1: [0; 32],
            s1: [0; 32],
            d1: [0; 32],
            l: vec![[0; 32]; 7],
            r: vec![[0; 32]; 7],
        }],
        tree_depth: 1,
        fcmp_proof: vec![0u8; 8],
        pseudo_outs: vec![[0; 32]],
    });
    tx
}

/// A served transaction built from the wire type rather than a JSON
/// literal, so the double cannot describe a shape the daemon does not
/// produce (RK-D1). Null operands: the fixtures' bodies carry none.
fn block_tx(tx_hash: TxHash, body: Vec<u8>) -> BlockTx {
    BlockTx {
        id: HashHex::from_bytes(tx_hash.to_bytes()),
        body: Bytes(body),
        prunable_hash: HashHex::from_bytes([0u8; 32]),
        pqc_auth_hash: Nullable(None),
        archival_size: Size(0),
    }
}

/// **A canonical transaction under a borrowed label is refused.**
///
/// Every field of the reply is the daemon's to choose, so the label
/// matching the request proves only that the daemon wanted it to match. The
/// body here is a real, well-formed, validator-passing transaction — it is
/// simply not the one that was asked for, which is what makes it dangerous:
/// a proof consumer would verify outputs belonging to a transaction that
/// may not be on this chain.
#[test]
fn a_valid_body_under_the_requested_label_is_refused() {
    let asked = pruned_spend_tx(0);
    let substituted = pruned_spend_tx(1);
    let asked_id = pruned_id(&asked);
    assert_ne!(asked_id, pruned_id(&substituted), "the fixture must differ");

    // The label is the requested hash; the bytes are another transaction.
    let txs = vec![block_tx(asked_id, substituted.serialize())];
    let err = bind_block_txs(&[asked_id], &slots(txs))
        .expect_err("a body that is not the requested transaction must be refused");
    assert!(
        format!("{err}").contains("a label is not an identity"),
        "the refusal must name the binding, not a parse failure: {err}"
    );
}

/// The prunable digest is the daemon's too, and choosing it freely does not
/// help: it leaves a keccak preimage, not a substitution. Pinned by moving
/// the digest under an otherwise-correct body and requiring a refusal.
#[test]
fn a_forged_prunable_digest_does_not_rescue_a_body() {
    let tx = pruned_spend_tx(0);
    let real_id = pruned_id(&tx);
    let mut entry = block_tx(real_id, tx.serialize());
    entry.prunable_hash = HashHex::from_bytes([0x77; 32]); // not the fixtures' zero

    let err = bind_block_txs(&[real_id], &slots(vec![entry]))
        .expect_err("a different digest yields a different identity");
    assert!(
        format!("{err}").contains("a label is not an identity"),
        "the digest is an operand of the identity, not decoration: {err}"
    );
}

/// **So is the archival length** (`SHT-Q2`): it is an operand of the txid, so
/// the reply's value is checked by the same recomputation. A daemon that
/// reports another length for an otherwise-correct body — one byte off is
/// enough to move a shard boundary for whoever believed it — is refused.
#[test]
fn a_forged_archival_length_does_not_rescue_a_body() {
    let tx = pruned_spend_tx(0);
    let real_id = pruned_id(&tx);
    let mut entry = block_tx(real_id, tx.serialize());
    entry.archival_size = Size(1); // not the fixtures' zero

    let err = bind_block_txs(&[real_id], &slots(vec![entry]))
        .expect_err("a different length yields a different identity");
    assert!(
        format!("{err}").contains("a label is not an identity"),
        "the length is an operand of the identity, not decoration: {err}"
    );
}

#[test]
fn bind_block_txs_accepts_in_order() {
    // Two DISTINCT bodies, each under the hash its own bytes produce. The
    // fixture used to serve one body under two different labels — which is
    // the substitution case, not the happy path, and only passed while the
    // label was the whole check.
    let (tx0, tx1) = (pruned_spend_tx(0), pruned_spend_tx(1));
    let (h0, h1) = (pruned_id(&tx0), pruned_id(&tx1));
    let txs = vec![block_tx(h0, tx0.serialize()), block_tx(h1, tx1.serialize())];
    let out = bind_block_txs(&[h0, h1], &slots(txs)).expect("in-order batch parses");
    assert_eq!(out.len(), 2);
    assert_eq!(
        out.iter()
            .map(shekyl_wire::BoundTx::txid)
            .collect::<Vec<_>>(),
        vec![h0, h1],
        "each bound body carries the txid it was requested as"
    );
}

#[test]
fn bind_block_txs_rejects_reordered_hashes() {
    // The daemon returns both requested txs but with their `id` labels
    // in swapped slots. Running global-output-index assignment depends on
    // block order, so a reorder must be rejected even though each tx is
    // individually valid (the adversarial-daemon mis-association case).
    let (h0, h1) = (TxHash::from_bytes([3u8; 32]), TxHash::from_bytes([4u8; 32]));
    let blob = pruned_tx_bytes();
    let txs = vec![block_tx(h1, blob.clone()), block_tx(h0, blob)];
    assert!(matches!(
        bind_block_txs(&[h0, h1], &slots(txs)),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn bind_block_txs_rejects_count_mismatch() {
    let (h0, h1) = (TxHash::from_bytes([3u8; 32]), TxHash::from_bytes([4u8; 32]));
    let txs = vec![block_tx(h0, pruned_tx_bytes())];
    assert!(matches!(
        bind_block_txs(&[h0, h1], &slots(txs)),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn a_reply_without_an_id_label_is_refused_at_the_boundary() {
    // No `id` → no association handle → a daemon that omits the label
    // cannot be order-pinned. The field is required on the shared wire
    // type, so the refusal happens when the reply decodes and the
    // malformed entry never reaches the binding.
    let doc = serde_json::json!({
        "body": Bytes(pruned_tx_bytes()),
        "prunable_hash": "00".repeat(32), "pqc_auth_hash": null, "archival_size": 0,
    });
    assert!(
        serde_json::from_value::<BlockTx>(doc).is_err(),
        "an entry with no id must not decode"
    );
}

#[test]
fn bind_block_txs_rejects_an_empty_body() {
    let h0 = TxHash::from_bytes([3u8; 32]);
    assert!(matches!(
        bind_block_txs(&[h0], &slots(vec![block_tx(h0, Vec::new())])),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn bind_block_txs_empty_is_ok() {
    let out = bind_block_txs(&[], &[]).expect("empty batch parses");
    assert!(out.is_empty());
}

/// **A whole body is not the pruned form** (`SB-Q2` item 10). A `prune`
/// request is answered by the skeleton alone; a daemon that serves the
/// whole body — even the right transaction, under its own operands — is
/// refused, because the pruned segment must be consumed exactly: the bytes
/// after the base would read as authentications the skeleton's txid
/// ignores, and the wallet must never have to parse `pqc_auths` bytes it
/// did not ask for.
#[test]
fn a_whole_body_is_refused() {
    let full = full_spend_tx();
    let (skeleton, id) = served_skeleton(&full);
    let mut entry = block_tx(id, full.serialize());
    entry.prunable_hash = HashHex::from_bytes(skeleton.prunable_hash.to_bytes());
    entry.pqc_auth_hash = skeleton
        .pqc_auth_hash
        .map(|hash| HashHex::from_bytes(hash.to_bytes()))
        .into();
    entry.archival_size = Size(skeleton.archival_len.to_raw());
    let err = bind_block_txs(&[id], &slots(vec![entry]))
        .expect_err("a whole body answers no prune request");
    assert!(
        format!("{err}").contains("does not bind"),
        "the refusal is the binding's, not a later parse: {err}"
    );
}

/// **An archived slot is not the pruned form's answer.** Every transaction
/// has a skeleton, so `archived` can only appear in a reply to a full-form
/// request; a `prune` reply carrying one is refused.
#[test]
fn an_archived_slot_in_a_prune_reply_is_refused() {
    let id = TxHash::from_bytes([9u8; 32]);
    let slot = OrArchived::Archived(ArchivedState::Archived(Archived {
        id: HashHex::from_bytes(id.to_bytes()),
        shard: shekyl_rpc_types::kinds::Integer(3),
    }));
    let err = bind_block_txs(&[id], &[slot]).expect_err("an archived slot is refused");
    assert!(
        format!("{err}").contains("archived"),
        "the refusal names the slot: {err}"
    );
}

/// **Arity downgrade** (`SB-Q2` falsifier vi). A spend whose body carries
/// `pqc_auths` hashes 4-part; served as a skeleton with `pqc_auth_hash:
/// null` it hashes 3-part, another identity, and does not bind. The
/// skeleton with its third operand present binds — and binds to the
/// body's own `hash()`, so the two hash paths agree on one transaction.
#[test]
fn a_carrying_skeleton_served_without_its_third_operand_does_not_bind() {
    let full = full_spend_tx();
    let (skeleton, id) = served_skeleton(&full);
    assert_eq!(id, full.hash(), "the skeleton's txid is the body's");
    assert!(
        skeleton.pqc_auth_hash.is_some(),
        "the fixture hashes 4-part"
    );
    bind_skeleton(&skeleton, id).expect("the complete skeleton binds");

    let downgraded = SkeletonTx {
        pqc_auth_hash: None,
        ..skeleton
    };
    let err = bind_skeleton(&downgraded, id)
        .expect_err("a third operand the prefix needs and was not given is refused");
    assert!(
        format!("{err}").contains("does not bind"),
        "refused by the binding, not a parse failure: {err}"
    );
}

/// The reverse: a `pqc_auth_hash` for a prefix that carries none is
/// refused outright (`SkeletonTx::parse`), ahead of the mixer that would
/// otherwise silently drop it and hash the body 3-part. The prefix here is
/// an FCMP++ body whose first input is `gen` — the one non-null shape the
/// mixer reads as 3-part (a null body is refused earlier, as no skeleton).
#[test]
fn a_third_operand_for_a_prefix_that_carries_none_is_refused() {
    let mut gen_first = pruned_spend_tx(0);
    gen_first.prefix.inputs.insert(0, Input::Gen(7));
    let (served, id) = served_skeleton(&gen_first);
    assert!(
        served.pqc_auth_hash.is_none(),
        "a gen-first prefix hashes 3-part"
    );
    let upgraded = SkeletonTx {
        pqc_auth_hash: Some(PqcAuthHash::from_bytes([0x33; 32])),
        ..served
    };
    let err = bind_skeleton(&upgraded, id)
        .expect_err("a third operand the prefix cannot carry is refused");
    assert!(
        format!("{err}").contains("carries none"),
        "refused by the arity check, not the shape gate: {err}"
    );
}

/// Hex of a valid pruned non-miner spend with the given `unlock_time` — for the
/// block-height-only ingestion gate tests.
fn pruned_skeleton_with_unlock_time(unlock_time: u64) -> SkeletonTx {
    skeleton(&pruned_spend_tx(unlock_time).serialize())
}

#[test]
fn bind_skeleton_rejects_timestamp_form_unlock_time() {
    // A structurally valid pruned tx whose `unlock_time` is the timestamp
    // form is non-canonical (consensus rejects it — GENESIS §9 creation
    // cut); ingestion must refuse it so the scanner never sees it.
    let bad = pruned_skeleton_with_unlock_time(UNLOCK_TIME_BLOCK_SENTINEL);
    assert!(matches!(
        bind_own(&bad),
        Err(RpcError::InvalidTransaction(_))
    ));
    // The largest block-form value still parses.
    let ok = pruned_skeleton_with_unlock_time(UNLOCK_TIME_BLOCK_SENTINEL - 1);
    assert!(bind_own(&ok).is_ok());
}

/// The untrusted-daemon size bound on a skeleton: more than `MAX_TX_SIZE`
/// bytes is refused before it is parsed.
#[test]
fn an_oversized_skeleton_is_refused() {
    assert!(matches!(
        bind_own(&skeleton(&vec![0u8; MAX_TX_SIZE + 1])),
        Err(RpcError::InvalidNode(_))
    ));
}

/// The size bound on a block: more than `MAX_BLOCK_BLOB_SIZE` bytes is
/// refused before it is parsed.
#[test]
fn parse_block_blob_rejects_an_oversized_block() {
    assert!(matches!(
        parse_block_blob(&vec![0u8; MAX_BLOCK_BLOB_SIZE + 1], 0),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn parse_block_blob_rejects_timestamp_form_coinbase() {
    // Defense-in-depth: a canonical coinbase is `height + 60` (block form);
    // the timestamp form is rejected at ingestion too.
    let mut block = coinbase_block(5);
    block.miner_transaction.prefix.unlock_time = UNLOCK_TIME_BLOCK_SENTINEL;
    assert!(matches!(
        parse_block_blob(&block.serialize(), 5),
        Err(RpcError::InvalidNode(_))
    ));
}
