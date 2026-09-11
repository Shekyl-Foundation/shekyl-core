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
use crate::engine::test_support::conforming_pqc_extra;
use core::future::Future;
use shekyl_rpc_types::HashHex;

use shekyl_wire::transaction::UNLOCK_TIME_BLOCK_SENTINEL;
use shekyl_wire::{BlockHeader, Ct, CtBase, Input, Output, TxPrefix};

/// A daemon that answers every route with one fixed document, so a test
/// can hand the consumer a reply the wire permits but the contract does
/// not — here, a refusal carrying a body.
#[derive(Clone)]
struct CannedDaemon(std::sync::Arc<Vec<u8>>);

impl Rpc for CannedDaemon {
    fn post(
        &self,
        _route: &str,
        _body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        let doc = self.0.clone();
        async move { Ok(doc.as_ref().clone()) }
    }
}

/// **A refusal is not evidence, even when it comes with a body.**
///
/// `rpc_call` only deserializes, so a daemon may answer a non-OK `status`
/// *and* a complete, plausible entry in one document. The body here is
/// built to clear every check downstream of the status — the count
/// matches, the entry's `tx_hash` equals the requested hash AND the body
/// hashes to it (`parse_tx_batch` binds both), and the pruned blob is a
/// transaction `parse_pruned_tx` accepts. So without the status check
/// this call **succeeds** and hands back a transaction the daemon declined
/// to vouch for; that is the hazard, not a parse error arriving late.
#[tokio::test]
async fn a_refusal_carrying_a_body_is_refused_not_parsed() {
    // Derived, not invented: with a chosen constant the body-identity check
    // at `parse_tx_batch` would refuse this entry anyway, and deleting
    // `refuse_unless_ok` would leave the test red for the wrong reason —
    // pinning the binding while claiming to pin the status guard.
    let tx = pruned_spend_tx(0);
    let prunable_digest = [0x5Au8; 32];
    let txid = tx.hash_with_supplied_prunable(prunable_digest);
    let mut body = Vec::new();
    tx.write(&mut body).expect("Vec write is infallible");
    let reply = shekyl_rpc_types::GetTransactionsResponse {
        status: shekyl_rpc_types::RpcStatus("Failed".to_owned()),
        txs: vec![TxEntry {
            tx_hash: HashHex::from_bytes(txid),
            as_hex: String::new(),
            pruned_as_hex: hex::encode(&body),
            prunable_as_hex: String::new(),
            prunable_hash: HashHex::from_bytes(prunable_digest),
            as_json: String::new(),
            pruned: false,
            double_spend_seen: false,
            location: shekyl_rpc_types::TxLocation::Mined {
                block_height: 3,
                block_timestamp: 1_700_000_000,
                confirmations: 1,
                output_indices: vec![1],
            },
        }],
        missed_tx: Vec::new(),
    };
    let rpc = CannedDaemon(std::sync::Arc::new(
        serde_json::to_vec(&reply).expect("wire type serializes"),
    ));

    let err = fetch_transactions(&rpc, &[txid], TxBodyForm::Pruned)
        .await
        .expect_err("a refusal must not be accepted as transactions");
    let text = format!("{err}");
    assert!(
        text.contains("get_transactions refused") && text.contains("not evidence"),
        "the refusal must name itself rather than surface as some later \
         failure: {text}"
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
            previous: [0u8; 32],
            nonce: 0,
            curve_tree_root: [0u8; 32],
            attestation_root: shekyl_archival_retention::empty_attestation_root(),
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
                extra: conforming_pqc_extra(1),
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
    let blob = hex::encode(block.serialize());
    let parsed = parse_block_blob(&blob, 5).expect("coinbase-with-base parses");
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
    let blob = hex::encode(block.serialize());
    assert!(matches!(
        parse_block_blob(&blob, 6),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn parse_block_blob_rejects_non_hex_and_garbage() {
    assert!(matches!(
        parse_block_blob("zz", 0),
        Err(RpcError::InvalidNode(_))
    ));
    assert!(matches!(
        parse_block_blob("00ff", 0),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn parse_pruned_tx_round_trips_and_rejects_trailing() {
    // A pruned non-miner spend: ToKey (key-image) input, 2 outputs (the anti-deanon
    // minimum), prunable proof + pqc_auths dropped — round-trips through from_bytes.
    let tx = pruned_spend_tx(0);
    let mut bytes = Vec::new();
    tx.write(&mut bytes).expect("Vec write is infallible");
    let hexed = hex::encode(&bytes);
    let parsed = parse_pruned_tx(&hexed, "").expect("pruned tx round trips");
    assert_eq!(parsed.prefix.outputs.len(), 2);

    let mut trailing = bytes.clone();
    trailing.push(0xAB);
    assert!(matches!(
        parse_pruned_tx(&hex::encode(&trailing), ""),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn parse_pruned_tx_rejects_non_hex() {
    assert!(matches!(
        parse_pruned_tx("zz", ""),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn parse_pruned_tx_rejects_coinbase_shaped() {
    // `get_transactions` returns only non-miner txs (the coinbase is embedded in
    // the block blob and parsed there). A coinbase served here — whether a clean
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
            extra: conforming_pqc_extra(1),
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
        parse_pruned_tx(&hex::encode(real_coinbase.serialize()), ""),
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
            extra: conforming_pqc_extra(1),
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: [0u8; 32],
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
        parse_pruned_tx(&hex::encode(gen_fcmp.serialize()), ""),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn parse_pruned_tx_rejects_single_output_spend() {
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
        parse_pruned_tx(&hex::encode(tx.serialize()), ""),
        Err(RpcError::InvalidNode(_))
    ));
}

/// A valid pruned non-miner spend: a `ToKey` key-image input, **2 outputs** (the
/// anti-deanonymization minimum the ingestion validator enforces), with the prunable
/// proof + pqc_auths dropped. The shared fixture for the `parse_pruned_tx` /
/// `parse_tx_batch` tests; `unlock_time` is varied for the block-height-only gate.
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
            reference_block: [0u8; 32],
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

/// Hex of a valid pruned non-miner tx that `parse_pruned_tx` accepts.
///
/// Its hash is **not** irrelevant — `parse_tx_batch` binds the body to the
/// requested txid, so a caller must label this body with [`pruned_id`]'s
/// derivation rather than a chosen constant. A fixture that invents a hash is
/// staging the substitution the binding exists to reject.
fn pruned_tx_hex() -> String {
    hex::encode(pruned_spend_tx(0).serialize())
}

/// The hash a pruned fixture body actually has, given the fixtures' all-zero
/// `prunable_hash`. Deriving it rather than picking a label is the point:
/// `parse_tx_batch` now binds the body, so a fixture that invents a hash is
/// staging the substitution it is supposed to reject.
fn pruned_id(tx: &Transaction) -> [u8; 32] {
    tx.hash_with_supplied_prunable([0u8; 32])
}

/// A **full** (unpruned) non-miner spend: [`pruned_spend_tx`] with the
/// prunable-coupled sections restored — one aggregated Bp+, one pseudo-out per
/// `ToKey` input, one `pqc_auths` slot per input — so it passes the complete
/// [`shekyl_wire::Transaction::validate`]. Proof bytes are zeroed placeholders:
/// the context-free validator checks structure (counts/arities), not proof math.
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

/// A reply entry built from the wire type rather than a JSON literal, so
/// the double cannot describe a shape the daemon does not produce (RK-D1).
/// The mined arm, because these fixtures stand in for confirmed txs.
fn tx_entry_with(tx_hash: [u8; 32], as_hex: &str, pruned_as_hex: &str) -> TxEntry {
    TxEntry {
        tx_hash: HashHex::from_bytes(tx_hash),
        as_hex: as_hex.to_owned(),
        pruned_as_hex: pruned_as_hex.to_owned(),
        prunable_as_hex: String::new(),
        prunable_hash: HashHex::from_bytes([0u8; 32]),
        as_json: String::new(),
        pruned: false,
        double_spend_seen: false,
        location: shekyl_rpc_types::TxLocation::Mined {
            block_height: 1,
            confirmations: 1,
            block_timestamp: 0,
            output_indices: Vec::new(),
        },
    }
}

fn tx_entry(tx_hash_hex: &str, pruned_hex: &str) -> TxEntry {
    let bytes: [u8; 32] = hex::decode(tx_hash_hex)
        .expect("test hash is hex")
        .try_into()
        .expect("test hash is 32 bytes");
    tx_entry_with(bytes, "", pruned_hex)
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
    let txs = vec![tx_entry(
        &hex::encode(asked_id),
        &hex::encode(substituted.serialize()),
    )];
    let err = parse_tx_batch(&[asked_id], &txs, TxBodyForm::Pruned)
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
    let mut entry = tx_entry(&hex::encode(real_id), &hex::encode(tx.serialize()));
    entry.prunable_hash = HashHex::from_bytes([0x77; 32]); // not the fixtures' zero

    let err = parse_tx_batch(&[real_id], &[entry], TxBodyForm::Pruned)
        .expect_err("a different digest yields a different identity");
    assert!(
        format!("{err}").contains("a label is not an identity"),
        "the digest is an operand of the identity, not decoration: {err}"
    );
}

#[test]
fn parse_tx_batch_accepts_in_order() {
    // Two DISTINCT bodies, each under the hash its own bytes produce. The
    // fixture used to serve one body under two different labels — which is
    // the substitution case, not the happy path, and only passed while the
    // label was the whole check.
    let (tx0, tx1) = (pruned_spend_tx(0), pruned_spend_tx(1));
    let (h0, h1) = (pruned_id(&tx0), pruned_id(&tx1));
    let txs = vec![
        tx_entry(&hex::encode(h0), &hex::encode(tx0.serialize())),
        tx_entry(&hex::encode(h1), &hex::encode(tx1.serialize())),
    ];
    let out = parse_tx_batch(&[h0, h1], &txs, TxBodyForm::Pruned).expect("in-order batch parses");
    assert_eq!(out.len(), 2);
}

#[test]
fn parse_tx_batch_rejects_reordered_hashes() {
    // The daemon returns both requested txs but with their `tx_hash` labels
    // in swapped slots. Running global-output-index assignment depends on
    // block order, so a reorder must be rejected even though each tx is
    // individually valid (the adversarial-daemon mis-association case).
    let (h0, h1) = ([3u8; 32], [4u8; 32]);
    let blob = pruned_tx_hex();
    let txs = vec![
        tx_entry(&hex::encode(h1), &blob),
        tx_entry(&hex::encode(h0), &blob),
    ];
    assert!(matches!(
        parse_tx_batch(&[h0, h1], &txs, TxBodyForm::Pruned),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn parse_tx_batch_rejects_count_mismatch() {
    let (h0, h1) = ([3u8; 32], [4u8; 32]);
    let blob = pruned_tx_hex();
    let txs = vec![tx_entry(&hex::encode(h0), &blob)];
    assert!(matches!(
        parse_tx_batch(&[h0, h1], &txs, TxBodyForm::Pruned),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn a_reply_without_a_tx_hash_label_is_refused_at_the_boundary() {
    // No `tx_hash` → no association handle → a daemon that omits the label
    // cannot be order-pinned. This used to be `parse_tx_batch`'s rejection;
    // with the shared wire type the field is required, so the refusal now
    // happens when the reply decodes and the malformed entry never reaches
    // the batch check. The guard moved — this test moved with it rather
    // than being dropped as "covered elsewhere".
    let blob = pruned_tx_hex();
    let doc = serde_json::json!({
        "status": "OK",
        "txs": [{
            "as_hex": "", "pruned_as_hex": blob, "prunable_as_hex": "",
            "prunable_hash": "00".repeat(32), "as_json": "",
            "in_pool": false, "double_spend_seen": false,
            "block_height": 1, "confirmations": 1, "block_timestamp": 0
        }]
    })
    .to_string();
    assert!(
        serde_json::from_str::<shekyl_rpc_types::GetTransactionsResponse>(&doc).is_err(),
        "an entry with no tx_hash must not decode"
    );
}

#[test]
fn parse_tx_batch_rejects_missing_pruned_blob() {
    let h0 = [3u8; 32];
    let txs = vec![tx_entry_with(h0, "", "")];
    assert!(matches!(
        parse_tx_batch(&[h0], &txs, TxBodyForm::Pruned),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn parse_tx_batch_empty_is_ok() {
    let out = parse_tx_batch(&[], &[], TxBodyForm::Pruned).expect("empty batch parses");
    assert!(out.is_empty());
}

#[test]
fn parse_tx_batch_full_form_reads_as_hex_with_pruned_fallback() {
    // The full form's primary field is the non-split `as_hex`; when the
    // daemon answers in the split form because the prunable section is
    // empty, `pruned_as_hex` IS the full body, so it is the accepted
    // fallback. (Our fixture's pruned form is a stripped spend, which the
    // full validator rejects — so the fallback leg uses the full blob under
    // the `pruned_as_hex` key, exactly the daemon's empty-prunable shape.)
    // Both slots carry the same full body, so both carry its real hash —
    // the leg under test is which FIELD the body arrives in, not identity.
    let full = full_spend_tx();
    let full_hex = hex::encode(full.serialize());
    let h = full.hash();
    let txs = vec![
        tx_entry_with(h, &full_hex, ""),
        tx_entry_with(h, "", &full_hex),
    ];
    let out = parse_tx_batch(&[h, h], &txs, TxBodyForm::Full).expect("full batch parses");
    assert_eq!(out.len(), 2);
    assert!(
        out.iter()
            .all(|tx| matches!(&tx.ct, Ct::Fcmp { prunable, .. } if prunable.is_some())),
        "full-form bodies carry their prunable section"
    );
}

#[test]
fn parse_full_tx_rejects_a_prunable_stripped_spend_naming_the_pruned_daemon() {
    // The fallback tripwire: a daemon answering a full-body request with
    // a storage-pruned spend (key-image inputs, prunable dropped) is
    // rejected at the ingestion boundary — it cannot survive to a bogus
    // null-prunable hash downstream. And because this exact shape is
    // what a storage-pruned daemon (a supported mode) serves for every
    // historical spend, the refusal must NAME that cause and its remedy
    // (rule 82) — a generic "invalid transaction" would tell the
    // operator their trusted node is corrupt, with no path out.
    let stripped_hex = pruned_tx_hex();
    match parse_full_tx(&stripped_hex, "") {
        Err(RpcError::InvalidNode(msg)) => {
            assert!(
                msg.contains("storage-pruned") && msg.contains("UNPRUNED"),
                "the refusal must name the pruned-daemon cause and remedy: {msg}"
            );
        }
        other => panic!("expected a cause-naming InvalidNode, got {other:?}"),
    }
    // The same blob is fine on the pruned path — the split is the form, not
    // the tx.
    parse_pruned_tx(&stripped_hex, "").expect("pruned form accepts the stripped spend");

    // A body that is malformed BEYOND the missing prunable section (a
    // single-output spend violates the anti-deanon minimum) keeps the
    // generic verdict — the pruned-daemon message must not blanket
    // genuinely invalid bodies.
    let mut malformed = pruned_spend_tx(0);
    malformed.prefix.outputs.truncate(1);
    if let Ct::Fcmp { base, .. } = &mut malformed.ct {
        base.enc_amounts.truncate(1);
        base.enc_labels.truncate(1);
        base.commitments.truncate(1);
    }
    match parse_full_tx(&hex::encode(malformed.serialize()), "") {
        Err(RpcError::InvalidNode(msg)) => {
            assert!(
                !msg.contains("storage-pruned"),
                "a malformed body must not draw the pruned-daemon verdict: {msg}"
            );
        }
        other => panic!("expected generic InvalidNode, got {other:?}"),
    }
}

#[test]
fn parse_tx_batch_full_form_requires_a_body_field() {
    let h0 = [3u8; 32];
    let txs = vec![tx_entry_with(h0, "", "")];
    assert!(matches!(
        parse_tx_batch(&[h0], &txs, TxBodyForm::Full),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn parse_tx_batch_empty_is_ok_full_form_too() {
    let out = parse_tx_batch(&[], &[], TxBodyForm::Full).expect("empty batch parses");
    assert!(out.is_empty());
}

/// Hex of a valid pruned non-miner spend with the given `unlock_time` — for the
/// block-height-only ingestion gate tests.
fn pruned_tx_hex_with_unlock_time(unlock_time: u64) -> String {
    hex::encode(pruned_spend_tx(unlock_time).serialize())
}

#[test]
fn parse_pruned_tx_rejects_timestamp_form_unlock_time() {
    // A structurally valid pruned tx whose `unlock_time` is the timestamp
    // form is non-canonical (consensus rejects it — GENESIS §9 creation
    // cut); ingestion must refuse it so the scanner never sees it.
    let bad = pruned_tx_hex_with_unlock_time(UNLOCK_TIME_BLOCK_SENTINEL);
    assert!(matches!(
        parse_pruned_tx(&bad, ""),
        Err(RpcError::InvalidNode(_))
    ));
    // The largest block-form value still parses.
    let ok = pruned_tx_hex_with_unlock_time(UNLOCK_TIME_BLOCK_SENTINEL - 1);
    assert!(parse_pruned_tx(&ok, "").is_ok());
}

#[test]
fn parse_pruned_tx_rejects_oversized_hex_before_decode() {
    // DoS pre-bound: a hex string longer than `2 * MAX_TX_SIZE` is rejected
    // by length before `hex::decode` allocates. All-hex chars of even
    // length, so only the length gate (not a decode error) can fire.
    let oversized = "0".repeat(MAX_TX_SIZE * 2 + 2);
    assert!(parse_pruned_tx(&oversized, "").is_err());
}

#[test]
fn parse_block_blob_rejects_oversized_hex_before_decode() {
    // DoS pre-bound: a hex string longer than `2 * MAX_BLOCK_BLOB_SIZE` is
    // rejected by length before `hex::decode` allocates. All-hex chars of
    // even length, so only the length gate (not a decode error) can fire.
    let oversized = "0".repeat(MAX_BLOCK_BLOB_SIZE * 2 + 2);
    assert!(matches!(
        parse_block_blob(&oversized, 0),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn parse_block_blob_rejects_timestamp_form_coinbase() {
    // Defense-in-depth: a canonical coinbase is `height + 60` (block form);
    // the timestamp form is rejected at ingestion too.
    let mut block = coinbase_block(5);
    block.miner_transaction.prefix.unlock_time = UNLOCK_TIME_BLOCK_SENTINEL;
    let blob = hex::encode(block.serialize());
    assert!(matches!(
        parse_block_blob(&blob, 5),
        Err(RpcError::InvalidNode(_))
    ));
}

#[test]
fn missed_tx_hashes_survive_the_typed_reply() {
    // `missed_tx` used to be walked entry-by-entry by `parse_missed_tx`.
    // It is `Vec<HashHex>` on the shared reply type now, so the walk is
    // gone — but the two properties it existed for are not, and they are
    // asserted here against the type that replaced it: valid hashes come
    // through in order, and a malformed entry is refused rather than
    // silently dropped, which would shrink the reported missing set and
    // misreport which transactions are absent.
    let (h0, h1) = ([3u8; 32], [4u8; 32]);
    let doc = |entries: String| format!(r#"{{"status":"OK","missed_tx":[{entries}]}}"#);
    let ok = doc(format!("\"{}\",\"{}\"", hex::encode(h0), hex::encode(h1)));
    let parsed: shekyl_rpc_types::GetTransactionsResponse =
        serde_json::from_str(&ok).expect("valid hashes decode");
    assert_eq!(
        parsed
            .missed_tx
            .iter()
            .copied()
            .map(shekyl_rpc_types::HashHex::to_bytes)
            .collect::<Vec<_>>(),
        vec![h0, h1]
    );

    for bad in ["\"zz\"", "\"00\"", "7", "null"] {
        let malformed = doc(format!("\"{}\",{bad}", hex::encode(h0)));
        assert!(
            serde_json::from_str::<shekyl_rpc_types::GetTransactionsResponse>(&malformed).is_err(),
            "a malformed missed_tx entry ({bad}) must be refused, not dropped"
        );
    }
}
