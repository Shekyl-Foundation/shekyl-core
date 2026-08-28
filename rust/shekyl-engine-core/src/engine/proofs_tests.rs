// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the Engine proofs workflow (`engine/proofs.rs`).
//!
//! Wired as a `#[path]` child of `proofs::tests`, so `use super::*`
//! resolves into the workflow module and private items stay testable;
//! the sibling file exists so the decomposition ratchet counts the
//! workflow file, not its test suite (the
//! `transfer/transfer_pending_tx_tests.rs` pattern).

use super::*;

use shekyl_address::Network;

fn test_address() -> ShekylAddress {
    ShekylAddress::new(
        Network::Mainnet,
        [0xAA; 32],
        [0xBB; 32],
        [0xEE; 48],
        vec![0xCC; 1184],
    )
}

// ── canonical address bytes ──────────────────────────────────────

#[test]
fn canonical_address_bytes_layout_is_pinned() {
    let addr = test_address();
    let bytes = canonical_address_bytes(&addr);
    assert_eq!(bytes.len(), 1 + 32 + 32 + 1184);
    assert_eq!(bytes[0], Network::Mainnet.as_u8());
    assert_eq!(&bytes[1..33], &[0xAA; 32]);
    assert_eq!(&bytes[33..65], &[0xBB; 32]);
    assert_eq!(&bytes[65..], &[0xCC; 1184][..]);
}

// ── tx-proof framing ─────────────────────────────────────────────

#[test]
fn tx_proof_direction_bytes_round_trip() {
    for d in [TxProofDirection::Outbound, TxProofDirection::Inbound] {
        assert_eq!(TxProofDirection::from_byte(d.byte()).unwrap(), d);
    }
    assert!(matches!(
        TxProofDirection::from_byte(0x00),
        Err(ProofsError::Malformed(_))
    ));
    assert!(matches!(
        TxProofDirection::from_byte(0x03),
        Err(ProofsError::Malformed(_))
    ));
}

#[test]
fn tx_proof_encoding_round_trips_direction_and_body() {
    let body = vec![0x42u8; 101];
    let encoded = encode_tx_proof(TxProofDirection::Outbound, &body).unwrap();
    let payload = decode_proof_payload(&encoded, HRP_TX_PROOF).unwrap();
    assert_eq!(payload[0], DIRECTION_OUTBOUND);
    assert_eq!(&payload[1..], &body[..]);
}

#[test]
fn decode_rejects_wrong_hrp() {
    let encoded = encode_blob(HRP_RESERVE_PROOF, &[1, 2, 3]).unwrap();
    assert!(matches!(
        decode_proof_payload(&encoded, HRP_TX_PROOF),
        Err(ProofsError::Malformed(_))
    ));
}

#[test]
fn decode_accepts_uppercase_reencoding() {
    let encoded = encode_tx_proof(TxProofDirection::Inbound, &[7u8; 10]).unwrap();
    let upper = encoded.to_uppercase();
    let payload = decode_proof_payload(&upper, HRP_TX_PROOF).unwrap();
    assert_eq!(payload[0], DIRECTION_INBOUND);
}

#[test]
fn decode_enforces_payload_size_cap() {
    let oversize = vec![0u8; MAX_DECODED_PROOF_BYTES + 1];
    let encoded = encode_blob(HRP_TX_PROOF, &oversize).unwrap();
    assert!(matches!(
        decode_proof_payload(&encoded, HRP_TX_PROOF),
        Err(ProofsError::Malformed(_))
    ));
}

// ── reserve locator framing ──────────────────────────────────────

fn locator_payload(locators: &[([u8; 32], u32)], proof: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::try_from(locators.len()).unwrap().to_le_bytes());
    for (txid, vout) in locators {
        payload.extend_from_slice(txid);
        payload.extend_from_slice(&vout.to_le_bytes());
    }
    payload.extend_from_slice(proof);
    payload
}

#[test]
fn reserve_locators_round_trip() {
    let locators = vec![([0x11; 32], 0u32), ([0x22; 32], 7u32)];
    let proof = vec![0xEE; 64];
    let payload = locator_payload(&locators, &proof);
    let (parsed, rest) = parse_reserve_locators(&payload).unwrap();
    assert_eq!(parsed, locators);
    assert_eq!(rest, &proof[..]);
}

#[test]
fn reserve_locators_reject_zero_count() {
    let payload = locator_payload(&[], &[0xEE; 8]);
    assert!(matches!(
        parse_reserve_locators(&payload),
        Err(ProofsError::Malformed(_))
    ));
}

#[test]
fn reserve_locators_enforce_count_cap_before_parsing() {
    // Claims u32::MAX locators with a tiny body: must refuse on the
    // count alone (the four-billion-fetch amplification lever).
    let mut payload = u32::MAX.to_le_bytes().to_vec();
    payload.extend_from_slice(&[0u8; 40]);
    assert!(matches!(
        parse_reserve_locators(&payload),
        Err(ProofsError::Malformed(_))
    ));
}

#[test]
fn reserve_locators_reject_truncated_section() {
    // Claims 2 locators but carries only one.
    let mut payload = 2u32.to_le_bytes().to_vec();
    payload.extend_from_slice(&[0x11; LOCATOR_BYTES]);
    assert!(matches!(
        parse_reserve_locators(&payload),
        Err(ProofsError::Malformed(_))
    ));
}

// ── reserve selection policy ─────────────────────────────────────

fn candidate(tag: u8, amount: u64) -> ReserveCandidate {
    ReserveCandidate {
        txid: [tag; 32],
        vout: u32::from(tag),
        amount: AtomicUnits::from_raw(amount),
        ciphertext: HybridCiphertext {
            x25519: [tag; 32],
            ml_kem: vec![tag; 4],
        },
        key_image: KeyImage::from_canonical_bytes([tag; 32]),
        output_key: [tag; 32],
    }
}

#[test]
fn selection_is_largest_first_and_minimal_for_amount_bounds() {
    let candidates = vec![candidate(1, 100), candidate(2, 500), candidate(3, 300)];
    let (selected, total) =
        select_reserve_outputs(candidates, Some(AtomicUnits::from_raw(600))).unwrap();
    // 500 + 300 covers 600; the 100 output stays undisclosed.
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].amount, AtomicUnits::from_raw(500));
    assert_eq!(selected[1].amount, AtomicUnits::from_raw(300));
    assert_eq!(total, AtomicUnits::from_raw(800));
}

#[test]
fn selection_prove_all_takes_everything() {
    let candidates = vec![candidate(1, 100), candidate(2, 500)];
    let (selected, total) = select_reserve_outputs(candidates, None).unwrap();
    assert_eq!(selected.len(), 2);
    assert_eq!(total, AtomicUnits::from_raw(600));
}

#[test]
fn selection_refuses_insufficient_total() {
    let candidates = vec![candidate(1, 100)];
    assert!(matches!(
        select_reserve_outputs(candidates, Some(AtomicUnits::from_raw(200))),
        Err(ProofsError::NoProvableOutputs(_))
    ));
}

#[test]
fn selection_refuses_empty_candidate_set() {
    assert!(matches!(
        select_reserve_outputs(Vec::new(), None),
        Err(ProofsError::NoProvableOutputs(_))
    ));
}

#[test]
fn selection_refuses_zero_amount_target() {
    // A zero target is "covered" before anything is selected; the
    // empty selection must refuse as NoProvableOutputs here rather
    // than reach the key actor with zero entries and surface as an
    // internal key-engine error.
    let candidates = vec![candidate(1, 100)];
    assert!(matches!(
        select_reserve_outputs(candidates, Some(AtomicUnits::ZERO)),
        Err(ProofsError::NoProvableOutputs(_))
    ));
}

// ── KeyEngineError → ProofsError mapping ─────────────────────────

#[test]
fn key_engine_proof_errors_keep_their_typed_class() {
    // The KeyEngineError::Proof wrap exists so structural proof
    // rejections stay discriminable from crypto failures: it must
    // map to the typed Generate arm, not stringify into Key.
    let structural =
        KeyEngineError::Proof(ProofError::InvalidFormat("no outputs specified".into()));
    assert!(matches!(
        ProofsError::from(structural),
        ProofsError::Generate(ProofError::InvalidFormat(_))
    ));

    // Every other actor failure stays in the rendered Key class.
    let stopped = KeyEngineError::KeyActorUnavailable;
    assert!(matches!(ProofsError::from(stopped), ProofsError::Key(_)));
}

// ── wallet-less check workflows over a mock daemon ───────────────
//
// End-to-end round trips for `check_tx_proof` / `check_reserve_proof`:
// real key material (`LocalKeys::from_test_seed`), real constructed
// outputs, a real serialized pruned wire transaction served by a mock
// `Rpc`, and the full Bech32m + locator framing in between. This is
// the WI-RPC-3 generate→check gate at the workflow layer (the RPC
// handler above it is a thin parameter mapper with its own tests).
mod check_workflows {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    use shekyl_proofs::tx_proof::generate_outbound_proof;

    use shekyl_crypto_pq::output::{
        compute_output_key_image, construct_output, recover_combined_ss, OutputData,
    };
    use shekyl_curve_generators::biased_hash_to_point;
    use shekyl_scanner::extra::ExtraField;
    use shekyl_wire::{CtBase, Input, Output, TxPrefix};

    use crate::engine::local_keys::LocalKeys;
    use crate::engine::proof_bridge;

    /// Deterministic wallet under test (testnet raw-seed derivation).
    const TEST_SEED: [u8; 32] = [0xA7; 32];
    /// Sender-side tx key for `construct_output` — the retained
    /// secret an OUTBOUND proof signs with.
    const TX_KEY_SECRET: [u8; 32] = [11u8; 32];
    /// Challenge message bound into every generated proof.
    const MSG: &str = "WI-RPC-3 check round trip";
    /// Mock daemon chain height (block COUNT, per `get_height`).
    const CHAIN_HEIGHT: usize = 108;
    /// The fixture tx's 0-based block height; with the height above
    /// the contract pin yields 8 confirmations.
    const TX_BLOCK_HEIGHT: u64 = 100;
    /// Amounts paid to the wallet at vout 0 and vout 1.
    const AMOUNTS: [u64; 2] = [5_000, 7_500];

    /// Canned daemon: serves `get_transactions` (pruned bodies by
    /// txid hex, `missed_tx` for anything else), `get_height`, and
    /// `is_key_image_spent` from fixed tables. Counts
    /// `get_transactions` calls so tests can pin the batching
    /// behavior (one chunked call, not one call per txid).
    #[derive(Clone)]
    struct MockRpc {
        /// txid hex → pruned body hex.
        txs: Arc<BTreeMap<String, String>>,
        /// `is_key_image_spent` reply, positional (0 = unspent).
        spent_status: Arc<Vec<u64>>,
        height: usize,
        /// Number of `get_transactions` requests served.
        get_transactions_calls: Arc<AtomicUsize>,
    }

    impl Rpc for MockRpc {
        async fn post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
            let reply = match route {
                // Built from the wire type for the same reason `get_height`
                // below is — and this one is the proof the reason is real. It
                // was a `json!` literal until RK-4c, and the moment the reader
                // became typed the literal stopped decoding: it named four
                // fields where the contract has nine. A double that cannot
                // express the reply is a double that was never checked against
                // it.
                "get_transactions" => {
                    self.get_transactions_calls.fetch_add(1, Ordering::SeqCst);
                    let req: shekyl_rpc_types::GetTransactionsRequest =
                        serde_json::from_slice(&body).expect("request decodes");
                    let mut txs = Vec::new();
                    let mut missed = Vec::new();
                    for h in &req.txs_hashes {
                        match self.txs.get(h.as_str()) {
                            Some(body_hex) => txs.push(shekyl_rpc_types::TxEntry {
                                tx_hash: shekyl_rpc_types::HashHex::from_hex(h)
                                    .expect("txid is 32 bytes of hex"),
                                as_hex: String::new(),
                                pruned_as_hex: (*body_hex).clone(),
                                prunable_as_hex: String::new(),
                                prunable_hash: shekyl_rpc_types::HashHex::ZERO,
                                as_json: String::new(),
                                pruned: false,
                                double_spend_seen: false,
                                location: shekyl_rpc_types::TxLocation::Mined {
                                    block_height: TX_BLOCK_HEIGHT,
                                    confirmations: 1,
                                    block_timestamp: 0,
                                    output_indices: Vec::new(),
                                },
                            }),
                            None => missed.push(
                                shekyl_rpc_types::HashHex::from_hex(h)
                                    .expect("txid is 32 bytes of hex"),
                            ),
                        }
                    }
                    serde_json::to_value(shekyl_rpc_types::GetTransactionsResponse {
                        status: shekyl_rpc_types::RpcStatus::ok(),
                        txs_as_hex: Vec::new(),
                        txs_as_json: Vec::new(),
                        txs,
                        missed_tx: missed,
                    })
                    .expect("wire type serializes")
                }
                // Built from the daemon's own wire type, not a JSON literal:
                // the compiler holds this double to the contract's field set
                // (a hand-written `{"height": ..}` once drifted and was only
                // caught when the typed reader refused it).
                "get_height" => serde_json::to_value(shekyl_rpc_types::GetHeightResponse {
                    status: shekyl_rpc_types::RpcStatus::ok(),
                    height: self.height as u64,
                    hash: shekyl_rpc_types::HashHex::ZERO,
                })
                .expect("wire type serializes"),
                "is_key_image_spent" => {
                    let req: shekyl_rpc_types::IsKeyImageSpentRequest =
                        serde_json::from_slice(&body).expect("request decodes");
                    let statuses: Vec<shekyl_rpc_types::KeyImageStatus> = (0..req.key_images.len())
                        .map(|i| {
                            let raw = self.spent_status.get(i).copied().unwrap_or(0);
                            shekyl_rpc_types::KeyImageStatus::try_from(
                                u8::try_from(raw).expect("fixture status is 0..2"),
                            )
                            .expect("fixture status is a defined state")
                        })
                        .collect();
                    serde_json::to_value(shekyl_rpc_types::IsKeyImageSpentResponse {
                        status: shekyl_rpc_types::RpcStatus::ok(),
                        spent_status: statuses,
                    })
                    .expect("wire type serializes")
                }
                other => panic!("mock daemon received unexpected route {other}"),
            };
            Ok(reply.to_string().into_bytes())
        }
    }

    struct CheckFixture {
        local: LocalKeys,
        address: ShekylAddress,
        txid: [u8; 32],
        outputs: Vec<OutputData>,
        rpc: MockRpc,
    }

    fn ciphertext_of(od: &OutputData) -> HybridCiphertext {
        HybridCiphertext {
            x25519: od.kem_ciphertext_x25519,
            ml_kem: od.kem_ciphertext_ml_kem.clone(),
        }
    }

    /// Build the wallet, a canonical 2-output pruned spend paying it
    /// at vout 0 and 1, and a mock daemon serving that tx.
    fn make_fixture(spent_status: Vec<u64>) -> CheckFixture {
        let local = LocalKeys::from_test_seed(TEST_SEED);
        let keys = &local.keys;

        let outputs: Vec<OutputData> = AMOUNTS
            .iter()
            .enumerate()
            .map(|(i, &amount)| {
                construct_output(
                    &TX_KEY_SECRET,
                    &keys.x25519_pk,
                    &keys.ml_kem_ek,
                    keys.spend_pk.as_canonical_bytes(),
                    amount,
                    u64::try_from(i).unwrap(),
                )
                .expect("construct_output succeeds for synthetic outputs")
            })
            .collect();

        // One concatenated hybrid KEM blob (x25519 ‖ ml_kem per
        // output, vout order) in a single 0x06 extra field — the
        // layout `on_chain_outputs_of` slices at the scanner's
        // offsets.
        let mut kem_blob = Vec::new();
        for od in &outputs {
            kem_blob.extend_from_slice(&od.kem_ciphertext_x25519);
            kem_blob.extend_from_slice(&od.kem_ciphertext_ml_kem);
        }
        let extra = ExtraField::PqcKemCiphertext(kem_blob).serialize();

        let tx = Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::ToKey {
                    amount: 0,
                    key_offsets: vec![],
                    key_image: [0x42u8; 32],
                }],
                outputs: outputs
                    .iter()
                    .map(|od| Output {
                        amount: 0,
                        key: od.output_key,
                        view_tag: od.view_tag_prefilter,
                    })
                    .collect(),
                extra,
            },
            ct: Ct::Fcmp {
                fee: 0,
                reference_block: [0u8; 32],
                base: CtBase {
                    enc_amounts: outputs
                        .iter()
                        .map(|od| od.enc_amount_wire().to_bytes())
                        .collect(),
                    enc_labels: outputs
                        .iter()
                        .map(|od| od.enc_label_wire().to_bytes())
                        .collect(),
                    commitments: outputs.iter().map(|od| od.commitment).collect(),
                },
                pqc_auths: vec![],
                prunable: None,
            },
        };

        // The pruned form is associated by the daemon's `tx_hash`
        // label, not by re-hashing (`parse_tx_batch`'s contract), so
        // a fixed txid keeps the fixture simple.
        let txid = [0x77u8; 32];
        let mut txs = BTreeMap::new();
        txs.insert(hex::encode(txid), hex::encode(tx.serialize()));

        let address = keys.to_address(Network::Testnet);

        CheckFixture {
            address,
            txid,
            outputs,
            rpc: MockRpc {
                txs: Arc::new(txs),
                spent_status: Arc::new(spent_status),
                height: CHAIN_HEIGHT,
                get_transactions_calls: Arc::new(AtomicUsize::new(0)),
            },
            local,
        }
    }

    /// Generate the wallet's INBOUND proof over both fixture outputs
    /// and frame it exactly as the workflow does.
    fn inbound_proof_string(fx: &CheckFixture) -> String {
        let bytes = proof_bridge::generate_inbound_proof(
            &fx.local,
            &InboundProofRequest {
                txid: fx.txid,
                address_bytes: canonical_address_bytes(&fx.address),
                message: MSG.as_bytes().to_vec(),
                outputs: fx
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(i, od)| InboundProofOutput {
                        vout_index: u32::try_from(i).unwrap(),
                        ciphertext: ciphertext_of(od),
                    })
                    .collect(),
            },
        )
        .expect("inbound generation succeeds");
        encode_tx_proof(TxProofDirection::Inbound, &bytes).expect("bech32m encode")
    }

    /// The wallet's canonical key image for a fixture output —
    /// recipient-side decap + `x = ho + b` key-image computation,
    /// the same chain the claim path runs.
    fn key_image_of(fx: &CheckFixture, vout: u64) -> KeyImage {
        let od = &fx.outputs[usize::try_from(vout).unwrap()];
        let keys = &fx.local.keys;
        let ss = recover_combined_ss(
            keys.view_sk.as_canonical_bytes(),
            keys.ml_kem_dk.as_canonical_bytes(),
            &od.kem_ciphertext_x25519,
            &od.kem_ciphertext_ml_kem,
        )
        .expect("decap of a self-paid ciphertext succeeds");
        let hp = biased_hash_to_point(od.output_key).compress().to_bytes();
        compute_output_key_image(&ss.0, vout, keys.spend_sk.as_canonical_bytes(), &hp)
            .expect("key image computes")
            .key_image
    }

    /// Generate a reserve proof over both fixture outputs and frame
    /// it (locator section + Bech32m) exactly as the workflow does.
    fn reserve_proof_string(fx: &CheckFixture) -> String {
        let bytes = proof_bridge::generate_reserve_proof(
            &fx.local,
            &ReserveProofRequest {
                address_bytes: canonical_address_bytes(&fx.address),
                message: MSG.as_bytes().to_vec(),
                outputs: fx
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(i, od)| {
                        let vout = u64::try_from(i).unwrap();
                        ReserveProofOutput {
                            vout_index: vout,
                            ciphertext: ciphertext_of(od),
                            key_image: key_image_of(fx, vout),
                            output_key: od.output_key,
                        }
                    })
                    .collect(),
            },
        )
        .expect("reserve generation succeeds");
        let payload = locator_payload(&[(fx.txid, 0), (fx.txid, 1)], &bytes);
        encode_blob(HRP_RESERVE_PROOF, &payload).expect("bech32m encode")
    }

    #[tokio::test]
    async fn check_inbound_tx_proof_round_trips_over_the_mock_daemon() {
        let fx = make_fixture(vec![]);
        let proof = inbound_proof_string(&fx);

        let checked = check_tx_proof(&fx.rpc, fx.txid, &fx.address, MSG, &proof)
            .await
            .expect("check succeeds");
        let CheckedTxProof::Valid {
            direction,
            received,
            outputs,
            in_pool,
            confirmations,
        } = checked
        else {
            panic!("expected Valid, got Invalid");
        };
        assert_eq!(direction, TxProofDirection::Inbound);
        assert_eq!(received, AtomicUnits::from_raw(12_500));
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].output_index, 0);
        assert_eq!(outputs[0].amount, AtomicUnits::from_raw(5_000));
        assert_eq!(outputs[1].output_index, 1);
        assert_eq!(outputs[1].amount, AtomicUnits::from_raw(7_500));
        assert!(!in_pool);
        // Contract pin: chain height (block count) minus 0-based
        // block height — 108 - 100 = 8.
        assert_eq!(confirmations, CHAIN_HEIGHT as u64 - TX_BLOCK_HEIGHT);
    }

    #[tokio::test]
    async fn check_outbound_tx_proof_round_trips_over_the_mock_daemon() {
        let fx = make_fixture(vec![]);
        let keys = &fx.local.keys;
        // The sender's side: sign with the (retained) tx key over
        // both outputs, exactly what `generate_outbound` produces
        // after vout discovery.
        let bytes = generate_outbound_proof(
            &TX_KEY_SECRET,
            &fx.txid,
            &canonical_address_bytes(&fx.address),
            MSG.as_bytes(),
            &keys.x25519_pk,
            &keys.ml_kem_ek,
            &[0, 1],
        )
        .expect("outbound generation succeeds");
        let proof = encode_tx_proof(TxProofDirection::Outbound, &bytes).expect("bech32m encode");

        let checked = check_tx_proof(&fx.rpc, fx.txid, &fx.address, MSG, &proof)
            .await
            .expect("check succeeds");
        let CheckedTxProof::Valid {
            direction,
            received,
            outputs,
            ..
        } = checked
        else {
            panic!("expected Valid, got Invalid");
        };
        assert_eq!(direction, TxProofDirection::Outbound);
        assert_eq!(received, AtomicUnits::from_raw(12_500));
        assert_eq!(outputs.len(), 2);
    }

    #[tokio::test]
    async fn check_tx_proof_with_a_tampered_message_is_invalid_not_error() {
        let fx = make_fixture(vec![]);
        let proof = inbound_proof_string(&fx);

        let checked = check_tx_proof(&fx.rpc, fx.txid, &fx.address, "a different message", &proof)
            .await
            .expect("the method answers the question rather than erroring");
        assert!(matches!(checked, CheckedTxProof::Invalid));
    }

    #[tokio::test]
    async fn check_tx_proof_against_the_wrong_address_is_invalid() {
        let fx = make_fixture(vec![]);
        let proof = inbound_proof_string(&fx);

        // A different wallet's address: same network, wrong keys.
        let other = LocalKeys::from_test_seed([0x5C; 32]);
        let wrong = other.keys.to_address(Network::Testnet);

        let checked = check_tx_proof(&fx.rpc, fx.txid, &wrong, MSG, &proof)
            .await
            .expect("check succeeds");
        assert!(matches!(checked, CheckedTxProof::Invalid));
    }

    #[tokio::test]
    async fn check_tx_proof_for_an_unknown_txid_is_tx_not_found() {
        let fx = make_fixture(vec![]);
        let proof = inbound_proof_string(&fx);

        let err = check_tx_proof(&fx.rpc, [0x99; 32], &fx.address, MSG, &proof)
            .await
            .expect_err("unknown txid refuses");
        assert!(matches!(err, ProofsError::TxNotFound(_)));
    }

    #[tokio::test]
    async fn check_tx_proof_with_a_corrupted_string_is_malformed() {
        let fx = make_fixture(vec![]);
        let mut proof = inbound_proof_string(&fx);
        // Flip the final data character: Bech32m's checksum refuses.
        let last = proof.pop().expect("proof string is non-empty");
        proof.push(if last == 'q' { 'p' } else { 'q' });

        let err = check_tx_proof(&fx.rpc, fx.txid, &fx.address, MSG, &proof)
            .await
            .expect_err("corrupted string refuses");
        assert!(matches!(err, ProofsError::Malformed(_)));
    }

    #[tokio::test]
    async fn check_reserve_proof_round_trips_and_reports_the_spent_portion() {
        // The daemon reports vout 1 (7,500) spent: the proof still
        // verifies, and the spent portion is reported for
        // subtraction (the contract's live-reserve semantics).
        let fx = make_fixture(vec![0, 1]);
        let proof = reserve_proof_string(&fx);

        let checked = check_reserve_proof(&fx.rpc, &fx.address, MSG, &proof)
            .await
            .expect("check succeeds");
        let CheckedReserveProof::Valid {
            total,
            spent,
            output_count,
        } = checked
        else {
            panic!("expected Valid, got Invalid");
        };
        assert_eq!(total, AtomicUnits::from_raw(12_500));
        assert_eq!(spent, AtomicUnits::from_raw(7_500));
        assert_eq!(output_count, 2);

        // Message binding: a tampered challenge is Invalid, not an
        // error.
        let tampered = check_reserve_proof(&fx.rpc, &fx.address, "not the message", &proof)
            .await
            .expect("the method answers the question rather than erroring");
        assert!(matches!(tampered, CheckedReserveProof::Invalid));
    }

    #[tokio::test]
    async fn check_reserve_proof_locator_out_of_range_is_malformed() {
        let fx = make_fixture(vec![]);
        // Valid proof bytes, but the second locator names vout 7 of
        // a 2-output tx.
        let decoded = decode_proof_payload(&reserve_proof_string(&fx), HRP_RESERVE_PROOF)
            .expect("fixture proof decodes");
        let (_, proof_bytes) = parse_reserve_locators(&decoded).expect("fixture parses");
        let payload = locator_payload(&[(fx.txid, 0), (fx.txid, 7)], proof_bytes);
        let proof = encode_blob(HRP_RESERVE_PROOF, &payload).expect("bech32m encode");

        let err = check_reserve_proof(&fx.rpc, &fx.address, MSG, &proof)
            .await
            .expect_err("out-of-range locator refuses");
        assert!(matches!(err, ProofsError::Malformed(_)));
    }

    #[tokio::test]
    async fn check_reserve_proof_duplicated_output_is_malformed_not_doubled() {
        // F-13 regression: a proof listing the SAME unspent output
        // twice — every entry verifies (same output key, same DLEQ,
        // same x), the spent set reports both copies unspent, and
        // without the key-image uniqueness guard the proven reserve
        // would be 2x the real balance. The verifier must refuse
        // (Malformed), not double `total`.
        let fx = make_fixture(vec![]);
        let dup = |vout: u64| {
            let od = &fx.outputs[usize::try_from(vout).unwrap()];
            ReserveProofOutput {
                vout_index: vout,
                ciphertext: ciphertext_of(od),
                key_image: key_image_of(&fx, vout),
                output_key: od.output_key,
            }
        };
        let bytes = proof_bridge::generate_reserve_proof(
            &fx.local,
            &ReserveProofRequest {
                address_bytes: canonical_address_bytes(&fx.address),
                message: MSG.as_bytes().to_vec(),
                outputs: vec![dup(0), dup(0)],
            },
        )
        .expect("generation is per-entry and does not itself dedup");
        let payload = locator_payload(&[(fx.txid, 0), (fx.txid, 0)], &bytes);
        let proof = encode_blob(HRP_RESERVE_PROOF, &payload).expect("bech32m encode");

        let err = check_reserve_proof(&fx.rpc, &fx.address, MSG, &proof)
            .await
            .expect_err("duplicated output refuses instead of inflating the reserve");
        assert!(matches!(err, ProofsError::Malformed(_)));
    }

    #[tokio::test]
    async fn check_reserve_proof_batches_unique_tx_fetches_into_one_call() {
        // F2 regression: locators spanning multiple txids must
        // resolve in chunked batched get_transactions calls, not
        // one awaited call per unique txid.
        let mut fx = make_fixture(vec![]);
        // Serve the same pruned body under a second txid (the
        // pruned form is associated by the daemon's tx_hash label,
        // not by re-hashing) so the locators span two txids whose
        // on-chain outputs still match the proof entries.
        let txid2 = [0x78u8; 32];
        let body = fx.rpc.txs[&hex::encode(fx.txid)].clone();
        let mut txs = (*fx.rpc.txs).clone();
        txs.insert(hex::encode(txid2), body);
        fx.rpc.txs = Arc::new(txs);

        let decoded = decode_proof_payload(&reserve_proof_string(&fx), HRP_RESERVE_PROOF)
            .expect("fixture proof decodes");
        let (_, proof_bytes) = parse_reserve_locators(&decoded).expect("fixture parses");
        let payload = locator_payload(&[(fx.txid, 0), (txid2, 1)], proof_bytes);
        let proof = encode_blob(HRP_RESERVE_PROOF, &payload).expect("bech32m encode");

        let checked = check_reserve_proof(&fx.rpc, &fx.address, MSG, &proof)
            .await
            .expect("check succeeds");
        assert!(matches!(checked, CheckedReserveProof::Valid { .. }));
        // Two unique txids fit one TXS_PER_REQUEST chunk: exactly
        // one get_transactions round trip.
        assert_eq!(fx.rpc.get_transactions_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fetch_proof_txs_chunks_at_the_daemon_batch_cap() {
        // 250 unique txids must resolve in ceil(250 / 100) = 3
        // batched calls (TXS_PER_REQUEST = 100), not 250.
        let fx = make_fixture(vec![]);
        let body = fx.rpc.txs[&hex::encode(fx.txid)].clone();
        let mut txs = BTreeMap::new();
        let mut ids: Vec<[u8; 32]> = Vec::with_capacity(250);
        for i in 0..250u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_le_bytes());
            ids.push(id);
            txs.insert(hex::encode(id), body.clone());
        }
        let rpc = MockRpc {
            txs: Arc::new(txs),
            spent_status: Arc::new(vec![]),
            height: CHAIN_HEIGHT,
            get_transactions_calls: Arc::new(AtomicUsize::new(0)),
        };

        let bodies = fetch_proof_txs(&rpc, &ids).await.expect("all txs served");
        assert_eq!(bodies.len(), 250);
        assert_eq!(rpc.get_transactions_calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn check_reserve_proof_unknown_locator_txid_is_tx_not_found() {
        // Batched fetching must preserve the per-tx error
        // semantics: a locator naming a txid the daemon does not
        // know refuses TxNotFound carrying that txid.
        let fx = make_fixture(vec![]);
        let decoded = decode_proof_payload(&reserve_proof_string(&fx), HRP_RESERVE_PROOF)
            .expect("fixture proof decodes");
        let (_, proof_bytes) = parse_reserve_locators(&decoded).expect("fixture parses");
        let unknown = [0x99u8; 32];
        let payload = locator_payload(&[(unknown, 0), (fx.txid, 1)], proof_bytes);
        let proof = encode_blob(HRP_RESERVE_PROOF, &payload).expect("bech32m encode");

        let err = check_reserve_proof(&fx.rpc, &fx.address, MSG, &proof)
            .await
            .expect_err("unknown locator txid refuses");
        match err {
            ProofsError::TxNotFound(hex) => assert_eq!(hex, hex::encode(unknown)),
            other => panic!("expected TxNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn discovered_secrets_generate_a_verifying_outbound_proof() {
        // F3 regression: the OUTBOUND generation path reuses the
        // shared secrets derived during recipient-output discovery
        // (one hybrid-KEM run per output, not two). The
        // with-secrets proof must be byte-identical to the
        // derive-again entry point outside the randomized 64-byte
        // Schnorr signature at [33..97), and must verify.
        let fx = make_fixture(vec![]);
        let keys = &fx.local.keys;
        let fetched = fetch_proof_tx(&fx.rpc, fx.txid)
            .await
            .expect("fixture tx fetches");
        let on_chain = on_chain_outputs_of(&fetched.tx).expect("outputs project");

        let discovered =
            discover_recipient_outputs(&TX_KEY_SECRET, &keys.x25519_pk, &keys.ml_kem_ek, &on_chain);
        let vouts: Vec<u64> = discovered.iter().map(|(i, _)| *i).collect();
        assert_eq!(vouts, vec![0, 1], "both fixture outputs pay the wallet");

        let address_bytes = canonical_address_bytes(&fx.address);
        let with_secrets = generate_outbound_proof_with_secrets(
            &TX_KEY_SECRET,
            &fx.txid,
            &address_bytes,
            MSG.as_bytes(),
            &discovered,
        )
        .expect("with-secrets generation succeeds");
        let rederived = generate_outbound_proof(
            &TX_KEY_SECRET,
            &fx.txid,
            &address_bytes,
            MSG.as_bytes(),
            &keys.x25519_pk,
            &keys.ml_kem_ek,
            &vouts,
        )
        .expect("derive-again generation succeeds");

        assert_eq!(with_secrets.len(), rederived.len());
        assert_eq!(with_secrets[..33], rederived[..33]);
        assert_eq!(with_secrets[97..], rederived[97..]);

        let verified = verify_outbound_proof(
            &with_secrets,
            &fx.txid,
            &address_bytes,
            MSG.as_bytes(),
            keys.spend_pk.as_canonical_bytes(),
            &keys.x25519_pk,
            &keys.ml_kem_ek,
            &on_chain,
        )
        .expect("with-secrets proof verifies");
        assert_eq!(verified.len(), 2);
    }
}
