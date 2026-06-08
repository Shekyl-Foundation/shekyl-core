// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Gate-2 serve-credit KAT (`fixtures/gate2_serve_credit_kat_v1.json`).
//!
//! Tripwires challenge replay, path encoding, signature preimage, and full vin
//! wire bytes. Regenerate with:
//! `cargo test -p shekyl-archival-retention regenerate_gate2_kat_fixture -- --ignored --nocapture`

use std::path::PathBuf;

use serde_json::{json, Value};
use shekyl_archival_retention::{
    challenge_fire_height, challenge_leaf_index, challenge_seal_height, encode_path,
    p_canonical_id_from_hybrid_pubkey, verify_leaf_index, verify_segment_path,
    ArchivalServeCreditResponse, SegmentPathOpening, SETTLEMENT_EPOCH_BLOCKS,
};
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, HybridSignature, SignatureScheme,
};
use shekyl_archival_retention::VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE;
use shekyl_curve_tree::{
    BlockLeaves, ChunkLeaf, CurveTreeClient, OutputIdentity, RawOutput, ReferenceBlock,
    TargetKind, TxLeafInputs,
};
use shekyl_fcmp::tree::{construct_leaf, ed25519_point_to_selene_scalar};

const CT2_FIXTURE: &str = include_str!("../../shekyl-curve-tree/tests/fixtures/ct2_tier_a.json");
const KAT_FIXTURE: &str = include_str!("fixtures/gate2_serve_credit_kat_v1.json");

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn decode_hex32(s: &str) -> [u8; 32] {
    let v = decode_hex(s);
    assert_eq!(v.len(), 32);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn decode_hex128(s: &str) -> [u8; 128] {
    let v = decode_hex(s);
    assert_eq!(v.len(), 128);
    let mut a = [0u8; 128];
    a.copy_from_slice(&v);
    a
}

fn layers_to_json(layers: &[Vec<[u8; 32]>]) -> Value {
    Value::Array(
        layers
            .iter()
            .map(|branch| {
                Value::Array(
                    branch
                        .iter()
                        .map(|scalar| Value::String(encode_hex(scalar)))
                        .collect(),
                )
            })
            .collect(),
    )
}

fn layers_from_json(v: &Value) -> Vec<Vec<[u8; 32]>> {
    v.as_array()
        .expect("layer array")
        .iter()
        .map(|branch| {
            branch
                .as_array()
                .expect("branch array")
                .iter()
                .map(|scalar| {
                    let bytes = decode_hex(scalar.as_str().expect("scalar hex"));
                    assert_eq!(bytes.len(), 32);
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&bytes);
                    a
                })
                .collect()
        })
        .collect()
}

fn settlement_epoch_open_height(settlement_epoch: u64) -> u64 {
    settlement_epoch.saturating_mul(SETTLEMENT_EPOCH_BLOCKS)
}

fn settlement_epoch_close_height(settlement_epoch: u64) -> u64 {
    settlement_epoch_open_height(settlement_epoch)
        .saturating_add(SETTLEMENT_EPOCH_BLOCKS.saturating_sub(1))
}

fn integration_keypair(
    pinned_pk_hex: Option<&str>,
    pinned_sk_hex: Option<&str>,
) -> (HybridPublicKey, HybridSecretKey) {
    if let (Some(pk_hex), Some(sk_hex)) = (pinned_pk_hex, pinned_sk_hex) {
        let pk = HybridPublicKey::from_canonical_bytes(&decode_hex(pk_hex)).expect("integration pk");
        let sk = HybridSecretKey::from_canonical_bytes(&decode_hex(sk_hex)).expect("integration sk");
        return (pk, sk);
    }
    HybridEd25519MlDsa.keypair_generate().expect("integration keypair")
}

fn flat_layer_scalars_hex(scalars: &[[u8; 32]]) -> String {
    encode_hex(&scalars.iter().flat_map(|s| s.iter().copied()).collect::<Vec<_>>())
}

fn build_integration_from_pinned_wire(
    wire_hex: &str,
    bond_hybrid_pubkey_hex: &str,
    leaf_layer_scalars_hex: &str,
) -> Value {
    let wire = decode_hex(wire_hex);
    assert_eq!(wire[0], VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE);
    let mut cursor = std::io::Cursor::new(&wire[1..]);
    let response =
        ArchivalServeCreditResponse::read_payload(&mut cursor).expect("pinned integration wire");

    let layer_scalars: Vec<[u8; 32]> = decode_hex(leaf_layer_scalars_hex)
        .chunks_exact(32)
        .map(|chunk| {
            let mut s = [0u8; 32];
            s.copy_from_slice(chunk);
            s
        })
        .collect();
    verify_segment_path(
        &response.leaf_bytes,
        &layer_scalars,
        &response.path,
        &response.segment_subroot_rk,
    )
    .expect("pinned integration path");

    let block_hash_at_seal = [0xABu8; 32];
    let settlement_epoch = response.settlement_epoch;
    let h_open = settlement_epoch_open_height(settlement_epoch);
    let h_close = settlement_epoch_close_height(settlement_epoch);
    let h_seal = challenge_seal_height(h_open);
    let h_fire = challenge_fire_height(
        h_open,
        h_close,
        &block_hash_at_seal,
        &response.p_canonical_id,
        response.shard_id,
        settlement_epoch,
    );

    json!({
        "label": "ct2_opening_epoch1_consensus_verify",
        "p_canonical_id_hex": encode_hex(&response.p_canonical_id),
        "shard_id": response.shard_id,
        "settlement_epoch": response.settlement_epoch,
        "segment_leaf_count": 26_000u64,
        "leaf_index_in_segment": response.leaf_index_in_segment,
        "freeze_height": h_fire,
        "h_open": h_open,
        "h_close": h_close,
        "h_seal": h_seal,
        "h_fire": h_fire,
        "current_height": h_fire.saturating_add(1),
        "block_hash_at_seal_hex": encode_hex(&block_hash_at_seal),
        "join_settlement_epoch": 0,
        "bond_hybrid_pubkey_hex": bond_hybrid_pubkey_hex,
        "leaf_layer_scalars_hex": leaf_layer_scalars_hex,
        "wire_hex": wire_hex,
    })
}

fn build_integration_substrate(
    pinned_pk_hex: Option<&str>,
    pinned_sk_hex: Option<&str>,
) -> Value {
    let scheme = HybridEd25519MlDsa;
    let (hybrid_pk, hybrid_sk) = integration_keypair(pinned_pk_hex, pinned_sk_hex);
    let hybrid_pk_bytes = hybrid_pk.to_canonical_bytes().expect("pk bytes");
    let _hybrid_sk_bytes = hybrid_sk.to_canonical_bytes().expect("sk bytes");
    let p_id = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes);

    let (leaf_bytes, rk, path, layer_scalars) = ct2_founder_opening();
    let shard_id = 42u64;
    // Consensus requires settlement_epoch >= join_settlement_epoch + 1; join at 0 ⇒ first credit at 1.
    let settlement_epoch = 1u64;
    let segment_leaf_count = 26_000u64;
    let leaf_index = challenge_leaf_index(&p_id, shard_id, settlement_epoch, segment_leaf_count);

    let block_hash_at_seal = [0xABu8; 32];
    let h_open = settlement_epoch_open_height(settlement_epoch);
    let h_close = settlement_epoch_close_height(settlement_epoch);
    let h_seal = challenge_seal_height(h_open);
    let h_fire = challenge_fire_height(
        h_open,
        h_close,
        &block_hash_at_seal,
        &p_id,
        shard_id,
        settlement_epoch,
    );
    let current_height = h_fire.saturating_add(1);

    let mut response = ArchivalServeCreditResponse {
        p_canonical_id: p_id,
        shard_id,
        settlement_epoch,
        segment_subroot_rk: rk,
        leaf_index_in_segment: leaf_index,
        leaf_bytes,
        path,
        hybrid_signature: kat_hybrid_signature(None),
    };
    let preimage = response.signature_preimage();
    response.hybrid_signature = scheme.sign(&hybrid_sk, &preimage).expect("integration sign");

    verify_leaf_index(
        response.leaf_index_in_segment,
        &response.p_canonical_id,
        response.shard_id,
        response.settlement_epoch,
        segment_leaf_count,
    )
    .expect("integration leaf index");
    verify_segment_path(
        &response.leaf_bytes,
        &layer_scalars,
        &response.path,
        &response.segment_subroot_rk,
    )
    .expect("integration path");

    let wire = response.serialize().expect("integration wire");
    json!({
        "label": "ct2_opening_epoch1_consensus_verify",
        "p_canonical_id_hex": encode_hex(&response.p_canonical_id),
        "shard_id": response.shard_id,
        "settlement_epoch": response.settlement_epoch,
        "segment_leaf_count": segment_leaf_count,
        "leaf_index_in_segment": response.leaf_index_in_segment,
        "freeze_height": h_fire,
        "h_open": h_open,
        "h_close": h_close,
        "h_seal": h_seal,
        "h_fire": h_fire,
        "current_height": current_height,
        "block_hash_at_seal_hex": encode_hex(&block_hash_at_seal),
        "join_settlement_epoch": 0,
        "bond_hybrid_pubkey_hex": encode_hex(&hybrid_pk_bytes),
        "leaf_layer_scalars_hex": flat_layer_scalars_hex(&layer_scalars),
        "wire_hex": encode_hex(&wire),
    })
}

fn kat_hybrid_signature(
    pinned_hex: Option<&str>,
) -> shekyl_crypto_pq::signature::HybridSignature {
    if let Some(hex) = pinned_hex {
        return shekyl_crypto_pq::signature::HybridSignature::from_canonical_bytes(&decode_hex(hex))
            .expect("pinned hybrid signature");
    }
    let scheme = HybridEd25519MlDsa;
    let (_pk, sk) = scheme.keypair_generate().expect("keypair");
    scheme
        .sign(&sk, b"gate2-serve-credit-kat-v1-hybrid-sig-anchor")
        .expect("sign")
}

struct Ct2Block {
    height: u64,
    root: [u8; 32],
    blob: Vec<u8>,
    outputs: Vec<RawOutput>,
}

fn ct2_main_chain() -> Vec<Ct2Block> {
    let f: Value = serde_json::from_str(CT2_FIXTURE).expect("ct2 parses");
    f["chains"]
        .as_array()
        .expect("chains")
        .iter()
        .find(|c| c["name"].as_str() == Some("main"))
        .expect("main chain")["blocks"]
        .as_array()
        .expect("blocks")
        .iter()
        .map(|b| {
            let mt = &b["miner_tx"];
            Ct2Block {
                height: b["height"].as_u64().expect("height"),
                root: decode_hex32(b["curve_tree_root"].as_str().expect("root")),
                blob: decode_hex(mt["pqc_leaf_hashes"].as_str().expect("0x07")),
                outputs: mt["outputs"]
                    .as_array()
                    .expect("outputs")
                    .iter()
                    .map(|o| RawOutput {
                        output_key: decode_hex32(o["output_key"].as_str().expect("O")),
                        commitment: o["commitment"].as_str().map(decode_hex32),
                        target: TargetKind::TaggedKey,
                    })
                    .collect(),
            }
        })
        .collect()
}

fn ct2_founder_opening() -> ( [u8; 128], [u8; 32], SegmentPathOpening, Vec<[u8; 32]> ) {
    let blocks = ct2_main_chain();
    let mut client = CurveTreeClient::new();
    for blk in &blocks {
        let txs = [TxLeafInputs {
            is_miner: true,
            leaf_hash_blob: Some(&blk.blob),
            outputs: &blk.outputs,
        }];
        client.ingest_block(BlockLeaves {
            height: blk.height,
            txs: &txs,
        });
    }
    let tip = blocks.last().expect("non-empty");
    let reference = ReferenceBlock {
        height: tip.height,
        curve_tree_root: tip.root,
    };
    let last_drained = reference.height.saturating_sub(61);
    let drained = blocks
        .iter()
        .find(|b| b.height == last_drained)
        .expect("drained block");
    let leaf_hashes = shekyl_curve_tree::recon::extract_leaf_hashes(Some(&drained.blob));
    let raw = drained.outputs[0];
    let founder = OutputIdentity {
        output_key: raw.output_key,
        commitment: raw.commitment,
        h_pqc: shekyl_curve_tree::recon::per_output_h_pqc(&leaf_hashes, 0),
        target: raw.target,
    };
    let path = client
        .assemble_path(&founder, &reference, [0u8; 32])
        .expect("assemble");
    let cl = path
        .leaf_chunk
        .iter()
        .find(|cl| cl.output_key == founder.output_key)
        .expect("founder chunk leaf");
    let leaf_bytes =
        construct_leaf(&cl.output_key, &cl.commitment, &cl.h_pqc).expect("leaf");
    let layer_scalars = leaf_layer_scalars(&path.leaf_chunk);
    let opening = SegmentPathOpening {
        c1_layers: path.c1_layers,
        c2_layers: path.c2_layers,
    };
    (leaf_bytes, reference.curve_tree_root, opening, layer_scalars)
}

fn leaf_layer_scalars(chunk: &[ChunkLeaf]) -> Vec<[u8; 32]> {
    let mut scalars = Vec::with_capacity(chunk.len() * 4);
    for cl in chunk {
        scalars.push(ed25519_point_to_selene_scalar(&cl.output_key).expect("O.x"));
        scalars.push(ed25519_point_to_selene_scalar(&cl.key_image_gen).expect("I.x"));
        scalars.push(ed25519_point_to_selene_scalar(&cl.commitment).expect("C.x"));
        scalars.push(cl.h_pqc);
    }
    scalars
}

fn build_kat_document(
    pinned_hybrid_signature_hex: Option<&str>,
    integration_pk_hex: Option<&str>,
    integration_sk_hex: Option<&str>,
) -> Value {
    let p_id = [0x42u8; 32];
    let shard_id = 7u64;
    let settlement_epoch = 100u64;
    let segment_leaf_count = 26_000u64;
    let leaf_index = challenge_leaf_index(&p_id, shard_id, settlement_epoch, segment_leaf_count);

    let h_open = 1_000_000u64;
    let h_close = h_open + 9_999;
    let block_hash_at_seal = [0xABu8; 32];
    let h_seal = challenge_seal_height(h_open);
    let h_fire = challenge_fire_height(
        h_open,
        h_close,
        &block_hash_at_seal,
        &p_id,
        shard_id,
        settlement_epoch,
    );

    let path = SegmentPathOpening {
        c1_layers: vec![vec![[0x44; 32]; 4]],
        c2_layers: vec![vec![[0x55; 32]; 8], vec![[0x66; 32]; 8]],
    };
    let response = ArchivalServeCreditResponse {
        p_canonical_id: [0x11; 32],
        shard_id: 42,
        settlement_epoch: 7,
        segment_subroot_rk: [0x22; 32],
        leaf_index_in_segment: 1_234,
        leaf_bytes: [0x33; 128],
        path: path.clone(),
        hybrid_signature: kat_hybrid_signature(pinned_hybrid_signature_hex),
    };
    let wire_hex = encode_hex(&response.serialize().expect("wire"));
    let encode_path_hex = encode_hex(&encode_path(&path));
    let signature_preimage_hex = encode_hex(&response.signature_preimage());

    let (opening_leaf, opening_rk, opening_path, _layer_scalars) = ct2_founder_opening();

    json!({
        "format_version": 1,
        "description": "Gate-2 serve-credit KAT. Single opening per epoch geometry; challenge + wire tripwires.",
        "challenge": [{
            "label": "synthetic_p42_epoch_100",
            "p_canonical_id_hex": encode_hex(&p_id),
            "shard_id": shard_id,
            "settlement_epoch": settlement_epoch,
            "segment_leaf_count": segment_leaf_count,
            "leaf_index": leaf_index,
            "h_open": h_open,
            "h_close": h_close,
            "block_hash_at_seal_hex": encode_hex(&block_hash_at_seal),
            "h_seal": h_seal,
            "h_fire": h_fire,
        }],
        "wire": {
            "label": "synthetic_minimal_path",
            "p_canonical_id_hex": encode_hex(&response.p_canonical_id),
            "shard_id": response.shard_id,
            "settlement_epoch": response.settlement_epoch,
            "segment_subroot_rk_hex": encode_hex(&response.segment_subroot_rk),
            "leaf_index_in_segment": response.leaf_index_in_segment,
            "leaf_bytes_hex": encode_hex(&response.leaf_bytes),
            "c1_layers": layers_to_json(&response.path.c1_layers),
            "c2_layers": layers_to_json(&response.path.c2_layers),
            "hybrid_signature_hex": encode_hex(
                &response.hybrid_signature.to_canonical_bytes().unwrap()
            ),
            "wire_hex": wire_hex,
            "encode_path_hex": encode_path_hex,
            "signature_preimage_hex": signature_preimage_hex,
        },
        "opening": {
            "label": "ct2_tier_a_founder_last_drained",
            "leaf_bytes_hex": encode_hex(&opening_leaf),
            "segment_subroot_rk_hex": encode_hex(&opening_rk),
            "c1_layers": layers_to_json(&opening_path.c1_layers),
            "c2_layers": layers_to_json(&opening_path.c2_layers),
        },
        "integration": build_integration_substrate(integration_pk_hex, integration_sk_hex),
    })
}

#[test]
#[ignore = "writes tests/fixtures/gate2_serve_credit_kat_v1.json"]
fn regenerate_gate2_kat_fixture() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/gate2_serve_credit_kat_v1.json");
    let existing: Option<Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    let pinned_sig = existing.as_ref().and_then(|v| {
        v["wire"]["hybrid_signature_hex"]
            .as_str()
            .map(str::to_owned)
    });
    let integration_pk = existing.as_ref().and_then(|v| {
        v["integration"]["bond_hybrid_pubkey_hex"]
            .as_str()
            .map(str::to_owned)
    });
    let integration_sk = existing.as_ref().and_then(|v| {
        v["integration"]["bond_hybrid_secret_key_hex"]
            .as_str()
            .map(str::to_owned)
    });
    let doc = build_kat_document(
        pinned_sig.as_deref(),
        integration_pk.as_deref(),
        integration_sk.as_deref(),
    );
    std::fs::write(&path, serde_json::to_string_pretty(&doc).expect("json")).expect("write");
    eprintln!("wrote {}", path.display());
}

#[test]
fn gate2_serve_credit_kat_vectors() {
    let kat: Value = serde_json::from_str(KAT_FIXTURE).expect("kat json");
    assert_eq!(kat["format_version"].as_u64(), Some(1));

    for case in kat["challenge"].as_array().expect("challenge array") {
        let p_id = decode_hex32(case["p_canonical_id_hex"].as_str().expect("p_id"));
        let shard_id = case["shard_id"].as_u64().expect("shard");
        let epoch = case["settlement_epoch"].as_u64().expect("epoch");
        let count = case["segment_leaf_count"].as_u64().expect("count");
        let h_open = case["h_open"].as_u64().expect("h_open");
        let h_close = case["h_close"].as_u64().expect("h_close");
        let seal_hash =
            decode_hex32(case["block_hash_at_seal_hex"].as_str().expect("seal hash"));

        assert_eq!(
            challenge_leaf_index(&p_id, shard_id, epoch, count),
            case["leaf_index"].as_u64().expect("leaf_index") as u32
        );
        verify_leaf_index(
            case["leaf_index"].as_u64().expect("leaf_index") as u32,
            &p_id,
            shard_id,
            epoch,
            count,
        )
        .expect("leaf index verify");
        assert_eq!(challenge_seal_height(h_open), case["h_seal"].as_u64().expect("h_seal"));
        assert_eq!(
            challenge_fire_height(h_open, h_close, &seal_hash, &p_id, shard_id, epoch),
            case["h_fire"].as_u64().expect("h_fire")
        );
    }

    let wire = &kat["wire"];
    let path = SegmentPathOpening {
        c1_layers: layers_from_json(&wire["c1_layers"]),
        c2_layers: layers_from_json(&wire["c2_layers"]),
    };
    let sig_bytes = decode_hex(wire["hybrid_signature_hex"].as_str().expect("sig"));
    let hybrid_signature =
        shekyl_crypto_pq::signature::HybridSignature::from_canonical_bytes(&sig_bytes)
            .expect("hybrid sig");
    let response = ArchivalServeCreditResponse {
        p_canonical_id: decode_hex32(wire["p_canonical_id_hex"].as_str().expect("p_id")),
        shard_id: wire["shard_id"].as_u64().expect("shard"),
        settlement_epoch: wire["settlement_epoch"].as_u64().expect("epoch"),
        segment_subroot_rk: decode_hex32(wire["segment_subroot_rk_hex"].as_str().expect("rk")),
        leaf_index_in_segment: wire["leaf_index_in_segment"]
            .as_u64()
            .expect("leaf idx") as u32,
        leaf_bytes: decode_hex128(wire["leaf_bytes_hex"].as_str().expect("leaf")),
        path,
        hybrid_signature,
    };

    assert_eq!(
        encode_hex(&encode_path(&response.path)),
        wire["encode_path_hex"].as_str().expect("encode_path")
    );
    assert_eq!(
        encode_hex(&response.signature_preimage()),
        wire["signature_preimage_hex"].as_str().expect("preimage")
    );
    assert_eq!(
        encode_hex(&response.serialize().expect("serialize")),
        wire["wire_hex"].as_str().expect("wire")
    );

    let opening = &kat["opening"];
    let opening_path = SegmentPathOpening {
        c1_layers: layers_from_json(&opening["c1_layers"]),
        c2_layers: layers_from_json(&opening["c2_layers"]),
    };
    let leaf_bytes = decode_hex128(opening["leaf_bytes_hex"].as_str().expect("leaf"));
    let rk = decode_hex32(opening["segment_subroot_rk_hex"].as_str().expect("rk"));

    let (live_leaf, live_rk, live_path, live_layer_scalars) = ct2_founder_opening();
    assert_eq!(leaf_bytes, live_leaf, "opening leaf_bytes drifted from CT-2");
    assert_eq!(rk, live_rk, "opening R_k drifted from CT-2");
    assert_eq!(opening_path.c1_layers, live_path.c1_layers);
    assert_eq!(opening_path.c2_layers, live_path.c2_layers);

    verify_segment_path(&leaf_bytes, &live_layer_scalars, &opening_path, &rk)
        .expect("opening verifies to R_k");

    let integration = &kat["integration"];
    let integration_wire = decode_hex(integration["wire_hex"].as_str().expect("integration wire"));
    assert_eq!(integration_wire[0], VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE);

    let mut cursor = std::io::Cursor::new(&integration_wire[1..]);
    let parsed =
        ArchivalServeCreditResponse::read_payload(&mut cursor).expect("parse integration wire");
    let int_pk = HybridPublicKey::from_canonical_bytes(&decode_hex(
        integration["bond_hybrid_pubkey_hex"]
            .as_str()
            .expect("integration pk"),
    ))
    .expect("integration pk parse");
    let int_sig = parsed
        .hybrid_signature
        .to_canonical_bytes()
        .expect("integration sig bytes");
    let int_sig = HybridSignature::from_canonical_bytes(&int_sig).expect("integration sig parse");
    assert!(HybridEd25519MlDsa
        .verify(&int_pk, &parsed.signature_preimage(), &int_sig)
        .expect("integration hybrid verify"));
    assert_eq!(
        challenge_leaf_index(
            &parsed.p_canonical_id,
            parsed.shard_id,
            parsed.settlement_epoch,
            integration["segment_leaf_count"].as_u64().expect("segment count"),
        ),
        parsed.leaf_index_in_segment
    );
}
