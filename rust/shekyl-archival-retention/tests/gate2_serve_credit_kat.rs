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
use shekyl_archival_retention::VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE;
use shekyl_archival_retention::{
    challenge_fire_height, challenge_leaf_chunk_bounds, challenge_leaf_index,
    challenge_seal_height, challenged_leaf_bytes, challenged_leaf_offset_in_chunk, encode_path,
    hybrid_countersignature, p_canonical_id_from_hybrid_pubkey, split_countersignature,
    verify_segment_path, ArchivalServeCreditPruned, ArchivalServeCreditResponse,
    SegmentPathOpening, ED25519_COUNTERSIGNATURE_LEN, SEGMENT_LEAF_COUNT, SETTLEMENT_EPOCH_BLOCKS,
};
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, SignatureScheme,
};
use shekyl_curve_tree::{
    AssembleInput, BlockHeight, BlockLeaves, ChunkLeaf, CurveTreeClient, Gindex, RawOutput,
    ReferenceBlock, TargetKind, TxLeafInputs,
};
use shekyl_fcmp::tree::{construct_leaf, ed25519_point_to_selene_scalar, SELENE_CHUNK_WIDTH};

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
        let pk =
            HybridPublicKey::from_canonical_bytes(&decode_hex(pk_hex)).expect("integration pk");
        let sk =
            HybridSecretKey::from_canonical_bytes(&decode_hex(sk_hex)).expect("integration sk");
        return (pk, sk);
    }
    HybridEd25519MlDsa
        .generate_ephemeral_keypair_for_tests()
        .expect("integration keypair")
}

fn flat_layer_scalars_hex(scalars: &[[u8; 32]]) -> String {
    encode_hex(
        &scalars
            .iter()
            .flat_map(|s| s.iter().copied())
            .collect::<Vec<_>>(),
    )
}

fn build_integration_substrate(
    pinned_pk_hex: Option<&str>,
    pinned_sk_hex: Option<&str>,
    pinned_sig_hex: Option<&str>,
) -> Value {
    let scheme = HybridEd25519MlDsa;
    let (hybrid_pk, hybrid_sk) = integration_keypair(pinned_pk_hex, pinned_sk_hex);
    let hybrid_pk_bytes = hybrid_pk.to_canonical_bytes().expect("pk bytes");
    let hybrid_sk_bytes = hybrid_sk.to_canonical_bytes().expect("sk bytes");
    let p_id = p_canonical_id_from_hybrid_pubkey(&hybrid_pk_bytes).to_bytes();

    // Full-chunk opening: the consensus challenge path reads exactly
    // SELENE_CHUNK_WIDTH leaves from the curve-tree leaf table
    // (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §6.2 — frozen segments have only
    // full chunks), so the integration substrate must carry a full chunk.
    // The founder's own leaf is NOT used as the challenged leaf: the challenge
    // index is derived, and the challenged leaf is whichever leaf of this
    // chunk sits at that index (RF-D8). The path is per-chunk, so it verifies
    // for every leaf in it; only the signed preimage depends on which.
    let (_founder_leaf, rk, path, layer_scalars) = ct2_full_chunk_opening();
    assert_eq!(
        layer_scalars.len(),
        4 * SELENE_CHUNK_WIDTH,
        "integration substrate requires a full leaf chunk"
    );
    let shard_id = 42u64;
    // Consensus requires settlement_epoch >= join_settlement_epoch + 1; join at 0 ⇒ first credit at 1.
    let settlement_epoch = 1u64;
    let segment_leaf_count = SEGMENT_LEAF_COUNT;
    let leaf_index = challenge_leaf_index(&p_id, shard_id, settlement_epoch, segment_leaf_count);
    // Cross-language pin: the fixture carries the chunk bounds the Rust
    // derivation produces so the C++ integration test can assert the FFI
    // returns the same values before seeding the leaf table.
    let chunk_bounds = challenge_leaf_chunk_bounds(shard_id, u64::from(leaf_index))
        .expect("challenged index within segment");

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

    // Kept half first (identity only); the signature legs are filled in below
    // once the preimage over the verifier-derived terms is known.
    // The verifier's view of the challenged leaf: selected from the chunk at
    // the derived offset (global index minus the chunk's first position).
    let leaf_offset = challenged_leaf_offset_in_chunk(shard_id, u64::from(leaf_index))
        .expect("derived index lies inside the segment");
    let leaf_bytes = challenged_leaf_bytes(&layer_scalars, leaf_offset)
        .expect("derived offset lies inside the substrate chunk");

    let mut response = ArchivalServeCreditResponse {
        p_canonical_id: p_id,
        shard_id,
        settlement_epoch,
        ed25519_countersignature: [0u8; ED25519_COUNTERSIGNATURE_LEN],
    };
    let preimage = response.signature_preimage(&rk, leaf_index, &leaf_bytes, &path);
    // Re-pin: reuse the committed integration signature while it still
    // verifies over the recomputed preimage (same idempotence discipline as
    // the wire anchor); re-sign only on a genuine construction change.
    let pinned_sig = pinned_sig_hex
        .map(decode_hex)
        .and_then(|bytes| {
            shekyl_crypto_pq::signature::HybridSignature::from_canonical_bytes(&bytes).ok()
        })
        .filter(|sig| {
            scheme
                .verify(
                    &hybrid_pk,
                    shekyl_crypto_pq::signature::SCHEME_DOMAIN_SERVE_CREDIT,
                    &preimage,
                    sig,
                )
                .is_ok()
        });
    let hybrid_signature = pinned_sig.unwrap_or_else(|| {
        scheme
            .sign(
                &hybrid_sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_SERVE_CREDIT,
                &preimage,
            )
            .expect("integration sign")
    });
    // RF-D2: one container, split across the kept/pruned boundary.
    let (ed_leg, ml_leg) = split_countersignature(&hybrid_signature).expect("canonical legs");
    response.ed25519_countersignature = ed_leg;
    let pruned = ArchivalServeCreditPruned {
        path,
        ml_dsa_countersignature: ml_leg,
    };

    verify_segment_path(&layer_scalars, leaf_offset, &pruned.path, &rk).expect("integration path");

    let wire = response.serialize().expect("integration wire");
    let pruned_bytes = pruned.serialize().expect("integration pruned");
    json!({
        "label": "ct2_opening_epoch1_consensus_verify",
        "p_canonical_id_hex": encode_hex(&response.p_canonical_id),
        "shard_id": response.shard_id,
        "settlement_epoch": response.settlement_epoch,
        "segment_leaf_count": segment_leaf_count,
        // Verifier-derived inputs, recorded so consumers (gate-4) can supply
        // them the way the verifier does -- from outside the wire. Neither is
        // transported (RF-D6/RF-D8); both are in the signed preimage.
        "leaf_index_in_segment": leaf_index,
        "segment_subroot_rk_hex": encode_hex(&rk),
        "leaf_bytes_hex": encode_hex(&leaf_bytes),
        "freeze_height": h_fire,
        "h_open": h_open,
        "h_close": h_close,
        "h_seal": h_seal,
        "h_fire": h_fire,
        "current_height": current_height,
        "block_hash_at_seal_hex": encode_hex(&block_hash_at_seal),
        "join_settlement_epoch": 0,
        "bond_hybrid_pubkey_hex": encode_hex(&hybrid_pk_bytes),
        // Persisted so the regen writer can re-pin: the secret key keeps the
        // keypair (and thus p_canonical_id / h_fire / leaf_index) stable
        // across regens; the signature hex lets the writer reuse it while it
        // still verifies. Test-only material, like every key in this fixture.
        "bond_hybrid_secret_key_hex": encode_hex(&hybrid_sk_bytes),
        "bond_hybrid_signature_hex": encode_hex(
            &hybrid_signature.to_canonical_bytes().expect("integration sig bytes")
        ),
        "leaf_layer_scalars_hex": flat_layer_scalars_hex(&layer_scalars),
        "chunk_first_leaf_position": chunk_bounds.first_leaf_position,
        "chunk_leaf_count": chunk_bounds.leaf_count,
        // The two halves of the record (RF-D1): `wire_hex` is the vin
        // (kept, tag included); `pruned_hex` is this vin's slice of the
        // prunable region.
        "wire_hex": encode_hex(&wire),
        "pruned_hex": encode_hex(&pruned_bytes),
    })
}

/// Test-only: where `leaf` sits in `chunk`. The verifier never searches — it
/// derives the offset from the challenge index — but a fixture that pins a
/// leaf by value needs to recover its position to call the verifier.
fn leaf_offset_in_chunk(chunk: &[[u8; 32]], leaf: &[u8; 128]) -> Option<usize> {
    (0..chunk.len() / 4).find(|&i| challenged_leaf_bytes(chunk, i).as_ref() == Some(leaf))
}

/// The fixed message the synthetic wire anchor signs. The anchor exists so the
/// wire section carries a genuine (verifiable) v2 signature, not opaque bytes.
const WIRE_ANCHOR_MESSAGE: &[u8] = b"gate2-serve-credit-kat-v1-hybrid-sig-anchor";

/// The synthetic wire section's anchor signature plus the keypair that minted
/// it (both persisted in the fixture so regens can re-pin).
struct WireAnchor {
    signature: shekyl_crypto_pq::signature::HybridSignature,
    pk_bytes: Vec<u8>,
    sk_bytes: Vec<u8>,
}

/// Build the wire anchor, re-pinning committed material wherever it is still
/// valid: the anchor keypair is reused whenever it parses, and the anchor
/// signature whenever it still **verifies** under the current construction —
/// so a regen run for an unrelated tweak rewrites these fields byte-identically
/// instead of churning the fixture (and desyncing the hand-synced C++
/// equivalence fixture). Only a genuine construction change re-signs, and only
/// a missing/corrupt fixture re-mints the keypair.
fn wire_anchor(existing: Option<&Value>) -> WireAnchor {
    use shekyl_crypto_pq::signature::{HybridPublicKey, HybridSecretKey, HybridSignature};
    let scheme = HybridEd25519MlDsa;

    let pinned_keys = existing.and_then(|v| {
        let pk_hex = v["wire"]["anchor_pubkey_hex"].as_str()?;
        let sk_hex = v["wire"]["anchor_secret_key_hex"].as_str()?;
        let pk = HybridPublicKey::from_canonical_bytes(&decode_hex(pk_hex)).ok()?;
        let sk = HybridSecretKey::from_canonical_bytes(&decode_hex(sk_hex)).ok()?;
        Some((pk, sk))
    });
    let (pk, sk) = pinned_keys.unwrap_or_else(|| {
        scheme
            .generate_ephemeral_keypair_for_tests()
            .expect("anchor keypair")
    });

    let pinned_sig = existing
        .and_then(|v| v["wire"]["hybrid_signature_hex"].as_str())
        .map(decode_hex)
        .and_then(|bytes| HybridSignature::from_canonical_bytes(&bytes).ok())
        .filter(|sig| {
            scheme
                .verify(
                    &pk,
                    shekyl_crypto_pq::signature::SCHEME_DOMAIN_SERVE_CREDIT,
                    WIRE_ANCHOR_MESSAGE,
                    sig,
                )
                .is_ok()
        });
    let signature = pinned_sig.unwrap_or_else(|| {
        scheme
            .sign(
                &sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_SERVE_CREDIT,
                WIRE_ANCHOR_MESSAGE,
            )
            .expect("anchor sign")
    });

    WireAnchor {
        signature,
        pk_bytes: pk.to_canonical_bytes().expect("anchor pk bytes"),
        sk_bytes: sk.to_canonical_bytes().expect("anchor sk bytes"),
    }
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

fn ct2_ingested() -> (CurveTreeClient, Vec<Ct2Block>, ReferenceBlock) {
    let blocks = ct2_main_chain();
    let mut client = CurveTreeClient::new();
    for blk in &blocks {
        let txs = [TxLeafInputs {
            is_miner: true,
            leaf_hash_blob: Some(&blk.blob),
            outputs: &blk.outputs,
        }];
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight(blk.height),
                txs: &txs,
            })
            .unwrap();
    }
    let tip = blocks.last().expect("non-empty");
    let reference = ReferenceBlock {
        height: BlockHeight(tip.height),
        curve_tree_root: tip.root,
        block_hash: [0u8; 32],
    };
    (client, blocks, reference)
}

fn ct2_opening_at(
    client: &CurveTreeClient,
    reference: &ReferenceBlock,
    gindex: u64,
    raw: RawOutput,
) -> ([u8; 128], [u8; 32], SegmentPathOpening, Vec<[u8; 32]>) {
    let input = AssembleInput {
        gindex: Gindex(gindex),
        output_key: raw.output_key,
        commitment: raw.commitment.expect("coinbase output has a commitment"),
    };
    let path = client.assemble_path(&input, reference).expect("assemble");
    let cl = path
        .leaf_chunk
        .iter()
        .find(|cl| cl.output_key == input.output_key)
        .expect("chunk leaf for opened output");
    let leaf_bytes = construct_leaf(&cl.output_key, &cl.commitment, &cl.h_pqc).expect("leaf");
    let layer_scalars = leaf_layer_scalars(&path.leaf_chunk);
    let opening = SegmentPathOpening {
        c1_layers: path.c1_layers,
        c2_layers: path.c2_layers,
    };
    (
        leaf_bytes,
        reference.curve_tree_root,
        opening,
        layer_scalars,
    )
}

fn ct2_founder_opening() -> ([u8; 128], [u8; 32], SegmentPathOpening, Vec<[u8; 32]>) {
    let (client, blocks, reference) = ct2_ingested();
    let last_drained = reference.height.0.saturating_sub(61);
    let drained = blocks
        .iter()
        .find(|b| b.height == last_drained)
        .expect("drained block");
    let raw = drained.outputs[0];
    // gindex = cumulative vouts in earlier blocks (drain-order next_output_seq);
    // resolve by it (X3), with the (output_key, commitment) as the consistency
    // pair.
    let founder_gindex: u64 = blocks
        .iter()
        .filter(|b| b.height < last_drained)
        .map(|b| b.outputs.len() as u64)
        .sum();
    ct2_opening_at(&client, &reference, founder_gindex, raw)
}

/// Opening for gindex 0 — the tree's first leaf chunk, which is full
/// (`SELENE_CHUNK_WIDTH` leaves) whenever at least one chunk's worth of
/// outputs has drained. The integration substrate needs a full chunk because
/// the consensus challenge path reads exactly one full chunk from the
/// curve-tree leaf table (pipeline doc §6.2).
fn ct2_full_chunk_opening() -> ([u8; 128], [u8; 32], SegmentPathOpening, Vec<[u8; 32]>) {
    let (client, blocks, reference) = ct2_ingested();
    let first = blocks.first().expect("non-empty");
    ct2_opening_at(&client, &reference, 0, first.outputs[0])
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
    anchor: &WireAnchor,
    integration_pk_hex: Option<&str>,
    integration_sk_hex: Option<&str>,
    integration_sig_hex: Option<&str>,
) -> Value {
    let p_id = [0x42u8; 32];
    let shard_id = 7u64;
    let settlement_epoch = 100u64;
    let segment_leaf_count = SEGMENT_LEAF_COUNT;
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
    // RF-D6: `R_k` and the leaf index are signed but NOT transported, so they
    // are preimage inputs here rather than struct fields. The fixture keeps
    // both under their old keys so the preimage pin stays byte-identical.
    let wire_rk = [0x22u8; 32];
    let wire_leaf_index = 1_234u32;
    let wire_leaf_bytes = [0x33u8; 128];
    let (anchor_ed, anchor_ml) = split_countersignature(&anchor.signature).expect("anchor legs");
    let response = ArchivalServeCreditResponse {
        p_canonical_id: [0x11; 32],
        shard_id: 42,
        settlement_epoch: 7,
        ed25519_countersignature: anchor_ed,
    };
    let pruned = ArchivalServeCreditPruned {
        path: path.clone(),
        ml_dsa_countersignature: anchor_ml,
    };
    let wire_hex = encode_hex(&response.serialize().expect("wire"));
    let pruned_hex = encode_hex(&pruned.serialize().expect("pruned"));
    let encode_path_hex = encode_hex(&encode_path(&path));
    let signature_preimage_hex = encode_hex(&response.signature_preimage(
        &wire_rk,
        wire_leaf_index,
        &wire_leaf_bytes,
        &path,
    ));

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
            // Preimage inputs only (RF-D6) -- not on the wire, still signed.
            "segment_subroot_rk_hex": encode_hex(&wire_rk),
            "leaf_index_in_segment": wire_leaf_index,
            "leaf_bytes_hex": encode_hex(&wire_leaf_bytes),
            "c1_layers": layers_to_json(&pruned.path.c1_layers),
            "c2_layers": layers_to_json(&pruned.path.c2_layers),
            "hybrid_signature_hex": encode_hex(
                &anchor.signature.to_canonical_bytes().unwrap()
            ),
            "anchor_pubkey_hex": encode_hex(&anchor.pk_bytes),
            "anchor_secret_key_hex": encode_hex(&anchor.sk_bytes),
            "wire_hex": wire_hex,
            "pruned_hex": pruned_hex,
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
        "integration": build_integration_substrate(
            integration_pk_hex,
            integration_sk_hex,
            integration_sig_hex,
        ),
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
    // Re-pin everything that is still valid (see `wire_anchor` and the
    // integration re-pin in `build_integration_substrate`): committed keys are
    // reused whenever they parse, committed signatures whenever they still
    // verify under the current construction. A regen for an unrelated tweak is
    // therefore byte-stable; only a genuine construction change re-signs (and
    // only then does the hand-synced C++ equivalence fixture need a re-sync).
    let anchor = wire_anchor(existing.as_ref());
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
    let integration_sig = existing.as_ref().and_then(|v| {
        v["integration"]["bond_hybrid_signature_hex"]
            .as_str()
            .map(str::to_owned)
    });
    let doc = build_kat_document(
        &anchor,
        integration_pk.as_deref(),
        integration_sk.as_deref(),
        integration_sig.as_deref(),
    );
    std::fs::write(&path, serde_json::to_string_pretty(&doc).expect("json")).expect("write");
    eprintln!("wrote {}", path.display());
}

/// The pruned pass record has ONE size for a FROZEN segment at
/// `SEGMENT_LAYER_J = 2`: the opening of any leaf in a full segment is one
/// Helios branch layer of 18 scalars and one Selene of 38 (CR-D2's 1,792 B of
/// layers plus varint framing), plus the ML-DSA-65 leg. `cryptonote_config.h`
/// pins that plus its 2-byte length prefix as
/// `ARCHIVAL_SERVE_CREDIT_PRUNED_RECORD_BYTES = 5107`, which is what lets a
/// pruned node reconstruct a serve-credit tx's weight exactly.
///
/// Constructed at the production geometry rather than borrowed from the CT-2
/// test substrate: that substrate is a small tree (its opening's top layer is
/// 4 wide, a 3,440-byte record), and a first draft of this test borrowed it
/// and pinned the wrong number. The determinism the C++ relies on holds
/// because admission verifies the path against a frozen segment's `R_k`, and
/// a frozen segment's opening has exactly this shape -- a record of any other
/// shape cannot hash to that root.
#[test]
fn pruned_record_size_is_deterministic_for_a_frozen_segment() {
    let pruned = ArchivalServeCreditPruned {
        path: SegmentPathOpening {
            c1_layers: vec![vec![[0u8; 32]; 38]],
            c2_layers: vec![vec![[0u8; 32]; 18]],
        },
        ml_dsa_countersignature: [0u8; 3309],
    };
    let bytes = pruned.serialize().expect("serialize");
    assert_eq!(
        bytes.len(),
        5_105,
        "pruned record size moved: re-pin the C++ twin (5107 incl. prefix)"
    );
    // The C++ transport adds varint(5105) = 2 bytes.
    assert_eq!(5_105 + 2, 5_107);
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
        let seal_hash = decode_hex32(case["block_hash_at_seal_hex"].as_str().expect("seal hash"));

        let leaf_index = u32::try_from(case["leaf_index"].as_u64().expect("leaf_index"))
            .expect("leaf_index fits u32");
        assert_eq!(
            challenge_leaf_index(&p_id, shard_id, epoch, count),
            leaf_index
        );
        // (verify_leaf_index was deleted by RF-D6; the derivation above IS the
        // pinned value, asserted against the fixture directly.)
        assert_eq!(
            challenge_seal_height(h_open),
            case["h_seal"].as_u64().expect("h_seal")
        );
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
    // The anchor is a genuine pinned signature, not opaque bytes: it must
    // still verify under the current construction (pinned-positive tripwire —
    // a construction change fails here until the fixture is regenerated).
    let anchor_pk = shekyl_crypto_pq::signature::HybridPublicKey::from_canonical_bytes(
        &decode_hex(wire["anchor_pubkey_hex"].as_str().expect("anchor pk")),
    )
    .expect("anchor pk parse");
    HybridEd25519MlDsa
        .verify(
            &anchor_pk,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_SERVE_CREDIT,
            WIRE_ANCHOR_MESSAGE,
            &hybrid_signature,
        )
        .expect("wire anchor must verify under the current construction");
    let (anchor_ed, anchor_ml) = split_countersignature(&hybrid_signature).expect("anchor legs");
    let response = ArchivalServeCreditResponse {
        p_canonical_id: decode_hex32(wire["p_canonical_id_hex"].as_str().expect("p_id")),
        shard_id: wire["shard_id"].as_u64().expect("shard"),
        settlement_epoch: wire["settlement_epoch"].as_u64().expect("epoch"),
        ed25519_countersignature: anchor_ed,
    };
    let pruned = ArchivalServeCreditPruned {
        path,
        ml_dsa_countersignature: anchor_ml,
    };
    // Preimage inputs the verifier supplies (RF-D6/RF-D8): off the wire, in the signature.
    let rk = decode_hex32(wire["segment_subroot_rk_hex"].as_str().expect("rk"));
    let leaf_index =
        u32::try_from(wire["leaf_index_in_segment"].as_u64().expect("leaf idx")).expect("u32");
    let wire_leaf_bytes = decode_hex128(wire["leaf_bytes_hex"].as_str().expect("leaf"));

    assert_eq!(
        encode_hex(&encode_path(&pruned.path)),
        wire["encode_path_hex"].as_str().expect("encode_path")
    );
    assert_eq!(
        encode_hex(&response.signature_preimage(&rk, leaf_index, &wire_leaf_bytes, &pruned.path)),
        wire["signature_preimage_hex"].as_str().expect("preimage")
    );
    assert_eq!(
        encode_hex(&response.serialize().expect("serialize")),
        wire["wire_hex"].as_str().expect("wire")
    );
    assert_eq!(
        encode_hex(&pruned.serialize().expect("serialize")),
        wire["pruned_hex"].as_str().expect("pruned")
    );
    // Both halves re-parse to what was written, and the legs reassemble to
    // the anchor signature that verified above.
    let kept_back = ArchivalServeCreditResponse::read(
        &mut decode_hex(wire["wire_hex"].as_str().unwrap()).as_slice(),
    )
    .expect("kept parse");
    let pruned_back = ArchivalServeCreditPruned::read_exact(
        &mut decode_hex(wire["pruned_hex"].as_str().unwrap()).as_slice(),
    )
    .expect("pruned parse");
    assert_eq!(
        hybrid_countersignature(&kept_back, &pruned_back)
            .to_canonical_bytes()
            .unwrap(),
        hybrid_signature.to_canonical_bytes().unwrap()
    );

    let opening = &kat["opening"];
    let opening_path = SegmentPathOpening {
        c1_layers: layers_from_json(&opening["c1_layers"]),
        c2_layers: layers_from_json(&opening["c2_layers"]),
    };
    let leaf_bytes = decode_hex128(opening["leaf_bytes_hex"].as_str().expect("leaf"));
    let rk = decode_hex32(opening["segment_subroot_rk_hex"].as_str().expect("rk"));

    let (live_leaf, live_rk, live_path, live_layer_scalars) = ct2_founder_opening();
    assert_eq!(
        leaf_bytes, live_leaf,
        "opening leaf_bytes drifted from CT-2"
    );
    assert_eq!(rk, live_rk, "opening R_k drifted from CT-2");
    assert_eq!(opening_path.c1_layers, live_path.c1_layers);
    assert_eq!(opening_path.c2_layers, live_path.c2_layers);

    let opening_offset = leaf_offset_in_chunk(&live_layer_scalars, &leaf_bytes)
        .expect("opening leaf is in the live chunk");
    verify_segment_path(&live_layer_scalars, opening_offset, &opening_path, &rk)
        .expect("opening verifies to R_k");

    let integration = &kat["integration"];
    let integration_wire = decode_hex(integration["wire_hex"].as_str().expect("integration wire"));
    assert_eq!(integration_wire[0], VIN_TYPE_ARCHIVAL_SERVE_CREDIT_RESPONSE);

    let mut cursor = std::io::Cursor::new(&integration_wire[1..]);
    let parsed =
        ArchivalServeCreditResponse::read_payload(&mut cursor).expect("parse integration wire");
    // RF-D6: the integration substrate's `R_k` and leaf index are verifier
    // inputs, not wire fields. Named `int_*` deliberately -- the opening
    // section's `rk` is a DIFFERENT segment's root, and reusing that name
    // here is exactly how this test briefly verified the integration
    // signature against the wrong preimage.
    let int_rk = decode_hex32(
        integration["segment_subroot_rk_hex"]
            .as_str()
            .expect("integration rk"),
    );
    let int_leaf_index = challenge_leaf_index(
        &parsed.p_canonical_id,
        parsed.shard_id,
        parsed.settlement_epoch,
        integration["segment_leaf_count"]
            .as_u64()
            .expect("segment count"),
    );
    let int_pk = HybridPublicKey::from_canonical_bytes(&decode_hex(
        integration["bond_hybrid_pubkey_hex"]
            .as_str()
            .expect("integration pk"),
    ))
    .expect("integration pk parse");
    // The pruned half, parsed from its own record; the legs reassemble into
    // the signature the verifier checks.
    let int_pruned = ArchivalServeCreditPruned::read_exact(
        &mut decode_hex(integration["pruned_hex"].as_str().expect("pruned")).as_slice(),
    )
    .expect("parse integration pruned");
    let int_leaf_bytes = decode_hex128(
        integration["leaf_bytes_hex"]
            .as_str()
            .expect("integration leaf"),
    );
    let int_sig = hybrid_countersignature(&parsed, &int_pruned);
    assert_eq!(
        encode_hex(&int_sig.to_canonical_bytes().expect("sig bytes")),
        integration["bond_hybrid_signature_hex"]
            .as_str()
            .expect("pinned sig"),
        "reassembled legs must equal the pinned hybrid signature"
    );
    let int_preimage =
        parsed.signature_preimage(&int_rk, int_leaf_index, &int_leaf_bytes, &int_pruned.path);
    HybridEd25519MlDsa
        .verify(
            &int_pk,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_SERVE_CREDIT,
            &int_preimage,
            &int_sig,
        )
        .expect("integration hybrid verify");

    // F1 regression (serve-credit surface): a well-formed signature under the
    // WRONG key must be REJECTED. The pre-SA-2 FFI gated on `.is_err()` over a
    // `Result<bool>`, so `Ok(false)` (this exact case) fell through to VERIFY_OK.
    // Under `verify -> Result<()>` there is no `Ok(false)`, so it returns `Err`.
    // A malformed-signature test would pass on the broken code; a wrong-KEY one
    // is the negative control on the axis the defect lived.
    let (foreign_pk, _foreign_sk) = HybridEd25519MlDsa
        .generate_ephemeral_keypair_for_tests()
        .expect("foreign keypair");
    assert!(
        HybridEd25519MlDsa
            .verify(
                &foreign_pk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_SERVE_CREDIT,
                &int_preimage,
                &int_sig,
            )
            .is_err(),
        "a well-formed serve-credit signature under a foreign key must be rejected (F1)"
    );
    // RF-D6: the index is not on the wire. The fixture records the verifier's
    // derived value; the derivation must still reproduce it.
    assert_eq!(
        u64::from(int_leaf_index),
        integration["leaf_index_in_segment"]
            .as_u64()
            .expect("recorded index"),
        "fixture's recorded leaf index drifted from the derivation"
    );

    // Chunk-bounds pin (pipeline doc §6.2): the fixture's pinned bounds must
    // match the live derivation, and the substrate chunk must be exactly one
    // full leaf chunk (chunk_leaf_count leaves × 128 bytes).
    let bounds = challenge_leaf_chunk_bounds(parsed.shard_id, u64::from(int_leaf_index))
        .expect("challenged index within segment");
    assert_eq!(
        bounds.first_leaf_position,
        integration["chunk_first_leaf_position"]
            .as_u64()
            .expect("chunk first"),
        "pinned chunk_first_leaf_position drifted from derivation"
    );
    assert_eq!(
        bounds.leaf_count,
        integration["chunk_leaf_count"]
            .as_u64()
            .expect("chunk leaf count"),
        "pinned chunk_leaf_count drifted from derivation"
    );
    let scalars_hex = integration["leaf_layer_scalars_hex"]
        .as_str()
        .expect("integration scalars");
    assert_eq!(
        scalars_hex.len() as u64,
        bounds.leaf_count * 128 * 2,
        "integration substrate chunk must be exactly one full leaf chunk"
    );
}
