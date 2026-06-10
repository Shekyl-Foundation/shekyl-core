// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-1 Tier-A store KAT: `LeafStore` hot-path root matches recon oracle.

use shekyl_curve_tree::recon::{
    assemble_leaf_stream, collect_block_leaves, root_from_scalars, TxOutputs,
};
use shekyl_curve_tree::{
    BlockLeaves, CurveTreeClient, OutputIdentity, RawOutput, ReferenceBlock, TargetKind,
    TxLeafInputs,
};

const FIXTURE: &str = include_str!("fixtures/ct2_tier_a.json");

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn decode_hex32(s: &str) -> [u8; 32] {
    let v = decode_hex(s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn target_kind(s: &str) -> shekyl_curve_tree::TargetKind {
    match s {
        "tagged_key" => shekyl_curve_tree::TargetKind::TaggedKey,
        "key" => shekyl_curve_tree::TargetKind::Key,
        other => panic!("unexpected target: {other}"),
    }
}

struct ClientBlock {
    height: u64,
    root: [u8; 32],
    blob: Vec<u8>,
    outputs: Vec<RawOutput>,
}

fn decode_client_block(b: &serde_json::Value) -> ClientBlock {
    let mt = &b["miner_tx"];
    let outputs = mt["outputs"]
        .as_array()
        .expect("outputs")
        .iter()
        .map(|o| RawOutput {
            output_key: decode_hex32(o["output_key"].as_str().expect("O")),
            commitment: o["commitment"].as_str().map(decode_hex32),
            target: target_kind(o["target"].as_str().expect("target")),
        })
        .collect();
    ClientBlock {
        height: b["height"].as_u64().expect("height"),
        root: decode_hex32(b["curve_tree_root"].as_str().expect("root")),
        blob: decode_hex(mt["pqc_leaf_hashes"].as_str().expect("blob")),
        outputs,
    }
}

fn ingest_chain(client: &mut CurveTreeClient, blocks: &[ClientBlock]) {
    for blk in blocks {
        let txs = [TxLeafInputs {
            is_miner: true,
            leaf_hash_blob: Some(&blk.blob),
            outputs: &blk.outputs,
        }];
        client
            .ingest_block(BlockLeaves {
                height: blk.height,
                txs: &txs,
            })
            .unwrap();
    }
}

#[test]
fn store_root_matches_oracle_and_header_tier_a() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).expect("json");
    for chain in fixture["chains"].as_array().expect("chains") {
        let name = chain["name"].as_str().unwrap();
        let blocks: Vec<_> = chain["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(decode_client_block)
            .collect();

        let mut client = CurveTreeClient::new();
        ingest_chain(&mut client, &blocks);

        let mut recon_entries = Vec::new();
        let mut gindex = 0u64;
        for blk in &blocks {
            let identities: Vec<OutputIdentity> = blk
                .outputs
                .iter()
                .enumerate()
                .map(|(i, raw)| OutputIdentity {
                    output_key: raw.output_key,
                    commitment: raw.commitment,
                    h_pqc: shekyl_curve_tree::recon::per_output_h_pqc(
                        &shekyl_curve_tree::recon::extract_leaf_hashes(Some(&blk.blob)),
                        i,
                    ),
                    target: match raw.target {
                        shekyl_curve_tree::TargetKind::TaggedKey => {
                            shekyl_curve_tree::TargetKind::TaggedKey
                        }
                        shekyl_curve_tree::TargetKind::Key => shekyl_curve_tree::TargetKind::Key,
                        shekyl_curve_tree::TargetKind::StakedKey { lock_blocks } => {
                            shekyl_curve_tree::TargetKind::StakedKey { lock_blocks }
                        }
                        shekyl_curve_tree::TargetKind::Other => {
                            shekyl_curve_tree::TargetKind::Other
                        }
                    },
                })
                .collect();
            let txs = [TxOutputs {
                is_miner: true,
                outputs: &identities,
            }];
            gindex = collect_block_leaves(blk.height, &txs, gindex, &mut recon_entries);
            let through = blk.height.saturating_sub(1);
            let oracle = root_from_scalars(&assemble_leaf_stream(&recon_entries, through));
            let store_root = client
                .root_at(blk.height)
                .expect("store hot path must not error during Tier-A KAT");
            assert_eq!(
                store_root, oracle,
                "{name} h={} store vs oracle",
                blk.height
            );
            if blk.height >= 5 {
                assert_eq!(
                    store_root, blk.root,
                    "{name} h={} store vs header",
                    blk.height
                );
                let reference = ReferenceBlock {
                    height: blk.height,
                    curve_tree_root: blk.root,
                };
                assert!(client.verify_root(&reference).is_ok());
            }
        }
    }
}

const ED25519_BASEPOINT: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

#[test]
fn store_root_mixed_maturity_drain_order() {
    // Coinbase (m=60) then regular (m=10) in block 0. At height 61 both are
    // drained; canonical order is by maturity, not block insertion order.
    let coinbase = RawOutput {
        output_key: ED25519_BASEPOINT,
        commitment: Some(ED25519_BASEPOINT),
        target: TargetKind::TaggedKey,
    };
    let regular = RawOutput {
        output_key: ED25519_BASEPOINT,
        commitment: Some(ED25519_BASEPOINT),
        target: TargetKind::TaggedKey,
    };
    let blob_cb = [0x01u8; 32];
    let blob_reg = [0x02u8; 32];
    let txs = [
        TxLeafInputs {
            is_miner: true,
            leaf_hash_blob: Some(&blob_cb),
            outputs: &[coinbase],
        },
        TxLeafInputs {
            is_miner: false,
            leaf_hash_blob: Some(&blob_reg),
            outputs: &[regular],
        },
    ];
    let mut client = CurveTreeClient::new();
    client
        .ingest_block(BlockLeaves {
            height: 0,
            txs: &txs,
        })
        .unwrap();

    let mut recon_entries = Vec::new();
    let identities_cb: Vec<OutputIdentity> = [coinbase]
        .iter()
        .enumerate()
        .map(|(i, raw)| OutputIdentity {
            output_key: raw.output_key,
            commitment: raw.commitment,
            h_pqc: shekyl_curve_tree::recon::per_output_h_pqc(
                &shekyl_curve_tree::recon::extract_leaf_hashes(Some(&blob_cb)),
                i,
            ),
            target: raw.target,
        })
        .collect();
    let identities_reg: Vec<OutputIdentity> = [regular]
        .iter()
        .enumerate()
        .map(|(i, raw)| OutputIdentity {
            output_key: raw.output_key,
            commitment: raw.commitment,
            h_pqc: shekyl_curve_tree::recon::per_output_h_pqc(
                &shekyl_curve_tree::recon::extract_leaf_hashes(Some(&blob_reg)),
                i,
            ),
            target: raw.target,
        })
        .collect();
    let recon_txs = [
        TxOutputs {
            is_miner: true,
            outputs: &identities_cb,
        },
        TxOutputs {
            is_miner: false,
            outputs: &identities_reg,
        },
    ];
    collect_block_leaves(0, &recon_txs, 0, &mut recon_entries);

    let through = 60u64;
    let oracle = root_from_scalars(&assemble_leaf_stream(&recon_entries, through));
    let store_root = client.root_at(61).expect("store hot path must not error");
    assert_eq!(
        store_root, oracle,
        "store must mirror canonical drain order"
    );

    let drained = shekyl_curve_tree::recon::drained_sorted(&recon_entries, through);
    assert_eq!(drained.len(), 2);
    assert!(
        drained[0].maturity < drained[1].maturity,
        "regular output (m=10) must precede coinbase (m=60)"
    );
}

#[test]
fn truncate_and_replay_matches_from_blocks() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).expect("json");
    let main = fixture["chains"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "reorg_deep")
        .expect("reorg_deep");
    let blocks: Vec<_> = main["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(decode_client_block)
        .collect();

    let mut full = CurveTreeClient::new();
    ingest_chain(&mut full, &blocks);
    let fork = 140usize;
    let prefix = &blocks[..=fork];
    let mut rebuilt = CurveTreeClient::new();
    ingest_chain(&mut rebuilt, prefix);

    for blk in prefix {
        assert_eq!(
            full.root_at(blk.height).expect("store hot path"),
            rebuilt.root_at(blk.height).expect("store hot path"),
            "reorg replay at {}",
            blk.height
        );
    }
}
