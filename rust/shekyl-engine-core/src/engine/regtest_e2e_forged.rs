// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A daemon started on a forged chain, loaded through its normal acceptance
//! path (Rick, 2026-11-22: the body-fill walks move onto a forged chain; no
//! trusted import).
//!
//! A forged chain (`CHAIN_FORGE.md`) is a corpus of real blocks: every
//! transaction proven and signed by the production code, every block mined
//! under the regtest identity on the chain's own schedule. [`load_forged`]
//! hands it to a running regtest daemon the way a local arrival comes in:
//! each listed transaction through `tx_submit` (the pool's admission), then
//! the block through `block_submit`, which connects only after the node's
//! full validation. Nothing is written into the node's store from outside.
//!
//! A child of the regtest harness (`#[path]`), like its siblings.

#![cfg(test)]

use std::path::{Path, PathBuf};

use shekyl_corpus::{CorpusReader, Record};

use super::*;

/// What a load connected.
pub(super) struct Loaded {
    /// The node's tip height after the load.
    pub(super) tip: u64,
    /// The node's tip hash, equal to the last loaded block's.
    pub(super) tip_hash: String,
    /// Blocks and transactions handed to the node.
    pub(super) blocks: u64,
    pub(super) transactions: u64,
    pub(super) elapsed: Duration,
}

/// A hosted forged chain's directory, as `scripts/ci/fetch_test_chain.py
/// <name>` lands it. Refuses by name when it is absent: a test on a chain
/// that is not there has no subject (rule 47).
pub(super) fn hosted_chain(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../shekyl-chain-forge/chains")
        .join(name)
        .join("hosted");
    assert!(
        dir.join("corpus.e2").is_file() && dir.join("manifest.json").is_file(),
        "the hosted chain `{name}` is not fetched: run `python3 scripts/ci/fetch_test_chain.py \
         {name}` from the repository root ({} is missing its corpus or manifest)",
        dir.display()
    );
    dir
}

/// The fields of a hosted chain's `manifest.json` a load reads.
pub(super) struct Manifest {
    pub(super) genesis_hash: String,
    pub(super) schedule: RegtestSchedule,
    pub(super) tip_height: u64,
    json: serde_json::Value,
}

impl Manifest {
    pub(super) fn read(dir: &Path) -> Self {
        let text = std::fs::read_to_string(dir.join("manifest.json")).expect("read the manifest");
        let json: serde_json::Value = serde_json::from_str(&text).expect("parse the manifest");
        let number = |path: &[&str]| -> u64 {
            let mut at = &json;
            for key in path {
                at = &at[*key];
            }
            at.as_u64()
                .unwrap_or_else(|| panic!("manifest {}: no number at {path:?}", dir.display()))
        };
        assert_eq!(json["network"], "regtest", "a forged chain is regtest-only");
        assert_eq!(
            number(&["schedule", "fixed_difficulty"]),
            1,
            "the harness daemon runs difficulty 1"
        );
        let schedule = RegtestSchedule {
            seb: number(&["schedule", "settlement_epoch_blocks"]),
            reorg_cap: number(&["schedule", "reorg_cap_blocks"]),
        };
        Self {
            genesis_hash: json["genesis_hash"]
                .as_str()
                .expect("the manifest names its genesis")
                .to_owned(),
            schedule,
            tip_height: number(&["tip_height"]),
            json,
        }
    }

    /// The height of the named event on the main branch (`shard-0-closed`):
    /// heights are read from the manifest, never written down, since a
    /// re-forge moves them.
    pub(super) fn event(&self, name: &str) -> u64 {
        self.json["events"]
            .as_array()
            .expect("the manifest lists its events")
            .iter()
            .find(|e| e["name"] == name && e["branch"] == "main")
            .and_then(|e| e["height"].as_u64())
            .unwrap_or_else(|| panic!("the manifest has no main-branch event `{name}`"))
    }
}

/// Hand `dir`'s corpus to `daemon` through its acceptance path, through
/// height `through` (inclusive). The daemon must run the manifest's
/// schedule and difficulty, and hold the chain's genesis and nothing past
/// it. Every transaction is admitted by the pool and every block connected
/// by the node's own validation, or the load fails naming the height.
pub(super) async fn load_forged(daemon: &RegtestDaemon, dir: &Path, through: u64) -> Loaded {
    let manifest = Manifest::read(dir);
    assert!(
        through <= manifest.tip_height,
        "the chain ends at {}, short of {through}",
        manifest.tip_height
    );
    let genesis = daemon.block_at(0).await;
    assert_eq!(
        genesis.header.hash.to_string(),
        manifest.genesis_hash,
        "the daemon's genesis is not the forged chain's"
    );
    assert_eq!(
        daemon.height().await,
        1,
        "the daemon holds more than genesis"
    );

    let started = Instant::now();
    let file = std::fs::File::open(dir.join("corpus.e2")).expect("open the corpus");
    let mut reader =
        CorpusReader::open(std::io::BufReader::new(file)).expect("the corpus's header");
    let (mut blocks, mut transactions, mut tip_hash) = (0u64, 0u64, String::new());
    while let Some(record) = reader.next_record().expect("a corpus record") {
        let extend = match record {
            Record::Extend(extend) => extend,
            Record::Rewind { to } => {
                panic!("a rewind to {to:?}: this loader extends only; cut before it")
            }
            Record::Offer(_) => panic!("an offer: this loader extends only; cut before it"),
        };
        let height = extend.height.to_raw();
        if height == 0 {
            continue;
        }
        if height > through {
            break;
        }
        assert!(
            extend.bundle_references.is_none() && extend.bundle_bodies.is_empty(),
            "the block at {height} carries a bundle section, which block_submit does not take"
        );
        for tx in &extend.transactions {
            let verdict = daemon
                .rpc
                .call::<wire::TxSubmit>(wire::tx::TxBody {
                    body: shekyl_rpc_types::kinds::Bytes(tx.serialize()),
                })
                .await
                .unwrap_or_else(|e| {
                    daemon.panic_with_log(
                        "tx_submit refused a forged transaction",
                        format!("height {height}: {e:?}"),
                    )
                });
            assert!(
                matches!(
                    verdict,
                    wire::tx::Verdict::Accepted | wire::tx::Verdict::AlreadyInPool { .. }
                ),
                "the pool did not admit a forged transaction at height {height}: {verdict:?}"
            );
            transactions += 1;
        }
        let hash = extend.block.hash().to_string();
        let accepted = daemon
            .rpc
            .call::<wire::BlockSubmit>(wire::block::BlockBody {
                body: shekyl_rpc_types::kinds::Bytes(extend.block.serialize()),
            })
            .await
            .unwrap_or_else(|e| {
                daemon.panic_with_log(
                    "block_submit refused a forged block",
                    format!("height {height}: {e:?}"),
                )
            })
            .hash
            .to_string();
        assert_eq!(
            accepted, hash,
            "the node connected another block at {height}"
        );
        tip_hash = hash;
        blocks += 1;
    }
    let tip = daemon.height().await - 1;
    assert_eq!(tip, through, "the load stopped short");
    assert_eq!(daemon.top_block_hash().await, tip_hash, "the node's tip");
    Loaded {
        tip,
        tip_hash,
        blocks,
        transactions,
        elapsed: started.elapsed(),
    }
}

/// The prototype for the body-fill walks: the hosted `shard-fill` chain,
/// loaded whole through the acceptance path, and the wallet the forge pays
/// (restored from the harness seed) sees its forged coinbases and spends
/// one, which the node connects in a block of its own.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live lane: requires SHEKYLD_BIN and the fetched hosted chain `shard-fill`"]
async fn a_forged_chain_loads_through_acceptance_and_its_coinbases_spend() {
    let dir = hosted_chain("shard-fill");
    let manifest = Manifest::read(&dir);
    let seed = shekyl_harness_wallet::HARNESS_SEED;
    let daemon = RegtestDaemon::start_for_seed_with_schedule(&seed, Some(manifest.schedule)).await;
    manifest.schedule.set_in_process_env();

    let loaded = load_forged(&daemon, &dir, manifest.tip_height).await;
    eprintln!(
        "forged chain `shard-fill` loaded through acceptance: {} blocks, {} transactions, \
         tip {} ({}), {:?}",
        loaded.blocks, loaded.transactions, loaded.tip, loaded.tip_hash, loaded.elapsed
    );
    for event in ["shard-0-closed", "shard-1-closed", "shard-2-closed"] {
        assert!(
            manifest.event(event) <= loaded.tip,
            "{event} is in what loaded"
        );
    }

    let (engine, _wallet_dir) = create_wallet(daemon.rpc_port, &seed, b"forged-harness").await;
    let arc = Arc::new(RwLock::new(engine));
    refresh(&arc).await;
    let spendable = spendable_balance(&arc).await;
    assert!(
        spendable.to_raw() > 0,
        "the wallet restored from the harness seed sees no spendable forged coinbase"
    );
    let address = arc
        .read()
        .await
        .primary_address()
        .encode()
        .expect("encode address");
    let before = daemon.height().await;
    submit_tier_b_spend(&daemon, &arc, &address, 1, 8).await;
    assert!(
        daemon.height().await > before,
        "the node mined the block holding the spend"
    );
    eprintln!("the harness wallet spent a forged coinbase: spendable was {spendable:?}");
}
