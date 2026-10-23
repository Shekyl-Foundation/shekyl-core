// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the node tests share.

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use shekyl_daemon_config::{load, Network, Platform, TABLE};
use shekyl_daemon_rpc::chain_facts::FactsFault;
use shekyl_difficulty::Difficulty;
use shekyl_miner::Job;
use shekyl_options::read_cli;
use shekyl_rpc_types::DaemonNetwork;
use shekyl_timing_engine::Tick;
use shekyl_types::BlockHash;

use super::*;

mod bans;
mod mining;
mod open;
mod pool;

fn config_at(dir: &Path) -> DaemonConfig {
    dev_config(dir, &[])
}
/// Wait until the follower's posting reads `want`.
fn wait_for_posting(posting: &mut tokio::sync::watch::Receiver<Posting>, want: &Posting) {
    let started = std::time::Instant::now();
    while *posting.borrow_and_update() != *want {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the posting stayed {:?}",
            *posting.borrow()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn open_at(dir: &Path, stop: Arc<dyn Fn() + Send + Sync>) -> Node {
    std::fs::create_dir_all(dir).expect("dir");
    let config = config_at(dir);
    Node::open(OpenArgs {
        config: &config,
        version: "test".to_owned(),
        protocol_version: 1,
        release_build: false,
        request_stop: stop,
    })
    .expect("node")
}
/// A regtest node mining to [`mining_address`] at difficulty one, with
/// `extra` options, once its first template is posted.
fn open_posted(dir: &Path, extra: &[&str]) -> Node {
    std::fs::create_dir_all(dir).expect("dir");
    let address = mining_address(shekyl_address::Network::Mainnet);
    let mut args = vec!["--mine-address", address.as_str(), "--dev-difficulty", "1"];
    args.extend(extra);
    let config = config_on(dir, "regtest", &args);
    let node = Node::open(OpenArgs {
        config: &config,
        version: "test".to_owned(),
        protocol_version: 1,
        release_build: false,
        request_stop: Arc::new(|| {}),
    })
    .expect("node");
    let mut posting = node.posting();
    let started = std::time::Instant::now();
    while !matches!(*posting.borrow_and_update(), Posting::Posted(_)) {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "nothing posted: {:?}",
            *posting.borrow()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    node
}
fn a_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
}
/// Make the posted template's block, as an outside miner would at
/// difficulty one, and submit it. Waits for the next template first,
/// so the block extends the current tip.
fn mine_one(node: &Node, above: u64) -> BlockHash {
    use shekyl_daemon_rpc::mining_methods::{get_block_template, submit_block};
    let handles = node.handles();
    let started = std::time::Instant::now();
    let reply = loop {
        match get_block_template(&*handles.mining) {
            Ok(reply) if reply.height > above => break reply,
            _ => {
                assert!(
                    started.elapsed() < Duration::from_secs(60),
                    "no template above {above}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    let blob = hex::decode(&reply.blocktemplate_blob).expect("hex");
    let made = a_runtime()
        .block_on(submit_block(
            &*handles.door,
            shekyl_rpc_types::mining::SubmitBlockRequest {
                body: hex::encode(&blob),
            },
        ))
        .expect("it connects");
    BlockHash::from_bytes(made.block_id.to_bytes())
}
/// A full address on `network`, from a fixed seed's keys.
fn mining_address(network: shekyl_address::Network) -> String {
    use shekyl_crypto_pq::account::{rederive_account, DerivationNetwork, SeedFormat};
    let blob = rederive_account(&[0x5a; 64], DerivationNetwork::Mainnet, SeedFormat::Bip39)
        .expect("the keys");
    shekyl_address::ShekylAddress::new(
        network,
        *blob.spend_pk.as_canonical_bytes(),
        *blob.view_pk.as_canonical_bytes(),
        [0; shekyl_address::MSG_SIGN_PK_LEN],
        blob.ml_kem_ek.to_vec(),
    )
    .encode()
    .expect("encodes")
}
/// A node opened on `network` that mines to [`mining_address`].
fn open_mining(dir: &Path, network: &str, address: shekyl_address::Network) -> Node {
    std::fs::create_dir_all(dir).expect("dir");
    let address = mining_address(address);
    let config = config_on(dir, network, &["--mine-address", &address]);
    Node::open(OpenArgs {
        config: &config,
        version: "test".to_owned(),
        protocol_version: 1,
        release_build: false,
        request_stop: Arc::new(|| {}),
    })
    .expect("node")
}
fn genesis_hash() -> BlockHash {
    BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(DaemonNetwork::Fakechain))
}
fn put_chain_version(path: &std::path::Path, version: u64) {
    use shekyl_chain_store::codec::{PropertyCellBytes, SchemaVersion};
    use shekyl_chain_store::schema::PROPERTIES;
    use shekyl_store_codec::{Canonical, Raw};
    let db = redb::Database::open(path).expect("the chain file opens");
    let txn = db.begin_write().expect("write");
    {
        let mut table = txn.open_table(PROPERTIES).expect("properties");
        let version = SchemaVersion::new(version);
        table
            .insert(
                "schema_version",
                Raw::<PropertyCellBytes>::new(&version.encode()),
            )
            .expect("version");
    }
    txn.commit().expect("commit");
}
fn put_pool_version(path: &std::path::Path, version: u64) {
    use shekyl_chain_store::codec::PropertyCellBytes;
    use shekyl_chain_store::pool::schema::POOL_HEADER;
    use shekyl_chain_store::pool::{PoolSchemaVersion, POOL_VERSION_KEY};
    use shekyl_store_codec::{Canonical, Raw};
    let db = redb::Database::open(path).expect("the pool file opens");
    let txn = db.begin_write().expect("write");
    {
        let mut table = txn.open_table(POOL_HEADER).expect("header");
        let version = PoolSchemaVersion::new(version);
        table
            .insert(
                POOL_VERSION_KEY,
                Raw::<PropertyCellBytes>::new(&version.encode()),
            )
            .expect("version");
    }
    txn.commit().expect("commit");
}
fn dev_config(dir: &Path, extra: &[&str]) -> DaemonConfig {
    config_on(dir, "regtest", extra)
}
fn config_on(dir: &Path, network: &str, extra: &[&str]) -> DaemonConfig {
    let log = dir.join("shekyld.log");
    let mut args = vec![
        "--network",
        network,
        "--clearnet",
        "off",
        "--tor",
        "off",
        "--data-dir",
        dir.to_str().expect("utf8"),
        "--log-file",
        log.to_str().expect("utf8"),
    ];
    args.extend(extra);
    let cli = read_cli(&TABLE, args.into_iter().map(OsString::from)).expect("cli");
    load(
        cli,
        &Platform {
            home: Some(dir.to_path_buf()),
            program_data: None,
        },
    )
    .expect("config")
    .config
}
