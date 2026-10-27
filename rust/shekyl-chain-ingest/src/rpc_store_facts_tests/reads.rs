// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Alt-chain work, pool spends, and the Q1 reads.

use super::*;

/// Under the real difficulty schedule an alt block's work is its own
/// chain's: the second block of a two-block branch is priced over a window
/// holding the branch's first, so its cumulative difficulty differs from
/// the main block's at the same height. The facts report the alt row's
/// figure and the producer's claimed target, never the main chain's.
#[tokio::test]
async fn an_alt_blocks_work_is_its_own_chains_not_the_main_chains_at_its_height() {
    let rules = ChainRules::Regtest {
        fixed_difficulty: None,
        schedule: shekyl_chain_rules::FakechainSchedule::PRODUCTION,
    };
    // Past LWMA-1's window: before it fills every block carries the
    // genesis difficulty, and the two works would coincide.
    let prefix = shekyl_difficulty::N + 2;
    let mut x = Scenario::open_under("rpc-store-facts-lwma-x", crate::scenario::FreeHash, rules);
    let mut y = Scenario::open_under("rpc-store-facts-lwma-y", crate::scenario::FreeHash, rules);
    x.mine(prefix).await;
    y.mine(prefix).await;
    let main = x.mine(3).await;
    y.idle();
    y.idle();
    y.idle();
    let branch = y.mine(2).await;
    for mined in &branch {
        match x.offer(mined).await.expect("offer") {
            Offered::Held { height } => assert_eq!(height, mined.height),
            other => panic!("a lighter branch is held: {other:?}"),
        }
    }
    let second = &branch[1];
    let main_at = main
        .iter()
        .find(|m| m.height == second.height)
        .expect("the main chain holds the height");
    x.reopen(|path| {
        let store = Arc::new(open_store_under(
            path,
            &rules.in_force(BlockHeight::ZERO),
            ApplyPolicy::Full,
        ));
        let facts = facts_over(Arc::clone(&store), path, rules);
        let row_cumulative = store
            .begin_read()
            .expect("read")
            .alt_block(&second.hash)
            .expect("read")
            .expect("held")
            .cumulative_difficulty()
            .to_raw();
        let main_header = facts
            .block_header_at(BlockLookup::Hash(main_at.hash.to_bytes()), false)
            .expect("facts")
            .header
            .expect("main block");
        // The test's subject exists: the two works differ at this height.
        assert_ne!(
            row_cumulative,
            main_header.cumulative_difficulty,
            "the branch's work differs from the main chain's at height {}",
            second.height.to_raw()
        );
        let header = facts
            .block_header_at(BlockLookup::Hash(second.hash.to_bytes()), false)
            .expect("facts")
            .header
            .expect("the alt block is held");
        assert!(header.orphan_status);
        assert_eq!(header.cumulative_difficulty, row_cumulative);
        assert_eq!(header.difficulty, second.target.difficulty().to_raw());
        drop(facts);
        drop(store);
    })
    .await;
    x.close().await;
    y.close().await;
}

/// `facts_over`, with the pool's shown entries spending `pool_spends`.
fn facts_with_pool_spends(
    store: Arc<ChainStore>,
    path: &Path,
    pool_spends: Vec<shekyl_types::KeyImage>,
) -> StoreFacts {
    let mut node = TestNode::synced();
    node.pool_spends = pool_spends;
    StoreFacts::new(
        store,
        path.to_path_buf(),
        Arc::new(move |h| RULES.in_force(h)),
        Arc::new(node),
        identity(),
        Arc::new(CacheStore::new()),
        shekyl_hash_budget::Budget::of_host(),
    )
}

/// A node whose pool read first lets a block connect — the race a live
/// node runs between the pool and the chain — and then reads the pool as
/// the reconcile left it: the connected spend is no longer there.
struct ConnectingNode {
    inner: TestNode,
    connect: std::sync::Mutex<Option<Box<dyn FnOnce() -> bool + Send>>>,
    connected: Arc<std::sync::atomic::AtomicBool>,
}

impl NodeFacts for ConnectingNode {
    fn sync(&self) -> Result<SyncFacts, FactsFault> {
        self.inner.sync()
    }
    fn pool_counts(
        &self,
        scope: PoolScope,
    ) -> Result<shekyl_daemon_rpc::info_facts::PoolState<PoolCounts>, FactsFault> {
        self.inner.pool_counts(scope)
    }
    fn pool_spends(&self, key_images: &[shekyl_types::KeyImage]) -> Result<Vec<bool>, FactsFault> {
        let connect = self.connect.lock().expect("the hook").take();
        if let Some(connect) = connect {
            self.connected
                .store(connect(), std::sync::atomic::Ordering::Release);
        }
        Ok(vec![false; key_images.len()])
    }
    fn pool_bodies(
        &self,
        ids: &[shekyl_types::TxHash],
        scope: PoolScope,
    ) -> Result<
        shekyl_daemon_rpc::info_facts::PoolState<
            Vec<Option<shekyl_daemon_rpc::store_facts::PoolBody>>,
        >,
        FactsFault,
    > {
        self.inner.pool_bodies(ids, scope)
    }
    fn peers(&self) -> Result<PeerFacts, FactsFault> {
        self.inner.peers()
    }
    fn sessions(&self) -> Result<SessionCounts, FactsFault> {
        self.inner.sessions()
    }
    fn free_space(&self) -> Result<u64, FactsFault> {
        self.inner.free_space()
    }
    fn now(&self) -> u64 {
        self.inner.now()
    }
}

/// A spend whose block connects between the pool read and the chain read
/// is answered spent in the chain, never unspent (the review of #1165,
/// M6). The block connects through a live service's door from inside the
/// pool read; the pool then no longer shows the spend. Red edit: read the
/// chain's snapshot before the pool.
#[tokio::test(flavor = "multi_thread")]
async fn a_spend_connected_between_the_reads_is_spent_in_the_chain() {
    use crate::service::{Arrival, ArrivalTag, Follow, Origin, Reply, Service};
    let (mut scenario, mined) = crate::pool_door_tests::matured("rpc-ki-race").await;
    let spend = crate::pool_door_tests::paying_the_floor(&mut scenario, &mined, 0).await;
    let image = key_image_of(&spend);
    let copy = crate::test_support::tmp("rpc-ki-race-copy");
    scenario
        .reopen(|path| {
            std::fs::copy(path, &copy).expect("a copy of the chain");
        })
        .await;
    let landed = scenario
        .mine_listing(vec![spend.clone()])
        .await
        .unwrap_or_else(|o| panic!("the spend lands: {o}"));
    let store = Arc::new(crate::test_support::open_store_under(
        &copy,
        &RULES.in_force(crate::test_support::h(0)),
        shekyl_chain_store::apply_policy::ApplyPolicy::Full,
    ));
    let service = Service::start(
        Arc::clone(&store),
        RULES,
        Arc::new(crate::service::service_tests::Gated::new()),
        crate::service::ServiceConfig::default(),
        shekyl_hash_budget::Budget::of_host(),
        Follow {
            job: None,
            pool: None,
            ..Default::default()
        },
    );
    let door = service.door();
    let runtime = tokio::runtime::Handle::current();
    let block = landed.template.block.serialize();
    let bodies = vec![spend.serialize()];
    let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let node = ConnectingNode {
        inner: TestNode::synced(),
        connect: std::sync::Mutex::new(Some(Box::new(move || {
            let reply = runtime.block_on(async move {
                door.offer(Arrival {
                    tag: ArrivalTag(1),
                    origin: Origin::Local,
                    block,
                    bodies,
                })
                .expect("room")
                .reply()
                .await
                .reply
            });
            matches!(reply, Reply::Connected { .. })
        }))),
        connected: Arc::clone(&connected),
    };
    let facts = StoreFacts::new(
        store,
        copy.clone(),
        Arc::new(move |h| RULES.in_force(h)),
        Arc::new(node),
        identity(),
        Arc::new(CacheStore::new()),
        shekyl_hash_budget::Budget::of_host(),
    );
    let spent = tokio::task::spawn_blocking(move || {
        shekyl_daemon_rpc::read_facts::ChainReadFacts::key_images_spent(
            &facts,
            &[shekyl_types::KeyImage::from_bytes(image)],
        )
    })
    .await
    .expect("joined");
    service.stop().await.expect("stops");
    crate::test_support::cleanup(&copy);
    scenario.close().await;
    assert!(
        connected.load(std::sync::atomic::Ordering::Acquire),
        "the block connected between the reads"
    );
    assert_eq!(
        spent.expect("read"),
        vec![shekyl_daemon_rpc::read_facts::SpentAt::Chain]
    );
}

/// A local HTTP stand-in for the daemon that serves the wallet's block
/// fetch from `facts`: `get_block` (JSON-RPC), `get_transactions` and
/// `get_o_indexes.bin`, each by the store-backed handler, one request per
/// connection.
async fn serve_the_block_fetch(facts: Arc<StoreFacts>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let url = format!("http://{}", listener.local_addr().expect("an address"));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let facts = Arc::clone(&facts);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body) = loop {
                    let read = socket.read(&mut chunk).await.expect("read");
                    assert!(read > 0, "the request ended early");
                    request.extend_from_slice(&chunk[..read]);
                    if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&request[..at]).to_string();
                        let length = head
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        while request.len() < at + 4 + length {
                            let read = socket.read(&mut chunk).await.expect("read");
                            request.extend_from_slice(&chunk[..read]);
                        }
                        break (head, request[at + 4..at + 4 + length].to_vec());
                    }
                };
                let path = head
                    .split_whitespace()
                    .nth(1)
                    .expect("a request line")
                    .to_owned();
                let reply: Vec<u8> = match path.as_str() {
                    "/json_rpc" => {
                        let call: serde_json::Value =
                            serde_json::from_slice(&body).expect("a JSON-RPC call");
                        assert_eq!(call["method"], "get_block");
                        let request: shekyl_rpc_types::GetBlockRequest =
                            serde_json::from_value(call["params"].clone()).expect("params");
                        let block = shekyl_daemon_rpc::methods::get_block(&*facts, &request, false)
                            .expect("the block");
                        serde_json::to_vec(&serde_json::json!({
                            "jsonrpc": "2.0", "id": 0, "result": block
                        }))
                        .expect("json")
                    }
                    "/get_transactions" => {
                        let request: shekyl_rpc_types::GetTransactionsRequest =
                            serde_json::from_slice(&body).expect("a request");
                        let reply = shekyl_daemon_rpc::read_methods::get_transactions(
                            &*facts, &request, false,
                        )
                        .expect("the bodies");
                        serde_json::to_vec(&reply).expect("json")
                    }
                    "/get_o_indexes.bin" => {
                        let request = shekyl_rpc_types::GetOIndexesRequest::from_bin(&body)
                            .expect("a request");
                        shekyl_daemon_rpc::read_methods::get_o_indexes(&*facts, &request)
                            .expect("the indices")
                            .to_bin()
                            .expect("bin")
                    }
                    other => panic!("the block fetch asked for {other}"),
                };
                let mut out = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                )
                .into_bytes();
                out.extend(reply);
                socket.write_all(&out).await.expect("write");
            });
        }
    });
    url
}

/// The wallet's block fetch reads a block and its spend from the
/// store-backed handlers (the review of #1165, ruling 7): `get_block`,
/// `get_transactions` in the pruned form the wallet asks for — with no
/// `as_json` — and the first output index. The wallet binds each pruned
/// body to the hash it asked by (its `prunable_hash` and archival length),
/// so a body served wrong fails here. A lone `Node` holds no spendable
/// output, so the chain is the scenario's, read through the same
/// `StoreFacts` a node's handles read. Red edit: serve the pruned half
/// without its `pqc_auths`.
#[tokio::test(flavor = "multi_thread")]
async fn the_wallets_block_fetch_reads_a_spend_from_the_store_backed_handlers() {
    let (mut scenario, mined) = crate::pool_door_tests::matured("rpc-wallet-fetch").await;
    let spend = crate::pool_door_tests::paying_the_floor(&mut scenario, &mined, 0).await;
    let landed = scenario
        .mine_listing(vec![spend.clone()])
        .await
        .unwrap_or_else(|o| panic!("the spend lands: {o}"));
    let copy = crate::test_support::tmp("rpc-wallet-fetch-copy");
    scenario
        .reopen(|path| {
            std::fs::copy(path, &copy).expect("a copy of the chain");
        })
        .await;
    let store = Arc::new(open_store(&copy));
    let facts = Arc::new(facts_with_pool_spends(store, &copy, Vec::new()));
    let url = serve_the_block_fetch(facts).await;
    let client = shekyl_engine_core::engine::DaemonClient::new(
        shekyl_rpc_transport::HttpRpc::new(url)
            .await
            .expect("a client"),
    );
    let fetched = client
        .fetch_scannable_block(usize::try_from(landed.height.to_raw()).expect("fits"))
        .await;
    crate::test_support::cleanup(&copy);
    scenario.close().await;
    let fetched = fetched.expect("the wallet reads the block");
    assert_eq!(fetched.block.serialize(), landed.template.block.serialize());
    assert_eq!(fetched.transactions.len(), 1);
    // The pruned form the wallet asked for: the wallet bound it to the
    // listed hash through `prunable_hash` and the archival length.
    assert_eq!(fetched.block.transaction_hashes, vec![spend.hash()]);
    assert_eq!(fetched.transactions[0].prefix, spend.prefix);
    assert!(fetched.first_output_index.is_some());
}

/// `get_transactions` over the store and a pool: a mined transaction
/// carries its height and output indices; a pool entry is `in_pool`,
/// relayed, with no receive time; an id held nowhere is missed; nothing
/// carries `as_json` (the review of #1165, ruling 7). Red edit: the gather
/// passes over the pool.
#[tokio::test]
async fn get_transactions_answers_the_chain_the_pool_and_a_miss() {
    let (mut scenario, mined) = crate::pool_door_tests::matured("rpc-get-transactions").await;
    let spend = crate::pool_door_tests::paying_the_floor(&mut scenario, &mined, 0).await;
    let landed = scenario
        .mine_listing(vec![spend.clone()])
        .await
        .unwrap_or_else(|o| panic!("the spend lands: {o}"));
    let pooled = crate::pool_door_tests::paying_the_floor(&mut scenario, &mined, 1).await;
    let nowhere = [0x66; 32];
    scenario
        .reopen(|path| {
            let store = Arc::new(open_store(path));
            let mut node = TestNode::synced();
            node.pool_bodies = vec![pooled.clone()];
            let facts = StoreFacts::new(
                store,
                path.to_path_buf(),
                Arc::new(move |h| RULES.in_force(h)),
                Arc::new(node),
                identity(),
                Arc::new(CacheStore::new()),
                shekyl_hash_budget::Budget::of_host(),
            );
            let reply = shekyl_daemon_rpc::read_methods::get_transactions(
                &facts,
                &shekyl_rpc_types::GetTransactionsRequest {
                    txs_hashes: vec![
                        hex::encode(spend.hash().to_bytes()),
                        hex::encode(pooled.hash().to_bytes()),
                        hex::encode(nowhere),
                    ],
                    decode_as_json: false,
                    prune: false,
                    split: false,
                },
                false,
            )
            .expect("answered");
            assert!(reply.status.is_ok());
            assert_eq!(reply.txs.len(), 2);
            assert_eq!(
                reply.missed_tx,
                vec![shekyl_rpc_types::HashHex::from_bytes(nowhere)]
            );
            let mined_entry = &reply.txs[0];
            assert_eq!(mined_entry.as_hex, hex::encode(spend.serialize()));
            match &mined_entry.location {
                shekyl_rpc_types::TxLocation::Mined {
                    block_height,
                    output_indices,
                    ..
                } => {
                    assert_eq!(*block_height, landed.height.to_raw());
                    assert_eq!(output_indices.len(), spend.prefix.outputs.len());
                }
                other => panic!("mined: {other:?}"),
            }
            let pool_entry = &reply.txs[1];
            assert!(pool_entry.location.in_pool());
            assert_eq!(
                pool_entry.location,
                shekyl_rpc_types::TxLocation::Pooled {
                    relayed: true,
                    received_timestamp: None,
                }
            );
            assert_eq!(pool_entry.as_hex, hex::encode(pooled.serialize()));
            assert!(reply.txs.iter().all(|entry| entry.as_json.is_none()));
            let wire = serde_json::to_string(&reply).expect("json");
            assert!(!wire.contains("as_json"), "absent, not empty: {wire}");
            assert!(!wire.contains("received_timestamp"), "{wire}");
        })
        .await;
    scenario.close().await;
}

/// The first key image `tx` spends.
fn key_image_of(tx: &shekyl_wire::Transaction) -> [u8; 32] {
    tx.prefix
        .inputs
        .iter()
        .find_map(|input| match input {
            shekyl_wire::transaction::Input::ToKey { key_image, .. } => Some(*key_image),
            _ => None,
        })
        .expect("a spend")
}

/// Q1's reads over the store and the pool (DX-Q3): the blocks by height
/// with their bodies whole, ending at the first height above the tip with
/// C++'s error status; a transaction's output indices, and `Failed` for
/// one the chain does not hold; a key image spent in the chain, one the
/// pool shows, and one spent nowhere. Red edit: answer the pool before the
/// chain, so a mined spend reads as a pool spend.
#[tokio::test]
async fn the_q1_reads_answer_from_the_store_and_the_pool() {
    use shekyl_daemon_rpc::read_methods::{
        get_blocks_by_height, get_o_indexes, is_key_image_spent,
    };
    use shekyl_rpc_types::{
        GetBlocksByHeightRequest, GetOIndexesRequest, IsKeyImageSpentRequest, KeyImageStatus,
    };
    let (mut scenario, mined) = crate::pool_door_tests::matured("rpc-q1-reads").await;
    let spend = crate::pool_door_tests::paying_the_floor(&mut scenario, &mined, 0).await;
    let landed = scenario
        .mine_listing(vec![spend.clone()])
        .await
        .unwrap_or_else(|o| panic!("the spend lands: {o}"));
    let pooled = crate::pool_door_tests::paying_the_floor(&mut scenario, &mined, 1).await;
    let mined_image = key_image_of(&spend);
    let pooled_image = key_image_of(&pooled);
    let nowhere = [0x5a; 32];
    let spend_id = spend.txid_parts().hash;
    scenario
        .reopen(|path| {
            let store = Arc::new(open_store(path));
            let facts = facts_with_pool_spends(
                Arc::clone(&store),
                path,
                vec![
                    shekyl_types::KeyImage::from_bytes(mined_image),
                    shekyl_types::KeyImage::from_bytes(pooled_image),
                ],
            );
            let past = landed.height.to_raw() + 1;
            let blocks = get_blocks_by_height(
                &facts,
                &GetBlocksByHeightRequest {
                    heights: vec![0, landed.height.to_raw(), past],
                },
                true,
            )
            .expect("blocks");
            assert_eq!(
                blocks.status.0,
                format!("Error retrieving block at height {past}")
            );
            assert_eq!(blocks.blocks.len(), 2, "the two below the tip");
            assert_eq!(blocks.blocks[0].block, mined[0].template.block.serialize());
            assert_eq!(blocks.blocks[1].block, landed.template.block.serialize());
            assert_eq!(
                blocks.blocks[1].txs,
                vec![spend.serialize()],
                "the body, whole"
            );

            let indices = get_o_indexes(
                &facts,
                &GetOIndexesRequest {
                    txid: spend_id.to_bytes(),
                },
            )
            .expect("indices");
            assert_eq!(indices.status.0, "OK");
            assert_eq!(indices.o_indexes.len(), spend.prefix.outputs.len());
            let unknown =
                get_o_indexes(&facts, &GetOIndexesRequest { txid: [0x77; 32] }).expect("answered");
            assert_eq!(unknown.status.0, "Failed");

            let spent = is_key_image_spent(
                &facts,
                &IsKeyImageSpentRequest {
                    key_images: vec![
                        hex::encode(mined_image),
                        hex::encode(pooled_image),
                        hex::encode(nowhere),
                    ],
                },
                true,
            )
            .expect("spent");
            assert_eq!(
                spent.spent_status,
                vec![
                    KeyImageStatus::SpentInBlockchain,
                    KeyImageStatus::SpentInPool,
                    KeyImageStatus::Unspent,
                ]
            );
        })
        .await;
    scenario.close().await;
}
