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
    let rules = ChainRules::harness_regtest(None, shekyl_chain_rules::CappedEpoch::PRODUCTION);
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
    path: impl AsRef<Path>,
    pool_spends: Vec<shekyl_types::KeyImage>,
) -> StoreFacts {
    let path: &Path = path.as_ref();
    let mut node = TestNode::synced();
    node.pool_spends = pool_spends;
    StoreFacts::new(
        store,
        path.to_path_buf(),
        Arc::new(move |h| RULES.in_force(h)),
        Arc::new(node),
        identity(),
        crate::test_support::unranked_hasher(),
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
    fn sync_view(&self) -> Result<shekyl_daemon_rpc::sync_facts::SyncViewFacts, FactsFault> {
        self.inner.sync_view()
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
                    bundle_references: Vec::new(),
                    bundle_bodies: Vec::new(),
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
        copy.path().to_path_buf(),
        Arc::new(move |h| RULES.in_force(h)),
        Arc::new(node),
        identity(),
        crate::test_support::unranked_hasher(),
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

/// What a serving stand-in does to a `block_show` reply before it goes on
/// the wire: nothing, or one edit a falsifier names.
pub(super) type ReplyEdit = Arc<dyn Fn(&mut shekyl_rpc_types::wire::block::Block) + Send + Sync>;

/// A local HTTP stand-in for the daemon that serves the wallet's reads
/// from `facts`: `block_show` (the block fetch) and `tx_list` (the proof
/// fetch), each by the store-backed handler, on `/json_rpc`, one request
/// per connection.
pub(super) async fn serve_the_block_fetch(facts: Arc<StoreFacts>) -> String {
    serve_the_block_fetch_editing(facts, Arc::new(|_| {})).await
}

/// [`serve_the_block_fetch`], with `edit` applied to every `block_show`
/// reply: the lying daemon of `SB-Q2`'s falsifiers, which change one
/// operand of one served skeleton.
pub(super) async fn serve_the_block_fetch_editing(
    facts: Arc<StoreFacts>,
    edit: ReplyEdit,
) -> String {
    use shekyl_rpc_types::wire::Id;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let url = format!("http://{}", listener.local_addr().expect("an address"));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let facts = Arc::clone(&facts);
            let edit = Arc::clone(&edit);
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
                assert_eq!(
                    path,
                    shekyl_rpc_types::endpoint::JSON_RPC_PATH,
                    "every call is on one path"
                );
                let call: serde_json::Value =
                    serde_json::from_slice(&body).expect("a JSON-RPC call");
                let method = call["method"].as_str().expect("a method");
                let params = call["params"].clone();
                let result = match Id::of(method) {
                    Some(Id::BlockShow) => {
                        let request = serde_json::from_value(params).expect("params");
                        let mut block =
                            shekyl_daemon_rpc::reads::block_show(&*facts, &*facts, &request)
                                .unwrap_or_else(|_| panic!("the block"));
                        edit(&mut block);
                        serde_json::to_value(block).expect("json")
                    }
                    Some(Id::TxList) => {
                        let request = serde_json::from_value(params).expect("params");
                        let listed = shekyl_daemon_rpc::reads::tx_list(&*facts, &request, false)
                            .unwrap_or_else(|_| panic!("the bodies"));
                        serde_json::to_value(listed).expect("json")
                    }
                    _ => panic!("the wallet asked for {method}"),
                };
                let reply = serde_json::to_vec(&serde_json::json!({
                    "jsonrpc": "2.0", "id": 0, "result": result
                }))
                .expect("json");
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
/// store-backed handlers (the review of #1165, ruling 7): one `block_show`
/// in the pruned form the wallet asks for, with the first output index. The wallet binds each pruned
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
    scenario.close().await;
    let fetched = fetched.expect("the wallet reads the block");
    assert_eq!(fetched.block.serialize(), landed.template.block.serialize());
    assert_eq!(fetched.transactions.len(), 1);
    // The pruned form the wallet asked for: the wallet bound it to the
    // listed hash through `prunable_hash` and the archival length.
    assert_eq!(fetched.block.transaction_hashes, vec![spend.hash()]);
    assert_eq!(fetched.transactions[0].tx().prefix, spend.prefix);
    assert!(fetched.first_output_index.is_some());
}

/// `tx_list` over the store and a pool: a mined transaction carries its
/// height and output indices; a pool entry is `pooled`, public, with no
/// receive time; an id held nowhere is `{"missing": null}`; the full form
/// carries each whole body and no `archived` state, since nothing is
/// discarded this side of the first boundary (`SB-Q2`). Red edit: the
/// gather passes over the pool.
#[tokio::test]
async fn tx_list_answers_the_chain_the_pool_and_a_miss() {
    use shekyl_rpc_types::wire::shared::{Slot, SlotState};
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
                crate::test_support::unranked_hasher(),
            );
            let reply = shekyl_daemon_rpc::reads::tx_list(
                &facts,
                &shekyl_rpc_types::wire::tx::TxListQuery {
                    id: vec![
                        HashHex::from_bytes(spend.hash().to_bytes()),
                        HashHex::from_bytes(pooled.hash().to_bytes()),
                        HashHex::from_bytes(nowhere),
                    ],
                    prune: false,
                },
                false,
            )
            .unwrap_or_else(|_| panic!("answered"));
            let [Slot::Item(mined_entry), Slot::Item(pool_entry), missing] = reply.as_slice()
            else {
                panic!("the chain's and the pool's entries, then the miss: {reply:?}");
            };
            assert_eq!(missing, &Slot::State(SlotState::Missing(Null)));
            assert_eq!(mined_entry.body.0, spend.serialize());
            assert!(!mined_entry.pooled);
            assert_eq!(
                mined_entry.mined_height.0.map(|h| h.0),
                Some(landed.height.to_raw())
            );
            assert_eq!(mined_entry.output_index.len(), spend.prefix.outputs.len());
            assert!(pool_entry.pooled);
            assert_eq!(pool_entry.public.0, Some(true));
            assert_eq!(pool_entry.mined_height.0, None);
            assert_eq!(pool_entry.body.0, pooled.serialize());
            let wire = serde_json::to_string(&reply).expect("json");
            assert!(!wire.contains("archived"), "no archived state: {wire}");
            assert!(!wire.contains("received"), "no receive time: {wire}");
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
/// with their bodies whole, a height above the tip `{"missing": null}`
/// and the request not failed; a block's first output index; a key image
/// spent in the chain, one the pool shows, and one spent nowhere. Red edit:
/// answer the pool before the chain, so a mined spend reads as a pool
/// spend.
#[tokio::test]
async fn the_q1_reads_answer_from_the_store_and_the_pool() {
    use shekyl_daemon_rpc::reads::{block_list, chain_spent};
    use shekyl_rpc_types::kinds::Height;
    use shekyl_rpc_types::wire::block::BlockListQuery;
    use shekyl_rpc_types::wire::chain::{Spent, SpentQuery};
    use shekyl_rpc_types::wire::shared::{OrArchived, Slot, SlotState};
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
            let past = landed.height.saturating_add(shekyl_types::BlockCount::ONE);
            let query = |heights: Vec<BlockHeight>, prune| BlockListQuery {
                height: heights
                    .into_iter()
                    .map(|height| Height(height.to_raw()))
                    .collect(),
                prune,
            };
            let blocks = block_list(
                &facts,
                &facts,
                &query(vec![BlockHeight::ZERO, landed.height, past], false),
                false,
            )
            .unwrap_or_else(|_| panic!("blocks"));
            let [Slot::Item(genesis), Slot::Item(block), above] = blocks.as_slice() else {
                panic!("two blocks, then the height above the tip: {blocks:?}");
            };
            assert_eq!(
                above,
                &Slot::State(SlotState::Missing(Null)),
                "only the height above the tip is missing"
            );
            assert_eq!(genesis.body.0, mined[0].template.block.serialize());
            assert_eq!(block.body.0, landed.template.block.serialize());
            let [OrArchived::Item(whole)] = block.tx.as_slice() else {
                panic!("one listed body, whole: {:?}", block.tx);
            };
            assert_eq!(
                whole.body.0,
                spend.serialize(),
                "the full form: the body, whole"
            );

            // The pruned form (SB-Q2): the slot is the skeleton, and it binds
            // to the id the block lists through `SkeletonTx::txid`.
            let pruned = block_list(&facts, &facts, &query(vec![landed.height], true), false)
                .unwrap_or_else(|_| panic!("blocks"));
            let [Slot::Item(pruned_block)] = pruned.as_slice() else {
                panic!("one block: {pruned:?}");
            };
            let [OrArchived::Item(slot)] = pruned_block.tx.as_slice() else {
                panic!("under prune the one listed body is a skeleton");
            };
            let parts = spend.txid_parts();
            // Under `prune` the operands are selected, so present.
            let prunable_hash = slot.prunable_hash.present().expect("asked with prune");
            let pqc_auth_hash = slot.pqc_auth_hash.present().expect("asked with prune");
            let archival_size = slot.archival_size.present().expect("asked with prune");
            assert_eq!(prunable_hash.to_bytes(), parts.prunable_hash.to_bytes());
            assert_eq!(
                pqc_auth_hash.0.map(shekyl_rpc_client::HashHex::to_bytes),
                parts.pqc_auth_hash.map(shekyl_types::PqcAuthHash::to_bytes)
            );
            let skeleton = shekyl_wire::SkeletonTx {
                unprunable: slot.body.0.clone(),
                prunable_hash: shekyl_types::PrunableHash::from_bytes(prunable_hash.to_bytes()),
                pqc_auth_hash: pqc_auth_hash
                    .0
                    .map(|h| shekyl_types::PqcAuthHash::from_bytes(h.to_bytes())),
                archival_len: shekyl_types::ArchivalLength::from_raw(archival_size.0),
            };
            assert_eq!(
                skeleton.txid().expect("the skeleton binds"),
                spend_id,
                "the skeleton rebinds the listed id"
            );
            // The block's first output index, beside its bytes (RW-Q5).
            assert_eq!(
                pruned_block.output_index, block.output_index,
                "one index whatever the form"
            );
            assert!(block.output_index.0 > genesis.output_index.0);

            let spent = chain_spent(
                &facts,
                &SpentQuery {
                    key_image: vec![
                        HashHex::from_bytes(mined_image),
                        HashHex::from_bytes(pooled_image),
                        HashHex::from_bytes(nowhere),
                    ],
                },
                true,
            )
            .unwrap_or_else(|_| panic!("spent"));
            assert_eq!(spent, vec![Spent::Chain, Spent::Txpool, Spent::Unspent]);
        })
        .await;
    scenario.close().await;
}
