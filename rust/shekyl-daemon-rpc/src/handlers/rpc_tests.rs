// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `/json_rpc` end to end through [`answer`]: the envelope, the method
//! table, admission at dispatch, and one refusal per class (`RPC_WIRE.md`
//! RW-Q1, RW-Q2, RW-Q3, RW-Q7).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::{json, Value};
use shekyl_chain_rules::{AdmissionPolicy, RuleSet};
use shekyl_chain_store::store::{ChainStore, SnapshotView};
use shekyl_mempool::Pool;
use shekyl_rpc_types::errors::{ErrorClass, RpcError, METHOD_NOT_FOUND};
use shekyl_rpc_types::method::{RpcMethod, UNARMED};
use shekyl_rpc_types::wire::{self, TABLE};
use shekyl_types::archival::SettlementEpochBlocks;
use shekyl_types::{BlockHeight, UnixSeconds};
use tokio::sync::Semaphore;

use super::{answer, codes};
use crate::authority::{codes as grant, Authority};
use crate::conn_limit::{ConnLimits, ConnTracker};
use crate::handles::Handles;
use crate::hash_budget::HashBudget;
use crate::options::OptionsAbsent;
use crate::server::AppState;
use crate::shard_view::{ShardViewAbsent, ShardViewHandle, TorOff};
use crate::store_facts::RulesAt;
use crate::submit::{DaemonTxVerifier, RustPoolShim, StoreChain, SubmitEngine};

/// A scratch directory under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("shekyl-rpc-dispatch-{tag}-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// The state `build_router` serves: a real submit engine over an empty
/// store and pool, and every node handle absent (each read is
/// `daemon.unready`). The shard view is the same absence.
fn state(tag: &str) -> (Scratch, Arc<AppState>) {
    state_with(tag, Arc::new(ShardViewAbsent))
}

/// `state`, with the shard view the test names. A node that was not
/// supplied is [`ShardViewAbsent`]; a node with Tor off is [`TorOff`].
fn state_with(tag: &str, shard_view: ShardViewHandle) -> (Scratch, Arc<AppState>) {
    let scratch = Scratch::new(tag);
    let epoch = SettlementEpochBlocks::new(10_000).expect("non-zero epoch");
    let store =
        Arc::new(ChainStore::create(scratch.0.join("chain.redb"), epoch).expect("create store"));
    let pool = {
        let snapshot = store.begin_read().expect("a snapshot");
        Pool::open(
            scratch.0.join("pool.redb"),
            UnixSeconds::from_raw(1),
            &SnapshotView::new(&snapshot),
            &RuleSet::GENESIS,
            &shekyl_network::HARNESS_NETWORK_ID,
            &AdmissionPolicy::GENESIS,
        )
        .expect("open pool")
        .0
    };
    let rules: Arc<dyn RulesAt> = Arc::new(|_: BlockHeight| RuleSet::GENESIS);
    let shim = RustPoolShim::new(
        StoreChain::new(store, rules),
        Arc::new(Mutex::new(pool)),
        AdmissionPolicy::GENESIS,
        || UnixSeconds::from_raw(1),
        shekyl_network::HARNESS_NETWORK_ID,
    );
    let state = Arc::new(AppState {
        submit_engine: Arc::new(SubmitEngine::new(shim, DaemonTxVerifier)),
        conn_tracker: ConnTracker::new(ConnLimits::default()),
        shard_view,
        options: Arc::new(OptionsAbsent),
        handles: Handles::absent(),
        tor: Arc::new(crate::tor_facts::TorAbsent),
        hash_budget: Arc::new(HashBudget::new(Instant::now())),
        coinbase_reads: Arc::new(Semaphore::new(1)),
    });
    (scratch, state)
}

/// One request's envelope.
fn call(method: &str, params: Value) -> Value {
    let mut request = json!({"jsonrpc": "2.0", "id": 7, "method": method});
    request["params"] = params;
    request
}

/// The reply to `body`, as JSON. Every reply is a result or an error,
/// never both and never neither: a refusal is never a result.
async fn reply_to(state: &Arc<AppState>, authority: Authority, body: &[u8]) -> Value {
    let reply = serde_json::to_value(answer(state, authority, body).await).expect("serializes");
    assert_eq!(reply["jsonrpc"], "2.0", "{reply}");
    assert!(
        reply.get("result").is_some() != reply.get("error").is_some(),
        "a result or an error, exactly one: {reply}"
    );
    reply
}

async fn send(state: &Arc<AppState>, authority: Authority, request: &Value) -> Value {
    reply_to(state, authority, request.to_string().as_bytes()).await
}

/// The refusal's JSON-RPC code and dotted diagnostic code, or `None` for a
/// result.
fn refusal(reply: &Value) -> Option<(i64, String)> {
    let error = reply.get("error")?;
    Some((
        error["code"].as_i64().expect("an integer code"),
        // A configuration refusal's `data` is its list (RT-O25), not a
        // diagnostic; it has no dotted code of its own.
        error["data"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    ))
}

const ADMIN: Authority = Authority::admin_listener(true);

/// Every 3.x method name the census lists (`INPUT_GRAMMAR.md` §17's "Served
/// today" column), JSON-RPC and REST alike with the path's slash dropped,
/// and the names DX-Q3 deleted. `option_set` and `option_show` kept their
/// names and are not here. At 4.0 none of them is a method, on any
/// listener: there are no aliases (rule 83).
const OLD_NAMES: &[&str] = &[
    "get_version",
    "get_height",
    "getheight",
    "get_block_count",
    "getblockcount",
    "get_block_header_by_height",
    "getblockheaderbyheight",
    "get_block_header_by_hash",
    "getblockheaderbyhash",
    "get_last_block_header",
    "getlastblockheader",
    "on_get_block_hash",
    "on_getblockhash",
    "get_block_headers_range",
    "getblockheadersrange",
    "get_block",
    "getblock",
    "get_blocks_by_height.bin",
    "getblocks_by_height.bin",
    "get_o_indexes.bin",
    "get_transactions",
    "gettransactions",
    "is_key_image_spent",
    "get_fee_estimate",
    "get_coinbase_tx_sum",
    "get_alternate_chains",
    "get_alt_blocks_hashes",
    "get_curve_tree_info",
    "get_curve_tree_checkpoint",
    "get_archival_emission_claim_source",
    "get_archival_shard_coverage",
    "request_archival_shard",
    "get_info",
    "getinfo",
    "sync_info",
    "get_connections",
    "get_peer_list",
    "get_net_stats",
    "stop_daemon",
    "get_transaction_pool",
    "get_transaction_pool_hashes",
    "get_txpool_backlog",
    "get_transaction_pool_stats",
    "flush_txpool",
    "relay_tx",
    "submit_transaction",
    "get_block_template",
    "getblocktemplate",
    "get_miner_data",
    "submit_block",
    "submitblock",
    "calc_pow",
    "start_mining",
    "stop_mining",
    "mining_status",
    "set_bans",
    "get_bans",
    "banned",
    "get_stem_tallies",
    "generateblocks",
    "pop_blocks",
    "save_bc",
    "flush_cache",
    "inject_archival_serve_credit",
    "set_log_hash_rate",
];

/// Every 3.x name is method-not-found with the `rpc.method` diagnostic
/// naming it, on the armed admin listener (every grant) and on the view
/// listener alike. Control: a 4.0 name on the same path is answered.
/// Red check run: aliasing `get_info` to `daemon_status` in `answer`'s
/// lookup (`Id::of(if method == "get_info" { "daemon_status" } else {
/// &method })`) turns this red.
#[tokio::test]
async fn every_old_name_is_method_not_found() {
    let (_scratch, state) = state("old-names");
    for authority in [ADMIN, Authority::VIEW_LISTENER] {
        for name in OLD_NAMES {
            let reply = send(&state, authority, &call(name, json!({}))).await;
            assert_eq!(
                refusal(&reply),
                Some((METHOD_NOT_FOUND, codes::METHOD.to_owned())),
                "{name}: {reply}"
            );
            assert_eq!(reply["error"]["data"]["parameter"]["method"], *name);
            assert_eq!(reply["id"], 7, "the call's id is answered");
        }
        let control = send(&state, authority, &call(wire::Version::NAME, json!({}))).await;
        assert_ne!(
            refusal(&control).map(|(code, _)| code),
            Some(METHOD_NOT_FOUND),
            "control: {control}"
        );
    }
}

/// Every row of the method table is a method on the armed admin listener:
/// whatever it answers with every handle absent, it is not
/// method-not-found. The 4.0 port of the 3.x
/// `every_route_is_one_method_row_and_every_rest_row_is_routed`: there is
/// one route, and the table is what it serves. Red check run: dropping
/// `fee` from the lookup in `answer` (`Id::of(&method).filter(|id| *id !=
/// Id::Fee)`) turns this red.
#[tokio::test]
async fn every_table_row_is_answered_on_the_admin_listener() {
    let (_scratch, state) = state("table");
    for row in TABLE {
        let reply = send(&state, ADMIN, &call(row.name, json!({}))).await;
        assert_ne!(
            refusal(&reply).map(|(code, _)| code),
            Some(METHOD_NOT_FOUND),
            "{}: {reply}",
            row.name
        );
    }
}

/// A key a method's request does not have is `rpc.params`, for every row:
/// the params are the method's own request type, and a call with a word
/// the method does not know is refused, naming the method, not answered
/// as if the word were absent (RW-Q2). Red check run: the `version` and `chain_height` arms of
/// `dispatch` read no params, and this test was red on both until each
/// read its `NoParams` (the production change this test forced).
#[tokio::test]
async fn an_unknown_parameter_is_refused_for_every_row() {
    let (_scratch, state) = state("unknown-param");
    for row in TABLE {
        let reply = send(
            &state,
            ADMIN,
            &call(row.name, json!({"no-such-parameter": true})),
        )
        .await;
        assert_eq!(
            refusal(&reply),
            Some((ErrorClass::BadParams.code(), codes::PARAMS.to_owned())),
            "{}: {reply}",
            row.name
        );
        assert_eq!(
            reply["error"]["data"]["parameter"]["method"], row.name,
            "the refusal names the method whose request it is"
        );
    }
}

/// What is not one JSON-RPC 2.0 request is `rpc.envelope` (BadParams), and
/// answered under the request's id where it has a usable one. Red check
/// run: accepting a missing `jsonrpc` in `read_envelope` turns the
/// `jsonrpc`-less case red.
#[tokio::test]
async fn what_is_not_one_request_is_an_envelope_refusal() {
    let (_scratch, state) = state("envelope");
    let version = wire::Version::NAME;
    let envelope = Some((ErrorClass::BadParams.code(), codes::ENVELOPE.to_owned()));
    let cases: Vec<(&str, Vec<u8>, Value)> = vec![
        ("not JSON", b"{\"jsonrpc\": ".to_vec(), Value::Null),
        (
            "a batch",
            json!([call(version, json!({}))]).to_string().into_bytes(),
            Value::Null,
        ),
        ("a string", b"\"version\"".to_vec(), Value::Null),
        (
            "no id",
            json!({"jsonrpc": "2.0", "method": version})
                .to_string()
                .into_bytes(),
            Value::Null,
        ),
        (
            "a null id",
            json!({"jsonrpc": "2.0", "id": null, "method": version})
                .to_string()
                .into_bytes(),
            Value::Null,
        ),
        (
            "an object id",
            json!({"jsonrpc": "2.0", "id": {"n": 1}, "method": version})
                .to_string()
                .into_bytes(),
            json!({"n": 1}),
        ),
        (
            "no jsonrpc",
            json!({"id": 3, "method": version}).to_string().into_bytes(),
            json!(3),
        ),
        (
            "jsonrpc 1.0",
            json!({"jsonrpc": "1.0", "id": 3, "method": version})
                .to_string()
                .into_bytes(),
            json!(3),
        ),
        (
            "a numeric method",
            json!({"jsonrpc": "2.0", "id": 3, "method": 5})
                .to_string()
                .into_bytes(),
            json!(3),
        ),
        (
            "positional params",
            json!({"jsonrpc": "2.0", "id": 3, "method": version, "params": []})
                .to_string()
                .into_bytes(),
            json!(3),
        ),
        (
            "null params",
            json!({"jsonrpc": "2.0", "id": 3, "method": version, "params": null})
                .to_string()
                .into_bytes(),
            json!(3),
        ),
        (
            "a member JSON-RPC does not have",
            json!({"jsonrpc": "2.0", "id": 3, "method": version, "extra": 1})
                .to_string()
                .into_bytes(),
            json!(3),
        ),
    ];
    for (what, body, id) in cases {
        let reply = reply_to(&state, ADMIN, &body).await;
        assert_eq!(refusal(&reply), envelope, "{what}: {reply}");
        assert_eq!(reply["id"], id, "{what}: {reply}");
    }
    // Control: the same envelope, well formed, is answered; `params` left
    // out is the same request as `{}`.
    let well_formed = json!({"jsonrpc": "2.0", "id": "s", "method": version});
    let reply = send(&state, ADMIN, &well_formed).await;
    assert_ne!(refusal(&reply), envelope, "control: {reply}");
    assert_eq!(reply["id"], "s");
}

/// The view listener's methods, written out from the census (§17's Grant
/// column against `RPC_CHANNEL.md` §6.2's view-listener grants: chain,
/// pool, health, submit, mining-work, and the version under no grant).
/// Every other row is refused it. Changing what the view listener reaches
/// must change this list in a diff a reviewer reads.
const VIEW_ADMITTED: &[&str] = &[
    wire::Version::NAME,
    wire::ChainHeight::NAME,
    wire::BlockHeaderShow::NAME,
    wire::BlockHeaderList::NAME,
    wire::BlockShow::NAME,
    wire::BlockList::NAME,
    wire::TxShow::NAME,
    wire::TxList::NAME,
    wire::ChainSpent::NAME,
    wire::Fee::NAME,
    wire::ChainCoinbaseSum::NAME,
    wire::CurveShow::NAME,
    wire::ArchivalClaimShow::NAME,
    wire::ShardCoverage::NAME,
    wire::ShardFetch::NAME,
    wire::DaemonStatus::NAME,
    wire::OptionShow::NAME,
    wire::TxpoolList::NAME,
    wire::TxpoolStats::NAME,
    wire::TxSubmit::NAME,
    wire::BlockTemplate::NAME,
    wire::BlockSubmit::NAME,
    wire::Pow::NAME,
];

/// Admission happens at dispatch, by the method's row: the view listener
/// is answered on exactly its methods and refused every other with
/// OutsideTheGrant — the anonymity graph (`relay_stats`) as host-only, the
/// armed levers as host-only, node administration as outside the grant.
/// The admin listener is refused nothing while armed, and only the two
/// levers (`grant.unarmed`) while not. Red check run: skipping
/// `authority.admit(row)` in `answer` turns the view-listener arm red.
#[tokio::test]
async fn each_listener_is_admitted_to_its_rows_at_dispatch() {
    use shekyl_rpc_types::method::Policy;
    let (_scratch, state) = state("admission");
    let outside = ErrorClass::OutsideTheGrant.code();
    for row in TABLE {
        let request = call(row.name, json!({}));
        let view = refusal(&send(&state, Authority::VIEW_LISTENER, &request).await);
        if VIEW_ADMITTED.contains(&row.name) {
            assert_ne!(view.map(|(code, _)| code), Some(outside), "{}", row.name);
        } else {
            let expected = match row.policy {
                Policy::HostOnly | Policy::Armed => grant::HOST_ONLY,
                _ => grant::OUTSIDE_THE_GRANT,
            };
            assert_eq!(view, Some((outside, expected.to_owned())), "{}", row.name);
        }
        let armed = refusal(&send(&state, ADMIN, &request).await);
        assert_ne!(armed.map(|(code, _)| code), Some(outside), "{}", row.name);
        let unarmed = refusal(&send(&state, Authority::admin_listener(false), &request).await);
        if matches!(row.policy, Policy::Armed) {
            assert_eq!(unarmed, Some((outside, UNARMED.to_owned())), "{}", row.name);
        } else {
            assert_ne!(unarmed.map(|(code, _)| code), Some(outside), "{}", row.name);
        }
    }
    // The anonymity graph, named: host-only data (§55).
    let stems = refusal(
        &send(
            &state,
            Authority::VIEW_LISTENER,
            &call(wire::RelayStats::NAME, json!({})),
        )
        .await,
    );
    assert_eq!(stems, Some((outside, grant::HOST_ONLY.to_owned())));
}

/// One refusal per class that dispatch reaches, each with its dotted code:
/// BadParams (`rpc.params`: a word where the heights are, and a `tx_submit`
/// body that is not base64), OutsideTheGrant (`grant.outside`),
/// OverResourceBound (`bound.block`, a bounded caller past the block cap),
/// NotReady (`daemon.unready`: no node, including a shard view that was not
/// supplied) and RefusedByMethod (`shard.tor-off`: a node with Tor off).
/// Method-not-found
/// (`rpc.method`) is [`every_old_name_is_method_not_found`]'s. StoreFault
/// and Internal need a store that fails; their codes are
/// `methods::tests::every_fault_is_its_class_and_its_dotted_code`. A
/// transaction's verdict, `rejected` included, is a result. Red check run:
/// dropping the block cap check in `reads::block_list` turns the
/// OverResourceBound case to NotReady, red.
#[tokio::test]
async fn one_refusal_per_class_through_dispatch() {
    let (_scratch, state) = state("classes");
    let over_cap: Vec<u64> = (0..=crate::methods::RESTRICTED_BLOCK_COUNT as u64).collect();
    let cases: Vec<(Authority, Value, ErrorClass, &str)> = vec![
        (
            ADMIN,
            call(wire::BlockList::NAME, json!({"height": "high"})),
            ErrorClass::BadParams,
            codes::PARAMS,
        ),
        (
            Authority::VIEW_LISTENER,
            call(wire::TxSubmit::NAME, json!({"body": "not base64!"})),
            ErrorClass::BadParams,
            codes::PARAMS,
        ),
        (
            Authority::VIEW_LISTENER,
            call(wire::DaemonStop::NAME, json!({})),
            ErrorClass::OutsideTheGrant,
            grant::OUTSIDE_THE_GRANT,
        ),
        (
            Authority::VIEW_LISTENER,
            call(wire::BlockList::NAME, json!({"height": over_cap})),
            ErrorClass::OverResourceBound,
            crate::methods::codes::BOUND_BLOCK,
        ),
        (
            ADMIN,
            call(wire::ChainHeight::NAME, json!({})),
            ErrorClass::NotReady,
            crate::methods::codes::DAEMON_UNREADY,
        ),
    ];
    for (authority, request, class, code) in cases {
        let reply = send(&state, authority, &request).await;
        assert_eq!(
            refusal(&reply),
            Some((class.code(), code.to_owned())),
            "{request}: {reply}"
        );
    }
    let unready = send(
        &state,
        ADMIN,
        &call(wire::ShardFetch::NAME, json!({"id": 0})),
    )
    .await;
    assert_eq!(
        refusal(&unready),
        Some((
            ErrorClass::NotReady.code(),
            crate::methods::codes::DAEMON_UNREADY.to_owned(),
        )),
        "{unready}"
    );
    let (_tor_scratch, tor_off) = state_with("classes-tor-off", Arc::new(TorOff));
    let shard = send(
        &tor_off,
        ADMIN,
        &call(wire::ShardFetch::NAME, json!({"id": 0})),
    )
    .await;
    assert_eq!(
        refusal(&shard),
        Some((
            ErrorClass::RefusedByMethod.code(),
            crate::shard_view::codes::TOR_OFF.to_owned(),
        )),
        "{shard}"
    );

    // A verdict is an answer: bytes that are no transaction are `rejected`
    // with `malformed`, in `result`, never an error.
    let verdict = send(
        &state,
        Authority::VIEW_LISTENER,
        &call(wire::TxSubmit::NAME, json!({"body": "AAEC"})),
    )
    .await;
    assert_eq!(
        verdict["result"],
        json!({"verdict": "rejected", "cause": {"malformed": null}}),
        "{verdict}"
    );
}

/// A worker that panics is an Internal refusal at stage `join`, on both
/// worker paths (a chain read and a lock-holding read), never a hung call
/// or a result. Red check run: mapping the join failure in `blocking` to
/// `InternalFault::Serialize` turns this red.
#[tokio::test]
async fn a_panicked_worker_is_an_internal_join_fault() {
    use super::{blocking, on_chain, Failure};
    use crate::methods::RpcFault;
    let (_scratch, state) = state("join");
    let joined = |error: RpcError| {
        assert_eq!(error.class, ErrorClass::Internal);
        assert_eq!(
            error.diagnostic.code,
            crate::methods::codes::DAEMON_INTERNAL
        );
        assert_eq!(error.diagnostic.parameter["stage"], "join");
    };
    let read = on_chain(&state, |_| -> Result<(), RpcFault> {
        panic!("a chain read panics")
    })
    .await;
    joined(read.expect_err("a refusal").into_error());
    let held = blocking(|| -> Result<(), RpcFault> { panic!("a held read panics") }).await;
    let Err(Failure::Error(error)) = held else {
        panic!("a refusal, not a result")
    };
    joined(error);
}

/// A hash that is not one is `rpc.params`, naming the method, and the
/// message says what was wrong with what was sent. The 4.0 port of the
/// 3.x `an_unparseable_hash_quotes_what_was_sent`: the hash is the wire
/// type's to read, so the refusal is the envelope's. Red check run:
/// dropping the reader's error from the `rpc.params` message in
/// `request` turns this red.
#[tokio::test]
async fn an_unparseable_hash_is_a_params_refusal() {
    let (_scratch, state) = state("bad-hash");
    let reply = send(
        &state,
        ADMIN,
        &call(wire::BlockHeaderShow::NAME, json!({"hash": "zz"})),
    )
    .await;
    assert_eq!(
        refusal(&reply),
        Some((ErrorClass::BadParams.code(), codes::PARAMS.to_owned())),
        "{reply}"
    );
    assert_eq!(
        reply["error"]["data"]["parameter"]["method"],
        wire::BlockHeaderShow::NAME
    );
    let message = reply["error"]["message"].as_str().expect("a message");
    assert!(
        message.contains("\"zz\""),
        "quotes what was sent: {message}"
    );
}
