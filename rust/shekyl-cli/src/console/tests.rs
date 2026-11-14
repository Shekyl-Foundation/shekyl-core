// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::blockchain::median;
use super::status::{mining_speed, sync_percentage};
use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;

use shekyl_rpc_types::errors::{Diagnostic, ErrorClass};
use shekyl_rpc_types::kinds::{Count, Duration, Integer, Size, Time};
use shekyl_rpc_types::nullable::Nullable;
use shekyl_rpc_types::wire::node::MineSpeed;
use shekyl_types::{BlockHash, TxHash};

fn run(args: &[&str], address: Option<&str>) -> Result<String, String> {
    // Mainnet: these harnesses drive the dispatch, not the handshake, and
    // their fake daemons answer mainnet.
    run_on(shekyl_rpc_types::Network::Mainnet, args, address)
}

/// [`run`], as a console started for `network`.
fn with_daemon(
    network: shekyl_rpc_types::Network,
    address: Option<&str>,
    call: impl FnOnce(&DaemonClient) -> Result<String, String>,
) -> Result<String, String> {
    let address = address.ok_or_else(|| "no daemon".to_owned())?;
    let daemon = DaemonClient::new(&format!("http://{address}"), None, None, network)
        .map_err(|error| error.to_string())?;
    call(&daemon)
}

fn run_on(
    network: shekyl_rpc_types::Network,
    args: &[&str],
    address: Option<&str>,
) -> Result<String, String> {
    match crate::grammar::parse(&args.join(" ")) {
        crate::resolve::ResolvedCommand::Daemon(view) => {
            with_daemon(network, address, |daemon| execute(daemon, &view))
        }
        crate::resolve::ResolvedCommand::Version => {
            with_daemon(network, address, super::node::version)
        }
        crate::resolve::ResolvedCommand::ShowTransfer { txid, body } => {
            with_daemon(network, address, move |daemon| {
                let answer = transaction(daemon, &txid)?;
                render_transaction(answer, &txid, body)
            })
        }
        crate::resolve::ResolvedCommand::Unknown { .. } => {
            Err("the console tests do not run an unknown command".to_owned())
        }
        crate::resolve::ResolvedCommand::Diagnostic { message } => Err(message),
        other => Err(format!("the console tests do not run {other:?}")),
    }
}

/// The route key a JSON-RPC call to method `M` is answered under.
fn rpc<M: RpcMethod>() -> &'static str {
    Box::leak(format!("json_rpc:{}", M::NAME).into_boxed_str())
}

/// The method a recorded request body names.
fn method_of(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("method")?
        .as_str()
        .map(str::to_owned)
}

/// A recorded log without the identity handshake, which is a request too
/// (VC-3) and not one of a command's legs.
fn legs(log: &std::sync::Mutex<Vec<(String, String)>>) -> Vec<(String, String)> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|(_, body)| method_of(body).as_deref() != Some(<wire::Version as RpcMethod>::NAME))
        .cloned()
        .collect()
}

/// The params of the first recorded call to `M`.
fn params_of<M: RpcMethod>(log: &std::sync::Mutex<Vec<(String, String)>>) -> serde_json::Value {
    legs(log)
        .iter()
        .find(|(_, body)| method_of(body).as_deref() == Some(M::NAME))
        .map(|(_, body)| serde_json::from_str::<serde_json::Value>(body).unwrap()["params"].clone())
        .unwrap_or_else(|| panic!("{} was asked for", M::NAME))
}

/// A JSON-RPC result envelope.
fn rpc_result(value: impl serde::Serialize) -> String {
    serde_json::json!({"jsonrpc": "2.0", "id": 0, "result": value}).to_string()
}

/// A JSON-RPC error envelope carrying `class` and the diagnostic `code`,
/// whose English the operator must not see.
fn rpc_refusal(class: ErrorClass, code: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 0,
        "error": {
            "code": class.code(),
            "message": "english the operator must not see",
            "data": Diagnostic::new(code, "english the operator must not see"),
        }
    })
    .to_string()
}

/// A `version` reply that agrees with this build except where `edit` says
/// otherwise.
fn version_but(edit: impl FnOnce(&mut wire::chain::Version)) -> String {
    let mut reply = wire::chain::Version {
        version: Integer(u64::from(shekyl_rpc_types::CORE_RPC_VERSION)),
        tagged: false,
        height: Height(0),
        target_height: Nullable(None),
        consensus_digest: shekyl_rpc_types::CONSENSUS_CONSTANTS_DIGEST_HASH,
        network: shekyl_rpc_types::Network::Mainnet,
        genesis: HashHex::from_bytes(shekyl_rpc_types::genesis_hash_for(
            shekyl_rpc_types::Network::Mainnet,
        )),
    };
    edit(&mut reply);
    rpc_result(&reply)
}

/// A `version` reply that MATCHES this build on all four axes.
///
/// Every remote-arm console command handshakes before it renders (`VC-3`),
/// so a harness whose fake daemon does not answer `version` tests the
/// refusal rather than the command.
fn agreeing_version() -> String {
    version_but(|_| {})
}

/// A multi-request acceptor that routes on the JSON-RPC `method` in the
/// body (every call is on `/json_rpc`, RW-Q2).
///
/// Routing rather than replaying a queue means the assertion is on the
/// reply the console asked for, not on call order: a command that stopped
/// issuing one of its legs gets `no reply`, not a silently shifted answer.
/// An unrouted request is answered `404` with an empty body.
fn route_server(routes: Vec<(&'static str, String)>) -> String {
    route_server_recording(routes).0
}

/// [`route_server`], plus the log of what was asked of it.
///
/// A canned reply is blind to the request that fetched it; the log makes
/// the *request* assertable.
#[expect(clippy::type_complexity, reason = "a test log of (route, body)")]
pub(crate) fn route_server_recording(
    mut routes: Vec<(&'static str, String)>,
) -> (
    String,
    std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
) {
    // Every remote-arm command handshakes first (VC-3), so an agreeing
    // daemon is the default. A test that wants a DISAGREEING one supplies
    // its own `version` route and this leaves it alone.
    let version = rpc::<wire::Version>();
    if !routes.iter().any(|(k, _)| *k == version) {
        routes.push((version, agreeing_version()));
    }
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let recorder = std::sync::Arc::clone(&log);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { return };
            let Some((path, body)) = read_request(&mut s) else {
                continue;
            };
            if let Ok(mut log) = recorder.lock() {
                log.push((path.clone(), body.clone()));
            }
            let key = if path == shekyl_rpc_types::endpoint::JSON_RPC_PATH {
                method_of(&body).map_or_else(|| path.clone(), |m| format!("json_rpc:{m}"))
            } else {
                path.clone()
            };
            let reply = routes.iter().find(|(k, _)| *k == key).map(|(_, v)| v);
            let (status, body) = reply.map_or_else(
                || ("404 Not Found", String::new()),
                |r| ("200 OK", r.clone()),
            );
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            // One write: a head-then-body pair lets a client that hung up
            // between them see a truncated reply.
            let mut response = head.into_bytes();
            response.extend_from_slice(body.as_bytes());
            if s.write_all(&response).is_err() {
                continue;
            }
        }
    });
    (address, log)
}

/// Read one HTTP request, returning its path and body.
///
/// Headers first, then exactly `Content-Length` more bytes — a single
/// `read` would truncate a body split across packets, which on loopback
/// is rare enough to pass locally and fail in CI.
fn read_request(s: &mut std::net::TcpStream) -> Option<(String, String)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let path = head.split_whitespace().nth(1)?.to_owned();
    let length: usize = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    s.read_exact(&mut body).ok()?;
    Some((path, String::from_utf8_lossy(&body).into_owned()))
}

/// A structurally canonical spend for the body-binding: the console now
/// recomputes each entry's identity from its bytes, so a fixture can no
/// longer label an arbitrary blob — a fixture that invents a hash is
/// staging the substitution the binding exists to refuse (the engine's
/// doubles learned this the same way).
fn console_spend() -> shekyl_wire::Transaction {
    use shekyl_wire::transaction::{PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN};
    use shekyl_wire::{BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, TxPrefix};
    shekyl_wire::Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: vec![],
                key_image: [0x42; 32],
            }],
            outputs: vec![
                Output {
                    amount: 0,
                    key: [1; 32],
                    view_tag: 0,
                },
                Output {
                    amount: 0,
                    key: [3; 32],
                    view_tag: 1,
                },
            ],
            extra: vec![],
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: BlockHash::NULL,
            base: CtBase {
                enc_amounts: vec![[0; 9], [0; 9]],
                enc_labels: vec![[0; 9], [0; 9]],
                commitments: vec![[2; 32], [3; 32]],
            },
            pqc_auths: vec![PqcAuth {
                auth_version: 1,
                scheme_id: 1,
                flags: 0,
                hybrid_public_key: vec![0; PQC_HYBRID_SINGLE_KEY_LEN],
                hybrid_signature: vec![0; PQC_HYBRID_SINGLE_SIG_LEN],
            }],
            prunable: Some(Prunable {
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
                fcmp_proof: vec![0; 8],
                pseudo_outs: vec![[0; 32]],
            }),
        },
    }
}

/// [`console_spend`]'s skeleton: the pruned segment and its txid operands.
fn console_spend_skeleton() -> shekyl_wire::SkeletonTx {
    let tx = console_spend();
    let segments = tx.write_segments().expect("segments");
    let parts = tx.txid_parts();
    shekyl_wire::SkeletonTx {
        unprunable: segments.pruned,
        prunable_hash: parts.prunable_hash,
        pqc_auth_hash: parts.pqc_auth_hash,
        archival_len: parts.archival_len,
    }
}

/// A complete `daemon_status` result for the chain of `count` blocks (the
/// wire carries its tip, `count - 1`), every part shown. A test removes or
/// alters the members it is about.
pub(crate) fn daemon_status_value(count: u64) -> serde_json::Value {
    let mut value = serde_json::json!({
        "height": count - 1,
        "hash": "5a".repeat(32),
        "target_height": null,
        "synchronized": true,
        "syncing": false,
        "offline": false,
        "degraded": false,
        "peered": true,
        "hiding": false,
        "writer": {"live": null},
        "protocol_version": 3,
        "difficulty": "0x1e240",
        "difficulty_cumulative": "0x2dc6c0",
        "block_spacing": 120,
        "tx_count": 0,
        "block_weight_max": 600_000,
        "block_weight_median": 300_000,
        "time_adjusted": 1_700_000_000_u64,
        "emission": "0",
        "emission_multiplier": 1_000_000,
        "burn": 0,
        "burn_total": "0",
        "stake_share": 0,
        "txpool_count": 4,
        "grant": ["health", "status", "chain", "pool", "peers", "submit", "mining-work",
                  "mining-control", "bans", "node", "config"],
        "started": 1_700_000_000_u64,
        "disk_free": 1_u64 << 40,
        "data_size": 1_u64 << 30,
        "randomx_caches": 1,
        "revision": "3.1.0-test",
        "peer_outbound_count": 8,
        "peer_inbound_count": 3,
        "alt_count": 0,
        "rpc_connections": 1,
        "txpool_retired": false,
        "connector": {"clearnet": {
            "inbound_count": 3, "outbound_count": 8,
            "peer_white_count": 10, "peer_gray_count": 20
        }},
        "txpool_private_count": 0,
    });
    // Status's Tor fields: a node with Tor off. Set after the literal, which
    // is at `json!`'s recursion limit.
    value["posture"] = serde_json::json!({"tor": "off", "clearnet": "on"});
    value["origination"] = serde_json::json!("clearnet-only");
    value["sync_connector"] = serde_json::json!(["clearnet"]);
    value["tor_quiet"] = serde_json::Value::Null;
    value["tor"] = serde_json::Value::Null;
    value
}

/// [`daemon_status_value`] for a chain of 100 blocks, for the client's own
/// decode test.
pub(crate) fn daemon_status_reply() -> serde_json::Value {
    daemon_status_value(100)
}

/// [`daemon_status_value`] as a `daemon_status` envelope.
fn status_reply(count: u64) -> String {
    rpc_result(daemon_status_value(count))
}

/// The wire names of `daemon_status`' Status part.
const STATUS_PART_KEYS: &[&str] = &[
    "started",
    "disk_free",
    "data_size",
    "randomx_caches",
    "revision",
    "peer_outbound_count",
    "peer_inbound_count",
    "alt_count",
    "rpc_connections",
    "txpool_retired",
    "posture",
    "origination",
    "sync_connector",
    "tor_quiet",
    "tor",
];

/// [`daemon_status_value`] with the Status part withheld, as a caller
/// without the `status` grant reads it.
fn status_withheld(count: u64) -> serde_json::Value {
    let mut value = daemon_status_value(count);
    let members = value.as_object_mut().unwrap();
    for key in STATUS_PART_KEYS {
        members
            .remove(*key)
            .unwrap_or_else(|| panic!("`{key}` is a Status member of the fixture"));
    }
    value
}

/// An offline daemon's `daemon_status`: the state in Health, `peered` and
/// the peer counts `null`.
fn status_offline(count: u64) -> serde_json::Value {
    let mut value = daemon_status_value(count);
    value["offline"] = serde_json::json!(true);
    value["peered"] = serde_json::Value::Null;
    value["peer_outbound_count"] = serde_json::Value::Null;
    value["peer_inbound_count"] = serde_json::Value::Null;
    value
}

/// A full-form `tx_list` entry whose body is `body`; the label is the
/// caller's. The full form is `{id, body}` and the entry's state: the txid's
/// operands are the pruned form's, selected by `prune` (4.1, IG-Q55).
fn mined_entry(label: [u8; 32], body: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "id": HashHex::from_bytes(label),
        "body": shekyl_rpc_types::kinds::Bytes(body.to_vec()),
        "pooled": false,
        "mined_height": 3,
        "confirmations": 1,
        "mined_time": 1_700_000_000_u64,
        "output_index": [1],
        "public": null,
    })
}

/// A daemon answering `tx_list` with `slots`.
#[expect(clippy::type_complexity, reason = "a test log of (route, body)")]
fn tx_list_server(
    slots: serde_json::Value,
) -> (
    String,
    std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
) {
    route_server_recording(vec![(rpc::<wire::TxList>(), rpc_result(slots))])
}

/// **A retained transaction prints its whole body.** The console asks
/// `tx_list` for the full form (`prune: false`), and the binding rehashes
/// the whole body. The request is asserted, so a console that asked for
/// the pruned form fails here rather than passing on a canned reply.
#[test]
fn a_retained_transaction_prints_from_its_whole_body() {
    let txid = console_spend().hash();
    let bytes = console_spend().serialize();
    let (addr, log) = tx_list_server(serde_json::json!([mined_entry(txid.to_bytes(), &bytes)]));
    let out = run(&["tx", "show", &hex::encode(txid), "--body"], Some(&addr))
        .unwrap_or_else(|error| error);
    assert!(
        out.contains("Found in blockchain at height 3"),
        "expected the confirmed line, got: {out}"
    );
    use base64::Engine as _;
    let printed = super::encode_body(&bytes);
    assert!(
        out.contains(&printed),
        "the whole body, base64, is what --body prints: {out}"
    );
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(printed)
        .expect("the printed body is base64");
    assert_eq!(
        decoded, bytes,
        "the printed body is the transaction's bytes"
    );
    let params = params_of::<wire::TxList>(&log);
    assert_eq!(
        params["prune"], false,
        "the full form was asked for: {params}"
    );
    assert_eq!(params["id"], serde_json::json!([hex::encode(txid)]));
}

/// **A discarded body is reported `archived` with its shard, not printed
/// and not "not found"** (`PDM-Q10`).
#[test]
fn an_archived_transaction_names_its_shard() {
    let txid = console_spend().hash();
    let (addr, _) = tx_list_server(serde_json::json!([
        {"archived": {"id": hex::encode(txid), "shard": 3}}
    ]));
    let out = run(&["tx", "show", &hex::encode(txid)], Some(&addr)).expect("renders");
    assert!(
        out.contains("archived") && out.contains("shard 3"),
        "an archived body names its shard: {out}"
    );
    assert!(
        !out.contains("wasn't found"),
        "archived is a state of a transaction the chain holds, not a miss: {out}"
    );
}

/// **A `null` slot is not "not found".** The chain does not hold the id and
/// the pool could not be asked (IG-Q73): whether the pool holds it has no
/// answer. Red edit: read `Slot::Unasked` as `NotHeld`.
#[test]
fn an_unasked_slot_says_the_pool_is_unavailable() {
    let (addr, _) = tx_list_server(serde_json::json!([null]));
    let out = run(&["tx", "show", &"31".repeat(32)], Some(&addr)).expect("renders");
    assert!(out.contains("pool is unavailable"), "{out}");
    assert!(!out.contains("wasn't found"), "{out}");
}

/// `{"missing": null}` is the one miss.
#[test]
fn a_missing_slot_is_not_found() {
    let (addr, _) = tx_list_server(serde_json::json!([{"missing": null}]));
    let out = run(&["tx", "show", &"31".repeat(32)], Some(&addr)).expect_err("a miss");
    assert!(out.contains("wasn't found"), "{out}");
}

/// **An echoed label over a substituted body is refused.** A daemon that
/// echoes the requested id while serving another canonical body passes the
/// label check; the binding recomputes the identity from the bytes and
/// refuses — the wallet's `bind_served` rule on the console's remote arm.
#[test]
fn an_echoed_label_over_a_substituted_body_is_refused() {
    let mut other = console_spend();
    other.prefix.unlock_time = 5;
    let requested = other.hash();
    let (addr, _) = tx_list_server(serde_json::json!([mined_entry(
        requested.to_bytes(),
        &console_spend().serialize()
    )]));
    let out = run(&["tx", "show", &hex::encode(requested)], Some(&addr)).expect_err("refused");
    assert!(
        out.contains("a label is not an identity"),
        "the substituted body must be refused by the binding, not rendered: {out}"
    );
}

/// **A pruned segment answering a request for the whole body is refused,
/// not reassembled.** The skeleton parses as a transaction with no
/// prunable region, which hashes to another identity: the binding refuses
/// it, and the daemon's operands are never consulted.
#[test]
fn a_pruned_form_answer_to_a_full_form_request_is_refused() {
    let txid = console_spend().hash();
    let (addr, _) = tx_list_server(serde_json::json!([mined_entry(
        txid.to_bytes(),
        &console_spend_skeleton().unprunable
    )]));
    let out = run(&["tx", "show", &hex::encode(txid)], Some(&addr)).expect_err("refused");
    assert!(out.contains("a label is not an identity"), "{out}");
}

/// A reply with extra slots is unreadable, not "use the first one".
#[test]
fn extra_transaction_slots_are_a_malformed_reply() {
    let txid = console_spend().hash();
    let bytes = console_spend().serialize();
    let (addr, _) = tx_list_server(serde_json::json!([
        mined_entry(txid.to_bytes(), &bytes),
        mined_entry(txid.to_bytes(), &bytes),
    ]));
    let out = run(&["tx", "show", &hex::encode(txid)], Some(&addr)).expect_err("refused");
    assert!(out.contains("asked about 1 transaction, got 2"), "{out}");
}

/// **A reply about a different transaction is not an answer.**
#[test]
fn an_entry_for_a_different_hash_is_refused() {
    let asked = [0x31u8; 32];
    let (addr, _) = tx_list_server(serde_json::json!([mined_entry(
        [0x99; 32],
        &console_spend().serialize()
    )]));
    let out = run(&["tx", "show", &hex::encode(asked)], Some(&addr)).unwrap_or_else(|e| e);
    assert!(
        out.contains("asked about") && !out.contains("Found in blockchain"),
        "an entry for another hash must be refused, not rendered: {out}"
    );
}

/// **The daemon's refusal reaches the operator as its class and code**,
/// never its English and never a decode complaint about the success type.
#[test]
fn a_refusal_reaches_the_operator_as_class_and_code() {
    let (addr, _) = route_server_recording(vec![(
        rpc::<wire::TxList>(),
        rpc_refusal(ErrorClass::StoreFault, "chain.unreadable"),
    )]);
    let out = run(&["tx", "show", &"31".repeat(32)], Some(&addr)).expect_err("refused");
    assert!(out.contains("StoreFault chain.unreadable"), "{out}");
    assert!(!out.contains("english"), "{out}");
}
/// The C++ printed `<unknown>` below its cutoff and UTC
/// `%Y-%m-%d %H:%M:%S` above it. A genesis block with timestamp 0 is the
/// case an operator actually sees.
#[test]
fn timestamps_render_as_the_cpp_did() {
    assert_eq!(human_readable_timestamp(0), "<unknown>");
    assert_eq!(human_readable_timestamp(1_234_567_889), "<unknown>");
    assert_eq!(
        human_readable_timestamp(1_234_567_890),
        "2009-02-13 23:31:30"
    );
    assert_eq!(
        human_readable_timestamp(1_700_000_000),
        "2023-11-14 22:13:20"
    );
    // A leap day, and the end of a year — the civil-from-days arithmetic
    // is where a hand-rolled calendar goes wrong.
    assert_eq!(
        human_readable_timestamp(1_709_164_800),
        "2024-02-29 00:00:00"
    );
    assert_eq!(
        human_readable_timestamp(1_735_689_599),
        "2024-12-31 23:59:59"
    );
}

/// Every line of `print_block_header`, in its order and wording. `reward`
/// is SKL with nine fractional digits, `is orphan` is 0/1, a `pow` the
/// request did not ask for prints as nothing after the colon, and a long-term weight off the
/// main chain is `none`.
#[test]
fn the_block_header_renders_line_for_line() {
    let header: BlockHeader = serde_json::from_value(serde_json::json!({
        "version_major": 1, "version_minor": 0, "time": 0,
        "parent": "00".repeat(32), "nonce": 10101, "orphan": false,
        "height": 0, "depth": 0, "hash": "07".repeat(32),
        "difficulty": "0x1", "difficulty_cumulative": "0x1",
        "reward": "100000000000000", "weight": 6263, "weight_longterm": 176_470,
        "tx_count": 0, "coinbase": "09".repeat(32),
        "curve_root": "00".repeat(32), "section_root": "00".repeat(32),
    }))
    .expect("a header decodes");
    let seven = "07".repeat(32);
    let nine = "09".repeat(32);
    let zero = "00".repeat(32);
    assert_eq!(
        render_block_header(&header),
        format!(
            "timestamp: 0 (<unknown>)\n\
             previous hash: {zero}\n\
             nonce: 10101\n\
             is orphan: 0\n\
             height: 0\n\
             depth: 0\n\
             hash: {seven}\n\
             difficulty: 1\n\
             cumulative difficulty: 1\n\
             POW hash: \n\
             block weight: 6263\n\
             long term weight: 176470\n\
             num txes: 0\n\
             reward: 100000.000000000\n\
             miner tx hash: {nine}"
        )
    );
}

/// `block show` asks for one block by height with its proof-of-work hash
/// filled, and renders the header.
#[test]
fn block_show_asks_for_the_block_with_its_pow() {
    let block = serde_json::json!({
        "header": {
            "version_major": 1, "version_minor": 0, "time": 0,
            "parent": "00".repeat(32), "nonce": 1, "orphan": false,
            "height": 5, "depth": 0, "hash": "07".repeat(32),
            "difficulty": "0x1", "difficulty_cumulative": "0x1",
            "reward": "0", "weight": 1, "weight_longterm": 1,
            "tx_count": 0, "pow": "08".repeat(32), "coinbase": "09".repeat(32),
            "curve_root": "00".repeat(32), "section_root": "00".repeat(32),
        },
        "body": "",
        "tx": [],
        "output_index": 0,
        "section": [],
        "section_body": [],
    });
    let (addr, log) = route_server_recording(vec![(rpc::<wire::BlockShow>(), rpc_result(block))]);
    let out = run(&["block", "show", "5"], Some(&addr)).expect("renders");
    assert!(out.contains("height: 5"), "{out}");
    assert!(
        out.contains(&format!("POW hash: {}", "08".repeat(32))),
        "{out}"
    );
    let params = params_of::<wire::BlockShow>(&log);
    assert_eq!(params["height"], 5, "{params}");
    assert_eq!(params["pow"], true, "{params}");
}

/// `chain height` prints the chain's block count: the tip plus one.
#[test]
fn print_height_renders_the_count() {
    let address = route_server(vec![(
        rpc::<wire::ChainHeight>(),
        rpc_result(serde_json::json!({
            "height": 41, "hash": "07".repeat(32), "writer": {"live": null}
        })),
    )]);
    let text = run(&["chain", "height"], Some(&address)).expect("renders");
    assert_eq!(text, "42");
}

/// **A daemon started offline prints the state** on every peer command
/// (Rick, 2026-10-14): its `p2p.offline` refusal is the state, not a
/// request failure. Red edit: drop the `p2p.offline` arm of `p2p_call`.
#[test]
fn an_offline_daemon_prints_the_state_on_every_peer_command() {
    let off = rpc_refusal(ErrorClass::RefusedByMethod, "p2p.offline");
    for (args, route) in [
        (&["peer", "list"][..], rpc::<wire::PeerList>()),
        (&["peer", "stats"][..], rpc::<wire::PeerList>()),
        (&["peer", "connections"][..], rpc::<wire::PeerConnections>()),
        (&["sync", "status"][..], rpc::<wire::SyncStatus>()),
        (&["p2p", "stats"][..], rpc::<wire::P2pStats>()),
    ] {
        let address = route_server(vec![(route, off.clone())]);
        let text = run(args, Some(&address)).unwrap_or_else(|error| panic!("{args:?}: {error}"));
        assert_eq!(text, "P2P: offline", "{args:?}");
    }
}

/// A refusal of any other kind is the command's failure, said as its class
/// and code.
#[test]
fn a_refusal_is_a_request_failure_with_the_class_and_code() {
    let address = route_server(vec![(
        rpc::<wire::ChainHeight>(),
        rpc_refusal(ErrorClass::NotReady, "daemon.unready"),
    )]);
    let text = run(&["chain", "height"], Some(&address)).expect_err("refused");
    assert_eq!(text, "NotReady daemon.unready");
}

/// Neither a reply nor a refusal: the reply is reported as malformed.
#[test]
fn malformed_reply_is_named_as_such() {
    let address = route_server(vec![(
        rpc::<wire::ChainHeight>(),
        "<html>not json</html>".to_owned(),
    )]);
    let text = run(&["chain", "height"], Some(&address)).expect_err("refused");
    assert!(text.contains("malformed"), "{text}");
}

#[test]
fn refused_connection_is_a_request_failure_with_a_reason() {
    let text = run(&["chain", "height"], Some("127.0.0.1:1")).expect_err("refused");
    assert!(!text.is_empty());
}

#[test]
fn unknown_command_refuses_without_a_daemon() {
    let parsed = crate::grammar::parse("no_such_command");
    assert!(
        matches!(parsed, crate::resolve::ResolvedCommand::Unknown { .. }),
        "{parsed:?}"
    );
}

// ── RK-5a: the ported format helpers ───────────────────────────────────
//
// Every expected string below was **printed by the C++ it replaces**, by
// linking `get_human_readable_timespan` and `get_human_readable_bytes`
// into the unit-test binary and dumping them for these inputs. They are
// transcriptions of an oracle's output, not a reading of its source — which
// is the difference between a test that pins the format and one that
// repeats whatever the port got wrong. (The dotted `d.h.m.s` interval of
// `get_time_interval_string` went with `print_pl`'s last-seen column,
// 2026-10-13: the Rust peer lists carry no clock.)

#[test]
fn a_timespan_reads_the_way_the_daemon_has_always_printed_it() {
    for (seconds, expected) in [
        (0u64, "0 seconds"),
        (1, "1 seconds"),
        (59, "59 seconds"),
        (60, "1.0 minutes"),
        (90, "1.5 minutes"),
        // The boundary is `< 3600`, so one second short of an hour is
        // sixty minutes rather than an hour.
        (3599, "60.0 minutes"),
        (3600, "1.0 hours"),
        (5400, "1.5 hours"),
        (86399, "24.0 hours"),
        (86400, "1.0 days"),
        (200_000, "2.3 days"),
        // A "month" is 30.5 days and a "year" 365.25, and the boundary
        // uses the same expression as the divisor.
        (2_635_200, "1.0 months"),
        (31_557_600, "1.0 years"),
        // Exactly a century is not "100.0 years".
        (3_155_760_000, "a long time"),
        (4_000_000_000, "a long time"),
    ] {
        assert_eq!(human_readable_timespan(seconds), expected, "{seconds}s");
    }
}

#[test]
fn bytes_read_in_base_two_units() {
    for (bytes, expected) in [
        (0u64, "0 B"),
        (1, "1 B"),
        (1023, "1023 B"),
        (1024, "1.00 kB"),
        (1500, "1.46 kB"),
        // One byte short of a mebibyte rounds *up* to "1024.00 kB"
        // rather than crossing into MB.
        (1_048_575, "1024.00 kB"),
        (1_048_576, "1.00 MB"),
        (1_073_741_824, "1.00 GB"),
        (1_099_511_627_776, "1.00 TB"),
        (5_000_000_000_000, "4.55 TB"),
    ] {
        assert_eq!(human_readable_bytes(bytes), expected, "{bytes} bytes");
    }
}

/// One line per peer: its tier, then its endpoint as the daemon wrote it
/// (host and port, an onion's included).
#[test]
fn peer_list_prints_each_tier_and_its_endpoint() {
    let peers = serde_json::json!([
        {"endpoint": "10.32.0.7:18080", "tier": "white"},
        {"endpoint": "abcdefghijklmnop.onion:18080", "tier": "gray"},
        {"endpoint": "[2001:db8::1]:18081", "tier": "white"},
    ]);
    let (address, log) =
        route_server_recording(vec![(rpc::<wire::PeerList>(), rpc_result(&peers))]);
    let out = run(&["peer", "list"], Some(&address)).expect("renders");
    assert_eq!(
        out,
        "white      10.32.0.7:18080\nwhite      [2001:db8::1]:18081\ngray       abcdefghijklmnop.onion:18080"
    );
    assert_eq!(
        params_of::<wire::PeerList>(&log)["local"],
        true,
        "the console asks for the whole list"
    );
    let (address, _) = route_server_recording(vec![(rpc::<wire::PeerList>(), rpc_result(&peers))]);
    let out = run(&["peer", "stats"], Some(&address)).expect("renders");
    assert!(out.contains("White list size: 2/1000"), "{out}");
    assert!(out.contains("Gray list size: 1/5000"), "{out}");
}

/// The capacities are a parameter, so this is tested against the values
/// the daemon holds: `shekyl-peerlist`'s caps, which the caller passes.
#[test]
fn the_peerlist_stats_report_real_capacities() {
    assert_eq!(shekyl_peerlist::WHITE_CAP, 1000);
    assert_eq!(shekyl_peerlist::GRAY_CAP, 5000);
    let out = render_peer_list_stats(7, 250, 1000, 5000);
    assert!(out.contains("White list size: 7/1000 (0.7%)"), "{out}");
    assert!(out.contains("Gray list size: 250/5000 (5%)"), "{out}");
    // The float noise this rounding exists to stop: 7/1000 is exactly the
    // value that renders `0.7000000000000001` under `{}` on an `f64`.
    assert!(!out.contains("0.7000000000000001"), "{out}");
}

/// A zero capacity is what the link stub would have supplied, and the
/// divide-by-zero guard makes it *survivable* — which is why a test that
/// touched it would have gone green rather than crashed.
#[test]
fn a_zero_capacity_renders_rather_than_dividing_by_zero() {
    let out = render_peer_list_stats(3, 0, 0, 0);
    assert!(out.contains("White list size: 3/0 (0%)"), "{out}");
}

fn p2p_stats_reply() -> String {
    rpc_result(serde_json::json!({
        "started": 1_700_000_000_u64,
        "download": 4096,
        "upload": 2048,
        "download_packets": 40,
        "upload_packets": 10,
    }))
}

/// An `option_show` reply carrying the two rate rows `p2p stats` reads.
fn option_show_rates(down: &str, up: &str) -> String {
    rpc_result(serde_json::json!([
        {"name": "p2p-download-max", "source": "default", "runtime": true, "secret": false, "value": down},
        {"name": "p2p-upload-max", "source": "runtime", "runtime": true, "secret": false, "value": up},
    ]))
}

/// `p2p stats` over its two legs: `p2p_stats` and `option_show`'s two rate
/// rows. The limits are asymmetric (8 down, 4 up) because a single number
/// would pass a renderer that read one row twice.
#[test]
fn net_stats_renders_the_option_show_limits_beside_the_counters() {
    let address = route_server(vec![
        (rpc::<wire::P2pStats>(), p2p_stats_reply()),
        (
            rpc::<wire::OptionShow>(),
            option_show_rates("8KiB/s", "4KiB/s"),
        ),
    ]);
    let out = run(&["p2p", "stats"], Some(&address)).expect("renders");
    assert!(out.contains("Received 4096 bytes"), "{out}");
    assert!(out.contains("Sent 2048 bytes"), "{out}");
    assert!(out.contains("limit of 8.00 kB/s"), "{out}");
    assert!(out.contains("limit of 4.00 kB/s"), "{out}");
}

/// `unlimited` is a bound of none, printed as such and never as a limit of
/// zero bytes.
#[test]
fn net_stats_prints_an_unlimited_direction_as_no_limit() {
    let address = route_server(vec![
        (rpc::<wire::P2pStats>(), p2p_stats_reply()),
        (
            rpc::<wire::OptionShow>(),
            option_show_rates("unlimited", "4KiB/s"),
        ),
    ]);
    let out = run(&["p2p", "stats"], Some(&address)).expect("renders");
    assert!(out.contains("average 0 B/s, no limit"), "{out}");
    assert!(!out.contains("limit of 0 B/s"), "{out}");
    assert!(out.contains("limit of 4.00 kB/s"), "{out}");
}

/// A reply missing a rate row, or carrying text that is not a rate, is
/// **named**, not defaulted.
#[test]
fn an_option_show_reply_without_a_rate_is_refused_rather_than_defaulted() {
    let only_down = rpc_result(serde_json::json!([
        {"name": "p2p-download-max", "source": "default", "runtime": true, "secret": false, "value": "8KiB/s"},
    ]));
    let address = route_server(vec![
        (rpc::<wire::P2pStats>(), p2p_stats_reply()),
        (rpc::<wire::OptionShow>(), only_down),
    ]);
    let out = run(&["p2p", "stats"], Some(&address)).expect_err("refused");
    assert!(out.contains("did not answer p2p-upload-max"), "{out}");

    let address = route_server(vec![
        (rpc::<wire::P2pStats>(), p2p_stats_reply()),
        (
            rpc::<wire::OptionShow>(),
            option_show_rates("8KiB/s", "fast"),
        ),
    ]);
    let out = run(&["p2p", "stats"], Some(&address)).expect_err("refused");
    assert!(out.contains("not a rate"), "{out}");
}

/// A method the daemon does not serve is a request failure, not a zero.
#[test]
fn a_method_the_daemon_does_not_serve_fails_loudly() {
    let address = route_server(vec![(rpc::<wire::P2pStats>(), p2p_stats_reply())]);
    let out = run(&["p2p", "stats"], Some(&address)).expect_err("refused");
    assert!(!out.contains("limit of 0 B/s"), "{out}");
}

/// `peer connections`: one line per connection, its connector, the byte
/// counts and idle times, the sync mode, and a local mark.
#[test]
fn connections_print_one_line_each() {
    let connections = serde_json::json!([{
        "inbound": true, "local": true, "endpoint": "127.0.0.1:18080", "connector": "clearnet",
        "download": 10, "upload": 20, "download_idle": 1, "upload_idle": 2, "mode": "slot",
        "age": 30, "download_speed_average": 3, "download_speed_current": 4,
        "upload_speed_average": 5, "upload_speed_current": 6, "id": "ab", "height": 7,
    }]);
    let address = route_server(vec![(
        rpc::<wire::PeerConnections>(),
        rpc_result(&connections),
    )]);
    let out = run(&["peer", "connections"], Some(&address)).expect("renders");
    let line = out.lines().nth(1).expect("one connection line");
    assert!(line.starts_with("INC 127.0.0.1:18080"), "{out}");
    assert!(
        line.contains("clearnet") && line.contains("10(1)/20(2)"),
        "{out}"
    );
    assert!(line.contains("slot") && line.ends_with("[LOCAL]"), "{out}");
}

/// `sync status`: heights as block counts (the wire's tips plus one), the
/// state, and one line per session.
#[test]
fn sync_status_prints_counts_and_sessions() {
    let sync = serde_json::json!({
        "height": 49, "target_height": 99, "state": "behind", "stalled": false,
        "session": [{
            "connection": "ab", "endpoint": "10.0.0.1:18080", "height": 99, "mode": "slot",
            "header": null,
            "span": [{"from": 50, "blocks": 10, "size": 100, "age": 1, "due": 2}],
            "download_speed": 500,
        }],
    });
    let address = route_server(vec![(rpc::<wire::SyncStatus>(), rpc_result(&sync))]);
    let out = run(&["sync", "status"], Some(&address)).expect("renders");
    assert!(
        out.starts_with("Height: 50, target: 100 (50%), behind"),
        "{out}"
    );
    assert!(out.contains("1 peers"), "{out}");
    assert!(
        out.contains("10.0.0.1:18080")
            && out.contains("100")
            && out.contains("10 blocks in 1 spans"),
        "{out}"
    );
}

fn header_at(height: u64) -> serde_json::Value {
    serde_json::json!({
        "version_major": 1, "version_minor": 0, "time": 1_600_000_000_u64 + height,
        "parent": "00".repeat(32), "nonce": 42, "orphan": false,
        "height": height, "depth": 0, "hash": hex::encode([u8::try_from(height % 256).unwrap(); 32]),
        "difficulty": "0x3e8", "difficulty_cumulative": "0x3e8",
        "reward": "600000000000", "weight": 100, "weight_longterm": 100,
        "tx_count": 1, "coinbase": "00".repeat(32),
        "curve_root": "00".repeat(32), "section_root": "00".repeat(32),
    })
}

fn headers_reply(headers: Vec<serde_json::Value>) -> String {
    rpc_result(headers)
}

/// `block header list --from 2 --to 3` asks for exactly that range and
/// lists it, and reads no tip.
#[test]
fn blockchain_info_lists_the_window_it_was_given() {
    let (address, log) = route_server_recording(vec![(
        rpc::<wire::BlockHeaderList>(),
        headers_reply(vec![header_at(2), header_at(3)]),
    )]);
    let out = run(
        &["block", "header", "list", "--from", "2", "--to", "3"],
        Some(&address),
    )
    .expect("renders");
    assert!(out.contains("height: 2, timestamp: 1600000002"), "{out}");
    assert!(out.contains("height: 3, timestamp: 1600000003"), "{out}");
    assert!(out.contains("major version: 1, minor version: 0"), "{out}");
    assert!(
        out.contains("difficulty: 1000, nonce 42, reward 600.000000000"),
        "{out}"
    );
    assert!(out.contains("\n\nheight: 3"), "{out}");
    let params = params_of::<wire::BlockHeaderList>(&log);
    assert_eq!(params["from"], 2, "{params}");
    assert_eq!(params["to"], 3, "{params}");
    assert!(
        legs(&log)
            .iter()
            .all(|(_, body)| method_of(body).as_deref()
                != Some(<wire::DaemonStatus as RpcMethod>::NAME)),
        "the literal form reads no tip"
    );
}

/// A height the daemon does not hold is named, not skipped.
#[test]
fn a_missing_header_slot_is_named() {
    let address = route_server(vec![(
        rpc::<wire::BlockHeaderList>(),
        rpc_result(serde_json::json!([header_at(2), {"missing": null}])),
    )]);
    let out = run(
        &["block", "header", "list", "--from", "2", "--to", "3"],
        Some(&address),
    )
    .expect_err("refused");
    assert!(out.contains("no header at height 3"), "{out}");
}

/// `--from` is a height. A sign is refused before any request.
#[test]
fn a_negative_start_counts_back_from_the_tip() {
    let (address, log) = route_server_recording(vec![]);
    let out = run(
        &["block", "header", "list", "--from", "-3", "--to", "3"],
        Some(&address),
    )
    .expect_err("refused");
    assert!(out.contains("takes an integer"), "{out}");
    assert!(
        log.lock().unwrap().is_empty(),
        "a signed height is refused before a request"
    );
}

/// `--from` after `--to` is refused by the grammar, before a request.
#[test]
fn a_window_longer_than_the_chain_is_refused_by_name() {
    let (address, log) = route_server_recording(vec![]);
    let out = run(
        &["block", "header", "list", "--from", "5", "--to", "3"],
        Some(&address),
    )
    .expect_err("refused");
    assert!(out.contains("--from is after --to"), "{out}");
    assert!(
        log.lock().unwrap().is_empty(),
        "the refusal makes no request"
    );
}

/// epee's median, both parities.
///
/// The even case is the one with a decision in it: epee averages the two
/// middle elements and floors, which a lower-middle median (the usual
/// Rust one-liner) would silently change.
#[test]
fn the_median_is_epees_including_its_even_length_average() {
    assert_eq!(median(&mut []), 0);
    assert_eq!(median(&mut [7]), 7);
    assert_eq!(median(&mut [3, 1, 2]), 2);
    // (2 + 4) / 2 = 3, not 2.
    assert_eq!(median(&mut [4, 2, 1, 8]), 3);
    // Floors: (1 + 2) / 2 = 1.
    assert_eq!(median(&mut [2, 1]), 1);
    // And it cannot overflow forming the sum.
    assert_eq!(median(&mut [u64::MAX, u64::MAX]), u64::MAX);
}

fn fee_reply() -> String {
    rpc_result(serde_json::json!({"economy": "20", "standard": "80", "high": "4000"}))
}

/// A range reply that does not fill the window it was asked for is refused,
/// not summarised: too few headers, and the right count for the wrong
/// heights.
#[test]
fn a_range_reply_that_misses_the_window_is_refused() {
    let address = route_server(vec![
        (rpc::<wire::DaemonStatus>(), status_reply(10)),
        (rpc::<wire::Fee>(), fee_reply()),
        (
            rpc::<wire::BlockHeaderList>(),
            headers_reply(vec![header_at(7)]),
        ),
    ]);
    let out = run(&["chain", "stats", "--last", "3"], Some(&address)).expect_err("refused");
    assert!(out.contains("answered 1 headers for the 3 blocks"), "{out}");

    let address = route_server(vec![
        (rpc::<wire::DaemonStatus>(), status_reply(10)),
        (rpc::<wire::Fee>(), fee_reply()),
        (
            rpc::<wire::BlockHeaderList>(),
            headers_reply(vec![header_at(100), header_at(101), header_at(102)]),
        ),
    ]);
    let out = run(&["chain", "stats", "--last", "3"], Some(&address)).expect_err("refused");
    assert!(out.contains("starting at height 100"), "{out}");
    assert!(!out.contains("Last 3:"), "{out}");
}

/// `chain stats` over its three legs. Every aggregate is distinguishable.
#[test]
fn dynamic_stats_reports_the_window_it_summarized() {
    let mut headers: Vec<serde_json::Value> = [7u64, 8, 9].iter().map(|h| header_at(*h)).collect();
    for (header, (weight, txs, time)) in
        headers
            .iter_mut()
            .zip([(100, 1, 1000), (300, 2, 1120), (200, 3, 1300)])
    {
        header["weight"] = serde_json::json!(weight);
        header["tx_count"] = serde_json::json!(txs);
        header["time"] = serde_json::json!(time);
    }
    let (address, log) = route_server_recording(vec![
        (rpc::<wire::DaemonStatus>(), status_reply(10)),
        (rpc::<wire::Fee>(), fee_reply()),
        (rpc::<wire::BlockHeaderList>(), headers_reply(headers)),
    ]);
    let out = run(&["chain", "stats", "--last", "3"], Some(&address)).expect("renders");
    // Difficulty 0x1e240 is 123456, the cumulative 0x2dc6c0 is 3000000, the
    // count is 10, and the fee is the lowest tier.
    assert!(
        out.contains("Height: 10, diff 123456, cum. diff 3000000, target 120 sec"),
        "{out}"
    );
    assert!(out.contains("dyn fee 0.000000020/byte"), "{out}");
    assert!(out.contains("Last 3: avg. diff 1000"), "{out}");
    assert!(out.contains("100 avg sec/block"), "{out}");
    assert!(out.contains("avg num txes 2"), "{out}");
    assert!(out.contains("avg. reward 600.000000000"), "{out}");
    assert!(out.contains("median block weight 200"), "{out}");
    // The window: a count of 10, three blocks, so [7, 9].
    let params = params_of::<wire::BlockHeaderList>(&log);
    assert_eq!(params["from"], 7, "{params}");
    assert_eq!(params["to"], 9, "{params}");
}

/// A window longer than the chain is clamped to the chain, not refused.
#[test]
fn dynamic_stats_clamps_a_window_longer_than_the_chain() {
    let (address, log) = route_server_recording(vec![
        (rpc::<wire::DaemonStatus>(), status_reply(2)),
        (rpc::<wire::Fee>(), fee_reply()),
        (
            rpc::<wire::BlockHeaderList>(),
            headers_reply(vec![header_at(0), header_at(1)]),
        ),
    ]);
    let out = run(&["chain", "stats", "--last", "500"], Some(&address)).expect("renders");
    assert!(out.contains("Last 2:"), "{out}");
    let params = params_of::<wire::BlockHeaderList>(&log);
    assert_eq!(params["from"], 0, "{params}");
    assert_eq!(params["to"], 1, "{params}");
}

fn one_alt_chain(tip: u8, height: u64, hashes: &[u8], parent: u8) -> serde_json::Value {
    serde_json::json!({
        "hash": hex::encode([tip; 32]),
        "height": height,
        "difficulty_cumulative": "0x3e8",
        "block": hashes.iter().map(|h| hex::encode([*h; 32])).collect::<Vec<_>>(),
        "parent": hex::encode([parent; 32]),
    })
}

/// The listing: sorted by height, each line carrying the fork point and its
/// depth below the main tip; the length is the chain's own block list.
#[test]
fn alt_chain_info_lists_and_filters() {
    let address = route_server(vec![
        (rpc::<wire::DaemonStatus>(), status_reply(100)),
        (
            rpc::<wire::ChainAlt>(),
            rpc_result(serde_json::json!([
                one_alt_chain(9, 90, &[8, 9], 7),
                one_alt_chain(5, 50, &[5], 4),
                one_alt_chain(3, 30, &[], 2),
            ])),
        ),
    ]);
    let out = run(&["chain", "alt"], Some(&address)).expect("renders");
    assert!(out.starts_with("2 alternate chains found:"), "{out}");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[1].contains("1 blocks long, from height 50"), "{out}");
    assert!(lines[2].contains("2 blocks long, from height 89"), "{out}");
    // 100 - 89 - 1 = 10 deep; 100 - 50 - 1 = 49.
    assert!(lines[1].contains("(49 deep)"), "{out}");
    assert!(lines[2].contains("(10 deep)"), "{out}");
    assert!(lines[2].contains("diff 1000"), "{out}");
}

/// A `mine_status` reply: the miner, idle or at `speed`, with a job posted
/// unless `cause` names why none is.
fn mining_reply(active: bool, speed: MineSpeed, cause: Option<&str>) -> String {
    rpc_result(serde_json::json!({
        "active": active,
        "speed": speed,
        "threads": 0,
        "address": null,
        "block_spacing": 120,
        "height": if cause.is_none() { serde_json::json!(5) } else { serde_json::Value::Null },
        "reward": if cause.is_none() { serde_json::json!("1") } else { serde_json::Value::Null },
        "difficulty": if cause.is_none() { serde_json::json!("0x1") } else { serde_json::Value::Null },
        "cause": cause.map(|code| Diagnostic::new(code, "why")),
        "txpool_retired": false,
    }))
}

const fn speed(count: u64, window: u64) -> MineSpeed {
    MineSpeed {
        count: Count(count),
        window: Duration(window),
    }
}

/// A hash rate for a human, at every prefix boundary the C++ had.
#[test]
fn a_mining_speed_picks_the_prefix_the_cpp_picked() {
    assert_eq!(mining_speed(0), "0 H/s");
    assert_eq!(mining_speed(999), "999 H/s");
    // 1000 is the first prefixed value: still under a million, so `k`.
    assert_eq!(mining_speed(1000), "1.00 kH/s");
    // 999999 / 1000 is 999.999, which `%.2f` rounds up — so the largest
    // value that still reads in kilohashes prints as `1000.00 kH/s`.
    // The C++ did this too; it is recorded rather than corrected,
    // because the alternative is a second rounding rule for a console
    // line.
    assert_eq!(mining_speed(999_999), "1000.00 kH/s");
    // A million divides once, then reads as thousands of thousands.
    assert_eq!(mining_speed(1_000_000), "1.00 MH/s");
    assert_eq!(mining_speed(2_500_000_000), "2.50 GH/s");
    // Past every prefix, the raw number — the C++ fell out of its loop
    // with `prefix = 0` and formatted the value it started with.
    assert_eq!(
        mining_speed(10u128.pow(33)),
        format!("{} H/s", 10u128.pow(33))
    );
}

/// The sync percentage, including the 99.9 clamp that exists so a daemon
/// one block short does not read as finished.
#[test]
fn the_sync_percentage_never_rounds_up_to_a_hundred() {
    assert!((sync_percentage(50, 100) - 50.0).abs() < f64::EPSILON);
    // Fully synced is a real 100.
    assert!((sync_percentage(100, 100) - 100.0).abs() < f64::EPSILON);
    // A target below our height means we are ahead of it.
    assert!((sync_percentage(100, 50) - 100.0).abs() < f64::EPSILON);
    // 99999/100000 would print as 100.0%; it must not.
    assert!((sync_percentage(99_999, 100_000) - 99.9).abs() < f64::EPSILON);
    // And an empty chain divides by one, not by zero.
    assert!((sync_percentage(0, 0) - 0.0).abs() < f64::EPSILON);
}

/// The status line names a network by its row's name, regtest included: a
/// regtest daemon is `regtest`, never `mainnet` (NI-Q8; the label once
/// mapped the regtest network to mainnet's name).
#[test]
fn the_network_label_is_the_rows_name() {
    assert_eq!(
        super::info::network_label(shekyl_rpc_types::Network::Regtest),
        "regtest"
    );
    for network in shekyl_rpc_types::Network::ALL {
        assert_eq!(super::info::network_label(network), network.name());
    }
}

/// **The status line's network is the one `version` named** (RK-Q6).
/// `daemon_status` carries no network: a testnet console against a testnet
/// daemon says testnet, and the handshake's reply is reused — `version` is
/// asked once.
#[test]
fn the_status_line_names_the_network_version_reported() {
    use shekyl_rpc_types::Network::Testnet;
    let (address, log) = route_server_recording(vec![
        (rpc::<wire::DaemonStatus>(), status_reply(100)),
        (
            rpc::<wire::MineStatus>(),
            mining_reply(false, speed(0, 0), None),
        ),
        (
            rpc::<wire::Version>(),
            version_but(|r| {
                r.network = Testnet;
                r.genesis = HashHex::from_bytes(shekyl_rpc_types::genesis_hash_for(Testnet));
            }),
        ),
    ]);
    let out = run_on(Testnet, &["daemon", "status"], Some(&address)).expect("renders");
    assert!(out.contains("Height: 100/100 (100.0%) on testnet"), "{out}");
    let asked = log.lock().unwrap();
    let version_requests = asked
        .iter()
        .filter(|(_, body)| method_of(body).as_deref() == Some(<wire::Version as RpcMethod>::NAME))
        .count();
    assert_eq!(version_requests, 1, "one handshake, reused: {asked:?}");
}

/// The whole status line, with both legs.
#[test]
fn the_status_line_reads_the_way_the_daemon_has_always_printed_it() {
    let address = route_server(vec![
        (rpc::<wire::DaemonStatus>(), status_reply(100)),
        (
            rpc::<wire::MineStatus>(),
            mining_reply(true, speed(2500, 1), None),
        ),
    ]);
    let out = run(&["daemon", "status"], Some(&address)).expect("renders");
    assert!(out.contains("Height: 100/100 (100.0%) on mainnet"), "{out}");
    assert!(out.contains("mining at 2.50 kH/s"), "{out}");
    // net hash = difficulty 123456 / target 120, integer-divided to
    // 1028 H/s, which reads as 1.03 kH/s.
    assert!(
        out.contains("net hash 1.03 kH/s, 8(out)+3(in) connections, uptime "),
        "{out}"
    );
    // The node's live caches, as memory (4.4). Red edit: drop the clause
    // from `show_status`.
    assert!(out.contains(", RandomX caches 1 (256 MiB)"), "{out}");
}

/// Eight hashes in ten seconds is 0.80 H/s.
#[test]
fn a_miner_below_one_hash_a_second_reads_as_a_fraction() {
    let address = route_server(vec![
        (rpc::<wire::DaemonStatus>(), status_reply(100)),
        (
            rpc::<wire::MineStatus>(),
            mining_reply(true, speed(8, 10), None),
        ),
    ]);
    let out = run(&["daemon", "status"], Some(&address)).expect("renders");
    assert!(out.contains("mining at 0.80 H/s"), "{out}");
}

/// **A daemon that withholds Status is not a daemon with no connections
/// and no uptime.**
#[test]
fn a_daemon_that_withholds_status_is_not_shown_as_zero_connections() {
    let address = route_server(vec![
        (
            rpc::<wire::DaemonStatus>(),
            rpc_result(status_withheld(100)),
        ),
        (
            rpc::<wire::MineStatus>(),
            mining_reply(false, speed(0, 0), None),
        ),
    ]);
    let out = run(&["daemon", "status"], Some(&address)).expect("renders");
    assert!(out.contains("not mining"), "{out}");
    assert!(
        out.trim_end().ends_with("connections not disclosed"),
        "no counts and no uptime clause: {out}"
    );
    assert!(!out.contains("(out)") && !out.contains("uptime"), "{out}");
    // Status withheld: no cache count either, never a zero.
    assert!(!out.contains("RandomX"), "{out}");
}

/// **An offline daemon that withholds Status still says it is offline**:
/// the state is Health, which every caller is told.
#[test]
fn an_offline_daemon_that_withholds_status_prints_the_state() {
    let mut info = status_offline(100);
    let members = info.as_object_mut().unwrap();
    for key in STATUS_PART_KEYS {
        members.remove(*key);
    }
    let address = route_server(vec![
        (rpc::<wire::DaemonStatus>(), rpc_result(info)),
        (
            rpc::<wire::MineStatus>(),
            mining_reply(false, speed(0, 0), None),
        ),
    ]);
    let out = run(&["daemon", "status"], Some(&address)).expect("renders");
    assert!(
        out.trim_end().ends_with("P2P: offline"),
        "the state, and no uptime clause: {out}"
    );
    assert!(
        !out.contains("not disclosed") && !out.contains("uptime"),
        "{out}"
    );
}

/// A shown zero connection count is a count, and it gets its uptime.
#[test]
fn a_shown_zero_connection_count_prints_as_zero() {
    let mut info = daemon_status_value(100);
    info["peer_outbound_count"] = serde_json::json!(0);
    info["peer_inbound_count"] = serde_json::json!(0);
    let address = route_server(vec![
        (rpc::<wire::DaemonStatus>(), rpc_result(info)),
        (
            rpc::<wire::MineStatus>(),
            mining_reply(false, speed(0, 0), None),
        ),
    ]);
    let out = run(&["daemon", "status"], Some(&address)).expect("renders");
    assert!(out.contains("0(out)+0(in) connections, uptime "), "{out}");
}

/// A daemon that will not answer `mine_status` still gets a status line.
#[test]
fn a_daemon_without_mine_status_still_reports_its_status() {
    let address = route_server(vec![(rpc::<wire::DaemonStatus>(), status_reply(100))]);
    let out = run(&["daemon", "status"], Some(&address)).expect("renders");
    assert!(out.contains("mining info unavailable"), "{out}");
    assert!(out.contains("Height: 100/100"), "{out}");
}

/// The view listener refuses `mine_status` (`mining-control`) with the grant
/// refusal: mining info is unavailable, and the rest of the line prints.
#[test]
fn a_view_listener_refuses_mine_status_and_status_still_prints() {
    let error = shekyl_daemon_rpc::authority::Authority::VIEW_LISTENER
        .admit(wire::Id::MineStatus.row())
        .expect_err("mining-control");
    let body = serde_json::to_string(&shekyl_daemon_rpc::authority::refusal(
        serde_json::Value::Null,
        &error,
    ))
    .expect("the envelope");
    let address = route_server(vec![
        (rpc::<wire::DaemonStatus>(), status_reply(100)),
        (rpc::<wire::MineStatus>(), body),
    ]);
    let out = run(&["daemon", "status"], Some(&address)).expect("renders");
    assert!(out.contains("mining info unavailable"), "{out}");
    assert!(out.contains("Height: 100/100"), "{out}");
}

/// A node that posts no job because it is not synced is neither mining nor
/// idle. Red edit: drop the `mine.syncing` arm in `fetch_mining_status`.
#[test]
fn a_miner_whose_node_is_syncing_reads_as_syncing() {
    let address = route_server(vec![
        (rpc::<wire::DaemonStatus>(), status_reply(100)),
        (
            rpc::<wire::MineStatus>(),
            mining_reply(false, speed(0, 0), Some("mine.syncing")),
        ),
    ]);
    let out = run(&["daemon", "status"], Some(&address)).expect("renders");
    assert!(out.contains(", syncing,"), "{out}");
}

// ── VC-3: the console's identity handshake ──────────────────────────────

#[test]
fn an_older_daemon_is_refused_and_named_as_the_older_one() {
    let addr = route_server(vec![(
        rpc::<wire::Version>(),
        version_but(|r| r.version.0 -= 1),
    )]);
    let out = run(&["chain", "height"], Some(&addr)).expect_err("refused");
    assert!(out.contains("RPC contract mismatch"), "{out}");
    assert!(out.contains("the daemon is the older one"), "{out}");
}

#[test]
fn a_newer_daemon_names_this_build_as_the_older_one() {
    let addr = route_server(vec![(
        rpc::<wire::Version>(),
        version_but(|r| r.version.0 += 1),
    )]);
    let out = run(&["chain", "height"], Some(&addr)).unwrap_or_else(|error| error);
    assert!(out.contains("this build is the older one"), "{out}");
}

#[test]
fn a_different_rules_digest_is_refused_without_inventing_an_ordering() {
    let addr = route_server(vec![(
        rpc::<wire::Version>(),
        version_but(|r| r.consensus_digest = HashHex::from_bytes([0x99; 32])),
    )]);
    let out = run(&["chain", "height"], Some(&addr)).expect_err("refused");
    assert!(out.contains("consensus-constant mismatch"), "{out}");
    // VC-D15: a hash carries no ordering, so the refusal must NOT claim one.
    assert!(!out.contains("older"), "{out}");
    assert!(out.contains("different rule set"), "{out}");
}

#[test]
fn a_wrong_network_daemon_is_refused_even_though_every_other_axis_agrees() {
    let addr = route_server(vec![(
        rpc::<wire::Version>(),
        version_but(|r| r.network = shekyl_rpc_types::Network::Testnet),
    )]);
    let out = run(&["chain", "height"], Some(&addr)).expect_err("refused");
    assert!(out.contains("network mismatch"), "{out}");
    assert!(out.contains("mainnet") && out.contains("testnet"), "{out}");
}

/// A word that changes the daemon posts nothing until the handshake agrees.
#[test]
fn a_mutating_word_refuses_a_wrong_network_daemon_before_it_posts() {
    let (addr, log) = route_server_recording(vec![(
        rpc::<wire::Version>(),
        version_but(|r| r.network = shekyl_rpc_types::Network::Testnet),
    )]);
    let out = run(&["option", "set", "log-level", "info"], Some(&addr)).expect_err("refused");
    assert!(out.contains("network mismatch"), "{out}");
    let asked = log.lock().expect("log");
    assert!(
        asked
            .iter()
            .all(|(_, body)| method_of(body).as_deref()
                != Some(<wire::OptionSet as RpcMethod>::NAME)),
        "a refused daemon is not asked to change: {asked:?}"
    );
}

#[test]
fn a_foreign_genesis_daemon_is_refused() {
    let addr = route_server(vec![(
        rpc::<wire::Version>(),
        version_but(|r| r.genesis = HashHex::from_bytes([0xff; 32])),
    )]);
    let out = run(&["chain", "height"], Some(&addr)).expect_err("refused");
    assert!(out.contains("genesis mismatch"), "{out}");
    assert!(out.contains("different chain"), "{out}");
}

/// A reply with no readable version, one that claims this build's version
/// and then answers in another shape, and a daemon with no `version` method
/// at all (a 3.x daemon, RW-Q6) are each the wire axis disagreeing, said as
/// that (VC-D16). Red edit: read `NoSuchMethod` as a transport fault in the
/// handshake.
#[test]
fn a_version_read_that_does_not_parse_is_reported_as_a_wire_mismatch() {
    let unreadable = [
        rpc_result(serde_json::json!({})),
        rpc_result(serde_json::json!({"version": shekyl_rpc_types::CORE_RPC_VERSION})),
        serde_json::json!({"jsonrpc": "2.0", "id": 0, "error": {
            "code": shekyl_rpc_types::errors::METHOD_NOT_FOUND, "message": "Method not found"
        }})
        .to_string(),
    ];
    for reply in unreadable {
        let addr = route_server(vec![(rpc::<wire::Version>(), reply.clone())]);
        let out = run(&["chain", "height"], Some(&addr)).expect_err("refused");
        assert!(
            out.contains("does not match the RPC contract"),
            "{reply}: {out}"
        );
        assert!(out.contains("cannot be named here"), "{reply}: {out}");
    }
}

/// **The version is read before the rest (RK-Q11).** A daemon of another
/// RPC version is still named: both versions, and which side is older.
#[test]
fn a_daemon_of_another_version_is_named_though_its_reply_does_not_decode() {
    let ours = shekyl_rpc_types::CORE_RPC_VERSION;
    for (theirs, older) in [
        (ours - 1, "the daemon is the older"),
        (5 << 16, "this build is the older"),
    ] {
        let addr = route_server(vec![(
            rpc::<wire::Version>(),
            rpc_result(serde_json::json!({
                "version": theirs,
                "a_member_this_build_has_never_heard_of": true,
            })),
        )]);
        let out = run(&["chain", "height"], Some(&addr)).expect_err("refused");
        assert!(out.contains("RPC contract mismatch"), "{out}");
        assert!(
            out.contains(&shekyl_rpc_types::core_rpc_version_string(theirs))
                && out.contains(&shekyl_rpc_types::core_rpc_version_string(ours)),
            "both versions are named: {out}"
        );
        assert!(out.contains(older), "{out}");
    }
}

#[test]
fn an_unknown_command_refuses_without_opening_a_socket() {
    // A typo is a parse refusal. It does not open a socket, so the handshake
    // never runs and an unreachable address is never dialed.
    let parsed = crate::grammar::parse("no_such_command");
    assert!(
        matches!(parsed, crate::resolve::ResolvedCommand::Unknown { .. }),
        "{parsed:?}"
    );
}

// ── `chain difficulty`, `version` and `txpool stats` ────────────────────

/// `chain difficulty`: the block count, the tip, both difficulties in
/// decimal, and the hash rate over the build's target.
#[test]
fn diff_prints_the_tip_the_difficulties_and_the_hash_rate() {
    let address = route_server(vec![(rpc::<wire::DaemonStatus>(), status_reply(100))]);
    let out = run(&["chain", "difficulty"], Some(&address)).expect("renders");
    assert_eq!(
        out,
        format!(
            "BH: 100, TH: {}, DIFF: 123456, CUM_DIFF: 3000000, HR: 1028 H/s",
            "5a".repeat(32)
        )
    );
}

/// `version` prints the daemon's revision.
#[test]
fn version_prints_the_daemons_software_version() {
    let address = route_server(vec![(rpc::<wire::DaemonStatus>(), status_reply(100))]);
    let out = run(&["version"], Some(&address)).expect("renders");
    assert_eq!(out, "3.1.0-test");
}

/// **`version` answers from a daemon every other command refuses** (VC
/// §3.6.2). The control is `chain difficulty` against the same daemon.
#[test]
fn version_answers_from_a_daemon_the_handshake_refuses() {
    let routes = || {
        vec![
            (rpc::<wire::DaemonStatus>(), status_reply(100)),
            (
                rpc::<wire::Version>(),
                version_but(|r| r.genesis = HashHex::from_bytes([0xff; 32])),
            ),
        ]
    };
    let out = run(&["chain", "difficulty"], Some(&route_server(routes()))).expect_err("refused");
    assert!(out.contains("genesis mismatch"), "{out}");
    let out = run(&["version"], Some(&route_server(routes()))).expect("renders");
    assert_eq!(out, "3.1.0-test");
}

/// **Against a daemon of another RPC version, `version` names both RPC
/// versions and reads nothing else** (RK-Q11, RK-D25): the fake daemon
/// serves no `daemon_status` at all.
#[test]
fn version_names_both_rpc_versions_when_they_differ() {
    let ours = shekyl_rpc_types::CORE_RPC_VERSION;
    for (theirs, older) in [
        (ours - 1, "the daemon is the older one"),
        (5 << 16, "this console is the older one"),
    ] {
        let address = route_server(vec![(
            rpc::<wire::Version>(),
            rpc_result(serde_json::json!({"version": theirs})),
        )]);
        let out = run(&["version"], Some(&address)).expect_err("refused");
        assert_eq!(
            out,
            format!(
                "The daemon speaks RPC {}; this console speaks RPC {}. {older}. The daemon's \
                 software version cannot be read across that difference.",
                shekyl_rpc_types::core_rpc_version_string(theirs),
                shekyl_rpc_types::core_rpc_version_string(ours),
            )
        );
    }
}

/// **No second lenient reader** (RK-D25): a `daemon_status` in another
/// shape is refused, naming the member.
#[test]
fn version_decodes_daemon_status_strictly() {
    let mut other = daemon_status_value(100);
    other["a_member_from_the_future"] = serde_json::json!(1);
    let address = route_server(vec![(rpc::<wire::DaemonStatus>(), rpc_result(other))]);
    let out = run(&["version"], Some(&address)).expect_err("refused");
    assert!(out.contains("a_member_from_the_future"), "{out}");
}

/// A daemon that withholds Status does not disclose its revision: a
/// failure that says so, not an empty line.
#[test]
fn version_says_when_the_daemon_does_not_disclose_it() {
    let address = route_server(vec![(
        rpc::<wire::DaemonStatus>(),
        rpc_result(status_withheld(100)),
    )]);
    let out = run(&["version"], Some(&address)).expect_err("refused");
    assert_eq!(out, "The daemon software version is not available.");
}

/// **An empty revision is not "undisclosed"** (RK-D23): a shown Status with
/// an empty `revision` is contract drift, refused as such. Red edit: drop
/// the empty check in `node::version`.
#[test]
fn version_refuses_a_shown_status_with_an_empty_revision() {
    let mut empty = daemon_status_value(100);
    empty["revision"] = serde_json::json!("");
    let address = route_server(vec![(rpc::<wire::DaemonStatus>(), rpc_result(empty))]);
    let out = run(&["version"], Some(&address)).expect_err("refused");
    assert_ne!(out, "The daemon software version is not available.");
    assert!(out.contains("empty `revision`"), "{out}");
}

fn pool_stats_reply() -> String {
    rpc_result(serde_json::json!({
        "count": 3, "weight_total": 700_001, "weight_min": 2_000, "weight_max": 400_000,
        "weight_median": 3_000, "fee_total": "3000000000", "private_count": 2,
    }))
}

/// `txpool stats` with both legs: the pool's statistics and
/// `daemon_status`' weight limit the backlog is measured against (600000,
/// so the zone is 300000).
#[test]
fn print_pool_stats_reads_the_stats_and_the_weight_limit() {
    let (address, log) = route_server_recording(vec![
        (rpc::<wire::TxpoolStats>(), pool_stats_reply()),
        (rpc::<wire::DaemonStatus>(), status_reply(100)),
    ]);
    let out = run(&["txpool", "stats"], Some(&address)).expect("renders");
    assert!(out.starts_with("3 tx(es), 700001 weight total"), "{out}");
    assert!(out.contains("2 not relayed"), "{out}");
    assert!(
        out.contains("estimated 3 block (6 minutes) backlog"),
        "{out}"
    );
    params_of::<wire::TxpoolStats>(&log);
    params_of::<wire::DaemonStatus>(&log);
}

/// A pool-stats reply missing a member is named, not rendered with a zero.
#[test]
fn a_pool_stats_reply_missing_a_member_is_refused_on_the_console() {
    let address = route_server(vec![
        (
            rpc::<wire::TxpoolStats>(),
            rpc_result(serde_json::json!({"count": 1})),
        ),
        (rpc::<wire::DaemonStatus>(), status_reply(100)),
    ]);
    let out = run(&["txpool", "stats"], Some(&address)).expect_err("refused");
    assert!(
        out.contains("malformed") || out.contains("missing field"),
        "{out}"
    );
}

/// A 64-character token that is not hex is not a block hash. Dropping the
/// hex check sends it to the daemon.
#[test]
fn a_non_hex_block_token_is_refused_before_a_request() {
    let (address, log) = route_server_recording(vec![]);
    let token = "z".repeat(64);
    let out = run(&["block", "show", &token], Some(&address)).expect_err("refused");
    assert!(out.contains("is not a block hash"), "{out}");
    assert!(log.lock().unwrap().is_empty(), "no request: {out}");
}

/// A key image is 64 hex characters. Anything else is refused at parse.
#[test]
fn chain_spent_refuses_a_token_that_is_not_a_key_image() {
    let (address, log) = route_server_recording(vec![]);
    let out = run(&["chain", "spent", "xyz"], Some(&address)).expect_err("refused");
    assert!(out.contains("is not a hash"), "{out}");
    assert!(log.lock().unwrap().is_empty(), "no request: {out}");
}

#[test]
fn chain_coinbase_sum_prints_the_emission_and_the_fee() {
    let (address, log) = route_server_recording(vec![(
        rpc::<wire::ChainCoinbaseSum>(),
        rpc_result(serde_json::json!({"emission": "1000000000", "fee": "2000000000"})),
    )]);
    let out = run(
        &["chain", "coinbase", "sum", "--from", "1", "--to", "3"],
        Some(&address),
    )
    .expect("renders");
    assert_eq!(out, "emission: 1.000000000 SKL\nfee: 2.000000000 SKL");
    let params = params_of::<wire::ChainCoinbaseSum>(&log);
    assert_eq!(params, serde_json::json!({"from": 1, "to": 3}));
}

/// `tx relay` names the id; an id the pool does not hold is said so.
#[test]
fn tx_relay_posts_the_id() {
    let hash = "ab".repeat(32);
    let (address, log) = route_server_recording(vec![(
        rpc::<wire::TxRelay>(),
        rpc_result(serde_json::json!([hash])),
    )]);
    let out = run(&["tx", "relay", &hash], Some(&address)).expect("renders");
    assert_eq!(out, format!("relayed {hash}"));
    assert_eq!(
        params_of::<wire::TxRelay>(&log),
        serde_json::json!({"id": [hash]})
    );

    let (address, _) = route_server_recording(vec![(
        rpc::<wire::TxRelay>(),
        rpc_result(serde_json::json!([{"missing": null}])),
    )]);
    let out = run(&["tx", "relay", &hash], Some(&address)).expect_err("refused");
    assert!(out.contains("holds no transaction"), "{out}");
}

#[test]
fn txpool_list_prints_each_entry_and_short_prints_ids() {
    let id = "cd".repeat(32);
    let list = rpc_result(serde_json::json!([{"id": id, "weight": 40, "fee": "1"}]));
    let address = route_server(vec![(rpc::<wire::TxpoolList>(), list.clone())]);
    let out = run(&["txpool", "list"], Some(&address)).expect("renders");
    assert_eq!(out, format!("{id}  40 weight  0.000000001 SKL"));
    let address = route_server(vec![(rpc::<wire::TxpoolList>(), list)]);
    let out = run(&["txpool", "list", "--short"], Some(&address)).expect("renders");
    assert_eq!(out, id);

    let address = route_server(vec![(
        rpc::<wire::TxpoolList>(),
        rpc_refusal(ErrorClass::OutsideTheGrant, "grant.outside"),
    )]);
    let out = run(&["txpool", "list"], Some(&address)).expect_err("refused");
    assert_eq!(out, "OutsideTheGrant grant.outside");
}

#[test]
fn txpool_flush_with_no_id_names_the_pool() {
    let (address, log) = route_server_recording(vec![(
        rpc::<wire::TxpoolFlush>(),
        rpc_result(serde_json::json!([])),
    )]);
    let out = run(&["txpool", "flush"], Some(&address)).expect("renders");
    assert!(out.contains("flushed the pool"), "{out}");
    // Every entry the caller may see: the optional `id` written `null`.
    assert_eq!(
        params_of::<wire::TxpoolFlush>(&log),
        serde_json::json!({"id": null})
    );
}

#[test]
fn ban_words_print_the_daemon_reply() {
    let list = rpc_result(serde_json::json!([
        {"host": "203.0.113.7", "duration": null, "permanent": true},
    ]));
    let show =
        rpc_result(serde_json::json!({"host": "203.0.113.7", "duration": 30, "permanent": false}));
    let (address, log) = route_server_recording(vec![
        (rpc::<wire::BanList>(), list),
        (rpc::<wire::BanAdd>(), rpc_result(serde_json::json!({}))),
        (rpc::<wire::BanRemove>(), rpc_result(serde_json::json!({}))),
        (rpc::<wire::BanShow>(), show),
    ]);
    let out = run(&["ban", "list"], Some(&address)).expect("renders");
    assert_eq!(out, "203.0.113.7  until lifted");
    let out = run(
        &["ban", "add", "203.0.113.7", "--duration", "30s"],
        Some(&address),
    )
    .expect("renders");
    assert_eq!(out, "banned 203.0.113.7 for 30 s");
    assert_eq!(
        params_of::<wire::BanAdd>(&log),
        serde_json::json!({"host": "203.0.113.7", "duration": 30})
    );
    let out = run(&["ban", "show", "203.0.113.7"], Some(&address)).expect("renders");
    assert_eq!(out, "203.0.113.7 is banned for 30 s");
    let out = run(&["ban", "remove", "203.0.113.7"], Some(&address)).expect("renders");
    assert!(out.contains("lifted"), "{out}");

    let address = route_server(vec![(
        rpc::<wire::BanShow>(),
        rpc_result(serde_json::Value::Null),
    )]);
    let out = run(&["ban", "show", "203.0.113.7"], Some(&address)).expect("renders");
    assert_eq!(out, "203.0.113.7 is not banned");
}

#[test]
fn option_show_prints_the_source_and_a_refusal_is_class_and_code() {
    let shown = rpc_result(serde_json::json!([
        {"name": "log-level", "source": "runtime", "runtime": true, "secret": false, "value": "info"},
        {"name": "rpc-key", "source": "file", "runtime": false, "secret": true, "assigned": true},
    ]));
    let address = route_server(vec![(rpc::<wire::OptionShow>(), shown)]);
    let out = run(&["option", "show"], Some(&address)).expect("renders");
    assert_eq!(
        out,
        "log-level  runtime  runtime  info\nrpc-key  file  startup  set"
    );

    let (address, log) = route_server_recording(vec![(
        rpc::<wire::OptionSet>(),
        rpc_refusal(ErrorClass::OutsideTheGrant, "grant.outside"),
    )]);
    let out = run(&["option", "set", "log-level", "info"], Some(&address)).expect_err("refused");
    assert_eq!(out, "OutsideTheGrant grant.outside");
    assert_eq!(
        params_of::<wire::OptionSet>(&log),
        serde_json::json!({"value": {"log-level": "info"}})
    );
}

#[test]
fn daemon_stop_is_the_stop_method() {
    let (address, log) = route_server_recording(vec![(
        rpc::<wire::DaemonStop>(),
        rpc_result(serde_json::json!({})),
    )]);
    let out = run(&["daemon", "stop"], Some(&address)).expect("renders");
    assert!(out.contains("stopping"), "{out}");
    params_of::<wire::DaemonStop>(&log);
}

/// The client's daemon-status fixture is this one.
#[test]
fn the_status_fixture_decodes_with_every_part_shown() {
    let status: shekyl_rpc_types::wire::daemon::DaemonStatus =
        serde_json::from_value(daemon_status_value(100)).expect("decodes");
    assert!(!status.started.is_withheld() && !status.connector.is_withheld());
    assert!(!status.txpool_private_count.is_withheld());
    serde_json::from_value::<shekyl_rpc_types::wire::daemon::DaemonStatus>(status_offline(100))
        .expect("the offline form decodes");
    let _ = (
        Size(0),
        Time(0),
        BlockHash::NULL,
        TxHash::from_bytes([0; 32]),
    );
}

// ── the Tor status ─────────────────────────────────────────────────────

/// The Tor oracle vectors of `kind` (`shekyl-rpc-types`'
/// `tests/vectors/rpc/tor/`), each spliced into this fixture's reply.
fn tor_vectors(kind: &str) -> Vec<(String, serde_json::Value)> {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../shekyl-rpc-types/tests/vectors/rpc/tor")
        .join(kind);
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| entry.expect("an entry").path())
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let tor: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).expect("readable"))
                    .expect("JSON");
            let mut value = daemon_status_value(100);
            for key in [
                "posture",
                "origination",
                "sync_connector",
                "tor_quiet",
                "tor",
            ] {
                value[key] = tor[key].clone();
            }
            (path.display().to_string(), value)
        })
        .collect()
}

/// **The Tor vectors read through this client as the daemon would send
/// them**: over HTTP, in the JSON-RPC envelope, through the reply checks
/// and the reply type (Rick, 2026-11-12). A known state reads; a value this
/// build does not know reads, is reported unknown and is never
/// address-hiding; a one-key object with no key or two is refused. Fails if
/// the client refuses a newer daemon's keyword, losing the whole reply.
#[test]
fn the_tor_vectors_read_through_the_client() {
    let read = |value: serde_json::Value| {
        let address = route_server(vec![(rpc::<wire::DaemonStatus>(), rpc_result(value))]);
        let daemon = DaemonClient::new(
            &format!("http://{address}"),
            None,
            None,
            shekyl_rpc_types::Network::Mainnet,
        )
        .expect("a client");
        daemon.daemon_status()
    };
    let known = tor_vectors("known");
    assert_eq!(known.len(), 27);
    for (name, value) in known {
        let status = read(value).unwrap_or_else(|error| panic!("{name}: {error}"));
        let tor = status.tor_status().expect("Status is shown");
        assert!(!tor.has_unknown(), "{name}: {tor:?}");
    }
    let unknown = tor_vectors("unknown");
    assert_eq!(unknown.len(), 14);
    for (name, value) in unknown {
        let status =
            read(value).unwrap_or_else(|error| panic!("{name}: the reply is lost: {error}"));
        let tor = status.tor_status().expect("Status is shown");
        assert!(tor.has_unknown(), "{name}: {tor:?}");
        assert!(
            !tor.own_tx_hides_address(),
            "{name}: read as address-hiding"
        );
    }
    let refused = tor_vectors("refused");
    assert_eq!(refused.len(), 4);
    for (name, value) in refused {
        assert!(read(value).is_err(), "{name}: read");
    }
}

/// **`status` says what the daemon's log says**: the Tor sentence is the
/// one renderer's, over the reply's Tor fields. Fails if the console
/// writes a Tor sentence of its own, or drops it.
#[test]
fn the_status_line_says_the_tor_status_in_the_renderers_words() {
    let address = route_server(vec![
        (rpc::<wire::DaemonStatus>(), status_reply(100)),
        (
            rpc::<wire::MineStatus>(),
            mining_reply(false, speed(0, 0), None),
        ),
    ]);
    let out = run(&["daemon", "status"], Some(&address)).expect("renders");
    let status: shekyl_rpc_types::wire::daemon::DaemonStatus =
        serde_json::from_value(daemon_status_value(100)).expect("the fixture decodes");
    let said = shekyl_tor_status::render(&status.tor_status().expect("shown"), None);
    assert!(!said.is_empty());
    assert!(out.ends_with(&format!("\n{said}")), "{out}");
}

/// A managed Tor held because its data directory is short of space.
fn short_of_space(grant: &[&str]) -> serde_json::Value {
    let mut value = daemon_status_value(100);
    value["grant"] = serde_json::json!(grant);
    value["posture"] = serde_json::json!({"tor": "managed", "clearnet": "off"});
    value["origination"] = serde_json::json!("connecting");
    value["tor"] = serde_json::json!({
        "state": "waiting", "cause": {"unusable": {"exhausted": {"free": 0, "needed": 35000000}}},
        "age": 9, "respawn_count": 0, "progress": null, "flagged": false, "fix": [],
        "onion": null, "bootstrap": null, "carriage": "gone"
    });
    value
}

/// **The data directory is named only for a connection holding `config`,
/// and printed without control characters** (IG-Q97; Rick, 2026-11-12: it
/// is a string the daemon supplies). Without `config` the console does not
/// ask for it and the sentence says "Tor's data directory". Fails if the
/// path is asked for or named without the grant, or if an escape sequence
/// in it reaches the terminal.
#[test]
fn the_data_directory_is_named_only_with_config_and_printed_without_control_characters() {
    let all = [
        "health",
        "status",
        "chain",
        "pool",
        "peers",
        "submit",
        "mining-work",
        "mining-control",
        "bans",
        "node",
        "config",
    ];
    let rows = serde_json::json!([{
        "name": "data-dir", "source": "file", "runtime": false, "secret": false,
        "value": "/var/lib/shek\u{1b}[2Jyl\u{7}"
    }]);
    let (address, log) = route_server_recording(vec![
        (
            rpc::<wire::DaemonStatus>(),
            rpc_result(short_of_space(&all)),
        ),
        (
            rpc::<wire::MineStatus>(),
            mining_reply(false, speed(0, 0), None),
        ),
        (rpc::<wire::OptionShow>(), rpc_result(rows)),
    ]);
    let out = run(&["daemon", "status"], Some(&address)).expect("renders");
    assert!(out.contains("/var/lib/shek[2Jyl"), "{out}");
    assert!(!out.contains('\u{1b}') && !out.contains('\u{7}'), "{out:?}");
    assert!(
        log.lock()
            .unwrap()
            .iter()
            .any(|(_, body)| method_of(body).as_deref()
                == Some(<wire::OptionShow as RpcMethod>::NAME)),
        "the path was asked for"
    );

    let (address, log) = route_server_recording(vec![
        (
            rpc::<wire::DaemonStatus>(),
            rpc_result(short_of_space(&["health", "status", "mining-control"])),
        ),
        (
            rpc::<wire::MineStatus>(),
            mining_reply(false, speed(0, 0), None),
        ),
    ]);
    let out = run(&["daemon", "status"], Some(&address)).expect("renders");
    assert!(
        out.contains("Tor's data directory has 0 bytes free"),
        "{out}"
    );
    assert!(!out.contains("/var/lib"), "{out}");
    assert!(
        !log.lock()
            .unwrap()
            .iter()
            .any(|(_, body)| method_of(body).as_deref()
                == Some(<wire::OptionShow as RpcMethod>::NAME)),
        "a connection without `config` asked for the path"
    );
}

/// Control characters are removed; everything else is kept.
#[test]
fn printable_removes_control_characters_only() {
    assert_eq!(
        super::status::printable("/a\u{1b}[31mb\nc\td\u{7f}é"),
        "/a[31mbcdé"
    );
}
