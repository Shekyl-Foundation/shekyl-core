// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `Rpc::call` and `Rpc::call_or_refusal` against canned daemon bodies
//! (`RPC_WIRE.md` RW-Q2, RW-Q3, RW-Q7).
//!
//! The double implements only `post` and records what it was sent; the
//! futures never yield, so no runtime is needed.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use shekyl_rpc_client::{wire, DaemonFault, ErrorClass, Rpc, RpcError};
use shekyl_rpc_types::kinds::NoParams;

fn block_on<F: Future>(future: F) -> F::Output {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    // SAFETY: a no-op vtable over a null data pointer is the standard inert
    // waker; nothing here yields, so nothing is woken.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(out) = Pin::new(&mut future).poll(&mut cx) {
            return out;
        }
    }
}

/// A daemon that answers every call with one canned body, and keeps what
/// it was sent.
#[derive(Clone)]
struct Canned {
    body: String,
    sent: Arc<Mutex<Vec<(String, Value)>>>,
}

impl Canned {
    fn new(body: &Value) -> Self {
        Self {
            body: body.to_string(),
            sent: Arc::default(),
        }
    }

    fn last(&self) -> (String, Value) {
        self.sent
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a call was sent")
    }
}

impl Rpc for Canned {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        self.sent.lock().unwrap().push((
            route.to_owned(),
            serde_json::from_slice(&body).expect("the client sends JSON"),
        ));
        let reply = self.body.clone().into_bytes();
        async move { Ok(reply) }
    }
}

fn result(result: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 0, "result": result})
}

fn error(code: i64, data: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 0, "error": {"code": code, "message": "english", "data": data}})
}

/// A call is strict JSON-RPC 2.0 on `/json_rpc`: the method's name from its
/// type, and named params (RW-Q2). The route is relative — the transport
/// appends it to its base URL as `{url}/{route}` — so it carries no leading
/// slash, and joined it is the daemon's one path. Red edit: post to another
/// route, or post `JSON_RPC_PATH` itself (the wire would carry
/// `//json_rpc`).
#[test]
fn a_call_is_json_rpc_on_one_route_with_named_params() {
    let daemon = Canned::new(&result(&json!({
        "height": 9, "hash": "ab".repeat(32), "writer": {"live": null}
    })));
    let count = block_on(daemon.get_height()).expect("a tip");
    assert_eq!(count.to_raw(), 10, "the count is the tip's height plus one");
    let (route, sent) = daemon.last();
    assert_eq!(route, "json_rpc");
    assert_eq!(
        format!("/{route}"),
        shekyl_rpc_types::endpoint::JSON_RPC_PATH,
        "joined to a base URL, the route is the daemon's path"
    );
    assert_eq!(sent["jsonrpc"], "2.0");
    assert_eq!(sent["method"], "chain_height");
    assert_eq!(sent["params"], json!({}));
    assert!(!sent["id"].is_null());
}

/// A refusal keeps its class and its dotted code, and is classified by the
/// class. Red edit: read every error as `InvalidNode`.
#[test]
fn a_refusal_is_typed_by_its_class_and_code() {
    let daemon = Canned::new(&error(
        ErrorClass::NotReady.code(),
        &json!({"code": "daemon.unready", "parameter": {}, "message": "english"}),
    ));
    let out = block_on(daemon.get_block_hash(0));
    let Err(RpcError::Refused(refusal)) = &out else {
        panic!("a typed refusal: {out:?}");
    };
    assert_eq!(refusal.class, ErrorClass::NotReady);
    assert_eq!(refusal.diagnostic.code, "daemon.unready");
    assert_eq!(out.unwrap_err().fault(), DaemonFault::Unreachable);

    let shard = Canned::new(&error(
        ErrorClass::RefusedByMethod.code(),
        &json!({"code": "shard.open", "parameter": {"id": "7"}, "message": "english"}),
    ));
    let answer = block_on(
        shard.call_or_refusal::<wire::ShardFetch>(wire::archival::ShardId {
            id: shekyl_rpc_types::kinds::Integer(7),
        }),
    )
    .expect("a refusal is an answer");
    let refusal = answer.expect_err("refused");
    assert_eq!(refusal.diagnostic.code, "shard.open");
    assert_eq!(refusal.diagnostic.parameter["id"], "7");
}

/// A name the daemon does not serve is its own error, never a refusal.
#[test]
fn method_not_found_is_no_such_method() {
    let daemon = Canned::new(&json!({"jsonrpc": "2.0", "id": 0, "error": {
        "code": -32601, "message": "Method not found"
    }}));
    let out = block_on(daemon.call::<wire::Fee>(NoParams));
    assert!(matches!(out, Err(RpcError::NoSuchMethod("fee"))), "{out:?}");
}

/// A body with both members, neither, a refusal this build cannot read, or
/// a reply of another shape is a protocol fault, not an answer.
#[test]
fn a_body_that_is_neither_one_reply_nor_one_refusal_is_a_protocol_fault() {
    for body in [
        json!({"jsonrpc": "2.0", "id": 0}),
        json!({"jsonrpc": "2.0", "id": 0, "result": {}, "error": {"code": -32602, "message": "x"}}),
        json!({"jsonrpc": "2.0", "id": 0, "error": {"code": -24, "message": "a 3.x code"}}),
        // A 3.x fee reply: positional tiers and a status.
        result(&json!({"status": "OK", "fees": [1, 2, 3]})),
    ] {
        let out = block_on(Canned::new(&body).call::<wire::Fee>(NoParams));
        assert!(
            matches!(out, Err(RpcError::InvalidNode(_))),
            "{body}: {out:?}"
        );
    }
}

/// The fee read names its tiers, each an amount per unit of weight (IG-Q52).
#[test]
fn the_fee_read_names_its_tiers() {
    let daemon = Canned::new(&result(&json!({
        "economy": "10", "standard": "20", "high": "40"
    })));
    let rate = |priority| {
        block_on(daemon.get_fee_rate(priority))
            .unwrap()
            .per_weight()
    };
    assert_eq!(rate(shekyl_rpc_client::FeePriority::Unimportant), 10);
    assert_eq!(rate(shekyl_rpc_client::FeePriority::Normal), 20);
    assert_eq!(rate(shekyl_rpc_client::FeePriority::Priority), 40);
}

/// A `result` of `null` is an answer: `ban_show` for a host not banned.
#[test]
fn a_null_result_is_an_answer() {
    let daemon = Canned::new(&result(&Value::Null));
    let ban = block_on(daemon.call::<wire::BanShow>(wire::node::BanHost {
        host: shekyl_rpc_types::kinds::Text("192.0.2.1".to_owned()),
    }))
    .expect("an answer");
    assert_eq!(ban.0, None);
}

/// A block header as a daemon writes it, with `pow` when `pow` is given.
fn header(pow: Option<&str>) -> Value {
    let mut header = json!({
        "version_major": 3, "version_minor": 3, "time": 1_700_000_000,
        "parent": "11".repeat(32), "nonce": 7, "orphan": false, "height": 9,
        "depth": 0, "hash": "22".repeat(32), "difficulty": "0x1",
        "difficulty_cumulative": "0xa", "reward": "1000", "weight": 400,
        "weight_longterm": 400, "tx_count": 0, "coinbase": "33".repeat(32),
        "curve_root": "44".repeat(32), "attestation_root": "55".repeat(32),
    });
    if let Some(pow) = pow {
        header["pow"] = json!(pow);
    }
    header
}

fn tip(pow: bool) -> shekyl_rpc_types::wire::block::HeaderSelect {
    use shekyl_rpc_types::wire::block::{BlockSelect, HeaderSelect};
    use shekyl_rpc_types::wire::shared::Selector;
    HeaderSelect(BlockSelect {
        select: Selector::Tip,
        pow,
        prune: None,
    })
}

/// A reply carries the fields the request's switches selected and no
/// other (RW-Q4, 4.1): `pow` asked for and missing, or present though not
/// asked for, is the daemon answering a request this client did not send,
/// refused before the decode. Red edit: skip `conforms_presence` in the client.
#[test]
fn a_reply_holds_exactly_the_fields_the_request_selected() {
    let call = |reply: Value, pow: bool| {
        block_on(Canned::new(&result(&reply)).call_or_refusal::<wire::BlockHeaderShow>(tip(pow)))
    };
    let pow = "66".repeat(32);
    assert!(matches!(call(header(Some(&pow)), true), Ok(Ok(_))));
    assert!(matches!(call(header(None), false), Ok(Ok(_))));
    for (reply, asked, why) in [
        (header(None), true, "missing"),
        (header(Some(&pow)), false, "present"),
    ] {
        match call(reply, asked) {
            Err(RpcError::InvalidNode(message)) => {
                assert!(
                    message.contains("`pow`") && message.contains(why),
                    "{message}"
                );
            }
            other => panic!("pow {why} with the switch {asked}: {other:?}"),
        }
    }

    // The same field inside a list slot. A header without `pow` is still a
    // header, not the slot's missing state, so the switch is still enforced.
    let list = |pow: bool| {
        use shekyl_rpc_types::kinds::Height;
        use shekyl_rpc_types::wire::block::{HeaderRange, HeaderRangeSelect};
        block_on(
            Canned::new(&result(&json!([header(None)]))).call_or_refusal::<wire::BlockHeaderList>(
                HeaderRange {
                    select: HeaderRangeSelect::Range {
                        from: Height(1),
                        to: Height(1),
                    },
                    pow,
                },
            ),
        )
    };
    match list(true) {
        Err(RpcError::InvalidNode(message)) => {
            assert!(
                message.contains("`pow`") && message.contains("missing"),
                "{message}"
            );
        }
        other => panic!("a listed header without pow: {other:?}"),
    }
    assert!(
        matches!(list(false), Ok(Ok(_))),
        "an unasked pow is absent from the header"
    );
}
