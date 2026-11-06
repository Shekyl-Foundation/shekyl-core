// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `Rpc::json_rpc_call_or_refusal` reads the daemon's `error` member as a
//! typed answer: the method whose refusals are part of its contract
//! (`request_archival_shard`'s open / unavailable / absent codes,
//! `SHARD_VIEW_FETCH.md` `SV-D5`, `SV-D9`) gets the code to branch on
//! rather than `json_rpc_call`'s "response wasn't the expected json".
//!
//! Same no-runtime shape as `reply_status.rs`: the double implements only
//! `post`, and the futures never yield.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use shekyl_rpc_client::{JsonRpcRefusal, Rpc, RpcError};

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

/// A daemon that answers every JSON-RPC call with one canned body.
#[derive(Clone)]
struct CannedDaemon(&'static str);

impl Rpc for CannedDaemon {
    fn post(
        &self,
        _route: &str,
        _body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        let body = self.0.as_bytes().to_vec();
        async move { Ok(body) }
    }
}

#[derive(Debug, PartialEq, serde::Deserialize)]
struct Answer {
    shard_id: u64,
}

#[test]
fn a_result_is_the_typed_answer() {
    let daemon = CannedDaemon(r#"{"jsonrpc":"2.0","id":0,"result":{"shard_id":7}}"#);
    let got = block_on(daemon.json_rpc_call_or_refusal::<Answer>("request_archival_shard", None))
        .expect("transport ok");
    assert_eq!(got, Ok(Answer { shard_id: 7 }));
}

#[test]
fn an_error_member_is_the_typed_refusal_with_its_code() {
    let daemon = CannedDaemon(
        r#"{"jsonrpc":"2.0","id":0,"error":{"code":-24,"message":"shard 7 is still open"}}"#,
    );
    let got = block_on(daemon.json_rpc_call_or_refusal::<Answer>("request_archival_shard", None))
        .expect("transport ok");
    assert_eq!(
        got,
        Err(JsonRpcRefusal {
            code: -24,
            message: "shard 7 is still open".to_owned(),
        })
    );
}

#[test]
fn neither_or_both_members_is_a_protocol_fault_not_an_answer() {
    for body in [
        r#"{"jsonrpc":"2.0","id":0}"#,
        r#"{"jsonrpc":"2.0","id":0,"result":{"shard_id":1},"error":{"code":-1,"message":"x"}}"#,
    ] {
        let daemon = CannedDaemon(body);
        let got =
            block_on(daemon.json_rpc_call_or_refusal::<Answer>("request_archival_shard", None));
        assert!(
            matches!(got, Err(RpcError::InvalidNode(_))),
            "{body}: {got:?}"
        );
    }
}

/// The old entry point's behaviour on a refusal is unchanged: it is a
/// protocol fault there, because its callers have no refusal to read.
#[test]
fn json_rpc_call_still_treats_a_refusal_as_invalid_node() {
    let daemon = CannedDaemon(r#"{"jsonrpc":"2.0","id":0,"error":{"code":-24,"message":"open"}}"#);
    let got = block_on(daemon.json_rpc_call::<Answer>("request_archival_shard", None));
    assert!(matches!(got, Err(RpcError::InvalidNode(_))), "{got:?}");
}
