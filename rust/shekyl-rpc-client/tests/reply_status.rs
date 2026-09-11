// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A non-OK reply status is a refusal, whatever the rest of the reply holds.
//!
//! **This is the trap the daemon side of RK-5b was changed to avoid, caught
//! on the side that was not changed.** The C++ `CHECK_CORE_READY()` answered
//! `status = BUSY` with a *default-constructed* `block_header`, and
//! `get_hardfork_version` read `major_version` straight through — reporting
//! fork version 0 for a syncing node. The daemon in this tree now refuses
//! with `CORE_BUSY` instead, which arrives as a JSON-RPC error.
//!
//! That fixed the producer. It did not fix this: the wallet talks to whatever
//! daemon it is pointed at, including an older build that still answers
//! `BUSY` with zeros. **Fixing the producer and trusting every peer to be the
//! fixed producer is not a fix**, and a review round found this method still
//! reading the header without looking at the status beside it.
//!
//! The double implements only `post`, because that is the trait's one
//! required method — everything else is a default. No async runtime: the
//! futures here never yield, so a no-op waker and a poll loop are enough, and
//! this crate's dev-dependencies stay the three the wire contract needs.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use shekyl_rpc_client::{Rpc, RpcError};

/// Poll a future that never yields to completion.
fn block_on<F: Future>(future: F) -> F::Output {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    // SAFETY: every vtable entry is a no-op over a null data pointer, which
    // is the standard inert waker; nothing here is woken because nothing
    // here yields.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(out) = Pin::new(&mut future).poll(&mut cx) {
            return out;
        }
    }
}

/// A daemon that answers every JSON-RPC call with one canned `result`.
#[derive(Clone)]
struct CannedDaemon(String);

impl Rpc for CannedDaemon {
    fn post(
        &self,
        _route: &str,
        _body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        let body = format!(r#"{{"jsonrpc":"2.0","id":"0","result":{}}}"#, self.0);
        async move { Ok(body.into_bytes()) }
    }
}

/// The daemon's own captured reply, as the fixture.
///
/// Hand-writing the JSON here failed on the first attempt — it described a
/// document the daemon cannot produce — which is the case for building a
/// fixture through the wire type rather than by hand. This goes one better
/// and uses the **oracle capture**: the same bytes the daemon's parity suite
/// reads, so an OK case that stops resembling a real reply fails here too.
const CAPTURED_OK: &str =
    include_str!("../../shekyl-rpc-types/tests/vectors/rpc/get_last_block_header_v1.json");

fn reply_with_status(status: &str) -> String {
    let mut reply: shekyl_rpc_types::GetLastBlockHeaderResponse =
        serde_json::from_str(CAPTURED_OK).expect("the captured reply parses");
    reply.status = shekyl_rpc_types::RpcStatus(status.to_owned());
    // The C++ shape: BUSY beside a header nobody filled in.
    if status != shekyl_rpc_types::RpcStatus::OK {
        reply.block_header.major_version = 0;
    }
    serde_json::to_string(&reply).expect("the wire type serializes")
}

/// A `BUSY` reply carrying a zero-filled header is refused, not read.
#[test]
fn a_busy_last_block_header_is_not_read_as_fork_version_zero() {
    let busy = CannedDaemon(reply_with_status(shekyl_rpc_types::RpcStatus::BUSY));
    let out = block_on(busy.get_hardfork_version());
    assert!(
        matches!(&out, Err(RpcError::InvalidNode(reason)) if reason.contains("BUSY")),
        "a BUSY node must be refused, not read as version 0: {out:?}"
    );

    // The OK path still answers, so this is not a test that only knows how to
    // refuse — and the version it answers with is the capture's own.
    let expected: shekyl_rpc_types::GetLastBlockHeaderResponse =
        serde_json::from_str(CAPTURED_OK).expect("the captured reply parses");
    let ok = CannedDaemon(reply_with_status(shekyl_rpc_types::RpcStatus::OK));
    assert_eq!(
        block_on(ok.get_hardfork_version()).expect("an OK reply"),
        expected.block_header.major_version
    );
}
