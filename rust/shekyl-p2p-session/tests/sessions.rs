// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The session layer, driven from the far side of the wire and the near
//! side of the owners (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §7). Each module
//! is one of those drives: the handshake both ways, the nonces, timed
//! sync, the dispatch table, the handle, and the board.

mod common;

#[path = "sessions/board.rs"]
mod board;
#[path = "sessions/dispatch.rs"]
mod dispatch;
#[path = "sessions/handle.rs"]
mod handle;
#[path = "sessions/inbound.rs"]
mod inbound;
#[path = "sessions/nonces.rs"]
mod nonces;
#[path = "sessions/outbound.rs"]
mod outbound;
#[path = "sessions/timed_sync.rs"]
mod timed_sync;

macro_rules! session_test {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            $crate::multi().block_on(async { $body.await });
        }
    };
}
pub(crate) use session_test;

/// The runtime each session test blocks on.
pub(crate) fn multi() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}
