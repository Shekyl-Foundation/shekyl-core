// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon binary's library half (`DAEMON_CONFIG_CUTOVER.md` DC-Q19).
//!
//! `shekyld` is where the archival fetch scheduler and the shard-view
//! implementor meet: `shekyl-archival-fetch-sched` reaches the fetch client,
//! `shekyl-daemon-rpc` may not (`check_p_fetch_dep_cut.py`). The process
//! composition root is `shekyl-daemon`, which builds `shekyl-node`'s `Node`
//! (N1). [`shard_view`] implements `ShardViewFacts` over a `ViewDesk` and is
//! handed to the RPC as that trait object. Production `ServerConfig` still
//! defaults to `SkeletonAbsent` until the flip routes the RPC onto the
//! node's store: until then the Rust store is not the chain the RPC
//! describes.
//!
//! The binary (`main.rs`) depends on this crate's dependencies for their C
//! exports too: the remnant's archives call `shekyl_*` in `shekyl-ffi`,
//! `shekyl_log_*` in `shekyl-logging`, `shekyl_daemon_rpc_*` in
//! `shekyl-daemon-rpc` and `shekyl_daemon_request_stop` in `shekyl-daemon`.
//! One cargo dependency graph gives the binary one `tracing-core`
//! dispatcher; the staged binary's `nm` gate asserts exactly one
//! `GLOBAL_DISPATCH`.

#![deny(unsafe_code)]

pub mod shard_view;
