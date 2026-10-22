//! Single Rust link image for the `shekyld` binary.
//!
//! This crate contains no logic. It exists so that the daemon links
//! exactly **one** Rust static archive (`libshekyl_daemon_image.a`)
//! carrying the union of the two Rust surfaces the daemon needs:
//!
//! - `shekyl-ffi` — crypto / wallet / consensus / logging C exports
//!   (`shekyl_*`, `shekyl_log_*`), linked by the C++ static libraries
//!   (`cryptonote_core`, epee, …);
//! - `shekyl-daemon-rpc` — the Axum daemon RPC server
//!   (`shekyl_daemon_rpc_*`).
//!
//! Why one archive matters: each Rust staticlib embeds its own copy of
//! `tracing-core`'s `GLOBAL_DISPATCH`. If the daemon linked the two
//! surfaces as separate archives, the subscriber installed through one
//! image's `shekyl_log_init_*` would never see events dispatched inside
//! the other image — they would be silently dropped. Building both
//! crates into one image gives Cargo a unified dependency graph and the
//! binary a single dispatcher; the post-link `nm` gate in
//! `src/daemon/CMakeLists.txt` asserts exactly one `GLOBAL_DISPATCH`
//! definition. See `docs/V3_WALLET_DECISION_LOG.md` (single-image
//! contract).
//!
//! The re-exports below force both crates into the archive; their
//! `#[no_mangle]` exports survive into the staticlib (verified by the
//! same mechanism that puts `shekyl_log_*` into `libshekyl_ffi.a`).
//!
//! This crate is also where the archival fetch scheduler and the shard-view
//! implementor meet: `shekyl-archival-fetch-sched` reaches the fetch client,
//! `shekyl-daemon-rpc` may not (`check_p_fetch_dep_cut.py`). The process
//! composition root is `shekyl-daemon`, which builds `shekyl-node`'s `Node`
//! (N1). [`shard_view`] implements `ShardViewFacts` over a `ViewDesk` and is
//! handed to the RPC as that trait object. Production `ServerConfig` still
//! defaults to `SkeletonAbsent` until the flip routes the RPC onto the
//! node's store: until then the Rust store is not the chain the RPC describes.

pub mod shard_view;

/// The daemon's entry, `shekyl_daemon_main`, and the snapshot gate
/// (`DAEMON_CONFIG_CUTOVER.md` §2.2): their `#[no_mangle]` exports survive
/// into this archive like `shekyl-ffi`'s.
pub use shekyl_daemon;

pub use shekyl_archival_fetch_sched;
pub use shekyl_daemon_rpc;
pub use shekyl_ffi;
