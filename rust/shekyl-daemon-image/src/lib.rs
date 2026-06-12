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

pub use shekyl_daemon_rpc;
pub use shekyl_ffi;
