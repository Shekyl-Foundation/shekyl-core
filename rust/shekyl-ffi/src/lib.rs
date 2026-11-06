//! FFI bridge between the C++ core and Rust modules.
//!
//! Exposes Rust functionality to C++ through a C-compatible ABI.
//! All public functions use `extern "C"` with `#[no_mangle]`.

// FFI boundary code has structural patterns that trigger clippy lints:
// - extern "C" functions take raw pointers (not_unsafe_ptr_arg_deref)
// - Mathematical variable names follow cryptographic notation (non_snake_case)
//
// The cast lints are deliberately NOT allowed here (SA-6 untrusted-cast
// ruling): this crate sits directly on the C++ trust boundary, which is
// exactly where the workspace `cast_possible_truncation`/`cast_sign_loss`
// denials earn their keep. A crate-root allow silently overrode the
// workspace manifest deny and turned every site-level `#[allow(...)]` in
// the crate into dead documentation; lossy casts now carry a site-level
// allow with a rationale, or use `try_from`.
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    clippy::missing_safety_doc,
    clippy::manual_let_else,
    clippy::ptr_as_ptr,
    non_snake_case
)]

// ---------------------------------------------------------------------------
// 64-bit-only gate — Chore #3, v3.1.0-alpha.5 (Tripwire B —
// structural-not-observable).
//
// This tripwire is DUPLICATED BY DESIGN. In the current workspace shape,
// `shekyl-ffi` always depends (transitively) on `shekyl-crypto-pq` whose
// Tripwire A would already fire; this gate is NOT expected to be the one
// that "catches" a 32-bit build in practice. Its job is different:
//
//   1. Preserve the refusal under a future refactor that might split
//      the FFI boundary from the PQC crate.
//   2. Make the refusal legible at the FFI seam, where downstream C++
//      consumers discover what Rust will and will not link against.
//
// Do NOT delete this gate on the grounds that it "never fires". Its
// value is structural, not observable. See Tripwire A in
// rust/shekyl-crypto-pq/src/lib.rs for the primary CT argument; Tripwire C
// in rust/shekyl-tx-builder/src/lib.rs for the fips204 transaction-signing
// gate; and Tripwire D at the top of CMakeLists.txt for the C++-side
// configure-time refusal.
// ---------------------------------------------------------------------------
#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "shekyl-ffi refuses to build on non-64-bit targets. This is \
     Tripwire B (structural-not-observable): duplicated by design to \
     preserve the 64-bit refusal at the FFI seam under future refactors \
     that might split this crate from shekyl-crypto-pq. See Tripwire A \
     in shekyl-crypto-pq for the primary ML-KEM/ML-DSA constant-time \
     argument; see docs/CHANGELOG.md 'Retired 32-bit build targets' \
     before attempting to revert this gate."
);

// LWMA-1 difficulty-adjustment FFI export. Wraps `shekyl_difficulty::
// lwma1_next` in a C-ABI surface using the `ShekylU128` two-u64
// decomposition per `DAA_LWMA1.md` §6.1. Consumed by the Phase 2
// cross-check harness (`tests/difficulty/lwma1_cross_check.cpp`) and
// (Phase 3 onward) by the daemon's difficulty path.
pub mod difficulty_ffi;

// DRS-P0d layout-independent logical state digest v0. C++ walks
// production LMDB; the hasher is shekyl-chain-store.
pub mod chain_digest_ffi;

// RandomX v2 light-cache PoW verification FFI. Wraps `shekyl_pow_randomx`
// (`compute_hash` + `CacheStore`) in a C-ABI surface: the consensus PoW
// hash (`shekyl_pow_randomx_v2_hash`) for the C++ parity gates. The
// daemon's PoW is the Rust ingest's, and the seed-epoch schedule is
// `shekyl_difficulty::seed_epoch`'s.
pub mod pow_randomx_ffi;

// Curve-tree replica FFI: an ephemeral `shekyl_curve_tree::CurveTreeClient`
// the C++ test generator (`tests/core_tests/chaingen.cpp`) drives to compute
// the `curve_tree_root` every generated block header must carry, now that
// the admission-time header-root check (CEN-B5) runs on every nettype.
// Test-generator surface; the daemon does not call it.
pub mod curve_tree_replica_ffi;

// tx_extra PQC field shape rule (GENESIS_TX_WIRE_FORMAT.md §9.6a, CEN-I19):
// exactly one 0x06 of 1120·n and one 0x07 of 32·n bytes when a transaction
// has n > 0 outputs, neither when n == 0. The rule lives in shekyl-wire; the
// daemon's admission path hands over its own parse's field lengths.
pub mod tx_extra_ffi;

// tx_extra codec (TX_EXTRA_RUST_CUTOVER.md §3): shekyl-wire parses and
// builds tx_extra; the daemon transports. Field/pubkey/leaf reads, the
// bytes-taking I19 form, and the coinbase writer — the C++ parser's
// replacement, one call per site.
pub mod tx_extra_codec_ffi;

// The transaction id (ARCHIVAL_SHARD_COUNT_CUTOVER.md SHT-Q2): shekyl-wire
// mixes — hashing the segments and measuring the archival length the id
// binds — and the daemon's calculate_transaction_hash serializes and cuts.
// One mixer; the C++ one is deleted.
pub mod txid_ffi;

// Archival serve-credit verification FFI (`ARCHIVAL_RETENTION_GATE2.md` §10).
pub mod archival_ffi;

// General CT cleartext-balance verification FFI (`GENESIS_TX_WIRE_FORMAT.md` §2.3).
pub mod ct_balance_ffi;

// Single-Rust-image contract: re-export shekyl-logging so its
// `#[no_mangle]` C exports (`shekyl_log_init_*`, `shekyl_log_emit`,
// `shekyl_log_set_categories`, …) are compiled into
// `libshekyl_ffi.a`. Every wallet-side binary then links exactly one
// Rust archive whose single `tracing-core` GLOBAL_DISPATCH is shared by
// the C++-installed subscriber and every `tracing::*` call site in this
// crate graph (engine-file, fcmp, …). Without this, those events
// dispatch into a dispatcher no subscriber is installed on and are
// silently dropped. See V3_WALLET_DECISION_LOG.md (single-image
// contract).
pub use shekyl_logging;

// The RPC server (`shekyl-daemon-rpc`) is not re-exported: it imports C++
// symbols from `rpc`, and a member of this archive can be pulled into any
// C++ binary by a shared monomorphization (DAEMON_CONFIG_CUTOVER.md
// DC-F26, corrected by DC-F30).

// Legacy monofile FFI surface (split from the former body of this file).
// Domain modules keep #[no_mangle] symbols; this root only wires and re-exports.
mod economics_ffi;
mod legacy_core;
mod legacy_curve_tree;
mod legacy_fcmp;
mod legacy_frost;
mod legacy_tx;
mod legacy_types;
mod legacy_util;

#[allow(unused_imports)]
pub use economics_ffi::*;
#[allow(unused_imports)]
pub use legacy_core::*;
#[allow(unused_imports)]
pub use legacy_curve_tree::*;
#[allow(unused_imports)]
pub use legacy_fcmp::*;
#[allow(unused_imports)]
pub use legacy_frost::*;
#[allow(unused_imports)]
pub use legacy_tx::*;
#[allow(unused_imports)]
pub use legacy_types::*;
#[allow(unused_imports)]
pub use legacy_util::*;

#[cfg(all(test, feature = "multisig"))]
pub(crate) use legacy_fcmp::parse_prove_witness;

#[cfg(test)]
#[path = "legacy_tests.rs"]
mod tests;
