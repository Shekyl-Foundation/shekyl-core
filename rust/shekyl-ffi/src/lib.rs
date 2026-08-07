//! FFI bridge between the C++ core and Rust modules.
//!
//! Exposes Rust functionality to C++ through a C-compatible ABI.
//! All public functions use `extern "C"` with `#[no_mangle]`.

// FFI boundary code has structural patterns that trigger clippy lints:
// - extern "C" functions take raw pointers (not_unsafe_ptr_arg_deref)
// - C-compatible APIs require specific cast patterns
// - Mathematical variable names follow cryptographic notation (non_snake_case)
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    clippy::missing_safety_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
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

// Stabilized v1 account-derivation FFI surface. See `account_ffi.rs` for
// per-function docs and the fail-closed / out-pointer / pinned-size
// disciplines. The legacy `shekyl_kem_keypair_generate` and
// `shekyl_seed_derive_{spend,view,ml_kem}` FFIs in this file remain for
// the duration of the wallet-account-rewire slice; they are replaced by
// `shekyl_account_*` callers and removed once C++ no longer references
// them.
pub mod account_ffi;

// Engine-file envelope (WALLET_FILE_FORMAT_V1) FFI surface. Six entry points
// matching `shekyl_crypto_pq::wallet_envelope`:
//   - shekyl_wallet_keys_inspect    (AAD-only header view)
//   - shekyl_wallet_keys_seal       (create .wallet.keys)
//   - shekyl_wallet_keys_open       (decrypt .wallet.keys)
//   - shekyl_wallet_keys_rewrap_password (rotate wrapping password)
//   - shekyl_engine_state_seal      (seal .wallet)
//   - shekyl_engine_state_open      (open .wallet)
// Each function follows the two-call sizing + zeroize-on-failure + narrow
// error-code discipline documented in the module header. Consumed by
// wallet2.cpp in the commit 2 slice.
pub mod wallet_envelope_ffi;

// Opaque high-level `ShekylWallet` handle wrapping `WalletFile` and
// the loaded `WalletLedger`. Where `wallet_envelope_ffi` exposes the raw
// envelope primitives so C++ can compose its own orchestration, this
// module exposes a single lifecycle surface (create / open / save /
// rotate / free) plus a non-secret metadata getter and a postcard ledger
// export. Consumed by wallet2.cpp in the 2k/2l rewire slices.
pub mod engine_file_ffi;

// LWMA-1 difficulty-adjustment FFI export. Wraps `shekyl_difficulty::
// lwma1_next` in a C-ABI surface using the `ShekylU128` two-u64
// decomposition per `DAA_LWMA1.md` §6.1. Consumed by the Phase 2
// cross-check harness (`tests/difficulty/lwma1_cross_check.cpp`) and
// (Phase 3 onward) by the daemon's difficulty path.
pub mod difficulty_ffi;

// RandomX v2 light-cache PoW verification FFI. Wraps `shekyl_pow_randomx`
// (`compute_hash` + `CacheStore`) in a C-ABI surface — the consensus
// PoW hash (`shekyl_pow_randomx_v2_hash`) plus the canonical-seedhash
// pin/eager-derive entry point (`shekyl_pow_randomx_v2_set_canonical`).
// Replaces the inherited C RandomX v1 path (`crypto::rx_slow_hash` /
// `rx_set_main_seedhash`) on the daemon block-verification boundary per
// `docs/design/RANDOMX_V2_PHASE3_PLAN.md`.
pub mod pow_randomx_ffi;

// Archival serve-credit verification FFI (`ARCHIVAL_RETENTION_GATE2.md` §10).
pub mod archival_ffi;
// D3/R3 bond-admission viability (kept separate so archival_ffi does not keep
// absorbing every archival surface).
pub mod archival_admission_ffi;

// General CT cleartext-balance verification FFI (`GENESIS_TX_WIRE_FORMAT.md` §2.3).
pub mod ct_balance_ffi;

// Production OsRng → RelayRng adapter shared by the relay FFI seams.
mod secure_relay_rng;

// Dandelion++ embargo / propagation-timeout FFI — RP-4
// (`DAEMON_RELAY_PRIVACY.md` §17). Stem-map exports retired at RP-3a; the zone
// owns a `StemMap` directly (`relay_zone_ffi`).
pub mod dandelionpp_ffi;

// Live relay zone FFI — RP-3a (`DAEMON_RELAY_PRIVACY.md` §18). The C++
// `levin::notify` forwards here; `Effect` is dispatched in Rust via per-variant
// callbacks so no enum tag crosses the boundary (§18.4a).
pub mod relay_zone_ffi;

// Levin payload compression FFI (IMPLEMENTATION_INDEX LV row). The C++
// `epee::levin` compression path is a marshaling shim over these exports;
// the Rust-pinned libzstd is the single zstd implementation in the binary.
pub mod levin_ffi;

// Single-Rust-image contract: re-export shekyl-logging so its
// `#[no_mangle]` C exports (`shekyl_log_init_*`, `shekyl_log_emit`,
// `shekyl_log_install_tracing_forwarder`, …) are compiled into
// `libshekyl_ffi.a`. Every wallet-side binary then links exactly one
// Rust archive whose single `tracing-core` GLOBAL_DISPATCH is shared by
// the C++-installed subscriber and every `tracing::*` call site in this
// crate graph (engine-file, fcmp, …). Without this, those events
// dispatch into a dispatcher no subscriber is installed on and are
// silently dropped. See V3_WALLET_DECISION_LOG.md (single-image
// contract).
pub use shekyl_logging;

// Legacy monofile FFI surface (split from the former body of this file).
// Domain modules keep #[no_mangle] symbols; this root only wires and re-exports.
mod legacy_core;
mod legacy_curve_tree;
mod legacy_fcmp;
mod legacy_frost;
mod legacy_kem;
mod legacy_proofs;
mod legacy_tx;
mod legacy_types;
mod legacy_util;

#[allow(unused_imports)]
pub use legacy_core::*;
#[allow(unused_imports)]
pub use legacy_curve_tree::*;
#[allow(unused_imports)]
pub use legacy_fcmp::*;
#[allow(unused_imports)]
pub use legacy_frost::*;
#[allow(unused_imports)]
pub use legacy_kem::*;
#[allow(unused_imports)]
pub use legacy_proofs::*;
#[allow(unused_imports)]
pub use legacy_tx::*;
#[allow(unused_imports)]
pub use legacy_types::*;
#[allow(unused_imports)]
pub use legacy_util::*;

#[cfg(test)]
pub(crate) use legacy_fcmp::parse_prove_witness;

#[cfg(test)]
#[path = "legacy_tests.rs"]
mod tests;
