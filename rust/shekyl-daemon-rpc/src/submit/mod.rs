// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Rust transaction-**admission engine** — the submit path's verdict
//! authority (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3).
//!
//! Rust owns parse, structural and semantic validation, fee arithmetic,
//! verification dispatch, and **verdict classification**; C++ owns byte
//! storage and index membership behind the narrow [`SubmitStateShim`] seam
//! (§3.2 / §4). The engine is generic over that seam: production implements
//! it over the three FFI shims, tests implement it as a deterministic mock,
//! and when the mempool itself migrates to Rust the Rust mempool implements
//! the trait — engine, wire contract, and wallet untouched (the *planned*
//! reversion per §11).
//!
//! ## Phase structure (§3.1)
//!
//! - **Phase A** ([`phase_a`]) — Rust-native admission, no FFI: hex decode,
//!   size cap, `shekyl-wire` parse + canonical-encoding check + `validate()`,
//!   coinbase reject, pool-policy statics (zero unlock time, tx-extra cap),
//!   key-image domain, canonical txid. Any failure is
//!   `Rejected{Malformed}` without touching C++.
//! - **Phase B** — one short pool→blockchain lock: the POD fact snapshot
//!   ([`SubmitFacts`]). Early return: `AlreadyInPool` / `AlreadyInChain`
//!   **only** — a snapshot key-image hit is a re-check input, never a
//!   verdict (defect 0.4's self-duplicate race).
//! - **Phase C** — no locks held, bounded by the process-global Phase-C
//!   semaphore ([`gate::phase_c_semaphore`], F39) acquired at the transport
//!   dispatch layer: ref-age window, fee floor ([`fee`]), weight rule, then
//!   the expensive cryptography behind the [`TxVerifier`] seam. Success mints
//!   the [`VerificationCertificate`] witness (§3.3).
//! - **Phase D** — one short lock via [`SubmitStateShim::commit`]: every
//!   mutable premise re-checked C++-side; on a race the shim returns fresh
//!   facts and **Rust classifies, most-terminal-first** (§3.1) — the C++
//!   never chooses a verdict.

pub mod certificate;
pub mod engine;
pub mod facts;
pub mod fee;
pub mod ffi_shim;
pub mod gate;
pub mod phase_a;
pub mod verifier;
pub mod verify;

/// FCMP++ reference-block age-window constants, generated from the JSON
/// authority (`config/consensus_constants.json`) by `build.rs` — the same
/// source that emits the C++ `shekyl/consensus_constants_generated.h`, so
/// the engine's Phase-C arithmetic cannot drift from the consensus check.
pub mod consensus {
    include!(concat!(env!("OUT_DIR"), "/submit_consensus_constants.rs"));

    // Decision-14 sentinels, mirroring the static_asserts in
    // src/cryptonote_config.h: a JSON bump must be a reviewed consensus
    // change, not a silent parameter drift.
    const _: () = assert!(
        FCMP_REFERENCE_BLOCK_MIN_AGE == 5,
        "FCMP_REFERENCE_BLOCK_MIN_AGE diverged from Decision 14 baseline (5); \
         review consensus implications before updating the sentinel"
    );
    const _: () = assert!(
        FCMP_REFERENCE_BLOCK_MAX_AGE == 100,
        "FCMP_REFERENCE_BLOCK_MAX_AGE diverged from baseline (100); \
         review consensus implications before updating the sentinel"
    );
}

pub use certificate::VerificationCertificate;
pub use engine::{EngineFault, SubmitCaller, SubmitEngine};
pub use facts::{
    CommitOutcome, KeyImageConflict, ReferenceFacts, ShimFault, SubmitFacts, SubmitStateShim,
    TxMeta,
};
pub use ffi_shim::FfiSubmitShim;
pub use gate::phase_c_semaphore;
pub use phase_a::{parse_submission, ParsedSubmission, PhaseAReject, SubmitTxKind};
pub use verifier::DaemonTxVerifier;
pub use verify::{TxVerifier, VerifyFailure};

/// The production engine: FFI state shim (§4) + native verifier (§3.3's
/// Phase-C battery). One instance per daemon, shared across transport
/// workers via `Arc` in the server's `AppState`.
pub type DaemonSubmitEngine = SubmitEngine<FfiSubmitShim, DaemonTxVerifier>;
