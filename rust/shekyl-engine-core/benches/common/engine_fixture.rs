// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! Production-lifecycle `Engine<SoloSigner>` fixture for the
//! `engine_trait_bench_*` benchmark family.
//!
//! # Path A: real lifecycle, no visibility expansion
//!
//! See `docs/design/STAGE_0_HARNESS.md` §4.2 "Fixture construction
//! approach (Path A)". Stage 0 PR-2 commits the project to constructing
//! the bench fixture through the production [`Engine::create`] entry
//! point — the same path the CLI / RPC server use — rather than
//! widening the visibility of an existing test helper through a
//! `__bench_internals` feature flag.
//!
//! # Why this duplicates `EngineCreateParams::for_test_full`
//!
//! The fixture's parameter-construction body is intentionally
//! duplicated from `EngineCreateParams::for_test_full` (see
//! `engine/lifecycle.rs`, `#[cfg(test)] pub(crate)`) rather than
//! widening that helper's visibility through a bench-internals
//! feature. The duplication is the cost of keeping the test surface
//! bounded; if `for_test_full`'s parameter shape evolves, this fixture
//! must be updated in lockstep, and reviewers verify the shape match
//! during PR review.
//!
//! The principle behind this choice (per §4.2): bench fixtures
//! duplicate test-helper logic locally rather than widening
//! test-helper visibility through bench-internals. The duplication
//! cost is small; the surface-expansion cost is permanent. This
//! principle applies to all subsequent Stage 1 per-trait PR bench
//! fixtures.
//!
//! # Setup-cost vs measurement region
//!
//! [`build_engine_fixture`] performs the full production lifecycle:
//! Argon2id KDF (relaxed `KdfParams { m_log2 = 0x08, t = 1, p = 1 }`
//! per `for_test_full`), ML-KEM keygen, classical-keypair derivation,
//! envelope encryption, filesystem layout, and lock acquisition. Each
//! call costs ~1–2 seconds wall-clock. **All of this is bench setup**,
//! excluded from the measured region by criterion's `b.iter` closure
//! boundary and iai-callgrind's `#[bench::*(setup = ...)]` attribute.
//!
//! Per §4.2 measurement-region discipline, post-fixture iai-callgrind
//! instructions for the `synced_height` workload should be in the
//! single-to-double-digits; orders-of-magnitude larger numbers
//! indicate the fixture has leaked into the measured region and the
//! bench is invalid.
//!
//! # Tokio runtime locality
//!
//! The Tokio runtime exists only to construct
//! [`SimpleRequestRpc::new`] (which is async); it is dropped before
//! the bench's measured region. The `DaemonClient` owns the
//! Arc-wrapped HTTP client and is self-sufficient post-runtime-drop.
//! The measured region (`engine.synced_height()`) does no async work;
//! cross-cutting lock 1's "caller-provided multi-threaded runtime"
//! requirement applies to `Engine::refresh`, which the bench does not
//! invoke.
//!
//! # Daemon URL is an unreachable sentinel
//!
//! `SimpleRequestRpc::new("http://127.0.0.1:1")` does not connect —
//! `new` only configures the HTTP agent and records the URL. The
//! workload measured at Stage 0 PR-2 (`synced_height`) does not
//! trigger a daemon RPC, so the URL is never contacted. A future
//! bench whose workload **does** trigger an RPC must swap the
//! `DaemonClient` for a real test double — `MockDaemon`, arriving
//! with Stage 1 PR 1 per `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §6.1.
//! That migration replaces [`construct_dummy_daemon`] in the fixture
//! (or introduces a sibling fixture under `benches/common/` per
//! §4.2's two-caller justification rule).
//!
//! # Returned guard shape
//!
//! [`build_engine_fixture`] returns `(Engine<SoloSigner>, TempDir)`.
//! The `TempDir` lives until the bench function's scope ends,
//! holding the wallet's filesystem footprint until measurement
//! completes. The Tokio runtime is fixture-internal — dropped before
//! return — and is **not** part of the guard tuple.

use shekyl_address::Network;
use shekyl_crypto_pq::account::{SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::{
    CapabilityInput, Credentials, DaemonClient, Engine, EngineCreateParams, SoloSigner,
};
use shekyl_engine_file::SafetyOverrides;
use shekyl_engine_prefs::WalletPrefs;
use shekyl_simple_request_rpc::SimpleRequestRpc;
use tempfile::TempDir;

/// Bench-fixture password. Bench-only; never written to disk outside
/// the temp directory the fixture cleans up on drop.
const BENCH_PASSWORD: &[u8] = b"shekyl-bench-fixture-password";

/// Construct a freshly-created `Engine<SoloSigner>` with deterministic
/// state, returning the engine and a `TempDir` guard.
///
/// Drop order is well-defined: tuple fields drop in declaration order,
/// so the engine drops before the temp directory and the wallet's
/// locks release before the directory is removed.
///
/// # Panics
///
/// Panics if any production lifecycle step fails (tempdir creation,
/// tokio runtime build, `SimpleRequestRpc::new`, `Engine::create`).
/// All five are deterministic on a healthy CI worker; failure is a
/// bench-environment problem, not a measurement to surface.
pub fn build_engine_fixture() -> (Engine<SoloSigner>, TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir for bench fixture");
    let base_path = tmp.path().join("bench-wallet");

    let creds = Credentials::password_only(BENCH_PASSWORD);
    let seed = fixed_seed();

    // Body intentionally duplicated from
    // `EngineCreateParams::for_test_full` per the file-level comment.
    // Update in lockstep with that helper.
    let params = EngineCreateParams {
        base_path: &base_path,
        credentials: &creds,
        network: Network::Stagenet,
        capability: CapabilityInput::Full {
            master_seed_64: &seed,
            seed_format: SeedFormat::Bip39,
        },
        creation_timestamp: 0,
        restore_height_hint: 0,
        kdf: KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        overrides: SafetyOverrides::none(),
        prefs: WalletPrefs::default(),
    };

    let daemon = construct_dummy_daemon();
    let engine = Engine::<SoloSigner>::create(params, daemon)
        .expect("Engine::create succeeded for the bench fixture");

    (engine, tmp)
}

/// Deterministic 64-byte master seed for the bench fixture.
///
/// Pattern: `byte[i] = (i & 0xff) * 7 mod 256`. Matches the shape used
/// by the existing in-crate `lifecycle.rs::tests::fixed_seed` helper
/// at the level of "deterministic, non-zero, non-trivial," without
/// borrowing the helper directly (test surface is bounded; benches
/// duplicate locally per §4.2 of the design doc).
fn fixed_seed() -> [u8; MASTER_SEED_BYTES] {
    let mut s = [0u8; MASTER_SEED_BYTES];
    for (i, b) in s.iter_mut().enumerate() {
        *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(7);
    }
    s
}

/// Build a `DaemonClient` against an unreachable URL.
///
/// `SimpleRequestRpc::new` does not connect — it only configures the
/// HTTP agent and records the URL. The runtime is local to this
/// function and dropped before return; the returned `DaemonClient`
/// owns an Arc-wrapped HTTP agent with no background tasks.
fn construct_dummy_daemon() -> DaemonClient {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread tokio runtime for bench fixture");
    let rpc = rt
        .block_on(SimpleRequestRpc::new("http://127.0.0.1:1".to_string()))
        .expect("SimpleRequestRpc::new (no connection attempted)");
    DaemonClient::new(rpc)
}
