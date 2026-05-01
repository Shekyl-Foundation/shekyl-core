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
//! # Measurement-region discipline (symmetry rule + boundary rule)
//!
//! Per `docs/design/STAGE_0_HARNESS.md` §4.2, two rules keep the
//! bench-function measurement bounded to the call only. Both rules
//! are operationalized through this fixture's shape and the
//! companion bench files' function signatures.
//!
//! ## Symmetry rule (criterion-vs-iai-callgrind asymmetry)
//!
//! **Setup and teardown are both excluded from the measured region;
//! measurement is the call only.** Both halves are mechanized
//! explicitly; the criterion and iai-callgrind harnesses use
//! different mechanisms because they handle drop cost differently
//! (criterion amortizes; iai-callgrind does not — see §4.2 for the
//! asymmetry's structural cause).
//!
//! [`build_engine_fixture`] performs the full production lifecycle:
//! Argon2id KDF (relaxed `KdfParams { m_log2 = 0x08, t = 1, p = 1 }`
//! per `for_test_full`), ML-KEM keygen, classical-keypair derivation,
//! envelope encryption, filesystem layout, and lock acquisition. Each
//! call costs ~1–2 seconds wall-clock. **All of this is setup**,
//! excluded from the measured region by:
//!
//! - criterion's `b.iter` closure boundary (the fixture is built once
//!   outside `b.iter`; the closure body borrows the engine by
//!   reference, dereferencing through `Box` transparently);
//! - iai-callgrind's `#[bench::*(setup = build_engine_fixture)]`
//!   attribute (the macro emits the setup call outside the measured
//!   region).
//!
//! Symmetrically, [`drop_fixture`] is the teardown helper that
//! iai-callgrind's `teardown = drop_fixture` parameter invokes
//! **outside** the measured region. Without this explicit teardown,
//! the fixture's `Drop` would run inside iai-callgrind's measured
//! region (it measures the full bench function body in a single shot),
//! and the cost of unwinding the engine, dropping its Arc-wrapped
//! components, and removing the `TempDir`'s files would inflate the
//! measured `instructions` count by orders of magnitude. The
//! corresponding criterion bench does not need an explicit teardown
//! because criterion's `b.iter` amortizes drop cost across millions
//! of iterations and rounds to zero. **Both harnesses arrive at the
//! same property — drop cost outside the measurement — through
//! different mechanisms.**
//!
//! ## Boundary rule (iai-callgrind measures function-boundary value movement)
//!
//! Per §4.2's boundary rule subsection, iai-callgrind measures the
//! *entire* bench function body, including memcpy at function entry
//! (when arguments are passed by value) and at function exit (when
//! return values are returned by value). **`Engine<SoloSigner>` is
//! 6,296 bytes** at this fixture's HEAD; passing the engine through
//! the bench function by value would produce ~600 instructions of
//! boundary memcpy cost (Valgrind models memcpy as instructions
//! proportional to bytes moved), dominating the measured number for
//! a `synced_height`-class workload whose actual call cost is ~5–10
//! instructions.
//!
//! The fix is pointer-sized indirection at the boundary: the fixture
//! returns `(Box<Engine<SoloSigner>>, TempDir)`. Total boundary
//! memcpy is `8 + sizeof::<TempDir>()` ≈ 32 bytes — well below the
//! 64-byte cutoff §4.2 names — and the iai-callgrind measurement's
//! residual boundary cost is ~5–10 instructions instead of ~600.
//! The criterion sibling is not directly affected (closure capture
//! by reference makes value-pass-at-boundary moot for criterion),
//! but the unified fixture shape lets both harnesses share one
//! [`build_engine_fixture`] / [`drop_fixture`] pair.
//!
//! ## Diagnostic signals
//!
//! Per §4.4's static check, post-fixture iai-callgrind instructions
//! for the `synced_height` workload should be in the **20–40 range**
//! (4–6 for the call body + 5–10 for the unified-fixture-shape
//! boundary memcpy + small wiring overhead). Two diagnostic signals:
//!
//! - **Order-of-magnitude divergence between the criterion and
//!   iai-callgrind harnesses on the same workload** — criterion
//!   reporting nanoseconds-per-iter consistent with a few cycles
//!   while iai-callgrind reports tens-of-thousands of instructions
//!   is the textbook sign that fixture `Drop` has leaked into iai's
//!   measured region (symmetry-rule violation).
//! - **An iai-callgrind number in §4.4's warning territory (50–300
//!   instructions) without the workload itself justifying that
//!   range** — most likely indicates a boundary-rule violation
//!   (some fixture component crossing the boundary by value with
//!   size > 64 bytes) or a workload genuinely larger than the model
//!   assumed. Per §4.4, three reviewer checks resolve this.
//!
//! The static check in §4.4 catches both at the workflow_dispatch
//! capture step before the number is transcribed into
//! `PERFORMANCE_BASELINE.md`.
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
//! # Returned guard shape (unified across both harnesses)
//!
//! [`build_engine_fixture`] returns `(Box<Engine<SoloSigner>>,
//! TempDir)` per the boundary rule above. The `TempDir` lives
//! across the bench function's measured region, holding the wallet's
//! filesystem footprint until measurement completes. The Tokio
//! runtime is fixture-internal — dropped before return — and is
//! **not** part of the guard tuple.
//!
//! Per the symmetry rule (§4.2), the iai-callgrind bench function
//! takes the tuple by value, performs its measured workload, and
//! **returns the tuple** so iai-callgrind's `teardown = drop_fixture`
//! parameter can invoke `Drop` outside the measured region. The
//! criterion sibling does not return the tuple because the engine and
//! tempdir live in the outer function scope across `b.iter`'s
//! iteration loop; the criterion closure body dereferences through
//! `Box`'s auto-deref (`engine.synced_height()` resolves to
//! `(*engine).synced_height()`) at zero pointer-chase cost beyond
//! the one Valgrind already attributes to the call.
//!
//! The unified `(Box<Engine<SoloSigner>>, TempDir)` shape is the
//! **canonical fixture shape for the `engine_trait_bench_*` family**.
//! Subsequent Stage 1 per-trait PRs that add additional fixture
//! components (e.g., a state-populated `Vec<Transfer>` for the
//! LedgerEngine PR's `balance` bench) follow the same pattern: any
//! fixture field exceeding 64 bytes goes behind `Box<T>` so the
//! bench-function boundary moves only pointer-sized data.

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
/// state, returning the boxed engine and a `TempDir` guard.
///
/// The engine is heap-allocated through `Box::new` per the boundary
/// rule (`docs/design/STAGE_0_HARNESS.md` §4.2): `Engine<SoloSigner>`
/// is 6,296 bytes and would dominate the iai-callgrind measurement's
/// boundary memcpy if passed by value. The boxed shape moves only an
/// 8-byte pointer across the bench function boundary.
///
/// Drop order is well-defined: tuple fields drop in declaration order,
/// so the box (and the engine inside it) drops before the temp
/// directory, and the wallet's locks release before the directory is
/// removed.
///
/// # Panics
///
/// Panics if any production lifecycle step fails (tempdir creation,
/// tokio runtime build, `SimpleRequestRpc::new`, `Engine::create`).
/// All five are deterministic on a healthy CI worker; failure is a
/// bench-environment problem, not a measurement to surface.
pub fn build_engine_fixture() -> (Box<Engine<SoloSigner>>, TempDir) {
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

    (Box::new(engine), tmp)
}

/// Teardown helper for iai-callgrind's `teardown = drop_fixture`
/// parameter.
///
/// The function body is empty — taking ownership of the tuple is
/// sufficient to schedule `Drop` execution on its members. iai-callgrind
/// invokes this helper **outside** the measured region (per the
/// symmetry rule in `docs/design/STAGE_0_HARNESS.md` §4.2), so the
/// engine teardown (Arc decrements, ML-KEM key zeroization, lock
/// release) and the `TempDir`'s `unlink` syscalls do not contaminate
/// the bench's `instructions` count.
///
/// # Why this is concrete and not generic
///
/// Stage 0 PR-2 ships exactly one engine-trait bench fixture shape
/// (`(Box<Engine<SoloSigner>>, TempDir)`, per the boundary rule in
/// §4.2). A generic `drop_fixture<T>` would not save complexity here,
/// and it would fight iai-callgrind's macro expansion (the `teardown =`
/// argument is resolved at macro-expansion time and prefers a
/// fully-applied function path). Stage 1 per-trait PRs that introduce
/// additional fixture shapes (e.g., a state-populated balance fixture
/// carrying a `Box<Vec<Transfer>>` alongside the boxed engine) add
/// their own concrete `drop_*` siblings rather than generalizing this
/// one.
///
/// # Dead-code suppression
///
/// `#[allow(dead_code)]` is required because the criterion sibling
/// bench does not need `drop_fixture` — criterion's `b.iter`
/// amortizes drop cost implicitly (see file-level docstring's
/// "Symmetry rule" subsection). Each per-bench target compiles
/// `mod common;` independently, and the criterion target sees
/// `drop_fixture` as unused. This is expected and load-bearing:
/// the symmetry rule's mechanism differs across harnesses.
#[allow(dead_code)]
pub fn drop_fixture(_fixture: (Box<Engine<SoloSigner>>, TempDir)) {}

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
