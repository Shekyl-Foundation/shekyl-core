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
//! `DaemonClient` for a real test double — `TestDaemon`, arriving
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
//! filesystem footprint until measurement completes. The daemon's
//! RPC-construction runtime is fixture-internal (dropped before
//! return); the `KeyActor`'s host runtime is the leaked process-wide
//! [`bench_runtime`] (it must outlive the actor). Neither runtime is
//! part of the guard tuple.
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

// `engine_trait_bench_ledger_balance{,_iai}.rs` require the
// `bench-internals` feature for state-injection on `LocalLedger`;
// the imports below stay feature-gated so the existing
// `engine_trait_bench_ledger_synced_height{,_iai}.rs` pair (which
// does *not* require `bench-internals`) compiles cleanly when this
// shared module is included from those targets.
//
// `derive_output_handle` and `HybridCiphertext` are M3d-additions
// (per `STAGE_1_PR_3_M3D_PREFLIGHT.md` §3.2 carve-out: bench
// fixtures populate the `source_ciphertext` + `output_handle` shape
// the post-pass produces, replacing the five legacy
// `Option<Zeroizing<…>>` fields the schema removed). They live only
// inside `sample_transfer`'s body, which is itself feature-gated
// below, so the imports gate on the same feature.
#[cfg(feature = "bench-internals")]
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
#[cfg(feature = "bench-internals")]
use shekyl_crypto_pq::handle::derive_output_handle;
#[cfg(feature = "bench-internals")]
use shekyl_crypto_pq::kem::HybridCiphertext;
#[cfg(feature = "bench-internals")]
use shekyl_engine_core::__bench_internals::engine_local_ledger_for_bench;
#[cfg(feature = "bench-internals")]
use shekyl_engine_state::{
    payment_id::PaymentId,
    subaddress::SubaddressIndex,
    transfer::{TransferDetails, SPENDABLE_AGE},
    BlockchainTip, LedgerBlock, ReorgBlocks,
};
#[cfg(feature = "bench-internals")]
use shekyl_oxide::primitives::Commitment;

/// Bench-fixture password. Bench-only; never written to disk outside
/// the temp directory the fixture cleans up on drop.
const BENCH_PASSWORD: &[u8] = b"shekyl-bench-fixture-password";

/// Representative height for the `engine_trait_bench_economics_base_emission_at`
/// pair (§3.8 / §5.2 B.6).
///
/// `EconomicsEngine::base_emission_at` is **O(height)** under
/// interpretation (A): it walks `projected_already_generated(height)`
/// block-by-block from genesis. `262_800` is ≈1 year of 120 s blocks —
/// the same "≈1 yr" anchor the C4 fixture's early neutral milestone
/// uses (`docs/test_vectors/economics/baseline_steady_state.json`) — so
/// the recorded loop length is a meaningful, reviewable workload rather
/// than an arbitrary magnitude. The frozen baseline pins to the workload
/// at the merge SHA, not to this constant's identifier; a future
/// workload-characterization PR that needs a different height adds a
/// sibling bench rather than mutating this constant.
///
/// Per-bench-target `mod common;` inclusion means each target uses only
/// a subset of this module's items; `#[allow(dead_code)]` on the unused
/// side is the same discipline applied to `drop_fixture`.
#[allow(dead_code)]
pub const ECONOMICS_BENCH_HEIGHT: u64 = 262_800;

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
    // `Engine::create` → `assemble` spawns the `KeyActor`, which (post
    // Stage-2 require-ambient) asserts an ambient Tokio runtime. Build
    // the daemon first (its own throwaway runtime), then enter the
    // leaked process-wide `bench_runtime` only for `create`, so the
    // actor spawns onto a runtime that outlives the fixture. The guard
    // drops here; the actor task continues on the never-dropped
    // runtime for the bench's lifetime.
    let engine = {
        let _rt_guard = bench_runtime().enter();
        Engine::<SoloSigner>::create(params, daemon)
            .expect("Engine::create succeeded for the bench fixture")
    };

    (Box::new(engine), tmp)
}

/// Process-wide multi-thread Tokio runtime for the bench fixture,
/// built once and intentionally leaked for the duration of the bench
/// binary.
///
/// The `KeyActor` spawned by [`Engine::create`] is an async task that
/// must live on a runtime that outlasts [`build_engine_fixture`]'s
/// return. A one-shot runtime dropped at fixture-build time would tear
/// the actor down immediately. Leaking one runtime for the whole bench
/// binary is the same shape `refresh.rs`'s test module uses, and keeps
/// the fixture guard tuple (`(Box<Engine<SoloSigner>>, TempDir)`) free
/// of a runtime handle.
fn bench_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .expect("build multi-thread tokio runtime for bench fixture")
    })
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

/// Default transfer count for the `engine_trait_bench_ledger_balance`
/// state-populated fixture.
#[cfg(feature = "bench-internals")]
///
/// `1024` is large enough that
/// [`shekyl_scanner::BalanceSummary::compute`]'s linear scan over the
/// transfer slice dominates per-call cost (so the workload classifies
/// as "state-dependent compute" per
/// [`docs/PERFORMANCE_BASELINE.md`](../../docs/PERFORMANCE_BASELINE.md)
/// §4.4) and small enough that the iai-callgrind Valgrind run
/// completes within the §4.4 dynamic-check budget on a CI runner.
/// Power-of-two so the numerical relationship between fixture size
/// and measured instruction count is reviewable on inspection.
///
/// If a future workload-characterization PR (e.g., the
/// transfer-count-scaling investigation §4.6 reserves) needs a
/// different N, it adds a sibling builder
/// (`build_engine_fixture_with_balance_n`) rather than mutating this
/// constant — the frozen baseline pins to the workload at the merge
/// SHA, not to the constant's identifier.
///
/// Per-bench-target `mod common;` inclusion means each target only
/// uses a subset of this module's items; `#[allow(dead_code)]` on
/// the unused side is the same discipline applied to `drop_fixture`
/// elsewhere in this file.
#[allow(dead_code)]
pub const BENCH_BALANCE_TRANSFER_COUNT: usize = 1024;

/// Construct a freshly-created `Engine<SoloSigner>` whose persistent
/// ledger is pre-populated with `n` synthetic transfers, returning
/// the boxed engine and a `TempDir` guard. Sibling of
/// [`build_engine_fixture`] for state-dependent benches.
///
/// Workload class: state-dependent compute. The
/// `LedgerEngine::balance` trait method walks the transfer slice
/// once per call (per [`shekyl_scanner::BalanceSummary::compute`]),
/// so per-call cost scales linearly with `n`.
///
/// # State-injection path (PR 2 commit 8)
///
/// Production `Engine::create` (called inside
/// [`build_engine_fixture`]) returns an engine with an empty
/// `WalletLedger`. To populate state for the balance bench without
/// running a full producer/scanner ceremony, this builder:
///
/// 1. Constructs `n` synthetic [`TransferDetails`] via
///    [`sample_transfer`] (deterministic by-index seed pattern,
///    matching the precedent in `refresh_snapshot.rs`).
/// 2. Wraps them in a fresh [`LedgerBlock::new`] with a fixed
///    10-entry reorg window and an arbitrary tip.
/// 3. Uses
///    [`shekyl_engine_core::__bench_internals::LocalLedger::populate_for_bench`]
///    to swap the engine's empty ledger for the populated one.
///    The helper is gated behind the `bench-internals` feature so
///    production callers cannot reach it.
///
/// # Drop order, panics, and Tokio locality
///
/// Same as [`build_engine_fixture`]: the box drops before the temp
/// directory; production lifecycle failures panic; the Tokio runtime
/// is fixture-internal and dropped before return.
#[cfg(feature = "bench-internals")]
#[allow(dead_code)]
pub fn build_engine_fixture_with_balance(
    n: usize,
) -> (
    Box<Engine<SoloSigner, DaemonClient, shekyl_engine_core::__bench_internals::LocalLedger>>,
    TempDir,
) {
    let (engine, tmp) = build_engine_fixture();

    let mut transfers = Vec::with_capacity(n);
    for i in 0..n {
        transfers.push(sample_transfer(i as u64));
    }
    let tip = BlockchainTip::new(1_000_000, [0xAA; 32]);
    let reorg_blocks = ReorgBlocks {
        blocks: (999_990..=1_000_000)
            .map(|h| (h, [(h & 0xff) as u8; 32]))
            .collect(),
    };
    let ledger_block = LedgerBlock::new(transfers, tip, reorg_blocks);

    engine_local_ledger_for_bench(&engine).populate_for_bench(ledger_block);

    (engine, tmp)
}

/// No-arg wrapper around [`build_engine_fixture_with_balance`] for
/// iai-callgrind's `#[bench::name(setup = …)]` attribute, which
/// resolves at macro-expansion time and prefers a fully-applied
/// function path over a closure or a parameterized call. Same
/// constant-arg pattern documented for `drop_fixture`.
#[cfg(feature = "bench-internals")]
#[allow(dead_code)]
pub fn build_engine_fixture_with_default_balance() -> (
    Box<Engine<SoloSigner, DaemonClient, shekyl_engine_core::__bench_internals::LocalLedger>>,
    TempDir,
) {
    build_engine_fixture_with_balance(BENCH_BALANCE_TRANSFER_COUNT)
}

/// Teardown for the balance fixture; mirrors [`drop_fixture`].
///
/// `Engine<SoloSigner, DaemonClient, LocalLedger>` is the same shape
/// `build_engine_fixture_with_balance` returns. iai-callgrind requires
/// a concrete `teardown =` symbol per fixture shape.
#[cfg(feature = "bench-internals")]
#[allow(dead_code)]
pub fn drop_balance_fixture(
    _fixture: (
        Box<Engine<SoloSigner, DaemonClient, shekyl_engine_core::__bench_internals::LocalLedger>>,
        TempDir,
    ),
) {
}

/// Deterministic 32-byte seed for the `LocalKeys` bench fixture.
///
/// Pattern `byte[i] = (i * 11 + 3) mod 256` — non-zero, non-trivial,
/// and orthogonal to [`fixed_seed`] (the 64-byte master-seed pattern
/// the `Engine` fixture uses). The `i as u8` cast is exact because
/// `i < 32 < 256`. Distinct constants keep the two fixtures' identity
/// material non-aliased, which matters only if a future bench
/// compares engine-side and key-side outputs against each other.
#[cfg(feature = "bench-internals")]
#[allow(dead_code)]
const LOCAL_KEYS_BENCH_SEED: [u8; 32] = {
    let mut s = [0u8; 32];
    let mut i: u8 = 0;
    while i < 32 {
        s[i as usize] = i.wrapping_mul(11).wrapping_add(3);
        i += 1;
    }
    s
};

/// Build a fixture for the `KeyEngine` bench family — a heap-
/// allocated [`LocalKeys`] derived from the deterministic
/// [`LOCAL_KEYS_BENCH_SEED`].
///
/// # Why the fixture is `Box<LocalKeys>` rather than `Box<Engine<...>>`
///
/// `Engine<S, D, L>` does not (yet) hold a `LocalKeys` field —
/// orchestrator integration of the `KeyEngine` implementor is the
/// `KeyEngine` PR-5 territory per
/// `docs/design/STAGE_1_PR_3_KEY_ENGINE.md` §2.1.1 (the Round 4a
/// workflow-shape pivot). The post-M3-series `Engine` keeps
/// `keys: AllKeysBlob` (the wallet key material) while the
/// `KeyEngine` implementor [`LocalKeys`] exists alongside but is
/// not field-wired yet (`#[allow(dead_code)]` on the type).
///
/// The substrate forces the divergence from the unified
/// `(Box<Engine<SoloSigner, DaemonClient, LocalLedger>>, TempDir)`
/// shape `engine_trait_bench_ledger_balance` uses; the bench still
/// classifies under the `engine_trait_bench_*` threshold class via
/// the `compare.py` function-name routing (per `STAGE_0_HARNESS.md`
/// §3.3.1, `classify()` routes on function name, not fixture
/// shape). The divergence is documented in this fixture's
/// docstring (here) and in the close-out PR's pre-flight §1.2.
///
/// # Boundary rule (iai-callgrind)
///
/// `LocalKeys` is significantly larger than the §4.2 64-byte
/// cutoff (the type carries an `AllKeysBlob` plus state-shaped
/// fields and a subaddress-registry `RwLock`). The
/// `Box<LocalKeys>` shape moves only an 8-byte pointer across the
/// bench-function boundary, matching the established discipline
/// for the engine-trait bench family.
///
/// # No `TempDir` needed
///
/// Unlike [`build_engine_fixture`] / [`build_engine_fixture_with_balance`],
/// the `KeyEngine` bench does not touch the filesystem — `LocalKeys`
/// is purely in-memory (no `WalletFile`, no advisory lock, no
/// wallet-state directory). The fixture is `Box<LocalKeys>`
/// without a guard tuple.
///
/// # Drop order, panics
///
/// `LocalKeys::Drop` zeroizes the contained `AllKeysBlob` secrets
/// (per the type's `ZeroizeOnDrop` discipline). No filesystem
/// teardown needed. Panics if
/// [`LocalKeys::from_test_seed`] panics (only on internal
/// `generate_account_from_raw_seed` failure, which is deterministic
/// on a healthy build).
#[cfg(feature = "bench-internals")]
#[allow(dead_code)]
pub fn build_local_keys_fixture() -> Box<shekyl_engine_core::__bench_internals::LocalKeys> {
    Box::new(
        shekyl_engine_core::__bench_internals::LocalKeys::from_test_seed(LOCAL_KEYS_BENCH_SEED),
    )
}

/// Teardown for the `LocalKeys` bench fixture; mirrors
/// [`drop_fixture`].
///
/// `LocalKeys::Drop` zeroizes the contained `AllKeysBlob` secrets;
/// taking ownership here is sufficient to schedule that work
/// outside the iai-callgrind measured region (the symmetry rule
/// per `STAGE_0_HARNESS.md` §4.2). The criterion sibling does not
/// invoke this teardown because criterion's `b.iter` amortizes
/// drop cost across iterations.
#[cfg(feature = "bench-internals")]
#[allow(dead_code)]
pub fn drop_local_keys_fixture(_fixture: Box<shekyl_engine_core::__bench_internals::LocalKeys>) {}

/// Mirrors `shekyl-engine-state::ledger_block::tests::sample_transfer`
/// — the canonical "lightweight transfer for tests" shape. Reproduced
/// here (and in `refresh_snapshot.rs`) because the test helper is
/// `cfg(test)` inside a different crate. Keep this in lockstep across
/// the two bench files if the test helper grows new fields: drift
/// between bench fixtures and test helpers would let regressions
/// hide behind shape mismatches.
///
/// Post-M3d (per `STAGE_1_PR_3_M3D_PREFLIGHT.md` §3.3), the per-output
/// secret-bearing fields (`combined_shared_secret`, `ho`, `y`, `z`,
/// `k_amount`) are no longer persisted on `TransferDetails`; the
/// engine re-derives them at signing time from `(view_secret,
/// source_ciphertext)`. The bench fixture populates
/// `source_ciphertext` (a ~1088-byte ML-KEM ciphertext + 32-byte
/// X25519 share) and `output_handle` (16-byte cSHAKE256 derivative)
/// so the snapshot workload reflects realistic post-M3d transfer
/// sizes — the dominant non-default Option payload shifts from
/// ~192 bytes/transfer of secret material to ~1120 bytes/transfer
/// of handle-pathway material.
#[cfg(feature = "bench-internals")]
#[allow(dead_code)]
fn sample_transfer(seed: u64) -> TransferDetails {
    let lo = (seed & 0xff) as u8;
    let tx_hash = [lo; 32];
    let internal_output_index = seed;
    TransferDetails {
        tx_hash,
        internal_output_index,
        global_output_index: 1_000 + seed,
        block_height: 100,
        key: ED25519_BASEPOINT_POINT,
        key_offset: Scalar::ONE,
        commitment: Commitment::new(Scalar::ONE, 1_000_000 + seed),
        subaddress: Some(SubaddressIndex::new((seed & 0xffff_ffff) as u32)),
        payment_id: Some(PaymentId([lo; 8])),
        spent: false,
        spent_height: None,
        key_image: Some(shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
            [lo ^ 0xFF; 32],
        )),
        staked: false,
        stake_tier: 0,
        stake_lock_until: 0,
        last_claimed_height: 0,
        source_ciphertext: Some(HybridCiphertext {
            x25519: [lo.wrapping_add(1); 32],
            ml_kem: vec![lo.wrapping_add(2); 1088],
        }),
        output_handle: Some(derive_output_handle(
            &[lo.wrapping_add(3); 32],
            &tx_hash,
            internal_output_index,
        )),
        eligible_height: 100 + SPENDABLE_AGE,
        frozen: false,
        fcmp_precomputed_path: None,
    }
}
