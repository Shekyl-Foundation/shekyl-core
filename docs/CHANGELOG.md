# Shekyl Changelog

## [Unreleased]

### Added

- **Stage 1 PR 4 — `RefreshEngine` trait surface**
  (`feat/stage-1-pr4-refresh-engine`, 2026-05-15 → 2026-05-20).
  Lands the Phase-0a-binding `RefreshEngine` trait and the
  `ViewMaterial` adjacent type per
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §4 Phase 0a + Phase 0c + Phase 0e and
  [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3 (PR 4 C0 = `322677261`; C1 = `d3edc1abb`).
  - `pub trait RefreshEngine: Send + Sync + 'static` at
    [`engine/traits/refresh.rs`](../rust/shekyl-engine-core/src/engine/traits/refresh.rs)
    with one async method `produce_scan_result(snapshot:
    LedgerSnapshot, daemon: &D, opts: &RefreshOptions, cancel:
    &CancellationToken, progress: &watch::Sender<RefreshProgress>,
    diagnostics: &dyn DiagnosticSink) -> Result<ScanResult,
    Self::Error>` and `type Error: Into<RefreshError>`.
  - Five-checkpoint cancellation discipline (1 / 4 on the
    orchestrator; 2 / 3 / 5 on the trait body; checkpoint 5
    is the per-transaction inner check per §5.4.9 F2 +
    F11 + F11-S safe-point pins).
  - `Self::Error` is **unit-variant-only at the trait surface**
    per §5.4.7 R6 reframe: rich structured diagnostic
    information flows through the `&dyn DiagnosticSink`
    second channel; the synchronous return is a structural-
    branch signal only. Of `RefreshError`'s six variants,
    three are reachable from a `RefreshEngine` impl's
    `Self::Error` via `Into` (`Cancelled` unit, `Io(IoError)`,
    `InternalInvariantViolation { context: &'static str }`);
    three are orchestrator-constructed only
    (`MalformedScanResult` at the merge layer;
    `ConcurrentMutation` at the merge gate; `AlreadyRunning`
    at binary-layer single-flight).
  - `ScanResult` atomicity-under-cancellation contract:
    `produce_scan_result` returns **either** a `ScanResult`
    covering the full span it scanned **or**
    `RefreshError::Cancelled` — no partial-span result is
    ever returned (R7 disposition).
  - `LedgerSnapshot` is passed **by value** (R5 + §5.4.5):
    the orchestrator constructs under the engine read-guard,
    drops the guard, and hands the snapshot to the producer
    by move; the snapshot carries reorg-window descriptors
    only and is cheap to clone.
  - `&D` daemon-handle borrow with the §2.5 `Clone + Send +
    Sync + 'static` bound on `D`, so implementors can clone
    internally if they need an owned handle to spawn work
    (e.g., parallel block-fetch refinements); implementors
    MUST NOT borrow `&D` across a `tokio::spawn` boundary.
  - `pub struct ViewMaterial { spend_pub: EdwardsPoint;
    view_scalar: Zeroizing<Scalar>; x25519_sk: Zeroizing<[u8;
    32]>; ml_kem_dk: Zeroizing<Vec<u8>>; spend_secret:
    Zeroizing<[u8; 32]> }` at
    [`engine/view_material.rs`](../rust/shekyl-engine-core/src/engine/view_material.rs)
    with `Zeroize + ZeroizeOnDrop` derived; capturing the
    view-and-spend material at `LocalRefresh::new` so the
    `Scanner` builds once and is held for the instance
    lifetime (no per-attempt scanner construction; no
    per-attempt secret duplication; R4 a-instance-scoped).
  - The `LocalRefresh` implementor at
    [`engine/local_refresh.rs`](../rust/shekyl-engine-core/src/engine/local_refresh.rs)
    (PR 4 C4 = `ac100e1ab`) is the V3.0 production `R`
    parameter for `Engine<S, D, L, R>`; future implementors
    (Stage 4 actor-mesh `RefreshActor`; any future producer
    variant) implement the same trait surface.

- **Stage 1 PR 4 — `RefreshDiagnostic` enum + `DiagnosticSink`
  trait + Stage 1 sink implementations** (PR 4 C2 =
  `8fc207051`; `SuppressedRateLimit` variant per Round 4
  review pass F6 = same commit). Lands the second channel of
  the two-channel error / diagnostic actor-mesh seam per
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R6 reframe + §5.4.8 attack-surface dispositions.
  - `pub enum RefreshDiagnostic` at
    [`engine/diagnostics.rs`](../rust/shekyl-engine-core/src/engine/diagnostics.rs)
    with `#[non_exhaustive]` and the Round-4-audit-confirmed
    Stage 1 variant set: `DaemonMalformed { kind:
    MalformedKind }`, `DaemonTimeout { op: DaemonOp, elapsed:
    Duration }`, `DaemonProtocolError { kind:
    ProtocolErrorKind }`, `ReorgObserved { fork_height: u64,
    depth: u32 }`, `ScanProgress { height: u64, candidates:
    u32 }`, and the Round-4-F6-added `SuppressedRateLimit {
    class: SuppressedClass }`.
  - Supporting bounded enums (`MalformedKind`, `DaemonOp`,
    `ProtocolErrorKind`, `SuppressedClass`), all
    `#[non_exhaustive]`; `SuppressedClass` carries one arm per
    rate-limited event class (`DaemonMalformed`,
    `DaemonTimeout`, `DaemonProtocolError`, `ReorgObserved`,
    `ScanProgress`). The `SuppressedRateLimit` variant
    carries *only* `class: SuppressedClass` — no count, no
    timing, no original-event payload — per the §5.4.8 #5
    F13-pin closing the suppressed-event-count covert
    channel back from the producer's internal state.
  - `pub trait DiagnosticSink: Send + Sync + 'static` with
    one method `fn emit(&self, event: RefreshDiagnostic)`.
    Trait-level contract pins (rustdoc): emission is
    **non-blocking** (extends to **non-blocking under
    concurrent emission**, foreclosing `Mutex<VecDeque<_>>`-
    style implementations that re-introduce the producer-
    liveness hazard at scale); emission/return **coherence**
    (every non-`Cancelled` `Err` return is preceded by at
    least one corresponding `RefreshDiagnostic` emission
    before the error returns, with `AssertionSink`-driven
    property tests at C7 as the canonical reference per
    [`19-validation-surface-discipline.mdc`](../.cursor/rules/19-validation-surface-discipline.mdc));
    **per-emitter FIFO ordering preserved** (the
    seventh contract pin added by Round 4 review pass F4 =
    §5.4.6; cross-emitter ordering is undefined); and the
    in-process-only trust-boundary contract per §5.4.6 /
    §5.4.8 #4 (full-fidelity `RefreshDiagnostic` consumers
    MUST live inside the wallet trust boundary recursively;
    cross-process / network-bound consumers receive only
    projection types sanitized at the boundary).
  - `pub struct NoopDiagnosticSink` + `pub struct
    TracingDiagnosticSink` ship as the Stage 1 sink
    implementations; `TracingDiagnosticSink::emit` routes
    **per-class projections** to `tracing::event!` per the
    Round-4-review-pass F9 audit (variant tag only for
    `DaemonMalformed` / `DaemonProtocolError` /
    `SuppressedRateLimit`; bucketed `elapsed` for
    `DaemonTimeout`; bucketed `depth` for `ReorgObserved`;
    bucketed `candidates` for `ScanProgress` with `height`
    elided), not the full `RefreshDiagnostic` `Debug` impl.
  - All trait + enum surface re-exported flat at the
    `shekyl_engine_core` crate root per the R3 pattern.

- **Stage 1 PR 4 — C6 no-Mock substrate pass (`RefreshEngine` /
  `LedgerEngine` failure-injection wrappers)**
  (`feat/stage-1-pr4-refresh-engine`, 2026-05-20). Lands the
  C6α + C6β sub-commits of PR 4's substrate pass per the Round 5
  amendment (commit `8484e669a`) and sub-pin extension
  (commit `29cb7e138`, F-Mock-1 through F-Mock-8). The pass closes
  the [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) "Stage 1 retroactive
  Mock-X cleanup: `MockLedger` → `LocalLedger::from_test_blocks(...)`
  + `FaultInjecting<LocalLedger>`" entry and applies the no-Mock
  pattern PR 3 established (production-only implementors +
  composable trait-level `FaultInjecting<T>` wrappers) to PR 2's
  inherited `MockLedger` parallel-implementation.

  *C6α — `FaultInjecting<R: RefreshEngine>` wrapper + `test-helpers`
  feature* (commit `e9310542a`):
  - Adds `test-helpers = []` Cargo feature to
    [`rust/shekyl-engine-core/Cargo.toml`](../rust/shekyl-engine-core/Cargo.toml)
    (mirrors the `bench-internals` precedent) gating the C6
    test-helper surfaces with `#[cfg(any(test, feature =
    "test-helpers"))]` per the F-Mock-1 symmetry pin.
  - Adds
    [`engine/fault_injecting_refresh.rs`](../rust/shekyl-engine-core/src/engine/fault_injecting_refresh.rs)
    implementing `FaultInjecting<R: RefreshEngine>` with the
    Option (i) wrapper API (`type Error = RefreshError`; FIFO
    `Mutex<VecDeque<RefreshError>>` queue; `queue_failure(err)`
    general injector; `queued_failures()` drain inspector;
    `debug_assert!`-on-Drop queue-drain contract per F-Mock-2).
  - Adds `Engine::replace_refresh` test-only setter on
    [`engine/lifecycle.rs`](../rust/shekyl-engine-core/src/engine/lifecycle.rs)
    mirroring the existing `replace_daemon` / `replace_ledger`
    helpers.
  - Adds Class 1 trait-surface smoke tests covering empty-queue
    passthrough, single-injection-then-delegation, multi-injection
    FIFO ordering, and `#[should_panic]` queue-drain-on-teardown.

  *C6β — `FaultInjecting<L: LedgerEngine>` + `LocalLedger::from_test_blocks`
  + `MockLedger` retirement*:
  - Adds
    [`engine/fault_injecting_ledger.rs`](../rust/shekyl-engine-core/src/engine/fault_injecting_ledger.rs)
    implementing `FaultInjecting<L: LedgerEngine>` with the same
    Option (i) wrapper shape (queue-of-`RefreshError`,
    `queue_failure` / `queue_concurrent_mutation` /
    `queued_failures`, `debug_assert!`-on-Drop). Not `Clone` by
    design — the prior `MockLedger`'s `Arc<Mutex<…>>` aliasing
    shape (inherited from CryptoNote test patterns) does not
    survive the no-Mock transition.
  - Adds test-only `LocalLedger::from_test_blocks(Vec<Block>)`
    constructor at
    [`engine/local_ledger.rs`](../rust/shekyl-engine-core/src/engine/local_ledger.rs).
    The V3.0 substrate supports the empty-`Vec` case only (the
    sole shape every existing `MockLedger`-replaced caller
    needs); non-empty `Vec` panics with a forward-pointer to
    the V3.1 `TestLedgerBuilder` substrate-design FOLLOWUPS
    entry. The `Vec<Block>` signature is load-bearing — V3.1's
    substrate consumes the body without a signature change per
    the rationale recorded in the constructor's rustdoc.
  - Migrates the §5.2 hybrid retry integration test
    `hybrid_apply_scan_result_retries_on_concurrent_mutation`
    (in
    [`engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs))
    from `MockLedger::with_seed(...)` +
    `queue_concurrent_mutation()` to
    `FaultInjecting::new(LocalLedger::from_test_blocks(Vec::new()))`
    + `queue_concurrent_mutation()`. The wrapper's non-`Clone`
    posture required restructuring the assertion sites from a
    cloned handle to read-guard access through the engine's
    `Arc<RwLock<Engine<…>>>`; this is the structurally-correct
    shape (single owner per the no-Mock substrate-inheritance
    discipline).
  - Deletes `MockLedger` + `MockLedgerState` + `ROLE_LEDGER` +
    associated rustdoc + contract tests +
    `derive_seed_pinned_fixture_for_role_ledger` test from
    [`engine/test_support.rs`](../rust/shekyl-engine-core/src/engine/test_support.rs)
    (`ROLE_LEDGER` becomes dead weight because `LocalLedger`'s
    `from_test_blocks` is deterministic and consumes no seed;
    the `ROLE_DAEMON` HKDF-derivation pinned-fixture test in
    the same module covers the underlying derivation mechanism).
  - Updates the stale `MockLedger` reference in
    [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
    §1.2 (the only active-doc factual claim that named
    `MockLedger` as the current substrate; the broader
    historical references in §§4+ and the PR 2 / PR 3 design
    docs remain as historical-record prose per the
    `15-deletion-and-debt.mdc` "while we're here" discipline).

  *C6γ — `MockDaemon` → `TestDaemon` rename*:
  - Mechanical rename of the test-substitute type and every call
    site across
    [`engine/test_support.rs`](../rust/shekyl-engine-core/src/engine/test_support.rs)
    (struct, `impl Rpc`, `impl DaemonEngine`, module docstrings),
    [`engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs),
    [`engine/lifecycle.rs`](../rust/shekyl-engine-core/src/engine/lifecycle.rs),
    [`engine/mod.rs`](../rust/shekyl-engine-core/src/engine/mod.rs),
    [`benches/common/engine_fixture.rs`](../rust/shekyl-engine-core/benches/common/engine_fixture.rs)
    (forward-pointer comment), and
    [`Cargo.toml`](../rust/shekyl-engine-core/Cargo.toml)
    (`ChaCha20Rng` rationale comment).
  - Structural shape unchanged — the type is still an alternative
    real implementation that serves canned / cached test responses
    without network connectivity (per PR 3 §2.1.2's distinction
    between "alternative real implementation" and "parallel-
    implementation fake"). Only the naming changed: `TestDaemon`
    signals the role correctly per the no-Mock substrate-
    inheritance discipline.
  - Active-doc trajectory updates in
    [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
    §1.2 (Generic `DaemonClient` trajectory row), §1.4 rename-chain
    note, §6.1 hybrid-test discussion, §6.2 RNG-seed pin, §3.5
    `Rpc`-impl rationale, and the §"Linked file paths" inventory
    entry (rename chain extended: `MockRpc` → `MockDaemon` →
    `TestDaemon`).

  *Test gates (post-C6).* `cargo fmt --all -- --check` clean;
  `cargo clippy -p shekyl-engine-core --all-targets --features
  test-helpers -- -D warnings` clean; `cargo clippy -p
  shekyl-engine-core --all-targets -- -D warnings` clean
  (default features); `cargo test -p shekyl-engine-core --lib`
  152/152 pass including the migrated hybrid retry test;
  `cargo check -p shekyl-engine-core` (default + `--features
  test-helpers` + `--tests` + `--benches` + `--workspace
  --tests`) all green.

  *C7 — hybrid retry test + property tests
  (`AssertionSink` / `PanickingSink`)* (commit `c9e65bbc6`):
  - Refactors `Engine::replace_refresh` at
    [`engine/mod.rs`](../rust/shekyl-engine-core/src/engine/mod.rs)
    from a `&mut self` setter into a consume-and-rebuild
    constructor (`fn replace_refresh<R2: RefreshEngine>(self,
    refresh: R2) -> Engine<S, D, L, R2>`) mirroring the
    existing `replace_daemon` / `replace_ledger` shape at
    [`engine/lifecycle.rs`](../rust/shekyl-engine-core/src/engine/lifecycle.rs).
    The refactor lets the generic `R` type parameter change
    between construction and replacement so test orchestration
    can build an `Engine<…, LocalRefresh>` at assemble time
    and rewire it to `Engine<…, FaultInjecting<LocalRefresh>>`
    for failure-injection scenarios without going through a
    `dyn`-erased trait object.
  - Adds `AssertionSink`, `PanickingSink`, and the
    `PanickingSinkTrigger` configuration enum to
    [`engine/diagnostics.rs`](../rust/shekyl-engine-core/src/engine/diagnostics.rs),
    all gated `#[cfg(any(test, feature = "test-helpers"))]`
    per the F-Mock-1 cfg-symmetry pin. `AssertionSink` records
    emitted `RefreshDiagnostic` events for post-hoc coherence
    assertions; `PanickingSink` panics on configured trigger
    events to exercise producer panic-safety.
  - Adds `proptest = "1"` as a `dev-dependency` in
    [`rust/shekyl-engine-core/Cargo.toml`](../rust/shekyl-engine-core/Cargo.toml)
    powering the new producer property tests below.
  - Adds the hybrid retry test
    `hybrid_refresh_engine_orchestrator_cancellation_retries`
    at
    [`engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs)
    that exercises the producer-trait / orchestrator
    cancellation-checkpoint split end-to-end against the
    fully-composed `Engine<SoloSigner, TestDaemon,
    FaultInjecting<LocalLedger>, FaultInjecting<LocalRefresh>>`
    stack, verifying the orchestrator retries on
    `ConcurrentMutation` (driven by
    `FaultInjecting<LocalLedger>::queue_concurrent_mutation`)
    and surfaces cancellation cleanly when
    `FaultInjecting<LocalRefresh>` injects
    `RefreshError::Cancelled`.
  - Adds the `producer_property_tests` module at
    [`engine/local_refresh.rs`](../rust/shekyl-engine-core/src/engine/local_refresh.rs)
    with five parametric coherence tests, one
    `proptest!`-driven fuzz test
    (`coherence_proptest_fuzz_chain_and_injection`) exercising
    randomized chain length + failure-injection scenarios,
    four panic-safety tests verifying clean unwind through
    `PanickingSink` panics across `DaemonMalformed` /
    `DaemonProtocolError` / `ScanProgress` / `Any` triggers
    plus a recovery test, and a classifier sanity test. The
    coherence tests exercise the §5.4.6 emission/return
    coherence pin: every non-`Cancelled` `RefreshError` is
    preceded by a corresponding `RefreshDiagnostic` emission.
    The panic-safety tests verify the §5.4.6 producer-side
    robustness property: `Scanner` zeroizes cleanly via
    `Drop` across a panicking `emit`, cancellation-token
    state remains well-defined, and the refresh attempt
    fails predictably without corrupting interior state.
    Tests are deterministic via a compile-time-generated
    `PROPERTY_TEST_MASTER_SEED` and `#[tokio::test(start_paused
    = true)]` for fake-time async scheduling.

  *Test gates (post-C7).* `cargo fmt --all -- --check` clean;
  `cargo clippy -p shekyl-engine-core --all-targets --features
  test-helpers -- -D warnings` clean; default-feature clippy
  clean; `cargo test -p shekyl-engine-core --features
  test-helpers --lib` 170/170 pass (152 → 170: +18 C7 tests);
  `cargo doc -p shekyl-engine-core --features test-helpers
  --no-deps` green with no new doc warnings (pre-existing
  intra-doc-link warnings to private items are baseline and
  unrelated to C7 changes).

  *C8 — docs propagation* (this commit):
  - This CHANGELOG entry extended with the C7 sub-section
    above and the C8 sub-section here.
  - [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
    gains the Phase-1-landed Status-banner closure paragraph
    enumerating C0–C8 landing SHAs; §7.X gains per-`Commit
    Cn` `Landed:` lines anchoring each commit's SHA inline
    next to the design-time prose.
  - [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](V3_ENGINE_TRAIT_BOUNDARIES.md)
    §2.3 past-tenses the "Stage 1 surface" header and cross-
    references the as-landed implementation locators
    (`engine/traits/refresh.rs`, `engine/diagnostics.rs`,
    `engine/local_refresh.rs`, `engine/mod.rs`,
    `engine/fault_injecting_refresh.rs`,
    `engine/fault_injecting_ledger.rs`) with their commit
    SHAs (C1 / C2 / C4 / C5a / C6α / C6β).
  - [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) gains a Phase 0d
    explicit retirement note ("struck, not deferred") at the
    top of the V3.x section, distinguishing the Round 2
    composition reframe's struck-candidate from the live
    R5 / R6 / R4 (c) V3.x consumer-actor deferrals that
    remain open per Round 3's prior amendments. The pre-
    existing closed-entries for Mock-X cleanup
    (`MockLedger` → `FaultInjecting<LocalLedger>` +
    `LocalLedger::from_test_blocks` and `MockDaemon` →
    `TestDaemon`) carry the `[CLOSED 2026-05-20]` marker
    from C6β / C6γ landing and are unchanged in C8.

  *C9 — FOLLOWUPS P1 / P2 / P3 re-anchor post-Phase-1
  landing* (this commit):
  - Doc-only follow-up commit; not in the original Round 4
    C0–C8 decomposition but added post-PR-open per the
    user-directed "correct known document errors within the
    current PR" trigger (per
    [`.cursor/rules/91-documentation-after-plans.mdc`](../.cursor/rules/91-documentation-after-plans.mdc)'s
    stale-doc detection discipline and
    [`.cursor/rules/15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)'s
    "deferred without a named home is the failure mode"
    framing). Surfaced during a post-C8 review of
    `docs/FOLLOWUPS.md` against the actual code state in
    `engine/local_ledger.rs:356–367` (trait-method
    `apply_scan_result` discards `Vec<usize>` and short-
    circuits `populate_engine_handle_fields`) and
    `engine/merge.rs:181–215` (inherent
    `Engine::apply_scan_result` runs the post-pass against
    the captured `inserted` indices) — the two paths diverge
    by construction in the post-Phase-1 substrate.
  - [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) P1 / P2 / P3 entries
    rewritten with **Post-PR-4-Phase-1 substrate** subsections
    + substrate-anchored reopening criteria per
    [`.cursor/rules/21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc).
    The pre-Phase-1 "defer to PR 4" dispositions all assumed
    α/β/γ Round 1 would reshape the producer/consumer pattern
    and the `LedgerEngine::apply_scan_result` trait surface,
    absorbing P1 / P2 / P3 as a side effect. Phase 1 settled
    on α (preserved current shape; trait surface unchanged) per
    `STAGE_1_PR_4_REFRESH_ENGINE.md` §5.4 Round 1, and did not
    absorb the three items. P1's hard precondition ("PR 4
    lands before any binary integrates `RefreshHandle`")
    survives intact and is restated as "P1 closes before any
    binary integrates `RefreshHandle`". Each entry's
    re-anchored disposition names a focused follow-up PR
    landing V3.0 pre-genesis: P1 →
    `refresh/p1-async-path-post-pass` (two candidate
    closing shapes both feasible against the post-Phase-1
    substrate — shape (b) `RefreshEngine` owns the merge
    post-pass is newly available because PR 4 landed the
    `RefreshEngine` trait at C1 / C4); P2 →
    `refresh/p2-wallet-birthday-plumbing` (substrate
    well-defined: `LocalRefresh::new` is the V3.0 production
    implementor per C4 = `ac100e1ab`); P3 → downstream of
    P1, closes alongside P1 in the same focused PR (both
    candidate P1-closing shapes close P3 as a side effect;
    P3 stays catalogued separately to preserve the Copilot
    PR #37 audit trail).
  - [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
    §5.5 named-home table rows P1 / P2 / P3 updated with a
    bold **Phase 1 landed without absorption** marker plus
    one-sentence cross-refs to the re-anchored FOLLOWUPS
    dispositions, preserving the §5.5 audit-trail discipline
    per `15-deletion-and-debt.mdc`.
  - `STAGE_1_PR_4_REFRESH_ENGINE.md` §7.X Status banner
    extended to enumerate C9 alongside C0–C8; the same §7.X
    gains a new `**Commit C9 — FOLLOWUPS P1 / P2 / P3
    re-anchor post-Phase-1 landing**` block documenting
    design-time intent and landing SHA, mirroring the
    per-commit documentation pattern from C0–C8.
  - Gate inheritance from C8: C9 is doc-only, so
    `cargo fmt --check`, `cargo clippy -- -D warnings`,
    `cargo test --lib`, and `cargo doc --no-deps` all
    inherit C8's results unchanged (170 / 170 lib tests
    pass; fmt clean; clippy clean under both default and
    `test-helpers` features; 48 doc warnings unchanged at
    the C7 baseline).

  *C10 – C13 — Copilot post-PR-open review responses*:
  - Four small post-PR-open commits closing the nine
    line-anchored findings the GitHub Copilot review raised
    against `95affda61` (C8 head before C9 push) on PR #60.
    Each commit is scoped to a single concern (file +
    correction class) per
    [`.cursor/rules/90-commits.mdc`](../.cursor/rules/90-commits.mdc)'s
    scope-per-commit discipline; each commit cites its
    Copilot finding IDs in the commit message body. Doc-only
    / harness-only; no API surface, no trait body, and no
    production code-path touched.
  - **C10** `60f401e77` — scanner rustdoc fn-name
    corrections in
    [`rust/shekyl-scanner/src/scan.rs`](../rust/shekyl-scanner/src/scan.rs).
    Six sites updated from pre-C4 `scan_transaction` to
    C4-landed `scan_transaction_with_cancel`, plus the
    gate-test rustdoc return-type updated from
    `Ok(Timelocked::empty())` to
    `Ok(ScanOutcome::Completed(Timelocked(empty)))` to match
    the actual `ScanOutcome` variant the gate returns.
    Closes Copilot finding IDs 3278232594 / 3278232649 /
    3278232666 / 3278232686 plus two same-class adjacent
    sites discovered during the audit.
  - **C11** `949e42bd8` — `bench_fixtures` rustdoc fact-fix
    in
    [`rust/shekyl-scanner/src/bench_fixtures.rs`](../rust/shekyl-scanner/src/bench_fixtures.rs).
    The `make_bench_wallet` spend-secret comment cited the
    on-chain spend point as the basepoint when
    `fake_spend_key_bytes()` actually returns `2 * G`. The
    `fake_spend_key_bytes()` rustdoc opening was internally
    contradictory and is rewritten as a clean three-property
    justification (torsion-free; non-default; distinct from
    `G`). Behaviour unchanged — `fake_spend_key_bytes()`
    body still returns `(2 * G).compress().to_bytes()`
    byte-identically; F11-S cold-cache audit-trail
    unaffected. Closes Copilot finding IDs 3278232628 /
    3278232770.
  - **C12** `20b082a38` — refresh-trait checkpoint-list
    temporal-firing-order explanation in
    [`rust/shekyl-engine-core/src/engine/traits/refresh.rs`](../rust/shekyl-engine-core/src/engine/traits/refresh.rs).
    The `RefreshEngine` trait rustdoc lists checkpoints in
    temporal-firing order (1 → 2 → 3 → 5 → 4) rather than
    numeric order. Copilot read this as out-of-order, but
    the numbering is repo-wide audit-trail convention
    preserving "checkpoint 5 added per PR 4 Round 4 F2".
    Synchronized renumbering would touch 12+ cross-reference
    sites and dissolve the F2-audit-trail provenance;
    rejected per
    [`.cursor/rules/21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)'s
    substrate-anchored disposition. Fix applied: add an
    explanatory paragraph to the trait rustdoc that names
    the temporal-firing-order convention explicitly so the
    question isn't re-litigated. Closes Copilot finding ID
    3278232791.
  - **C13** `262ece667` — scan-transaction warm-cache bench
    harness clone-out-of-timed-region fix in
    [`rust/shekyl-scanner/benches/scan_transaction.rs`](../rust/shekyl-scanner/benches/scan_transaction.rs).
    Both warm-cache benchmark variants used
    `iter_batched_ref` with an in-routine
    `mem::replace(b, block.clone())`, placing
    `ScannableBlock::clone` inside the timed region.
    Switched to `iter_batched(|| block.clone(), |block|
    scanner.scan(block), ..)` so the clone is in the setup
    closure and only `Scanner::scan` is measured. **F11-S
    audit-trail impact: ZERO** — the F11-S binding
    measurement (per
    [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
    §3.1 / §5.4.9 / §7.Y) is anchored on the cold-cache
    N=16 worst-case p99 (12.95 ms per-tx / 819 µs
    per-output), and the cold variant was already
    methodologically correct (all setup outside the timed
    region). Captured F11-S numbers at `a4da2212a` and the
    C4 per-output safe-point disposition stand without
    revision. Closes Copilot finding IDs 3278232713 /
    3278232736.
  - Gates per commit: each commit ran its scoped bisection-
    discipline gates against the affected crate
    (`shekyl-scanner` for C10 / C11 / C13;
    `shekyl-engine-core` for C12). Test counts and doc-
    warning baselines unchanged: 57 / 57 scanner lib tests
    pass; 170 / 170 engine-core lib tests pass; scanner doc
    warnings = 2 (C8 baseline); engine-core doc warnings =
    49 (C9 baseline). C13 additionally ran
    `cargo check --benches` to confirm the bench targets
    compile under the new `iter_batched` shape.

  *C14 — `[Unreleased]` doc-after-plans propagation for
  C10 – C13* (this commit):
  - Doc-only follow-up commit per
    [`.cursor/rules/91-documentation-after-plans.mdc`](../.cursor/rules/91-documentation-after-plans.mdc)'s
    final-task-always rule. After C10 / C11 / C12 / C13
    landed locally with green gates, the design doc §7.X
    Status banner (line ~478) was extended to enumerate
    C10 – C13 alongside C0 – C9 with landing SHAs and
    per-commit one-paragraph summaries, and the §7.X
    commit-block section gained a new
    `**Commits C10 – C13 — Copilot post-PR-open review
    responses.**` block with the same per-commit prose +
    F11-S impact statement + gate evidence. The C9 block's
    placeholder `**Landed: this commit**` was replaced with
    the landed SHA `839c4bbfd`. This `*C10 – C13 — Copilot
    post-PR-open review responses*` subsection above is
    the matching CHANGELOG entry; the doc-after-plans
    propagation also updates the closing C0–C13 paragraph
    below.
  - Gate inheritance from C13: C14 is doc-only, so the
    `cargo fmt --check`, `cargo clippy --all-targets --
    -D warnings`, `cargo test --lib`, and `cargo doc --no-
    deps` gates all inherit C13's results unchanged
    (no rust files touched in C14).

  PR 4 §7.X commits C0 through C14 are now all landed; PR
  #60 carries the full C0–C14 set. See the separate `###
  Added` and `### Changed` entries below for the trait-
  surface and `Engine<S, D, L, R>` four-parameter additions
  PR 4 ships,
  per the C8 spec at `STAGE_1_PR_4_REFRESH_ENGINE.md` §7.X
  C8.

- **RandomX v2 — Phase 1: pinned submodule + out-of-tree build wiring**
  (`feat/randomx-v2-phase1`, PR #54, merge commit `c0c4a11e5`,
  2026-05-19). Adds `external/randomx-v2` submodule pinned to
  Shekyl-Foundation/RandomX SHA
  `aaafe71322df6602c21a5c72937ac284724ae561` (v2.0.1 release;
  identical to `tevador/RandomX:master` at pin time, per the
  dependency-discipline verification in
  `docs/design/RANDOMX_V2_PHASE1_PLAN.md` §1.3). Adds
  `BUILD_RANDOMX_V2_MINER_LIB` CMake option (default `OFF`). When
  `ON` on a single-config generator (Ninja, Make), an
  `ExternalProject_Add` block in `external/CMakeLists.txt` builds
  the v2 fork out-of-tree under
  `${CMAKE_BINARY_DIR}/external/randomx-v2-build/` and exposes the
  `shekyl_randomx_v2` `IMPORTED` static-library target plus its
  include directory. The block forwards the standard CMake
  cross-build knobs (toolchain file, sysroot, Apple/Android
  settings, system name/processor, compiler launchers) to the
  sub-build via a semicolon-safe `LIST_SEPARATOR`-based forwarding
  pattern. On multi-config generators (MSVC, Xcode, Ninja
  Multi-Config) the option fails with a `FATAL_ERROR` directing
  the developer to `-G Ninja` plus an explicit
  `-DCMAKE_BUILD_TYPE`; per-`CONFIG` wiring is the V3.x Phase 2
  FOLLOWUPS item alongside the first real consumer. The
  out-of-tree build pattern avoids the target-name collision with
  `external/randomx` (v1.2.1), which declares the same
  `project(RandomX)` and `add_library(randomx ...)` symbols; see
  `RANDOMX_V2_PHASE1_PLAN.md` §2 for the collision analysis and
  disposition rationale. No Shekyl C++ consumer links the new
  target in this PR; first consumers are Phase 2 cross-check
  tests against the canonical v2 implementation (the new Rust
  crate `rust/shekyl-pow-randomx/`) and Phase 3's miner cutover.
  The existing `external/randomx` (v1.2.1 at `102f8acf`) is
  unchanged; the v1 fallback path per
  `docs/design/RANDOMX_V1_FALLBACK.md` §1 remains reachable. See
  `docs/design/RANDOMX_V2_PHASE1_PLAN.md` for the full scope, the
  `ExternalProject_Add` configuration rationale, the build-smoke
  test results, the §10 implementation-time dispositions (D1
  `check_submodule` omission, D2 multi-config fail-fast, D3
  toolchain forwarding expansion, D4 semicolon-escape), and the
  reversibility plan.

- **LWMA-1 difficulty-adjustment migration — Phase 4 C++ cutover**
  (`feat/daa-lwma1-phase4`, 2026-05-18). Lands the consensus-atomic
  cutover from the inherited CryptoNote cut-windowed-average DAA to
  LWMA-1, plus the two paired FTL/MTP value changes, in a single PR
  invoking `07-consensus-atomic-cutovers.mdc`. The PR contains
  eleven commits that respect single-purpose scope per
  `90-commits.mdc`; the eleven-commit structure is the
  pre-flight-disposed shape (`docs/design/DAA_LWMA1_PHASE4_PREFLIGHT.md`
  §18). Closes work-items 1–14 of `docs/design/DAA_LWMA1_PLAN.md`
  Phase 4 and the V3.0 DAA item in `docs/FOLLOWUPS.md`.

  *Consensus-rule deltas* (the load-bearing changes a validator must
  agree on):

  - **DAA**: `Blockchain::next_difficulty` (CryptoNote
    cut-windowed-average, `DIFFICULTY_WINDOW=720`,
    `DIFFICULTY_LAG=15 // !!!`, `DIFFICULTY_CUT=60`) is replaced by
    LWMA-1 from
    [`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3)
    with `N=90`, `T=120s`, `GENESIS_DIFFICULTY=100`. The FFI
    surface (`shekyl_difficulty_lwma1_next`) is wrapped at the
    three `Blockchain` call sites
    (`get_difficulty_for_next_block`, `recalculate_difficulties`,
    `get_next_difficulty_for_alternative_chain`) by the
    `lwma1_next_difficulty` helper in `blockchain.cpp`, which
    throws `cryptonote::difficulty_computation_error` (declared in
    `src/cryptonote_core/difficulty_engine_error.h`) on non-zero
    FFI return codes.
  - **FTL**: `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT` (`60*60*2` = 7200s)
    becomes `SHEKYL_DAA_FTL_SECONDS` = 540s (zawy12-required
    `N*T/20`). Tightens by 13.3×; reorgs more than 9 minutes deep
    on local-clock disagreement are no longer accepted.
  - **MTP**: `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` = 60 becomes
    `SHEKYL_DAA_MTP_WINDOW` = 11. Tightens back from the Monero-era
    widening to the CryptoNote-original window.

  *Mechanical rewires* (value-preserving):

  - `DIFFICULTY_TARGET_V2` (120s) consumers across the daemon,
    wallet, RPC, and tests are rewired to
    `SHEKYL_DAA_TARGET_SECONDS` (also 120s). 8 production sites
    and 5 test sites; verified by the consensus-invariants gate
    (`scripts/ci/check_consensus_invariants.sh` invariant 3).
  - `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2` is preserved
    with its RHS rewired from `DIFFICULTY_TARGET_V2` to
    `SHEKYL_DAA_TARGET_SECONDS`; two live consumers
    (`blockchain.cpp:4043`, `wallet2.cpp:7330`) are unaffected.
  - `DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN` (60s V1 alias used by
    tests as a generic "block time" multiplier) is replaced by
    `SHEKYL_DAA_TARGET_SECONDS` (120s) at 4 non-deletion test
    files (`bulletproof_plus.cpp`, `chaingen.cpp`,
    `transactions_flow_test.cpp`,
    `block_validation.cpp:267`). Semantic shift: 60s base → 120s
    base for tests' block-time approximation, matching the actual
    block rate.

  *Deletions*:

  - Seven inherited `#define`s removed from
    `src/cryptonote_config.h`: `DIFFICULTY_TARGET_V[12]`,
    `DIFFICULTY_WINDOW`, `DIFFICULTY_LAG` (with its `// !!!`
    warning), `DIFFICULTY_CUT`, `DIFFICULTY_BLOCKS_COUNT`,
    `DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN`. The V1 lock-delta
    `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1` is removed
    (pre-genesis Monero behavior, dead under
    `60-no-monero-legacy.mdc`).
  - `next_difficulty` and `next_difficulty_64` deleted from
    `src/cryptonote_basic/difficulty.{h,cpp}` (surgical, per the
    pre-flight's drift-F6 amendment: the `check_hash` PoW family
    in the same file is retained with ~12 live production
    consumers).
  - `tests/difficulty/{difficulty.cpp,data.txt,generate-data,gen_wide_data.py,wide_difficulty.py}`
    deleted (~23 KB) — exercised the now-deleted CryptoNote DAA;
    the `lwma1-cross-check` harness (Phase 2 vintage) is retained
    in `tests/difficulty/CMakeLists.txt`.
  - `lift_up_difficulty` helper plus `gen_block_invalid_nonce`
    and `gen_block_invalid_binary_format` test classes removed
    from `block_validation.{cpp,h}` (V1-only fixtures, already
    disabled in the test driver).

  *Regression tests added*:

  - `tests/unit_tests/rpc_target_wire_contract.cpp` — pins the
    public JSON-RPC wire contract for `mining_status.block_target`
    and `get_info.target` at `120`. Both gtests plus the
    `static_assert(SHEKYL_DAA_TARGET_SECONDS == 120, …)` static
    pin remain after the cutover.
  - `tests/unit_tests/stall_detection_calibration.cpp` — pins the
    daemon's stall-detection calibration: 1/7200 false-positive
    threshold, `{45, 30, 15, 10, 5}` expected-block counts across
    the five Poisson windows, and the zero-blocks-tail-probability
    boundary (the 600s window must NOT trip at λ=5; the four
    longer windows must trip at λ ≥ 10).

  *CI gate added*:

  - `.github/workflows/consensus-invariants.yml` plus
    `scripts/ci/check_consensus_invariants.sh` — three
    source-level grep invariants (no live consumers of the
    deleted DAA functions; no C-ABI in `rust/shekyl-difficulty`;
    no orphaned references to the deleted `#define`s).
    Shared landing pad for the upcoming RandomX v2 Phase 2f
    symbol-isolation checks. Binary-level `nm`-on-`shekyld`
    verification is a deferred enhancement (recorded in this
    entry as a follow-up below).

  *Pre-flight drift findings closed*:

  - **F1** — surgical (not wholesale) deletion of
    `tests/difficulty/`; the `lwma1-cross-check` harness stays.
  - **F2** — `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2`
    preserved with rewired RHS (option B); `_V1` deleted.
  - **F3** — V1 `next_difficulty(...)` fixtures in
    `block_validation.cpp` deleted along with the helper that
    drove them.
  - **F4** — `DIFFICULTY_TARGET_V2` consumer count corrected from
    "~14 sites across 9 files" to the actual 8 production + 5
    test sites enumerated by the commit-6 sweep.
  - **F5** — `DIFFICULTY_TARGET_V2` consumer **undercount in
    `blockchain.cpp`**: the plan's §9.7 enumeration missed two
    sites at lines 4239 / 4243 (an MTP-window correction and a
    `timestamps.back() + DIFFICULTY_TARGET_V2` adjustment inside
    `check_block_timestamp`); both rewired to
    `SHEKYL_DAA_TARGET_SECONDS`. `wallet2.cpp`'s lines 181, 182,
    5975, 11548 were never drift — the earlier text mis-attributed
    F5 to `wallet2.cpp`; corrected 2026-05-18 per PR #53 Copilot
    review C-6.
  - **F6** — surgical (not wholesale) deletion of
    `src/cryptonote_basic/difficulty.{h,cpp}`: the `check_hash`
    PoW-validation family is retained; only the
    `next_difficulty` family is deleted.
  - **F7** — `check_difficulty_checkpoints()` is NOT a deletion
    target. Pre-flight §14 (and `DAA_LWMA1.md` §7.1) erroneously
    enumerated it as a symbol-isolation deletion candidate. The
    function in `blockchain.cpp:1066` is a checkpoint-cumulative-
    difficulty comparison independent of the deleted DAA functions;
    retained. The spec doc and pre-flight are amended in this
    commit.

  *Reviewer-map structure* (per
  `07-consensus-atomic-cutovers.mdc` sub-clause 4.3):

  - **A. Consensus-affecting changes** (priority attention):
    `blockchain.cpp` DAA rewires (commit 3), FTL rewires
    (commit 4), MTP rewires (commit 5), `cryptonote_config.h`
    deletions (commit 7), `difficulty.cpp` deletions (commit 8).
  - **B. Mechanical rewires** (value-unchanged):
    `DIFFICULTY_TARGET_V2` → `SHEKYL_DAA_TARGET_SECONDS` (commit
    6), `DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN` rewires in tests
    (commit 7).
  - **C. Deletions**: legacy DAA tests + V1 fixtures (commit 9).
  - **D. New artifacts**: regression tests (commits 1, 2),
    CI gate (commit 10), this changelog entry (commit 11).

  *Rollback procedure* (per sub-clause 4.4):

  If consensus breaks post-merge, the reversion is to revert the
  merge commit on `dev` (single non-FF merge per
  `06-branching.mdc`) and re-tag. Because the cutover is atomic
  (FTL/MTP/DAA all in one PR), no partial reversion is required.
  The pre-merge state of `blockchain.cpp`'s three
  `next_difficulty` call sites, the FTL/MTP consumer surfaces,
  and the deleted `#define`s are all captured in the pre-cutover
  `dev` SHA recorded in the PR description; reverting the merge
  restores them byte-identically.

  *Follow-up*: binary-level `nm shekyld | rg -q '^.* (T|U)
  (next_difficulty_64|next_difficulty)\b'` symbol-isolation check.
  Source-level grep (this PR's invariant 1) is a necessary
  precondition for binary absence; the binary-level check is a
  deferred enhancement when CI is restructured to expose the
  linked daemon binary to a post-link grep step. Tracked in
  `docs/FOLLOWUPS.md`.

- **LWMA-1 difficulty-adjustment migration — Phase 0 design docs**
  (`feat/daa-lwma1-phase0-design`, 2026-05-17). Adds two Phase 0
  design documents under `docs/design/`:
  [`DAA_LWMA1.md`](./design/DAA_LWMA1.md) (the primary design) and
  [`DAA_LWMA1_PLAN.md`](./design/DAA_LWMA1_PLAN.md) (the phased
  execution plan, five phases sequential, no parallel tracks). The
  primary design records the disposition to replace the inherited
  CryptoNote cut-windowed-average DAA (`src/cryptonote_basic/difficulty.cpp`,
  `DIFFICULTY_WINDOW=720`, `DIFFICULTY_LAG=15` with literal `// !!!`
  warning, `DIFFICULTY_CUT=60`) with LWMA-1 from zawy12's canonical
  reference at
  [`zawy12/difficulty-algorithms#3`](https://github.com/zawy12/difficulty-algorithms/issues/3),
  implemented as a Rust crate `shekyl-difficulty` per
  `20-rust-vs-cpp-policy.mdc` rule 2 (cryptographic-contract surface).
  Concrete parameter selection: N=90 (zawy12 canonical for T=120s),
  T=120s (inherited), GENESIS_DIFFICULTY=100 (proposed), FTL=N\*T/20=540s
  (zawy12-required, replaces inherited 7200s), MTP=11 (Cryptonote default
  unchanged). The design pins genesis-time landing per
  `16-architectural-inheritance.mdc` pre-genesis discount and
  `60-no-monero-legacy.mdc` no-version-dispatch rule. Sibling track to
  RandomX v2 but **independent**: math-orthogonal (DAA operates on
  `(timestamps, cum_difficulties)`; PoW changes the hash function),
  no wallet V3.2 gate applies, no Monero release-time audit dependency.
  A pre-design `rust/shekyl-difficulty/src/lwma1.rs` sketch is explicitly
  documented as **not** canonical (different formula, missing `6*T`
  solvetime clamp, missing `N*N*T/20` minimum-L floor, missing `99/200`
  bias factor) and was **deleted** during Phase 0 so Phase 1 starts from
  an empty crate directory; the divergence catalogue is retained in
  `DAA_LWMA1.md` §2.4 as the design record of why each non-canonical
  shape is rejected.
  Reversion clauses per `21-reversion-clause-discipline.mdc` cover
  LWMA-2/3/4 and ASERT reopening criteria.

  *Round 2 review update (2026-05-17):* (a) reframes `shekyl-difficulty`
  as a **leaf crate** with zero internal workspace dependencies per
  `18-type-placement.mdc`, with FFI exposure routed through `shekyl-ffi`
  (`DAA_LWMA1.md` §2.1); (b) records the explicit "DAA is a primitive,
  not an actor" disposition (`DAA_LWMA1.md` §2.7) — `lwma1_next` is a
  free function plus typed constants plus the FTL/MTP predicates, no
  `DifficultyEngine` actor wrapper; (c) pivots the consensus-constants
  source-of-truth from a `cbindgen` handwave to the existing
  `config/consensus_constants.json` JSON-authority pattern documented
  in `docs/FOLLOWUPS.md` and the 2026-05-05 FFI constant-drift audit
  (`DAA_LWMA1.md` §4, plan Phase 1 task); (d) adds a chain-state-
  ownership disposition (`DAA_LWMA1.md` §17) acknowledging that
  daemon-side LMDB chain state remains in C++ `Blockchain` through
  Phase 4 and that no Rust crate owns daemon-side chain state today;
  the future Rust validator actor will consume the same DAA transform
  without changes to the DAA crate.

  *Round 3 review update (2026-05-17):* (a) corrects the
  contradictory dispositions for `DIFFICULTY_TARGET_V2` — design doc
  §9.2 now matches the plan's delete-not-rename directive (rename
  would preserve the hand-maintained `#define` drift class the JSON
  authority exists to close); (b) corrects two real factual errors
  surfaced by a Round 3 reconnaissance grep of the C++ tree: the
  constant is `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT` (not
  `BLOCK_FUTURE_TIME_LIMIT`; there is no `_V2` variant), and
  `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW` is currently `60` (Monero-era
  widening from the CryptoNote-original `11`), so the LWMA-1
  disposition is a tightening — not preservation — from 60 back to
  11; (c) adopts algorithm-version-free naming for the JSON keys
  (`daa_window_n`, etc.) and the generated C++ symbols
  (`SHEKYL_DAA_*`, not `SHEKYL_DAA_LWMA1_*`) so a future §10
  reversion doesn't require renaming every consumer; (d) enumerates
  the full Phase 4 consumer surface in new sections §9.5
  (`CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT`: 2 sites), §9.6
  (`BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW`: 9 sites), and §9.7
  (`DIFFICULTY_TARGET_V2`: ~14 sites across 9 files), and adds §9.8
  to flag the `core_rpc_server.cpp:1452 res.block_target` RPC-contract
  preservation property; (e) acknowledges Phase 4 atomicity as a
  deliberate exception to `06-branching.mdc` (FTL/MTP value changes
  cannot stage behind alias `#define`s without weakening consensus
  in the intermediate state); (f) resolves the bias-factor location
  drift — `99` and `200` (plus `6` and `1/20`) appear as bare
  integer literals inside `src/lwma1.rs` to match canonical zawy12
  verbatim, **not** as named `pub(crate) const` in `consts.rs`;
  (g) mechanizes Phase 5's conditional cross-reference to
  `24-reviewer-discipline.mdc` so the Phase 5 reviewer can verify by
  grep; (h) closes open question #3 (build.rs location) as Option A
  per the leaf-crate property in §2.1; (i) adds a `solvetime[1]`
  `-T` offset regression vector to §8.1's required-vector list;
  (j) adds explicit MIT attribution to the Phase 2 vendored
  `tests/difficulty/zawy12_lwma1_reference.h`; (k) moves long
  reviewer-note prose out of the long-lived `Cargo.toml` into a
  Phase 1 review-checklist section; (l) flags `is_above_mtp`'s
  `&[u64; 11]` vs slice ergonomics as a Phase 1 implementation
  choice (not a Phase 0 blocker); (m) adds canonical line-number
  stability caveats to §5.3 step 7 and step 8 (line numbers are
  stable only against the Phase 2 pinned-spec revision);
  (n) updates Phase 4 work-item count from 11 to the actual 14.

  *Round 4 review update (2026-05-17):* (a) pivots the FFI ABI for
  difficulty values from `u128` / `__uint128_t` to canonical
  little-endian `[u8; 16]` byte arrays (`DAA_LWMA1.md` §6.1 and
  plan Phase 3). Rationale: Rust's `u128` C ABI was unsound on
  several targets until rustc 1.77 (March 2024) and remains a
  target-portability footgun on uncommon platforms; for a
  consensus-critical surface that's unacceptable. Explicit byte
  arrays match the FCMP++ and KEM-derivation FFI precedent already
  in the workspace and immunize the boundary against
  target-dependent ABI surprises. C++ consumers memcpy between
  their native `uint128_t` and the canonical-LE buffer at every
  call site so the endianness assumption is a deliberate checkpoint
  rather than an implicit invariant.
  (b) **Consensus-correctness fix to §8.1 test vectors.** The
  Round 3 vector "perfectly stable hashrate produces
  `next_D == avg_D` (within rounding)" was mathematically wrong:
  with `solvetime[i] == T` for all `i`, the formula yields
  `next_D == avg_D * 99 / 100` — a deliberate 1 % downward bias,
  which is the point of the `99/200` factor per §5.3 step 7's
  derivation. The Round 3 expectation invited three implementer
  failure paths (relax tolerance to absorb the 1 % shift; remove
  the bias from the algorithm to satisfy the test; misread
  "rounding" as ±1 %). Round 4 replaces all `≈`-shaped vectors
  with concrete numerical tuples: stable hashrate → `0.99 * avg_D`,
  2× hashrate increase → `1.98 * avg_D`, 2× hashrate decrease →
  `0.495 * avg_D`, minimum-L floor (all solvetimes == 1) →
  `~10.01 * avg_D`. Tuples are derived analytically from §5.3
  and force the Phase 1 implementer to confront the bias at
  design time, not at debug time. Also corrects an off-by-one in
  §2.6's "first N+1 blocks" framing (canonical's `height < N`
  short-circuit covers N blocks, not N+1; the Shekyl FFI
  `chain_height < N` translation puts blocks `1..=N` in the
  short-circuit per the new §5.6 validator consumer contract).
  (c) Adds `DAA_LWMA1.md` §5.6 "Validator consumer contract:
  `chain_height → header.difficulty`" specifying the off-by-one
  mapping between the DAA function's `chain_height` parameter
  (predecessor's height) and the block-being-validated's height,
  plus the per-block disposition: block 0 (genesis) is exempt;
  blocks `1..=N` carry `GENESIS_DIFFICULTY`; blocks `≥ N+1` are
  algorithm-computed. Pre-empts the Phase 4 reviewer's first
  question.
  (d) **Closes all Phase 0 open questions.** `GENESIS_DIFFICULTY =
  100` and `N = 90` are ratified zawy12 canonical with reversion
  triggers in §10 covering simulation-driven change; the
  "Shekyl-empirical RandomX v2 single-CPU measurement" alternative
  referenced a measurement that cannot exist until RandomX v2
  ships and is functionally identical to the §10 reversion trigger
  already in place. Phase 2 cross-check harness language closed as
  C++ test target (the canonical reference is C++; consuming
  it directly is simpler than Rust-side vendoring; the alternative
  was a cosmetic preference). Build.rs location (Option A) and
  JSON-key naming (`daa_*` algorithm-version-free) were already
  closed in Round 3 and are restated for completeness. No open
  questions are carried into Phase 1; the design-rounds-in-
  implementation-PR anti-pattern is closed at Phase 0.
  (e) Adds three LWMA1_() disambiguation anchors to `DAA_LWMA1.md`
  §3 and plan Phase 2: byte-offset range, first-line, last-line.
  zawy12 Issue #3 contains four LWMA reference functions
  (`LWMA1_/2_/3_/4_`); §5.3's "Issue #3, lines N–M" citations are
  otherwise ambiguous and would break Phase 2 cross-check at the
  smallest upstream reordering.
  (f) Reframes `T = 120 s` as Shekyl's chosen target block time
  (zawy12 LWMA-1 recommends 60–120 s for CPU-mineable chains)
  rather than "inherited from CryptoNote `DIFFICULTY_TARGET_V2`."
  The numerical value matches; the source-of-truth is the JSON
  authority `daa_target_seconds`, not the inherited `#define`.

  *Round 5 review update (2026-05-17):* (a) **FFI ABI pivot
  from `[u8; 16]` byte arrays to `#[repr(C)] struct ShekylU128
  { lo: u64, hi: u64 }`.** Round 4 named the `u128` ABI
  unsoundness as a Tier 1 blocker but stopped short of
  proposing the specific wire representation. Round 5 closes
  this. `ShekylU128` decomposes the 128-bit value into two
  `u64` fields whose ABI is universally stable on every Shekyl-
  supported target — no `improper_ctypes` exposure, no
  MSRV-pin-to-1.78 constraint, no per-target ABI verification
  matrix. The struct-with-named-fields shape preserves explicit
  `lo`/`hi` semantics (debugger-friendly, unambiguous, survives
  any future endianness disposition because the field meaning
  is carried by the field name). Endianness is consensus-locked
  in `DAA_LWMA1.md` §6.1: `ShekylU128` is little-endian by
  field semantics — `lo` is the low 64 bits, `hi` is the high
  64 bits, reconstruction is `value = (hi as u128) << 64 | (lo
  as u128)`. Cost: one struct definition and four lines of
  `From` impls per direction. Benefit: the consensus-critical
  surface is immune to `u128`-ABI target-portability issues
  permanently, not just on rustc ≥ 1.77.
  (b) **MTP 60 → 11 trade-off framing.** The
  `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW = 60` → `SHEKYL_DAA_MTP_WINDOW
  = 11` change travels in opposite directions on two security
  axes simultaneously and a release-note skimmer reading the
  value change in isolation would misread it as a security
  regression. Surfaced explicitly: the **MTP-only timestamp-
  attack defense weakens** (it is easier for an adversary to
  satisfy "strictly greater than the median of 11 timestamps"
  than "strictly greater than the median of 60 timestamps"
  in isolation), and the **LWMA-1-coupled defense engages**
  (the canonical zawy12 math is calibrated against MTP = 11,
  not MTP = 60; running LWMA-1 with MTP = 60 would understate
  the algorithm's solvetime-clamp resistance). `DAA_LWMA1.md`
  §5.5 names all three checks (MTP + FTL + solvetime-clamp)
  as *jointly* load-bearing — the combined defense profile
  post-Phase-4 is stronger than either the pre-Phase-4
  MTP=60-only profile or a hypothetical LWMA-1-with-MTP=60
  configuration. The value change is the cost of moving from a
  MTP-only-anchored defense to the canonical zawy12-coupled
  defense; it is not a unilateral loosening.
  (c) **RPC-contract preservation regression test (§9.8).** The
  byte-identity assertion is now explicit: a wallet calling
  `get_info` against the post-Phase-4 daemon receives a
  `block_target` field that is **byte-identical** to the same
  wallet's response against the pre-Phase-4 daemon (captured
  as a fixture at PR-open). The value-identity assertion
  (`120 == 120`) catches value drift; the byte-identity
  assertion catches encoding drift (a future "change varint
  encoding to little-endian byte array" refactor would
  preserve the numeric value but break the wire contract). Both
  are required to make the RPC-contract-preservation property
  auditable rather than asserted.
  (d) **"Consensus-atomic cutover" exception class drafted in
  `DAA_LWMA1_PLAN.md`** Phase 4 (four criteria: consensus-rule
  boundary; structural indivisibility; surface enumerated in
  advance; documented disposition citing the criteria). The
  class was drafted here as four criteria; the sibling PR
  `feat/consensus-atomic-cutovers-rule` ratifies the criteria
  as `.cursor/rules/07-consensus-atomic-cutovers.mdc` and
  refines them through Round 6 / Round 7 review before landing
  (PR #50). The ratified form: the rule is opt-in
  (`alwaysApply: false`) and unreachable by any PR that does
  not cite it explicitly; criterion 2 is reframed as the
  structural-inapplicability of flag decomposition to consensus
  rules — a flag decomposition is consensus-safe only if both
  flag states are simultaneously valid, which for a consensus
  rule is impossible by definition, so criterion 2 is met
  whenever criterion 1 is met (closing the "yes-it's-consensus-
  but-splitting-would-be-inconvenient" loophole); criterion 3
  adds a base-commit-anchored, timestamped grep so reviewers
  re-run against the same SHA; criterion 4 is numbered into
  sub-clauses 4.1–4.4 with reviewer-map-accuracy and
  rollback-correctness promoted into the criterion itself
  (rejecting the PR is the response to a map miss, not patching
  the map); a "what this is not" section disqualifies
  convenience / velocity / reviewer-bandwidth /
  retroactive-citation; and the history of application is split
  into "Approved invocations" (LWMA-1 Phase 4) and "Cases that
  might appear analogous but are not" (RandomX v2 Phase 3,
  where the 3a flag is build-system / FFI-routing rather than
  consensus, the algorithm change ships in Phase 1's submodule
  swap, and criterion 1 is therefore not met for Phase 3 at
  all — structurally inapplicable, not "evaluated and
  rejected"). The mechanism for future invocations is
  self-anchoring: an invoking PR must include a commit that
  adds its own entry to the rule's history-of-application
  section. Phase 4's section in this plan invokes the ratified
  rule by name and maps each criterion to LWMA-1 Phase 4
  specifically; Phase 4's exception is auditable against the
  class's four criteria mechanically, not against
  LWMA-1-specific precedent.
  (e) **Round 8 bias-factor stochastic-vs-deterministic
  clarification (`DAA_LWMA1.md` §5.3 step 7, §8.1).** The Round 4
  test-vector correction landed concrete numerical tuples that
  expect `next_D == avg_D * 99/100` on the §8.1 perfectly-stable
  hashrate input (deliberate downward bias from the `99/200`
  factor). The Round 4 fix did not synchronously update §5.3
  step 7's derivation prose, which still described the `99/100`
  factor as "compensating for a ~1 % upward bias" — leaving the
  doc internally contradictory: one section described the factor
  as canceling drift (stable input → `avg_D` exactly), the other
  expected a 1 % residual. Round 8 resolves the contradiction by
  making the stochastic-vs-deterministic distinction explicit:
  the canonical zawy12 bias correction targets *stochastic*
  upward drift (Poisson skew, `6*T` clamp truncation, jump-rule
  amplification from downstream LWMA-2+ variants) present under
  realistic chain operation; on §8.1's *deterministic* unit-test
  vectors (all solvetimes exactly `T`, no clamp engagement,
  no PRNG), the same factor surfaces as a deterministic 1 %
  downward residual rather than as a corrective cancellation.
  Both readings of the algorithm are correct under their
  respective input shapes; the doc now says so explicitly so a
  Phase 1 implementer who transcribes the formula and observes
  `next_D == 990_000` on the §8.1 stable vector knows that's a
  correctly implementing algorithm rather than a test
  expectation to "fix." A Phase 1 pre-flight verification step
  is added to `DAA_LWMA1_PLAN.md`: the canonical zawy12 C++
  reference is run once against the §8.1 stable vector and the
  result recorded in the Phase 1 PR description before
  implementation begins, removing the residual ambiguity as a
  function of empirical evidence rather than as a function of
  prose interpretation.
  (f) **Round 8 §11 wallet touchpoint correction.** §11
  previously read "LWMA-1 is not consumed by the wallet —
  wallets do not compute or check difficulty (validators do)" —
  true for the *algorithm* but incomplete for the
  *target-block-time constant `T`*, which §9.7's enumeration
  surfaced as a wallet consumer at `wallet2.cpp:181, 182, 5975,
  11548` and `wallet_rpc_server.cpp:163` (unlock-time defaults,
  recent-spend-window math, `seconds_per_block` consumers,
  `suggested_confirmations_threshold` math — five wallet-side
  sites). §11 now reads accurately: the algorithm is not
  consumed by the wallet, but `T` is, with a value-preserving
  rewire from `DIFFICULTY_TARGET_V2` to
  `SHEKYL_DAA_TARGET_SECONDS` across all five sites. Phase 4's
  wallet impact is no longer mis-stated as "no wallet impact."
  The §11 prose-vs-§9.7 enumeration drift was a Round 1 grep
  finding that didn't make it into the §11 prose; Round 8
  closes the loop.
  (g) **Round 8 polish.** (i) `DAA_LWMA1.md` §6.3 explicitly
  records that the `is_above_mtp` and `is_timestamp_below_ftl`
  predicates committed in §2.5 are Rust-internal helpers
  consumed by the §17 future validator actor, not exposed via
  the FFI — the C++ side does the corresponding FTL and MTP
  checks directly against the generated header constants per
  §6.2's source-of-truth pattern, keeping the FFI surface
  minimal per §6.1's "one committed export" discipline. (ii)
  `DAA_LWMA1.md` §9.5 adds a Phase 4 reviewer note that with
  the FTL value change from 7200 to 540, the FTL test margin
  in `tests/core_tests/block_validation.cpp:137` shrinks from
  "7.2 hours past FTL" to "1 hour past FTL"; the test must
  assert rejection *specifically because of the FTL check*
  (error-code equality, not generic "block rejected"), so the
  test can't pass for the wrong reason if a future refactor
  moves rejection to a different validation path. (iii)
  `DAA_LWMA1.md` §9.7 adds a Phase 4 reviewer note for the
  `cryptonote_core.cpp:1817, 1829, 1838` Poisson stall-detection
  sites: the rewire is value-preserving but the path is not
  exercised by any current test, so Phase 4 either confirms
  coverage exists or adds a minimal regression test; "rewire
  textually, value unchanged" alone is not a sufficient
  verification claim for a path with no test coverage. (iv)
  `DAA_LWMA1.md` §9.3 is repopulated with substantive
  consolidation prose pointing FTL/MTP enumeration cross-
  references to §9.5 and §9.6 respectively (was previously an
  empty "deprecated section header" pointer with no content).
  (v) `DAA_LWMA1_PLAN.md` Phase 4 adds a reviewer-expectation
  note that the "14 work items" framing categorizes work but
  understates diff size: actual file-change count lands at
  roughly 45–55 files across `src/` and `tests/`. (vi)
  `DAA_LWMA1.md` status block on line 3 updated from "Round 1"
  to reflect that Rounds 1–8 have all landed against this PR.
  (h) **Round 9 zawy12 issue #24 cumulative-history review.**
  Reviews the design against
  [zawy12/difficulty-algorithms#24](https://github.com/zawy12/difficulty-algorithms/issues/24)
  ("LWMA's history"), the canonical author's cumulative log of
  known LWMA issues, fixes, and security-relevant findings.
  Five items receive explicit dispositions; four (#1, #2, #4,
  #5, #6, #10, #12, #15, #16) are confirmed already-addressed.
  Substantive changes:
  - **Item #14 (September 2018 selfish-mine via out-of-sequence
    timestamps).** Algorithm-level change. `DAA_LWMA1.md` §5.3
    steps 2 and 3 adopt LWMA-3's running-max + signed-solvetime
    mechanism and symmetric `±6*T` clamp, replacing the
    kyuupichan-style forward-pass-with-1-floor used through
    Round 8. The remainder of the algorithm (weighted-sum,
    minimum-L floor, bias factor 99/200, overflow guard,
    genesis-window short-circuit) stays LWMA-1-canonical.
    Disposition recorded in §1.3 (alternatives — "Partial
    LWMA-3 adoption"), §3 (pinned spec — deviation note +
    `LWMA3_()` reference pin), §5.3 steps 2/3/4 (algorithm
    rewrite to signed-i128 intermediates + symmetric clamp),
    §5.4 ("Signed-arithmetic discipline" property), §5.5
    (defense-surface enumeration grows to four mechanisms), and
    §8.1 (out-of-sequence vector reformulated for running-max
    semantics, new "Selfish-mine attack regression (zawy12 issue
    #24 item 11)" required vector). `DAA_LWMA1_PLAN.md` Phase 1
    adds a signed-arithmetic discipline section detailing the
    i128/u128 boundary and lists the two Round 9 test vectors
    as required Phase 1 merge-gate criteria. Phase 2's
    cross-check harness composes expectations from both
    canonical `LWMA1_()` and `LWMA3_()` references per §8.2.
  - **Item #17 (May 2019 33% Sybil attack via peer-time-offset).**
    Closed by absence of substrate. The attack's precondition
    ("If your coin uses network time instead of node local
    time") is not met by Shekyl. `Blockchain::check_block_timestamp(b)`
    compares against `time(NULL)` directly
    (`blockchain.cpp:4276`); `Blockchain::get_adjusted_time(height)`
    is blockchain-derived (median of recent block timestamps)
    and consulted only by non-consensus paths. No peer-time-correction
    mechanism exists in the daemon; audit-trail grep returned
    zero matches for `time_offset|TimeOffset|GetAdjustedTime|GetTimeOffset|MAX_PEER_DELTA|MAX_TIME_DELTA|MEDIAN_TIME|TIMESTAMPS_FOR_TIME_SYNC`
    against consensus-relevant surface. Lowering FTL from 7200 s
    to 540 s is therefore safe against the
    [zcash/zcash#4021](https://github.com/zcash/zcash/issues/4021)
    attack class. Disposition recorded in
    `DAA_LWMA1.md` §5.5's "Disposition on peer-time-derived
    clocks" paragraph, with a forward-looking constraint: if a
    future Shekyl version adds peer-time correction, the
    `FTL / 2` revert-threshold relationship per zawy12 issue
    #24 item 14 becomes load-bearing at that point and
    `daa_peer_time_revert_threshold_seconds` MUST be added to
    the JSON authority. The FTL value reduction (7200 → 540)
    pre-dates this round but the safety rationale is now
    explicit: it is safe *because* Shekyl does not implement
    peer-time-derived clocks.
  - **Item #7 (Jagerman MTP patch).** Verified present in
    Shekyl's inherited `Blockchain::create_block_template` at
    `blockchain.cpp:1650–1656` (the canonical pattern: set
    `b.timestamp = time(NULL)`, then if `check_block_timestamp`
    fails, raise to `median_ts`). The MTP window change from
    60 to 11 preserves the patch's effectiveness; no Phase 4
    work required. Disposition recorded in `DAA_LWMA1.md` §5.5
    with code citation. A minor doc-vs-code drift at
    `blockchain.cpp:1540`'s cached-template path is recorded
    as a `FOLLOWUPS.md` candidate, not a Phase 4 atomic-cutover
    work item.
  - **Item #3 (window size N=60 vs N=90).** Documentation polish.
    `DAA_LWMA1.md` §4's N parameter row notes that zawy12 issue
    #24's 2018 "N ≈ 60" recommendation referred to `T = 60 s`
    chains; the recommendation scales inversely with `T` and
    for `T = 120 s` the canonical N is 90 (same ~90-minute
    window).
  - **Item #9 (±7xT header timestamp limits vs FTL boundary).**
    Documentation only. `DAA_LWMA1.md` §5.5 records that Shekyl
    uses MTP + FTL + symmetric solvetime clamp + running-max
    normalization (four mechanisms) as the defense surface and
    does not implement a separate per-block-header `±7xT` rule,
    consistent with zawy12 issue #24 item 9's post-FTL deprecation
    of `±7xT`.

  `DAA_LWMA1_PLAN.md` gains a "Round 9 dispositions" section
  recording all five issue-item dispositions and naming items
  #1, #2, #4, #5, #6, #10, #12, #15, #16 as already-addressed
  with their corresponding §ref. `DAA_LWMA1.md` status block on
  line 3 updated from "Round 8" to "Round 9" to reflect the
  cumulative review pass.
  (i) **Round 9 supplement — local-time-only FTL trade-off
  named.** The Round 9 closure of zawy12 issue #24 item 17 (FTL
  vs peer-time-derived clocks) recorded the absence of substrate
  but did not name the threat-model trade the local-time-only
  FTL disposition deliberately accepts. This supplement makes the
  trade explicit so a future reader does not misread the
  disposition as missing functionality. `DAA_LWMA1.md` §5.5's
  "Disposition on peer-time-derived clocks" paragraph is expanded
  into four labelled subsections: (1) **the trade-off, named
  explicitly** — Shekyl trades the zawy12 #17 / zcash/zcash#4021
  peer-time-Sybil attack class (a ~$1000 attack accessible to
  anyone with bandwidth to run enough peers) for an operator-side
  NTP-hygiene requirement plus a coordinated-NTP-infrastructure-
  compromise threat that requires state-level access; (2) **residual
  threat-class ranking** — four classes documented from highest-
  probability/lowest-impact (individual node clock skew, mitigated
  by standard NTP hygiene, isolates affected node without
  propagating to peers) through lowest-probability/highest-impact
  (coordinated NTP-infrastructure compromise at scale, requiring
  state-level access, not consensus-protocol-mitigated); (3)
  **operator obligations** — validators are responsible for
  keeping local clocks within ±540 s of network truth via standard
  NTP discipline (multiple time sources, drift monitoring); NTP
  failure is a liveness failure for the affected node, not a
  safety failure that propagates; (4) **Y2038-adjacent note** —
  `time(NULL)` returns `time_t`, which on 64-bit platforms (the
  only Shekyl-supported platforms per the 32-bit retirement chore
  landed at commit `e06ee37d96af`, recorded in `docs/FOLLOWUPS.md`)
  is 64-bit signed and Y2038 is not a concern; if 32-bit platforms
  ever return to scope, both the FTL comparison and the FTL/2
  forward-looking peer-time constraint must be revisited. `DAA_LWMA1.md` §1.2 (Commitment 1) gains a
  closing observation: "The FTL-disposition choice (local-time-
  only, no peer-time-derived clock) reflects a deliberate
  threat-model preference for closing low-bar consensus attacks
  at the cost of slightly higher operator NTP-hygiene
  responsibility — consistent with Shekyl's broader posture on
  operator autonomy per `75-system-autonomy.mdc`." The trade
  itself, ranking observation, and the "safe because" framing on
  the FTL value reduction (7200 → 540) are now consistently
  cross-referenced from §1.2, §5.5, and this CHANGELOG entry.
  (j) **Round 10 zawy12 issue #24 item-number reconciliation +
  issue pin + reference-file enumeration + commit-hash
  cite-stabilization.** Round 10 review identified one
  load-bearing finding and three robustness improvements:
  - **Item-number drift sweep (load-bearing).** The Round 9
    body edits used item numbers that did not match the live
    zawy12 issue #24 numbering: 11 was used for the September
    2018 selfish-mine attack (live: item 14), 14 for the May
    2019 33% Sybil (live: item 17), 6 for the Jagerman MTP
    patch (live: item 7), 8 for the post-FTL `±7xT`
    disposition (live: item 9), and 13 for the January 2019
    LWMA-2/3/4 deprecation (live: item 16). The pattern was
    not a uniform offset but a cluster of mistranscriptions
    during Round 9's body edits while the status block was
    checked separately. The Round 10 sweep corrected 14 sites
    in `DAA_LWMA1.md` body, 2 sites in `DAA_LWMA1_PLAN.md`
    body, and 2 sites in this CHANGELOG entry — all now
    consistent with the live issue and with the status block's
    "items 3, 7, 9, 14, 17" enumeration. The discipline going
    forward: cite by date + description as the primary
    identifier (e.g., "September 2018 selfish-mine attack
    class") so renumbering by the upstream author does not
    silently invalidate cross-references; the item number is
    a redundant cross-reference resolving against the §3 pin
    (next item).
  - **zawy12 issue #24 pin (audit-trail-stable).**
    `DAA_LWMA1.md` §3 gains a "zawy12 issue #24 pin
    (Round 10 addition)" bullet pinning the raw `.body` of
    [`zawy12/difficulty-algorithms#24`](https://github.com/zawy12/difficulty-algorithms/issues/24)
    via `docs/design/refs/zawy12_issue_24_history.md` at
    Phase 2 PR time, using the same `gh api` + `jq -r .body`
    mechanism as the existing issue-#3 pin. Every "zawy12
    issue #24 item N" cross-reference downstream now resolves
    against this pin's numbered list, not against the live
    GitHub-rendered issue. The pin's SHA-256 and capture
    timestamp land in §3's pin record at Phase 2 commit time.
    `DAA_LWMA1_PLAN.md` Phase 2 task content extends to commit
    the issue-#24 pin alongside the existing issue-#3 pin.
  - **Phase 2 reference-file enumeration clarified.**
    `DAA_LWMA1.md` §3's Round-9 disposition paragraph is
    expanded into an explicit three-file enumeration making
    clear that `zawy12_issue_3_lwma1.md` (raw issue-#3
    `.body`, the canonical pin),
    `zawy12_issue_3_lwma3.md` (convenience extraction of just
    the LWMA3_() function, *not* the canonical pin), and
    `zawy12_issue_3_lwma1_with_lwma3_step2.md` (Shekyl-composed
    hybrid, a derived file used by the cross-check harness)
    are three distinct files with distinct purposes. The
    "snapshot pinned per §3" cross-reference at §5.3 step 2
    now resolves unambiguously. `DAA_LWMA1_PLAN.md` Phase 2
    body section gains a "Round 9 + Round 10 supplementary
    reference files" subsection enumerating all four
    Phase-2-committed files (three issue-#3 derivatives plus
    the issue-#24 pin) and extending the anchors-file schema
    with the LWMA3_() byte-offset anchors.
  - **Commit-hash cite for 32-bit-retirement chore.**
    `DAA_LWMA1.md` §5.5's Y2038-adjacent note and this
    CHANGELOG's Round 9 supplement entry both previously cited
    the chore by branch name (`chore/retire-32bit-targets`),
    which is a deleted post-merge branch and not a stable cite
    target. Both citations are now anchored on the merge
    commit `e06ee37d96af` ("Merge pull request #15 from
    Shekyl-Foundation/chore/retire-32bit-targets") with the
    rationale named in §5.5.

  Status block on line 3 updates from "Round 9" to "Round 10"
  recording the cumulative review pass. No algorithm-level or
  consensus-rule changes in Round 10; the round is documentation
  drift remediation and audit-trail-stability improvements.
  (k) **Round 11 consumer-count drift reconciliation (Copilot
  review of PR #49).** Copilot's first review pass on the
  ready-for-review PR flagged two count-mismatch findings of the
  same shape as Round 10's item-number drift — prose totals that
  did not match their adjacent enumerations. The Round 11 sweep
  reconciles both flagged sites plus the adjacent sites Copilot
  did not flag but that exhibit the same drift pattern (per the
  Round 10 discipline: fix the pattern, not just the flagged
  instances).
  - **MTP consumer count (§9.6 in `DAA_LWMA1.md`, propagated to
    `DAA_LWMA1_PLAN.md` Phase 4 work item 6 and the breakdown
    paragraph).** The §9.6 prose said "**seven** direct
    consumers ... plus **two** test-suite consumers" but the
    enumeration immediately below has always listed:
    `blockchain.cpp:1981, 1985` (2 daemon sites) +
    `blockchain.cpp:4223, 4230, 4240, 4259, 4285, 4293`
    (6 daemon sites) +
    `tests/core_tests/block_validation.h:92, 97`
    (2 test sites) +
    `tests/core_tests/block_validation.cpp:106, 120, 122`
    (3 test sites) — **8 daemon + 5 test = 13 total sites across
    3 files**. The prose now matches the enumeration: "eight
    direct consumers ... plus five test-suite consumers —
    thirteen total sites across three files." Downstream
    propagation: the Phase 4 work item 6 in
    `DAA_LWMA1_PLAN.md` previously read "the **nine** MTP
    consumers ... (seven in `blockchain.cpp`, two in
    `block_validation.{h,cpp}`)"; it now reads "the **thirteen**
    MTP consumers ... (eight in `blockchain.cpp`, five in
    `block_validation.{h,cpp}`)." The Phase 4 file-change
    breakdown paragraph previously read "9 MTP consumer rewires
    across 4 files (§9.6)" and now reads "13 MTP consumer rewires
    across 3 files (§9.6)" — the file count was also wrong
    (`blockchain.cpp` + `block_validation.h` + `block_validation.cpp`
    is 3 files, not 4; the prior "4" likely double-counted
    `cryptonote_config.h` where the `#define` lives, but that's
    already counted in the adjacent "1 MTP `#define` removed"
    item).
  - **`DIFFICULTY_*` count (§9.2 in `DAA_LWMA1.md` and Phase 4
    work item 3 + YAML phase4-cpp-cutover todo in
    `DAA_LWMA1_PLAN.md`).** Copilot flagged the plan's Phase 4
    work item 3 ("six constants" but enumerating seven names);
    the same drift exists in `DAA_LWMA1.md` §9.2 line 1973
    ("all five inherited `DIFFICULTY_*` `#define`s and the two
    timestamp-validation `#define`s") and in the plan's YAML
    todo block (line 18: "Delete the 6 inherited
    DIFFICULTY_*"). The §9.2 enumeration has always listed
    seven `DIFFICULTY_*` defines plus two timestamp-validation
    defines, and the §9.3 cross-reference at line 2022
    ("the seven `DIFFICULTY_*` defines plus FTL plus MTP")
    and the plan's breakdown at line 789 ("7 `DIFFICULTY_*`
    defines removed") have always been correct. The prose at
    line 1973, the plan's work item 3 body, and the plan's
    YAML todo are now reconciled to "seven" everywhere.
  - **Forward-looking discipline.** Both drift instances share
    the same pattern as Round 10's item-number drift: prose
    totals composed by hand on top of enumerations that
    accumulated incrementally across review rounds. The fix
    going forward, per the Round 10 discipline, is the same: a
    pre-PR scan for "prose says N, enumeration says M" mismatches
    catches the class before it lands as a Copilot finding.

  Status block on line 3 updates from "Round 10" to "Round 11"
  recording the cumulative review pass. No algorithm-level or
  consensus-rule changes in Round 11; the round is documentation
  drift remediation surfaced by the first AI-reviewer pass on the
  ready-for-review PR.
  (l) **Phase 0 closeout (Round 12): §5.3 step 2 pseudocode
  reorder, Phase 1 pre-flight execution, hybrid-reference
  rename.** (2026-05-18 UTC). Phase 0 ratified after 12 review
  rounds. Three load-bearing closeout actions in a single
  commit:
  - **Status block transition.** `DAA_LWMA1.md` line 3 transitions
    from "Status: DRAFT — Round 11 …" to "Status: RATIFIED —
    Phase 0 close (2026-05-18 UTC) — 12 review rounds. Round 12
    was the final round; the status reflects ratification, not
    'round 12 of N.'" The status block now records the Round 12
    findings inline (pseudocode reorder, pre-flight execution,
    hybrid-reference rename, three reference pins landed) so that
    a future reader of the design doc sees the closeout summary
    without needing to read the CHANGELOG.
  - **§5.3 step 2 pseudocode reorder (load-bearing correctness
    fix).** Round 12 review identified an order-of-operations bug
    in the §5.3 step 2 pseudocode that contradicted the
    surrounding prose at lines 957–960 and 994–996. The
    pre-Round-12 pseudocode read `prev_max = max(prev_max,
    timestamps[i-1]); solvetime[i] = timestamps[i] - prev_max;`
    which, on the first loop iteration (`i=1`), executes
    `prev_max = max(timestamps[0] - T, timestamps[0])`, evaluating
    to `timestamps[0]` since `T > 0`. This overwrites the `-T`
    anchor the surrounding prose claims is preserved, producing
    `solvetime[1] = timestamps[1] - timestamps[0]` rather than the
    intended `solvetime[1] = timestamps[1] - (timestamps[0] - T)
    = T + T = 2T` on the stable input. The pseudocode is now
    reordered to subtract-then-max:
    `solvetime[i] = timestamps[i] - prev_max; prev_max =
    max(prev_max, timestamps[i]);`. On the first iteration this
    correctly evaluates `solvetime[1] = timestamps[1] - (t0 - T)
    = 2T` (using the `-T` anchor), then updates `prev_max =
    max(t0 - T, t1) = t1`. The prose at §5.3 lines 957–960 and
    994–996 is updated to make the subtract-then-max semantics
    explicit, including the empirical observation (from the
    pre-flight harness, below) that the canonical zawy12
    `LWMA1_()` reference behaves equivalently to the corrected
    Shekyl pseudocode on monotonic inputs (both produce 990_000
    on the §8.1 stable vector) but diverges on out-of-sequence
    inputs (canonical 990_000 vs Shekyl-corrected 992_000 on the
    Round 12 regression vector), confirming the running-max
    mechanism's security property is load-bearing rather than
    cosmetic.
  - **Phase 1 pre-flight verification (executed at Phase 0 close
    per §5.3 step 7).** Built a minimal C++ harness from the
    canonical `LWMA1_()` reference transcribed verbatim from
    `docs/design/refs/zawy12_issue_3_lwma1.md` (lines 77–119 of
    the pinned `.body`), compiled with `g++ -std=c++17 -O2`, and
    ran against the §8.1 "perfectly stable hashrate" input vector
    with `avg_D = 1_000_000`, `N = 90`, `T = 120`, and
    `timestamps[i] = 1_700_000_000 + i*T` for `i ∈ 0..=N`. Result:
    canonical output `990_000` (matches §8.1 expected value).
    An initial harness run with `timestamps[i] = i*T` produced
    `10_000_000` due to `uint64_t(0) - uint64_t(120)` underflow at
    `timestamps[0] - T`; corrected to realistic Unix epoch
    timestamps and re-ran with the expected result. The
    Shekyl-corrected algorithm (transcribed from
    `docs/design/refs/shekyl_lwma1_running_max_symmetric_clamp.md`)
    was also compiled and run against the same stable input,
    producing byte-identical `990_000` (confirming §8.2's
    cross-check assertion that monotonic inputs match canonical
    byte-for-byte). An out-of-sequence regression vector (the
    same stable timestamps with `timestamps[2] = timestamps[1] -
    5*T`) produced canonical `990_000` (attack neutralized to
    `+1` via canonical's `previous_timestamp+1` floor; no
    penalty) versus Shekyl-corrected `992_000` (attacker's
    negative-solvetime contribution to `L` produces higher
    `next_D`, denying the attack). The §5.3 step 7 stochastic-vs-
    deterministic framing and §8.1's stable-vector expected
    value are both empirically confirmed; the running-max
    mechanism's load-bearing security property in §5.3 step 2 is
    empirically verified by the regression vector. `DAA_LWMA1.md`
    §5.3 step 7 and §8.1 record the inputs, the actual outputs,
    and the divergence on the out-of-sequence vector;
    `DAA_LWMA1_PLAN.md`'s Phase 1 pre-flight subsection records
    the executed result and preserves the reversion-clause
    triggers for any Phase 1 re-run that produces a different
    number.
  - **Hybrid-reference rename
    (`zawy12_issue_3_lwma1_with_lwma3_step2.md` →
    `shekyl_lwma1_running_max_symmetric_clamp.md`).** The Round 9
    working name attributed the running-max + symmetric-clamp
    mechanism to canonical LWMA-3 ("with_lwma3_step2"), but
    canonical LWMA-3 (per the
    `docs/design/refs/zawy12_issue_3_lwma3.md` extraction
    referenced in the Phase 2 plan) does not actually implement
    running-max, signed-solvetimes, or symmetric clamping in the
    form §5.3 step 2 specifies — these are Shekyl-specific
    refinements drawing on the *idea* of LWMA-3's out-of-sequence
    handling but composed independently. The file is renamed to
    `shekyl_lwma1_running_max_symmetric_clamp.md` to reflect the
    Shekyl-specific construction; the file's preamble documents
    the naming rationale, the empirical equivalence on monotonic
    inputs, and the divergence on the regression vector. All
    cross-references in `DAA_LWMA1.md` §3 and `DAA_LWMA1_PLAN.md`
    are updated to the new name. The `zawy12_issue_3_lwma3.md`
    convenience extraction (verbatim LWMA-3 reference, *not* a
    pin) remains a Phase 2 work item per `DAA_LWMA1_PLAN.md`; it
    is not load-bearing for Phase 1.
  - **Three reference pins landed at Phase 0 close.** Per the
    Phase 0 close discipline obligation, the three Phase 2 spec-
    pin files landed as a Phase 1 precondition:
    `docs/design/refs/zawy12_issue_3_lwma1.md` (canonical LWMA-1
    pin, SHA-256
    `14c68aee9780ca1b1fb8ca28ac43f7956996859f5281ef166cc0634b2cc50df9`,
    captured-at 2026-05-18T05:25:21Z),
    `docs/design/refs/zawy12_issue_24_history.md` (LWMA history
    issue pin, SHA-256
    `94a6fc8f10b57cf7d0731f62d07c0b4bbdf65d969d7c8679755b22eace76891d`,
    same capture timestamp), and
    `docs/design/refs/shekyl_lwma1_running_max_symmetric_clamp.md`
    (Shekyl hybrid reference, SHA-256
    `f16f62695ae74b2ca47d15227b79035cdc349609d9fc73db2b7a3c57c0dfcc4a`,
    same capture timestamp). `DAA_LWMA1.md` §3's pin records
    embed the SHA-256s and timestamps; the `LWMA1_()` byte-offset
    anchors and the LWMA3_() convenience extraction remain Phase
    2 work per `DAA_LWMA1_PLAN.md` (not load-bearing for Phase 1).

  Status block on line 3 updates from "DRAFT — Round 11" to
  "RATIFIED — Phase 0 close (2026-05-18 UTC) — 12 review
  rounds." Phase 0 is closed; Phase 1 (`shekyl-difficulty` crate
  scaffold per `DAA_LWMA1_PLAN.md`) opens against ratified spec.
  The pre-flight harness source (transcribed from the pinned
  `zawy12_issue_3_lwma1.md` LWMA1_() function) is available at
  this commit and is reproducible via
  `g++ -std=c++17 -O2 preflight.cpp -o preflight && ./preflight`.

  (m) **Round 13 post-Phase-0-close cleanup (§5.3 step 9
  canonical-rounding-step documentation, §8.1 base-anchor
  convention and arithmetic correction, harness commit).**
  (2026-05-18 UTC.) Addresses Copilot PR #49 findings 3, 4, 5
  surfaced after the Phase 0 close commit. Phase 0 stays
  ratified; Round 13 is post-ratification cleanup against the
  same design intent. Four load-bearing changes:
  - **§5.3 new step 9 — canonical zawy12 LWMA-1 trailing
    rounding step.** Documents the previously-undocumented
    `((next_D + r/2) / r) * r` rounding-to-3-significant-decimal-
    digits step from canonical `LWMA1_()` (`zawy12_issue_3_lwma1.md`
    lines 116–119 of the pinned `.body`). The §8.1 expected
    values all depend on this step; without it, the raw outputs
    are `989_758` (stable), `1_035_252` (out-of-sequence), etc.
    — close but not byte-equal to the canonical 3-significant-
    digit values. Round 13 adds the step explicitly so the
    §8.2 canonical-reference byte-cross-check is well-defined,
    and includes a reversion clause requiring a §10 disposition
    for any future PR proposing to drop or alter it.
  - **§8.1 timestamp base-anchor convention (Copilot finding
    5).** All §8.1 vectors are now specified as
    `timestamps[i] = B + f(i)` with `B = 1_700_000_000` (Unix
    epoch base). The pre-Round-13 specification used `i*T` or
    `(i-1)*T` formulas with `B` implicit; the latter produced
    `timestamps[0] = -T`, unrepresentable as `u64` (wraps to
    `~1.8e19`) and the cause of the pre-flight harness's
    initial `10_000_000` mis-output before the Round 12
    correction. Base-anchoring is now a §8.1 invariant rather
    than a harness-side workaround.
  - **§8.1 out-of-sequence and minimum-L-floor vectors — full
    arithmetic rederivation (Copilot findings 3, 4).** The
    pre-Round-13 out-of-sequence vector's worked arithmetic
    inflated the numerator by ~1000× and omitted the
    rounding step entirely (numerator `97_297_560 * 10^7`
    instead of `97_297_200_000_000`; quotient `1_035_521_504`
    instead of step-9-rounded `1_040_000`). Round 13 rederives
    `L = T*(N-1)*(N-2)/2 = 469_920`, computes raw `next_D =
    1_035_252`, applies step 9 to round to `1_040_000`, and
    cross-checks against the harness output. The minimum-L
    floor vector's expected output drops from `10_010_000`
    (analytic, missing step 9) to `10_000_000` (step-9-rounded);
    the analytic intermediate is preserved in the prose so
    the rounding-step contribution is auditable.
  - **§8.1 selfish-mine attack regression — pinned numerical
    outputs.** The Round-9-era assertion was relational only
    ("Shekyl > kyuupichan output," "Shekyl > all-monotonic-T
    reference"). Round 13 pins the empirical values: canonical
    `911_000`, Shekyl `1_040_000`. Canonical's `911_000` is
    *below* the `990_000` stable reference, surfacing the
    load-bearing property that canonical LWMA-1 actually
    *rewards* this attack class (lower difficulty post-attack
    means cheaper subsequent mining) — the regression Shekyl's
    running-max + symmetric-clamp formulation exists to fix.
    The §8.1 entry is rewritten to specify the canonical-and-
    Shekyl outputs side-by-side, the divergence ratio
    (~1.14×), and the four-part assertion the test vector
    must verify.
  - **Pre-flight harness committed to `tests/phase0/`.** The
    three C++ harnesses produced during Phase 0 close and
    Round 13 (`preflight.cpp`, `preflight_corrected.cpp`,
    `preflight_outofseq.cpp`) are now committed alongside the
    design doc as authoritative reproducibility artifacts,
    with `README.md` explaining build/run/license. The MIT
    SPDX identifier covers the canonical `LWMA1_()`
    transcription; the Shekyl variant header documents
    Shekyl Foundation origin. The `DAA_LWMA1.md` §3 reference
    list and §8.1 vector-derivation footer point at the
    harness directory; the Phase 1 implementer reproduces the
    pinned values via `g++ -std=c++17 -O2
    preflight_outofseq.cpp -o p && ./p` before opening
    Phase 1's first commit.

  Round 13 leaves the `RATIFIED — Phase 0 close (2026-05-18
  UTC)` line on `DAA_LWMA1.md` line 3 unchanged — Phase 0
  closed at Round 12; Round 13 is post-ratification cleanup of
  finding-classes that surfaced after PR #49 was marked
  merge-ready. The summary paragraphs below line 3 are
  extended with a "Round 13 applied:" block listing the four
  changes above. Phase 1 remains unblocked.

- **`07-consensus-atomic-cutovers.mdc` — named exception to
  branching policy for consensus-atomic cutovers**
  (`feat/consensus-atomic-cutovers-rule`, 2026-05-17). New rule
  ratifying the "consensus-atomic cutover" exception class
  drafted during PR #49's Round 5 review
  (`DAA_LWMA1_PLAN.md` Phase 4) and refined through Round 7
  before landing. `06-branching.mdc`'s 5-working-day / 10-commit
  splitting guidance defends against unreviewable PRs
  accumulating; this rule names the small class of PRs that
  genuinely cannot split because every intermediate state would
  be a non-canonical consensus configuration. The rule is
  **opt-in** (`alwaysApply: false`) — a PR that does not
  explicitly cite the rule cannot invoke it. Four
  objectively-testable criteria, all required:

  1. **Consensus-rule boundary.** The PR changes behavior all
     correctly-implementing nodes must reproduce byte-identically
     on the same input. Refactors, RPC formatting, internal
     caches, renames, and file reorganizations of consensus code
     that preserve the rule do not qualify.
  2. **Indivisible under flag decomposition.** Met whenever
     criterion 1 is met, for structural rather than contingent
     reasons. A flag decomposition only counts as consensus-safe
     if both flag states are simultaneously valid (build-system
     flags, performance-tuning flags, instrumentation flags
     qualify). For a consensus rule, simultaneous validity is
     impossible by definition: the flag would have to dispatch
     identically regardless of state, which means it doesn't
     gate consensus behavior at all. Hard-fork activations are
     the consensus event the PR ratifies, not a decomposition of
     it; Shekyl's `60-no-monero-legacy.mdc` no-version-dispatch
     posture forecloses any other interpretation. This shape
     closes the loophole where a PR author argues "yes, this is
     a consensus change, but splitting would be inconvenient":
     either the change affects consensus output (criteria 1+2
     both met) or it does not (neither met).
  3. **Surface enumerated in advance, with evidence.** A
     grep-result-derived enumeration of every consensus-affecting
     symbol/file/constant pasted into the PR description, **run
     against the PR's base commit and timestamped at PR-open**
     so reviewers re-run the same grep against the same base
     commit to verify the surface hasn't shifted.
  4. **Disposition documented in PR.** Numbered sub-clauses:
     4.1 rule citation; 4.2 per-criterion justification; 4.3
     reviewer-map (with enforcement: substantive consensus
     changes found outside the map's "consensus-affecting"
     subsection are grounds for rejecting the PR — the response
     is re-opening with a corrected enumeration, not patching
     the map); 4.4 rollback procedure (with enforcement:
     procedure must be executable by a reviewer who has not
     seen the PR; tacit-knowledge rollback procedures fail 4.4).

  A "what this is not" section explicitly disqualifies
  convenience, velocity, reviewer bandwidth, and retroactive
  citation as justifications. A "compensating discipline"
  section names scope-creep within an exception-invoking PR as
  itself grounds for rejection. The rule records LWMA-1 Phase
  4 as its first approved instance under "Approved invocations,"
  and RandomX v2 Phase 3 under a separate "Cases that might
  appear analogous but are not" subsection — Phase 3 ships
  implementation routing (the 3a flag is a build-system /
  FFI-routing flag, not a consensus flag; the algorithm body is
  byte-identical on both sides), so criterion 1 is not met and
  the exception is **structurally inapplicable**, not
  "evaluated and rejected" (the latter framing would invite
  precedent-erosion arguments against future invocations). The
  mechanism for future invocations is self-anchoring: the
  invoking PR must include a commit that adds its own entry to
  the rule's history-of-application section, so the audit trail
  cannot be reconstructed retrospectively. Per
  `21-reversion-clause-discipline.mdc`'s named-criteria
  principle, the exception is auditable mechanically against
  the four criteria, not against LWMA-1-specific precedent
  erosion.
- **RandomX v2 Rust port — Phase 0 design docs**
  (`feat/randomx-v2-phase0-design`, 2026-05-16). Adds three Phase 0
  design documents under `docs/design/`:
  [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) (the primary
  design),
  [`RANDOMX_V1_FALLBACK.md`](./design/RANDOMX_V1_FALLBACK.md) (the
  contingency design), and
  [`RANDOMX_V2_PLAN.md`](./design/RANDOMX_V2_PLAN.md) (the phased
  execution plan with sub-PR breakdown and gating diagram). The
  primary design pins the permanent C-miner / Rust-verifier split,
  derived-first verifier architecture under `18-type-placement.mdc`,
  the one-function FFI target, no-prewarm disposition, performance
  budgets, C-library symbol-isolation invariant, and the wallet V3.2
  gate before Track B. The Grover-bound argument scaffold is recorded
  in [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §10; the
  concrete release-checklist target-range calculation is explicitly
  deferred to Phase 0 review per §10's closing sentence rather than
  shipped in this PR. The fallback doc records the late-binding
  unpin-and-revert recovery path (`102f8acf` pin plus verifier
  toggle) for any time between Phase 0 and genesis release if the
  algorithm-review gate fails per `RANDOMX_V2_RUST.md` §1.4.

- **LWMA-1 difficulty-adjustment migration — Phase 2 cross-check
  harness + FFI export (absorbs original Phase 3)**
  (`feat/daa-lwma1-phase2`, 2026-05-18). Lands the C++ cross-check
  harness that validates the Phase 1 Rust implementation against
  both the canonical zawy12 LWMA-1 reference and the Shekyl hybrid
  (running-max + symmetric-clamp) reference across the §8.1 test
  corpus per `docs/design/DAA_LWMA1_PLAN.md` Phase 2, and lands the
  `shekyl_difficulty_lwma1_next` FFI export the harness consumes.

  **Phase 2/3 absorption.** The original plan separated Phase 2
  ("harness only") from Phase 3 ("FFI export only"). The "or" clause
  in Phase 2 ("via FFI declared in Phase 3, or via a tiny test-only
  C++ wrapper") collapsed to a single architectural disposition on
  audit: any C++ caller into Rust requires `extern "C"` symbols, and
  the only architecturally clean place to host them is `shekyl-ffi`
  (hosting in `shekyl-difficulty` itself would violate the Phase 1
  `#![deny(unsafe_code)]` posture; hosting as a throwaway test shim
  would be torn down by the original Phase 3 anyway). The two paths
  collapsed: land the production FFI export in Phase 2 alongside the
  harness, and have Phase 3 collapse to a "see Phase 2" plan-doc
  note. The Phase 2 PR is correspondingly larger but produces zero
  throwaway code; the harness is the integration test for the
  production FFI surface.

  **`catch_unwind` panic-safety wrapper dropped.** The original
  Phase 3 prescription wrapped the FFI body in `std::panic::catch_unwind`.
  The workspace runs `panic = "abort"` in both `dev` and `release`
  profiles (`rust/Cargo.toml` lines 103, 106); under `panic = "abort"`,
  `catch_unwind` is a no-op because panics terminate the process
  before any catch can engage. The Rust algorithm body is panic-free
  by construction (returns `Result<u128, Error>` for every spec error
  path; uses explicit `checked_*` / `try_from` overflow guards), and
  the §8.1 corpus exercises both branches. The FFI shim calls
  `lwma1_next` directly. `SHEKYL_DIFFICULTY_ERR_INTERNAL` (-4)
  remains reserved in the C header for forward compatibility but is
  not currently emitted.

  **Reference pinning.** Three pin records land:

  - `docs/design/refs/zawy12_issue_3_lwma1.anchors.json` — byte-offset
    + first/last-line anchors for `LWMA1_()` and the upstream LWMA-3
    function inside the pinned `.body`, plus the pinned-body SHA-256
    cross-reference (`14c68aee9780ca1b1fb8ca28ac43f7956996859f5281ef166cc0634b2cc50df9`).
    The anchors file's own SHA-256 (`406320ca29e67e564b7c13eb0fd706b393f0af7558fd99bac391a73542250783`)
    and capture timestamp (`2026-05-18T18:22:42Z`) land in
    `DAA_LWMA1.md` §3 as the pin record.
  - `docs/design/refs/zawy12_issue_3_lwma3.md` — convenience
    extraction of the canonical LWMA-3 (`next_difficulty_v3`)
    function from the pinned body. Shekyl-authored header (SPDX
    `BSD-3-Clause AND MIT`) plus byte-identical extraction against
    the anchors above. The pinned upstream LWMA-3 contains malformed
    C++ at upstream lines 376-381 (incomplete `next_D =` assignment
    and an unbalanced `)` in the jump-rule branch); the extraction
    preserves the malformation as-is, documented in both the file
    header and `DAA_LWMA1.md` §3. The closing-brace anchor at
    upstream line 384 is a textual delimiter, not a balanced-brace
    marker. SHA-256:
    `9e2db49a7e2151177cced1748a3d0a4e7cb68ed2b0ecd0c2995cf86f38323671`.

  **FFI surface (`rust/shekyl-ffi/src/difficulty_ffi.rs`).** New
  module exposing `shekyl_difficulty_lwma1_next` as a
  `pub unsafe extern "C" fn` with the `ShekylU128` two-u64
  decomposition ABI per `DAA_LWMA1.md` §6.1 (Round 5's disposition
  against target-defined Rust `u128` C ABI). Error codes wire-stable
  at `0` / `-1` / `-2` / `-3` / `-4`; null-input pointers permitted
  iff `count == 0` (genesis short-circuit). Five unit tests cover
  the `ShekylU128` round-trip, the genesis path, the null-pointer
  rejection paths (both `out` and inputs-with-nonzero-count), and
  the `ERR_INVALID_COUNT` mapping.

  **C header (`src/shekyl/shekyl_ffi.h`).** Adds the
  `shekyl_difficulty_lwma1_next` declaration, the `struct shekyl_u128`
  definition, and the `SHEKYL_DIFFICULTY_OK` /
  `SHEKYL_DIFFICULTY_ERR_NULL_PTR` / `_ERR_INVALID_COUNT` /
  `_ERR_OVERFLOW` / `_ERR_INTERNAL` macros. The struct lives inside
  the existing top-of-file `extern "C"` block; macros sit at file
  scope below the block per the C++ rule that `extern "C"` applies
  to linkage of declarations, not to preprocessor symbols.

  **Cross-check harness (`tests/difficulty/lwma1_cross_check.cpp`
  + `tests/difficulty/zawy12_lwma1_reference.h` +
  `tests/difficulty/shekyl_lwma1_hybrid_reference.h`).** Iterates
  the seven §8.1 vectors and asserts the documented cross-
  implementation relations:

  - Vectors 1-5 (monotonic): canonical ≡ hybrid ≡ Rust (byte-equal
    at the §8.1 pinned outputs).
  - Vectors 6-7 (out-of-sequence): hybrid ≡ Rust (byte-equal at
    `1_040_000`), both strictly different from canonical
    (`1_010_000` for vector 6, `911_000` for vector 7 — the
    load-bearing security divergence per zawy12 issue #24 item 14).

  The canonical reference header carries the MIT SPDX header citing
  the pinned-body byte-offset anchor; the hybrid reference header
  is BSD-3-Clause-MIT dual-licensed (canonical portions are MIT;
  the step-2/3 refinement is BSD-3-Clause per the Shekyl Foundation
  copyright). The harness uses `SHEKYL_DAA_*` constants from
  `shekyl/consensus_constants_generated.h` (Phase 1's
  JSON-authoritative emit) so any drift between the JSON authority
  and the harness expectations fails the build.

  **CMake / ctest integration.** Extends
  `tests/difficulty/CMakeLists.txt` with the `lwma1-cross-check`
  target (linked against `${SHEKYL_FFI_LINK_LIBS}`) and the
  `lwma1_cross_check` ctest registration. Harness reports 100 %
  passing across the §8.1 corpus; failure aborts the test.

- **LWMA-1 difficulty-adjustment migration — Phase 1 crate scaffold
  + spec-vector tests** (`feat/daa-lwma1-phase1-crate`, 2026-05-18).
  Lands the Rust crate `rust/shekyl-difficulty` per
  `docs/design/DAA_LWMA1.md` and `DAA_LWMA1_PLAN.md` Phase 1. Pure-
  arithmetic `#![no_std]` + `#![deny(unsafe_code)]` leaf crate with
  zero internal workspace deps; the FFI export
  (`shekyl_difficulty_lwma1_next` with the `ShekylU128` ABI per
  `DAA_LWMA1.md` §6.1) is deferred to Phase 3 in `shekyl-ffi`.

  **Public surface.** `lwma1_next(chain_height, &timestamps,
  &cumulative_difficulties) -> Result<u128, Error>` transcribes the
  §5.3 algorithm verbatim (running-max + signed-solvetime per the
  §5.3 step-2 Shekyl refinement, symmetric ±6T clamp per step 3, i128
  weighted-sum accumulation per step 4, min-L floor at N²T/20 per
  step 5, bias-corrected `99/200` formula per step 7, overflow guard
  per step 8, and the canonical rounding-to-3-significant-decimal-
  digits step 9 added in Round 13). Coupled timestamp predicates
  `is_timestamp_below_ftl` and `is_above_mtp` co-located in the same
  crate per `DAA_LWMA1.md` §2.5. Window-shape constants `N`,
  `T_SECONDS`, `FTL_SECONDS`, `MTP_WINDOW`, `GENESIS_DIFFICULTY` flow
  through the existing `config/consensus_constants.json` JSON
  authority (extended with five `daa_*` keys); the bias factor
  `99/200`, the solvetime clamp `6`, and the min-L floor divisor `20`
  deliberately stay as bare integer literals inside `src/lwma1.rs`
  per the Round 3 disposition (`DAA_LWMA1.md` §4) because changing
  them is a deviation from canonical zawy12 LWMA-1, not a tunable
  parameter.

  **JSON-authority extension.** `config/consensus_constants.json`
  adds `daa_window_n=90`, `daa_target_seconds=120`,
  `daa_ftl_seconds=540`, `daa_mtp_window=11`,
  `daa_genesis_difficulty=100`. `cmake/generate_consensus_constants.py`
  extends `KEYS_INTEGER` and the emitted header with five
  `SHEKYL_DAA_*` macros; until Phase 4 lands, these macros are
  emitted but have no C++ consumer (the Phase 4 cutover replaces
  inherited `DIFFICULTY_TARGET_V2`, `CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT`,
  and `BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW`). `rust/shekyl-difficulty/build.rs`
  reads the same JSON and emits the Rust mirrors to `OUT_DIR` (Round 3's
  Option A; extending `shekyl-engine-core/build.rs` would have broken
  the leaf-crate property). The build script also emits `usize` mirrors
  of `N` and `MTP_WINDOW` as plain `usize` literals rather than via
  `usize::try_from(u64)` in a const block, because `TryFrom::try_from`
  is not yet const-trait-stable in rustc 1.95.0 (issue #143874); this
  keeps the workspace's `cast_possible_truncation = "deny"` lint clean
  without per-site `#[allow]` annotations.

  **Test corpus.** 18 tests all pass with the workspace's full lint
  suite under `-D warnings`. The 7 §8.1 spec vectors reproduce the
  Phase 0 C++ harness outputs byte-for-byte: `990_000` (stable),
  `1_980_000` (2× up), `495_000` (2× down), `892_000` (clamp
  engagement), `10_000_000` (min-L floor), `1_040_000` (out-of-
  sequence single back-step, Shekyl ≠ canonical's `1_010_000`),
  `1_040_000` (selfish-mine attack regression, Shekyl ≠ canonical's
  `911_000`). Edge cases: genesis short-circuit across `chain_height
  ∈ 0..N` returns `GENESIS_DIFFICULTY`, the §5.3 step-1 boundary
  surfaces `Error::InvalidCount` on length mismatch, a non-
  monotonic cumulative-difficulty input surfaces `Error::Overflow`,
  both branches of the §5.3 step-8 overflow guard execute cleanly,
  the `solvetime[1] = -T` regression computes without overflow, and
  the FTL/MTP predicates cover their respective boundaries.

  **Gates.** Per `45-rust-lint-checks.mdc`, `cargo test --package
  shekyl-difficulty`, `cargo clippy --package shekyl-difficulty
  --all-targets -- -D warnings`, and `cargo fmt --package
  shekyl-difficulty -- --check` all pass. `cargo check --workspace`
  passes (the JSON authority extension does not affect existing
  consumers; `shekyl-engine-core/build.rs` continues to read only
  the FCMP/RCT keys it already consumed).

### Changed

- **Stage 1 PR 4 — `Engine` parameterized over `R: RefreshEngine`
  (fourth type parameter)** (`feat/stage-1-pr4-refresh-engine`,
  PR 4 C5a = `553d70139`; default `R = LocalRefresh` per the
  Round 4 turnkey-default discipline). `Engine<S: Signer>`
  becomes `Engine<S: Signer, D: DaemonEngine = DaemonClient, L:
  LedgerEngine = LocalLedger, R: RefreshEngine = LocalRefresh>`
  at
  [`engine/mod.rs`](../rust/shekyl-engine-core/src/engine/mod.rs).
  The orchestrator retry loop in
  [`engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs)
  migrates from a free-function `produce_scan_result(...)` to
  trait dispatch on `R` via `self.refresh.produce_scan_result(...)`
  per PR 4 C5 = `7140f726a`; the legacy producer scaffolding
  (`produce_scan_result` free function + `ProduceError` +
  `ProgressEmitter` + duplicated helpers + constants) is deleted
  from `engine/refresh.rs` per PR 4 C5β = `b6a1274de`. The new
  `Engine::replace_refresh` test-only constructor (consume-and-
  rebuild; refactored at PR 4 C7 = `c9e65bbc6` from its initial
  `&mut self` setter form per PR 4 C6α = `e9310542a`) lets the
  `R` type parameter change between construction and replacement
  so test orchestration can build the engine with `LocalRefresh`
  at assemble time and rewire to `FaultInjecting<LocalRefresh>`
  for failure-injection scenarios. `ViewMaterial::try_from_keys`
  at
  [`engine/view_material.rs`](../rust/shekyl-engine-core/src/engine/view_material.rs)
  derives the trait-required view-and-spend material from the
  `KeyEngine` at engine-assemble time, populating the
  `LocalRefresh` constructor argument. Crate-level public APIs
  consuming the engine type alias (`Wallet`,
  `WalletWithLedger<L>` test helpers, `RefreshHandle`, the
  benchmark fixtures) thread the additional type parameters
  forward with appropriate defaults; no consumer outside the
  `shekyl-engine-core` crate is required to name `R`
  explicitly under the default-parameter discipline.

- **Stage 1 PR 4 — `RefreshError::InternalInvariantViolation
  { context: &'static str }` variant addition** (PR 4 C3 =
  `c45894ffe`; Phase 0c amendment per
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R6 close-out). Resolves the Round 2 R6 "(a) extend
  `ConcurrentMutation` or (b) introduce
  `InternalInvariantViolation`" cleanup pin at the design layer.
  Disposition (b): conflating "wallet under sustained merge
  contention" and "wallet hit an internal bug" into
  `ConcurrentMutation` would deny downstream consumers
  (`PeerReputationActor`, telemetry, user-facing error surface)
  the structural distinction they need to respond correctly.
  The retry-loop call sites in
  [`engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs)
  (per PR 4 C5 = `7140f726a`) and the `RefreshHandle::join`
  dropped-sender site surface state-machine invariant
  violations as `InternalInvariantViolation { context }` with
  compile-time-fixed developer content; `&'static str` is
  appropriate at the orchestrator-internal site because the
  field carries no attacker-influenced data (the memory-
  amplifier and log-exfiltration vectors the producer-trait
  unit-variant discipline closes do not apply here). The
  variant is one of three `RefreshError` variants reachable
  from a `RefreshEngine` impl's `Self::Error` via `Into`
  (alongside `Cancelled` unit and `Io(IoError)`); the other
  three variants (`MalformedScanResult`, `ConcurrentMutation`,
  `AlreadyRunning`) are orchestrator-constructed only per
  the §6.1.1 two-enum architecture pin and the
  F-Mock-3-sharpening trait-reachable-variant enumeration.

### Removed

- **Electrum-words subsystem — Phase 2: JSON-RPC surface deletion**
  (`feat/electrum-words-removal-phase2-rpc-deletion`, 2026-05-19).
  Deletes the inherited CryptoNote 25-word seed surface from the
  wallet JSON-RPC layer per
  `docs/design/ELECTRUM_WORDS_REMOVAL_PLAN.md` Phase 2 and
  `docs/design/ELECTRUM_WORDS_REMOVAL.md` substrate §2.4. Closes
  Phase 0 Mission Audit Lens B finding B-1 at the RPC layer (FFI +
  `wallet2` core deletions follow in Phase 3 / Phase 4 / Phase 5).
  Landed across the commit list below (the bullet list is the
  source of truth; explicit count omitted because review iterations
  add closeout commits). All in `src/wallet/wallet_rpc_server*`
  plus `tests/`:

  - `restore_deterministic_wallet` JSON-RPC method + handler +
    `COMMAND_RPC_RESTORE_DETERMINISTIC_WALLET` request/response
    structs deleted. The method took a 25-word Electrum seed +
    optional `seed_offset` + `language` and reconstructed an
    account; Shekyl wallets restore from raw seeds via the
    `shekyl_account_generate_from_raw_seed` FFI surface
    (testnet/fakechain only per
    `rust/shekyl-crypto-pq/src/account.rs`'s permitted
    network/seed-format matrix), not from word lists.
  - `get_languages` JSON-RPC method + handler +
    `COMMAND_RPC_GET_LANGUAGES` request/response structs
    deleted. The method enumerated Electrum-word language packs
    that have no analogue in the Shekyl seed flow.
  - `language` request field + `is_valid_language(req.language)`
    validation branch + `wal->set_seed_language(req.language)`
    call removed from `COMMAND_RPC_CREATE_WALLET` and
    `COMMAND_RPC_GENERATE_FROM_KEYS`. The request-schema change
    drops the field from the deserializer surface. **epee
    KV-serialization is pull-based**: keys the consumer struct
    does not declare are silently ignored, so callers that still
    send `language="English"` do not see a parse error — the
    value is dropped on the floor and `wallet2::generate()` runs
    with the wallet2 default seed language. The §4.3 hard-error
    discipline is enforced at the **FFI surface** (Phase 1
    `wallet2_ffi_create_wallet` / `wallet2_ffi_generate_from_keys`
    reject non-empty `language` per
    `src/wallet/wallet2_ffi.cpp:309–320, 485–495`); the
    wallet-RPC handler reaches `wallet2::generate()` directly,
    so the FFI's hard-error gate is not on this code path. The
    load-bearing property at the wallet-RPC layer is therefore
    **structural unreachability** of the field from request
    parsing — no read path from JSON to behavior — rather than
    runtime rejection. Phase 3 deletes the FFI parameter
    entirely, collapsing both surfaces. The underlying
    `wallet2::set_seed_language` and
    `crypto::ElectrumWords::is_valid_language` symbols still
    exist (called from `wallet2_ffi.cpp` and `wallet2`
    internals); their full removal lands with the mnemonics
    module in Phase 5.
  - `seed` and `seed_offset` request fields + the entire
    seed-recovery branch (the
    `if (!req.seed.empty()) { words_to_bytes / decrypt_key /
    account.generate(...) / spend-key match check }` block at
    `wallet_rpc_server.cpp:2316–2366`) removed from
    `COMMAND_RPC_STOP_BACKGROUND_SYNC`. The branch was P0-broken
    on mainnet/stagenet under the legacy 3-arg
    `account.generate()` overload (constant-drift audit
    `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`);
    password-only `stop_background_sync` survives unchanged. A
    BIP39 / raw-seed replacement is a `docs/FOLLOWUPS.md` V3.2
    item, not Phase 2 scope.
  - `#include "mnemonics/electrum-words.h"` removed from
    `wallet_rpc_server.cpp` (no remaining ElectrumWords callers
    in the file).
  - `tests/functional_tests/` (29 files, 6,786 lines) deleted
    outright. The plan-doc draft proposed migrating 12
    (actually 28) `restore_deterministic_wallet` and 3
    (actually 4) `stop_background_sync(seed=...)` call sites to
    surviving RPC methods. Pre-flight investigation
    (2026-05-19) surfaced four blockers that flipped the
    disposition from migrate to delete: (a) the harness invokes
    `monerod` / `monero-wallet-rpc` binaries that don't exist
    in the Shekyl tree; (b) `functional_tests_rpc` and
    `check_missing_rpc_methods` were silently skipped in CI
    because the build environment lacked the
    `requests` / `psutil` / `monotonic` / `deepdiff` Python
    deps at `cmake` configure time — inherited dead code with
    no live caller; (c) `shekyl-wallet-rpc` lacks a
    `--regtest` / `--fakechain` flag and defaults to mainnet,
    so the FFI rejects raw-seed restore on the regtest
    daemon's fakechain network; (d) the harness is
    Monero-shaped end-to-end and warrants a Shekyl-native
    rewrite under its own design doc, not a "while we're here"
    revival here. Per `15-deletion-and-debt.mdc`'s
    default-delete posture, deletion is the disposition.
    `add_subdirectory(functional_tests)` removed from
    `tests/CMakeLists.txt`; the Functional tests section of
    `tests/README.md` is rewritten to record the deletion +
    the planning posture for a Shekyl-native replacement.

  Build verification: `wallet_rpc_server`, `wallet`, `shekyld`,
  and `unit_tests` targets all build clean; `unit_tests` ctest
  pass (306s, 0 failures).

- **Vestigial CLSAG-era `ring_size` field (Phase 0 Mission Audit
  Lens E finding E.2-A; Batch α PR 2)**
  (`chore/audit-batch-alpha-pr2-ring-size-cleanup`, 2026-05-17).
  Removes the surviving CLSAG-era "ring signature size"
  parameter from the C++ wallet RPC surface and from two
  blockchain-utility residue sites. Under FCMP++ with
  full-chain membership proofs, there is no user-tunable
  ring size; the anonymity set is the entire UTXO set.
  This entry completes the cleanup begun by the prior
  Rust-side `ring_size` removal recorded above ("Decoy and
  `ring_size` removal from Rust RPC") by deleting the
  remaining C++ residue that pre-genesis audit reviewers
  would otherwise read as semantically live.

  **Wallet RPC surface (`src/wallet/wallet_rpc_server_commands_defs.h`).**
  Deleted `ring_size` field + serializer from four request
  structs (`COMMAND_RPC_TRANSFER`, `COMMAND_RPC_TRANSFER_SPLIT`,
  `COMMAND_RPC_SWEEP_ALL`, `COMMAND_RPC_SWEEP_SINGLE`; all
  four were accepted-and-ignored via `KV_SERIALIZE_OPT(...,
  (uint64_t)0)` with zero readers in the post-FCMP++
  codepath) and from one response struct
  (`transfer_description` inside `COMMAND_RPC_DESCRIBE_TRANSFER`;
  `KV_SERIALIZE(ring_size)` mandatory in response, populated
  by the now-meaningless min-across-sources walk below).

  **Wallet RPC handler (`src/wallet/wallet_rpc_server.cpp`).**
  Deleted the L1503–1505 `min(cd.sources[s].outputs.size())`
  walk that populated `desc.ring_size`; under FCMP++,
  `cd.sources[s].outputs.size()` does not represent a CLSAG
  ring and the computed value has no consensus meaning.
  Adjusted the `res.desc.push_back({...})` brace-init at
  L1471 to drop the corresponding `std::numeric_limits<uint32_t>::max()`
  third element.

  **Blockchain logging (`src/cryptonote_core/blockchain.cpp`).**
  Removed the `ring_size` local at L3192 and reformatted the
  `MINFO` log line from `I/M/O` to `I/O` (inputs/outputs).
  Under FCMP++ the "M" (mixin / ring-member count) field
  pulled from `txin_to_key.key_offsets.size()` no longer
  represents a CLSAG ring and was a vestigial logging
  residue.

  **Blockchain-usage analysis utility
  (`src/blockchain_utilities/blockchain_usage.cpp`).**
  Removed the `ring_size` field from the `reference` struct,
  the corresponding constructor parameter (`uint64_t rs`),
  and updated the sole call site at L216 from
  `reference(height, txin.key_offsets.size(), n)` to
  `reference(height, n)`. The field was write-only across
  the utility's lifetime; the per-output frequency
  accounting at the loop's tail (L222–236) counts
  `out.second.size()` only.

  **Scope and rationale.** Pre-genesis Rule-60 residue
  cleanup per `.cursor/rules/60-no-monero-legacy.mdc`. The
  standalone-PR disposition (rather than folding into the
  V3.1+ Legacy `wallet_rpc_server` Rust cutover) was
  selected because folding means vestigial `ring_size`
  ships at genesis = concrete audit-confusion vector for
  genesis-audit reviewers (5 RPC structs + desc calc +
  log line + utility struct all look semantically live
  without reading FCMP++ disambiguators). Bisectable,
  mechanical, no architectural implications. Production-
  source diff (excluding this CHANGELOG entry, which adds
  ~70 lines of documentation delta):
  `4 files changed, 4 insertions(+), 19 deletions(-)`.
  Not RingCT proper — `rct::*` types, output commitments,
  Bulletproofs+ range proofs, and the wider RCT machinery
  remain load-bearing under `RCTTypeFcmpPlusPlusPqc`.

### Changed

- **RandomX v2 Phase 0 — Copilot PR #45 Round 2 findings addressed
  (5 inline + 16 low-confidence suppressed)**
  (`feat/randomx-v2-phase0-design`, 2026-05-17). Round 2 of
  Copilot's inline review surfaced 5 inline comments and 16
  low-confidence suppressed findings against the four design
  documents. Triage and disposition follow; all 21 were accepted
  with fixes (no rejections). The findings clustered into seven
  themes:

  1. **Error-taxonomy ambiguity** (RUST.md:776, PLAN.md:290).
     `ERR_CACHE_DERIVE_FAILED` and `ERR_INTERNAL` both claimed
     coverage of "Rust panic caught at FFI shim," making the
     taxonomy ambiguous for implementers. Resolved by assigning
     panics uniformly to `ERR_INTERNAL (-4)` via
     `catch_unwind` at the shim, while
     `ERR_CACHE_DERIVE_FAILED (-3)` covers only structured
     VM-level failures the derivation deliberately returns
     (e.g., debug_assert paths). The two codes are now disjoint
     by construction; the PLAN.md §2e prose mirrors the §17
     taxonomy verbatim so future drift is impossible.

  2. **Reviewer-rule misattribution** (RUST.md:934, FOLLOWUPS
     reviewer-discipline rules-queue entry). Both entries cited
     `.cursor/rules/06-branching.mdc` as the source of an "at
     least one reviewer who is not the author" rule. Verified
     against the file: `06-branching.mdc` governs branch flow
     and release operations and contains no reviewer-count
     rule. Rewrote both to acknowledge the requirement is an
     aspirational project convention, not a codified rule, and
     to record that the V3.1 `24-reviewer-discipline.mdc`
     rules-queue entry is the *introducing* rule rather than a
     promotion of an existing one.

  3. **`cncrypto` PUBLIC-link survey gaps** (RUST.md:499,
     PLAN.md:338/402, CHANGELOG.md:98). The Round 1 survey
     expansion (from 4 to 9 targets) was still incomplete and
     misnamed `monero_fcmp_pp_crypto`. Re-ran the survey
     against the pinned tree: corrected `monero_fcmp_pp_crypto`
     → `fcmp_basic` (with `fcmp` as the second `src/fcmp/`
     target); added `src/blockchain_db/`, `src/checkpoints/`,
     `src/device/`, and `src/wallet/` (wallet_rpc_server) to
     the production-`src/` direct-consumer list; added
     `tests/wallet_bench/`, `tests/daemon_tests/`,
     `tests/functional_tests/` (two targets), `tests/hash/`,
     and `tests/performance_tests/` to the test-target list.
     Total direct-consumer count grew from 9 to 19 (13
     production + 6 test). Also clarified the §10 vs §11
     citation in PLAN.md: the survey is RUST.md §11, not §10
     (§10 is the Grover-bound section); two PLAN.md references
     corrected.

  4. **Phase 3c / Phase 4 ordering hazard** (PLAN.md:338).
     Phase 3c deletes `slow-hash.c` / `rx-slow-hash.c` / 
     `pow_cryptonight.cpp` together, but `src/cryptonote_basic/miner.cpp`
     still declares `slow_hash_allocate_state` / 
     `slow_hash_free_state` `extern "C"` and
     `src/cryptonote_basic/cryptonote_format_utils.cpp` still
     calls `crypto::rx_slow_hash` and `crypto::cn_slow_hash`
     (PoW and KDF). Phase 4 was scheduled to remove these
     callers, so the intermediate state between 3c-landed and
     4-landed would not build. Added an explicit ordering
     precondition: Phase 3c assumes §15 (RPC payments delete)
     and Phase 4 (version-gate + IPowSchema deletion) have
     already cleared the `miner.cpp` and `cryptonote_format_utils.cpp`
     call sites; if any caller remains at 3c open-time, the
     ordering is to pull that caller's removal forward into
     the 3c PR. Also noted that
     `cryptonote_format_utils.cpp`'s `cn_slow_hash` calls at
     lines 1465/1473 are non-PoW KDFs that need a Rust-side
     replacement before 3c — a Phase 4 deliverable.

  5. **RPC-payments §15.4 incompleteness** (RUST.md:642). The
     deletion checklist omitted three surfaces:
     `src/rpc/core_rpc_ffi.cpp` (registers the six
     `rpc_access_*` JSON-RPC dispatch entries),
     `src/rpc/core_rpc_server_commands_defs.h` (defines the
     `COMMAND_RPC_ACCESS_*` request/response structs), and
     `tests/functional_tests/functional_tests_rpc.py` (includes
     `'rpc_payment'` in `DEFAULT_TESTS` at line 13). All three
     added to the checklist.

  6. **Section-number drift** (CHANGELOG.md:23 inline + multiple
     §10 vs §11 references in PLAN.md). The May-16 changelog
     said "Grover-bound argument scaffold is recorded in
     `RANDOMX_V2_RUST.md` §9," but the actual section is §10
     (§9 is "Environment and Consensus Constants"). The
     PLAN.md Phase 3c step and its corresponding Risk
     acknowledgement said "Phase 0 §10 PUBLIC-link survey"
     where the survey is RUST.md §11. All corrected to RUST.md
     §10 (Grover) and §11 (cncrypto) respectively.

  7. **Smaller items.** (a) `#[export_name]` CI grep
     extended in PLAN.md §2f to cover both bare and
     `#[unsafe(export_name = "...")]` forms, mirroring the
     existing `no_mangle` pattern; the RUST.md §7.2 prose now
     names both spellings explicitly so the design doc and the
     CI grep cite the same patterns. (b) PLAN.md §6 "5 hours
     of baseline PoW work" rewritten to match RUST.md §8's
     canonical numbers: 2-hour C baseline (12 ms × 600k),
     4-hour delta at 3.0× ratio, 6-hour Rust-target total.
     (c) PLAN.md §9 Grover "√2 speedup" corrected to "square-
     root speedup against unstructured preimage search, ~2²⁵⁶
     → ~2¹²⁸" matching RUST.md §10. (d) PLAN.md §15
     "rewrite or delete" reframed as the resolved-to-delete
     disposition. (e) PLAN.md §5 (and RUST.md §5)
     `seedheight(height) -> u64` discretionary export
     reshaped to the same `i32`-return + out-parameter
     discipline as the committed hash export, per
     `40-ffi-discipline.mdc`. (f) FALLBACK.md §2's
     "`external/randomx-v2` is not added in fallback mode"
     framing split into pre-Phase-1 and post-Phase-1 cases so
     §1's late-binding framing is honored. (g) FALLBACK.md §4
     "filled after RUST.md §1" placeholder replaced with the
     concrete list of v2-deferred improvements drawn from
     RUST.md §1.3 (CFROUND throttling, F/E AES mix, program
     size, prefetch lookahead, efficiency-per-watt aggregate).
     (h) CHANGELOG.md May-16 entry's "six places" replaced
     with "eight places" so the count matches the
     enumeration that follows.

  Files touched: `docs/CHANGELOG.md`,
  `docs/design/RANDOMX_V2_PLAN.md`,
  `docs/design/RANDOMX_V2_RUST.md`,
  `docs/design/RANDOMX_V1_FALLBACK.md`,
  `docs/FOLLOWUPS.md`.

- **RandomX v2 Phase 0 — Copilot PR-review-bot findings triaged and addressed (PR #45)**
  (`feat/randomx-v2-phase0-design`, 2026-05-16). Copilot's inline
  review of PR #45 surfaced 13 findings against the Phase 0 design
  docs. Triage and disposition follow; 12 accepted with fixes, 1
  accepted as a CHANGELOG-only softening (the Grover §9 placeholder
  is intentional Phase 0 work, but the CHANGELOG previously
  overpromised that it was shipped).
  
  Fixes in this commit:
  
  - **CHANGELOG**: PLAN.md added to the "Added" entry alongside
    RUST.md and FALLBACK.md (PLAN.md was added in this PR but the
    Added entry only named two of the three design docs). The
    Grover-bound claim softened to "scaffold recorded in §9;
    concrete release-checklist calculation deferred to Phase 0
    review per §9's closing sentence."
  - **PLAN.md frontmatter**: `overview:` value wrapped in double-
    quotes per the WALLET_REWRITE_PLAN.md precedent so the unquoted
    `: ` sequences (`No prewarm: lazy`, etc.) no longer break YAML
    parsing. Confirmed parsing via `python3 -c "import yaml; ..."`.
  - **PLAN.md Decision #6 cost analysis + §6 perf budget**: rewrote
    the "below Nielsen's 100 ms threshold" claim (mathematically
    wrong: 150 ms > 100 ms). New framing: "above 100 ms by ~50 ms
    but well below the 1 s continuous-flow threshold, and invisible
    in practical RPC-round-trip context."
  - **PLAN.md root-relative links**: 32 cross-references rewritten
    from repo-root-relative (`](src/...)`, `](rust/...)`, etc.) to
    proper relative paths (`](../../src/...)`) so GitHub renders
    them correctly from `docs/design/`. Verified each rewritten
    link resolves to a real path (29 OK; 2 intentional forward
    references: `external/randomx-v2` is added by Phase 1,
    `RANDOMX_V2_PHASE_3B_DELETED_CALL_AUDIT.md` by Phase 3b).
  - **PLAN.md Phase 2f C-ABI exports invariant**: the existing
    `extern\s*"C"\s*\{` grep matches only foreign import blocks,
    not the `pub extern "C" fn` shape the invariant is supposed to
    forbid. Replaced with three explicit patterns: `#[no_mangle]`
    (both spellings), `extern "C" fn` (any function declaration),
    and `#[export_name = "..."]` (the bypass shape). The intent of
    each pattern is documented inline.
  - **PLAN.md Phase 3 caller-survey scope**: added an explicit
    clarifying paragraph noting that the "six C++ daemon-side
    caller files" is the Phase 3 *rewire* set, not the full repo-
    wide `rx_*` footprint. The four additional files Copilot's
    grep surfaced (`miner.cpp`, `cryptonote_format_utils.cpp`,
    `rpc_payment.cpp`, `wallet_rpc_payments.cpp`) are intentionally
    handled by §15 (RPC payments deletion) and Phase 4 (version-
    gate + IPowSchema deletion), not by Phase 3.
  - **PLAN.md Phase 2e allocation guidance**: softened the
    misleading OOM coverage. The Phase 2e allocation APIs
    (`Box::new_zeroed_slice`, `vec![]`) are infallible: they abort
    on OOM rather than return an error, so the FFI shim never sees
    a result it could map to `ERR_CACHE_DERIVE_FAILED`. The plan
    now records that OOM at cache derivation aborts and that a
    fallible-allocation path with an `ERR_CACHE_ALLOC_FAILED`
    taxonomy entry is V3.x work if any future caller needs OOM-
    recoverable derivation.
  - **RUST.md §1.2 reference clone**: removed the
    contributor-specific absolute path
    `/home/torvaldsl/shekyl/RandomX/` (committing a single
    developer's `$HOME` path is non-reproducible). Replaced with a
    portable description noting that Phase 0 contributors may keep
    a sibling clone at the same pin as a contributor-local
    convention, with a fork URL for those who prefer not to.
  - **RUST.md §11 cncrypto PUBLIC-link survey**: expanded the
    direct-consumer list from 4 targets to 9, adding the load-
    bearing `common` link (which sits below most subsystems and
    transitively re-exports `randomx_*` to everything depending on
    `common`) plus `cryptonote_basic` (two targets), `cryptonote_core`,
    `daemon`, and `fcmp` (two targets). Also recorded that
    `tests/crypto/CMakeLists.txt`'s `cncrypto-tests` does **not**
    link `cncrypto` directly (it links `common` and gets cncrypto
    transitively); the test name is historical. Phase 3 link-drop
    checklist is now accurate.
  - **RUST.md §19 audit doc filename**: renamed
    `RANDOMX_V2_PHASE3B_AUDIT.md` (RUST.md's spelling) to
    `RANDOMX_V2_PHASE_3B_DELETED_CALL_AUDIT.md` (PLAN.md's
    canonical spelling). Single canonical filename across both
    design docs.
  - **RUST.md §17 ERR_CACHE_DERIVE_FAILED semantics**: clarified
    that this code covers VM-level failures and Rust panics caught
    at the FFI shim, **not** allocation failure. OOM during cache
    derivation aborts the process via `handle_alloc_error` per
    Rust's default allocator; this is consistent with PLAN.md
    §2e's infallible-allocation choice. A future
    `ERR_CACHE_ALLOC_FAILED (-5)` entry is sketched as V3.x work
    if a caller ever needs OOM-recoverable derivation.
  - **FALLBACK.md status block**: rewrote the L6 status block to
    match §1's late-binding framing. The previous text ("invoked
    only if Phase 0 review concludes RandomX v2 is not ready")
    contradicted the §1 round-1 revision that made the fallback
    invocable any time between Phase 0 and genesis release.
  
  Findings rejected or partially addressed:
  
  - **Grover §9 placeholder (RUST.md L481)**: Copilot flagged §9
    as incomplete because it ends with "Phase 0 review must fill
    this section with the concrete target-range calculation." The
    placeholder is intentional — concrete numbers depend on
    Shekyl's final difficulty-target tuning, which is a Phase 0
    review item, not implementation. Disposition: keep §9 as-is;
    soften the CHANGELOG's claim about Grover-bound coverage (done
    in this commit) so the doc-vs-changelog asymmetry resolves.
  
  Files touched: `docs/CHANGELOG.md`,
  `docs/design/RANDOMX_V2_PLAN.md`,
  `docs/design/RANDOMX_V2_RUST.md`,
  `docs/design/RANDOMX_V1_FALLBACK.md`.

- **RandomX v2 Phase 0 — plan-vs-design-doc drift fix and four smaller items**
  (`feat/randomx-v2-phase0-design`, 2026-05-16). The previous round
  moved the algorithm-review gate from "before Phase 2" to release-
  time in [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §1.4,
  but [`RANDOMX_V2_PLAN.md`](./design/RANDOMX_V2_PLAN.md) still
  carried the old Phase-2-gate framing in eight places: frontmatter
  `algorithm-review-gate` todo, frontmatter `overview` text,
  frontmatter `phase5-docs` todo, body §"Algorithm-review gate
  (Track A intra-track)", body §"Track A — Algorithm-review gate",
  body §"Track A — Phase 2 (gated on algorithm review)" title, body
  §"Risk acknowledgments" v2-algorithm-posture entry, and the
  mermaid diagram. This commit aligns the plan with the design doc:
  the gate is release-time, Phase 2 proceeds in parallel with
  Monero's audit, and the mermaid diagram redrawn so the release
  gate sits after Phase 5 with `MonAudit`/`MonDeploy` as parallel
  external inputs that don't block Track A or Track B.
  Also folds in four smaller items from the same review pass:
  (a) [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §16 gains
  a `const _: () = assert!(...)` compile-time assertion that
  `SEEDHASH_EPOCH_BLOCKS.is_power_of_two()`, because the
  `& !(SEEDHASH_EPOCH_BLOCKS - 1)` mask in the `seedheight()`
  formula silently produces the wrong consensus result if the
  constant is ever changed to a non-power-of-2. (b) §17 adds an
  explicit four-case table for the `data` / `data_len` pairing so
  the `data == NULL && data_len == 0` empty-input case is no longer
  ambiguous at the FFI boundary. (c) §23 gains §23.1 recording the
  per-gate reviewer-discipline calibration pattern as a candidate
  for promotion to `.cursor/rules/24-reviewer-discipline.mdc`. (d)
  Two new V3.1 FOLLOWUPS entries in
  [`FOLLOWUPS.md`](./FOLLOWUPS.md): one tracking the §22 Guix
  reproducible-build obligation pickup (fires when Guix integration
  lands; closes when the Guix-integration design doc rewrites §22
  to point at the actual manifest), and one tracking the §23.1
  reviewer-discipline rule promotion (sibling to the existing
  rules-queue entries).
  Softens the previous round's framing: the RandomX v2 work is
  primarily **fresh debt clearance** (`IPowSchema`/`pow_registry`,
  `shekyl-consensus`, RPC payments, and the `rx-slow-hash.c`
  stateful core were not previously tracked in FOLLOWUPS), so the
  Phase 5 FOLLOWUPS pass is mostly forward-looking close-records
  rather than closure of pre-existing items. The V3.0 pre-genesis
  queue's accumulation/resolution trajectory is unaffected by this
  work.

- **RandomX v2 Phase 0 — algorithm-review gate moves from Phase-2 to release**
  (`feat/randomx-v2-phase0-design`, 2026-05-16). Rewrites
  [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §1.4 to record
  that the two Phase-0 open questions ("who else deploys v2?" and
  "who funds the v1→v2 delta audit?") both resolve to **Monero**.
  Monero is in the process of deploying upstream RandomX v2 (PR #317)
  in parallel with Shekyl's implementation, and is funding the delta
  audit. Because Shekyl is non-divergent from upstream (§1.1) the
  audit's scope covers Shekyl's pinned code byte-for-byte; Shekyl
  inherits the audit result without coordinating it. The
  previously-listed "algorithm-review gate before Phase 2" is
  **removed** — Phase 2 is faithful spec implementation, not an
  algorithm-soundness decision, and gating it on external work
  Shekyl does not control would either delay or duplicate effort.
  §1.4 introduces the explicit **release-time gate**: before genesis,
  Monero's production v2 deployment must have had meaningful
  observation-window exposure AND the Monero-funded delta audit must
  have completed without contraindicating findings. §1.1 records
  that non-divergence is a load-bearing strategic posture — what
  buys Shekyl audit inheritance and the unpin-and-revert v1 fallback
  — not an accident. §23 reviewer-discipline updated to reflect the
  release-time gate and to distinguish inherited external review
  (via non-divergence) from Shekyl-direct external review.
  [`RANDOMX_V1_FALLBACK.md`](./design/RANDOMX_V1_FALLBACK.md) §1
  reframes the fallback as **late-binding** (any time between Phase
  0 and release), unpin-to-`102f8acf` rather than stop-and-restart,
  with explicit Production-deployment-failure and Inheritance-
  failure trigger classes added to the existing list. Plan todo
  `algorithm-review-gate` rewritten from a Phase-2 blocker to a
  release-time gate that runs in parallel with implementation work.

- **RandomX v2 Phase 0 — fork relationship and pinned source recorded**
  (`feat/randomx-v2-phase0-design`, 2026-05-16). Rewrites
  [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §1 from a
  forward-looking "Shekyl-controlled divergence" framing to the
  empirical picture: the `Shekyl-Foundation/RandomX` fork tracks
  upstream `tevador/RandomX` without divergence; RandomX v2 is the
  upstream tevador algorithm landed in PR #317 (commit `bb6ed2c`);
  and the fork's pinned commit is `aaafe71` ("Prepare v2.0.1
  release", 2026-05-10). (The original draft of §1.2 named a
  contributor-local sibling-clone path; that path was removed in
  the same review round per the portable-path rule, see the later
  Changed entry. The path is intentionally not quoted here either.)
  §1.3 distills the four concrete
  v1→v2 changes from the fork's `doc/design_v2.md` (CFROUND
  throttling, F/E AES mix replacing XOR, program-size 256→384,
  two-iteration dataset prefetch lookahead) and their ~130-165 %
  efficiency improvement on Zen 3/4/5 silicon. §1.4 records the
  algorithm-review status: the four 2019 audits in the fork's
  `audits/` directory (Trail of Bits, X41, Kudelski, Quarkslab) cover
  v1 and bound the Phase 2 review scope to the v1→v2 delta rather
  than RandomX from scratch. §3 names the three normative spec files
  (`doc/specs.md`, `doc/design_v2.md`, `doc/configuration.md`) as the
  Rust port's source-of-truth references. §11 records that the
  current `external/randomx` submodule is at v1-era `102f8acf` and
  Phase 1 adds `external/randomx-v2` at `aaafe71` as a **new**
  submodule alongside it (not a repoint) so the v1→v2 swap is a
  single reviewable commit later. [`RANDOMX_V1_FALLBACK.md`](./design/RANDOMX_V1_FALLBACK.md)
  §2 records that v1 lives at any pre-PR-#317 commit on the same
  fork (default fallback pin: `102f8acf`, already in the existing
  submodule), and §3 records that the four 2019 audits already ship
  in the fork's `audits/` directory at the pinned v1 commit.

- **RandomX v2 Phase 0 — RPC-payments disposition resolved to delete**
  (`feat/randomx-v2-phase0-design`, 2026-05-16). Rewrites
  [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) §15 from the
  open "rewrite or delete" question to an explicit **delete** decision
  with the rationale recorded (no users pre-genesis per
  `60-no-monero-legacy.mdc`; the feature shipped with essentially zero
  Monero production adoption; a future monetization story is better
  designed fresh against 2026+ options than inherited from 2020). Adds
  §15.4 with the concrete deletion checklist — five `rpc_payment*`
  files plus `wallet_rpc_payments.cpp` plus a functional test deleted
  whole, surgical hook removal across `core_rpc_server`,
  `bootstrap_daemon`, `node_rpc_proxy`, `wallet2`, `wallet_args`,
  `wallet_rpc_helpers`, `wallet_rpc_server`, the daemon CLI command
  files, `cryptonote_config.h`, and the two CMakeLists — so Phase 4
  inherits a checklist rather than a question. Tightens Phase 4 scope
  materially: the v2 verifier FFI export is consumed by daemon block
  verification only, with no wallet wiring.
  [`RANDOMX_V1_FALLBACK.md`](./design/RANDOMX_V1_FALLBACK.md) §2
  records the deletion as algorithm-independent and inherits the same
  checklist under fallback.

- **RandomX v2 Phase 0 — Round 1 review-feedback revisions**
  (`feat/randomx-v2-phase0-design`, 2026-05-16). Expands
  [`RANDOMX_V2_RUST.md`](./design/RANDOMX_V2_RUST.md) with new sections
  §16 (genesis-block seedhash handling, including the `rx_seedheight`
  early-block branch and a canonical Rust `seedheight()` form), §17
  (FFI error-code taxonomy with stable negative codes), §18 (thread-
  safety contract for `shekyl_pow_randomx_v2_hash`), §19
  (`block.major_version` field disposition after PoW dispatch
  deletion), §20 (BSD-3-Clause licensing and attribution), §21 (MSRV
  pin proposal and `#[no_mangle]` / `#[unsafe(no_mangle)]` grep
  coverage), §22 (Guix reproducible-build forward-looking impact), and
  §23 (reviewer discipline under the project's solo-architect reality).
  Tightens §3 with test-vector provenance rules (`tests/vectors/spec/`
  vs `tests/vectors/reference/`), §8 with the synthetic pre-genesis
  600k-block release-gate harness, and §15 with a checked-in grep
  result narrowing wallet-tree PoW touchpoints to
  `wallet_rpc_payments.cpp:156/158/163`.
  [`RANDOMX_V1_FALLBACK.md`](./design/RANDOMX_V1_FALLBACK.md) §2
  records the upstream-`tevador/RandomX`-vs-Shekyl-fork v1 source
  choice and the `BUILD_RANDOMX_V2_MINER_LIB` rename, §4 fixes the
  cross-reference to `RANDOMX_V2_RUST.md` §1, §6 corrects the same
  cross-reference, and §7 mirrors the reviewer-discipline section.

- **Stage 1 PR 3 — close-out: `engine_trait_bench_key_account_public_address`
  pair** (`chore/stage-1-pr3-closeout`, 2026-05-12). Introduces the
  criterion + iai-callgrind sibling pair for the
  `KeyEngine::account_public_address` trait method, classified under
  the `engine_trait_bench_*` threshold class via `compare.py`'s
  `classify()` function-name routing. The fixture is `Box<LocalKeys>`
  rather than the canonical `(Box<Engine<...>>, TempDir)` shape per
  the substrate-forced divergence documented in
  [`STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md`](./design/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md)
  §1.2 — `Engine` does not yet hold a `LocalKeys` field;
  orchestrator integration is `KeyEngine` PR-5 territory per
  [`STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
  §2.1.1 (Round 4a workflow-shape pivot). Workload class is
  **trivial pure-read** (cached `AccountPublicAddress` borrow);
  iai-callgrind is the load-bearing signal because criterion
  `median_ns` reflects optimizer amortization across the iteration
  loop (§4.4 hoisting caveat). The bench-internals visibility
  expansion adds only `LocalKeys` to the `pub` surface (following
  the exact precedent of `LocalLedger` at Stage 1 PR 2 — name-only
  expansion; fields stay private). `LocalKeys::from_test_seed`
  becomes `pub` under `#[cfg(any(test, feature = "bench-internals"))]`
  matching `LocalLedger::populate_for_bench`'s gating.
  `AccountPublicAddress` stays `pub(crate)` — the bench helper
  returns a primitive `usize` summary (sum of address-field
  byte-lengths) rather than the natural `&AccountPublicAddress`
  return type, sidestepping the API-widening Copilot's PR review
  flagged. Closes two of four deferred-bench slots from
  [`FOLLOWUPS.md`](./FOLLOWUPS.md)'s Stage-1-performance-baseline
  entry (`ledger_balance` previously satisfied at Stage 1 PR 2,
  `key_account_public_address` here); two EconomicsEngine slots
  remain pinned to the EconomicsEngine trait-introducing PR.

### Changed

- **Stage 1 PR 4 — Round 4 review pass meta-review amendment
  (review of F1–F9 disposition substrate; three additional
  findings F11–F13 dispositioned without reopening
  Round 1–4)** (`feat/stage-1-pr4-round-4`, 2026-05-15).
  Doc-only meta-review of the F1–F9 disposition substrate
  itself, asking "do the dispositions create new attack
  surface or leave under-specifications that would surface
  at Phase 1 commit-authoring as substrate decisions?" Three
  additional findings emerged, each targeting an under-
  specification *introduced by* an F1–F9 disposition rather
  than a substrate decision Rounds 1–4 settled; none reopens
  a Round 1–4 disposition; the F1–F9 dispositions remain
  unchanged. **F11 (per-transaction cancellation safe-point
  pin; meta-review of F2).** F2's five-checkpoint discipline
  pinned *that* a per-transaction cancellation check fires
  but did not pin *where* in the per-transaction body. F11
  pins the check fires *between* transactions, *after* the
  prior iteration's `Zeroizing<…>`-wrapped per-output
  materials have left scope, *before* the next transaction's
  view-tag / hybrid-decap / key-image derivation begins
  (forbidding mid-derivation firing that would defeat F2's
  lock-latency property by exposing partial-derivation
  state on the unwound stack to memory-disclosure
  adversaries). C7's `AssertionSink` / coherence-pair test
  substrate gains a safe-point fixture asserting no partial-
  derivation state at the observed cancellation point.
  **F12 (cross-emitter ordering contract-gap; meta-review
  of F4).** F4's seventh contract pin (per-emitter FIFO
  preserved; cross-emitter ordering undefined) is enforced
  procedurally; consumer-actor authors who depend on
  cross-emitter arrival order produce code that compiles
  cleanly, passes per-emitter FIFO tests, and silently
  misbehaves under reordering at audit. F12 closes the gap
  at the discipline level (V3.0: §5.4.6 amendment binding
  consumer actors to derive cross-emitter ordering from
  causal-context fields like `SnapshotId`, `ReservationId`
  + version, `BlockHeight`) and at the lint level (V3.1+:
  scope-extending the FOLLOWUPS F5 entry to a unified
  `diagnostic_consumer_discipline` lint covering both
  recursive-trust-boundary and cross-emitter-ordering misuse
  sub-scopes). PR 5 §5.0.3 carries the parallel amendment.
  **F13 (`SuppressedRateLimit` field-shape pin; meta-review
  of F6).** F6 added the `SuppressedRateLimit` variant
  without pinning its field shape; counts, timestamps, and
  original-event payloads are each attacker-relevant signal
  (counts are a covert channel back from the producer's
  internal state; timestamps add scheduling side-channels;
  payloads defeat the projection-type discipline). F13
  pins the variant carries `class: SuppressedClass` only,
  where `SuppressedClass` is a project-defined
  `#[non_exhaustive]` enum at the same crate-root scope
  with arms one-per-rate-limited event class; consumer
  actors derive the suppression count from absence-of-
  further-events within the attempt boundary. C2's
  `SuppressedClass` enum addition lifts the flat-crate-root
  re-export list from eight items to nine. The
  implementation-branch authorization continues to hold;
  the meta-review amendment shapes Phase 1's substrate
  without reopening it or extending its scope. The
  meta-review pattern itself is recorded as a forward-
  template under
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)'s
  "audits-are-clean-so-compress" anti-pattern framing:
  clean F1–F9 dispositions invite declaring victory; the
  discipline asks whether the dispositions themselves
  carry the property they claim before implementation cuts
  against them.

  **Post-amendment sub-pins (F11-S, F12-S, F13-S, 2026-05-15).**
  A third-pass review of the F11–F13 dispositions themselves
  surfaced three Phase-1-author-aware sub-pins. Each sharpens
  the corresponding F-finding's disposition without reopening
  it; none reopens a Round 1–4 substrate decision; none
  reopens an F1–F9 disposition. The recursive structure
  (review pass → meta-review → post-amendment) is the
  closure rule's reopening mechanism operating at each level
  of the substrate hierarchy. **F13-S
  (`SuppressedRateLimit` emission-cadence sub-pin; the
  substantive one).** F13's field-shape pin (carries class
  only) closed the payload covert channel but left the
  emission-cadence covert channel open: if the producer
  emits one notice per suppression-fire, an attacker
  reconstructs suppression frequency by counting notice
  arrivals in their own emit-arrival timeline regardless of
  payload shape. F13-S pins emission cadence at "at most one
  `SuppressedRateLimit { class }` per class per attempt" —
  the producer's per-attempt `emit_state` carries a per-class
  `notice_emitted: bool` latch, cleared at attempt start,
  never cleared mid-attempt; subsequent in-class budget
  exceedances drop events but do not emit further notices.
  Cross-attempt cadence (attacker forcing many attempts via
  `ConcurrentMutation`-driven retries) is bounded at the
  orchestrator's existing retry-loop policy layer; no
  producer-side state survives across attempts (the
  zeroization scope for `ViewMaterial` and `Scanner`
  forecloses producer-side cross-attempt state). **F11-S
  (per-output safe-point escalation criterion).** F11's
  per-transaction safe-point closes the mid-derivation
  residency window for typical transactions but may not hold
  under hostile transactions carrying many outputs (FCMP++
  permits some upper bound; the §3.1 lock-latency property's
  content-independence becomes content-dependent if
  `recover_outputs_in_tx`'s per-output cost grows linearly
  with output count above the lock-latency target). F11-S
  pins the escalation criterion: Phase 1 commit-author
  verifies against benchmarked cost on reference hardware
  and against the protocol-parameter upper bound on outputs
  per transaction; if worst-case per-tx scan time exceeds the
  §3.1 lock-latency target, the safe-point escalates to
  per-output granularity (check between consecutive per-output
  decap iterations). The C4 commit message records the
  measurement and the chosen granularity. **F12-S
  (`diagnostic_consumer_discipline` lint conceptual
  unification).** F12's unification is at the contract level
  (one named discipline, two related properties); the
  implementation strategy follows each property's nature (F5
  sub-scope likely as a compile-time trait-bound or `clippy`
  lint over consumer constructors; F12 sub-scope likely as an
  AST-level pattern-match over event-handler bodies). F12-S
  pins the conceptual-not-monolithic clarification in the
  FOLLOWUPS entry, foreclosing a future "the lint doesn't
  exist as a single pass" finding from invalidating a
  multi-check implementation that delivers the unified
  discipline. The post-amendment pattern compounds the
  closure-rule discipline (PR 5 §7): each level closes the
  wargaming surface known at its own closure time;
  reopening is explicit at the level of the surface that
  surfaced. The implementation-branch authorization continues
  to hold; the sub-pins shape Phase 1's substrate without
  reopening it or extending its scope.

- **Stage 1 PR 4 — Round 4 review pass
  (adversarial review of post-Round-4 substrate; nine
  findings dispositioned)**
  (`feat/stage-1-pr4-round-4-review`, 2026-05-15). Doc-only
  pre-implementation adversarial review of the post-Round-4
  substrate before Phase 1 cuts. Two reviewers exercised
  the diagnostic-stream seam, the encrypted-persistence
  opt-in language at PR 4 §5.4.8 #1, and the resilience
  surface from a hostile-daemon perspective; the pass
  produced **nine actionable findings**, all dispositioned
  and applied as substrate hardening rather than reopening
  any Round 1–4 question. Full writeup at PR 4 §5.4.9.
  Findings cluster across three threat-model surfaces.
  **Feature-soft-commitment hardening (F1, F7).** F1
  rewrites the §5.4.8 #1 R17 encrypted-persistence opt-in
  language from "V3.x evaluates" to a hard rejection at
  V3.0 with strict conditional reopening criteria (six
  attack vectors named: crypto code-path expansion,
  deserialization-on-startup, metadata side-channel,
  cross-wallet correlation, adversary-controlled DoS,
  forensic-artifact); F7 adds a parallel new §5.4.8 #6
  rejecting "encrypted cache for RPC recovery" V3.x
  candidates at V3.0 under symmetric criteria. PR 5
  §5.4 R17 carries the F1 hardening symmetrically;
  the FOLLOWUPS `PersistenceConsumerActor` entry is
  rewritten as a conditional-reopening bookmark with no
  version target. **Checkpoint-discipline tightening (F2).**
  §3.1 wallet-lock-latency property refines from
  "single-block scan time, typically tens of ms" to
  "per-transaction scan time, sub-block-bounded; millisecond-
  scale even under adversarial daemon block crafting"; §7
  checkpoint discipline extends from four to **five**
  checkpoints with a per-transaction inner cancellation
  check inside the per-block scan loop (closing the
  adversarial-block-crafting / extended-spend-secret-
  residency vector). **Diagnostic-stream contract
  pinning (F3, F4, F5, F6, F8, F9).** F3 pins
  `AssertionSink` / `PanickingSink` as permanent CI
  regression coverage rather than one-shot landing tests;
  F4 adds a **seventh contract pin** at §5.4.6
  (per-emitter FIFO ordering preserved; cross-emitter
  ordering undefined) — the same pin lands symmetrically
  in PR 5 §5.0.3; F5 strengthens §5.4.8 #4's
  aggregator-republisher recursive-leak framing with a
  V3.x forward-template (per-consumer external-surface
  audit, projection-or-rejection, future CI-lint
  enforcement) and gets a new V3.1+ FOLLOWUPS entry
  (consumer-actor-PR aggregator-republisher CI lint);
  F6 adds a producer-side per-class emission rate budget
  to §5.4.8 #5 (per-block ceilings per event class plus a
  `RefreshDiagnostic::SuppressedRateLimit` variant); F8
  adds a new §5.4.8 #7 acknowledging emit-timing variance
  as a microarchitectural side-channel residual with a
  Phase 1 implementation note for bounded-variance
  lock-free queues; F9 adds a §6 projection-type audit
  per event class with explicit V3.0 per-class projections
  for `TracingDiagnosticSink` and gets a new V3.x
  FOLLOWUPS entry (diagnostic-stream spec-doc projection-
  type formalization). The §7.X commit decomposition
  absorbs the substrate hardening: C2 carries the
  `SuppressedRateLimit` variant + per-class projections +
  7th contract pin; C4 carries the per-transaction inner
  cancellation check + producer-side per-class emission
  rate budget enforcement; C7 carries `AssertionSink` /
  `PanickingSink` as permanent CI fixtures. The
  α-disposition still holds; all Round 1–4 dispositions
  still hold; the review pass hardens contract pins and
  attack-surface dispositions without reopening any
  design question. Implementation-branch authorization
  (per §6 Round 4 readiness gate) is unchanged;
  Phase 1 cuts against the hardened substrate. The
  review-pass shape is recorded as a forward-template
  artifact under
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)'s
  "discovery cadence" framing — substrate hardening ahead
  of implementation is reusable for PR 5+ pre-implementation
  substrate review.

- **Stage 1 PR 4 — Round 4 close
  (commit decomposition + Phase 1 commit list)**
  (`feat/stage-1-pr4-round-4`, 2026-05-14). Single-commit
  doc-only Round 4 close on
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  per the PR 1 / PR 2 / PR 3 / PR 5 precedent. §4 Phase 0
  candidates (0a–0e, with 0d struck) finalize as
  binding-pinned at the type-signature level; Round 4 audit
  confirms `DaemonOp` two-variant and `ProtocolErrorKind`
  five-variant refresh-reachable subset against the producer's
  actual call sites. §6 review checklist fills in following
  PR 5's shape (binding-check matrix against
  `V3_ENGINE_TRAIT_BOUNDARIES.md` §2.3, test-substrate
  preservation list, call-site sweep audit, Round 4 readiness
  gate authorizing Phase 1 cut). §7 extends with the Round-4
  retrospective + a new §7.X Phase 1 commit decomposition
  subsection — eight load-bearing-ordered commits (C0 doc-only
  spec amendment + C1 trait declaration + `ViewMaterial` type;
  C2 `RefreshDiagnostic` + `DiagnosticSink` + Stage 1 sink
  impls; C3 `RefreshError::InternalInvariantViolation` variant
  addition; C4 `LocalRefresh` aggregate + producer-body
  migration; C5 `Engine` parameterization + retry-loop call-site
  migration + `RpcError` classification; C6 `MockRefresh` test
  substrate + `replace_refresh`; C7 hybrid retry test +
  `AssertionSink` / `PanickingSink` property tests; C8 docs +
  CHANGELOG). §8 closes out the five "Remaining for Round 4"
  items (each marked Round-4-deliverable or
  Phase-1-commit-target) and updates the round trajectory
  banner — all PR-4-internal design rounds are closed.
  Implementation branch (`feat/stage-1-pr4-refresh-engine`)
  is authorized to cut off the post-Round-4 dev tip per the
  §6 Round 4 readiness gate; no further design rounds open
  unless Phase 1 commit-authoring surfaces a structural
  finding (the closure rule per
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §7 governs reopening if it does).

- **Stage 1 PR 4 — Round 3 confirmation
  (α confirmed by PR 5 Round 1's actor-mesh-framed disposition)**
  (`feat/stage-1-pr4-round-3-confirmation`, 2026-05-14). Single-commit
  doc-only Round 3 closure on
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md).
  PR 5 Round 1's disposition under the actor-mesh framing (per
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.0 / §5.2 / §5.5) confirmed shape (1) — *snapshot-ID pinning* —
  with the reservation tracker holding monotone semantics under
  PR 4's α; PR 4 advances directly to Round 4 (commit decomposition
  + Phase 1 commit list). The
  *provisionally-load-bearing* qualifier on Round 1's α
  (per §5.3 / §5.4.7 R1 / §8) is closed; the re-evaluation gate
  collapsed without firing. Four housekeeping items land alongside
  the closure: (1) §3.1 acknowledges the V3.0 *dual spend-material
  holder* state — `LocalRefresh` / `Scanner` (PR 4 R4 (a),
  inheritance-asymmetry justification) and `LocalSigner` (PR 5 R11
  (b), architectural-integrity-now justification), convergent to
  one holder via R4 (c) in V3.x; (2) §8 / FOLLOWUPS R4 (c) entry
  cross-references PR 5 R11 (b)'s `Signer` trait substrate as the
  V3.x migration target — the R4 (c) migration becomes *"`Scanner`
  stops holding spend material; delegates key-image generation
  via the existing `Signer` trait"* rather than designing the
  split from scratch, shrinking the V3.x cost to a producer-side
  shape change (no architectural change); (3) the
  `REFRESH_DIAGNOSTIC_STREAM.md` → `DIAGNOSTIC_STREAM.md` rename
  housekeeping was already covered by PR 5 segment 2g — no PR 4
  doc references remain to sweep (confirmed by `rg`); (4) §5.4.8
  #1's drop-on-close-by-default rule is acknowledged as
  project-wide rather than refresh-specific per PR 5 R17's
  closure — V3.0 ships drop-on-close across all diagnostic
  streams; per-stream wallet-internal encrypted-persistence
  opt-in is a V3.x refinement evaluated at the diagnostic-stream
  spec doc. The discovery-cadence prediction in
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  ("PR 4 onward's audits are increasingly likely to be
  confirmations") holds at the Round 1 / Round 3 boundary on the
  load-bearing question; the Round 2 reframe and PR 5 R11 (b)'s
  reframe are the two structural-density events that surfaced
  inside this PR's design rounds.

- **Stage 1 PR 3 — close-out: `STAGE_1_PR_*` design-doc past-tensing
  + plan-vs-state-divergence rules-queue input sharpening**
  (`chore/stage-1-pr3-closeout`, 2026-05-12). Three-commit close-out
  PR consolidating audit findings from PR #40 under the trinary
  rule-15 reading per
  [`STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md`](./design/STAGE_1_PR_3_CLOSEOUT_PREFLIGHT.md):
  - **A1 commit (mechanical past-tensing sweep)**: reconciled
    17-reference enumeration across
    [`STAGE_0_HARNESS.md`](./design/STAGE_0_HARNESS.md),
    [`STAGE_1_PR_1_DAEMON_ENGINE.md`](./design/STAGE_1_PR_1_DAEMON_ENGINE.md),
    and [`STAGE_1_PR_2_LEDGER_ENGINE.md`](./design/STAGE_1_PR_2_LEDGER_ENGINE.md)
    to 13 in-scope references; `PERFORMANCE_BASELINE.md`'s four
    references were deferred to the A2 commit which rewrites those
    sections wholesale. Mode-2 closing-out residue under the trinary
    rule-15 reading, swept inline rather than deferred.
  - **B1+B2 + lemma commit (rules-queue input sharpening for V3.1)**:
    extends `FOLLOWUPS.md` §19 (plan-vs-state-divergence) with the
    commit-history-level fourth-precedent instance (PR #40's
    4-vs-6-vs-8 commit divergence between planned logical units,
    pre-review commit count, and final merged commit count). Extends
    the rule-15 trinary entry with PR #40's applied-disposition
    table (eight dispositions across two review-response cycles,
    classified by mode 1/2/3). Adds a new V3.1 entry — "Rules-queue:
    encode the pre-flight-FOLLOWUP-scope discipline" — generalizing
    the recurrence that FOLLOWUP items naming target PRs as
    resolution points orphan when target pre-flights don't claim
    them; cites L353-379 KeyEngine slot's M-series-wide skip as
    precedent.
  - **A2 commit (KeyEngine bench introduction)**: see the "Added"
    section above for full detail.
  - **C1-C3 audit verifications (recorded in PR description)**:
    `TransferDetails` field removal structurally complete; M3-series
    naming sweep complete (preserved-as-history or false-positive);
    `42-serialization-policy.mdc` stale globs closed in M3e. Three
    clean-as-found invariants from PR #40's audit pass.

- **Stage 1 PR 3 — M3e: documentation realignment to post-M3d
  architecture** (`feat/stage-1-pr3-m3e`; six commits cut off `dev`
  post-M3d, landing the four logical units planned at amendment-cycle
  time per
  [`STAGE_1_PR_3_M3E_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3E_PREFLIGHT.md)
  §4: the "preflight + review-response + amendment" logical unit
  landed across three actual commits — original preflight at
  `82693bab7`, forward-templates capture at `4b931b1b5`, amendment
  at `1f9a7ad59` — followed by three substantive commits at
  `8e6780062` / `582c19caf` / `c61f0d38f`. The plan-vs-state
  divergence between the four-logical-unit framing and the six-actual-
  commit landing is recorded inline in §4 of the preflight as an
  instance of the §19 plan-vs-state-divergence pattern at the commit-
  history level). Closes the M3-series migration of `TransferDetails`
  per
  [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`](./design/STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.5 (M3e — documentation realignment-of-the-whole) and
  [`docs/design/STAGE_1_PR_3_M3E_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3E_PREFLIGHT.md)
  §6 (Success criteria). The M3-series (M3a–M3e) is complete; the
  "secrets confined to engine" property activated by M3d is now
  reflected throughout the design-doc and rules-corpus surfaces.

  - **Design-doc realignment.**
    [`KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md) carries a
    post-migration status banner and past-tensed forward-looking
    framing in §1.1, §1.2, §5.2; open questions in §7 are annotated
    per-question with `[Closed at M3<X>; see <ref>]` or `[Remains
    open / Forward-looking record]` while preserving original
    framing as historical record.
    [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
    replaces the pre-migration `KeyEngine` trait block with the
    post-M3 4-method shape (`account_public_address`,
    `derive_subaddress`, `try_claim_output`, `sign_transaction` per
    `rust/shekyl-engine-core/src/engine/traits/key.rs:616`),
    refactors the per-method classification table and retry-safety
    enumeration, and updates 13 scattered narrative references to
    `sign_with_spend` → `sign_transaction` while preserving the
    "Round 2 dispositions" section's original Q9.1/Q9.2/Q9.3
    framings as historical record.
    [`MIGRATION_AUDIT.md`](./design/STAGE_1_PR_3_MIGRATION_AUDIT.md)
    gains a post-M3 status banner clarifying that the audit's
    commit hashes (`ffcaa62e9` and `e6efaf5b5`) are immutable
    historical anchors and are not to be refreshed to post-M3d
    state. The discrepancy between the M3e preflight's D2 count
    (claimed "0 references to old `KeyEngine` method names outside
    the trait block") and the actual surface (17 references found)
    is documented in the commit message; the surface was classified
    as mode-2 mechanical-residue under the rule-15 trinary reading
    (per
    [`STAGE_1_PR_3_M3E_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3E_PREFLIGHT.md)
    §11.1) and swept inline rather than deferred.
  - **Rules realignment.**
    [`.cursor/rules/42-serialization-policy.mdc`](../.cursor/rules/42-serialization-policy.mdc)
    underwent a mechanical rename of all 11 stale crate-path
    references (`shekyl-wallet-state` → `shekyl-engine-state`;
    `shekyl-wallet-file` → `shekyl-engine-file`) across the `globs`
    frontmatter, intro paragraph, pairing table, mechanical
    enforcement subsections, and procedure section. The stale
    `globs` field previously prevented the rule from auto-applying
    to any file under the workspace's renamed crate trees; the
    realignment restores the auto-application surface. Closes the
    M3d-surfaced rule-realignment FOLLOWUP (relocated to the
    "Recently resolved (audit trail)" section in
    [`FOLLOWUPS.md`](./FOLLOWUPS.md)).
  - **FOLLOWUPS structuring.**
    [`FOLLOWUPS.md`](./FOLLOWUPS.md) gains a "Queue structure"
    preamble that splits the queue into V3.0 pre-genesis
    (load-bearing; per-PR overhead compounds the pre-genesis
    trajectory) and V3.1+ post-genesis (sustainable backlog)
    queues. The Stage 2 `KeyEngine`-actor entry is updated to
    reflect the post-M3 trait surface. Two new V3.1 rules-queue
    entries are added: "Encode the rule-15 trinary reading in
    `15-deletion-and-debt.mdc`" (codifying the M3e §11.1
    calibration shift that distinguishes in-scope mechanical-
    residue from out-of-scope structural-tangent) and
    "Consolidate the rules-queue itself into 1–2 PRs" (pinning the
    consolidation target from M3e §11.3 against the current
    six-deep rules-queue accumulation).
  - **Path-rename residue sweep.** The 34-occurrence path-rename
    residue surfaced by the M3d → M3e D5 audit (path-rename
    surface across 12 files) was swept inline per the rule-15
    trinary-reading calibration shift. Per-category disposition:

    - **Active narrative documents updated** (current-state
      references, no append-only constraint): 8 adversarial test
      fixture markdown files + their README; 2 crate-internal
      READMEs (`shekyl-engine-state/fuzz`, `shekyl-scanner`); 3
      benchmark prose documents (`benchmarks/README.md`,
      `shekyl_rust_v0.manifest.md`,
      `wallet2_baseline_v0.manifest.md`); the
      `V3_WALLET_DECISION_LOG.md` intro paragraph only (dated
      entries preserved per append-only discipline); and the
      `WALLET_REWRITE_PLAN.md` current-state architecture
      descriptions (Mermaid diagrams, inventory section, gap
      section, locked-design section, code-block comment, narrative
      paragraphs at §3.2 and Phase 1 audit; PR-0.X sections
      preserved as historical PR descriptions).
    - **References preserved as historical anchors** (49
      occurrences across 6 files):
      [`CHANGELOG.md`](./CHANGELOG.md) (6 occurrences: rename-event
      entries plus this M3d entry's historical reference to the
      pre-realignment rule state, which this M3e entry now closes);
      [`FOLLOWUPS.md`](./FOLLOWUPS.md) (8 occurrences across
      historical audit-trail entries plus the new M3e entries that
      reference the rename event);
      [`V3_WALLET_DECISION_LOG.md`](./V3_WALLET_DECISION_LOG.md)
      (16 occurrences across dated decision-log entries protected
      by the file's append-only discipline);
      [`WALLET_REWRITE_PLAN.md`](./design/WALLET_REWRITE_PLAN.md)
      (6 occurrences inside PR-0.X historical descriptions);
      [`shekyl_rust_v0.json`](./benchmarks/shekyl_rust_v0.json) (10
      occurrences; captured baseline pinned to `git_rev` anchor
      `a2bf417e4b7985ed2097dc5d3fb53affef306d1a`); and
      [`shekyl_rust_v0.iai.snapshot`](./benchmarks/shekyl_rust_v0.iai.snapshot)
      (3 occurrences; historical iai-callgrind capture). Refreshing
      these would falsify their respective historical anchors.

    The trinary-reading calibration anchors the sweep: substrate-
    change mechanical-residue (the rename was the substrate
    change; the path references inside active documents are its
    residue) folds into the closing PR; historical anchors and
    append-only entries are preserved by construction. The
    discriminating tests (derivability + boundedness + traceability
    + surface-during-review) are satisfied by the sweep's
    discoverability via single `rg` invocation and by surface
    during the M3e preflight's D5 audit.

### Removed

- **Stage 1 PR 3 — M3d: legacy secret-bearing fields removed from
  `TransferDetails`** (`feat/stage-1-pr3-m3d`; one pre-flight commit +
  one pre-flight-review-amendment commit + four implementation
  commits cut off `dev` post-M3c). Activates the **"secrets confined
  to engine" property** for the orchestrator/engine boundary per
  [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`](./design/STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.4 (and §3.4.1's M3d landing-notes cross-reference),
  [`docs/design/STAGE_1_PR_3_M3D_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3D_PREFLIGHT.md)
  §3.3, and the audit migration table at
  [`docs/design/STAGE_1_PR_3_MIGRATION_AUDIT.md`](./design/STAGE_1_PR_3_MIGRATION_AUDIT.md)
  §2.1 row 1 (now marked "Removed at M3d (landed 2026-05-11)").

  - **Schema change:** five `Option<Zeroizing<[u8; N]>>` fields
    deleted from `shekyl_engine_state::TransferDetails`:
    `combined_shared_secret` (64 bytes), `ho`, `y`, `z`, `k_amount`
    (32 bytes each). Corresponding entries in the
    `TransferDetailsSchema` mirror struct, the `impl Zeroize for
    TransferDetails` block, and the
    `rust/shekyl-engine-state/.zeroize-allowlist` schema-mirror
    entries were removed in the same commit.
  - **Version bumps (paired per the in-source rule at
    `rust/shekyl-engine-state/src/wallet_ledger.rs:67`):**
    `LEDGER_BLOCK_VERSION`: 3 → 4; `WALLET_LEDGER_FORMAT_VERSION`:
    3 → 4. The `wallet_ledger.rs` docstring is the authoritative
    in-source statement of the pairing rule ("Each per-block bump
    implies a `WALLET_LEDGER_FORMAT_VERSION` bump") — the
    workspace-wide rule `.cursor/rules/42-serialization-policy.mdc`
    still carries pre-rename `shekyl-wallet-state` /
    `shekyl-wallet-file` path references (tracked as a focused
    FOLLOWUP for path-rename realignment). Per the workspace's
    `15-deletion-and-debt.mdc` "no in-Shekyl migration code" rule,
    v4 stores refuse v3 loads rather than migrate; pre-genesis
    users `rm -rf ~/.shekyl` and re-sync.
  - **Property activated:** orchestrator-side `TransferDetails` no
    longer carries derived per-output secrets. The engine
    re-derives them inside its signing-session boundary from
    `(view_secret, source_ciphertext)` via
    `LocalKeys::derive_source_secrets_bundle` (per
    `STAGE_1_PR_3_KEY_ENGINE.md` §7.10–§7.12) and wipes them on
    drop. Orchestrator memory disclosure no longer exposes
    output-secret material; capability disclosure is unchanged
    (per Round 3 §7.10 / §7.11 framing).
  - **Snapshot regeneration:** the two `.snap` files that
    transitively serialize `TransferDetails`
    (`schemas/ledger_block.snap`, `schemas/wallet_ledger.snap`)
    drift; the three others
    (`bookkeeping_block.snap`, `tx_meta_block.snap`,
    `sync_state_block.snap`) are unchanged, confirming
    pre-flight invariant 8 (snapshot universe verification).
  - **Production write-site removed:** the five
    `td.<field> = Some(Zeroizing::new(...))` write lines at
    `shekyl-scanner/src/ledger_ext.rs::process_scanned_outputs`
    deleted; the M3b deterministic-handle pathway
    (`source_ciphertext`, `output_handle` populated by
    `engine::merge::populate_engine_handle_fields`) is the only
    write path post-M3d.
  - **Test/bench fixture rewrites:**
    `shekyl-engine-state` (`transfer.rs::tests`, `ledger_block.rs::tests`,
    `ledger_indexes.rs::tests`, `invariants.rs::tests`, four
    `benches/*.rs`),
    `shekyl-scanner::balance.rs::tests`, and the engine-core
    bench fixtures
    (`benches/common/engine_fixture.rs`,
    `benches/refresh_snapshot.rs`) updated to the post-M3d shape.
    Where the prior fixtures populated the five legacy secrets,
    the replacement populates `source_ciphertext` (via direct
    `HybridCiphertext` construction) and `output_handle` (via
    `shekyl_crypto_pq::handle::derive_output_handle`) so
    `Option`-valued roundtrip / snapshot benches continue
    exercising non-default payloads representative of post-M3d
    transfers. The `postcard_roundtrip_with_secrets` test was
    renamed to `postcard_roundtrip_with_handle_fields`.
  - **Documentation cleanup (carve-out per
    `91-documentation-after-plans.mdc`):** the past-tensing edits
    to `STAGE_1_PR_3_KEY_ENGINE.md` §3.5 ("residue of that direct
    port" paragraph), `STAGE_1_PR_3_MIGRATION_AUDIT.md` §2.1 row 1
    (five legacy-field disposition column), and
    `docs/benchmarks/shekyl_rust_v0.manifest.md` (the two §3
    paragraphs referencing the five legacy fields) landed in
    M3d's final docs commit alongside the plan §3.4 amendment.
    The broader M3e doc sweep remains scope-bounded to whole-doc
    realignment.

  - **Commit decomposition (five commits, matching pre-flight's
    planned count but with a different load distribution):** the
    per-commit-CI-green gate forced consolidation of pre-flight
    commits 1 + 3 plus the scanner's `from_wallet_output` cleanup
    into a single cross-crate schema-migration commit (commit 2);
    a fifth slot was reused for a small bench-fixture-fix commit
    (commit 4) feature-gating two `shekyl_crypto_pq` imports under
    `bench-internals` in the engine-core common bench fixture
    after `cargo clippy --all-targets` surfaced them as unused
    when included from the default-feature `synced_height` bench
    pair. See plan §3.4.1 for the forward-template framing
    (pre-flight wording may strengthen during implementation if
    the underlying property is preserved).

### Added

- **Stage 1 PR 3 — M3c: additive end-to-end engine-bundle signing
  test** (`feat/stage-1-pr3-m3c`; one pre-flight commit + two
  implementation commits + one cross-reference commit cut off `dev`
  at `ea1df2539`). Lands the validation milestone per
  [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`](./design/STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.3 (with §3.3.1 cross-reference to the implementation
  disposition) and the pre-flight in
  [`docs/design/STAGE_1_PR_3_M3C_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3C_PREFLIGHT.md)
  §2.1 (Option C disposition; §2.1.1 Trim-1 amendment). Property
  delivery: **complete for the bundle → SpendInput → SignedProofs
  cryptographic chain at the `tx_builder::sign_transaction`
  surface** — the precondition M3d depends on for removing the
  legacy `TransferDetails`-secret-bearing-fields fallback.

  - **New unit test:**
    `engine_derived_bundle_signs_through_tx_builder_end_to_end`,
    inline in `rust/shekyl-engine-core/src/engine/local_keys.rs`'s
    `mod tests` as a peer to M3b D5. Constructs a `LocalKeys` from
    `TEST_SEED`; for each of 9 fixtures (3 input counts {1, 2, 3}
    × 3 subaddress indices {`PRIMARY`, `SubaddressIndex::new(1)`,
    `SubaddressIndex::new(42)`} — `SubaddressIndex` is a flat
    `u32`, not a `(major, minor)` pair) synthesizes
    *n_in* outputs paid to `subaddress_keys(idx)` for every idx
    (including PRIMARY — see the test docstring's
    relationship-to-M3b-D5 section for why bare primary spend keys
    cannot recover here); recovers each output via
    `scan_output_recover` to compose a hand-derived legacy bundle;
    derives the engine bundle via
    `LocalKeys::derive_source_secrets_bundle`; asserts engine and
    legacy `SpendInput`s are byte-identical field-by-field at the
    input layer (12 fields per input including per-`leaf_chunk`-
    entry equality); calls `tx_builder::sign_transaction(...)`
    *once* on the engine path; asserts BP+ deserializes via
    `Bulletproof::read_plus` and verifies via
    `Bulletproof::verify` against un-cofactored output commitment
    points; asserts FCMP++ verifies via
    `shekyl_fcmp::proof::verify` against engine-derived key
    images, the proof's pseudo-outputs, the synthetic h_pqc Selene
    scalars, the synthetic single-leaf-chunk tree root, and the
    same `signable_tx_hash` passed to the prover; asserts
    `reference_block` and `tree_depth` echo unchanged.
  - **Inline cryptographic tree-fixture helpers.** Replicates the
    recipe from `shekyl-fcmp::proof::tests::prove_verify_roundtrip`
    inline in `local_keys.rs::tests` (single-leaf chunk; depth = 1;
    `tree_root = SELENE_HASH_INIT + multiexp_vartime` over Selene
    generators × leaf scalars; h_pqc derived deterministically via
    `dalek_ff_group::FieldElement::wide_reduce` for
    reproducibility; recipient `output_index` offset by `n_in + 100`
    to avoid the input/output commitment-mask collision that
    collapses FCMP++'s rerandomization scalar to zero in
    single-input/single-output sweeps with shared `combined_ss`).
    Helpers: `build_synthetic_single_chunk_tree_root`,
    `make_synthetic_h_pqc_bytes`, `make_recipient_output_info`,
    `compute_test_key_image`. New `[dev-dependencies]` on
    `shekyl-tx-builder`, `shekyl-fcmp`, `shekyl-bulletproofs`,
    `shekyl-fcmp-plus-plus`, `shekyl-generators`, `shekyl-io`,
    `shekyl-primitives`, `multiexp`, `ec-divisors`, `ciphersuite`,
    `helioselene`, `dalek-ff-group`, `rand_core` per
    `17-dependency-discipline.mdc`.
  - **Layered framing.** The test docstring records three layers:
    Layer 1 — cryptographic chain `bundle → SpendInput →
    tx_builder::sign_transaction → BP+ verify + FCMP++ verify`
    (this test's scope); Layer 2 — `KeyEngine::sign_transaction`
    trait method (PR-5+ scope; today returns
    `KeyEngineError::SignTransactionTraitSurfaceIncomplete` because
    `TxToSign`'s `outputs` and `fcmp_plus_plus_context` are
    PR-5-pinned forward-declared stubs); Layer 3 — orchestrator-
    engine message envelope / actor mailbox (PR-5+ scope;
    cryptographic chain in Layer 1 is invariant under that
    decision). The test docstring also records the relationship to
    M3b D5 as intentional layered coverage (M3b D5 pins bundle-
    byte identity without exercising recovery; M3c-via-C pins
    recovery-correctness which forces the recipient subaddress
    consistency M3b D5 doesn't enforce — the two pin complementary
    properties at adjacent layers).
  - **Trim-1 disposition (post-implementation amendment).** An
    earlier draft issued a parallel sign call with legacy-derived
    `SpendInput`s for `commitments` / `enc_amounts` byte-equality
    at the signer-output layer. Pre-flight review surfaced that
    `SpendInput` byte-equality at the input layer is strictly
    stronger (subsumes the original property by signer
    determinism, and additionally guards regressions in
    `SpendInput` fields irrelevant to commitments / enc_amounts
    but relevant to signature behavior or future field additions).
    Substituting the parallel sign call for input-layer byte-
    equality + sign-once on the engine path halves the test
    runtime (32s → 17.65s debug; 12s → 6.87s release). Pre-flight
    §2.1.1 records the discovery and names it as a forward
    template: implementation may strengthen pre-flight properties
    post-implementation; weakening requires explicit revisit. The
    named coverage gap (workspace sole-coverage of
    `tx_builder::sign_transaction` end-to-end success goes from
    2× to 1×) is named-and-accepted given M3d removes the legacy
    bundle-derivation chain entirely; the engine path is the
    load-bearing path going forward and the redundant second
    exercise of the same signer would only have decaying value.
    Workspace-coverage note: pre-PR-3 this end-to-end success path
    had **0×** coverage anywhere (`shekyl-tx-builder/src/tests.rs`
    only validation-error paths; `transfer_e2e[_iai].rs` benches
    explicitly elide full sign pending a checked-in tree-fixture;
    `shekyl-fcmp::proof::tests::prove_verify_roundtrip` exercises
    FCMP++ in isolation only; FFI / engine-rpc are production
    callers without in-file tests; BP+ fuzz target only fuzzes BP+
    in isolation). Post-Trim-1 the test is the workspace's sole
    end-to-end successful-execution coverage of
    `tx_builder::sign_transaction`.
  - **Migration plan + FOLLOWUPS updates.**
    `STAGE_1_PR_3_MIGRATION_PLAN.md` §3.3.1 records the Option C
    disposition + Trim-1 amendment so a reader of the original
    §3.3 wording reaches the implementation-side disposition in
    one hop. `docs/FOLLOWUPS.md`'s M3b-D5 re-location entry is
    refactored to cover both M3b D5 and M3c-via-C under the same
    `KeyEngine`-widens-to-`pub` trigger (one re-location PR
    bundles both tests; the visibility flip is the trigger for
    both, and bundling them keeps the migration-tail discipline
    cost bounded).

- **Stage 1 PR 3 — M3b: scanner reroute + bridge source switch**
  (`feat/stage-1-pr3-m3b`; ten substantive commits + one mechanical
  rustfmt fix + one docs commit cut off `dev` at `647f82d59` on
  2026-05-09). Lands the `KeyEngine`-mediated source-secrets
  derivation path per
  [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`](./design/STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3.2 and the pre-flight dispositions in
  [`docs/design/STAGE_1_PR_3_M3B_PREFLIGHT.md`](./design/STAGE_1_PR_3_M3B_PREFLIGHT.md)
  §2 / §3 / §5. Property delivery: **partial** — every output the
  scanner ingests now carries a deterministic `OutputHandle` and the
  `HybridCiphertext` it was decapsulated from on its
  `TransferDetails`; the legacy secret-bearing `TransferDetails`
  fields remain populated transitionally to keep the bridge-impl
  fallback live until M3d removes them.

  - **Two-layer derivation primitive split (D1).**
    `shekyl_crypto_pq::output::recover_combined_ss(view_x25519_sk,
    ml_kem_dk, kem_ct_x25519, kem_ct_ml_kem) -> Result<SharedSecret,
    CryptoError>` (Layer 1, transform-shaped, in `shekyl-crypto-pq`)
    extracts the X25519 + ML-KEM-768 + HKDF-SHA-512 re-decap chain
    from `scan_output_recover`'s prefix; `LocalKeys::derive_source_secrets_bundle(
    source_ciphertext, output_index, subaddress_idx) ->
    Result<SourceSecretsBundle, KeyEngineError>` (Layer 2, state-shaped,
    in `shekyl-engine-core::engine::local_keys`) composes Layer 1's
    output with the engine-owned `b` (spend secret) and `m_i`
    (subaddress derivation scalar). Placement per
    `18-type-placement.mdc`: transform-shaped lives with its
    function; state-shaped lives with its owner.
  - **`TransferDetails` schema extension (D3).** Two `Option<…>`
    fields — `source_ciphertext: Option<HybridCiphertext>` (the
    on-chain hybrid X25519 + ML-KEM-768 ciphertext the scanner
    detected) and `output_handle: Option<OutputHandle>` (the
    deterministic 16-byte handle from cSHAKE256 keyed by the view
    secret). `Zeroize` impl skips the new non-secret fields per
    `35-secure-memory.mdc`'s redaction discipline. Both fields land
    behind an `Option` so the bridge-impl fallback is feature-detected
    (presence of `source_ciphertext` ↔ primary path; `None` ↔ legacy
    field path). `LEDGER_BLOCK_VERSION` and
    `WALLET_LEDGER_FORMAT_VERSION` bumped 2 → 3; both schema
    snapshots regenerated. The new fields' wire stability is
    locked by extending the `postcard` round-trip test;
    `postcard-schema = "0.2"` added as a direct dep on
    `shekyl-crypto-pq` per `17-dependency-discipline.mdc` (matches
    the existing `shekyl-engine-state` direct-dep pin).
  - **`TxInputSigningContext` field swap (D2).** Drops
    `source_secrets: SourceSecretsBundle` (the by-value secret
    carrier that contradicted the engine-confined-secrets property)
    in favor of `source_ciphertext: HybridCiphertext` +
    `output_index: u64`. The trait-surface input is now the public
    on-chain ciphertext; the engine derives the secrets internally
    via `LocalKeys::derive_source_secrets_bundle`. `Debug` impl
    simplified; redaction tests updated.
  - **Engine post-pass at the orchestrator layer (Q2 δ disposition).**
    `Engine::apply_scan_result` becomes a three-step body inside
    one `LocalLedger` write guard: `collect_detection_residue`
    (pre-collects a `HashMap<(tx_hash, internal_output_index),
    HybridCiphertext>` from the `ScanResult`'s new transfers) →
    `apply_scan_result_to_state` (the existing sync bookkeeping
    merge, unchanged) → `populate_engine_handle_fields` (walks the
    freshly-merged `TransferDetails` and binds each to its
    `source_ciphertext` + deterministic `output_handle` from the
    residue map). Atomic against external readers — concurrent
    reads either see pre-merge or post-population, never an
    intermediate state. Idempotent. The sync helper is async-ready
    by design: M3b derives the handle directly via
    `shekyl_crypto_pq::handle::derive_output_handle` (a synchronous
    pure function that requires only `(view_secret, tx_hash,
    output_index)`); M3c+ wires `LocalKeys` onto `Engine` and
    re-routes the helper through `KeyEngine::try_claim_output`,
    at which point the helper signature becomes `async fn` and
    `Engine::apply_scan_result` takes the corresponding `.await`.
    The two-step trajectory is intentional and pinned in the
    helper's doc-comment; M3b's architectural property (every
    output gets a deterministic handle) does not require the
    audit's "engine sole authority on handles" framing to activate,
    which lands at M3d.
  - **Scanner residue plumbing.** `RecoveredWalletOutput` extended
    with four public on-chain residue fields (`source_ciphertext:
    HybridCiphertext`, `view_tag: u8`, `enc_amount: [u8; 8]`,
    `amount_tag: u8`, all `#[zeroize(skip)]` per the type's
    redaction discipline) so the engine post-pass has the structured
    input it needs. The pre-flight estimated this commit as "~0–10
    lines, may be no-op," but inspection revealed
    `RecoveredWalletOutput` was discarding the on-chain residue at
    construction time. Reordered to land before the engine post-pass
    commit so each commit leaves the workspace
    `cargo check`-green; the layering is honest about producer
    (scanner) and consumer (engine).
  - **Named failure mode (D6).**
    `KeyEngineError::SourceCiphertextDecapsulationFailed(#[from]
    CryptoError)` for re-decap rejection. The variant carries the
    inner `CryptoError` so audit logs distinguish whether the
    rejection was at the X25519 layer (`LowOrderPoint`), the
    ML-KEM-768 layer (`DecapsulationFailed`), or the input-shape
    layer (`InvalidKeyMaterial`); all three indicate the same
    operational class (corrupted or tampered persisted state) but
    name which step rejected the input. The expected operational
    case for this variant is **none** — re-decap runs only on
    outputs the wallet itself scanned and persisted; a failure
    implies storage corruption or malicious local actor.
  - **Byte-identical-derivation property test (D5).** Two unit
    tests in `local_keys.rs::tests`: (a) `derive_source_secrets_bundle_byte_identical_against_legacy_chain`
    asserts field-by-field byte-equality between the new
    Layer 2 chain (`derive_source_secrets_bundle`) and a hand-rolled
    bundle from `scan_output_recover`'s `RecoveredOutput` across 24
    derivations (8 distinct (output_index, tx_hash) pairs × 3
    subaddress indices — PRIMARY, idx=1, idx=42); (b)
    `derive_source_secrets_bundle_diverges_across_distinct_seeds`
    exercises cross-seed isolation. The second test's docstring
    pins a subtle property: ML-KEM-768 implements implicit
    rejection per FIPS 203, so a wrong-wallet decap *succeeds* with
    a junk bundle (the IND-CCA2 oracle defense); the isolation
    property is "junk bundle differs byte-for-byte," not "function
    refuses." Located alongside C6's smoke tests in
    `local_keys.rs::tests` rather than the pre-flight's planned
    `tests/byte_identical_derivation.rs` integration test, due to
    the M3a Round 4a `pub(crate)` lock on `LocalKeys`,
    `SourceSecretsBundle`, and `KeyEngineError`; tracked for
    re-location in `docs/FOLLOWUPS.md` § V3.2 if the visibility
    lock relaxes at the wallet-RPC cutover.

  Property-delivery framing: structural — no consensus rule, no
  wire format on-chain, no FFI layout changes. The `TransferDetails`
  schema bumps `WALLET_LEDGER_FORMAT_VERSION` from 2 to 3, which is
  a wallet-state schema change handled by the pre-V3-launch
  `rm -rf ~/.shekyl` migration path per `15-deletion-and-debt.mdc`
  (no in-Shekyl format-detection code; pre-genesis users have no
  real state to preserve). M3c–M3e land the additive test caller
  (M3c), the legacy-fallback removal (M3d), and the audit closure
  (M3e).

- **Stage 1 PR 3 — Phase 0: `AllKeysBlob` zeroize-discipline
  realignment** (`chore/allkeysblob-zeroize-realignment`; closes
  [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
  §3.5 (Phase 0e) and §7.5). Three rule-grounded edits that landed
  together as a focused chore PR before the M3b implementation, each
  closing an audit finding cited to a rule with a concrete failure
  mode prevented:

  - **F1 / `35-secure-memory.mdc:21–22`.** `AllKeysBlob.ml_kem_dk`
    (the ML-KEM-768 decap secret key, 2400 bytes) was the lone
    unwrapped secret-bearing array on the struct; wrapped in a new
    `MlKem768DecapKey` typed newtype in
    [`rust/shekyl-crypto-pq/src/keys.rs`](../rust/shekyl-crypto-pq/src/keys.rs)
    that mirrors the established `ViewSecret` / `SpendSecret` shape
    (`#[repr(transparent)]`, `Clone + Zeroize + ZeroizeOnDrop`, no
    `Copy`, no `Debug`, `pub(crate)` constructor, public
    `as_canonical_bytes()` accessor). Sweeps eight in-Rust read sites
    (`account.rs`'s field/zeroed/rederive/test, `local_keys.rs:344`,
    `refresh.rs:1283`, `account_ffi.rs:531`); the FFI mirror keeps
    raw `[u8; ML_KEM_768_DK_LEN]` and the bit-for-bit layout
    invariant (size, alignment, per-field offsets) is preserved by
    `#[repr(transparent)]` and asserted directly by
    `account_ffi::tests::struct_layout_matches`. The producer
    [`crate::account::ml_kem_keypair_from_d_z`] returns the typed
    `MlKem768DecapKey` directly (constructed via `from_zeroizing`
    consuming a `Zeroizing<[u8; N]>` source) — the secret travels
    through the type system from producer to consumer without any
    call site materialising an untracked stack `Copy` of the
    2400-byte buffer between them.
  - **F2 / `35-secure-memory.mdc:23–25`.** `AllKeysBlob` migrated
    from a hand-written `Drop` impl (which the design doc itself
    characterized as "documenting the lie" — the spec asserted
    `AllKeysBlob: ZeroizeOnDrop` while the trait was not implemented)
    to `#[derive(Zeroize, ZeroizeOnDrop)]`. With every field now
    `Zeroize`-bearing (typed wrappers + zeroize-crate blanket impls
    on `[u8; N]`), the structural condition for the derive holds
    and the manual impl is replaced wholesale. The derived
    `Drop::drop` calls `self.zeroize()` once on every field;
    field-drop-glue then re-invokes each `ZeroizeOnDrop` field's
    destructor independently — an idempotent double-wipe documented
    in the struct rust-doc so future `ZeroizeOnDrop`-grep audits do
    not mistake the pattern for a discipline violation.
  - **F3 / `KEY_ENGINE.md` §7.5.** `AllKeysBlob: Clone` derive deleted.
    Workspace audit (`rg 'AllKeysBlob.*\.clone\(\)'` + per-call-site
    read; `cargo build --workspace --all-targets` is the locking
    gate that compiles every `#[cfg(test)]` block) surfaced zero
    callers in production *or* test code; per `30-cryptography.mdc`
    and `35-secure-memory.mdc:26-28`, `Clone` on a secret-bearing
    struct requires explicit justification, and none surfaced. The
    `traits/key.rs:581` doc-comment ("Not Clone — implementors wrap
    `AllKeysBlob`") becomes literally enforced.

  **`ml_kem_ek` deliberately stays raw `[u8; ML_KEM_768_EK_LEN]`.**
  Public encap key, broadcast in the address; outside
  `35-secure-memory.mdc:21–22`'s reach as public material. Wrapping
  it would be uniformity-driven completionism without rule grounding
  (per `15-deletion-and-debt.mdc`'s "while we're here is the enemy")
  and would create a permanent type-system signal collision
  (`Zeroize` semantics on a public type as a distractor for any
  future grep-for-secrets audit). Five-reason disposition recorded
  inline at
  [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
  §3.5's "Closed (post-M3a, post-Phase-0)" subsection
  against re-litigation.

  **Closure-path narrative.** The originally-specified §3.5 sequencing
  was "Phase 0e lands first, before PR 3 cuts." The actual landing
  was post-M3a, via this chore. The deviation is **substrate-change**,
  not extension: §3.5 was specced when `AllKeysBlob` carried raw
  `[u8; N]` fields (where `derive(ZeroizeOnDrop)` would have been a
  literal one-line addition). The intervening
  `chore/allkeysblob-typed-wrappers-monero-sweep` (which closed the
  inheritance audit's `spend_sk` / `view_sk` secret-flow finding)
  left `ml_kem_dk` as the residual raw secret-bearing array, which
  prevented the parent derive from taking. This chore re-anchors
  §3.5's load-bearing goal (Q9.3 precondition true; `AllKeysBlob:
  ZeroizeOnDrop` literally implemented) to the post-sweep substrate;
  the work-shape adapted to the post-sweep state rather than
  extended from the original 5–10-line plan.

  Property-delivery framing: structural — no consensus rule, no
  wire format, no FFI layout changes. The deliverable is rule
  alignment between code and spec on the `AllKeysBlob` zeroize
  discipline, restoring the precondition that Q9.3 / Phase 0d's
  cross-reference language now resolves cleanly against. M3b cuts
  off the post-merge `dev` tip with the precondition true.

- **Single-source-of-truth JSON authority for the consensus-affecting
  constant subset: `config/consensus_constants.json`.** Mirrors the
  existing `config/economics_params.json` pattern. The JSON is the
  authority; `cmake/generate_consensus_constants.py` emits
  `shekyl/consensus_constants_generated.h` for the C++ build, and
  `rust/shekyl-engine-core/build.rs` reads the same file and emits
  a `consensus_constants_generated.rs` module that
  `rust/shekyl-engine-core/src/multisig/v31/intent.rs` consumes via
  `include!()`. Closes the C++/Rust drift class for the constants
  where drift causes silent wrong-output (vs. fail-closed-on-load).

  Constants in scope (per `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`):

  - `FCMP_REFERENCE_BLOCK_MIN_AGE = 5` — reorg-safety margin locked
    by Decision 14. Pre-fix, hand-defined as `5` in
    `src/cryptonote_config.h` and as `10` in
    `rust/shekyl-engine-core/src/multisig/v31/intent.rs`. The
    drift was Bug 3 of the audit and silently rejected legitimate
    multisig intents at the wallet layer.
  - `FCMP_REFERENCE_BLOCK_MAX_AGE = 100` — same shape, no observed
    drift but in the same value class and migrated together.
  - `RCT_TYPE_FCMP_PLUS_PLUS_PQC = 7` — single-source on each side
    today (`enum RCTType` in C++; `ProofType::FcmpPlusPlusPqc => 7`
    in `shekyl-oxide`); both sides now stamped against the JSON via
    `static_assert` (C++ in `src/fcmp/rctTypes.cpp`) and a runtime
    test (Rust, in `intent.rs::tests::shekyl_oxide_proof_type_matches_consensus_authority`).

  **Sentinel discipline:** every consumption site that previously
  hand-defined a value now carries either a `static_assert` (C++) or
  a `const _: () = assert!(...)` (Rust) sentinel pinning the value
  to a Decision-14-era baseline. Bumping the sentinel requires
  updating both the JSON and the consumption-site comment, so a
  silent value drift through the JSON alone fails the build with a
  clear message.

  **Fixture update:** `intent.rs::tests::validate_temporal_rejects_ref_block_too_fresh`
  changed from `tip = 905` (age = 5, the boundary value `age < 5`
  evaluates false under the post-fix `MIN_AGE = 5`) to `tip = 903`
  (age = 3, unambiguously rejected). The test exercises the
  rejection branch (`age < MIN_AGE`) and stays correct as long as
  `MIN_AGE > 3` — i.e. it survives any tightening (`MIN_AGE`
  increasing above 5) and any loosening down to and including
  `MIN_AGE = 4`. Only a loosening to `MIN_AGE = 3` or lower would
  invalidate the fixture, which itself would warrant the consensus
  re-review the sentinel demands.

  **Out of scope:** `ADDRESS_VERSION_V1` is single-source in Rust
  with no C++ duplicate, so there's nothing to align. The
  full-migration follow-up for the remaining `SHEKYL_*` fail-closed-
  on-misuse constants (~40) stays as FOLLOWUPS V3.0.

### Documentation

- **Stage 1 PR 5 — address PR #43 Copilot review findings,
  Round 2 (post-Round-2-close follow-up cycle).** Doc-only
  commit on `feat/stage-1-pr5-pending-tx-engine-design`.
  Addresses nine additional Copilot review findings surfaced
  against the Round-2-close-out commit (`b85edec9a`), the
  first Copilot-fix commit (`871efa40c`), and the Round-1
  CHANGELOG entries. The fixes consolidate hash-primitive
  dependency-discipline correctness, cryptographic-security-
  rationale framing, sink-binding shape alignment across
  segments, variant-name alignment in V3.x FOLLOWUPS entries,
  and architectural soundness of the V3.x `TimeoutResolverActor`
  correlation contract.
  - **Findings A + E + H — `SnapshotId` hash primitive
    correction (covers three Copilot comments on §4
    Phase 0b, §5.4 R2 sketch, CHANGELOG segment-2g entry,
    §5.5 Round 2 summary, and the doc header).**
    Segment-2g's prior binding pinned `SnapshotId` to
    SHA-256 via `sha2 = "0.10"`, citing
    `rust/shekyl-engine-core/Cargo.toml` line 115 as the
    workspace-state-reuse anchor. That citation was a
    dependency-discipline error:
    [`Cargo.toml`](../rust/shekyl-engine-core/Cargo.toml)
    line 115 is in `[dev-dependencies]` (test-only), and
    the production `sha2` at line 33 is `optional = true`
    (gated behind a feature flag). The Copilot-fix
    follow-up switches the primitive to
    `shekyl-crypto-hash::cn_fast_hash` (Keccak-256, original
    padding) — `shekyl-crypto-hash` is an unconditional
    `[dependencies]` entry per Cargo.toml line 28, the
    consensus-audited Keccak primitive Shekyl already uses
    throughout its codebase. Strictly better disposition
    against the
    [`17-dependency-discipline.mdc`](../.cursor/rules/17-dependency-discipline.mdc)
    workspace-state reuse rule against the actual
    production-dependency graph. The §5.4 R2 sketch also
    still showed a prior `blake3::hash` form from
    segment-2d's open-shape-not-primitive disposition; the
    sketch is updated to the binding `cn_fast_hash` form.

    The security rationale is also reframed. Segment-2g's
    prior framing was "128-bit collision resistance gives
    ~2⁶⁴ classical work and ~2³² quantum work via Grover-
    doubled width." Two errors: (i) Grover's algorithm
    gives 2^(n/2) work against **preimage** attacks, not
    collision attacks — quantum collision is governed by
    BHT (Brassard–Høyer–Tapp), ~2^(n/3) ≈ 2⁴³ for 128-bit
    outputs; (ii) the use-case framing is incorrect —
    `SnapshotId` is a wallet-internal equality token over
    a bounded snapshot population, not a collision-
    resistance primitive against arbitrary inputs.

    Corrected framing: **second-preimage resistance over
    bounded snapshot population**. The wallet observes
    ≪ 2⁴⁰ snapshots over its operational lifetime
    (≤ ~10⁷ snapshots over 100 years; one snapshot per
    refresh merge). Classical second-preimage on 128-bit
    truncated hash is ~2¹²⁸ work; quantum Grover second-
    preimage is ~2⁶⁴ work — large but bounded under
    aggressive quantum-adversary assumptions. The impact
    bound under successful attack is also constrained: a
    daemon-forged colliding `LedgerSnapshot` merely makes
    the wallet submit a tx valid against the prior
    snapshot; the daemon could have rejected the tx anyway
    via `DoubleSpend` if the prior snapshot's outputs are
    now spent on-chain. No consensus violation; no wallet-
    state corruption that refresh cannot reconcile. The
    versioned domain-separation prefix
    (`b"shekyl-snapshot-id-v1"`) permits V3.x migration to
    a wider output or different hash family without cross-
    stage rebuild.

    Sites updated: `docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`
    §4 Phase 0b binding, §5.4 R2 sketch + prose, §5.5
    Round 2 summary, §6 review-checklist `SnapshotId` item,
    and the header status block; this CHANGELOG segment-2g
    entry with a Copilot-fix forward-pointer.
  - **Finding B — §5.4 R2 cross-reference to rejected option
    (b).** §5.4 R2 prose referenced
    `DIAGNOSTIC_STREAM_CONTRACTS.md` (the parent-doc
    factoring option (b) considered in §5.0.3), but
    segment 2g's diagnostic-stream-doc generalization
    closed as **option (a) — rename
    `REFRESH_DIAGNOSTIC_STREAM.md` →
    `DIAGNOSTIC_STREAM.md`**. The cross-reference is
    updated to the chosen doc name with the closure
    rationale.
  - **Finding F — `&dyn DiagnosticSink` vs
    `Arc<dyn DiagnosticSink>` inconsistency.** §5.0.2.1
    (the segment-2f sink-binding-closure section) used the
    earlier `&dyn DiagnosticSink` form when the closure
    section itself pins `Arc<dyn DiagnosticSink>`; this is
    corrected for self-consistency. The Round-1-close
    CHANGELOG entry's `&dyn DiagnosticSink` description
    receives a forward-pointer noting that segment 2f
    tightened the form to `Arc<dyn>` for reference-shape
    ergonomics during R11 closure (the earlier wording
    remains historically accurate at Round 1 close).
  - **Findings C + D — V3.x FOLLOWUPS
    `SubmitFailureAnalyzer` variant-name alignment.** The
    `SubmitFailureAnalyzer` FOLLOWUPS entry referenced
    `SnapshotInvalidated` in two places and
    `SubmitFailed { kind: Timeout }` in one place; the
    binding variant names per segment 2f / Phase 0a /
    Phase 0f are `SubmitSnapshotInvalidated` and
    `SubmitFailed { kind: DaemonTimeout | DaemonUnavailable }`
    respectively. All three sites updated; the timeout
    bullet is also expanded to cover both ambiguous-failure
    variants per segment-2f's daemon-side authority
    disposition (both carry the same operational signal for
    pattern-detection purposes).
  - **Finding G — `TimeoutResolverActor` chain-observation
    correlation contract architectural mismatch.** The
    `TimeoutResolverActor` FOLLOWUPS entry described
    subscribing to `LedgerDiagnostic::SnapshotMerged` to
    observe whether the timed-out `tx_hash` landed on
    chain — but `SnapshotMerged` is pinned by Phase 0g as
    `{ new: SnapshotId, prior: SnapshotId, height:
    BlockHeight }` and carries no `tx_hash` field, so the
    actor cannot implement the correlation from the stated
    event stream. The §5.4 R9 disposition prose carried the
    same mismatch. Disposition: soften both prose surfaces
    to defer the chain-observation mechanism to the V3.x
    consumer-actor PR's own design — the actor needs
    either (i) an additive `LedgerDiagnostic` variant
    carrying tx-confirmation payloads, or (ii) an additive
    `LedgerEngine` chain-query accessor, or (iii) both
    (event-driven for low-latency notification, polling
    for restart-amnesia catch-up). Pinning the mechanism
    in PR 5 would overspecify a V3.x consumer-actor that
    doesn't ship in V3.0; the `LedgerEngine` and
    `LedgerDiagnostic` surfaces have their own additive-
    extension discipline that the consumer-actor PR
    composes against. Wallet-correctness is preserved by
    R8's `ReservationTTLActor` safety net regardless of
    when `TimeoutResolverActor` lands.
  - **Finding I — PR #43 title + description scope
    correction.** The PR title and body still framed PR
    #43 as a Round-1-only doc-only PR with three commits,
    but the branch now contains all seven Round 2 segments
    (segments 2a–2g) plus two Copilot-review follow-up
    commits. PR metadata updated to reflect the actual
    Round 1 + Round 2 closed scope, with the seven-segment
    summary and Phase 0 binding enumeration mirroring the
    design doc's §5.5 closure. The earlier "Round 1 only,
    Round 2 out of scope" wording is replaced.

  **Markdownlint baseline parity confirmed** after edits
  (no new violations introduced). Round 2 remains closed;
  Round 3 (commit decomposition + Phase 1 commit list) is
  the next forward step pending user authorization.

- **Stage 1 PR 5 — address PR #43 Copilot review findings
  (Round 2 close-out follow-up).** Doc-only commit on
  `feat/stage-1-pr5-pending-tx-engine-design`. Addresses three
  Copilot review findings surfaced against the Round 2
  segments and segment 2g close-out:
  - **Finding 1 — §3.3 pre-flight checklist staleness
    (raised against b85edec9a, line 609 of design doc;
    re-raised on the same line).** The pre-flight checklist at
    §3.3 still marked R1 disposition / Phase 0 spec
    amendments / PR 4 Round 3 input bundle as pending, even
    though Round 1 closed those items (R1 in §5.5; Phase 0 in
    segment 2g §4; PR 4 Round 3 bundle as confirmation per
    §5.2 + §6). **Fix**: marked R1 / Phase 0 / PR 4 Round 3
    items as `[x]` with cross-references to the closure
    sections; Phase 1 commit decomposition remains `[ ]`
    pending Round 3.
  - **Finding 2 — R8 `ReservationTTLActor` subscription
    contract incomplete (raised against 2f177a0c3, line
    987 of design doc).** Segment 2e's R8 closure named only
    `PendingTxDiagnostic::BuildSucceeded` as the actor's
    subscription, with no terminal events. This would leak
    closed reservations into the actor's in-memory
    age-tracking map indefinitely, producing stale
    `ReservationOutstanding` warnings on already-terminated
    reservations and spurious `AutoDiscardMessage` round-trips
    to `PendingTxActor`. **Fix**: §5.4 R8 prose expanded with
    a full subscription contract section pinning
    `BuildSucceeded` (insert), `SubmitSucceeded` (remove —
    terminal success), and `Discarded` (remove regardless of
    `reason` — covers all four `DiscardReason` variants
    including the segment-2f `DaemonRejectedTerminal` and
    the segment-2e `TTLAutoDiscard` self-cleanup). Explicit
    "what `SubmitFailed` does *not* close" note per
    segment-2f R9's two-stage submit-flow + Finding-2
    daemon-side authority disposition: `SubmitFailed` on
    `DaemonTimeout` / `DaemonUnavailable` keeps the
    reservation in `SubmitPendingDaemonAck` and the actor
    keeps tracking. Memory-bound property pinned:
    actor's map size is bounded by
    `PendingTxActor::outstanding()`, not by cumulative
    reservation count.
  - **Finding 3 — FOLLOWUPS `ReservationTTLActor` entry has
    the same subscription gap (raised against 2f177a0c3,
    FOLLOWUPS line 3029).** Identical finding to Finding 2,
    in the FOLLOWUPS entry rather than the design doc.
    **Fix**: same subscription-contract expansion applied to
    the FOLLOWUPS entry; cross-reference to the design-doc
    §5.4 R8 closure preserved.
  - **Finding 4 — CHANGELOG Round 1 close entry residuals
    count predates R12 (raised against b85edec9a, CHANGELOG
    line 1449).** The Round 1 close entry says "four carry to
    Round 2; one new (R11)"; R12 was added in a subsequent
    Round 1 follow-up commit (the immediately-following
    CHANGELOG entry). **Fix**: added a parenthetical
    forward-pointer to the Round 1 close entry noting R12's
    addition in the follow-up; preserves the entry's
    historical accuracy at commit time while resolving the
    in-isolation reader's apparent inconsistency. The
    follow-up entry's existing R12 documentation is
    unchanged.

  No segment-2g substrate is revised; all four fixes are
  contract-clarification / status-update edits. Round 3
  readiness gate per segment 2g §8 fenceposts is unaffected.
  Updates docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md (§3.3
  checklist; §5.4 R8 subscription-contract subsection);
  docs/FOLLOWUPS.md (`ReservationTTLActor` entry subscription-
  contract subsection); docs/CHANGELOG.md (this entry +
  forward-pointer note on the Round 1 close entry). No code
  changes; no test impact.

- **Stage 1 PR 5 — Round 2 segment 2g (Round 2 close-out:
  §4 Phase 0 binding-form enumeration; `SnapshotId` hash
  primitive pin; §5.0.3 diagnostic-stream-doc generalization
  closure; §6 review checklist filled).** Doc-only commit on
  `feat/stage-1-pr5-pending-tx-engine-design`. Segment 2g
  closes Round 2 — the final segment that pins all Phase 0
  binding-form type-signature detail, fills the review
  checklist, and finalizes the diagnostic-stream-doc
  generalization disposition. Round 3 (commit decomposition +
  Phase 1 commit list) is the next forward step. **§4 Phase 0
  binding-form enumeration finalized**: Phase 0a
  (`SubmitError` and `SubmitErrorKind` enums per segment 2f);
  Phase 0b
  (`SnapshotId` opaque type with binding hash primitive — see
  below); Phase 0c (REMOVED at the trait surface per segment
  2d's R12 (a) closure); Phase 0d (`Reservation` struct shape
  with `extensions: Vec<ReservationExtension>` per segment 2b
  R14); Phase 0e (reservation-lifecycle prose with R5 / R9
  segment-2f / R10 closure cross-references); Phase 0f
  (`PendingTxDiagnostic` enum + constructor-bound
  `DiagnosticSink` per segment-2f §5.0.2.1); Phase 0g
  (`LedgerDiagnostic::SnapshotMerged` deferred to consumer-PR
  per segment-2g introduction-PR disposition — avoids
  speculative-introduction-without-consumer violation of the
  [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  no-live-caller rule); **four new Phase 0 candidates** from
  segment-2b / segment-2c residual closures: Phase 0h
  (`Signer` trait surface per R11 (b) segment-2b closure);
  Phase 0i (`OutputSelector` trait surface per R13 segment-2c
  closure); Phase 0j (`FeeEstimator` trait surface +
  `FeePriority` enum per R16 segment-2c closure with
  segment-2d V3.0-lift evaluation); Phase 0k
  (`SubmissionStrategyActor` topology slot per R15 segment-2c
  closure — V3.x introduction; no V3.0 trait amendment).
  **`SnapshotId` hash primitive pinned** as Keccak-256 via
  `shekyl-crypto-hash::cn_fast_hash` (original padding,
  consensus-audited) truncated to the first 128 bits with
  versioned domain-separation prefix
  (`b"shekyl-snapshot-id-v1"`). *(Forward-pointer: the
  Copilot-fix follow-up entry below revised this binding from
  segment-2g's prior `sha2`-based form to the Keccak-based
  form. The prior `sha2` citation referenced
  `rust/shekyl-engine-core/Cargo.toml` line 115, which is in
  `[dev-dependencies]` and therefore unavailable to production
  code; the production `sha2` at line 33 is `optional = true`.
  `shekyl-crypto-hash` is the consensus-audited Keccak
  primitive already unconditional in `shekyl-engine-core`
  production deps at line 28 — the strictly better
  dependency-discipline disposition.)* Selection rationale
  (revised form): `shekyl-crypto-hash` is an unconditional
  `[dependencies]` entry per
  [`17-dependency-discipline.mdc`](../.cursor/rules/17-dependency-discipline.mdc)
  workspace-state reuse rule against the actual
  production-dependency graph; security framing reset from
  collision-resistance / Grover-doubled-width (technically
  incorrect — Grover applies to preimage, not collision;
  quantum collision is governed by BHT, ~2⁴³ for 128 bits)
  to **second-preimage resistance over bounded snapshot
  population** (wallet observes ≪ 2⁴⁰ snapshots over its
  operational lifetime; classical second-preimage ~2¹²⁸
  work; quantum Grover second-preimage ~2⁶⁴ work; impact
  bound by adversary-controlled-daemon design-center per
  §5.3); versioned prefix permits V3.x migration to a wider
  output or different hash family without cross-stage
  rebuild because `SnapshotId` is a wallet-internal token
  that does not cross the wire. **§5.0.3 diagnostic-stream-doc generalization
  closure**: option (a) — rename
  `REFRESH_DIAGNOSTIC_STREAM.md` → `DIAGNOSTIC_STREAM.md`
  (general). Existing FOLLOWUPS entry amended with rename
  rationale (shared contracts modest in volume relative to
  per-stream taxonomies; single doc with shared-then-per-
  stream structure lower cross-reference cost than
  parent-and-children factoring) and doc-structure
  prescription for V3.x introduction PR (shared contracts at
  top; per-stream sections for `RefreshDiagnostic` /
  `PendingTxDiagnostic` + `DiscardReason` / `LedgerDiagnostic`
  pending the consumer-actor PR). Option (b) — parent
  `DIAGNOSTIC_STREAM_CONTRACTS.md` factoring — preserved as
  retroactively-applicable if growth justifies. **§6 review
  checklist filled**: binding-check matrix against the §2.4
  spec (trait surface methods unchanged; engine-type
  parameter additions `S: Signer`, `O: OutputSelector`,
  `F: FeeEstimator`); test-substrate preservation list
  (`AssertionSink` / `PanickingSink` property-test
  infrastructure inherited from PR 4 pattern; per-error-class
  R9 coverage; Finding-2 daemon-side authority coverage);
  call-site sweep audit enumeration (Phase 1 confirms every
  diagnostic-event emission site); PR 4 Round 3 input bundle
  resolved as confirmation per §5.2. **Round 3 readiness
  gate**: all §4 Phase 0 candidates binding-pinned; §6
  filled; FOLLOWUPS amended for the segment-2g rename;
  Round 3 ready to proceed. Updates §4 Phase 0 enumeration
  (full rewrite with binding-form signatures for all
  candidates 0a–0k); §5.0.3 generalization-question section
  (closes as (a) rename); §5.5 "What Round 2 carried"
  inventory (seven-segment summary; Round 2 final form);
  §6 review checklist (filled with all sub-checklists);
  §8 fenceposts (segment 2g moves to "Round 2 — completed";
  Round 3 named as next forward step); header status
  (Round 2 closed); CHANGELOG; FOLLOWUPS. No code changes;
  no test impact.
- **Stage 1 PR 5 — Round 2 segment 2f (R9 two-stage submit-flow
  closure with daemon-side authority for Finding 2 ambiguous
  outcomes; `SubmitError` + `SubmitErrorKind` enum pins;
  sink-binding constructor-bound closure for Finding 4).**
  Doc-only commit on `feat/stage-1-pr5-pending-tx-engine-design`.
  Segment 2f closes the last residual on the load-bearing
  submit path and the constructor-vs-per-method sink-binding
  question, leaving only Round 2 close-out work for segment 2g.
  **R9 closure** pins the two-stage submit flow with explicit
  internal `ReservationState` machine (`Active |
  SubmitPendingDaemonAck | Resolved`); trait surface unchanged
  (`outstanding()` counts `Active + SubmitPendingDaemonAck`).
  Self-continuation message pattern pinned: `PendingTxActor`
  defers reply until `SubmitCompleted` self-message arrives,
  preserving mailbox throughput. Per-error-class disposition
  table pins state-transition + diagnostic-event-sequence +
  trait-return tuples for `Accepted` / `AlreadyInMempool` /
  `DoubleSpend` / `FeeTooLow` / `Malformed` / `Timeout` /
  `NetworkError`. **Finding 2 closes as (B) — daemon-side
  authority**: on `Timeout` or `DaemonUnavailable`, reservation
  stays in `SubmitPendingDaemonAck`; consumer-explicit
  `discard(id, ConsumerExplicit)` is the resolution path; R8's
  `ReservationTTLActor` (per-state TTL with shorter TTL on
  `SubmitPendingDaemonAck`) is the safety net for forgotten
  resolutions. (A) actor-state authority rejected because the
  phantom-spent-output window violates the monotonicity
  property the tracker delivers per §3.4.5 (the same "consumer
  checking does work the trait should be doing structurally"
  anti-pattern PR 4 named). **`SubmitError` + `SubmitErrorKind`
  enums** pinned in §5.0.2 (both `#[non_exhaustive]`):
  `SubmitError = SnapshotInvalidated{..} | DaemonRejected{kind:
  SubmitErrorKind}`; `SubmitErrorKind = DoubleSpend | FeeTooLow
  | Malformed | DaemonTimeout | DaemonUnavailable`. **R5 ↔ R8
  ↔ R9 coherence verified** — reactive cleanup
  (`SnapshotRotationAutoDiscard`), proactive cleanup
  (`TTLAutoDiscard`), and daemon-authority cleanup
  (`DaemonRejectedTerminal`) share the
  `DiscardReason`/`Discarded` event infrastructure. **No new
  `PendingTxDiagnostic` variants needed** (existing variant set
  sufficient for R9 state machine); **no new trait surface
  methods needed** (`discard(id, ConsumerExplicit)` is
  sufficient for consumer-explicit resolution of Finding-2
  ambiguity; `resolve_pending(id, chain_observation)` preserved
  as a V3.x ergonomic-API candidate). **Sink-binding closure
  (Finding 4)**: new §5.0.2.1 pins `LocalPendingTx::new(...,
  sink: Arc<dyn DiagnosticSink>, ...)` as constructor-bound
  under PR 4 §3.4.5 / R4 (a) consistency. R11's segment-2b
  closure as (b) made the sink-binding question independent of
  spend-material disposition; the two close separately.
  Rationale: engine-identity coupling (1-to-1 mapping load-
  bearing at the type level); Stage 4 actor wiring alignment
  (spawn-time DI); call-site cleanliness; runtime-swap surface
  preserved via sink-side indirection; no load-bearing reason
  for per-method override in production engines. Existing
  `SubmitFailureAnalyzer` FOLLOWUPS entry amended with
  segment-2f closure status; new `TimeoutResolverActor`
  FOLLOWUPS entry added naming the V3.x ergonomic-complement
  surface for Finding 2's daemon-side authority disposition.
  Updates §5.0.2 (`SubmitError` + `SubmitErrorKind` enum
  sketches); new §5.0.2.1 (sink-binding closure rationale);
  §5.4 R9 (closure prose with state-transition table); §5.5
  "What Round 2 carries" inventory; §8 fenceposts (segment 2f
  moves to "Round 2 — completed"); header status; CHANGELOG;
  FOLLOWUPS. No code changes; no test impact.
- **Stage 1 PR 5 — Round 2 segment 2e (R8 `ReservationTTLActor`
  composition closure; `DiscardReason::TTLAutoDiscard` variant
  pin).** Doc-only commit on
  `feat/stage-1-pr5-pending-tx-engine-design`. Segment 2e closes
  R8 (reservation TTL / leak prevention) by pinning all V3.0
  deliverables explicitly so V3.x's `ReservationTTLActor`
  introduction is additive-only — no V3.x trait revision, no
  V3.x enum revision, no V3.x consumer-side breaking change per
  the
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  continuous-discipline corollary. The Round 1 reframe already
  named `ReservationTTLActor` as the consumer-actor composition
  shape (same pattern as PR 4's `PeerReputationActor` /
  `RecoveryActor`); segment 2e pins the V3.0 deliverables: (1)
  `PendingTxDiagnostic::BuildSucceeded` emitted at the
  `build`-success path in `LocalPendingTx::build` /
  `PendingTxActor::handle_build` (Phase 1 call-site review
  confirms); (2) `PendingTxDiagnostic::Discarded { reason:
  SnapshotRotationAutoDiscard }` emitted at `submit`'s
  snapshot-mismatch path (R5's lazy-discard semantics); (3)
  `PendingTxDiagnostic::ReservationOutstanding` variant exists
  in the `#[non_exhaustive]` enum (no V3.0 emitter; V3.x
  `ReservationTTLActor` is the first emitter); (4) **new in
  segment 2e:** `DiscardReason::TTLAutoDiscard` variant added
  to the `#[non_exhaustive] DiscardReason` set so V3.x's
  `ReservationTTLActor` can trigger `PendingTxActor` to emit
  `Discarded { reason: TTLAutoDiscard }` events without a V3.x
  enum revision. **R5 ↔ R8 coherence verified** — R5's
  `SnapshotRotationAutoDiscard` is the reactive cleanup path
  (cleanup-on-use); R8's `TTLAutoDiscard` is the proactive
  complement (age-based policy on never-used reservations);
  both share the `DiscardReason`/`Discarded` event
  infrastructure. **Hard mitigation pins inherited verbatim
  from PR 4 §5.4.8** (restart-amnesia per #1; recursive trust
  boundary per #4; bounded mailbox per #5) bind on the V3.x
  consumer-actor PR via §5.0.3 — no PR 5 amendments needed.
  Existing `ReservationTTLActor` FOLLOWUPS entry amended with
  segment-2e closure-status confirmation and the new
  `DiscardReason::TTLAutoDiscard` variant pin; no new
  FOLLOWUPS entry needed. The R1 disposition still holds;
  segment 2e is residual-closure work that finalizes R8's
  disposition for design purposes. Updates §5.0.2 `DiscardReason`
  enum sketch (adds `TTLAutoDiscard` variant); §5.4 R8 (closure
  prose); §5.5 "What Round 2 carries" inventory; §8 fenceposts;
  header status; CHANGELOG; FOLLOWUPS. No code changes; no test
  impact.
- **Stage 1 PR 5 — Round 2 segment 2d (R2 + R12 co-disposition;
  Phase 0c truly collapses; `SnapshotId` opacity closed as
  16-byte content-addressed digest).** Doc-only commit on
  `feat/stage-1-pr5-pending-tx-engine-design`. Segment 2d
  closes the two remaining `SnapshotId`-adjacent residuals
  against the actual shape of the `LedgerSnapshot` substrate
  landed in PR 2. **R12 closes as (a)** — content-derived
  `SnapshotId` from existing `LedgerSnapshot` data; substrate
  inspection confirmed `LedgerSnapshot` carries
  `synced_height: u64` + `reorg_blocks: ReorgBlocks`
  (deterministic by construction; sufficient for content-
  addressed derivation). Stage 1's `LocalPendingTx` derives
  `SnapshotId` from `LedgerEngine::snapshot()` (existing trait
  method); Stage 4's `PendingTxActor` receives identical
  values via `LedgerDiagnostic::SnapshotMerged` events using
  the same digest function. No `LedgerEngine` trait amendment;
  Phase 0c truly collapses. **R2 closes as opaque 16-byte
  content-addressed digest** (`pub struct SnapshotId([u8;
  16])`); domain-separated hash over `LedgerSnapshot`'s
  deterministic fields; specific hash primitive pinned at
  Phase 0 review (segment 2g) per §3.1 PQC-discipline
  alignment. Determinism required by §5.0's submit-handler
  field-comparison contract; height-leak side-channel closed
  by construction. **§5.5 ground-1 prose softening** — drop
  "(pending R12)" qualifier; ground 1 is now closure-confirmed
  alongside grounds 2 and 3. **§4 Phase 0c prose softening**
  — drop "(pending R12)" qualifier; Phase 0c is REMOVED at the
  trait surface, full stop. **Projection-type discipline
  preserved-as-pattern** — no V3.0 PR 5 call-site introduces a
  cross-trust-boundary `SnapshotId` or `SnapshotMerged`
  consumer; the projection-type implementation lands in the
  V3.x consumer-actor PR per PR 4 §5.4.8 #4's recursive-
  trust-boundary discipline. **R16 conditional V3.0 lift
  evaluation** (segment-2c trigger): `LedgerBlock` carries no
  per-block fee data today; lifting R16 (c) to V3.0 would
  require either a storage-layout amendment (persistence-
  layer migration) or an unbounded historical-block walk per
  estimator call — neither is bounded cost; **R16 (c) does
  not lift to V3.0**, the conservative segment-2c default
  holds, and R16 (c) lands in V3.x behind a coordinated
  `LedgerEngine` + `FeeEstimator` PR. The R1 disposition
  still holds; segment 2d is segment-2c follow-through
  (closure-rule operational discipline applied to the
  conditional-V3.0-lift surface) plus the
  `SnapshotId`-substrate co-disposition the §8 fenceposts
  sequenced for this slot. Updates §5.4 R2, §5.4 R12, §5.4
  R16, §4 Phase 0c, §5.5 ground 1, §5.5 "What Round 2
  carries" inventory, §8 fenceposts, header status, and
  CHANGELOG. No code changes; no test impact.
- **Stage 1 PR 5 — Round 2 segment 2c (closure-rule and
  lens-applicability refinements paired with R13 / R15 / R16 /
  R17 named with dispositions).** Doc-only commit on
  `feat/stage-1-pr5-pending-tx-engine-design`. Segment 2c lands
  two project-wide discipline refinements (lens-applicability
  structural-conditions test; closure-rule wargaming-surface-
  known-at-closure-time qualifier) alongside four named-with-
  disposition R-residuals (R13 output-selection algorithm; R15
  submission-strategy as composable actor; R16 wallet-side fee
  estimation; R17 event-sourced recovery as user-controlled
  tradeoff). All four R-residuals close their V3.0 vs V3.x
  decisions with seam-design implications for Phase 0
  (`OutputSelector` / `SubmissionStrategyActor` / `FeeEstimator`
  / refined diagnostic-stream contract).

  **§5.0.4 lens-applicability discipline.** Section expanded
  with structured "Lens-applicability discipline" subsection
  establishing three structural conditions that govern when
  the actor-mesh lens applies to a per-engine extraction:
  (1) trait surface mediates state-mutation across actors,
  (2) adversarial review surfaces a cross-actor liveness or
  quiescence dependency, (3) Stage 4 actor-migration target
  is non-trivial. Per-engine PR pre-flights test
  applicability rather than presume it; the lens compounds
  across PRs **whose structure admits it**, not uniformly.
  Closure-rule cross-reference and fourth-shape adversarial-
  test record (Round 1 closure-review log: (1)-build paired
  with (3)-submit hybrid tested and rejected on criterion 5).
  Forward-template content for V3.1 rules-queue PR.

  **§7 closure-rule strengthening.** Restructured into
  "Closure rule (strengthened)" + "Round 1 closure rule
  (applied to PR 5)". General rule pinned: Round-N closes
  when the wargaming surface **known at closure time** is
  genuinely exhausted; new shapes surfacing in Round-N+1
  reopen Round N rather than slipping past closure (the
  closure rule pins what was known, not what could ever be
  known). Lens-applicability cross-reference: closure rule's
  "exhausted" criterion is satisfied differently depending
  on whether the lens applies. Round 1 fourth-shape
  closure-review test recorded as instance of the
  strengthened rule. Forward-template content for V3.1
  rules-queue PR.

  **§5.4 R13 — output selection algorithm.** Added with
  threat-model framing (deterministic-correlation, change-
  reuse, order-leak independent of FCMP++ ring semantics);
  options enumerated; disposition closed as V3.0 ships
  wallet2-greedy under `OutputSelector` trait-parameter seam
  (`LocalPendingTx<S: Signer, O: OutputSelector>`); V3.x
  lands `RandomizedSelector` / `EntropyMaximizingSelector`
  alternatives.

  **§5.4 R15 — submission strategy as composable actor.**
  Added with threat-model framing
  (transaction-network-entry-point timing / routing as
  wallet-layer privacy weakness against
  `ANONYMITY_NETWORKS.md` adversary); options enumerated;
  disposition closed as V3.0 ships `SubmissionStrategyActor`
  seam with `DirectStrategy` default; V3.x lands
  `JitteredSubmissionStrategy` / `CircuitRotationStrategy` /
  `BroadcastStrategy` / `BatchedStrategy`.

  **§5.4 R16 — wallet-side fee estimation.** Added with
  threat-model framing (daemon-recommendation on-chain
  fingerprint exploitable by malicious daemon per §5.3
  threat-model anchor); options enumerated; disposition
  closed as V3.0 ships
  daemon-recommendation-with-explicit-override under
  `FeeEstimator` trait seam; V3.x lands `WalletSideEstimator`
  analyzing `LedgerEngine` historical block fee
  distribution. **Conditional V3.0 lift** noted: if
  segment-2d Phase 0 review confirms bounded `LedgerEngine`-
  accessor cost, R16 (c) lifts to V3.0.

  **§5.4 R17 — event-sourced recovery as user-controlled
  tradeoff.** Added with threat-model framing (PR 4 §5.4.8
  #1 restart-amnesia rule's privacy property =
  diagnostic-event persistence does not leak across trust
  boundaries; refinement narrows prohibition to
  cross-boundary persistence specifically); options
  enumerated; disposition closed as V3.0 ships PR 4 §5.4.8
  #1 carryover (drop-on-close); V3.x optionally lands
  encrypted-persistence consumer for institutional /
  long-running / multi-day workflows. Diagnostic-stream
  contract pin refined: in-memory-by-default plus
  permitted user-controlled encrypted-persistence opt-in
  for consumers entirely within wallet's own
  encrypted-state surface (no cross-trust-boundary leak per
  PR 4 §5.4.8 #4).

  **FOLLOWUPS update.** Four V3.x entries added (output-
  selection alternatives under `OutputSelector` trait seam;
  submission-strategy actors under `SubmissionStrategyActor`
  seam; wallet-side fee estimator under `FeeEstimator`
  trait seam; encrypted-persistence
  `PersistenceConsumerActor` for long-running deployments).
  Each names the V3.x trigger and the seam-design
  implication that segment 2c lands at V3.0.

  **What Round 2 carries (§5.5).** Inventory updated to
  reflect R13 / R15 / R16 / R17 named-with-dispositions in
  segment 2c; §5.0.4 lens-applicability discipline + §7
  closure-rule strengthening landed in segment 2c; pending
  segments (2d / 2e / 2f / 2g) unchanged in scope.

  **§8 fenceposts.** Segment 2c moved from "Round 2 —
  pending" to "Round 2 — completed" with structured prose
  (six sub-bullets: §5.0.4 + §7 + R13 + R15 + R16 + R17 +
  CHANGELOG forward-template note).

  **V3.1 rules-queue inputs (forward-template content).**
  Two forward-template patterns this segment surfaces
  belong in the consolidated V3.1 rules-queue PR:
  - **Closure-rule wargaming-surface-known-at-closure-time
    qualifier.** "Round-N closes when the wargaming surface
    known at closure time is genuinely exhausted; new shapes
    surfacing in Round-N+1 reopen Round N rather than
    slipping past closure." Lift to a project-wide
    `16-architectural-inheritance.mdc` amendment (or
    standalone closure-discipline rule) when the rules-
    queue PR consolidates.
  - **Lens-applicability structural-conditions test.** The
    actor-mesh lens compounds across PRs whose structure
    admits it (three conditions: (1) trait mediates
    state-mutation across actors; (2) adversarial review
    surfaces cross-actor liveness/quiescence dependency;
    (3) Stage 4 actor-migration target non-trivial). Per-
    engine PR pre-flights test applicability rather than
    presume it. Lift to `16-architectural-inheritance.mdc`
    or a new `discipline.mdc` rule when the rules-queue PR
    consolidates.

  **Discipline note (forward-template).** Segment 2c is
  discipline-strengthening + opportunity-surface naming
  work that compounds project-wide design discipline
  without reopening the load-bearing question. Where
  segment 2a was audit-readiness and segment 2b was
  architectural-integrity-now at the residual level (R11),
  segment 2c lifts the project-wide pattern that makes
  future per-engine PR pre-flights answer the same
  questions methodically rather than adversarially.

- **Stage 1 PR 5 — Round 2 segment 2b (R11 signing-actor split
  reframe to (b); R14 reservation extensibility seam).**
  Doc-only commit on `feat/stage-1-pr5-pending-tx-engine-design`.
  The post-Round-1-closure adversarial review's primary finding
  surfaced an architectural-integrity-now item that the Round 1
  R11 working disposition deferred under PR 4 R4-consistency
  grounds; segment 2b reframes R11 to (b) — separate
  `LocalSigner` / `SigningActor` from Stage 1 — and adds R14 as
  a near-zero-cost reservation extensibility seam in the same
  commit.

  - **R11 reframe to (b) (architectural-integrity-now).** §5.4
    R11 prose replaced. Round 1's working disposition leaned
    (a) — `PendingTxActor` holds spend material, "matches PR 4
    R4's instance-scoped pattern" — with shape (b) (separate
    `SigningActor`) deferred to V3.x with the HW-wallet
    trigger. The cost-asymmetry argument that justified PR 4
    R4's tactical (a) (Scanner already existed in C++ holding
    view + spend material; restructuring Scanner was the
    deferral trigger) does **not** apply to PR 5 R11: PR 5 is
    opening the trait surface; `LocalPendingTx` does not yet
    exist; the choice between (a) and (b) is the same cost
    either way (we are designing one or the other from scratch,
    not moving from one to the other). R4-consistency cuts the
    other way: PR 4 R4's (a) explicitly named (c) as the
    long-term shape with the HW-wallet trigger; PR 5 R11 lands
    that long-term shape from the start. HW wallets are core,
    not edge, per `00-mission.mdc` §1; designing the trait
    surface so spend material never enters `PendingTxActor` is
    the threat-model-correct shape; deferring it to V3.x treats
    the architecturally-cleaner shape as an optimization rather
    than the baseline. Audit surface narrows under (b) (one
    actor whose sole job is signing); Stage 4 actor-migration
    cost is asymmetric (splitting an existing actor is harder
    than designing actors split). §5.0.1 sketches updated to
    add `signer: Arc<S>` (Stage 1) and `signer:
    ActorRef<SigningActor>` (Stage 4) fields plus prose pinning
    the spend-material-locality discipline.

  - **R14 reservation extensibility seam.** New §5.4 R14 entry.
    `Reservation` shape gains an `extensions:
    Vec<ReservationExtension>` field; `ReservationExtension` is
    `#[non_exhaustive]` with empty V3.0 variant set; same
    extensibility pattern as `RefreshDiagnostic` /
    `PendingTxDiagnostic`. Forecloses V3.x trait revision when
    coinjoin / atomic-swap / time-locked / multi-stage /
    composable reservation variants land in V3.x consumer-actor
    PRs. Round 2 hygiene at near-zero cost; large optionality
    preservation.

  - **FOLLOWUPS update.** The pre-segment-2b
    `PendingTxEngine`-(b)-signing-actor-split V3.x deferral
    entry in [`FOLLOWUPS.md`](./FOLLOWUPS.md) is replaced by
    a V3.x entry tracking HW-wallet integration as a
    `Signer`-impl substitution against the existing
    architecture. PR 4 R4 V3.x deferred-(c)
    (split-producer/recoverer for view-tag matching vs. final
    hybrid-decap) remains V3.x-deferred but benefits from PR 5
    R11 (b)'s `SigningActor` infrastructure: the spend-key-
    isolated actor R4 (c) needs has a precedent in PR 5's
    `SigningActor`; lifting R4 (c) at the V3.x trigger becomes
    simpler.

  - **Discipline note (forward-template).** R11's reframe is
    the architectural-integrity-now discipline applied at the
    residual-disposition level — R-residual dispositions
    inherit the same architectural-integrity-now discipline
    that PR 3 / PR 4 established at the load-bearing question.
    The cost-benefit-defer-to-later anti-pattern per
    `16-architectural-inheritance.mdc` recurred in a residual
    disposition rather than a load-bearing question; segment
    2b's reframe makes future per-engine PRs subject to the
    same discipline at the R-residual level.

  - **Header status + §8 fenceposts updated.** Header acquires
    a Round 2 segment 2b paragraph documenting the R11 reframe
    rationale and the R14 extensibility seam. §8 fenceposts:
    segment 2b moves to "Round 2 — completed" with a per-item
    breakdown; pending segments renumber as 2c (closure-rule +
    lens-applicability + R13 / R15 / R16 / R17 named with
    dispositions), 2d (R2 + R12 co-disposition), 2e (R8), 2f
    (R9 + sink-binding decouple from R11), 2g (close-out).

- **Stage 1 PR 5 — Round 2 segment 2a (audit-readiness): §5.3
  criterion 5 strengthening + threat-model anchor explicit
  defense + §5.5 scorecard rationale clarification.** Doc-only
  commit on `feat/stage-1-pr5-pending-tx-engine-design`. The
  post-Round-1-closure adversarial review surfaced five
  refinements for Round 2; segment 2a lands the three audit-
  relevant items (3 / 4 / 5 from the outcomes summary) in one
  commit ahead of the R-residual dispositions per the
  audit-blocking sequencing decision so audit-prep does not
  sequence behind R2 / R8 / R9 / R11 / R12.

  - **Item 4 (audit-blocking) — §5.3 criterion 5 strengthening.**
    Reframes the rejection ground for shapes (2)/(3) from
    "cross-actor liveness query" to **"contract dependency on
    refresh quiescence at any point in the build/submit flow."**
    Documents the stream-subscription steelman implementation
    (PR 4 `RefreshDiagnostic::AttemptStarted` /
    `AttemptCompleted` events push-driving a
    `refresh_in_flight: bool` rather than a synchronous query)
    and explains why it still fails: the daemon controls when
    `AttemptCompleted` fires, the bool stays `true`
    indefinitely under drip-feed responses, and the build (or
    submit) stalls regardless of which mechanism observes
    quiescence. The load-bearing property is the contract
    dependency, not the observation channel — synchronous
    query, push-driven bool, mailbox await, polling, or any
    other mechanism delivering the "quiescent" signal carries
    the same daemon-controllable failure mode.

  - **Item 5 — §5.3 threat-model anchor explicit defense.**
    Adversary-controlled-daemon-as-design-center made explicit
    (not citation-only). References
    [`ANONYMITY_NETWORKS.md`](./ANONYMITY_NETWORKS.md) plus
    the structural property "daemon outside the wallet's trust
    boundary by **design choice**, not as a hardened edge
    case." The Tor/I2P-first deployment posture means
    adversary-controlled daemons are the **expected
    deployment**, not an exception. Designs that admit
    structural single-peer DoS of transaction submission are
    rejected as **structurally incompatible with the project's
    primary deployment model** — the rejection is not "we can
    tolerate this in some deployments and harden against it in
    others"; it is "this contract shape contradicts the
    deployment model the design serves."

  - **Item 3 — §5.5 scorecard rationale clarification.**
    One-line clarification expanded into structured prose
    explaining criteria 4 and 5 share **underlying mechanism**
    (the contract dependency on refresh quiescence) but score
    **distinct consequences**: criterion 4
    (implementation-feasibility / actor-migration
    compatibility) evaluates "the implementation creates the
    vulnerability"; criterion 5 (threat-model-survival /
    adversarial-daemon resistance) evaluates "the threat model
    exercises the vulnerability." Both ✗s correctly scored;
    the shared mechanism is one structural property; the
    criteria evaluate distinct consequence axes; not
    double-counting.

  - **Propagation: §5.1 (2)/(3) + §5.5 ground 3.** Updated to
    use the contract-dependency reframe consistently with §5.3's
    strengthened framing. The standard implementation and
    stream-subscription steelman share the same fatal property
    (contract dependency on refresh quiescence); the prose says
    so explicitly; the rejection ground is named as
    "contract-level, not implementation-level."

  - **Header status + §8 Round 2 fenceposts updated.** Header
    acquires a Round 2 segment 2a paragraph documenting what
    landed and why the audit-blocking sequencing puts items
    3/4/5 ahead of the R-residual dispositions. §8 restructured
    into "Round 2 — completed" / "Round 2 — pending"
    sub-sections with segment 2a marked completed and segments
    2b/2c/2d enumerated as pending.

  R1 disposition still holds — the strengthening sharpens the
  audit-blocking defense without reopening the disposition.
  Segments 2b (closure-rule + lens-applicability), 2c
  (R2/R12, R8, R9, R11 dispositions), and 2d (Phase 0
  enumeration + close-out) follow at normal cadence.

  **V3.1 rules-queue inputs (forward-template content).** Two
  patterns this adversarial pass surfaced belong in the
  consolidated rules-queue PR alongside the §19 /
  rule-15-trinary / pre-flight-FOLLOWUP-scope items already
  queued from PR #41 Commit 2: (i) **closure-rule scope
  qualifier** ("Round-N closes when the wargaming surface
  known at closure time is exhausted; new shapes surfacing in
  Round-N+1 reopen Round N rather than slipping past
  closure"), generalizes from PR 5's specific instance to any
  project-wide design discipline using round-by-round
  wargaming closure; (ii) **lens-applicability discipline**
  ("project-wide design lenses compound across PRs whose
  structure admits the lens; future per-trait PRs test
  applicability rather than presume it"), tempers PR 4
  §5.4.6 / PR 5 §5.0.4's projection without weakening the
  institutional payoff claim. Both land in segment 2b's
  doc edits to §5.0.4 and §7; the V3.1 rules-queue PR will
  consolidate them with the other queued inputs.

- **Stage 1 PR 5 — PR #43 Copilot review-pass disposition: two
  R12-enumeration-consistency findings.** Doc-only follow-up
  commit on `feat/stage-1-pr5-pending-tx-engine-design`.
  `copilot-pull-request-reviewer` surfaced two valid findings
  on PR #43, both at the same audit-time question ("does R12
  appear in every Round 2 residual enumeration?"): §5.1 closure
  summary at line 429 ("R3 / R5 / R10 dissolve by composition
  under §5.0; R2 / R8 / R9 / R11 carry to Round 2") and §7
  discipline budget revised estimate at line 1294 ("Round 2
  disposes residuals (R2 / R8 / R9 / R11)"). Both omitted R12
  despite the surrounding sections (§1, §5.2, §5.4, §5.5 "What
  Round 2 carries", §8 fenceposts) consistently including it.
  Both fixed verbatim per Copilot's suggestions; defensive sweep
  via grep confirmed all six R-residual enumerations now
  consistently carry R12, and the four "what dissolves"
  enumerations correctly remain on R3 / R5 / R10. Doc-only;
  no Rust or C++ code touched.

- **Stage 1 PR 5 — Round 1 follow-up: R12 (Stage 1
  `current_snapshot` acquisition mechanism) added; §5.5 ground-1
  prose softened against implicit overclaim.** Doc-only follow-up
  commit on `feat/stage-1-pr5-pending-tx-engine-design`. Round 1
  review surfaced one R1-adjacent finding the closure commit
  implicitly overclaimed: §5.0.1's `LocalPendingTx` sketch holds
  `ledger: L` "for `current_snapshot` reads in Stage 1," but
  §5.5's first structural ground claimed Phase 0c collapses
  without naming Stage 1's actual snapshot-acquisition mechanism.
  Adding R12 names the three options without resolving them
  (deferred to Round 2 alongside R2's `SnapshotId` opacity
  disposition); the §5.5 ground-1 prose is softened from
  "Phase 0c collapses" to "Phase 0c collapses at the trait
  surface (pending R12)" to match the mechanism uncertainty.

  **Three options enumerated in R12 (no resolution).**
  - **(a) Content-derived `SnapshotId` from existing
    `LedgerSnapshot` data (working hypothesis).** Stage 1 reads
    snapshot identity via existing `LedgerEngine` /
    `LedgerSnapshot` surface; computes content-addressed ID
    locally. **Phase 0c truly collapses** in this disposition;
    no new trait surface.
  - **(b) Stage 1 subscribes to the `LedgerDiagnostic` stream.**
    Stage 1 implementation symmetric with Stage 4; modest
    implementation-symmetry cost in `LocalPendingTx`. Phase 0c
    still collapses at the trait surface.
  - **(c) `LedgerEngine` grows a small additive accessor.**
    Phase 0c partially restored, but **additive only** — read-
    only and idempotent; not the load-bearing coupling the
    original Phase 0c projected.

  Round 2 confirms by inspecting `LedgerSnapshot`'s actual
  shape against the working hypothesis. Disposition's outcome
  triggers a small mechanical softening of §5.5 ground-1 prose
  (drop "pending R12" qualifier on (a); reword for (b)/(c) as
  needed) and the matching §4 Phase 0c hedge.

  **Round 1 disposition unchanged.** Grounds 2 and 3 (CAS-isn't-CAS
  / adversarial-daemon-resistance-as-structural) are
  **independently sufficient** to defeat shapes (2) and (3) under
  the actor-mesh framing per
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.5. Ground 1 is expected confirmation, not load-bearing for
  the disposition.

  **Findings deferred to Round 2 (review-pass scoping).**
  - Finding 2 — mailbox-ordering vs daemon-side authority for
    R9 (terminal-rejection visibility): R9 contract clarification
    in Round 2.
  - Finding 3 — criterion 5 strengthening from "cross-actor
    liveness query" framing to "contract-dependency-on-refresh-
    quiescence" framing: closes a steelman attack ("but you
    could implement (2) via stream subscription, no synchronous
    query") without changing the disposition. Round 2 prose pass.
  - Finding 4 — sink-binding decoupling from R11 in §5.0.2:
    constructor-bound is the right answer on PR 4 §3.1 / R4
    consistency grounds, independent of R11's spend-material
    disposition. Round 2 hygiene.

  This is the architectural-integrity-now disposition per
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  applied to documentation honesty: cheap residual addition +
  one prose softening preserves the discipline against the
  cost-benefit-defer-to-later anti-pattern (the Round 2 commit
  would otherwise have to correct an overclaim that lived in
  the Round 1 commit's prose). Doc-only; no Rust or C++ code
  touched.

- **Stage 1 PR 5 — Round 1 close: actor-mesh reframe + shape (1)
  disposition (snapshot-ID pinning).** Doc-only commit on
  `feat/stage-1-pr5-pending-tx-engine-design` (off `dev` at
  PR-#42 merge `6de8335d5`). Closes the load-bearing open
  question
  [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5 in **one round** rather than the seed's
  three-to-four-rounds projection because the §5.0 actor-mesh
  framing exhausts the wargaming surface in this round per the
  §7 closure rule. Shape (1) — build-against-current-snapshot +
  snapshot-ID pinning — wins on **structural** grounds; shapes
  (2) and (3) fail criterion 5 (adversarial-daemon resistance)
  by construction under the actor framing; no fourth shape
  survives. **Two rounds saved against the seed projection.**

  **The §5.0 actor-mesh reframe.** PR 4's Round 2 reframe
  established a project-wide design lens: the trait surface is
  the synchronous decision point that consumers branch on; the
  rich semantic surface lives on the diagnostic-stream seam
  (`DiagnosticSink` parameter; typed event enum). PR 5 inherits
  the lens from Round 1 — the cost-benefit-defer-to-later
  anti-pattern PR 4 named has its cure now structurally
  available per
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc),
  applied at the load-bearing question rather than discovered
  in Round 2+.

  **Three structural grounds shape (1) wins on (§5.1).**
  - **Phase 0c collapses (§5.5 ground 1).** Under the seed's
    synchronous framing, `LedgerEngine` had to grow
    `current_snapshot_id() -> SnapshotId` so
    `PendingTxEngine::build` could read it inline. Under the
    actor framing, snapshot identity flows through the
    diagnostic-stream surface as
    `LedgerDiagnostic::SnapshotMerged { new, prior, height }`
    events emitted at the merge gate's normal operation. Phase
    0c (load-bearing cross-trait surface coupling) collapses to
    Phase 0g (additive event-variant amendment).
  - **The CAS isn't a CAS (§5.5 ground 2).** Under the actor
    mesh, `submit` is a mailbox message; the actor processes
    one message at a time; "check `reservation.snapshot_id`
    against `current_snapshot`" is a **field comparison in the
    message handler**, not a compare-and-swap. There is no
    concurrency to swap against — the actor is the
    serialization point. R3 / R10 dissolve as trait-surface
    contract questions.
  - **Adversarial-daemon resistance is structural (§5.5 ground
    3, criterion 5).** Under the actor mesh, `PendingTxActor`
    is decoupled from `RefreshActor`'s liveness by mailbox.
    Hostile daemon stalling refresh keeps `RefreshActor` busy
    in `produce_scan_result`; `PendingTxActor`'s mailbox
    continues processing build/submit/discard against the
    most-recently-merged snapshot regardless. **Shapes (2) and
    (3) require `PendingTxActor` to query `RefreshActor`'s
    state**, which is what creates the DoS surface; shape (1)
    has no such query. Per
    [`00-mission.mdc`](../.cursor/rules/00-mission.mdc) §1
    (security as precondition) and
    [`ANONYMITY_NETWORKS.md`](./ANONYMITY_NETWORKS.md) (adversary-
    controlled daemons in privacy-wallet topologies), a shape
    that admits structural single-peer DoS of transaction
    submission is rejected even when its UX and trait surface
    are otherwise minimal.

  **Five-criteria scorecard (§5.5).** Shape (1) passes all five;
  (2)/(3) pass criteria 1–3 but fail criteria 4 (Stage 4
  actor-migration compatibility — their cross-actor query
  introduces the DoS surface) and 5 (adversarial-daemon
  resistance, structurally).

  **Implications for PR 4 (§5.2 — resolved as confirmation).**
  PR 4 §5.3 deferred PR 4 Round 3 to PR 5 R1. Resolution: PR 4
  α confirms; the "provisionally load-bearing" qualifier on
  PR 4 §5.3's α is withdrawn. PR 4 Round 3 is a
  **confirmation-shape round**, not a re-evaluation round —
  α holds and PR 4 advances directly to Round 4 (commit
  decomposition + Phase 1 commit list). No γ-style
  consumer-driven refresh-progress streaming is required: under
  the actor framing, `PendingTxActor` already gets
  refresh-progress state push-driven from the diagnostic stream;
  γ becomes a redundant pattern the framing makes superfluous.

  **The diagnostic-stream seam for PR 5 (§5.0.2).** Parallel to
  PR 4's `RefreshDiagnostic`, PR 5 defines `PendingTxDiagnostic`
  (`#[non_exhaustive]`) carrying `BuildSucceeded` /
  `BuildFailed` / `SubmitAttempted` / `SubmitSucceeded` /
  `SubmitFailed` / `SubmitSnapshotInvalidated` / `Discarded` /
  `ReservationOutstanding` plus the `DiscardReason` enum
  (`#[non_exhaustive]`: `ConsumerExplicit` /
  `SnapshotRotationAutoDiscard` (R5 lazy-discard) /
  `DaemonRejectedTerminal` (R9 terminal disposition)). The trait
  surface adds a `&dyn DiagnosticSink` parameter on
  `LocalPendingTx::new` (constructor-bound, matching PR 4
  §3.1 / R4 preference; constructor-vs-per-method shape jointly
  disposed with R11 in Round 2). *(Forward-pointer: Round 2
  segment 2f tightened the constructor parameter from
  `&dyn DiagnosticSink` to `Arc<dyn DiagnosticSink>` for
  reference-shape ergonomics during the R11 closure; see the
  segment-2f and segment-2g CHANGELOG entries below for the
  final binding form.)* The cross-cutting
  `DiagnosticSink` contracts from PR 4 §5.4.6 / §5.4.7 R6
  reframe / §5.4.8 (non-blocking emit, recursive trust boundary,
  restart-amnesia detection, panic safety, concurrent emit,
  emission/return coherence) bind verbatim per §5.0.3.

  **Residuals (§5.4).** Five residuals dissolve by composition
  under §5.0; four carry to Round 2; one new (R11) surfaces.
  (R12 — Stage 1 `current_snapshot` acquisition mechanism — was
  identified in a subsequent Round 1 follow-up commit and added
  to the Round 2 carry list; see the immediately-following
  Round 1 follow-up changelog entry. Round 2 thus carries five
  residuals in total: R2 / R8 / R9 / R11 / R12.)
  - **Dissolved by §5.0:** R3 (build-during-refresh-during-reorg
    — mailbox FIFO orders structurally), R5-trait-surface-aspect
    (outstanding-reservations-on-rotation policy is local to
    `PendingTxActor`, not a trait-surface question), R10
    (concurrent build/submit/discard — mailbox FIFO is the
    actor-system contract).
  - **Carry to Round 2:** R2 (`SnapshotId` opacity / projection
    types; recursive trust boundary), R8 (reservation TTL /
    leak prevention — reframed as `ReservationTTLActor`
    composition + V3.x FOLLOWUPS), R9 (daemon-side submit
    failure — reframed as two-stage submit flow with
    intermediate `submitted-pending-daemon-ack` state and
    self-continuation message), R11 (signing-actor split — new
    under §5.0; Stage 1 keeps option (a) instance-scoped per
    PR 4 R4; V3.x FOLLOWUPS for option (b) `SigningActor`
    isolation, same trigger as PR 4 R4 deferred-(c) HW-wallet
    integration).
  - **Retained but lower-priority hygiene:** R4 (discard
    semantics under invalidation), R5-policy-aspect, R6
    (`outstanding()` semantics), R7 (`Send + Sync + 'static`
    on `P`).

  **Phase 0 net change (§4).** One amendment removed: 0c
  (load-bearing cross-trait synchronous query →
  `LedgerEngine`). Two added: 0f (`PendingTxDiagnostic` enum +
  `DiagnosticSink` parameter on `LocalPendingTx`); 0g
  (`LedgerDiagnostic::SnapshotMerged` variant addition —
  cross-trait but additive only, lives in the diagnostic-stream
  surface not in `LedgerEngine`'s trait surface). **Net effect:
  load-bearing surface coupling collapses to additive-only
  event-surface coupling**, which is exactly the kind of
  structural cleanup
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)'s
  continuous-discipline corollary predicts.

  **V3.x FOLLOWUPS landed in this commit.**
  - `ReservationTTLActor` consumer actor (closes R8 by
    composition; subscribes to `BuildSucceeded` / `Discarded`
    events; restart-amnesia constraint per PR 4 §5.4.8 #1).
  - `SubmitFailureAnalyzer` consumer actor (subscribes to
    `SubmitFailed` / `SubmitSnapshotInvalidated`; pattern
    detection — many `SnapshotInvalidated` in a row →
    adversarial reorg-churn; recurring `FeeTooLow` → fee
    estimator drift; recursive trust boundary applies).
  - `ReservationAuditActor` consumer actor (subscribes to all
    `PendingTxDiagnostic` events; in-memory wallet-action audit
    log; falls under recursive trust boundary discipline if it
    persists or exports — projections only).
  - `SigningActor` migration entry (R11 option (b); Stage 4
    spend-secret isolation; same HW-wallet-trigger language as
    PR 4 R4 deferred-(c)).

  **Cross-cutting `DiagnosticSink` contract-doc generalization
  (Round 2 disposition).** The contracts are now used by both
  PR 4 and PR 5; they are cross-cutting design invariants.
  PR 4's FOLLOWUPS named `docs/design/REFRESH_DIAGNOSTIC_STREAM.md`
  as the spec doc; Round 2 disposes whether to rename to
  `DIAGNOSTIC_STREAM.md` (general) or factor a parent
  `DIAGNOSTIC_STREAM_CONTRACTS.md` that PR 4 / PR 5 inherit
  from. Doc-only.

  Doc-only; no Rust or C++ code touched. Cross-references:
  [`STAGE_1_PR_5_PENDING_TX_ENGINE.md`](./design/STAGE_1_PR_5_PENDING_TX_ENGINE.md)
  §5.0 (actor-mesh framing as Round 1 substrate), §5.1
  (three-shape comparison under the lens), §5.2 (PR 4 α
  confirmed), §5.3 (five criteria), §5.4 (residuals), §5.5
  (Round 1 disposition + scorecard);
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.6 / §5.4.7 R6 reframe / §5.4.8 (the cross-cutting
  `DiagnosticSink` contracts inherited by PR 5);
  [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.4 (PR 5's binding trait surface — unchanged by Round 1).

- **Stage 1 PR 4 — PR #42 Copilot review-pass disposition:
  two typos, one stale work-list row, two CHANGELOG link
  retargets, one CHANGELOG ordering correction.** Six
  findings surfaced by `copilot-pull-request-reviewer` on
  PR #42's design-branch open. Validated each at source;
  five fixes landed verbatim, one fixed in the
  opposite-direction-from-Copilot-suggested (CHANGELOG
  ordering — Copilot suggested oldest-first; the file's
  established `[Unreleased]` convention is newest-first
  within substantive groupings, so the §5.5 hygiene entry
  moved to the **top** of the PR 4 cluster rather than to
  the bottom). Concrete dispositions:
  - Typo `Forecloseing` → `Foreclosing` in
    [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
    §5.4.6 (R6 reframe, concurrent-emit pin discussion).
  - Typo `dispositon` → `disposition` in
    [`REFRESH_DESIGN_LANDSCAPE.md`](./design/REFRESH_DESIGN_LANDSCAPE.md)
    §6 (bandwidth/pruning interplay paragraph).
  - §5.5 work-list row for β internal-batching updated
    from pre-Round-2 staleness (`V3.x (R2)` /
    "promotion to FOLLOWUPS pending Round 2 R2 disposition")
    to the settled Round 2 R2 disposition (**closed —
    kept as §2.2 future-scaling note; not promoted to
    FOLLOWUPS yet; revisit if V3.0 RC stabilization
    bandwidth profiling identifies β as the remediation
    over alternatives**).
  - Two CHANGELOG citation links retargeted from
    self-references to
    [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
    over to the actual
    [`engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs)
    source. The link **text** named the source file; the
    link **target** pointed to the design doc. Audit
    readers couldn't follow the citation to code; that
    misled the audit trail.
  - PR 4 CHANGELOG cluster reordered so the newest commit
    (§5.5 hygiene) sits at the top, matching the file's
    `[Unreleased]` newest-first convention. The Round 1
    chronological pair (disposition above review pass) is
    preserved as a narrative — moving them to the bottom
    of the cluster would have required two cross-reference
    rewrites (`above` → `below`) for marginal benefit;
    the minimal-invasive disposition is correct here. The
    Round 2 sub-cluster was already newest-first; only the
    §5.5 hygiene's position needed correction. PR #42
    test plan updated to describe the resolved layout.
  Doc-only; no Rust or C++ code touched.

- **Stage 1 PR 4 — §5.5 work-list hygiene: P3
  `apply_scan_result_to_state` `Vec<usize>`-discard row
  added.** Single-row addition to the
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.5 work-list against the dev-side FOLLOWUPS entry
  ("P3: `apply_scan_result_to_state` allocates `Vec<usize>`
  even for trait-impl callers that discard it") that landed
  via PR #37 (commit `0a0d46b38`, 2026-05-10) during the
  design branch's pre-M3-tail window. The design branch was
  cut at `9e53c82fa` (pre-PR-#37); PR #37 reshaped the merge
  pipeline (`LedgerIndexes::ingest_block`,
  `process_scanned_outputs`, `apply_scan_result_to_state`
  carry insertion-index ranges) and added P3 to FOLLOWUPS as
  a PR 4-triggered deferral. The work-list row closes the
  audit delta between the design doc's enumeration and the
  dev-side FOLLOWUPS state before the design branch lands
  onto `dev`. P3's disposition under α (Round 1) plus
  (a-instance-scoped) view-material (Round 2 R4) remains
  Round 3 / Round 4 trait-surface enumeration: either
  `LedgerEngine::apply_scan_result` grows to surface the
  insertion-range carryout (Vec consumed, optimization dead
  code) or `RefreshEngine` owns the post-pass directly and
  the trait method is removed (discard sites disappear).
  Doc-only; no Rust or C++ code touched.

- **Stage 1 PR 4 — Round 1 disposition: α (preserved current
  shape) for the `RefreshEngine` producer-redesign question.**
  Doc-only commit on `feat/stage-1-pr4-refresh-engine-design`
  (off `dev` at `9e53c82fa`). Closes the load-bearing open
  question
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5 named in the seed; α is the disposition because it satisfies
  all four review criteria — PR 4 extraction cleanliness, PR 5
  two-phase build/submit/discard contract over reorg events,
  reservation-tracker reorg surfacing, Stage 4 actor-migration
  compatibility — without forcing additional discipline into the
  per-trait PR or its consumers. β (internal batching) and γ
  (consumer-driven streaming) are separated as independent
  validation surfaces per
  [`19-validation-surface-discipline.mdc`](../.cursor/rules/19-validation-surface-discipline.mdc)
  (named on `dev` 2026-05-10) and recorded as residual questions
  R2 (β as V3.x FOLLOWUPS) and a hypothetical follow-up PR (γ
  if R1's PR 5 design surfaces correctness need).

  - Adds [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
    §5.4 (Round 1 disposition with four-criteria rationale and
    R1 / R2 / R3 residuals) and §5.5 (work-list table for every
    refresh-adjacent item with its target version and "where
    documented" pointer); marks the producer-redesign decision
    complete on §3.3's pre-flight checklist; rewrites §5.3's
    rounds trajectory to reflect Round 1's convergence on α and
    the resulting compression of Rounds 2–4.
  - Adds [`docs/design/REFRESH_DESIGN_LANDSCAPE.md`](./design/REFRESH_DESIGN_LANDSCAPE.md):
    refresh-design-space substrate covering the privacy-by-default
    precondition (§2), the operational view-tag pre-filter from
    [`STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
    §3.1.1 (§3), FMD as a V4 research direction (§4 — negative
    result for V3.0), OMR as a V3.x research direction (§5 —
    negative result for V3.0), and the pruning-vocabulary
    sidebar (§7) disambiguating daemon-side
    `--prune-blockchain` / archival `--no-prune` / RPC-server
    prune / wallet-side prune-by-birthday / prune-by-skip-to-height.
  - Adds a V3.0 [`docs/FOLLOWUPS.md`](./FOLLOWUPS.md) entry
    ("Refresh bandwidth tradeoff under α") naming the cost-benefit
    artifact PR 4's α-disposition consumed; entry pinned to V3.0
    RC stabilization (per the user's 2026-05-12 sequencing
    decision) so the cold-sync bandwidth tradeoff is load-bearing
    on RC stabilization rather than open-ended on the post-genesis
    backlog.

  Doc-only; no Rust or C++ code touched. Branch posture:
  `feat/stage-1-pr4-refresh-engine-design` stays on `dev`-rooted
  doc-only commits until M3e closes per
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)'s
  branch policy.

- **Stage 1 PR 4 — Round 1 review pass: more carefully-specified
  α (view-material flow, atomicity, error taxonomy).** Same-day
  follow-up to the Round 1 disposition above. The review pass
  corrected
  [`STAGE_1_PR_4_REFRESH_ENGINE.md`](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §3.1's materially-wrong "no secret-touching surface" framing
  to **master-secret isolation** routed through R4 — the existing
  producer
  ([`engine/refresh.rs:1254`](../rust/shekyl-engine-core/src/engine/refresh.rs))
  builds a `Scanner` carrying both the view secret (X25519
  view-tag pre-filter + hybrid-decap chain) and the spend secret
  (key-image computation) per attempt, so the load-bearing
  threat-model property is "no per-output derived secrets cross
  the trait surface," not "no secrets." The review pass
  surfaced four additional residual questions and three
  trait-contract observations:

  - **R4 — view-material flow** (constructor-bound vs. per-call
    vs. split-producer/recoverer). Load-bearing; affects
    `LocalRefresh::new` constructor shape and Stage 4 actor
    envelope. §4 Phase 0a / 0b candidate. Round 2 disposition.
  - **R5 — mid-scan reorg-abort at checkpoint 3**. Mitigation
    for the reorg-amplification adversarial scenario (§5.4.5).
    Trade-off: extra daemon RPC cost vs. hostile-daemon work
    amplification. §4 Phase 0d (conditional). Discipline-budget
    gated. Round 2 disposition.
  - **R6 — `RefreshError::ConcurrentMutation` boundary**. Pinned
    as orchestrator-internal translation of `LedgerEngine`
    errors; **excluded** from `RefreshEngine::produce_scan_result`'s
    error type. §4 Phase 0c variant set: `Cancelled`,
    `DaemonError(D::Error)`, `ScannerContractViolation { kind,
    evidence }`, `ReorgTooDeep { fork_height, max_rewind }`.
    Round 2 hygiene disposition.
  - **R7 — `ScanResult` atomicity-under-cancellation contract**.
    Confirmed against the existing implementation (cancel
    checks at lines 980 / 1140 / 1186 return `Cancelled`
    immediately; partial state drops via the function frame).
    Pinned in the trait contract per
    [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
    §2.3 / §7. §4 Phase 0a candidate.
  - Refines **R1**'s working hypothesis to
    *build-against-current-snapshot with snapshot-ID pinning*
    — the reservation tracker carries a snapshot ID per
    reservation; the submit path becomes a CAS against
    `current_snapshot == reservation.snapshot_id`. PR 5's
    design rounds open with this as the working hypothesis.

  **§5.4.4 three-call-mode constraint.** Cold open / restore,
  steady-state poll (~10–30 s), and post-submit confirmation
  have very different cost and cancellation profiles; per-call
  setup must be near-zero for steady-state. Phase 1's commit
  decomposition (Round 4) must not introduce per-call setup
  the inherent method did not have.

  **§5.4.5 adversarial scenarios under α.** Four daemon-attack
  vectors recorded with their dispositions: reorg amplification
  (mitigation = R5), view-tag DoS (Scanner implementation
  property; constant-time framing assumes non-adversarial input
  rates), withholding / partial responses (inherited from PR 1's
  `DaemonEngine` contract), snapshot poisoning via
  `LedgerSnapshot` (confirmed value-typed at lines 147–156),
  and `ScannerContractViolation.evidence` as memory-amplifier
  vector (bounded shape required).

  **§5.4.6 trait-surface contract pins.** `Send + Sync + 'static`
  bound on `R: RefreshEngine` (Stage 4 `kameo` actor wrap
  predicate); `Progress`-channel trust-boundary pin (consumers
  must be inside the wallet trust boundary; refused as a design
  question if not).

  The α-disposition holds against all of the review pass'
  findings — none argue for β or γ. They argue for a more
  carefully-specified α. Doc-only; no Rust or C++ code touched.

- **Stage 1 PR 4 — Round 2 close-out: Phase 0c
  `InternalInvariantViolation` + Phase 0e `DaemonOp` /
  `ProtocolErrorKind` seed enums.** Same-day follow-up to
  the Round 2 reframe contract-pin refinements
  (immediately-following bullet) that resolves two items
  the refinements had flagged as "Round 4 vs Round 2
  hygiene" questions. Both worth settling in Round 2
  because of downstream impact: deferring to Round 4
  re-opens a phase Round 2 was supposed to close.

  **Phase 0c amendment — `InternalInvariantViolation
  { context: &'static str }` on the orchestrator-side
  `RefreshError` enum.** Resolves the §5.4.7 R6
  "(a) extend `ConcurrentMutation` or (b) introduce
  `InternalInvariantViolation`" cleanup pin at the design
  layer, not Round 4 commit-decomposition. The retry-loop
  call sites at
  [`engine/refresh.rs:1672–1680`](../rust/shekyl-engine-core/src/engine/refresh.rs)
  and `:2055–2065` are **state-machine invariant
  violations** ("loop body itself is broken" per the
  existing site comments), not retry-budget exhaustion.
  Conflating both into `ConcurrentMutation` would route
  "wallet under sustained merge contention" (back off and
  retry) and "wallet hit an internal bug" (report and
  stop) through the same variant; downstream consumers
  (`PeerReputationActor`, telemetry, user-facing error
  surface) need the structural distinction. `&'static
  str` for `context` is appropriate at this site —
  compile-time-fixed developer content, not attacker-
  influenced data; the memory-amplifier and log-
  exfiltration vectors the producer-trait unit-variant
  discipline closes do not apply. The variant also bounds
  future migrations: future "state machine reached a
  should-never-happen path" findings route here. **Round 4
  migration target**: the two call sites migrate from
  `MalformedScanResult { reason: "..." }` to
  `InternalInvariantViolation { context: "..." }`; existing
  reason strings become `context` values.

  **Phase 0e seed enums — `DaemonOp` and `ProtocolErrorKind`
  initial variant sets, audited against the producer's
  actual call-site surface.** Two ground-truth findings:

  - `DaemonOp` narrows to two variants per the
    [`engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs)
    audit. The producer issues exactly two daemon RPCs:
    `daemon.get_height()` (tip fetch; lines 1480 / 1958)
    and `rpc.get_scannable_block_by_number(...)` (per-block
    fetch; line 1190). Under FCMP++ with view-tag
    pre-filtering, `get_scannable_block_by_number` returns
    the full per-block payload; no separate `GetBlocks` /
    `GetTransactions` / `GetOutputs` / `GetChainHashes`
    are issued. `GetFeeEstimates` and `SubmitTransaction`
    are `PendingTxEngine`-issued (PR 5), not refresh-issued.
  - `ProtocolErrorKind` is **fresh-defined**, not a
    re-export of upstream `shekyl_rpc::RpcError`. Upstream
    `RpcError` is a flat enum carrying `String` payloads
    in three of its eight variants (`InternalError(String)`
    / `ConnectionError(String)` / `InvalidNode(String)`)
    and is not a bounded re-export candidate. The producer
    must classify upstream into the bounded enum at the
    `RefreshDiagnostic`-emission boundary; the `String`
    payload elision is the load-bearing classification
    step per §5.4.7 R6's memory-amplifier closure.
    Initial variant set seeded against the call-site-
    reachable subset for the refresh producer:
    `{ ConnectionError, InternalError, InvalidNode,
    InvalidTransaction, PrunedTransaction }`. The other
    upstream variants (`TransactionsNotFound`, `InvalidFee`,
    `InvalidPriority`) are not reachable from refresh-issued
    RPCs.

  Round 4 commit-decomposition re-audits both seeds (the
  audit may surface additional reachable variants the seed
  missed, or paths the seed listed that aren't actually
  reachable); the audit is authoritative. The seeds serve
  as design-doc completeness and as an audit checklist.

  Doc-only; no Rust or C++ code touched.

- **Stage 1 PR 4 — Round 2 reframe contract-pin refinements:
  concurrent-emit clarification, producer-panic-safety property,
  and test-as-canonical-reference pin.** Same-day follow-up to
  the Round 2 reframe follow-up (immediately-following bullet)
  that closes three smaller remaining holes before Phase 0
  closes. None re-open the reframe; each closes a class of
  drift / failure-mode that would otherwise propagate to the
  V3.x consumer-actor PR.

  **Concurrent-emit clarification on the non-blocking pin
  (§5.4.6 + `DiagnosticSink` docstring).** The `Send + Sync`
  bound permits concurrent `emit` from multiple tasks; the
  non-blocking contract **holds under concurrent emission**,
  not merely per call. Serializing internal synchronization
  that admits unbounded contention — `Mutex<VecDeque<_>>`,
  `RwLock`-wrapped state, any shared mutable structure without
  bounded-wait guarantees — violates the contract even when
  each `emit` call returns promptly in isolation. Conforming
  implementations use lock-free queueing (`crossbeam::queue::ArrayQueue`,
  `flume` non-blocking sends), atomic counters, or sharded
  mailboxes. Forecloses a class of implementation that
  type-checks against the literal per-call non-blocking
  property and still re-introduces the producer-liveness
  hazard at scale — load-bearing under any future
  producer-side parallelism shape or Stage 4 actor-mesh
  topology where multiple `LocalRefresh` instances share a
  sink.

  **Producer-panic-safety property and Round 4 `PanickingSink`
  test deliverable (§5.4.6).** The non-blocking pin closes the
  producer-liveness hazard from a *blocking* `emit`. It does
  not close the adjacent hazard from a *panicking* `emit` —
  a buggy or third-party sink implementation that panics
  (null pointer dereference in a logger, allocator failure in
  a metrics consumer, panic-on-overflow in an aggregator)
  propagates unwind through the producer's call stack while
  the `Scanner` (holding spend material) is live across the
  `emit` call. **Pinning "MUST NOT panic" on `emit` as a hard
  trait contract is rejected** — it is unenforceable at the
  type system and pushes development cost onto every sink
  author for limited gain. The load-bearing property lives on
  the producer side: any panic propagating out of `emit`
  results in a predictable refresh-attempt failure with
  `Scanner` cleanly zeroized via `Drop`, no leaked half-state,
  and the cancellation token consistently in either
  fired-or-not state. **Phase 1 test deliverable:** the
  `AssertionSink` coherence property test grows a
  `PanickingSink` variant that panics on configured event
  variants; the test asserts (a) `Scanner` is dropped before
  the panic crosses the producer frame (visible via a
  `Zeroize` observer wrapper in the test harness), (b) no
  inconsistent producer state remains observable after the
  unwind, and (c) the panic propagates without `Drop`-chain
  corruption or double-panic. Round 4 commit-decomposition
  pass records this alongside the `AssertionSink` coherence
  test as a Phase 1 deliverable.

  **Test-as-canonical-reference pin on the coherence contract
  (§5.4.6 + `DiagnosticSink` docstring).** When the
  `AssertionSink` coherence property test lands in Round 4 it
  becomes **executable documentation of what coherence means**.
  If a future implementer reads §5.4.6 prose and is uncertain
  about an edge case (e.g., "does a `ScanProgress` emission
  count toward coherence for a `MalformedScanResult` return?"
  or "do two distinct error-class events from the same scan
  span count as one emission or two?"), the test's behavior is
  the authoritative answer. Prose ambiguities resolve against
  test behavior, not the other way around; if the test is
  wrong, the test is fixed and the prose follows, never the
  reverse. Per
  [`19-validation-surface-discipline.mdc`](../.cursor/rules/19-validation-surface-discipline.mdc),
  the property test is one of the validation surfaces for the
  coherence rule; naming it as authoritative makes prose / test
  drift impossible without explicit re-examination — a future
  PR landing prose changes to the coherence contract is
  required to re-examine the test, and vice versa.

  **§5.5 work-list amendments and §8 Round 4 deliverable
  update.** New work-list rows record the four-part
  contract-pin bundle (`non-blocking` + concurrent-emit
  clarification + coherence + canonical-reference) and the
  producer-panic-safety Round 4 test deliverable. §8's
  "Remaining for Round 4" prose names the paired
  `AssertionSink` (coherence) and `PanickingSink`
  (panic-safety) test deliverables as Phase 1 test-design
  outputs.

  Doc-only; no Rust or C++ code touched.

- **Stage 1 PR 4 — Round 2 reframe follow-up: `DiagnosticSink`
  contract pins and §5.4.8 refinements.** Follow-up to the
  Round 2 reframe (immediately-following bullet) that pins
  load-bearing contracts the V3.x consumer-actor PR would
  otherwise have to re-derive from first principles, and
  tightens two §5.4.8 attack-surface dispositions whose
  Round 2 framing was correct but underspecified.

  **Two contract pins added at §5.4.6 / §5.4.7 R6 / Phase 0e
  docstring.**
  - **Non-blocking `emit` contract.** `DiagnosticSink::emit`
    MUST NOT block. Implementations use `try_send`-shaped
    semantics; on a full bounded channel, unavailable
    consumer, or any other back-pressure condition, `emit`
    drops the event silently and returns promptly. Pinned
    to close the producer-liveness hazard: a blocked sink
    would pin the producer at the emission call holding the
    Scanner's spend material and would block observation of
    the cancellation token at checkpoints 2 and 3 —
    defeating both the §5.4.4 invocation-overhead
    constraint and the §3.1 wallet-lock-latency property.
    Without the trait-surface pin, a hostile or buggy
    consumer-actor sink in V3.x can introduce the hazard
    post-hoc with no structural reason for the consumer-
    actor author to know they did.
  - **Emission/return coherence contract.** `RefreshEngine`
    implementations MUST emit at least one corresponding
    `RefreshDiagnostic` event to the sink for every
    non-`Cancelled` `RefreshError` returned, before
    returning the error. Pinned to close the silent-error
    failure mode (orchestrator rotates peer with no
    telemetry; reputation actor blind) and the phantom-error
    failure mode (telemetry attributes a defect to a peer
    but the wallet then merges that peer's scan result as
    authoritative). Both fail open at the type-system
    level; only a contract pin closes them. Phase 1
    delivers a property-test CI invariant: an
    `AssertionSink` wraps `LocalRefresh` and asserts
    coherence on fuzzed inputs (Round 4 test-design
    deliverable).

  **§5.4.8 #1 — restart-amnesia named explicitly as a
  deliberate threat-model consequence.** The no-persistence
  posture is correct privacy-first, but an adversary who can
  observe or trigger wallet restarts (process kill,
  RPC-daemon restart, scheduled rotation, OOM, user
  quit-and-restart cycles) can rate-limit hostile behavior
  to evade reputation accumulation. **Pinned forward to the
  V3.x consumer-actor PR design:** detection logic is
  **coarse-window-based**, not credit-history-based; no
  "trust accumulation" over time. Forecloses the
  evasion-via-restart-cycle and the dual evasion-via-trust-
  accumulation patterns. Binding on `PeerReputationActor`
  and `ViewTagAnomalyDetector` design.

  **§5.4.8 #4 — trust-boundary framing re-phrased
  recursively.** The current text targeted obvious
  network-bound consumers (analytics, crash reporters,
  remote tracing); the subtler case is the *in-process
  aggregator-republisher* — a consumer in-process by
  topology but trust-boundary-crossing by publication
  (metrics-export actors with HTTP endpoints, debug UI
  actors over IPC, logger actors writing files collected by
  remote infrastructure, developer-mode flags dumping to
  off-host log collectors). The principle reframed: full-
  fidelity events flow only to actors whose **external
  surface is itself inside the wallet trust boundary,
  recursively**. The recursion creates a continuous audit
  obligation that binds on every PR touching the consumer-
  actor topology, anchored procedurally to
  `19-validation-surface-discipline.mdc`.

  **Phase 0e seed — `MalformedKind` initial variants
  recorded.** Six daemon-attributable variants
  (`NonEmptyForEmptyRange`, `RangeLengthMismatch`,
  `RangeMembershipViolation`, `DuplicateHeight`,
  `MissingHeightEntry`, `ResidualAfterApply`) covering the
  current `MalformedScanResult { reason: &'static str }`
  call sites in `engine/merge.rs` and `engine/refresh.rs`,
  so the unit-variant migration has a straightforward
  mapping at Round 4 commit decomposition. Non-daemon-
  attributable call sites (the retry-loop-exhaustion
  reasons in `engine/refresh.rs:1678–1680` and
  `:2061–2064`) are flagged for Round 4 cleanup — they
  don't belong on `MalformedScanResult`'s "peer rotation
  decision needed" structural branch.

  **Variant-ordering / serialization forward-note.** Under
  the §5.4.6 / §5.4.8 #4 in-process trust-boundary pin, the
  diagnostic stream is not serialized to any stable external
  format and variant ordering is not load-bearing; the
  `#[non_exhaustive]` attribute preserves additive evolution.
  The note exists for a hypothetical future PR that records
  diagnostic streams to disk for test replay — at that
  point, on-disk-format stability becomes load-bearing and
  the additive-evolution discipline acquires a backward-
  compatibility constraint. **No PR 4 action required;** the
  note is forward-recorded so the future PR has the
  constraint named.

  **FOLLOWUPS amendments.**
  - Added `ViewTagAnomalyDetector` V3.x entry with the
    explicit producer-side dependency: before the detector
    lands, the producer must grow a `ViewTagFalsePositive
    { observed_rate, expected_rate }` (or equivalent)
    variant. `#[non_exhaustive]` makes the addition
    additive without trait-surface revision.
  - Extended the diagnostic-stream spec-doc FOLLOWUPS entry
    (`docs/design/REFRESH_DIAGNOSTIC_STREAM.md`) to record
    the four binding contract pins (non-blocking,
    coherence, recursive trust-boundary, restart-amnesia
    detection discipline) as load-bearing spec content that
    consumer-actor PRs reference rather than re-deriving.

  Doc-only; no Rust or C++ code touched.

- **Stage 1 PR 4 — Round 2 reframe: diagnostic-stream seam
  supersedes Round 2 first-pass R5 / R6 dispositions.** This
  bullet supersedes the immediately-following bullet's R5 and
  R6 dispositions per the
  [Round 2 reframe section](./design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  §5.4.7 R5 reframe / §5.4.7 R6 reframe / §5.4.8. The
  immediately-following bullet's R1 / R2 / R3 / R4 / R7
  dispositions are unchanged and still hold.

  **Why the reframe.** Round 2's first-pass R5 (defer to V3.x
  with telemetry trigger) and R6 (keep `MalformedScanResult {
  reason: &'static str }`) reasoned about `RefreshEngine` in a
  synchronous function-call graph where the error is a single
  isolated event and the payload question is "what does this
  caller branch on." The design target is an actor-mesh fabric
  (Stage 4) where the error is a stream event with temporal
  context, and the same event routes to multiple consumers
  with different security properties per consumer. The
  first-pass disposition is the cost-benefit-defer-to-later
  anti-pattern per
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc);
  the reframe is the architectural-integrity-now answer —
  lay the seam now, defer only the consumer implementations.

  **The two-channel shape (R6 reframe).** The synchronous
  trait return and the actor-mesh diagnostic stream are
  different artifacts with different consumers and different
  security properties; they get different types.
  - **Channel 1: synchronous trait return `RefreshError` —
    unit variants only.** Three variants: `Cancelled`, `Io`,
    `MalformedScanResult`. **No string, no evidence, no
    payload of any kind.** The orchestrator's branch table is
    structural (cancel-propagate / retry-with-backoff /
    peer-rotation); the decision needs zero information
    beyond the variant tag. **Closes the memory-amplifier
    vector by construction** — there is no attacker-controlled
    data anywhere on the producer trait error surface.
  - **Channel 2: `RefreshDiagnostic` event stream emitted via
    `DiagnosticSink`.** Rich structured events fan out to
    specialized consumer actors with per-consumer trust
    posture and sanitization rules. `produce_scan_result`
    gains a `diagnostics: &dyn DiagnosticSink` parameter
    (per-call; runtime-dispatch; locked now so Stage 4
    doesn't re-rev the trait). Stage 1 emits a minimal seed
    variant set (`DaemonMalformed { kind: MalformedKind }`,
    `DaemonTimeout { op, elapsed }`, `DaemonProtocolError
    { kind }`, `ReorgObserved { fork_height, depth }`,
    `ScanProgress { height, candidates }`); Stage 1 sinks
    are `NoopDiagnosticSink` / `TracingDiagnosticSink`; the
    actor-mesh sink lands in V3.x. The enum is
    `#[non_exhaustive]` so the variant set grows additively
    with PR 1's peer-aware `DaemonEngine` surface and
    future-PR consumer patterns.
  - **Sanitization is a property of the consumer, not the
    stream.** Full-fidelity events stay in-process per the
    §3.1 / §5.4.6 trust-boundary pin (extended from the
    Progress-channel pin to the broader diagnostic-stream
    pin); persisted or exported projections are lossy by
    design.

  **R5 dissolved by composition (R5 reframe).** The
  reorg-amplification scenario resolves via a
  `ReorgAmplificationDetector` consumer actor that subscribes
  to `RefreshDiagnostic::ReorgObserved` events, maintains a
  windowed count, and signals cancellation back through the
  existing `CancellationToken` checkpoint-3 plumbing. **The
  producer's §7 checkpoint discipline does not grow.** No
  per-checkpoint-3 daemon RPC; no §7 amendment. The
  capability is added by composition of the actor mesh's
  consumers; the implementation deferred to the V3.x
  actor-mesh PR. **Trigger is policy-driven, not
  evidence-driven** — the previous "if hostile-daemon
  work-amplification scenarios become measurable" gate is
  withdrawn.

  **What the reframe unlocks (consumer-side; deferred
  implementations).** Fail2ban-style intra-session mitigation
  via `PeerReputationActor` (per-peer event history with
  decay; threshold-based graduated response); pattern-based
  recovery via `RecoveryActor` (Byzantine-fault-tolerance-flavored
  N-of-M agreement on contested data); reorg-amplification
  detection via `ReorgAmplificationDetector` (R5's natural
  home); future variant additions as the consumer-pattern
  surfaces mature.

  **Five new attack surfaces honestly enumerated (§5.4.8).**
  The reframe is not free; the diagnostic-stream seam
  introduces five attack surfaces, each with a mitigation
  pinnable now and a deferred consumer-actor implementation.
  - **Peer-reputation fingerprint** → in-memory only, scoped
    to wallet session, drop on close. Privacy-first wins
    over classical fail2ban's cross-session memory.
  - **`PeerId` stability under Tor/I2P** → `PeerId` is a
    transport-defined opaque token; decay calibrated to
    circuit-rotation cadence; Stage 1 variants omit peer
    attribution entirely until PR 1's peer-aware
    `DaemonEngine` surface lands.
  - **Rotation-timing side-channel** → jittered rotation,
    batched decisions, temporal decoupling of
    event-observation-time from rotation-action-time inside
    the `PeerReputationActor`.
  - **Diagnostic stream as covert channel** → trait-contract
    pin (§5.4.6 / §3.1): full-fidelity events flow only to
    in-process consumers inside the wallet trust boundary;
    cross-process or network-bound consumers receive only
    explicitly-sanitized projection types.
  - **Mailbox saturation as DoS** → bounded consumer
    mailboxes with explicit overflow policies (drop-oldest
    for diagnostics consumers; aggregate-on-overflow for
    reputation; event-sequence-aware drop for recovery).
    Producer-side: emit at natural rate; lossless delivery
    is not promised.

  **Phase 0 finalized under the reframe.**
  - Phase 0a: trait-surface contract pins + `ViewMaterial`
    type definition (R4) + diagnostic-stream trust-boundary
    pin (Round 2 reframe).
  - Phase 0b: `LocalRefresh::new(view_material: ViewMaterial)`
    constructor + flat-crate-root exports (R3 confirmation +
    `ViewMaterial`).
  - Phase 0c: **reframed** — unit-variant `RefreshError`
    (`Cancelled` / `Io` / `MalformedScanResult`; no payload).
    Orchestrator-side `RefreshError` retained with
    backward-compat content constructed orchestrator-side;
    no attacker-controlled trait payload.
  - Phase 0d: **retired** — R5 resolves by composition, not
    by deferral.
  - Phase 0e (**new**): `RefreshDiagnostic` enum +
    `DiagnosticSink` trait + `produce_scan_result` signature
    change (`diagnostics: &dyn DiagnosticSink` parameter).
    Stage 1 sinks: `NoopDiagnosticSink`, `TracingDiagnosticSink`.

  **FOLLOWUPS amended.** The previous Round 2 "extend
  checkpoint 3" V3.x FOLLOWUPS entry is **withdrawn** and
  replaced by the `ReorgAmplificationDetector` entry. Three
  new V3.x FOLLOWUPS entries added: `PeerReputationActor`
  (with §5.4.8 #1 / #2 / #3 mitigation pins binding on the
  implementation), `RecoveryActor`, and
  `docs/design/REFRESH_DIAGNOSTIC_STREAM.md` spec doc (seeded
  by PR 4's §5.4.7 R6 / §5.4.8 content; grows additively as
  consumers are designed).

  **Trajectory after the reframe.** Only Round 4 remains as
  PR-4-internal work (Phase 0 commit decomposition + §6
  review checklist); PR 5's design rounds carry R1 forward
  with the snapshot-ID-pinning working hypothesis. The
  α-disposition's *provisionally load-bearing* status remains
  the re-evaluation gate.

  **Meta-observation recorded.** The reframe is the
  recurrence pattern named by
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  "the cost-benefit-defer-to-later anti-pattern" working
  against itself — Round 2's first pass defaulted to deferral
  and minimal-surface; the architectural-integrity-now answer
  was to lay the structural seam (one parameter, one enum,
  one trait) and defer only the consumer implementations.
  The compounded benefit is what
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)'s
  "continuous discipline as inheritance prevention" framing
  predicts: the seam landed now removes the need for V3.x to
  re-litigate the trait surface.

  Doc-only; no Rust or C++ code touched.

- **Stage 1 PR 4 — Round 2 dispositions: R2 / R3 / R4 / R5 / R6 /
  R7 settled.** Same-day follow-up to the Round 1 review pass
  above. Round 2 closes all seven residuals named by Round 1 +
  the review pass; the more-carefully-specified-α frame is now
  closed and PR 4's design surface is Phase-0-ready.

  - **R1 — `PendingTxEngine::build` during long refresh.**
    Carried into PR 5's design rounds as the working hypothesis
    *build-against-current-snapshot + snapshot-ID pinning* — the
    reservation tracker carries a snapshot ID per reservation;
    the submit path becomes a CAS against
    `current_snapshot == reservation.snapshot_id`. Of the three
    sub-options, the only one that gives the reservation tracker
    monotone snapshot semantics + low-latency UI without
    serializing user input behind background work.
  - **R2 — β internal-batching.** Stays as the §2.2 "future
    scaling refinement" note; not promoted to FOLLOWUPS. The V3.0
    bandwidth FOLLOWUP entry already names α's bandwidth cost;
    V3.0 RC stabilization profiles cold-sync; if β is the right
    remediation, promote then. Premature promotion overspecifies
    against alternatives (daemon-side prefix matching, view-tag
    pre-filter improvements, wallet-side prune-by-birthday).
  - **R3 — `RefreshOptions` / `RefreshProgress` public-module
    promotion.** Confirmation, not discovery: `RefreshOptions`,
    `RefreshProgress`, `RefreshSummary`, `RefreshHandle`,
    `RefreshReorgEvent`, `RefreshPhase` are already crate-publicly
    re-exported from
    [`shekyl_engine_core/src/lib.rs:25–30`](../rust/shekyl-engine-core/src/lib.rs)
    at the flat crate root, matching the `DaemonEngine` /
    `LedgerEngine` convention. Stage 4's `kameo` actor implementor
    imports them as Stage 1 callers do today; no module promotion
    needed.
  - **R4 — view-material flow to the producer (load-bearing).**
    Disposition: **(a-instance-scoped)** —
    `LocalRefresh::new(view_material: ViewMaterial)`. New public
    `Zeroize + ZeroizeOnDrop` type carrying `{ spend_pub,
    view_scalar, x25519_sk, ml_kem_dk, spend_secret }` — exactly
    the fields `build_scanner_from_keys` extracts from
    `&AllKeysBlob` today. One `Scanner` held for `LocalRefresh`'s
    lifetime; per-attempt cost drops to snapshot+daemon RPC
    (no scanner construction). Stage 4 actor mailbox carries no
    secrets. Wallet-lock semantics drop `LocalRefresh` and
    zeroize via the existing `ZeroizeOnDrop` chain.
    **(c) split-producer/recoverer deferred to V3.x FOLLOWUPS**
    with trigger "HW-wallet-backed signing or post-V3 threat-
    model refinement requires producer-side spend-key isolation."
    (b) per-call rejected (hostile to actor migration).
  - **R5 — mid-scan reorg-abort at checkpoint 3.** Deferred to
    V3.x FOLLOWUPS. The per-checkpoint-3-hit `get_height` RPC
    cost (~per-block; ~10K+/wallet-day in steady-state) is
    non-trivial; the reorg-amplification attack is mitigated at
    a higher layer by PR 1's `DaemonEngine` peer-rotation
    contract; the discipline-budget cost of extending §7's
    checkpoint discipline is non-trivial. **Trigger for V3.x:**
    "hostile-daemon work-amplification scenarios become
    measurable in V3.0 RC stabilization or post-genesis
    production telemetry."
  - **R6 — `RefreshError::ConcurrentMutation` boundary + variant
    set.** Promote the existing crate-internal `ProduceError`
    ([`engine/refresh.rs:202`](../rust/shekyl-engine-core/src/engine/refresh.rs))
    to public `RefreshEngineError`; use it as
    `RefreshEngine::Error: Into<RefreshError>`. Variant set:
    `Cancelled`, `Io(IoError)`, `MalformedScanResult { reason:
    &'static str }` — the existing name and bounded payload are
    kept; the user-proposed `ScannerContractViolation { kind,
    evidence }` rename declined for V3.0 since `&'static str` is
    the strictest possible memory-amplifier-mitigation bound.
    **Excluded** from producer trait error: `ConcurrentMutation`
    (orchestrator-internal merge-gate concern), `AlreadyRunning`
    (orchestrator-internal handle-racing concern), `ReorgTooDeep`
    (kept as Ok-with-rewind merge-layer detection per §1.5
    actor-identity reasoning). The trait/orchestrator split is
    a Phase 0c spec amendment.
  - **R7 — `ScanResult` atomicity-under-cancellation contract.**
    Pinned in
    [`V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
    §2.3 / §7 prose: a `produce_scan_result` call returns either
    a `ScanResult` covering the full span scanned, or
    `RefreshError::Cancelled`; no partial-span `ScanResult`.
    Already true in the existing implementation per the cancel
    checks at
    [`engine/refresh.rs:980 / :1140 / :1186`](../rust/shekyl-engine-core/src/engine/refresh.rs);
    the contract pin prevents future drift.

  **§4 Phase 0 finalized.** Phase 0a: trait-surface contract
  pins (`Send + Sync + 'static` on `R`; Progress-channel trust
  boundary; `ScanResult` atomicity per R7; `LedgerSnapshot`
  value-typed contract; `ViewMaterial` type definition per R4).
  Phase 0b: `LocalRefresh::new(view_material: ViewMaterial)`
  constructor + flat-crate-root export of `ViewMaterial`.
  Phase 0c: `RefreshEngineError` promotion per R6. Phase 0d:
  retired (R5 deferred).

  **Two new V3.x FOLLOWUPS entries** in
  [`docs/FOLLOWUPS.md`](./FOLLOWUPS.md): R5 mid-scan reorg-abort
  deferral; R4 (c) split-producer/recoverer deferral. Both have
  named triggers per
  [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc).

  **Trajectory after Round 2.** Only Round 4 remains as
  PR-4-internal work (Phase 0 commit decomposition + §6 review
  checklist). PR 5's design rounds carry R1 forward with the
  snapshot-ID-pinning working hypothesis. The α-disposition's
  *provisionally load-bearing* status remains the re-evaluation
  gate: if PR 5's R1 resolution requires γ for correctness,
  PR 4 re-opens; otherwise PR 4 advances directly to Round 4.

  Doc-only; no Rust or C++ code touched.

### Fixed

- **CI bench gate no longer false-fails on `baseline=0` capture
  anomalies; the anomaly is surfaced as informational rather than
  silenced.** Discovered on PR #34: the `bench-baseline` branch's
  most-recent refresh (from dev-tip `647f82d5`) recorded
  `instructions=0` for six `hot_path_bench_ledger_postcard_*`
  entries that the prior nine baselines measured at ~4.4M / 44M /
  444M instructions each, with no causal code change between
  snapshots and iai-callgrind's own run summary embedded in
  `baseline.iai.snapshot` reporting `6 without regressions; 0
  regressed; 6 benchmarks finished` — the capture ran to
  completion. Cause is unknown (runner-image drift,
  iai-callgrind-runner version skew, build-flag drift, or a
  transient anomaly in the measurement layer are all candidates);
  investigation lives on
  `chore/investigate-bench-baseline-flake-2026-05-09`.
  [`scripts/bench/compare.py`](../scripts/bench/compare.py) now
  routes `(base_val == 0 && pr_val != 0)` into a distinct
  `baseline_zero` bucket — informational, not gating — that
  preserves the PR-side measurement for diagnosis.
  [`scripts/bench/post_comment.py`](../scripts/bench/post_comment.py)
  renders the bucket under its own header line ("Baseline anomaly
  (informational, not gated)") and table rows with a `_baseline=0_`
  verdict badge distinct from `ok` / `FAIL` / `added` / `missing`,
  so the anomaly surfaces to reviewers rather than being silently
  masked under the "new in PR" label. The post-merge
  `update-baseline` job re-captures from the next push to `dev`;
  if the next refresh produces real numbers the anomaly was
  transient and self-heals, if zeros persist the investigation
  branch has a fresh signal. Regression guards: real regressions
  still trip `fail` (validated with a +39% hot_path fixture); the
  `(base=0, pr=0)` edge case is preserved as a 0% delta `ok`
  rather than getting routed away. Lock-down:
  [`scripts/bench/test_compare.py`](../scripts/bench/test_compare.py)
  pins the routing logic with four regression tests
  (baseline-zero-bucket, real-regression-still-fails,
  both-zero-stays-ok, added-in-pr-distinct-from-baseline-zero);
  stdlib-only, runs via `python3 scripts/bench/test_compare.py`.

- **Bench-capture producer guard rejects `instructions=0` rows at
  source so the anomaly cannot reach `bench-baseline` again.**
  Paired defense-in-depth with the consumer-side `baseline_zero`
  bucket (above): the consumer routes around already-corrupted
  baseline data; the producer prevents new corruption from being
  written. Implemented in
  [`scripts/bench/capture_rust_baseline.sh`](../scripts/bench/capture_rust_baseline.sh)
  inside the JSON-assembly heredoc, post-parse / pre-write: any iai
  entry with `metrics.instructions == 0` causes the script to
  exit `2` with a structured error that lists the offending
  `(crate, bench_target, group, function, run_id)` tuples and
  points operators at `docs/investigation/2026-05-09-bench-baseline-flake.md`.
  The canonical `shekyl_rust_v0.json` is **not** written when the
  guard trips, so the prior good `bench-baseline` content is
  preserved across both pipeline arms — `update-baseline` (push to
  `dev`) and `capture-pr` (per-PR baseline). The raw stdout
  snapshot at `shekyl_rust_v0.iai.snapshot` is still written
  unconditionally as bisection evidence, and a diagnostic side-file
  at `shekyl_rust_v0.json.flake.json` carries the parsed envelope
  plus a `flake` block enumerating the zero entries — investigators
  can `gh run download`-style fetch it without re-running the
  harness. Bypass: `SHEKYL_BENCH_ALLOW_ZERO=1` skips the check
  with a loud `WARNING` line for local debugging of the capture-zero
  phenomenon itself; CI workflows must not set this. Validated
  with three smoke-tests against the heredoc body in isolation:
  mixed-healthy-and-zero rejects with exit 2 and writes only the
  flake side-file; bypass env var allows write-through with the
  warning; clean capture flows normally with no flake side-file.
  The guard's error message frames a workflow rerun as the
  expected operator response, matching the empirically observed
  flake rate (the same runner class typically produces a healthy
  capture on retry).

- **`account_base::generate(...)` no longer hardcodes `FAKECHAIN`;
  the legacy 3-arg overload is deleted entirely and every caller
  spells its network out explicitly.**
  Pre-fix, the 3-arg `account_base::generate(recovery_key, recover,
  two_random)` overload (with default args `secret_key{} / false /
  false`) hardcoded `DerivationNetwork::Fakechain` as the raw-seed
  derivation salt regardless of the wallet's actual `network_type`.
  Three production callers reached it via the implicit FAKECHAIN
  default: `wallet2::generate(name, password, recovery, recover,
  ...)` (the CLI / RPC wallet-creation and recovery entry),
  `wallet2`'s 0-change dummy-destination address generator
  (`transfer_selected_rct`), and
  `wallet_rpc_server::on_stop_background_sync`'s seed-recovery
  path. On TESTNET, every from-seed wallet creation produced a
  FAKECHAIN-salted account that failed `wallet2::load`'s rederive
  (which uses `m_nettype`, not FAKECHAIN). On MAINNET / STAGENET,
  the call was doubly broken: the FAKECHAIN-derived keys disagreed
  with the rederive salt, and RAW32 isn't a permitted seed format
  on those networks anyway. This footgun was masked for the entire
  window during which Bug 1's off-by-one was preventing any wallet
  from loading. Bug 4-adjacent in the 2026-05-05 FFI constant-
  drift audit.

  **Fix:** the new
  `account_base::generate(recovery_key, recover, two_random,
  network_type nettype)` overload threads the caller's network
  through `generate_from_raw_seed`, and is now the **only**
  `generate(...)` overload — the legacy 3-arg form is deleted
  entirely. `wallet2::generate(...)` and
  `wallet_rpc_server::on_stop_background_sync` migrated to pass
  `m_nettype` / `m_wallet->nettype()`. The 0-change dummy-
  destination caller in `wallet2::transfer_selected_rct` migrated
  to the same 4-arg form with `cryptonote::FAKECHAIN` hardcoded —
  it's a transient one-shot whose secret keys are discarded;
  properly network-matching the dummy address requires a BIP-39
  path on MAINNET / STAGENET (RAW32 isn't permitted there) and is
  filed under FOLLOWUPS V3.2. All 28 test callers across
  `tests/{unit_tests,core_tests,performance_tests,trezor,
  functional_tests,wallet_bench}` migrated to pass
  `cryptonote::FAKECHAIN` explicitly. The structural deletion
  eliminates the "one omitted argument away from FAKECHAIN"
  footgun class entirely — there is no longer a `generate(...)`
  overload that can pick a network silently.

  **Failure-mode change:** on MAINNET / STAGENET, every
  `wallet2`-routed raw-seed creation path now throws cleanly via
  the FFI's `permitted_seed_format` check instead of silently
  producing FAKECHAIN-salted unspendable wallets. The throw scope
  is wider than just the recovery path: `wallet_rpc_server::on_create_wallet`
  (fresh CSPRNG-seed wallet creation) and `wallet2_ffi::create`
  (FFI wallet creation) also throw on MAINNET / STAGENET. Both
  paths were already silently broken pre-fix — the post-fix
  behaviour is a strict improvement (fail-loud over fail-silent),
  but neither becomes a finished feature: fresh-seed wallet
  creation on MAINNET / STAGENET via `wallet2` simply does not
  work by design until the wallet2 BIP-39 entry point lands (Bug
  4 in the audit, deferred per the Rust wallet migration). On
  TESTNET / FAKECHAIN, every migrated caller produces correctly-
  network-salted accounts that round-trip through `wallet2::load`.

  **New regression test:** `tests/unit_tests/account.cpp` ::
  `generate_uses_explicit_nettype_argument` pins (a) `generate(...,
  TESTNET)` matches `generate_from_raw_seed(..., TESTNET)`, (b)
  `generate(..., FAKECHAIN)` produces a distinct account (different
  HKDF salt), and (c) `generate(..., MAINNET / STAGENET)` throws
  for **both** `recover=true` (recovery) and `recover=false` (fresh
  CSPRNG seed). See
  `docs/audit_trail/2026-05-ffi-constant-drift-audit.md` Bug
  4-adjacent.
- **`FCMP_REFERENCE_BLOCK_MIN_AGE` aligned to consensus authority (5).**
  `rust/shekyl-engine-core/src/multisig/v31/intent.rs` defined
  `FCMP_REFERENCE_BLOCK_MIN_AGE = 10` while
  `src/cryptonote_config.h` defines it as `5` (locked by Decision 14
  in commit `6561278d9`, asserted by `tests/unit_tests/fcmp.cpp:668`,
  documented in `docs/FCMP_PLUS_PLUS.md:432`). The Rust multisig
  `SpendIntent` was added in `744ab6407` 23 days after Decision 14
  and copied the pre-Decision-14 value `10`. Bug 3 of the 2026-05-05
  FFI constant-drift audit. Failure mode: a multisig wallet would
  reject reference blocks at heights `tip-9..tip-5` that the daemon
  consensus accepts — fail-closed at the wallet's own pre-broadcast
  validation, no path to silent acceptance, but still a real bug
  (UX: legitimate intents rejected by the proposer's own check).
  Fixed by aligning the Rust value to `5`, with a doc-comment that
  cross-references the C++ authority and the audit. Test
  `validate_temporal_rejects_ref_block_too_fresh` updated to use
  `tip = 903` (age = 3) instead of `tip = 905` (age = 5, which was
  the boundary value that masked the regression — age = 5 is not
  `< 5`). `docs/SHEKYL_MULTISIG_WIRE_FORMAT.md` aligned. The
  `chore/cbindgen-consensus-constants` follow-up generates this
  value from the Rust authority into the C++ build to prevent
  recurrence. See `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`.

- **C++/Rust FFI constant disagreement broke every wallet round-trip
  on every network.** `src/shekyl/shekyl_ffi.h` defined
  `SHEKYL_CLASSICAL_ADDRESS_BYTES = 64` while authoritative
  `rust/shekyl-crypto-pq/src/account.rs::CLASSICAL_ADDRESS_BYTES =
  1 + 32 + 32 = 65`. Because `ShekylAllKeysBlob` is `#[repr(C)]` with
  byte-aligned `[u8; N]` arrays, the 1-byte deficit shifted every
  later field's offset by one. C++ `populate_account_from_blob` read
  `spend_sk` and `view_sk` from the wrong bytes; the resulting
  non-canonical Ed25519 scalars failed `sc_check` inside
  `secret_key_to_public_key`, so `verify_keys` returned false and
  every `wallet2::load` threw `error::wallet_files_doesnt_correspond`.
  Header constant set to `65`. **Bug 1 of 2 surfaced by
  `wallet_storage.{store_to_mem2file, change_password_mem2file}`.**
  See `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`.

- **C++/Rust FFI constant disagreement caused every RAW32 wallet to
  silently mis-encode its `seed_format` byte.** `src/shekyl/shekyl_ffi.h`
  defined `SHEKYL_SEED_FORMAT_BIP39 = 0` / `_RAW32 = 1` while
  authoritative `rust/shekyl-crypto-pq/src/account.rs` defines
  `SEED_FORMAT_BIP39 = 0x01` / `SEED_FORMAT_RAW32 = 0x02` (with `0`
  reserved for "unset"). C++ wrote `m_seed_format = 1` to disk
  meaning RAW32; on `wallet2::load`, the FFI received `seed_format =
  1` and Rust decoded it as `Bip39`; `permitted_seed_format(Fakechain,
  Bip39)` returned `false`; the rederive returned `false` with
  `"(network, seed_format) pair disallowed or derivation
  inconsistent"`. The BIP-39 path was equally broken (both sides
  held `0`, which Rust rejected as "unset") but had no test
  exercising it at the C++/FFI layer — the bug went undetected for
  the entire window during which Bug 1 was masking it. Header
  constants set to `1` / `2`. **Bug 2 of 2.** Pre-V3 launch: no
  on-disk wallets exist, so no migration code is required. See
  `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`.

- **`wallet_storage` round-trip tests now construct `wallet2` with
  `cryptonote::FAKECHAIN`.** `wallet2::generate(name, password)`
  routes through the legacy `account_base::generate()` test wrapper,
  which hardcodes `FAKECHAIN` for raw-seed derivation regardless of
  the wallet's `m_nettype`. The default-constructed `wallet2`
  inherited `MAINNET`, so the rederive on `load` passed `MAINNET`,
  which doesn't permit `RAW32`. Tests now use `tools::wallet2
  w(cryptonote::FAKECHAIN, 1, true)` to keep the in-memory derivation
  network and the on-disk rederive network aligned. The same
  hardcoded-FAKECHAIN footgun in `account_base::generate()`'s callers
  (the `wallet2::generate("", password)` test path and
  `wallet_rpc_server::stop_background_sync`) is the **Bug 4-adjacent**
  finding in
  `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`, slated for
  the sibling branch `fix/legacy-account-generate-network-guard`.

### Performance

- **Refresh post-pass cost drops from O(n × B) to O(k × B).** The
  engine post-pass at
  `shekyl-engine-core::engine::merge::populate_engine_handle_fields`
  previously scanned the full `ledger.transfers` Vec on every
  `Engine::apply_scan_result` invocation, even though only
  `result.new_transfers.len()` entries can match the residue map.
  At a 100k-transfer ledger refreshed across 1k batches with
  k≈10 new transfers per batch, the post-pass alone executed
  ~10⁸ HashMap probes against `residue` that found nothing —
  ~5 s of refresh-time wallclock. The merge pipeline now threads
  the inserted-index list out of `LedgerIndexes::ingest_block`
  (now `Range<usize>`), through `LedgerIndexesExt::process_scanned_outputs`
  (now `Range<usize>`) and `apply_scan_result_to_state` (now
  `Result<Vec<usize>, RefreshError>`); the post-pass walks only
  the freshly-merged indices. Trait-impl wrappers
  (`LocalLedger::apply_scan_result`,
  `EngineFixture::apply_scan_result`) discard the Vec via
  `.map(|_| ())` so the orchestrator-public surface is
  unchanged. Closes the FOLLOWUPS V3.0 entry
  *"`populate_engine_handle_fields` O(n) → O(k) per scan"*.
  Pre-flight: `docs/design/PERF_MERGE_INSERTION_INDICES_PREFLIGHT.md`.

### Removed

- **Monero-era keys-file fixtures and unconditionally-skipped
  `wallet_storage` tests deleted.** The `tests/data/wallet_00fd416a*`
  and `tests/data/wallet_9svHk1*` fixtures were inherited from
  upstream Monero and predate the SHKW1 master-seed envelope
  entirely; they cannot be loaded under any version of the
  v3-from-genesis keystore. The three tests that referenced them
  (`wallet_storage.{store_to_file2file, change_password_same_file,
  change_password_different_file}`) had been gated behind
  `GTEST_SKIP()` for that reason and were providing zero coverage.
  Per `.cursor/rules/15-deletion-and-debt.mdc`'s "default: delete":
  4 fixture files (~2.3 MB) and 3 skipped tests removed.

### Added

- **Rust-internal FFI constant equality-assertion tests
  (`rust/shekyl-ffi/src/account_ffi.rs::tests`).**
  `ffi_classical_address_bytes_matches_rust_authority` and
  `ffi_seed_format_constants_match_rust_authority` pin the FFI
  re-exports to the authoritative
  `rust/shekyl-crypto-pq/src/account.rs` constants. **Scope (honest):**
  these tests compare two Rust-side values; they do not read
  `src/shekyl/shekyl_ffi.h`. A hand-edit to the C++ `#define` alone —
  the exact drift that produced Bugs 1 and 2 — would still leave
  them green. They catch a different and narrower bug class:
  divergence introduced inside the Rust workspace between
  authoritative and re-exported constants, before the C++ build
  runs. Cross-boundary detection (catching C++-side drift) is the
  explicit job of the reduced-scope generator in the sibling branch
  `chore/cbindgen-consensus-constants`, which generates a header
  from the Rust constants for `RCTTypeFcmpPlusPlusPqc`,
  `FCMP_REFERENCE_BLOCK_*_AGE`, and `ADDRESS_VERSION_V1`. Full
  migration of the remaining ~40 fail-closed-on-misuse constants is
  filed as FOLLOWUPS V3.0 (target pre-audit-final).

- **`tests/unit_tests/account.cpp` — BIP-39 + MAINNET coverage.**
  Four new tests close the only path Bug 2 broke that the existing
  test surface didn't exercise:
  `rederive_from_bip39_reproduces_account_mainnet` (full BIP-39
  derive + rederive round-trip via `account_base`),
  `bip39_passphrase_changes_account_mainnet` (passphrase isolation),
  `generate_from_bip39_rejects_fakechain_and_testnet`,
  `generate_from_raw_seed_rejects_mainnet_and_stagenet`,
  `rederive_from_bip39_reproduces_account_stagenet`, and
  `rederive_from_raw_seed_reproduces_account_testnet` (consensus-level
  `(network, format)` matrix invariants). The `wallet2`-level
  BIP-39 entry point that would let the test use the production API
  end-to-end does not exist **by design** — see Bug 4 below.

- **CI tripwire defending the `wallet2::generate_from_bip39` absence
  (`tests/unit_tests/wallet_storage.cpp`).** Three SFINAE detectors +
  one combined `static_assert` that fires at build time if a future
  contributor adds `wallet2::generate_from_bip39` with any of the
  three most plausible signatures (`(std::string&, std::string&,
  network_type)`, `(epee::wipeable_string&, epee::wipeable_string&,
  network_type)`, or `(std::string&, network_type)` — the
  defaulted-passphrase shorthand). The honest scope: an exotic
  signature could still slip past the detectors, so the
  load-bearing artifact remains the FOLLOWUPS architectural decision,
  not the tripwire itself. Includes per-detector positive-control
  self-tests (`tripwire_self_test::synthetic_has_member_*`) so a
  refactor that breaks any detector fails its own assertion rather
  than silently letting the negative one pass for the wrong reason.
  Tripwire deletes itself with `wallet2.cpp` at Phase 5 of the Rust
  rewrite. Architectural decision recorded in `docs/FOLLOWUPS.md`
  §"V3.1+ Legacy C++ → Rust rewrite scope". See
  `docs/audit_trail/2026-05-ffi-constant-drift-audit.md` Bug 4.

- **Cross-reference comment in
  `shekyl-crypto-pq::tests::generate_from_bip39_mainnet_roundtrips_to_rederive`.**
  Identifies the Rust test as the primary functional guarantee for
  BIP-39 wallet creation on Mainnet and points forward at the C++
  tripwire and the FOLLOWUPS architectural-decision entry. A future
  investigator asking "where is BIP-39 wallet creation tested?"
  finds the answer here, not in C++.

- **`docs/audit_trail/2026-05-ffi-constant-drift-audit.md` — one-page
  audit record.** Documents the wallet_storage failure trace, the
  Bug 1 / Bug 2 / Bug 3 / Bug 4 findings, the 43 constants confirmed
  aligned, and the prevention work pattern (per-PR equality
  assertions in this branch, reduced-scope generated header in the
  cbindgen sibling, full migration in V3.0). Audit-quality artifact
  for the August external review.

- **`AllKeysBlob` and `KeyImage` typed-wrapper sweep (between Stage 1
  PR 3 M3a and M3b; short-lived sweep branch off the M3a PR head per
  [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`](./design/STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3 "Landing notes (M3a closed)").** Closes the deferred-from-M3a
  typed-wrapper migration that the M3a `ViewSecret` work pre-announced
  in `shekyl-crypto-pq::keys`'s "near-term workstream" docstring.
  Three new newtypes plus two API extensions, no consensus or wire
  format changes (every wrapper is `#[repr(transparent)]`; serde
  formats use `#[serde(transparent)]`).

  **`shekyl-crypto-pq::keys` newtypes:**
  - **`SpendSecret`** — secret-bearing scalar mirroring `ViewSecret`'s
    discipline exactly: `#[repr(transparent)]`, `Clone + Zeroize +
    ZeroizeOnDrop`, no `Copy`, no `Debug`, `pub(crate) fn from_bytes`,
    `as_canonical_bytes()` accessor for raw-byte consumers at the
    boundary.
  - **`SpendPublicKey` / `ViewPublicKey`** — public-key identity
    values: `Copy + PartialEq + Eq + Hash + PartialOrd + Ord +
    Zeroize` for use as registry keys (`LocalKeys`'s
    `HashMap<SpendPublicKey, SubaddressIndex>` reverse-lookup
    registry); manual truncated `Debug` matching `KeyImage`'s
    privacy-correlation discipline (first two bytes only); `pub fn
    from_canonical_bytes` constructor — engine boundaries outside this
    crate (`shekyl-engine-core::engine::local_keys::derive_subaddress`)
    are legitimate construction sites, mirroring `KeyImage`'s pattern.
    No `ZeroizeOnDrop` because that conflicts with `Copy` (Rust trait
    coherence rule); the surrounding `AllKeysBlob::drop` clears these
    public fields explicitly via `.zeroize()` for the same uniform-
    write-pattern reason raw `[u8; 32]` fields had.

  **`AllKeysBlob` field migration:**
  - `spend_pk: [u8; 32]` → `spend_pk: SpendPublicKey`
  - `view_pk:  [u8; 32]` → `view_pk:  ViewPublicKey`
  - `spend_sk: [u8; 32]` → `spend_sk: SpendSecret`
  - `view_sk: ViewSecret` (already typed in M3a Commit 2; unchanged)

  The `Drop` implementation simplifies: `spend_sk` and `view_sk` now
  wipe via field-drop-glue (`ZeroizeOnDrop`), only public-key +
  composite fields remain in the manual zeroization block. The
  `#[repr(transparent)]` invariant continues to be asserted by
  `shekyl-ffi`'s `size_of::<...>()` test against
  `ShekylAllKeysBlob`.

  **`shekyl-crypto-pq::key_image::KeyImage` API extensions:**
  - Now derives `Zeroize`, `Serialize`, `Deserialize`, with
    `#[serde(transparent)]`. Wire format remains byte-identical to
    `[u8; 32]`.
  - `Zeroize` (without `ZeroizeOnDrop`, which would conflict with
    `Copy`) lets containers that hold a `KeyImage` alongside genuinely-
    secret material (`shekyl_engine_state::TransferDetails`,
    `shekyl_scanner::RecoveredWalletOutput`) wipe every field on
    `Drop` for uniform-write-pattern hygiene — the same `Copy +
    Zeroize` pairing the new public-key newtypes use. The manual
    `Debug` and absence-of-`Display` privacy discipline is unchanged.

  **`KeyImage` call-site sweep across the workspace:**
  - **`shekyl-engine-state::TransferDetails.key_image`:** `Option<[u8;
    32]>` → `Option<KeyImage>`. The on-disk and postcard-schema
    layouts are preserved by `KeyImage`'s `#[serde(transparent)]`.
    `TransferDetails::zeroize` continues to wipe the field; `Zeroize`
    on `KeyImage` removes the special-case `Option`-then-bytes
    accessor previously needed at the wipe site.
  - **`shekyl-engine-state::LedgerIndexes.key_images`:** `HashMap<[u8;
    32], usize>` → `HashMap<KeyImage, usize>`. Method signatures on
    `mark_spent`, `unmark_spent`, `detect_spends`, `set_key_image`,
    `freeze_by_key_image`, `thaw_by_key_image` updated to take
    `&KeyImage` / `KeyImage` / `&[KeyImage]`. The `[0u8; 32]` filter
    on rebuild/ingest is removed: the runtime-scanner path always
    produces a real key image, and `Option<KeyImage>` already encodes
    "not yet computed" — sentinel-byte gating was redundant in the
    on-disk path. (See FOLLOWUPS for the matching deferred promotion
    of `RecoveredWalletOutput.key_image` to `Option<KeyImage>` in
    V3.1.)
  - **`shekyl-scanner::RecoveredWalletOutput.key_image`:** `[u8; 32]`
    → `KeyImage` with `#[zeroize(skip)]`. The boundary in
    `ledger_ext.rs` retains a `[0u8; 32]` test-fixture filter so
    `RecoveredWalletOutput::new_for_test`'s zero placeholder maps to
    `td.key_image = None` (preserving the offline-derivation /
    `set_key_image` fill-in semantics view-only wallets rely on); a
    FOLLOWUPS V3.1 entry tracks promoting the field itself to
    `Option<KeyImage>` and deleting the boundary filter.
  - **`shekyl-engine-core::scan::KeyImageObserved.key_image`:** `[u8;
    32]` → `KeyImage`. Constructor sites in `refresh.rs`'s per-block
    input-walk wrap raw bytes via `KeyImage::from_canonical_bytes`.
  - **`shekyl-proofs::reserve_proof::{ReserveOutputEntry,
    VerifiedReserveOutput}.key_image`:** `[u8; 32]` → `KeyImage`. The
    192-byte per-output wire layout is unchanged — the proof's
    `write_per_output` consumes via `key_image.as_bytes()` and the
    verifier wraps the on-wire bytes back into `KeyImage` at the
    return boundary.
  - **`shekyl-engine-core::multisig::v31::prover::ProverInputProof.key_image`:**
    `[u8; 32]` → `KeyImage`. `signable_bytes()` consumes via
    `key_image.as_bytes()`; serde wire format unchanged.
  - **`shekyl-engine-core::multisig::v31::counter_proof::CounterProof.consumed_inputs`:**
    `Vec<[u8; 32]>` → `Vec<KeyImage>`; `CounterProofChainView::is_tracked_unspent`
    signature updated to take `&KeyImage`.
  - **`shekyl-engine-core::engine::traits::key::SubaddressKeyPair`:**
    `spend_pk` / `view_pk` typed as `SpendPublicKey` / `ViewPublicKey`.
  - **`shekyl-engine-rpc::handlers::parse_key_image`:** now returns
    `KeyImage` (constructor site at the wallet-RPC boundary).
  - All `[u8; 32]` test fixtures across `shekyl-engine-state`,
    `shekyl-engine-core` (including bench fixtures and adversarial
    multisig tests), and `shekyl-scanner` updated to construct
    `KeyImage::from_canonical_bytes(...)` explicitly.

  **Cascade closure (verify API + tests).** Final pass on the
  cascade — the public verifier surface and the last test-helper
  seams:
  - **`shekyl-fcmp::proof::verify`:** `key_images: &[[u8; 32]]` →
    `&[KeyImage]`. `pseudo_outs: &[[u8; 32]]` stays raw — pseudo-
    output commitments are a different concept, and the type-system
    protection is specifically for the key-image slot. The verifier
    consumes typed inputs via `.as_bytes()` exactly once at the
    point where the function downcasts to the upstream FCMP++
    library's byte-shaped API. New `shekyl-fcmp` regular dependency
    on `shekyl-crypto-pq` (cycle-free: `shekyl-crypto-pq` references
    `shekyl-fcmp` only as a `[dev-dependencies]` entry). The type is
    re-exported as `pub use shekyl_crypto_pq::key_image::KeyImage`
    from `shekyl-fcmp::proof` so callers (fuzz harnesses) can name
    it without taking a direct dep.
  - **`shekyl-ffi::lib`'s `shekyl_fcmp_verify` marshaling:** rebuilds
    `Vec<KeyImage>` via `KeyImage::from_canonical_bytes` from the
    C-supplied `*const u8` buffer; `pseudo_outs` marshaling is
    unchanged.
  - **`shekyl-fcmp` fuzz targets** (`fuzz_tx_deserialize_fcmp_type7`,
    `fuzz_fcmp_proof_deserialize`) updated their key-image
    generators to `Vec<KeyImage>` since they call `verify` directly.
  - **`shekyl-engine-core::engine::refresh::tests::make_block_with_spending_tx`:**
    `key_image: [u8; 32]` → `key_image: KeyImage`; the typed value
    is unwrapped via `.as_bytes()` exactly once at the
    `Input::ToKey { key_image: CompressedPoint(...) }` construction
    site (the on-wire `CompressedPoint` is the raw-byte boundary).
  - **`shekyl-ffi/tests/signing_round_trip::ScannedSecrets.key_image`:**
    intentionally remains `[u8; 32]`. This is a C-ABI scratch
    buffer: `shekyl_scan_and_recover` writes via
    `key_image.as_mut_ptr()` and the bytes are re-handed to a later
    FFI call via `.as_ptr()`. The C ABI is the authoritative raw-
    byte boundary on both sides; wrapping in `KeyImage` here would
    inject `from_canonical_bytes` / `as_bytes` shuffles at every
    seam without adding type protection. A doc-comment on the
    struct records the rationale.

  **Property-delivery framing.** This sweep is structural — no
  consensus rule, no wire format, no FFI layout changes. The
  type-system protection is the deliverable: every secret-bearing
  32-byte field and every per-output `KeyImage` field now refuses
  accidental cross-wiring through Rust's nominal type system, which
  is what M3d's "secrets confined to engine" property is later
  going to lean on. M3a alone landed `ViewSecret` and the
  `KeyEngine` trait; this sweep extends the typed-wrapper coverage
  to every remaining call site so M3b–M3e don't have to revisit
  the same surface.

- **Monero-reference rename for Shekyl-genesis primitives (sweep
  branch follow-on; analogous to M3a Commit 5's `classical-Monero`
  → `classical Edwards-curve` rename per `60-no-monero-legacy.mdc`).**
  Three call sites in Shekyl-first crates framed Shekyl-genesis-locked
  primitives as Monero-side artifacts; reframed to put Shekyl
  primary, with the upstream/CryptoNote provenance noted as
  context rather than ownership.

  - `rust/shekyl-ffi/Cargo.toml` description: `"FFI bridge between
    C++ Monero core and Rust modules"` → `"FFI bridge between
    Shekyl's C++ core and Shekyl's Rust crates"`. The C++ daemon is
    Shekyl's (forked-and-renamed); the FFI does not bridge to
    upstream Monero.
  - `rust/shekyl-crypto-pq/src/derivation.rs` test-helper varint
    comment: `// Monero varint encoding` → "Shekyl wire varint
    (7-bit continuation, CryptoNote-style; same shape as upstream
    Monero's varint, but Shekyl-genesis-locked)". The varint format
    is the standard 7-bit-continuation shape inherited from
    CryptoNote, not a Monero-specific construct.
  - `rust/shekyl-crypto-hash/src/lib.rs` module doc-comment:
    `Keccak-256 hashing matching Monero/Shekyl's cn_fast_hash` →
    `Keccak-256 hashing for Shekyl's cn_fast_hash primitive
    (byte-identical to upstream Monero's; that compatibility is
    incidental to the genesis-locked Shekyl spec, not a
    Monero-compatibility requirement)`.

  Out of scope: legitimate provenance pointers (`monero-oxide`'s
  `hash_to_point`, fork-attribution license headers in
  `shekyl-scanner`, "Monero mainnet" empirical comparisons,
  `60-no-monero-legacy.mdc` exclusion notices documenting what
  Shekyl deliberately rejects from Monero) are preserved as-is —
  those describe the fork relationship correctly. The earlier
  M3a Commit 5 sweep cleared the design-doc misframings; this
  pass closes the remaining Rust-side residue.

- **`KeyEngine` trait surface and `LocalKeys` in-process implementor
  introduced (Stage 1 PR 3 — M3a; the third trait-boundaries PR per
  [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.3).** The M3a slice of the five-PR Stage-1 PR 3 migration
  (M3a–M3e per
  [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`](./design/STAGE_1_PR_3_MIGRATION_PLAN.md)
  §3) lands as `pub(crate)` on `shekyl-engine-core`. M3a is the
  architectural foundation against which the "secrets confined to
  engine" structural property activates at M3d's merge; M3a itself
  delivers no user-visible behavior change. The trait owns
  `AllKeysBlob` privately and exposes a workflow-shape surface
  (no per-output secret material crosses the trait boundary).

  - **`pub(crate) trait KeyEngine`** in
    [`engine::traits::key`](../rust/shekyl-engine-core/src/engine/traits/key.rs).
    Four workflow-shaped methods per
    [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
    §4: `account_public_address(&self) -> &AccountPublicAddress`
    (sync borrowed read); `derive_subaddress(&self, idx,
    purpose) -> Result<SubaddressFor, Self::Error>` (sync, two
    purposes — `Audit` returns the classical Edwards-curve
    `(spend_pk, view_pk)` pair, `Recipient` returns the encoded
    address + hybrid KEM PK pair); `try_claim_output(&self,
    input) -> impl Future<Output = Result<OutputClaimResult,
    Self::Error>> + Send` (async; bundles X25519 view-tag
    pre-filter, hybrid decap, HKDF chain, key-image computation,
    deterministic `OutputHandle` derivation behind a single trait
    boundary); `sign_transaction(&self, tx) -> impl
    Future<Output = Result<TxSignatures, Self::Error>> + Send`
    (async; resolves per-input handles to per-output spending
    material and produces hybrid signatures + FCMP++ witnesses).
    The associated `type Error: Into<KeyEngineError>` lets
    orchestration code propagate uniform errors regardless of
    implementor.
  - **`pub(crate) struct LocalKeys`** in
    [`engine::local_keys`](../rust/shekyl-engine-core/src/engine/local_keys.rs).
    Owns `AllKeysBlob` privately; caches `AccountPublicAddress`
    and pre-computes `(view_scalar, spend_public)` cryptographic
    forms at construction; guards a reverse-lookup subaddress
    registry under `RwLock` (the `LocalLedger` precedent for
    `&self` async with synchronous interior mutation). Real
    implementations of `account_public_address`,
    `derive_subaddress(_, Audit)`, and `try_claim_output`;
    named-infrastructure-gap stubs for
    `derive_subaddress(_, Recipient)` and `sign_transaction`.
    Constructors: `from_keys_blob(keys, network)` (production)
    and `#[cfg(test)] from_test_seed(seed)` (raw32 testnet
    derivation for unit/integration fixtures); 11 tests cover
    cached-address stability, audit-derivation determinism,
    recipient-stub validation, claim happy path, deterministic-
    handle property, varying `tx_hash`, other-wallet rejection,
    unregistered-subaddress rejection, register-then-claim
    sequence, and `sign_transaction` stub validation.
  - **Two named-infrastructure-gap `KeyEngineError` variants:**
    `RecipientSubaddressKemKeygenNotImplemented` (per-subaddress
    hybrid X25519+ML-KEM-768 keygen,
    `shekyl_crypto_pq::subaddress::derive_subaddress_kem_keypair`,
    is unbuilt; lands per
    [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
    §6.4 / §3.1.3) and `SignTransactionTraitSurfaceIncomplete`
    (`TxToSign`'s public-on-chain per-input data and FCMP++
    tree-branch context are PR-5-pinned forward-declared; the
    bridge to `shekyl_tx_builder::sign_transaction` lands when
    the `PendingTxEngine` PR finalizes the shape). Both variants
    are `#[non_exhaustive]`-shaped accretions; existing call
    sites stay source-compatible as the surface evolves.
  - **`OutputHandle` newtype + `derive_output_handle`** in
    [`shekyl_crypto_pq::handle`](../rust/shekyl-crypto-pq/src/handle.rs).
    16-byte opaque reference deterministically derived via
    cSHAKE256 over `view_secret || tx_hash || output_index_le8`
    with customization `"shekyl/output-handle-v1"` per
    [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](./design/STAGE_1_PR_3_KEY_ENGINE.md)
    §7.12. The deterministic-handle pathway (Round 4 pre-flight
    closure of §7.11=(3)) replaces the originally-considered
    cached `HandleTable` data structure: re-derivation at spend
    time is cheap (one cSHAKE256 invocation) and dissolves the
    A6 (memory pressure) and Pattern-5 (concurrent-access)
    Round-3 attack-surface clusters by construction. Reference
    vectors locked in the module's test substrate.
  - **`KeyImage` newtype** in
    [`shekyl_crypto_pq::key_image`](../rust/shekyl-crypto-pq/src/key_image.rs).
    32-byte canonical compressed Ed25519 encoding of `I = x ·
    H_p(O)`; the per-output public on-chain double-spend
    identifier. Carries the same privacy-correlation discipline
    as `OutputHandle` (truncated `Debug` exposing the first two
    bytes only; no `Display`; no `Zeroize` because key images are
    publicly derivable from on-chain data). Per
    [`.cursor/rules/18-type-placement.mdc`](../.cursor/rules/18-type-placement.mdc),
    `KeyImage` is **transform-shaped** — defined by its
    derivation function — so it lives with the function rather
    than with any state-shaped consumer that happens to store it.
  - **`ViewSecret` newtype** in
    [`shekyl_crypto_pq::keys`](../rust/shekyl-crypto-pq/src/keys.rs).
    `#[repr(transparent)]` 32-byte wrapper preserving the
    bit-for-bit FFI layout invariant with
    `shekyl_ffi::ShekylAllKeysBlob.view_sk: [u8; 32]`. Manual
    truncated `Debug`; structural `ZeroizeOnDrop`. Wraps
    `AllKeysBlob::view_sk`; downstream call sites consume the
    canonical bytes via `.as_canonical_bytes()`. The remaining
    `AllKeysBlob` typed-wrapper migration (`spend_sk` →
    `SpendSecret`, `view_pk` → `ViewPublicKey`, `spend_pk` →
    `SpendPublicKey`) lands as a separate short-lived branch
    between M3a and M3b.
  - **Subaddress derivation primitives relocated to
    [`shekyl_crypto_pq::subaddress`](../rust/shekyl-crypto-pq/src/subaddress.rs).**
    Classical Edwards-curve `subaddress_derivation_scalar` and
    `subaddress_keys` (formerly methods on
    `shekyl_scanner::ViewPair`) move to a dedicated module per the
    path-stateless discipline (extension to the stateless-actor
    framing): paths from trait surface to cryptographic primitive
    must be stateless end-to-end, not just at their endpoints.
    The module is positioned to also house the future
    `derive_subaddress_kem_keypair` (per-subaddress hybrid X25519
    + ML-KEM-768 keygen, §6.4) when its infrastructure lands —
    the canonical home for **all** Shekyl subaddress derivation.
    `ViewPair::subaddress_keys` is preserved as a thin call-
    through; `ViewPair::subaddress_derivation` was deleted (no
    live caller after the relocation, per
    [`.cursor/rules/15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)).
    `SubaddressIndex::to_canonical_bytes` accessor and the
    `PRIMARY` constant added to
    [`shekyl_engine_state::SubaddressIndex`](../rust/shekyl-engine-state/src/subaddress.rs)
    per
    [`.cursor/rules/18-type-placement.mdc`](../.cursor/rules/18-type-placement.mdc):
    state-shaped types whose serialization is cryptographically
    load-bearing carry a single canonical-bytes accessor at the
    type definition; the cryptographic functions take pre-converted
    bytes rather than the typed index.
  - **`SourceSecretsBundle` transitional contract type** in
    [`engine::traits::key`](../rust/shekyl-engine-core/src/engine/traits/key.rs).
    Documents the per-input secret material
    `KeyEngine::sign_transaction` needs — `(spend_key_x,
    spend_key_y, commitment_mask, combined_ss, output_index)`,
    each `Zeroizing`-wrapped — independent of where the secrets
    originate. The bundle's *shape* is stable across the migration
    (M3a populates from `TransferDetails`'s legacy fields; M3b+
    derives internally from `(view_secret, source_ciphertext,
    output_index)`); only the *source* evolves. Localizing the
    M3b churn to bundle-population sites (rather than across the
    trait surface and every implementor) is the load-bearing
    property of this transitional field.

  Property-delivery framing: M3a alone does not activate the
  "secrets confined to engine" property — `TransferDetails`
  still carries its 5 secret-bearing fields, and the bridge
  reads from them transitionally. The property activates at
  M3d's merge per
  [`docs/design/STAGE_1_PR_3_MIGRATION_PLAN.md`](./design/STAGE_1_PR_3_MIGRATION_PLAN.md)
  §4.1, when those fields are deleted. M3a is what makes the
  activation possible: the `KeyEngine` trait is the boundary the
  property eventually attaches to, and the deterministic
  `OutputHandle` is the stateless-shape that replaces a per-call
  handle table by re-deriving spending material at spend time.

  Post-merge fix-ups against the M3a PR's review feedback (PR #32
  Copilot review, landed before merge):

  - **Redacted `Debug` on secret-bearing message shapes.**
    `SourceSecretsBundle`, `TxInputSigningContext`, and `TxToSign`
    each now carry a manual `Debug` impl (no `derive(Debug)`)
    redacting the four `Zeroizing<…>` secret fields under
    `[REDACTED]`. Per `35-secure-memory.mdc`, `Zeroizing<T>: Debug`
    delegates to `T: Debug`, so deriving `Debug` on a secret-bearing
    struct prints raw secret bytes through `tracing` fields, panic
    backtraces, or `dbg!()` calls. Three new sentinel-byte tests in
    `engine::traits::key::tests` pin the redaction.
  - **PRIMARY special-cased in `derive_subaddress(_, Audit)`.**
    The encoded primary address packs the wallet's *base* keys
    (`spend_pk = D`, `view_pk = a*G`) into `classical_address_bytes`
    directly, and the reverse-lookup registry pre-registers
    `keys.spend_pk` against `SubaddressIndex::PRIMARY`. The trait
    method previously routed `PRIMARY` through `subaddress_keys`,
    returning `(D + m_0*G, a*(D + m_0*G))` — a different point that
    matched neither the encoded address nor the registry. Special-
    casing `idx.is_primary()` to return the base account keys
    aligns the trait with the encoded address; for `idx >= 1`, the
    per-index derivation is unchanged. New
    `derive_subaddress_primary_audit_returns_base_account_keys`
    test pins the contract; docstrings on
    `shekyl_engine_state::SubaddressIndex`,
    `shekyl_crypto_pq::subaddress`, and the `subaddress_keys`
    primitive itself updated to spell out the special-case truth.
  - **Hard-coded pinned vector for `subaddress_derivation_scalar`.**
    The prior `derivation_scalar_pinned_vector` test re-ran the
    same `keccak256_to_scalar` primitive on both sides of the
    equality, so any drift inside that primitive flowed through
    both arms. Replaced with a true known-answer test (32-byte
    expected vector hard-coded for
    `(view = 0x0102_0304_0506_0708, idx = 1)`) plus a renamed
    formula-lock companion test that retains the prior coverage.
    The pair fails in different classes of regression and pins
    both the spec output bytes and the implementation composition.
  - **Type-placement rule corrected.** `.cursor/rules/18-type-placement.mdc`
    named `SubaddressIndex`'s home as `shekyl-engine-core` (twice);
    the type actually lives in `shekyl-engine-state`. Updated.

- **`LedgerEngine` trait extracted; `Engine<S, D>` parameterized
  over `L: LedgerEngine` with default `LocalLedger` (Stage 1 PR 2,
  the second trait-boundaries PR per
  [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.2).** The Phase 2a `LedgerEngine` slice of the Stage 1
  trait-extraction work lands as `pub(crate)` on
  `shekyl-engine-core`. The PR's primary surface — the
  `LedgerEngine` trait, the `LocalLedger` aggregate, and the
  `Engine<S, D, L>` / `OpenedEngine<S, D, L>` parameterization.
  The new type parameters carry default arguments (`D =
  DaemonClient, L = LocalLedger`) so non-test consumers continue
  to name `Engine<S>` / `OpenedEngine<S>` exactly as before; the
  default-argument shape preserves the *names* of the public
  types, not every method signature underneath them. The one
  observable public-API signature change is `Engine::ledger()`,
  which now returns `LedgerReadGuard<'_>` (a wrapper around
  `RwLockReadGuard<'_, LedgerState>`) instead of `&WalletLedger`;
  `LedgerReadGuard` derefs to `WalletLedger`, so call-style read
  access (`engine.ledger().balance()`, etc.) is
  source-compatible. Code that named the previous return type
  explicitly (`let r: &WalletLedger = engine.ledger();`) or
  stored the method as a function item must update — see the
  `Engine::ledger()` doc-comment in
  [`rust/shekyl-engine-core/src/engine/mod.rs`](../rust/shekyl-engine-core/src/engine/mod.rs)
  for the explicit upgrade path.
  The PR's lifecycle threaded three pre-flight doc-only spec
  amendments (PRs #22, #23, #25) before the implementation work
  began — see
  [`docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md`](./design/STAGE_1_PR_2_LEDGER_ENGINE.md)
  §1.1 / §2.2 for the discipline pattern.

  - **`pub(crate) trait LedgerEngine`** in
    [`engine::traits::ledger`](../rust/shekyl-engine-core/src/engine/traits/ledger.rs).
    Post-Phase-0c four-method surface: `synced_height(&self) ->
    u64`, `snapshot(&self) -> LedgerSnapshot`, `balance(&self) ->
    BalanceSummary` (sync, infallible reads), and
    `apply_scan_result(&self, ScanResult) -> Result<(),
    RefreshError>` (async, mutating; signals
    `RefreshError::ConcurrentMutation` for the §5.2 retry
    contract). The async `&self` mutation is enabled by interior
    `RwLock<LedgerState>` per §2.2's Round 3 disposition; this is
    the Stage-4-correct call shape, landed Stage-1-early so the
    actor cutover becomes a no-op for this concern. `LedgerError`
    is reserved as an empty starter type for Phase-2a-specific
    error variants the trait does not currently emit.
  - **`pub struct LocalLedger { state: RwLock<LedgerState> }`** in
    [`engine::local_ledger`](../rust/shekyl-engine-core/src/engine/local_ledger.rs).
    `LedgerState` bundles `WalletLedger` + `LedgerIndexes` (the
    two fields previously held flat on `Engine`); reservations
    stay on `Engine` for now and migrate to `LocalPendingTx` when
    the `PendingTxEngine` PR ships. The aggregate is `pub` (not
    the originally-planned `pub(crate)`) because Rust requires
    every default type parameter on a `pub` type to be at least as
    visible as the type itself; the trait `LedgerEngine` itself
    stays `pub(crate)` per §1.4 of the contract. See
    [`docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md`](./design/STAGE_1_PR_2_LEDGER_ENGINE.md)
    §3.4 for the visibility-lift rationale.
  - **`Engine<S, D: DaemonEngine = DaemonClient, L: LedgerEngine
    = LocalLedger>`** and **`OpenedEngine<S, D, L>`**. The ledger
    component becomes a third generic parameter with a default
    that preserves the existing concrete-typed shape for
    production callers, while making the ledger surface
    substitutable for hybrid tests. The trait-dispatch shape
    monomorphizes away as expected, but the parameterization
    intentionally pairs with the `LocalLedger` interior-mutability
    refactor below; the measured iai-callgrind cost of the
    combined change on `engine_trait_bench_ledger_synced_height`
    is `+390%` (10 → 49 instructions, sourced entirely from the
    `RwLock::read()` acquisition in `LocalLedger::read()`, not
    from trait dispatch). Per the
    [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
    §3.3.1 disposition (a) — intrinsic to Stage 1's interior-
    mutability shape and retiring at Stage 4 when Path B replaces
    `RwLock<LedgerState>` with `Arc`-published snapshots for read
    paths — the cumulative-delta breach is acknowledged as
    structural rather than as a regression to optimize within
    PR 2; full reasoning in
    [`docs/PERFORMANCE_BASELINE.md`](./PERFORMANCE_BASELINE.md)'s
    `engine_trait_bench_ledger_synced_height` cumulative-delta
    footnote. Each `pub` item bounded by the `pub(crate)`
    `LedgerEngine` trait carries an `#[allow(private_bounds)]`
    annotation paralleling the `DaemonEngine` annotations from
    PR 1; both clear at Stage 4 when both traits promote to `pub`
    per §1.4.
  - **Refresh path migrated to `&self` interior mutation.**
    `Engine::synced_height` now dispatches through
    `LedgerEngine::synced_height`; `Engine::apply_scan_result`,
    `Engine::refresh`, and `Engine::refresh_with` flip from
    `&mut self` to `&self`; the producer task `run_refresh_task`'s
    outer `Arc<RwLock<Engine>>` write-lock guard becomes a
    read-lock per the §3.3 over-serialization framing. The
    synchronous wrappers `refresh` / `refresh_with` retain their
    `LocalLedger`-specialized impl block because the trait method
    `apply_scan_result` is `async fn` and the sync entry points
    use `LocalLedger::write()` directly without a Tokio runtime
    in scope (queued at V3.x in
    [`docs/FOLLOWUPS.md`](./FOLLOWUPS.md) for full sync-wrapper
    generalization). `Engine::start_refresh` and
    `run_refresh_task` *are* generalized over `L: LedgerEngine`,
    sufficient for the hybrid retry test to dispatch through the
    trait against `MockLedger`.
  - **`MockLedger` deterministic in-memory `LedgerEngine`
    implementor** in
    [`engine::test_support`](../rust/shekyl-engine-core/src/engine/test_support.rs).
    Holds `WalletLedger` + `LedgerIndexes` + a queued-failure
    pump (`ConcurrentMutation`) + a `ChaCha20Rng` reserved for
    future RNG-driven fixtures. Constructors mirror PR 1's
    `MockDaemon`: `with_seed(master, ROLE_LEDGER)`,
    `with_seed_and_state`, plus a `queue_concurrent_mutation`
    helper for failure injection. `ROLE_LEDGER` was reserved in
    PR 1's `test_support.rs` and is now consumed.
  - **`Engine::replace_ledger<L2: LedgerEngine>(self, ledger: L2)
    -> Engine<S, D, L2>`** mirrors `Engine::replace_daemon` from
    PR 1. `#[cfg(test)] pub(crate)` for now; retires alongside the
    Stage 4 trait-promotion / production-constructor
    generalization at V3.2 per the
    [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
    §1.2 row.
  - **Hybrid retry test
    `hybrid_apply_scan_result_retries_on_concurrent_mutation`** —
    end-to-end coverage of the §5.2 retry contract via
    `MockLedger.queue_concurrent_mutation`. PR 1 covered the §5.2
    happy path (`hybrid_linear_scan_5_blocks_advances_synced_
    height`); PR 2 covers the failure-path retry contract; PR 3+
    pick up the remaining §5.2 properties under the
    "each per-trait PR exercises one §5.2 property predecessors
    have not yet covered" template pinned in
    [`docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md`](./design/STAGE_1_PR_2_LEDGER_ENGINE.md)
    §2.3.
  - **`engine_trait_bench_ledger_balance` criterion +
    iai-callgrind bench pair** under
    `rust/shekyl-engine-core/benches/`, gated on the existing
    `bench-internals` Cargo feature. Measures the
    `LedgerEngine::balance` trait method against a 1024-
    `TransferDetails` state-populated fixture
    (`LocalLedger::populate_for_bench` injects state through a
    `bench-internals`-only escape hatch; production state remains
    behind the trait-dispatched mutating path). The
    `engine_trait_bench_ledger_synced_height` pair from Stage 0
    PR-2 carries forward and gains a cumulative-delta row at the
    PR-tip SHA `8efae3a40` per §3.3.1 of the trait-boundaries
    spec. Frozen-baseline source, iai-callgrind gate metric,
    iai informational metrics, criterion metrics, and capture-
    environment cross-references for
    `engine_trait_bench_ledger_balance` (instructions=20580 on
    a 1024-`TransferDetails` fixture) are now transcribed into
    [`docs/PERFORMANCE_BASELINE.md`](./PERFORMANCE_BASELINE.md)
    from N=3-invariant CI `workflow_dispatch` runs `25307774464`,
    `25307777614`, `25307781436` against PR-tip `8efae3a40`,
    following the "do-not-transcribe-laptop-captures" discipline
    established during Stage 0 PR-2. The PR-tip SHA
    `8efae3a40` includes two preparatory script commits
    (`80d913ea2`: extend `BENCHES` row format to thread cargo
    `--features`; `8efae3a40`: append the balance bench row with
    `:bench-internals`) that landed after the design doc's nine-
    commit plan to surface the new bench to the rolling-baseline
    harness.

- **`DaemonEngine` trait extracted; `Engine<S>` parameterized over
  the daemon implementor (Stage 1 PR 1, the first
  trait-boundaries PR per
  [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
  §2.5).** The Phase 2a `DaemonEngine` slice of the Stage 1
  trait-extraction work lands as `pub(crate)` on
  `shekyl-engine-core`. The PR's primary surface — the
  `DaemonEngine` trait and the `Engine<S, D>` /
  `OpenedEngine<S, D>` parameterization — is `pub(crate)` and
  only visible to crate-internal callers; existing public types
  (`Engine`, `OpenedEngine`, `DaemonClient`, the lifecycle /
  refresh / pending re-exports in `lib.rs`) keep their existing
  shapes for non-test consumers via the `D = DaemonClient`
  default. The one externally-visible surface change is the
  removal of the previously-public `DaemonClient::inner()`
  accessor (called out under "Removed" below); cross-workspace
  audit found zero remaining callers, and the functionality is
  preserved via `DaemonClient`'s direct `Rpc` impl.

  - **`pub(crate) trait DaemonEngine: Rpc + Clone + Send + Sync +
    'static`** in
    [`engine::traits::daemon`](../rust/shekyl-engine-core/src/engine/traits/daemon.rs).
    `type Error: Into<IoError>`. Stage 1 surface per §2.5: two
    method signatures (`get_fee_estimates`,
    `submit_transaction`) defined as `impl Future` (the
    in-trait-async stable form) so the trait is dyn-incompatible
    by design and every consumer monomorphizes against a concrete
    `D`. Method bodies on `DaemonClient` are `todo!()` stubs
    pending Phase 2a fee-policy / submit-policy work; the trait
    surface is what's load-bearing for this PR.
  - **`#[non_exhaustive] FeeEstimates { economy, standard,
    priority: FeeRate }`** and **`#[non_exhaustive] enum
    TxSubmitOutcome { Submitted { hash }, AlreadyKnown { hash }
    }`** colocated with the trait. Both types are `pub(crate)`
    and grow additively; Phase 2a may extend `FeeEstimates` with
    `estimated_block_height` / `estimation_timestamp` etc. and
    `TxSubmitOutcome` with richer dedup context without breaking
    callers.
  - **`Engine<S, D: DaemonEngine = DaemonClient>` and
    `OpenedEngine<S, D: DaemonEngine = DaemonClient>`.** The
    daemon component becomes a generic parameter with a default
    that preserves the existing concrete-typed shape for
    production callers (`shekyl-cli`, `shekyl-engine-rpc`, the
    forthcoming Rust JSON-RPC server), while making the
    daemon-touching surface substitutable for hybrid tests. The
    parameterization compiles to identical code via monomorphization;
    expected iai-callgrind delta on
    `engine_trait_bench_ledger_synced_height` is 0% (10 → 10
    instructions) since the bench's call path doesn't observe
    the daemon parameter.
    Each `pub` item bounded by the `pub(crate)` `DaemonEngine`
    trait carries an `#[allow(private_bounds)]` annotation with a
    centralized rationale on the `Engine` struct definition; the
    annotations clear at Stage 4 when the trait promotes to `pub`
    per `V3_ENGINE_TRAIT_BOUNDARIES.md` §1.4.
  - **`DaemonClient` now implements `Rpc` directly** by
    delegating each method to its inner `SimpleRequestRpc`. The
    previous `DaemonClient::inner()` accessor is removed; in-tree
    callers (`engine::refresh::*`) bind against `DaemonEngine`
    or `Rpc` instead of reaching through to the wrapped
    transport. `From<RpcError> for IoError` lands in
    [`engine::error`](../rust/shekyl-engine-core/src/engine/error.rs)
    to satisfy `DaemonEngine::Error: Into<IoError>` for the
    `DaemonClient` impl.
  - **`MockDaemon` (renamed from `MockRpc`) extends to a full
    `DaemonEngine` implementor** in
    [`engine::test_support`](../rust/shekyl-engine-core/src/engine/test_support.rs).
    Adds `submit_transaction` deduplication by deterministic tx
    hash, `get_fee_estimates` returning a fixed snapshot
    (configurable via `set_fee_estimates`), fee-error queueing,
    submit-error queueing, and the `with_seed` /
    `with_seed_and_chain` constructors that carry a
    `ChaCha20Rng` reserved for future RNG-driven affordances per
    §6.2 (fee jitter, synthetic-fork randomization) — held but
    not yet consumed at this PR's contract surface.
    Failure-injection contract fidelity per §6.1 is exercised
    by a new test suite in the same module (deterministic
    submit hashing across clones, submit dedup behaviour,
    fee-snapshot-override persistence, queued-error drain
    semantics).
  - **`MockDaemon` chain-indexing convention now matches the
    real-daemon protocol** (`chain[0]` is genesis at height 0;
    `chain[h]` is the block at height `h`; `get_height` returns
    `chain.len()`). The previous off-by-one convention
    (`chain[i]` was the block at height `i + 1`) was a latent
    contradiction that surfaced as soon as a hybrid test
    composed `MockDaemon` with the production producer's range
    derivation. Aligning the conventions removes the
    bug-attractor; the existing `refresh_driver_tests` were
    re-arithmetic'd in the same commit so the test substrate has
    one convention going forward.
  - **`derive_seed(master: &[u8; 32], role: &[u8]) -> [u8; 32]`**
    in `engine::test_support` (HKDF-SHA256 per
    `V3_ENGINE_TRAIT_BOUNDARIES.md` §6.2). The first role tag
    `ROLE_DAEMON = b"role/daemon"` lands in this PR; per-trait
    roles join as their owning trait extracts. Pinned by a
    fixture-based unit test so accidental changes to the role
    tag or KDF construction surface as test failures.
  - **`#[cfg(test)] pub(crate) Engine::replace_daemon<D2>(self,
    daemon: D2) -> Engine<S, D2>`** in
    [`engine::lifecycle`](../rust/shekyl-engine-core/src/engine/lifecycle.rs).
    Move-rebuild helper for the §6.3 hybrid-construction
    discipline: real `Engine::create` with a dummy `DaemonClient`
    pays the lifecycle cost once (file lock, KDF, ledger init,
    refresh slot), then `replace_daemon(mock)` swaps in the
    `MockDaemon` for the measured region. Test-only visibility;
    cleanup target is V3.2 alongside the production-constructor
    generalization over `D: DaemonEngine` (documented at the
    method site).
  - **First end-to-end hybrid test under
    `start_refresh_integration_tests::hybrid_linear_scan_5_blocks_advances_synced_height`.**
    Wires `MockDaemon` as the engine's daemon component for a
    real `start_refresh` invocation (fresh wallet at
    `synced_height = 0`, six-block chain at heights 0..=5),
    asserting (a) the producer derives `processed_height_range
    == 1..6`, (b) `blocks_processed == 5` (post-genesis only),
    (c) post-refresh `synced_height() == 5`, (d) the refresh
    slot releases within 5s of `join().await` returning. This
    is the §5.2 retry-contract reachability proof — the slot
    release timing observation is the first coverage of the
    success-path lifecycle for the refresh slot (the existing
    `start_refresh_integration_tests` module exercises only the
    unreachable-daemon error path).
  - **Closes the FOLLOWUPS.md V3.1 row "Generic `DaemonClient`
    so `MockRpc` can drive `start_refresh`".** The row's
    close-condition (handle-layer end-to-end scenarios against
    a synthetic block batch via a substitutable daemon
    transport) is satisfied by the parameterization plus the
    hybrid test above.

  Performance gate per `V3_ENGINE_TRAIT_BOUNDARIES.md` §3.3.1:
  the `engine_trait_bench_ledger_synced_height` cumulative-delta
  row for this PR's tip is captured via GHA `workflow_dispatch`
  (N=3 invariance) and appended to
  [`docs/PERFORMANCE_BASELINE.md`](./PERFORMANCE_BASELINE.md) in
  a follow-up commit on this branch before merge per the
  "do-not-transcribe-laptop-captures" discipline established
  during Stage 0 PR-2.

### Removed

- **Chaingen-dependent C++ test surface (`tx_validation`,
  `fcmp_tests`, `staking`).** Test hygiene Δ1 (2026-05-05) deletes
  `tests/core_tests/{tx_validation,fcmp_tests,staking}.{cpp,h}`
  (~2200 lines, 32 registered tests + 7 already-disabled struct
  decls), the `chaingen_main.cpp` registrations, and the dead
  helpers `apply_fcmp_pipeline` / `construct_fcmp_tx` /
  `construct_fcmp_staked_tx` in `chaingen.cpp` (no callers remain
  after the test deletion). Root cause: the chaingen synthetic-block
  mining infrastructure (`MAKE_GENESIS_BLOCK`, `REWIND_BLOCKS_N`,
  `MAKE_NEXT_BLOCK`) produces v1 coinbase transactions that
  `cryptonote_format_utils.cpp:295` rejects under v3-from-genesis
  ("Shekyl requires tx version >= 3"); no chain ever materializes
  on the synthetic side, so `fill_tx_sources_and_destinations`
  returns no spendable outputs and every test that needs to construct
  a user transaction fails at chain setup. The CI baseline previously
  flagged 19 failures (cluster C); a full survey (this PR) confirmed
  the same root cause hits all 32 chaingen-dependent tests including
  `gen_fcmp_tx_valid`. The invariants those tests covered migrate to
  Rust per [`docs/FOLLOWUPS.md`](./FOLLOWUPS.md) — three target-V3.x
  entries (tx-validation, FCMP++ tx-pool, staking lifecycle), each
  landing with the corresponding Rust port of the daemon-side
  validation path. Per `.cursor/rules/20-rust-vs-cpp-policy.mdc`, tx
  validation defines a cryptographic contract → Rust. Per
  `.cursor/rules/15-deletion-and-debt.mdc` "default: delete," dead
  code goes; the V3.1 disposition that previously deferred this work
  to "wallet2 hardening / V3.2 wallet2 removal" is closed by this
  deletion. Closes
  [`docs/CI_BASELINE.md`](./CI_BASELINE.md) cluster C.

- **`DaemonClient::inner()` accessor** in
  [`engine::daemon`](../rust/shekyl-engine-core/src/engine/daemon.rs).
  The method exposed the wrapped `SimpleRequestRpc` so callers
  could invoke `Rpc` methods through it; with the Stage 1 PR 1
  parameterization, `DaemonClient` implements `Rpc` directly and
  the indirection is dead. Cross-workspace audit
  (`shekyl-core`, `shekyl-gui-wallet`, `shekyl-dev`, `shekyl-web`,
  `shekyl-mobile-wallet`, `monero-oxide`) found zero remaining
  callers; per `15-deletion-and-debt.mdc` "default: delete" and
  the no-`#[deprecated]`-without-deletion-target rule, the
  accessor is removed outright rather than retained as a
  deprecation shim.   Any downstream caller can replace
  `client.inner().get_height()` with `client.get_height()`
  (the `Rpc` supertrait is in scope wherever `DaemonClient` is)
  with no functional difference.

### Changed

- **Rust workspace clippy and rustfmt CI gates** in
  [`.github/workflows/build.yml`](../.github/workflows/build.yml)
  (`Rust: audit, test, determinism` job, immediately after `cargo
  audit`). Two gates added:

  - `cargo fmt --all -- --check` — fails CI on any unformatted
    Rust file across the 14-crate workspace.
  - `cargo clippy --workspace --all-targets --keep-going --
    -D warnings` — fails CI on any clippy finding of any
    severity. The workspace already configured many lints at
    deny-level via [`rust/Cargo.toml`](../rust/Cargo.toml)
    `[workspace.lints.clippy]` (`let_underscore_must_use`,
    `cast_possible_truncation`, `uninlined_format_args`, et al.);
    `-D warnings` extends enforcement to the default-warn lints
    (`clone_on_copy`, `type_complexity`, `dead_code`,
    `bound_in_more_than_one_place`, …).

  The pre-existing fmt and clippy debt was discharged in this PR's
  preceding commits before the gates were wired:

  - `cargo fmt --all` over 15 Rust files (mechanical
    import-sort and module-declaration reordering, zero behavior
    change).
  - 12 machine-applicable clippy auto-fixes (9 `clone_on_copy`
    deref + 3 `uninlined_format_args` inlines).
  - 19 `let_underscore_must_use` cures via destructuring
    assignment (`let _ = expr;` → `_ = expr;`) at best-effort
    channel-send and join-drain sites.
  - 7 substantive clippy findings cured with per-site rationale:
    bound consolidation in `run_refresh_task`, `usize::try_from`
    at the test-loop cast site, `RefreshHandleFixture` typedef,
    and per-item `#[allow(dead_code)]` on the Phase 2a-stub
    `DaemonEngine` trait surface.

- **`.cursor/rules/15-deletion-and-debt.mdc` "While we're here"
  carve-out.** New paragraph in the rule clarifying that the
  "while we're here is the enemy" prohibition does not preclude
  the disciplined practice of leaving files you are *already*
  editing for substantive reasons in fmt-clean and clippy-clean
  shape. The carve-out distinguishes:

  - Undisciplined "while we're here" creep (still prohibited):
    fixing arbitrary out-of-scope issues in unrelated files.
  - Disciplined "leave the file you touched in good shape" (now
    explicitly permitted): mechanical fmt/clippy cleanup *within
    the substantive-edit set* such that the post-PR file is
    fmt-clean and clippy-clean.

  The cleanup-PR pattern this project ran for Stage 1 PR 1's
  fmt-debt is now a one-time discharge, not a recurring practice.
  Going forward, every file your PR touches is fmt-clean and
  clippy-clean by the time the PR lands; mechanical findings in
  files your PR does not otherwise touch remain out-of-scope.

- **`docs/CONTRIBUTING.md` Rust style and lints section.** New
  section between "CI baseline" and "Branch protection on `dev`"
  documenting the two new gates, the workspace-vs-per-item-vs-
  module suppression hierarchy (`[workspace.lints.clippy] allow`
  in `rust/Cargo.toml` for project-wide misleading lints;
  `#[allow(lint_name)]` with one-line rationale comment for
  site-specific suppressions matching the existing project
  convention; module-level allows reserved for explicit
  reviewer sign-off), and the carve-out reference. The
  "Status checks must pass" bullet under "Branch protection on
  `dev`" was updated to enumerate the two new gates explicitly.

  Discipline reversal recorded for future readers: from this PR
  forward, the previous practice of noting "pre-existing fmt
  debt in <files> is unmodified per the deletion-and-debt rule"
  is no longer applicable. Fmt-clean is the gate, not a per-PR
  option to defer.

- **`Swatinem/rust-cache@v2` replaces `actions/cache@v5` in the
  `rust-audit-and-test` CI job** in
  [`.github/workflows/build.yml`](../.github/workflows/build.yml).
  The prior cache strategy had three documented waste modes
  measured against dev tip `1155c1abe`:

  - ~8m44s post-job cache UPLOAD on every run, regardless of
    whether the cache key changed (see
    [`docs/CI_TIMING_BASELINE.md`](./CI_TIMING_BASELINE.md)
    "Per-step breakdown"). `actions/cache@v5` re-uploads the
    full path set when the cache key differs from what was
    restored; `Swatinem/rust-cache@v2` writes deltas only.
  - No `rustc` version component in the cache key, so a
    toolchain bump (e.g. 1.94.0 → 1.95.0 as occurred mid-cycle
    on the `ubuntu-latest` runner) would have silently restored
    a 1.94-built `target/`. Swatinem's default key includes
    `rustc --version`.
  - No `~/.cargo/bin` caching, so `cargo install cargo-audit
    --locked` recompiled from source every run (~2m34s).
    Swatinem caches `~/.cargo/bin` by default; combined with
    `--locked` idempotency, the install becomes a few-second
    metadata check on cache hits.

  The `install cargo-audit` step also moved from pre-checkout
  (where the cache had no chance to populate `~/.cargo/bin`) to
  immediately after the Swatinem step, so the cache restore
  reaches it first.

  Measured impact (GHA run id `25265761303`,
  `chore/ci-cache-tightening` branch tip `911989b24`,
  toolchain 1.95.0; full breakdown in
  `docs/CI_TIMING_BASELINE.md`):

  - **Post-run cache UPLOAD**: 8m 44s before → **1m 30s cold**,
    **0s hot**. Structural; reliably reproduces every run.
  - **`install cargo-audit`**: 2m 34s before → **0s on hot-cache**.
    Structural; reliably reproduces every hot-cache run.
  - **Rust job total wall clock**: 48m 22s before (run
    `25263753443`, dev tip `1155c1abe`) → 37m 24s cold, 35m 57s
    hot. Headline numbers are noisy because `cargo test` swings
    ±~3m run-to-run independently of the cache (24m 20s cold vs
    27m 16s hot on the same SHA). The structural cache savings
    above are the durable component of the wall-clock delta.

  The PR scope is intentionally tight per the
  `tight_then_iterate` disposition (2026-05-02). APT package
  caching, extending Swatinem to the C++ build matrix's Rust
  half (`Ubuntu 22.04`, `Ubuntu 24.04`, `Arch Linux`), ccache
  effectiveness audits, and `cargo-binstall` migration are
  enumerated as deferred follow-ups in
  `docs/CI_TIMING_BASELINE.md` "Out of scope". Each of those is
  a >1 commit change with its own baseline-then-after capture
  cycle and lands as its own PR after the Swatinem deltas are
  observed and documented.

- **`docs/CI_TIMING_BASELINE.md` introduced** to record CI
  wall-clock per job per dev tip, anchored on the metric being
  recorded (job-level wall clock, not step durations) so deltas
  across caching changes are reproducibly comparable. The
  document captures the `chore/ci-cache-tightening` baseline
  before/after pair and is the going-forward home for similar
  captures (CI cache strategy changes, runner-image upgrades,
  toolchain bumps that affect compile time, etc.). Per
  `91-documentation-after-plans.mdc`, this file lives under
  `docs/` rather than scratch so future readers don't have to
  re-derive baselines from `gh run` logs.

### Fixed

- **CI Post Run cleanup no longer surfaces `##[error]ENOENT` on
  `rust/target/tests/target` for the `Rust: audit, test, determinism`
  job.** The `Swatinem/rust-cache@v2` post-run cleanup walker
  ([`src/cleanup.ts` `cleanProfileTarget`](https://github.com/Swatinem/rust-cache/blob/v2.7.5/src/cleanup.ts#L41-L51))
  treats any `target/` subdirectory named `tests` as a
  [`kaos`](https://github.com/vertexclique/kaos) /
  [`macrotest`](https://github.com/eupn/macrotest) /
  [`trybuild`](https://github.com/dtolnay/trybuild)
  nested-workspace layout and recursively cleans both
  `tests/target/` and `tests/trybuild/`. The recursive
  `cleanTargetDir` calls are not awaited, so async ENOENT
  rejections on missing paths escape the synchronous `try`/`catch`
  and surface as `##[error]ENOENT: opendir
  rust/target/tests/target` annotations in the run summary. The
  job concludes success (the action continues), but the
  annotation pollutes the run summary and obscures real errors.

  Why we hit it:
  [`rust/shekyl-logging/tests/trybuild.rs`](../rust/shekyl-logging/tests/trybuild.rs)
  uses `dtolnay/trybuild`, which creates
  `rust/target/tests/trybuild/`. We do not use `kaos`/`macrotest`,
  so `rust/target/tests/target/` never gets created — the walker
  tries it anyway. Confirmed against
  [Swatinem/rust-cache#144](https://github.com/Swatinem/rust-cache/issues/144)
  (open since 2023; the user-proposed
  `if (e.code === "ENOENT") continue;` patch never landed).

  Workaround: a defensive `mkdir -p rust/target/tests/target`
  step runs as the last pre-cleanup step in the job, ensuring the
  walker's `opendir` call succeeds and finds an empty directory
  to clean. Cache cost: a single empty directory entry,
  negligible. The new step's comment documents the upstream
  issue, the removal condition (delete the step in the same PR
  that bumps the action pin once Swatinem merges either the
  ENOENT-skip patch or adds `await` to the recursive
  `cleanTargetDir` calls), and the dependency chain
  (`shekyl-logging` `trybuild` test → `target/tests/trybuild/`
  → walker → `target/tests/target/` ENOENT). Files touched:
  [`.github/workflows/build.yml`](../.github/workflows/build.yml)
  in the `Rust: audit, test, determinism` job (one new step
  after `determinism check`).

- **Workspace clippy gate green on Rust toolchain 1.95.0.** Three
  newly-deny-able clippy 1.95 findings cured with mechanical,
  behavior-identical fixes after the toolchain on the
  `ubuntu-latest` GitHub Actions runner advanced past 1.94.0 (which
  is what the preceding `chore/workspace-fmt-clippy-baseline` PR
  was triaged against). Without this fix the
  `cargo clippy --workspace --all-targets --keep-going --
  -D warnings` gate added in that PR rejects every push to `dev`.

  - `clippy::useless_conversion` (×3 in vendored
    `rust/shekyl-oxide/`):
    `for (a, b) in xs.into_iter().zip(ys.into_iter())` →
    `for (a, b) in xs.into_iter().zip(ys)`. `Iterator::zip`
    accepts any `IntoIterator`, so the inner `.into_iter()` was
    redundant. Sites:
    - [`rust/shekyl-oxide/crypto/generalized-bulletproofs/src/inner_product.rs`](../rust/shekyl-oxide/crypto/generalized-bulletproofs/src/inner_product.rs)
      lines 216 and 220 (BP++ inner-product reduction
      `g_bold` / `h_bold` recursion).
    - [`rust/shekyl-oxide/shekyl-oxide/fcmp/bulletproofs/src/plus/weighted_inner_product.rs`](../rust/shekyl-oxide/shekyl-oxide/fcmp/bulletproofs/src/plus/weighted_inner_product.rs)
      line 380 (verifier folding loop over commitment pairs
      `(L_i, R_i)`).
  - `clippy::unnecessary_sort_by` (×2 in Shekyl-native
    `shekyl-scanner`):
    [`rust/shekyl-scanner/src/coin_select.rs`](../rust/shekyl-scanner/src/coin_select.rs)
    lines 114–115. Both calls sort descending by the second
    tuple element; rewrote to
    `sort_by_key(|b| std::cmp::Reverse(b.1))` per clippy's
    suggestion. Behavior-identical sort key, no change in
    coin-selection ordering.

  Vendored-divergence framing (in keeping with `10-shekyl-first.mdc`):
  the vendored copies under `rust/shekyl-oxide/` are already
  Shekyl-modified relative to the `monero-oxide` fork pin
  (`UPSTREAM_MONERO_OXIDE_COMMIT=3933664`, sync 2026-04-25); a
  prior commit (`44fe03453 chore: resolve all clippy warnings
  across the Rust workspace`) rewrote `inner_product.rs` with
  +360/-332 against upstream for clippy compliance under
  toolchain 1.94. There is no upstream fix to cherry-pick — the
  same pattern exists at the same lines in upstream
  (`monero-oxide` `crypto/generalized-bulletproofs/src/inner_product.rs:204,208`),
  last touched 2025-08-30, and would fail the same lint under
  clippy 1.95. This PR continues the precedent of treating
  `rust/shekyl-oxide/` as Shekyl-customized vendored code rather
  than a frozen mirror.

  Affected-crate test runs locally (release profile, toolchain
  1.95.0):

  | Crate | Tests passing |
  | --- | --- |
  | `generalized-bulletproofs` (with `--features tests`) | 5 / 5 |
  | `shekyl-bulletproofs` | 5 / 5 |
  | `shekyl-scanner` | 47 / 47 (1 ignored, pre-existing) |

  Local `cargo clippy --workspace --all-targets --keep-going --
  -D warnings` on toolchain 1.95.0 returns exit 0 after the fixes.

### Changed (BREAKING)

- **Wallet → Engine rename across Rust workspace** (decision log
  *"Wallet → Engine rename"*, 2026-04-27). Mechanical rename of the
  domain orchestrator type and its supporting crates and modules to
  consistently use "engine" terminology. The on-chain consensus rules
  and wire formats are unaffected; this is a source-only API churn.

  - **Crates renamed.** Workspace members and on-disk paths:
    `shekyl-wallet-core` → `shekyl-engine-core`,
    `shekyl-wallet-state` → `shekyl-engine-state`,
    `shekyl-wallet-file` → `shekyl-engine-file`,
    `shekyl-wallet-prefs` → `shekyl-engine-prefs`,
    `shekyl-wallet-rpc` → `shekyl-engine-rpc`. The `shekyl-cli`,
    `shekyl-ffi`, `shekyl-scanner`, `shekyl-tx-builder`,
    `shekyl-daemon-rpc`, `shekyl-fcmp`, `shekyl-crypto-pq`,
    `shekyl-proofs`, `shekyl-address`, `shekyl-shard-visual`, and the
    `monero-oxide` family (`shekyl-oxide`) are unchanged.
  - **Module renamed.**
    `shekyl-engine-core::wallet` → `shekyl-engine-core::engine`. The
    module re-exports retain their semantics through the new path.
  - **Types renamed.** Orchestrator-shaped types now use `Engine*`:
    `Wallet<S>` → `Engine<S>`, `WalletSignerKind` → `EngineSignerKind`,
    `WalletCoreError` → `EngineCoreError`,
    `OpenedWallet` → `OpenedEngine`,
    `WalletCreateParams` → `EngineCreateParams`. Domain-shaped types
    that name file format primitives or generic envelope concepts
    (`WalletFile`, `WalletLedger`, `WalletPrefs`, `WalletEnvelopeError`,
    `WalletOutput`) are intentionally retained — they describe a
    user's set of secrets, not the orchestrator.
  - **CLI surfaces.** `shekyl-cli` user-facing strings, help text,
    REPL prompts (`shekyl-cli [engine]>`), and command names
    (`engine_info` replaces `wallet_info`) now use "engine" terminology
    throughout per Option α. The `--wallet-dir` / `--wallet-file`
    flags are renamed to `--engine-dir` / `--engine-file`.
  - **Filesystem layout.** Default home directory subtree
    `~/.shekyl/wallets/` is renamed to `~/.shekyl/engines/`. The
    `.wallet` and `.wallet.keys` file extensions are retained so that
    existing tooling and the file format documentation in
    [`docs/WALLET_FILE_FORMAT_V1.md`](WALLET_FILE_FORMAT_V1.md) stay
    valid.
  - **What is *not* renamed in this release.**
    1. **FFI C ABI symbols.** `shekyl_wallet_*` `#[no_mangle]` exports
       and the `ShekylWallet` opaque-handle struct retain their names.
       The internal Rust types backing those handles are renamed; the
       C ABI is held stable until the C++ `wallet2.cpp` retirement
       work in V3.2 lets us cut both at once. See FOLLOWUPS V3.2.
    2. **C++ JSON-RPC method names.** `wallet_*` JSON-RPC method
       strings exposed by the C++ `shekyl-wallet-rpc.exe` binary are
       not renamed here. They are deleted, not aliased, when the
       Rust-native JSON-RPC server lands as part of Phase 4b's
       Shekyl-native RPC method-set work in V3.2. See FOLLOWUPS V3.2.
    3. **C++ binary names** (`shekyl-wallet-rpc`, `shekyl-wallet-cli`,
       `shekyl-wallet-bench`) and references to them in
       `.github/workflows/build.yml`, `scripts/bench/`, and stress-net
       harnesses. Tied to the same C++ retirement work.
  - **Migration guidance.** No on-disk migration code is shipped or
    needed pre-V3 launch (per `15-deletion-and-debt.mdc`). Pre-launch
    users re-sync from genesis. Tooling that depends on the renamed
    Rust crates updates `[dependencies]` paths and import paths in
    one mechanical pass; the FFI C ABI and JSON-RPC wire surfaces are
    intentionally unchanged.

### Added

- **`Engine::refresh` driver and `produce_scan_result` producer
  (Phase 2a `refresh_scan_loop` bundle, Branch 1).** The
  [`shekyl_engine_core::engine::refresh`](../rust/shekyl-engine-core/src/engine/refresh.rs)
  module ships the snapshot-merge-with-retry sync driver that
  replaces the standalone `shekyl-scanner::sync::run_sync_loop`.
  Public surface:

  - `Engine::refresh(&mut self, opts: &RefreshOptions, runtime:
    &tokio::runtime::Handle) -> Result<RefreshSummary, RefreshError>`
    — synchronous entry point on `Engine<S>`. Captures a
    `LedgerSnapshot` of the wallet's current `(synced_height,
    reorg_blocks)` under a brief read borrow, drops the borrow,
    drives the async producer on `runtime`, and merges the result
    back via `apply_scan_result_to_state` under `&mut self`. On
    `RefreshError::ConcurrentMutation` the snapshot is re-taken
    and the call retries up to `RefreshOptions::max_retries`.
  - `produce_scan_result(rpc, scanner, &LedgerSnapshot,
    height_range, cancel) -> Result<ScanResult, ProduceError>` —
    `pub(crate)` async producer that fetches blocks via the `Rpc`
    trait, scans them with `shekyl_scanner::Scanner`, detects
    reorgs by comparing `header.previous` against the snapshot's
    `reorg_blocks` (with a `find_fork_point` walk on mismatch),
    and returns a typed `ScanResult` envelope rather than mutating
    wallet state in place. Reorgs surface as
    `ScanResult::reorg_rewind: Some(_)`; the merge applies the
    rewind atomically before applying forward-progress events.
  - `LedgerSnapshot { synced_height: u64, reorg_blocks: ReorgBlocks
    }` — minimal read-only view of the pieces of
    `(LedgerBlock, LedgerIndexes)` the producer needs to detect
    reorgs and resume scanning. Cloned (not `Arc`-wrapped) per the
    snapshot benchmark in
    `rust/shekyl-engine-core/benches/refresh_snapshot.rs`, which
    measures clone cost across realistic reorg-window sizes so any
    future `Arc` switch has an empirical baseline.
  - `RefreshOptions { max_retries: u32 }` — caller-supplied knobs
    for the snapshot-merge retry loop. Default `8`; rationale on
    the bound is in the decision-log entry
    *"Snapshot-merge-with-retry semantics for `Wallet::refresh`"*
    (2026-04-26). `#[non_exhaustive]` so Branch 2 can add the
    cancel-token / progress-channel / batch-size knobs without a
    breaking change.
  - `RefreshSummary { processed_height_range, blocks_processed,
    transfers_detected, key_images_observed, stake_events,
    reorg: Option<RefreshReorgEvent>, merge_attempts }` —
    caller-visible result of a successful refresh.
    `#[non_exhaustive]`; `stake_events` is reserved for Phase 2b's
    richer event vocabulary and is always `0` today.
  - `RefreshError` — typed failure surface:
    `ConcurrentMutation { wallet, result }` (snapshot drifted under
    the producer; safe retry), `AlreadyRunning` (single-flight
    enforcement at the binary layer; reserved for Branch 2's
    handle path), `MalformedScanResult { reason }` (producer-bug
    signal: scan-result invariants violated; not a race),
    `Cancelled` (cooperative shutdown), `Io` (RPC failure surfaced
    from `ProduceError::MaxRetriesExhausted`). The variant set is
    `#[non_exhaustive]`.

  The driver is the snapshot-merge realization of the cross-cutting
  locking decision: queries take `&self`, mutations take
  `&mut self`, and refresh threads the long-running scan
  *between* borrow points so the wallet is never held across an
  `await`. The contract is locked in
  `docs/V3_WALLET_DECISION_LOG.md` *"`Wallet::refresh`
  snapshot-merge-with-retry"* (2026-04-26),
  *"`MalformedScanResult`: producer-bug signal vs.
  `ConcurrentMutation`"* (2026-04-26), and *"Retire
  `shekyl-scanner::sync::run_sync_loop` (Phase 2a/4b boundary)"*
  (2026-04-27).

  The `RefreshHandle` async surface (cancel-on-drop, watch-based
  `RefreshProgress`, `AlreadyRunning` enforcement, `start_refresh`
  spawning) lands in Branch 2 of the bundle (immediately below);
  this branch is the synchronous entry point and the producer /
  merge contract that the handle wraps.

  Test coverage lives in `rust/shekyl-engine-core/src/engine/refresh.rs`'s
  `mod tests` (producer-side: smoke / linear-scan / reorg-shallow /
  reorg-deep / reorg-at-tip / RPC-failure-fetch / RPC-failure-tip /
  scanner-failure / cancellation-mid-scan /
  cancellation-between-blocks / empty-range / range-validation;
  driver-side: round-trip, reorg-merge, retry-on-concurrent-mutation,
  retry-budget-exhausted, malformed-scan-result-bypass-retry,
  cancellation-end-to-end, no-progress-when-tip-equal,
  reorg-rewind-then-apply). The `MockRpc` test scaffold and
  `make_synthetic_block` helper live in
  `rust/shekyl-engine-core/src/engine/test_support.rs` for
  deterministic fault injection across producer and driver suites.

- **`Engine::start_refresh` async refresh handle (Phase 2a
  `refresh_scan_loop` bundle, Branch 2).** The
  [`shekyl_engine_core::engine::refresh`](../rust/shekyl-engine-core/src/engine/refresh.rs)
  module ships the cancel-on-drop / one-at-a-time / progress-
  channel handle that wraps the snapshot-merge driver from Branch
  1. The handle spawns the long-running scan onto a tokio runtime
  the caller does not have to manage, and threads cancellation
  and progress through typed channels. Public surface:

  - `Engine::start_refresh(self_arc: Arc<tokio::sync::RwLock<Self>>,
    opts: RefreshOptions) -> Result<RefreshHandle, RefreshError>` —
    async constructor on `Engine<S>`. Claims a `RefreshSlot` under
    a brief read borrow, spawns a producer task, and returns a
    handle observing the running task. A second call while a
    handle is alive returns `RefreshError::AlreadyRunning`. The
    `Arc<RwLock<Engine<S>>>` shape is the transitional shared-
    handle realization of the message-passing boundary decided in
    *2026-04-27 — Engine binary boundary: pure message-passing
    over shared handle*; the actor migration replaces the
    parameter without changing the handle's external surface.
  - `RefreshHandle` — RAII handle for the running refresh.
    Methods: `progress() -> watch::Receiver<RefreshProgress>`
    (clonable observer of phase / height / blocks-processed /
    blocks-total updates), `cancel()` (idempotent; fires the
    shared `CancellationToken`), `is_running() -> bool` (non-
    blocking poll of the producer's `JoinHandle::is_finished`),
    `async fn join(self) -> Result<RefreshSummary, RefreshError>`
    (push-completion via internal `oneshot`; consumes the handle).
    `Drop for RefreshHandle` is cancel-only — slot release lives
    on producer task exit, not on handle drop, so the cancel
    contract is `Drop`-scoped while the slot is self-healing
    across success / error / cancellation paths.
  - `RefreshProgress { height, blocks_processed, blocks_total,
    phase: RefreshPhase }` — `#[non_exhaustive]` snapshot
    delivered through a `tokio::sync::watch` channel. Per-attempt
    semantics: `blocks_total` is the per-retry total, not a
    cumulative running count. The watch channel is seeded by
    `Engine::start_refresh` with the wallet's current
    `synced_height` (and zeroed counters) so subscribers observe
    a baseline matching the wallet state before the producer
    publishes its first per-attempt update.
  - `RefreshPhase { Scanning, Merging, Retrying, Cancelled }` —
    coarse-grained producer state. `Scanning` covers fetch + scan
    of a per-block batch; `Merging` covers the brief write-locked
    `apply_scan_result` call; `Retrying` is published when the
    merge returned `ConcurrentMutation` and the loop is about to
    retake the snapshot; `Cancelled` is published before the
    handle's completion `oneshot` fires `Err(Cancelled)`.
  - `RefreshOptions` extended with no new fields in Branch 2;
    `max_retries` (Branch 1) is the only public knob.
    `#[non_exhaustive]` so future progress / batching knobs do
    not break call sites.
  - `RefreshError::AlreadyRunning` becomes load-bearing in this
    branch (Branch 1 reserved the variant); other variants
    propagate unchanged.

  Test coverage lives in three new modules:
  `mod refresh_handle_tests` (six unit tests pinning the handle's
  channel-shaped surface in isolation: progress baseline,
  progress propagation, cancel + is_running flip, join success,
  join error, dropped-sender → `MalformedScanResult`),
  `mod refresh_slot_tests` (four unit tests pinning single-flight
  semantics: claim-when-unheld, claim-fails-when-held, release-on-
  guard-drop, clone-shares-flag), and `mod start_refresh_integration_tests`
  (three integration tests against the real engine + unreachable-
  daemon: `start_refresh` propagates `IoError::Daemon` via `join`,
  concurrent `start_refresh` returns `AlreadyRunning`, drop
  releases the slot for a subsequent `start_refresh`). A
  `pub(crate) fn for_test(...)` constructor on `RefreshHandle`
  is the testability seam that lets the surface tests run without
  spinning up an `Engine<S>`.

  The decision-log scope-closing entry is *2026-04-27 —
  `RefreshHandle` (Phase 2a Branch 2) ships transitional
  `Arc<RwLock<Engine>>` under Path B*; the upstream handle-shape
  entry is *2026-04-25 — `RefreshHandle`: cancel-on-drop RAII,
  one-at-a-time, scanner checkpoints between blocks*. Wider
  scenario coverage of `start_refresh` against synthetic block
  batches lands when `DaemonClient` is generic (deferred outside
  Branch 2; tracked under V3.1 in `docs/FOLLOWUPS.md`).

- **`Engine::create` / `Engine::open_full` / `Engine::change_password` /
  `Engine::close` lifecycle methods on `shekyl-engine-core` (Phase 1
  `lifecycle` task).** The new
  [`shekyl_engine_core::engine::lifecycle`](../rust/shekyl-engine-core/src/engine/lifecycle.rs)
  module composes
  [`shekyl-engine-file`](../rust/shekyl-engine-file/src/),
  [`shekyl-crypto-pq::account::rederive_account`](../rust/shekyl-crypto-pq/src/account.rs),
  [`shekyl-engine-prefs`](../rust/shekyl-engine-prefs/src/),
  [`shekyl-engine-state::WalletLedger`](../rust/shekyl-engine-state/src/wallet_ledger.rs),
  and
  [`shekyl-engine-state::LedgerIndexes`](../rust/shekyl-engine-state/src/ledger_indexes.rs)
  into the `Engine<S>` orchestrator's open / create / rotate / close
  surface. Public API:

  - `Credentials<'a>` — forward-compatible authentication parameter.
    V3.0 has a private `password: &'a [u8]` field reachable through
    `Credentials::password_only(&[u8])` and `Credentials::password()`;
    V3.1 adds `authenticator: Option<AuthenticatorRequest<'a>>` and
    `Credentials::password_with_authenticator(pwd, auth)` without
    breaking existing call sites. See `docs/V3_WALLET_DECISION_LOG.md`
    *"Wallet authentication: V3.0 password-only; MFA is V3.1 via
    format-version bump"* (2026-04-26) for the API shape rationale.
  - `OpenedEngine<S>` typed-sum return for `open_full`.
    `Loaded(Engine<S>)` indicates the persisted ledger file decoded
    cleanly; `Restored { wallet, from_height }` indicates the keys
    file was intact but the ledger file was missing or unreadable —
    the wallet was reconstructed against an empty ledger anchored at
    `from_height = restore_height_hint` and the caller must drive a
    refresh to rebuild state. See `docs/V3_WALLET_DECISION_LOG.md`
    *"`Wallet::open_full`: lost-state surfacing via typed
    `OpenedWallet` sum"* (2026-04-26).
  - `EngineCreateParams<'a>` (9 public fields) and
    `CapabilityInput<'a>::Full { master_seed_64, seed_format }` for
    `Engine::create`. ViewOnly / HardwareOffload `CapabilityInput`
    variants are deferred alongside the matching `open_*` bodies;
    the FULL variant ships end-to-end. A `#[cfg(test)]
    EngineCreateParams::for_test_full(base_path, password,
    master_seed_64)` helper pins all eight non-essential fields to
    known-good defaults for unit-test fixtures; production callers
    (CLI / RPC) construct the struct literal so the field set is
    explicit at every call site.
  - `Engine::create(params) -> Result<Engine<SoloSigner>, OpenError>` —
    delegates to `WalletFile::create` with derived
    `DerivationNetwork` / `SeedFormat`, runs `rederive_account` to
    populate `AllKeysBlob`, cross-checks
    `blob.classical_address_bytes` against the envelope's
    `expected_classical_address` (failure → `KeyError::PublicBytesMismatch`),
    initializes `WalletLedger::empty()` and `LedgerIndexes::empty()`,
    persists initial prefs via `WalletFile::save_prefs`, and assembles
    the `Engine<SoloSigner>` instance.
  - `Engine::open_full(base_path, &credentials, network, daemon,
    overrides) -> Result<OpenedEngine<SoloSigner>, OpenError>` — opens
    the envelope (mapping `WalletEnvelopeError::InvalidPasswordOrCorrupt`
    to `OpenError::IncorrectPassword`,
    `RequiresMultisigSupport` to `OpenError::RequiresMultisig`, and
    capability / network mismatches to the corresponding typed
    variants), enforces FULL-only on this entry point
    (`OpenError::CapabilityMismatch` if the disk envelope is
    ViewOnly or HardwareOffload), runs the same rederive +
    public-bytes-cross-check sequence as `create`, surfaces tampered
    prefs as a structured `tracing::warn!` and falls back to defaults
    per `docs/WALLET_PREFS.md §5`'s advisory failure policy, rebuilds
    `LedgerIndexes` from the persisted `LedgerBlock`, and returns
    `Loaded` or `Restored { from_height }` based on the
    `WalletFile::open` outcome.
  - `Engine::open_view_only(...)` / `Engine::open_hardware_offload(...)`
    — signature-only stubs that return
    `OpenError::CapabilityNotYetImplemented { capability }` pending
    the matching `shekyl-crypto-pq` `AllKeysBlob` constructors. The
    error variant is deletion-tracked at the code site and in
    `docs/FOLLOWUPS.md` *V3.0 → "View/HW lifecycle bodies in
    `shekyl-engine-core`"*. See `docs/V3_WALLET_DECISION_LOG.md`
    *"`Wallet<S>` lifecycle: capability scoping for V3.0"* (2026-04-26)
    for the stub-shape rationale.
  - `Engine::change_password(&old, &new, new_kdf) -> Result<(), OpenError>`
    — delegates to `WalletFile::rotate_password`, mapping
    `WalletEnvelopeError::InvalidPasswordOrCorrupt` to
    `OpenError::IncorrectPassword`. Available on every signer kind
    (FULL / ViewOnly / HardwareOffload / multisig) since the
    underlying envelope rewrap is capability-agnostic.
  - `Engine::close(self, &credentials) -> Result<(), OpenError>` —
    refuses with `OpenError::OutstandingPendingTx { count }` when
    `outstanding_pending_txs() > 0` (drives cross-cutting lock 4's
    "no clean close while reservations are live" invariant).
    Otherwise saves state via `WalletFile::save_state`, saves prefs
    via `WalletFile::save_prefs`, and consumes `self`. The
    method's doc comment names the zeroization chain explicitly:
    `WalletFile::Drop` releases the advisory lock on `<base>.keys`;
    `AllKeysBlob::Drop` zeroizes `spend_sk` / `view_sk` /
    `ml_kem_dk` and the public-key fields. The chain is
    single-level (`Engine<S>.keys: AllKeysBlob` directly, no
    wrapper), and the underlying `Drop` semantics are tested in
    `shekyl-crypto-pq`'s own unit tests.

  Eleven unit tests cover the round-trip create / open path, password
  rotation followed by reopen-with-new-password and refusal of the
  old, `OpenError::IncorrectPassword`, `OpenError::NetworkMismatch`,
  the `Restored { from_height }` lost-state path (state file deleted
  between create and open), `OpenError::OutstandingPendingTx` (close
  refused while a synthetic reservation is in `Engine::reservations`),
  the structured `tracing::warn!` on prefs HMAC tamper events, and
  the typed `OpenError::CapabilityNotYetImplemented` returns from
  the view-only and hardware-offload stubs. The
  `apply_scan_result_post_open_works` lifecycle ↔ scan-result
  composition test is deferred to the Phase 2a `refresh` commit
  where it can exercise a real `ScanResult` against the lifecycle's
  `LedgerIndexes::rebuild_from_ledger` output.

  The lifecycle commit ships `tracing = "0.1"` as a runtime
  dependency on `shekyl-engine-core` (used for the prefs-tamper
  warn log only) and `tempfile = "3"` plus `tokio = { version = "1",
  features = ["macros", "rt"] }` as dev-dependencies (lifecycle
  tests construct on-disk fixtures and instantiate a
  `SimpleRequestRpc` against an unreachable URL for the dummy
  `DaemonClient`).

- **`Engine::build_pending_tx` / `submit_pending_tx` / `discard_pending_tx`
  three-method `PendingTx` lifecycle (Phase 1 `pending_tx` task).** The
  new
  [`shekyl_engine_core::engine::pending`](../rust/shekyl-engine-core/src/engine/pending.rs)
  module lands the runtime-only side of cross-cutting lock 4. Public
  surface:

  - `PendingTx { id, built_at_height, built_at_tip_hash, fee_atomic_units,
    tx_bytes, recipients }` — the chain-state-tagged handle returned by
    `build_pending_tx`. `tx_bytes` is `Vec::new()` in Phase 1 and is
    explicitly documented as Phase-2a's integration point for
    `shekyl-tx-builder`.
  - `TxRequest { recipients, priority, from_subaddress }`,
    `TxRecipient { address, amount_atomic_units }`,
    `FeePriority { Economy, Standard, Priority, Custom(NonZeroU64) }`,
    `TxRecipientSummary`, `ReservationId(u64)`, `TxHash([u8; 32])` —
    the strongly-typed input/handle/summary newtypes.
  - `Engine::build_pending_tx(&request) -> Result<PendingTx, SendError>` —
    selects largest-amount-first spendable outputs from
    `LedgerIndexes`/`LedgerBlock` (excluding outputs already reserved
    by another in-flight `PendingTx`), captures real chain state
    (`synced_height` + `block_hash_at(synced_height)`), bumps a
    monotonic `next_reservation_id`, and inserts a `Reservation` into
    `Engine::reservations`. Phase 1 uses a fixed
    `STUB_FEE_ATOMIC_UNITS = 1_000` stub fee; Phase 2a will replace
    it with a `daemon.get_fee_estimates()` call.
  - `Engine::submit_pending_tx(id) -> Result<TxHash, PendingTxError>` —
    runs the cross-cutting-lock-4 invariants
    (`PendingTxError::TooOld { built, current, max_reorg }` against
    `NetworkSafetyConstants::for_network(network).max_reorg_depth`,
    `PendingTxError::ChainStateChanged { height }` against the stored
    `built_at_tip_hash`, `PendingTxError::UnknownHandle` for unknown
    `id`s), and on success removes the reservation, marks each
    selected `TransferDetails` as `spent = true` with
    `spent_height = None` (the "unconfirmed-spent" Phase-1 state, made
    proper in Phase 2a once daemon broadcast confirmation arrives),
    and returns a stub `TxHash` whose first 8 bytes encode the
    `ReservationId`.
  - `Engine::discard_pending_tx(id) -> Result<(), PendingTxError>` —
    idempotent: returns `Ok(())` regardless of whether `id` is
    currently recognized, releases the reservation entry so the
    referenced outputs become selectable by a subsequent build.
  - `Engine::outstanding_pending_txs() -> usize` — count accessor used
    by `Engine::close` (lifecycle commit) to refuse closing while any
    reservation is active.

  Reservations live exclusively on `Engine<S>` as a runtime-only
  `BTreeMap<ReservationId, Reservation>` field alongside the
  existing runtime-only `indexes: LedgerIndexes`. They are not
  persisted in `WalletLedger.bookkeeping`; `BOOKKEEPING_BLOCK_VERSION`
  does not change. Process crash between build and submit/discard
  drops reservations along with the in-memory `PendingTx` handle —
  which is the correct behavior, since the tx never broadcast and the
  outputs are correctly spendable again on next open.

  The full lifecycle body is exposed as `pub(crate)`
  free helpers (`build_pending_tx_in_state`,
  `submit_pending_tx_in_state`, `discard_pending_tx_in_state`)
  operating on `(&LedgerBlock, &mut BTreeMap<ReservationId,
  Reservation>, ...)` so unit tests can drive the full lifecycle
  without standing up an `Engine<S>` (whose constructors land in the
  lifecycle commit). Twelve unit tests cover output reservation, the
  reserved-output filter, insufficient-funds, the no-block-yet
  `SendError::CannotSign`, all three `PendingTxError` paths, the
  spent-state mutation on submit, the rebuild-after-discard path,
  discard idempotency on unknown handles, and `FeePriority::Custom`
  preservation.

  See `docs/V3_WALLET_DECISION_LOG.md` *"Reservation tracker:
  runtime-only on `Wallet`, never persisted"* (2026-04-26 sub-section
  of the `Wallet<S>` struct entry) for the runtime-vs-persisted
  decision and the supersession of the original cross-cutting-lock-4
  draft phrasing.

- **`shekyl_engine_core::scan::ScanResult` typed scanner-output value
  and `Engine::apply_scan_result` merge surface (Phase 1 `scan_result`
  task).** A new
  [`shekyl_engine_core::scan`](../rust/shekyl-engine-core/src/scan.rs)
  module defines the additive event vocabulary the Phase 2a
  `Engine::refresh()` pipeline produces from a scanner pass:

  - `ScanResult { processed_height_range, parent_hash, block_hashes,
    new_transfers, spent_key_images, stake_events, reorg_rewind }`.
  - `DetectedTransfer { block_height, output: RecoveredWalletOutput }`
    — the secret-bearing variant; `RecoveredWalletOutput` already
    `ZeroizeOnDrop`, so dropping the enclosing `ScanResult` wipes
    PQC re-derivation material in place.
  - `KeyImageObserved { block_height, key_image }` — drives
    `LedgerIndexes::detect_spends` per height.
  - `StakeEvent::Accrual { height, record }`, `#[non_exhaustive]` so
    Phase 2b `StakeInstance` variants can land additively.
  - `ReorgRewind { fork_height }` — drives
    `LedgerIndexes::handle_reorg` before per-height events.
  - `ScanResult::empty_at(start, parent_hash)` for the
    nothing-changed-at-tip case and tests.

  The companion `Engine::apply_scan_result(&mut self, ScanResult) ->
  Result<(), RefreshError>` lives in
  [`engine::merge`](../rust/shekyl-engine-core/src/engine/merge.rs) and
  is the only audited code path that mutates the scanner-derived slice
  of `WalletLedger` plus `LedgerIndexes` during refresh. It enforces
  two snapshot-consistency invariants before applying any events,
  rejecting with `RefreshError::ConcurrentMutation` on either failure:

  1. **Start-height equality.** `processed_height_range.start` must
     equal `synced_height + 1` (or `fork_height` when `reorg_rewind`
     is present, since the rewind sets `synced_height` to
     `fork_height - 1` first).
  2. **Parent-hash chain.** `parent_hash` must match
     `LedgerBlock::block_hash_at(start - 1)`, with `None` matching
     `None` at genesis (`start == 1`).

  The merge runs in a fixed order: optional reorg rewind first, then
  per-height ingest (`process_scanned_outputs` + `detect_spends`)
  driven by `block_hashes` so `synced_height` advances exactly once
  per scanned block — even when the block had no events — then
  staker-pool aggregate events. `Engine<S>` now carries
  `indexes: LedgerIndexes` as a direct field so the merge can mutate
  both the persisted `LedgerBlock` (via `WalletLedger.ledger`) and
  the runtime indexes under a single `&mut self` borrow without
  needing an inner lock. The full merge body is exposed `pub(crate)`
  as `apply_scan_result_to_state(&mut LedgerBlock, &mut LedgerIndexes,
  ScanResult)` so tests can drive it without standing up a full
  `Engine<S>` (whose lifecycle methods land in a follow-up commit).

  See `docs/V3_WALLET_DECISION_LOG.md` *"`ScanResult` type"*
  (2026-04-25, **crate location: `shekyl-engine-core::scan`**) and
  *"`Wallet::apply_scan_result` invariants and Wallet-side
  `LedgerIndexes`"* (2026-04-26).

### Changed

- **`RuntimeWalletState` folded into `LedgerBlock` + `LedgerIndexes`
  (Phase 1 `runtime_state_audit` task).** The `RuntimeWalletState`
  type and the transitional `pub use ... as WalletState` re-export
  are deleted. Its responsibilities split along the persistence
  boundary:

  - **Persisted, on-disk state** — `transfers`, `synced_height`,
    `reorg_blocks`, claim watermarks — was already covered by
    `WalletLedger.ledger` (`LedgerBlock`). Read-only queries
    (`height`, `transfers`, `unspent_transfers`, `staked_outputs`,
    `matured_staked_outputs`, `locked_staked_outputs`,
    `claimable_outputs`, `unstakeable_outputs`, `spendable_outputs`,
    `block_hash_at`) and transfer-only mutators (`set_staking_info`,
    `update_claim_watermark`, `freeze`, `thaw`, `transfer_mut`) move
    to inherent methods on `LedgerBlock`.
  - **Runtime-only derived state** — the `key_images` and `pub_keys`
    lookup maps plus the `staker_pool` accrual aggregate — moves to
    a new `pub struct LedgerIndexes` in
    `rust/shekyl-engine-state/src/ledger_indexes.rs`. `LedgerIndexes`
    is **never serialized**, has no `Serialize` / `Deserialize`
    derives, and is rebuilt by scanner replay at every wallet open
    via `LedgerIndexes::rebuild_from_ledger`. Cross-cutting
    mutations (`ingest_block`, `mark_spent`, `unmark_spent`,
    `detect_spends`, `set_key_image`, `freeze_by_key_image`,
    `thaw_by_key_image`, `handle_reorg`, `insert_accrual`) take
    `&mut self, ledger: &mut LedgerBlock, …` so a single call
    updates ledger and indexes atomically. Invariant:
    `LedgerIndexes` is reconstructible from `LedgerBlock` plus
    daemon block replay; this is enforced by convention (struct
    doc-comment) rather than by the type system.

  Live wallet state behind a single mutex is the tuple
  `pub type LiveLedger = (LedgerBlock, LedgerIndexes)` in both
  `shekyl-engine-rpc::scanner_state` and the (cfg `rust-scanner`)
  `shekyl-scanner::sync` background loop. Scanner-specific behavior
  that needs `Timelocked` / `RecoveredWalletOutput` /
  `BalanceSummary` / `ClaimableInfo` lives in extension traits in
  `shekyl-scanner::ledger_ext` (`TransferDetailsExt`,
  `LedgerIndexesExt`, `LedgerBlockExt`); the canonical
  `shekyl-engine-state` crate stays scanner-free. The old
  `shekyl-scanner::runtime_ext` and `shekyl-scanner::wallet_state`
  modules are deleted.

  See `docs/V3_WALLET_DECISION_LOG.md` *"`RuntimeWalletState` audit:
  full fold, derived indexes rebuilt at open"* (2026-04-25); the
  same commit also corrects two errata in that entry: the persisted
  transfer path is `WalletLedger.ledger.transfers` (not
  `bookkeeping.transfers`), and `staker_pool`'s home on
  `LedgerIndexes` is now pinned explicitly.

### Documentation

- **Performance baseline document restructured for per-bench
  frozen baselines + §3.3.1 spec amendment + responsibility-
  allocation and toolchain-bump policies (Stage 0 PR-B).**
  [`docs/PERFORMANCE_BASELINE.md`](./PERFORMANCE_BASELINE.md) is
  rewritten from the Round 4b template stub into the per-bench
  frozen-baseline shape that
  [`docs/design/STAGE_0_HARNESS.md`](./design/STAGE_0_HARNESS.md)
  §4.5 operationalizes (one populated section for
  `engine_trait_bench_ledger_synced_height` frozen at Stage 0
  PR-2's merge SHA; four deferred-bench placeholder sections for
  `engine_trait_bench_ledger_balance`,
  `engine_trait_bench_economics_current_emission`,
  `engine_trait_bench_economics_parameters_snapshot`, and
  `engine_trait_bench_key_account_public_address`, each pinned to
  its introducing per-trait PR per §4.6's per-bench deferred
  assignment). The new document shape carries: per-bench
  frozen-baseline source (introducing PR + merge SHA), workload
  class (per §4.2 hoisting rule), iai-callgrind gate metric
  (`instructions`) isolated in its own table from the
  hardware-dependent informational rows (`l1_hits`, `ll_hits`,
  `ram_hits`, `total_read_write`, `estimated_cycles`), criterion
  metrics (`median_ns`, `std_dev_ns`) with hoisting-rule note,
  capture-environment cross-reference (`env-<short-SHA>`), and a
  cumulative-delta table with one row representing the introducing
  capture itself. The threshold-of-concern disposition is restated
  to apply per-bench (cumulative deltas do not sum across benches)
  and to the iai-instructions gate metric only (criterion
  `median_ns` is informational and does not gate). Two new policy
  sections close gaps surfaced during PR-B drafting:
  **responsibility allocation** pins that the PR which pushes
  cumulative delta past 10% (warn) or 25% (fail) is responsible
  for the breach regardless of its own per-PR contribution size
  (closes the slow-bleed failure mode where N PRs each at +9%
  cumulatively breach +25%); **toolchain-bump policy** pins that
  rustc / valgrind / iai-callgrind-runner version changes during
  Stage 1 trigger a per-bench rebaseline (re-capture each in-scope
  bench at its introducing PR's tree state under the new toolchain;
  reset the cumulative-delta column; CHANGELOG entry; the
  rebaseline commit is itself a non-Stage-1 change and does not
  count toward any bench's cumulative-delta column). A new in-tree
  reference capture
  ([`docs/benchmarks/reference-captures/stage-0-pr-2-c4c-shekyl_rust_v0.json`](./benchmarks/reference-captures/stage-0-pr-2-c4c-shekyl_rust_v0.json),
  with explanatory README) supports PR-B's review-surface
  verification gate against a stable in-tree artifact rather than
  a transient GHA artifact path.
  [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)
  §3.3.1 Component 1 is amended to match: replaces the
  single-SHA / "first Stage 1 PR" / "cumulative-is-sum" framing
  with per-bench introducing-PR-merge-SHA framing, per-bench
  cumulative-delta independence, and a §4.5 back-pointer for
  operational details. The amendment bundles with the
  `PERFORMANCE_BASELINE.md` rewrite per the bundling exception
  codified in §4.6 of the design doc (correction of existing
  wrong text, fully derived from already-merged design content,
  ~27 lines within an existing ~36-line component — above the
  ~15-line soft anchor but below the 50-line "structural rewrite"
  cutoff, with content qualifying as mechanical-derivation rather
  than re-framing per the codification's allowance). Numbers and
  in-tree iai-callgrind snapshot refresh are deferred to Stage 0
  PR-2 commit 5 per the framing-vs-numbers split.
  [`FOLLOWUPS.md`](./FOLLOWUPS.md) §"V3.0" gets two updates:
  the existing Stage 1 baseline-measurement row is rewritten to
  the per-bench framing (replacing the single-SHA / 30-day-tip
  language with the four-deferred-benches close-condition); a new
  row tracks the CHANGELOG-backfill discipline gap surfaced during
  PR-B (PR-A `3d313256c`, PR-A-extension `2e5309ad3`, and PR-C
  `93d515123` merged without `## [Unreleased] / ### Documentation`
  entries). The CHANGELOG-backfill row is targeted at V3.0 and can
  land any time before V3.0 cut.
- **`engine_trait_bench_ledger_synced_height` frozen baseline
  transcribed (Stage 0 PR-2 commit 5).** The validated CI capture
  values (iai `instructions=10`, hardware-dependent informational
  rows `l1_hits=16` / `ll_hits=0` / `ram_hits=2` /
  `total_read_write=18` / `estimated_cycles=86`, criterion
  `median_ns=0.6221` / `std_dev_ns=0.005864`) are recorded in
  [`docs/PERFORMANCE_BASELINE.md`](./PERFORMANCE_BASELINE.md) under
  the bench's frozen-baseline source, gate metric, informational
  metric, and cumulative-delta tables. The `env-0276d210` capture
  environment is populated with the toolchain (`rustc 1.95.0` /
  `cargo 1.95.0` / `valgrind-3.22.0` / `iai-callgrind-runner 0.16.1`)
  and runner state (`AMD EPYC 7763` / `Linux 6.17.0-1010-azure`)
  from the GHA `workflow_dispatch` run `25239954863`, one of the
  three N=3 invariance-verification captures (runs `25239954863`,
  `25239956447`, `25239958016`) that produced byte-identical
  iai-callgrind output (±0% variance on the gate metric per
  [`STAGE_0_HARNESS.md`](./design/STAGE_0_HARNESS.md) §4.4 dynamic
  check). The bench's "frozen at" SHA is the capture SHA
  `0276d210e` (PR-2 commit 4c, post-Q `Box<Engine<S>>` fixture);
  the in-tree
  [`reference-captures/stage-0-pr-2-c4c-shekyl_rust_v0.json`](./benchmarks/reference-captures/stage-0-pr-2-c4c-shekyl_rust_v0.json)
  remains the stable artifact citation. The four deferred bench
  sections (`balance`, `current_emission`, `parameters_snapshot`,
  `account_public_address`) are unchanged — each will be populated
  by its introducing per-trait PR per §4.6's per-bench deferred
  assignment. Closes Stage 0 PR-2's measurement work.
- **Stage 1 trait-boundaries spec, Round 1 draft
  ([`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`](./V3_ENGINE_TRAIT_BOUNDARIES.md)).**
  First draft of the Stage 1 design document called for by the
  decision-log entry *"Engine architecture: actor model with staged
  migration from composition"* (2026-04-27) and the
  `phase_2b_prep_stage_1_trait_boundaries` plan. Pins six trait
  surfaces (`KeyEngine`, `LedgerEngine`, `RefreshEngine`,
  `PendingTxEngine`, `DaemonEngine`, `PersistenceEngine`), the
  composition shape (`Engine<S, K, L, R, P, D, F>` with default type
  parameters; concrete fields, generic-bounded methods, no
  `Box<dyn>`), the per-trait async story, the per-trait error model
  (per-trait families with a single shared `EngineError` aggregate),
  the test boundary unlocked by `MockKeyEngine` /
  `MockDaemonEngine` / etc. (closes today's gap that there is no way
  to plug `MockRpc` into `start_refresh` end-to-end), the Stage 4
  transition guarantee (the trait surface in §2 does not change at
  Stage 4; `kameo` actors implement the same traits with the same
  signatures), the Stage 1 migration order (`DaemonEngine` first to
  unlock integration tests; `LedgerEngine` second; the other four
  in any reviewer-convenient order), and a consolidated 15-item
  open-questions list as the Round 2 agenda. **Markdown-only; no
  code changes.** Per
  [`.cursor/rules/20-rust-vs-cpp-policy.mdc`](../.cursor/rules/20-rust-vs-cpp-policy.mdc),
  the document runs through 4–6 review rounds against `dev` before
  any Rust lands. Round 1 draft only — open questions are written
  down with tentative answers, not closed.
- **Engine binary boundary pinned as pure message-passing
  (decision log *"Engine binary boundary: pure message-passing
  over shared handle"*, 2026-04-27).** The post-Stage-4 binary
  boundary in `shekyl-engine-rpc` is settled as
  `HashMap<EngineId, ActorRef<EngineActor>>`, not
  `Arc<RwLock<Engine>>`. Per-engine concurrency control is the
  `kameo` mailbox; the registry holds actor handles directly. The
  new entry documents the rationale (Shape B retired the
  synchronous-blocking caller; actors handle concurrency
  internally; kameo's API targets the wrapper-free model), the
  three honest costs (test ergonomics, re-entrancy discipline,
  pure-CPU operations on the actor-dispatch path), and the
  resolutions (free-function vs message boundary criterion;
  cross-leaf immutable-data construction-time pattern with an
  enumerated immutable-fields list; no-cycle DAG topology;
  kameo-specific constraints including issue #306 forward-chain
  avoidance and bounded mailboxes). The same commit amends the
  prior 2026-04-27 *"Engine architecture: actor model with staged
  migration from composition"* entry: the RPC boundary paragraph
  gains an `Update (2026-04-27):` supersession block, and Stage 4's
  description picks up the wrapper removal and the no-cycle-DAG /
  kameo-constraints / cross-leaf-immutable-data implementation
  requirements. A FOLLOWUPS entry under V3.0 gates Stage 2 on
  `kameo >= 0.20.0` version pin, MSRV `>= 1.88` verification, and
  a workspace-wide bounded-mailbox default.

- **Phase 1 sub-decision log entries appended (Phase 1
  `decision_log_entries` task).** Three new dated entries land in
  `docs/V3_WALLET_DECISION_LOG.md` to lock the Phase 1 surface
  decisions whose defaults were taken from the Phase 0
  `surface_decisions` review:

  - *"`RuntimeWalletState` audit: full fold, derived indexes
    rebuilt at open"* — `RuntimeWalletState` ceases to exist;
    `key_images` / `pub_keys` indexes promote into a `pub(crate)
    LedgerIndexes` owned by `Wallet`, rebuilt from the
    authoritative ledger at open time, never persisted. Schema
    unchanged. Closes the `runtime_state_audit` Phase 1 task and
    the `pub use ... as WalletState` transitional alias deletion.
  - *"`tx_keys` storage: persist in `TxMetaBlock`, never
    re-derived"* — pins the rule that per-tx randomness lives in
    `TxMetaBlock::tx_keys: BTreeMap<TxHash, TxSecretKeys>`
    (already shipped in schema), is never reconstructed from any
    other state, and that `Engine::tx_proof` /
    `Engine::reserve_proof` (Phase 2) read it by `txid` lookup
    with a typed `ProofError::TxKeyNotPersisted` on miss.
  - *"Daemon-side `tracing` install:
    `shekyl_log_install_tracing_forwarder` under
    `shekyl-logging::ffi`"* — locks the FFI export name, signature
    (`pub unsafe extern "C" fn() -> i32`, idempotent, returns
    typed `ALREADY_INSTALLED` / `NOT_INITIALIZED`), home
    (`shekyl-logging::ffi`, **not** `shekyl-daemon-rpc::ffi`), and
    the rule that `shekyl-daemon-rpc`'s `tracing::*` call sites
    are kept verbatim — the forwarder routes them through
    `shekyl-logging` automatically. Closes the `docs/FOLLOWUPS.md`
    V3.2 entry *"`shekyl-daemon-rpc` staticlib: `tracing::*` calls
    silently dropped"* by absorption into the Phase 1 logging
    deliverable.

  No code changes ship in this entry; each decision is realized
  by a subsequent Phase 1 commit (the `RuntimeWalletState` fold
  is the next task in line per the todo list).

- **Engine rename, actor-architecture, and pending-tx protocol
  decision-log entries appended (2026-04-27).** Three new dated
  entries land in `docs/V3_WALLET_DECISION_LOG.md` to pin major
  Phase-2-and-beyond architectural commitments whose rationale
  must be in tree before the supporting code commits land:

  - *"`Wallet<S>` renamed to `Engine<S>`: privacy-correct framing
    for the local artifact"* — pins the renaming of the
    orchestrator type, all related types, all crate paths
    (`shekyl-wallet-core` → `shekyl-engine-core`,
    `shekyl-wallet-file` → `shekyl-engine-file`,
    `shekyl-wallet-state` → `shekyl-engine-state`,
    `shekyl-wallet-rpc` → `shekyl-engine-rpc`,
    `shekyl-wallet-prefs` → `shekyl-engine-prefs`), JSON-RPC
    method strings (`wallet_*` → `engine_*`), CLI subcommand
    names, file paths (`~/.shekyl/wallets/` → `~/.shekyl/engines/`),
    and CLI user-facing language ("engine" used consistently in
    CLI help text). GUI/mobile user-facing language stays a
    separate marketing decision deferred to post-V3 user-
    interaction testing. Domain-primitive crates
    (`shekyl-shard-visual`) and binary/product crates remain as-
    is. The decision is realized by the immediately-following
    mechanical rename commit on `shekyl-core` `dev`.
  - *"Engine architecture: actor model with staged migration from
    composition"* — pins the migration of `Engine<S>` from
    composition to an actor model with `kameo` as the framework,
    over five staged actor builds plus a Stage 1 framework-
    agnostic preparation pass. Stage 2 introduces `kameo` and
    builds `KeyEngine` first (smallest internal state, cleanest
    privacy boundary, framework-friction surfaces with bounded
    blast radius). Stage 3 builds `StakeEngine` native-as-actor
    in Phase 2b for consensus-bond responsibilities only. Stage 4
    migrates remaining subsystems (`DaemonEngine`,
    `PersistenceEngine`, `PendingTxEngine`, `RefreshEngine`,
    `LedgerEngine`) one at a time. Stage 5 (V3.x, simulation-
    gated) builds `ArchivalEngine` as a sibling to `StakeEngine`
    (not a child) for slashing-domain integrity, failure
    isolation, and the Hayekian shard-market property. The entry
    pins the locked stage sequence end-to-end, the framework
    choice (`kameo`), the privacy benefits realized (view-key vs
    spend-key separation across actors becomes enforceable), the
    horizontal-scaling benefits enabled (V4+, stateless actor
    pools), and the long-tier staker upgradability shape (V5+,
    signed actor-patch distribution; V3 and V4 use restart-based
    upgrades). The entry rejects the alternatives explicitly:
    pure composition (privacy weaker), Stage-1-as-`kameo`
    (premature framework lock-in), single-cutover migration
    (review-undeliverable), `ArchivalEngine`-as-child-of-
    `StakeEngine` (slashing-domain integrity violation).
  - *"Pending-tx protocol: two-phase build/submit/discard over
    single-phase callback"* — pins the canonical transaction-
    sending API as the two-phase pending-transaction protocol
    (`build` / `submit` / `discard`, with `inspect`,
    `adjust_fee`, `sign_partial`, `aggregate_signatures`,
    `export` as additional pending-tx operations). The single-
    phase `send(request, confirm_fn) -> Result<TxHash>` callback
    model is rejected. Rationale: explicit lifecycle for
    multisig and air-gapped signing flows, RPC-friendly across
    the JSON-RPC boundary, fee-adjustment without rebuild,
    audit/inspect surface, recovery from partial failure.

  Companion `docs/FOLLOWUPS.md` updates land in the same commit:

  - V3.0 — Stage 2 `KeyEngine` migration; Stage 3 `StakeEngine`
    native build; Stage 4 remaining-subsystem migrations
    (`DaemonEngine`, `PersistenceEngine`, `PendingTxEngine`,
    `RefreshEngine`, `LedgerEngine` in suggested order); RPC
    boundary refinements (idle eviction with TBD-at-implementation
    rationale, `engine_lock` JSON-RPC method, multi-engine
    registry, snapshot reads from `LedgerEngine`, multi-peer
    archival routing client surface).
  - V3.1 — sibling resolution entry for the `assemble_tree_path_for_output`
    bug, locking the resolution architecture (foundation
    `--no-prune` archival as floor; staker-distributed archival
    via `ArchivalEngine` as primary path; multi-peer routing
    against per-block root snapshots). The original bug entry is
    preserved untouched as historical record.
  - V3.x — Stage 5 `ArchivalEngine` native build (simulation-
    gated); no-tradeability invariant codification placeholder
    cross-referencing `docs/V3_SHARD_VISUALIZATION.md` and
    `docs/V3_STAKER_ARCHIVAL.md`.
  - V4+ — horizontal scaling via stateless actor pools.
  - V5+ — signed actor-patch distribution over staker P2P.

  The 2026-04-25 *"Locking discipline: `RwLock<Wallet>` over
  `RefCell` / sharded locks / actor model"* sub-section receives a
  one-line forward-pointer noting that it is partially superseded
  by the new actor-architecture entry from Stage 2 onward; lock-
  discipline reasoning still applies during Phase 2b composition.

  This commit is documentation-only. No code, schema, or
  protocol surface changes here. The mechanical rename commit
  ships separately as the immediately-following commit on
  `shekyl-core` `dev`; Stage 1 and beyond ship over subsequent
  PRs per the locked stage sequence in the actor-architecture
  decision-log entry.

- **`docs/V3_STAKER_ARCHIVAL.md` and `docs/V3_SHARD_VISUALIZATION.md`
  added under `shekyl-core/docs/` (relocated and rescoped from
  `shekyl-dev/docs/V4_*`).** Two design documents covering the
  staker-distributed chain-history archival mechanism and the
  deterministic shard visualization surface relocate from the
  `shekyl-dev` planning workspace to the `shekyl-core` canonical
  documentation tree, content-checked to reflect their V3 ship
  scope rather than the V4 ship scope they originally drafted
  against. Status blocks at the top of each document pin the new
  ship target and reference the 2026-04-27 actor-architecture
  decision-log entry that established `ArchivalEngine` as a
  sibling to `StakeEngine` and `shekyl-shard-visual` as a
  domain-primitive library crate. The earlier
  `docs/V4_STAKER_ARCHIVAL.md` and `docs/V4_SHARD_VISUALIZATION.md`
  copies in `shekyl-core/docs/` (added in commit 9dc44687d) are
  removed in this commit; the V3-named documents are the canonical
  homes going forward. The companion `git rm` of the V4-named
  drafts from `shekyl-dev/docs/` ships as a separate commit on
  `shekyl-dev` `dev` that references this commit's shekyl-core
  SHA.

- **Phase 2b prep — Track 1 audit-hygiene pass (2026-04-28).** Five
  small editorial / re-export commits close the loose ends surfaced
  by the Phase 2a Branch 2 audit before Stage 1 spec work begins.
  None of the five touch consensus, secret-handling, persisted
  format, or wire format; they are pure plumbing / docs / re-exports.

  1. **`shekyl-engine-core` crate-root re-exports for `Refresh*`
     types.** [`rust/shekyl-engine-core/src/lib.rs`](../rust/shekyl-engine-core/src/lib.rs)
     now re-exports `RefreshHandle`, `RefreshOptions`, `RefreshPhase`,
     `RefreshProgress`, `RefreshReorgEvent`, and `RefreshSummary`
     alongside the `RefreshError` it already re-exported.
     Downstream callers (CLI, JSON-RPC server, benches, FFI) no
     longer have to reach through `engine::refresh::*`. The
     `engine` module itself already re-exported the full set
     ([`engine/mod.rs:168–170`](../rust/shekyl-engine-core/src/engine/mod.rs)).

  2. **CHANGELOG `[Unreleased]` editorial sweep — `Wallet` →
     `Engine` running prose.** Phase 1 and Phase 2a Branch 1 bullets
     (lifecycle, pending-tx, scan-result, refresh-driver, struct,
     module-skeleton) carried `Wallet<S>` / `Wallet::*` /
     `OpenedWallet` / `WalletSignerKind` / `WalletCreateParams` /
     `shekyl_engine_core::wallet::*` references that pre-dated the
     2026-04-27 rename bullet at the top of `[Unreleased]`. The sweep
     normalizes the running prose. Decision-log title citations and
     the rename bullet's mapping enumeration are intentionally
     preserved verbatim — the cited
     `docs/V3_WALLET_DECISION_LOG.md` entries still carry their
     historical titles.

  3. **`docs/FOLLOWUPS.md` V3.1 row added — `transfer_details` Rust
     migration.** [`.cursor/rules/15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
     cites `transfer_details` Rust migration as V3.1 scope; the row
     now exists. Rewrites each C++ consumer of `struct
     transfer_details` (balance, output selection, key-image / spend
     tracking, payment-id surface, password rotation, persistent
     wallet-cache I/O) to drive
     `shekyl-engine-state::TransferDetails` through FFI, then deletes
     the C++ struct from
     [`src/wallet/wallet2.h`](../src/wallet/wallet2.h) and
     [`src/wallet/wallet_rpc_server_commands_defs.h`](../src/wallet/wallet_rpc_server_commands_defs.h).
     Closes either at V3.1 or by superseding deletion in the V3.2
     `wallet2.cpp` retirement.

  4. **`docs/FOLLOWUPS.md` V3.2 row added — *"Re-examine
     `/FIiso646.h` and `rct::` → `ct::` deferrals."*** Reconciles a
     dead citation in [`docs/STRUCTURAL_TODO.md`](STRUCTURAL_TODO.md):17–18,
     37–38. Both deferrals rest on the same upstream-cherry-pick-risk
     framing the STRUCTURAL_TODO calls "largely notional"; the V3.2
     row pins per-item disposition rules (`/FIiso646.h`: `/permissive-`
     vs. mechanical replacement vs. stay-on-workaround;
     `rct::`→`ct::`: confirm or compress the V4 target).

  5. **`Engine::refresh` cancellation contract pinned in the
     docstring at
     [`rust/shekyl-engine-core/src/engine/refresh.rs`](../rust/shekyl-engine-core/src/engine/refresh.rs)**
     (lines 1815–1827 in the pre-edit revision). Sync path stays
     cancel-internal (the token is created fresh per call and never
     fires); async path (`Engine::start_refresh` returning
     `RefreshHandle`) owns cooperative cancellation. The split is
     deliberate, not a TBD: threading a token through every sync
     caller is design churn for no win, and the async surface
     already exists for callers that need shutdown.

  Audit reference:
  [`.cursor/plans/phase_2b_prep_stage_1_trait_boundaries_0d37a30e.plan.md`](
  ../.cursor/plans/phase_2b_prep_stage_1_trait_boundaries_0d37a30e.plan.md)
  Track B items 1–5. Track 2 (Stage 1 trait-boundaries spec, V3.2)
  begins after this hygiene pass lands.

### Removed

- **`shekyl-scanner::sync` module and `shekyl-scanner::rust-scanner`
  Cargo feature retired (Phase 2a `refresh_scan_loop` bundle,
  Branch 1).** The standalone background-sync surface
  (`run_sync_loop`, `LiveLedger`, `SyncProgress`, `SyncError`) and
  its feature flag are deleted in favor of the
  `shekyl-engine-core::Engine::refresh` driver. `shekyl-scanner`
  becomes a pure scanning library — `Scanner`, extra-field parsing,
  KEM rederivation, the `LedgerBlock` / `LedgerIndexes` extension
  traits, balance, and coin selection — and drops its `tokio` /
  `tokio-util` optional dependencies along with the feature.
  `shekyl-engine-rpc::rust-scanner` is **not** affected by this
  change; that feature gates a JSON-RPC-side
  `(LedgerBlock, LedgerIndexes)` cache (`scanner_state::LiveLedger`,
  a *local* type alias unrelated to the deleted scanner-side
  alias) which retires in Phase 4b alongside `shekyl-engine-rpc`'s
  Rust cutover. See `docs/V3_WALLET_DECISION_LOG.md`
  *"Retire `shekyl-scanner::sync::run_sync_loop` (Phase 2a/4b
  boundary)"* (2026-04-27) for the rationale and Phase boundary.
  The `sync_bookkeeping` test module in `shekyl-scanner` is
  retained: it exercises the `(LedgerBlock, LedgerIndexes)`
  state-management primitives (progress monotonicity, reorg
  handling, spend-detection tracking) that the producer side of
  `Engine::refresh` now drives, and remains load-bearing
  regardless of who owns the outer loop.

- **`rust/shekyl-ffi/src/wallet_ledger_ffi.rs` deleted as a Phase 5
  pre-emption.** The typed cache-handle FFI surface from sub-commit
  2l.a — `ShekylTransferDetailsC` / `ShekylBlockchainTipC` /
  `ShekylReorgBlockEntryC` / `ShekylSubaddressRegistryEntryC` /
  `ShekylSubaddressLabelEntryC` / `ShekylAddressBookEntryC` /
  `ShekylTxKeyEntryC` / `ShekylTxNoteEntryC` /
  `ShekylTxAttributeEntryC` / `ShekylScannedPoolTxEntryC` /
  `ShekylSyncStateScalarsC` and their
  `shekyl_wallet_{get,set,free}_*` trios plus
  `shekyl_wallet_ledger_preflight` — is gone. The corresponding
  declarations in `src/shekyl/shekyl_ffi.h` are stripped; the
  reserved `SHEKYL_WALLET_ERR_BLOCK_NOT_HYDRATED` (codepoint 29)
  retires alongside the surface that produced it. `save_as`
  (the in-scope C-ABI export from `wallet_file_ffi.rs`) and its
  refusal codes (`SAVE_AS_CROSS_FILESYSTEM` / `SAVE_AS_TARGET_EXISTS`)
  remain unchanged. The `shekyl-primitives` main- and dev-dep are
  also removed from `rust/shekyl-ffi/Cargo.toml`; the only consumer
  was the deleted file's `Commitment` reconstruction path.

  **Caller evidence (commit message body).** Pre-flight `git grep`
  against `*.cpp` / `*.cc` / `*.h` / `*.hpp` for every export of the
  deleted surface returned only `src/shekyl/shekyl_ffi.h` itself
  (the prototypes that this commit removes). Zero `.cpp` consumers
  ever materialized — the original consumer
  (`wallet2_handle_views.h/.cpp`) was scheduled but never written,
  and Phase 5 will delete the enclosing `wallet2.cpp` shim
  wholesale. Full `git grep` transcript pinned in the deletion
  commit's message body for reproducibility.

  **Decision rule.** This deletion establishes the *Phase 5
  pre-emption rule* in `docs/V3_WALLET_DECISION_LOG.md`: an
  individual Phase 5 inventory item may be deleted early when (1)
  zero current `.cpp` callers, (2) grep evidence in the deletion
  commit's message body, and (3) atomic update of
  `docs/FOLLOWUPS.md` / Phase-5-inventory metadata in the same
  commit. Pre-empting items with surviving callers is
  not acceptable. The Decision Log entry locks the rule so future
  pre-emptions follow a precedent rather than an ad-hoc precedent.

  **Inventory hygiene.** `docs/FOLLOWUPS.md` (sub-bullet *"Phase 5
  inventory pre-emptions"* under the *wallet2.cpp absorption*
  entry) records this file as already pre-empted; the eventual
  Phase 5 commit's deletion list excludes it. The pre-existing
  clippy lints in the now-deleted file (`as u8` casts, explicit
  `iter()` loop, `_keep_imports` arg count) close by absorption —
  the file holding them no longer exists.

### Changed

- **Subaddress namespace flattened to `SubaddressIndex(u32)` across the
  wallet stack and the typed-ledger FFI surface (Phase 1 of the
  [shekyl-v3-wallet-rust-rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md),
  `primitives` task).** `SubaddressIndex` is now a `u32` newtype with
  `index == 0` reserved for the primary address; the legacy
  `{account, address}` pair is gone everywhere — `WalletLedger`,
  `BookkeepingBlock::subaddress_registry` /
  `subaddress_labels.per_index`, scanner outputs, transfer records,
  `RuntimeWalletState::filter`, and the typed-ledger FFI in
  `rust/shekyl-ffi/src/wallet_ledger_ffi.rs`. Account-level concepts
  inherited from wallet2 (`AccountTags`, the `tag_descriptions` /
  `account_tags` FFI trios) are removed wholesale; the Decision Log
  entry "Subaddress hierarchy: flat, no account level" pins the
  rationale (most users use one account; account-level tags were
  wallet2 baggage; multi-wallet-file isolation is genuinely stronger
  than account-level subaddresses). A separate
  `SubaddressLabels::primary` slot is gone too — the primary label is
  the `index == 0` entry of `per_index` like every other label.

  **FFI surface delta (this commit).** `shekyl_ffi.h` mirrors the Rust:
  `ShekylSubaddressRegistryEntryC` and `ShekylSubaddressLabelEntryC`
  carry a single `index: u32` field (sizes 36 and 24 respectively, no
  trailing pad — there are zero `.cpp` callers in tree, so preserving
  the legacy stride for hypothetical future callers would be a
  defensive measure for nobody); the
  `ShekylTagDescriptionEntryC` /
  `ShekylAccountTagAssignmentEntryC` typedefs and their
  `static_assert`s, plus the
  `shekyl_wallet_{get,set,free}_{tag_descriptions,account_tags,primary_label}`
  prototypes, are removed. The FFI file
  `wallet_ledger_ffi.rs` itself is scheduled for outright deletion in
  the immediate follow-up commit (Phase 5 pre-emption); this commit
  lands the field-rename half of the migration so the deletion commit
  is a one-concern review.

  **Behavioral delta.** `shekyl_wallet_set_subaddress_registry` now
  rejects an entry with `index == 0` by returning
  `SHEKYL_WALLET_ERR_LEDGER`. The primary address is reconstructed
  from the wallet keys at every load and is not registry-managed; an
  attempted insert at index 0 is structurally impossible rather than
  benign overwrite. wallet2 silently accepted such inserts; the V3
  surface fails loudly. Belt-and-suspenders unit test
  `wallet_ledger_ffi::tests::registry_set_rejects_index_zero` pins
  the contract.

  **On-disk schema.** All three persisted-block version constants are
  bumped from `1` to `2`: `BOOKKEEPING_BLOCK_VERSION` (the direct
  field-shape changes — `subaddress_registry` /
  `subaddress_labels.per_index` flatten and `account_tags` removal),
  `LEDGER_BLOCK_VERSION` (transitive — every `TransferDetails` in
  `LedgerBlock::transfers` now carries the flattened newtype), and
  `WALLET_LEDGER_FORMAT_VERSION` (transitive — the bundle's serialized
  bytes shift wherever any nested `SubaddressIndex` or
  `SubaddressLabels` appears). The strict pairing of "snap drift ↔
  paired version-constant bump" is enforced by the
  `ci/schema-snapshot` workflow per
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.4 and
  [`.cursor/rules/42-serialization-policy.mdc`](../.cursor/rules/42-serialization-policy.mdc);
  the gate caught the original commit shipping only the bookkeeping
  bump, and the missing two were folded in atop the existing branch
  rather than rewriting history. Legacy v1 ledgers have no live
  readers — pre-V3 launch, `rm -rf ~/.shekyl` is the migration path
  per
  [`.cursor/rules/15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc).
  The `bookkeeping_block.snap` / `ledger_block.snap` /
  `wallet_ledger.snap` schema fixtures are regenerated; the
  `SubaddressIndex` shape went from a two-field struct to a
  `NewtypeStruct(u32)`, and `BookkeepingBlock::account_tags` is gone.

  **JSON shape factoring.** Transfer records expose subaddress
  indices as `{"index": u32}` (bare form, no label); address-list
  responses expose them as `{"index": u32, "label": Option<String>}`
  (joined form, label looked up at handler time). Decision Log entry
  "Subaddress JSON shapes: two schemas, no label join in transfer
  records" pins the factoring for Phase 4b OpenAPI work.

### Added

- **`shekyl-engine-core::Engine<S>` struct + `DaemonClient` thin wrapper
  (Phase 1 of the [shekyl-v3-wallet-rust-rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md),
  cross-cutting locks 1, 3, 4 type-layer realization).** Lands the
  `Engine<S: EngineSignerKind>` struct itself with its full dependency
  graph wired in: `file: shekyl_engine_file::WalletFile`, `keys:
  shekyl_crypto_pq::account::AllKeysBlob`, `ledger:
  shekyl_engine_state::WalletLedger`, `prefs:
  shekyl_engine_prefs::WalletPrefs`, `daemon: DaemonClient`, `network:
  Network`, `capability: Capability`, plus `_signer: PhantomData<S>`
  for compile-time signer-kind dispatch. `network` and `capability` are
  cached from `WalletFile`'s region 1 (which is write-once after
  `create`) so the hot accessors are infallible and O(1). Read-only
  accessors (`network()`, `capability()`, `file()`, `ledger()`,
  `prefs()`, `daemon()`) plus a `pub(crate) keys()` for in-crate sign /
  proof code paths. Redacted `Debug` impl: `keys` prints as
  `<redacted: AllKeysBlob>`, `ledger` / `prefs` print as `<…>`, `file`
  and `daemon` delegate to their own already-redacting impls. No
  `Drop` impl on `Engine<S>` itself: `AllKeysBlob` and `WalletFile`
  each ship their own `Drop` for the secret bytes / KEK / advisory
  lock; composing types that already wipe correctly is sound, and a
  wrapper `Drop` would risk shadowing the inner ones. New
  `DaemonClient` thin wrapper around
  `shekyl_simple_request_rpc::SimpleRequestRpc` insulates `Engine`'s
  public API from the transport choice and gives Phase 2a a single
  audited site for `get_info` network verification, `get_fee_estimates`
  fee-priority resolution, and tx submission. The six lifecycle methods
  (`create`, `open_full`, `open_view_only`, `open_hardware_offload`,
  `change_password`, `close`), `RefreshHandle`, `PendingTx`, and
  `ScanResult` each land in their own follow-up commits on this same
  Phase 1 branch. Cargo dependency graph: `shekyl-crypto-pq` is now a
  non-optional dependency of `shekyl-engine-core` (the `multisig`
  feature flag previously gated it; with `keys: AllKeysBlob` on the
  struct it is mandatory regardless of feature). Full rationale and
  field-by-field justification recorded in
  [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md)
  §"`Wallet<S>` struct shape and accessor surface".

- **`shekyl-engine-core::engine` module skeleton (Phase 1 of the
  [shekyl-v3-wallet-rust-rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md),
  cross-cutting locks 2, 4, 5, 6, 7, 8 type-layer realization).** New
  module `rust/shekyl-engine-core/src/engine/` ships the type-layer
  foundations of the V3 wallet orchestrator without yet introducing the
  `Engine` struct itself: per-domain error enums (`OpenError`,
  `RefreshError`, `SendError`, `PendingTxError`, `KeyError`, `IoError`,
  `TxError`) with the plan-locked variants pinned by name
  (`OpenError::NetworkMismatch`, `RefreshError::ConcurrentMutation`,
  `PendingTxError::TooOld`, `PendingTxError::ChainStateChanged`,
  `TxError::DaemonFeeUnreasonable`, etc.); a re-export of
  `shekyl_address::Network` (the fourth `Fakechain` variant lands in a
  separate scoped commit on the same branch); a re-export of
  `shekyl_engine_file::Capability` (canonical spelling — the plan's
  "`CapabilityMode`" reference is satisfied); and a sealed
  `EngineSignerKind` trait with `SoloSigner` ZST as the V3.0 default.
  V3.1's `MultisigSigner<N, K>` will join behind the existing `multisig`
  Cargo feature without changing call sites. `#[from]` impls for upstream
  errors (`WalletFileError`, `CryptoError`, `WalletLedgerError`, etc.)
  are deliberately deferred to the lifecycle / refresh / send commits
  that introduce the call sites needing them, so an `#[from]` impl never
  exists without a caller. Full rationale recorded in
  [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md)
  §"Per-domain `Wallet` error enums + sealed `WalletSignerKind`".

- **`shekyl-engine-state::LocalLabel` and `SecretStr<'a>` (Phase 1 of the
  [shekyl-v3-wallet-rust-rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md),
  cross-cutting lock 9 type-layer realization).** Locally-sensitive
  UTF-8 wrappers for every user-supplied string the wallet persists
  but never transmits — address-book descriptions, subaddress labels,
  transaction notes. `LocalLabel` is `Zeroizing<String>` with redacting
  `Debug` / `Display` (`"<redacted N bytes>"`); no derived
  `Serialize` / `Deserialize`. Persistence routes through the explicit
  `serde_helpers::local_label` adapter, which is wire-byte-identical
  to a plain `String` (test
  `serde_helpers::tests::local_label_postcard_wire_matches_plain_string`
  pins this), so the upcoming bookkeeping_block / tx_meta_block retypes
  will not bump `BOOKKEEPING_BLOCK_VERSION` or
  `TX_META_BLOCK_VERSION`. Borrowed in-process inspection goes through
  `LocalLabel::expose() -> SecretStr<'_>`, whose only `Display` /
  `Debug` output is the redaction marker; callers that need raw bytes
  call `SecretStr::as_str()` explicitly so the call site is the audit
  point. Full rationale (including why the value-typed `SecretStr<'a>`
  shape rather than the literal `&SecretStr` shorthand from the
  decision log — `unsafe_code` is forbidden workspace-wide) recorded
  in
  [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md)
  §"`LocalLabel` / `SecretStr` typing for locally-sensitive UTF-8".

### Changed

- **`monero-oxide` vendor-bump `87acb57` → `3933664` (PR 0.6 of the
  [shekyl-v3-wallet-rust-rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md),
  closing Operation A of the `monero-oxide` un-pin question).**
  Updated [`rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`](../rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT)
  from `87acb57e0c3935c8834c8a270bd3bdcbbe36bcde` (sync_date 2026-04-06)
  to `3933664d0851871c976f07298b862373d1c6fec0` (sync_date 2026-04-25),
  the current Shekyl fork tip on `Shekyl-Foundation/monero-oxide`
  `fcmp++`. **No vendored source files changed.** Of the five fork
  commits between the two pins, the only ones with code-content deltas
  (`182b648` Cargo profiles + base58 decoder hardening) touched
  `shekyl-oxide/wallet/base58/`, a Monero-shaped wallet path that is
  not vendored in shekyl-core per `60-no-monero-legacy.mdc` — Shekyl
  uses native Bech32m via `shekyl-address` instead. The umbrella
  `shekyl-oxide/Cargo.toml` is byte-identical between the vendored
  copy and fork tip; `182b648`'s Cargo profile changes live in the
  fork's workspace-root `Cargo.toml`, which we do not vendor either.
  Workspace grep for `monero_base58 | shekyl-oxide.*base58 |
  ::base58::` returns zero matches across `rust/`, confirming that
  `shekyl-address` (Bech32m via the `bech32` crate) and no other
  Shekyl crate imports the fork's base58 module. The hardening itself
  is strictly more restrictive — `checked_add` overflow detection plus
  non-canonical-encoding rejection — so even a hypothetical downstream
  consumer would only see additional `None` returns, never different
  `Some(_)` payloads. Verification per
  [`docs/SHEKYL_OXIDE_VENDORING.md`](SHEKYL_OXIDE_VENDORING.md):
  `cd rust && cargo build --locked -p shekyl-fcmp` clean, `cd rust &&
  cargo test --locked --workspace` **900 passed, 0 failed, 6 ignored**
  (exit 0). `ninja shekyld` skipped because PR 0.6 does not touch the
  C++ side and `docs/SHEKYLD_PREREQUISITES.md` already certifies the
  C++ daemon as ready. The `.github/workflows/shekyl-oxide-divergence.yml`
  CI guard now compares against the new pin and reports zero divergence
  until the fork advances again. Operation B (40-commit fork ↔ upstream
  merge, including the cypherstack `generalized-bulletproofs-fix`
  audit response and the Veridise `HelioseleneField::invert`
  correctness cluster) remains a separate V3.1.x follow-up per
  [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) § "V3.1+ — Legacy C++ → Rust
  rewrite scope" and is unaffected by this PR. Half-day review gate
  (PR 0.4 / 0.5 findings, FOLLOWUPS V3.1+ rewrite interactions,
  cross-cutting locks confirmation, un-merged-upstream impact on
  Phase 1 Wallet API shape) cleared cleanly before this PR;
  conclusions recorded in
  [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md). With
  PR 0.6 merged, Phase 0 of the V3 wallet rewrite is complete (six PRs
  for six PRs); Phase 1 (Wallet API + cross-cutting locks) is now
  unblocked. Audit doc
  [`docs/MONERO_OXIDE_VENDOR_STATUS.md`](MONERO_OXIDE_VENDOR_STATUS.md)
  amended with a "PR 0.6 vendor-bump execution (2026-04-25)" section
  recording the metadata-only finding so future readers don't replay
  the base58-content review against vendored paths that don't have it.

- **`shekyl-engine-file::WalletFileHandle` → `WalletFile`** (PR 0.2 of
  the [shekyl-v3-wallet-rust-rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md)).
  Mechanical rename across all call sites in `shekyl-engine-file`,
  `shekyl-engine-prefs`, `shekyl-ffi`, and the C FFI doc-comment in
  `src/shekyl/shekyl_ffi.h`. No ABI change (the C-ABI symbols use the
  `shekyl_wallet_*` prefix, not the Rust type name). Frees the
  `Engine` identifier for the Phase 1 `shekyl-engine-core::Engine`
  orchestrator and aligns the file-orchestrator type name with what it
  actually is — envelope, atomic IO, advisory locking, payload
  framing. Rationale and decision archive in
  [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md)
  ("Wallet stack greenfield Rust rewrite", 2026-04-25).

### Documentation

- **`shekyld` Phase 0 prerequisites audit (PR 0.3 of the
  [shekyl-v3-wallet-rust-rewrite plan](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md)).**
  New file [`docs/SHEKYLD_PREREQUISITES.md`](SHEKYLD_PREREQUISITES.md)
  consolidating the audit of three daemon-side prerequisites against
  the rewrite plan's later phases:

  1. **Instant-mining regtest mode** (Phase 6 prereq):
     PRESENT — `--regtest --offline --fixed-difficulty 1` +
     `generateblocks` JSON-RPC works as inherited from Monero;
     V3-specific caveats documented (FCMP++ tx-type and
     `curve_tree_root` header checks bypassed on `FAKECHAIN`,
     reference-block age rules still enforced). No daemon change
     required.
  2. **`get_fee_estimate(s)` RPC** (Phase 2a prereq):
     PRESENT as singular `get_fee_estimate` returning a positional
     4-element `fees` vector matching HF 2021-scaling tiers; no
     name-keyed buckets on the wire — priority-name binding is
     wallet-side. Decision-log entry adjusted: wallet supplies the
     names, daemon supplies the numbers. No daemon change required.
  3. **Fee policy / rules version exposure**:
     ABSENT entirely — no `fee_version` / `fee_policy_id` on
     `get_fee_estimate`, on `get_info`, or as a separate RPC. Filed
     as a V3.1 daemon-side follow-up; not a Phase 0 blocker. The
     rewrite's Phase 2a builds a forward-compatible client that
     consumes the field gracefully if it appears later.

  Phase 6 and Phase 2a unblocked against the existing daemon
  surface.

- **`monero-oxide` vendor freshness audit (PR 0.4 of the V3 wallet
  rewrite plan,
  [`docs/MONERO_OXIDE_VENDOR_STATUS.md`](MONERO_OXIDE_VENDOR_STATUS.md)).**
  Point-in-time (2026-04-25) record of where the vendored
  `shekyl-oxide` snapshot (`87acb57e`) sits relative to the Shekyl
  fork tip (`Shekyl-Foundation/monero-oxide` `fcmp++` `3933664d`,
  +5 commits, all non-crypto) and the original upstream
  (`monero-oxide/monero-oxide` `fcmp++` `0e438ae`, +40 commits since
  the 2025-11-22 merge base, including the cypherstack
  `generalized-bulletproofs-fix` audit response, the Veridise
  `HelioseleneField::invert` correctness cluster, and a major
  upstream restructure that the fork has not adopted). The doc is a
  freshness audit only — it does not re-vendor or un-pin. The actual
  un-pin / merge-from-upstream operation is a separate plan; this
  audit produces its input queue (substantive upstream commits the
  fork is missing) and baseline (the eight Shekyl-only fork commits,
  of which only `416d8d1` rename and `87acb57` extra leaf scalars
  are crypto-substantive). Audit lifecycle: append-only — refresh
  runs add a new dated section rather than editing in place, so the
  rewrite plan's Phase 0 record stays intelligible after the un-pin
  lands.

- **Mid-rewire hardening plan (`docs/MID_REWIRE_HARDENING.md`)
  amended in §3.1 and §4.3.** §3.1 updated to reflect the
  architecturally honest scope for the C++ baseline capture: path
  relocated to `tests/wallet_bench/` (repo convention for
  benchmarks; `src/` is product code), coverage reduced to three
  of the Five with explicit per-benchmark C++/Rust availability
  table and the daemon-coupling rationale spelled out for the two
  Rust-only paths (`scan_block_K`, `transfer_e2e_1in_2out`). §4.3
  gained a "Benchmarks Rust-only by necessity" subsection
  capturing the asymmetry so the bench-comparison script (§3.3)
  and the PR-comment format can handle it deterministically rather
  than treating missing C++ numbers as a regression. The
  acknowledgment is explicit: two paths have no pre-deletion C++
  baseline and will never have one; regression detection across
  the rewire for those paths relies on the Rust rolling baseline
  plus human order-of-magnitude sanity, not on a pre-deletion
  comparator.

- **Mid-rewire hardening plan (`docs/MID_REWIRE_HARDENING.md`).**
  New design spec pinning the eight-commit instrumentation pass
  that lands between the Rust-side wallet-file FFI (commits
  `2a`…`2k.4`, merged) and the C++ consumer rewire (commits
  `2k.5a` onward, deferred). Covers: Google Benchmark C++ baseline
  capture against the existing `wallet2.cpp` hot paths;
  criterion + iai-callgrind Rust benchmark harness mirroring the
  same five paths; GitHub Actions CI integration with
  bidirectional thresholds for `crypto_bench_*` (any drift is
  suspicious — constant-time property defense) and slowdown-only
  thresholds for `hot_path_bench_*`; rolling baseline on a
  dedicated `bench-baseline` branch; `postcard-schema` snapshot
  files with CI-enforced `block_version` bump on every drift;
  ripgrep + allowlist secret-wipe discipline for
  `shekyl-engine-state` blocks; `WalletLedger::check_invariants()`
  with five cross-block tripwires and a new
  `WalletFileError::InvariantFailed { invariant, detail }` variant;
  adversarial wallet-file corpus covering the three capability-
  mode attack shapes (tamper-in-place, declared-FULL-with-VIEW_ONLY-
  shape, declared-VIEW_ONLY-with-trailing-bytes); proptest fuzz
  harness on stable plus checked-in (non-CI) `cargo-fuzz` targets.
  Also captures the dual-path output-equivalence requirement for
  `2k.5b`…`2l` as a structural commit-message template line, not a
  reviewer convention. No code or CI changes in this commit — spec
  only; the eight follow-up commits each cite a section.

### Added

- **Mid-rewire benchmark warning window (commit 2k.c of the
  wallet-state-promotion plan,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.3.1).**
  Closes the structural-noise loophole that the 2k.a / 2k.b
  dual-stack rewire would otherwise punch through the
  `ci/benchmarks` gate. New sentinel file
  [`docs/benchmarks/MID_REWIRE_WARNING_WINDOW.active`](benchmarks/MID_REWIRE_WARNING_WINDOW.active)
  toggles warning-only mode — when present, the `fail job on
  threshold trip` step in
  [`.github/workflows/benchmarks.yml`](../.github/workflows/benchmarks.yml)
  downgrades the would-be `::error::` annotation to a
  `::warning::` and exits 0, preserving the upstream
  `compare` / PR comment / `profile-on-fail` observability
  chain without blocking merges. Policy paragraph in
  `MID_REWIRE_HARDENING.md` §3.3.1 pins *why* the window is
  needed (pre-rewire baseline vs. post-rewire gate calibration
  vs. structurally-slower-during-dual-stack middle state),
  *how* the sentinel beats workflow-level flags / Actions
  secrets / branch-name matching on grep discoverability and
  git-authored toggle trail, and *when* it must close (2m-cache
  commit, with a mandatory post-rotation of `bench-baseline`).
  The sentinel path is included in the workflow's `paths:`
  filters for both `pull_request` and `push` triggers, so
  opening and closing the window self-triggers the gate.
  Reviewers still see every delta and every samply profile
  during the window; what they lose is the automated merge
  block, which would otherwise fire on structural noise the
  rewire *is* expected to produce.

- **2k.b — refuse legacy `store_keys` writes on SHKW1 wallets
  (commit 2k.b of the wallet-state-promotion plan,
  [`.cursor/plans/wallet-state-promotion_ab273bfe.plan.md`](../.cursor/plans/wallet-state-promotion_ab273bfe.plan.md)
  §2k.b).** Installs the keys-layer fault line in
  `wallet2::store_to` so SHKW1-backed wallets cannot silently
  corrupt their on-disk file by falling back to the legacy
  `store_keys` JSON path. The two triggers that would otherwise
  reach the legacy save branch — save-as (`path` differs from
  the current `m_wallet_file`) and password change
  (`force_rewrite_keys=true`, as routed from
  `wallet2::change_password`) — now throw a typed
  [`tools::error::wallet_shkw1_operation_unsupported`](../src/wallet/wallet_errors.h)
  before any wallet-state mutation (no `trim_hashchain` cache
  touch, no `prepare_file_names` path rewrite, no cache
  serialization). Both flows require FFI that doesn't exist
  yet (`shekyl_wallet_save_as`, `shekyl_wallet_rotate_password`)
  and land in 2l alongside the cache-side rewire. The common
  `store()` → `store_to("", "")` path (same file, no forced
  keys rewrite) is *not* refused — it never touches the keys
  file, and its cache save still works through the legacy
  `shekyl_encrypt_wallet_cache` path until 2l. Callers audited:
  `wallet2::change_password` (exposed via `wallet2_ffi.cpp`
  and `wallet_rpc_server.cpp`) and direct `store_to(path, pw)`
  invocations in `tests/wallet_bench/` and
  `tests/unit_tests/wallet_storage.cpp` — all refused for
  SHKW1-backed wallets during the 2k.a → 2l window, revalidated
  in the rewrite-testing phase. `wallet_errors.h` hierarchy
  extended with the new `wallet_logic_error` subclass carrying
  both the operation name and the keys file path for UX
  rendering. Verified locally: full shekyl-core C++ rebuild
  clean across `wallet`, `daemon`, `shekyl-engine-rpc`,
  `unit_tests`, `core_tests`, `functional_tests`; no new
  lints introduced.

- **2k.a — rewire `wallet2` load/verify/rewrite onto the SHKW1
  handle (commit 2k.a of the wallet-state-promotion plan,
  [`.cursor/plans/wallet-state-promotion_ab273bfe.plan.md`](../.cursor/plans/wallet-state-promotion_ab273bfe.plan.md)
  §2k.a).** The keys-side half of the wallet2 → Rust rewire.
  `wallet2::load_keys` now magic-sniffs via
  `shekyl_wallet_keys_inspect`; on an SHKW1 match it routes
  through `shekyl_wallet_open`, gates **before** any secret
  material leaves Rust on capability
  (`tools::error::wallet_keys_unsupported_capability`) and
  derivation network
  (`tools::error::wallet_keys_wrong_network`), then extracts
  only the 64-byte master seed into a scrubbing file-local
  `TransitionalRederivationInputs` RAII wrapper
  (`epee::mlocked<tools::scrubbed_arr<uint8_t, 64>>`).
  `m_account.load_from_shkw1` rebuilds every derived field
  (classical SK/PK, view SK/PK, ML-KEM decap key, account
  address) from the seed; `m_account.forget_master_seed`
  immediately scrubs the C++ copy (Option β — the
  `ShekylWallet` handle is the single in-memory source of
  truth for the master seed post-load). An AAD-bound
  address-match sanity check against
  `ShekylWalletMetadata::expected_classical_address` catches
  corruption, HKDF policy drift, and handle-repoint bugs
  via a distinct
  `tools::error::wallet_keys_aad_address_mismatch`; `init_type`
  and `set_createtime` land atomically with the handle-stash
  on `m_shekyl_wallet`. `wallet2::load_keys_buf` refuses SHKW1
  inputs with `error::wallet_internal_error` — the envelope
  requires the file-lock path and cannot be driven through a
  raw buffer. Both `verify_password` overloads route SHKW1
  verification through `shekyl_wallet_keys_open` with a sizing
  probe for the capability payload; the instance overload runs
  the same address-match sanity check against the opened
  handle's metadata so a future migration tool that repoints
  `m_keys_file` without re-opening the handle surfaces as a
  typed error rather than silently returning keys from the
  wrong handle. The static overload logs an L1 warning if a
  caller passes `no_spend_key=false` (no in-tree caller does
  today; the log guarantees any future regression trips test
  output). `wallet2::rewrite` becomes a logged L1 no-op for
  SHKW1 wallets — settings writes land in 2k.b's `store_to`
  rewire. `wallet2::deinit` resets `m_shekyl_wallet` *before*
  `m_account.deinit()` so the Rust handle's final state write
  runs while C++ secrets are still live, and the C++ wipe
  happens after the handle drops. Three new typed refusals
  in
  [`src/wallet/wallet_errors.h`](../src/wallet/wallet_errors.h)
  discriminate structural failure modes (wrong network vs.
  AAD-bound cryptographic inconsistency vs. unsupported
  capability) so CLI, wallet RPC, and tests can render
  targeted messages without parsing log strings. Security
  invariants: the 64-byte master seed lives in C++ only for
  the duration of `load_from_shkw1`, under `mlock`; the
  address-match check fires before any scalar is materialized
  in C++; `xor_with_key_stream` / `rederive_from_master_seed`
  / `decrypt` are all length-gated, so the post-scrub empty
  vector state is a no-op everywhere it's read. Verified
  locally: full shekyl-core C++ rebuild clean across `wallet`,
  `daemon`, `shekyl-engine-rpc`, `unit_tests`, `core_tests`,
  `functional_tests`; `cargo check -p shekyl-engine-file -p
  shekyl-ffi` clean. Test regeneration / wallet2 fixture
  migration deferred to the rewrite-testing phase per the
  user-approved scope split.

- **Region-2 parser fuzz harnesses (commit 8 of the mid-rewire
  hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.8).**
  Closes the gap the adversarial corpus (commit 7) structurally
  cannot cover: the corpus pins *specific* typed refusals against
  *specific* malformations it was written to check, which says
  nothing about byte patterns nobody thought to enumerate. New
  [`rust/shekyl-engine-state/tests/fuzz_region2.rs`](../rust/shekyl-engine-state/tests/fuzz_region2.rs)
  is a stable-Rust proptest harness that drives randomized input
  into `WalletLedger::from_postcard_bytes` — the canonical region-2
  decoder used by the wallet-file orchestrator — and asserts the
  single load-bearing property: **the parser never panics and
  always terminates with a typed result** (either `Ok`, or one of
  the four enumerated `WalletLedgerError` variants). Five
  strategies at 128 cases each cover every relevant mutation
  shape: point mutation of a valid empty bundle, truncation,
  random byte insertion, random byte deletion, and entirely-random
  bytes up to 4 KiB. The error-classification match in
  `assert_typed_or_ok` is deliberately exhaustive with distinct
  classification tags per arm, so adding a new `WalletLedgerError`
  variant without updating the harness is a compile-time error —
  the harness stays in lockstep with the error taxonomy
  mechanically rather than culturally. Total wall-clock is ≈0.06 s
  per run (three orders of magnitude under the plan's 30 s-per-PR
  exit criterion); cases = 640 total (128 × 5), comfortably inside
  the plan's ~500-iteration budget. Companion local-only
  coverage-guided harness at
  [`rust/shekyl-engine-state/fuzz/`](../rust/shekyl-engine-state/fuzz/):
  a minimal `fuzz_target!` wrapping
  `let _ = WalletLedger::from_postcard_bytes(data)`, excluded from
  the workspace via new `exclude = ["shekyl-engine-state/fuzz"]`
  in [`rust/Cargo.toml`](../rust/Cargo.toml) so stable CI never
  tries to resolve `libfuzzer-sys`. Runnable locally with
  `cargo +nightly fuzz run region2_parser`; its README documents
  the two-condition graduation plan (nightly stabilisation OR
  mainnet-freeze proximity) and why nightly is not in CI today.
  The harness is kept trivial by design so that it cannot itself
  panic and mask a parser regression. Verified locally: 96
  existing `shekyl-engine-state` unit tests remain green; 5-test
  proptest harness passes in 0.06 s; `cargo check --workspace
  --tests` on stable ignores the fuzz crate entirely; clippy is
  clean with `-D warnings`; fmt is clean.

- **Adversarial wallet-file corpus (commit 7 of the mid-rewire
  hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.7).**
  Locks in the "every layer refuses with a typed error, not a panic
  or a silent fallback" posture at the integration boundary. New
  [`rust/shekyl-engine-file/tests/adversarial_corpus.rs`](../rust/shekyl-engine-file/tests/adversarial_corpus.rs)
  drives 16 programmatic attack shapes through
  `WalletFile::open` and asserts the exact `WalletFileError`
  variant each one must surface: envelope header attacks on
  `.wallet.keys` (wrong magic → `UnknownMagic`, truncated header
  → `FileTooShort`, `file_version = 0xFF` → `FormatVersionTooNew`,
  region-1 ciphertext bit flip → `InvalidPasswordOrCorrupt`);
  envelope header attacks on `.wallet` (wrong magic, future
  `state_version`, region-2 ciphertext bit flip →
  `StateSeedBlockMismatch` as currently mapped, cross-wallet
  companion swap → `StateSeedBlockMismatch`); SWSP frame attacks
  (`BadMagic`, `UnsupportedPayloadVersion`, `BodyLenMismatch`);
  `WalletLedger` body attacks (bundle `format_version` bump →
  `UnsupportedFormatVersion`, per-block `block_version` bump →
  `UnsupportedBlockVersion`, truncated postcard → `Postcard`);
  the cross-block invariant gate from commit 6
  (`INV_TX_KEYS_NO_ORPHANS` → `InvariantFailed`); and a wiring
  assertion that capability-shape mismatches (plan rows B / C) flow
  through the existing envelope-level
  `CapContentLenMismatch { mode, len }` variant unchanged — the
  plan's proposed new `CapabilityPayloadMismatch` was dropped on
  review because `validate_cap_content` in
  `shekyl-crypto-pq::wallet_envelope` already enforces the entire
  intended `(mode, cap_content_len)` shape, and adding a second
  variant with identical semantics would duplicate the gate. The
  corpus is programmatic rather than binary-pinned: each test
  builds a real wallet pair via `WalletFile::create(...)`,
  then performs narrow byte surgery (on ciphertext-protected
  regions via the public
  `shekyl_crypto_pq::wallet_envelope::seal_state_file` helper) so
  it stays green across future format-field renames and AEAD
  parameter changes. New
  [`docs/WALLET_FILE_FORMAT_V1.md`](WALLET_FILE_FORMAT_V1.md) §2.5
  writes up the capability decode posture the corpus enforces —
  mode first, then `cap_content_len`, then per-capability
  interpretation, each step refusing rather than tolerating — so
  reviewers encountering a "why no new variant?" test can follow
  the trail. New
  [`rust/shekyl-engine-file/tests/fixtures/adversarial/`](../rust/shekyl-engine-file/tests/fixtures/adversarial/)
  holds a README + one `.md` per attack row documenting the
  construction and the rationale behind each typed refusal
  (including the deliberate
  `region-2-bit-flip → StateSeedBlockMismatch` collapse rather than
  `InvalidPasswordOrCorrupt`, which the envelope cannot
  distinguish from a seed-block-tag mismatch without running the
  full region-2 verification twice). Verified locally: all 16
  corpus tests pass; the rest of the `shekyl-engine-file` suite
  remains green; clippy clean with `-D warnings`; fmt clean.

- **`WalletLedger::check_invariants()` aggregator-level gate (commit 6
  of the mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.6).**
  Closes the gap that neither single-block schemas (commit 4) nor the
  zeroizing-field grep (commit 5) structurally cover: a `.wallet`
  bundle whose every block decoded cleanly and whose every field is
  correctly wrapped can still be *semantically* impossible (a scanner
  tip below a recorded transfer; a key image shared between two
  transfers; an orphan per-tx secret whose transaction has been
  garbage-collected from every live reference). New
  [`rust/shekyl-engine-state/src/invariants.rs`](../rust/shekyl-engine-state/src/invariants.rs)
  owns the closed set of five cross-block invariants with stable
  machine-readable names: `tip-height-not-below-transfer`,
  `tx-keys-no-orphans`, `subaddress-registry-dense`,
  `reorg-trail-monotonic`, `spent-state-consistent`. Each check is
  O(n) in the number of transfers or map keys with a single
  `HashSet<[u8; 32]>` allocation, well under 100 µs for a 10 k-transfer
  bundle. New
  [`WalletLedgerError::InvariantFailed { invariant, detail }`](../rust/shekyl-engine-state/src/error.rs)
  variant carries the stable name plus a pointed diagnostic ("missing
  minor index 3 in [1, 4]" rather than "file is corrupt"), which flows
  through `shekyl-engine-file`'s `WalletFileError::Ledger` by existing
  `#[from]`. Two call sites wire the checks in: `WalletLedger::from_postcard_bytes`
  runs them after the per-block version gates pass (typed refusal on
  load), and `WalletLedger::preflight_save` runs them ahead of every
  `save_state` in `shekyl-engine-file/src/handle.rs` — `debug_assert!`
  in debug so a runtime-induced invariant break aborts tests loudly,
  typed `Err` in release so a user save never panics mid-write. Two
  invariants (subaddress density, key-image uniqueness) replace the
  plan's §3.6 `spent_images` and `transfer_index` proposals with shapes
  that match the actual blocks (`BookkeepingBlock::subaddress_registry`
  and `TransferDetails::key_image` — there is no separate spent-image
  set and no transfer-index join); the plan explicitly sanctions such
  adjustment on landing, and the machine-readable names are chosen to
  outlive any future shape refactor. Verified locally: 16 unit tests
  (one positive + at least one negative per invariant, plus alternate
  reference paths for I-2 proving a pool- or pending-referenced tx
  passes) all pass; the pre-existing 96-test `shekyl-engine-state`
  suite and 51-test `shekyl-engine-file` suite remain green; clippy
  clean with `-D warnings`; fmt clean.
- **Zeroizing-field grep + allowlist CI guard (commit 5 of the
  mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.5).**
  Closes the gap that the wire-schema snapshot from commit 4
  structurally cannot cover: `Zeroizing<[u8; 32]>` and `[u8; 32]`
  produce byte-identical postcard output, so unwrapping a zeroize
  wrapper leaves the snapshot green while silently breaking the
  runtime secret-wipe contract. New
  [`scripts/ci/check_zeroize.sh`](../scripts/ci/check_zeroize.sh)
  walks `rust/shekyl-engine-state/src/**/*.rs` and emits every
  `[u8; N]` or `Vec<u8>` field declaration: production code only
  (`#[cfg(test)]` modules and everything past the first
  `#[cfg(test)]` in a file are elided), with paren-depth tracking
  across multi-line `fn` signatures so `pub fn new(x: [u8; 32], …)`
  parameters are not mistaken for struct fields, and with standard
  filters on `//`, `///`, `use`, `type`, `impl`, `let`, `for`,
  `match`, `->` , and `assert` lines. Every hit must either carry a
  `Zeroizing<...>` / `SecretKey<...>` wrapper on the same line
  (auto-pass, no allowlist entry needed) or be enumerated verbatim —
  `<relative-path>|<normalized decl>` — in
  [`rust/shekyl-engine-state/.zeroize-allowlist`](../rust/shekyl-engine-state/.zeroize-allowlist).
  The allowlist is bi-directional: a new unwrapped field with no
  entry fails with `FATAL: unwrapped byte-shaped field(s) without
  allowlist entry`, and an allowlist line whose field no longer
  exists fails with `FATAL: stale allowlist entry — field no longer
  exists`, so the file cannot rot with ghost entries that would
  silently re-admit a future field of the same spelling. Initial
  allowlist encodes 27 deliberate public-bytes entries across six
  files (`bookkeeping_block`, `ledger_block`, `payment_id`,
  `runtime_state`, `sync_state_block`, `transfer`, `tx_meta_block`),
  grouped by category with per-entry comments: (a) public chain
  hashes (tip/reorg/creation-anchor/pending-tx/reference-block),
  (b) public key-image markers on `TransferDetails`, (c) 32-byte
  map keys keying per-tx metadata (tx hashes are public lookup
  handles; values that carry secrets, like `TxSecretKey`, are wrapped
  on their own line), (d) the clear `PaymentId([u8; 8])` handle
  (obfuscation is applied by the tx-builder, not the storage type),
  (e) FCMP++ `path_blob: Vec<u8>` (public-input proof bytes; leaks
  anonymity-set choice but not spender secrets), (f) mirror-struct
  schema fields on `TransferDetailsSchema` / `TxSecretKeySchema` that
  exist only to drive the `postcard_schema::Schema` derive and never
  allocate at runtime, (g) `runtime_state.rs` in-memory indexes
  that are rebuilt from `LedgerBlock` on every load and never
  persisted. New
  [`.github/workflows/zeroize-check.yml`](../.github/workflows/zeroize-check.yml)
  runs the script on PRs into `dev` that touch the wallet-state
  source tree, the allowlist, the script itself, or this workflow.
  Policy captured in
  [`.cursor/rules/42-serialization-policy.mdc`](../.cursor/rules/42-serialization-policy.mdc)'s
  enforcement section (§3.4 schema snapshot + §3.5 zeroize grep
  together form the mechanical half of the wire-format and
  secret-wipe discipline). Verified locally: script exits 0 on
  the current tree ("33 candidate field(s) scanned, all wrapped or
  allowlisted"); the three failure modes — adding an unwrapped
  `scratch_field: [u8; 32]`, adding a stale allowlist entry,
  unwrapping an `Option<Zeroizing<[u8; 32]>>` to `Option<[u8; 32]>`
  — each produce the expected pinpoint error.
- **Wire-schema snapshot + paired `block_version` CI guard (commit 4 of
  the mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.4).**
  Converts the `block_version` discipline from cultural invariant
  (previously policed only by reviewer attention and the prose rule in
  `.cursor/rules/42-serialization-policy.mdc`) into a mechanical check
  that fires on every PR. Adds a `postcard-schema = "0.2"` dependency
  to `shekyl-engine-state` (pinned at the same major as the on-disk
  `postcard = "1"` wire-format crate, stable schema representation),
  derives `postcard_schema::Schema` on every persisted block
  (`WalletLedger`, `LedgerBlock`, `BookkeepingBlock`, `TxMetaBlock`,
  `SyncStateBlock`, plus the nested `BlockchainTip`, `ReorgBlocks`,
  `FcmpPrecomputedPath`, `SubaddressLabels`, `AddressBookEntry`,
  `AccountTags`, `TxSecretKeys`, `ScannedPoolTx`, `SubaddressIndex`,
  `PaymentId` types), and hand-rolls `Schema` for the two leaf types
  whose fields use `#[serde(with = "…")]` helpers the derive macro
  cannot introspect (`TransferDetails`, `TxSecretKey`). The hand-rolled
  impls use the mirror-struct pattern: a compile-only
  `TransferDetailsSchema` / `TxSecretKeySchema` that mirrors the wire
  layout with `Vec<u8>` for byte sequences, then lifts
  `NamedType.ty` out of its derived `Schema` impl under the
  domain-facing type name. This is wire-identical to the original types
  (both produce length-prefixed byte sequences under postcard) but
  participates in `postcard-schema`'s `NamedType` tree, which is the
  load-bearing part of the check.
  [`rust/shekyl-engine-state/src/schema_snapshot.rs`](../rust/shekyl-engine-state/src/schema_snapshot.rs)
  is a new test module that renders each block's `NamedType` tree as
  pretty JSON (via `OwnedNamedType` — `NamedType` holds `&'static`
  references that `serde_json` cannot roundtrip through) and
  diff-compares against a committed `.snap` file under
  [`rust/shekyl-engine-state/schemas/`](../rust/shekyl-engine-state/schemas/).
  Seven tests: one per block (5) plus a self-parseability roundtrip
  guard and a canonicality check on the schemas-dir path. Running
  `UPDATE_SNAPSHOTS=1 cargo test -p shekyl-engine-state schema_snapshot`
  regenerates; running without the env var asserts. Mismatches print a
  line-oriented unified diff, name the file that moved, and spell out
  the three-step fix (bump the constant, regenerate, review).
  [`.github/workflows/schema-snapshot.yml`](../.github/workflows/schema-snapshot.yml)
  wires two jobs. The first runs
  `cargo test -p shekyl-engine-state schema_snapshot --no-fail-fast`
  against the PR head. The second diffs the PR against the `dev`
  merge-base and, for every `.snap` that changed, insists that both
  (a) the paired source file was touched, and (b) the `pub const` line
  that declares the matching version constant appears on either side of
  the file's unified diff. Pairing is canonical in both the workflow
  (`PAIRS` array) and the `schema_snapshot.rs` module docs:
  `wallet_ledger.snap ↔ WALLET_LEDGER_FORMAT_VERSION`,
  `ledger_block.snap ↔ LEDGER_BLOCK_VERSION`,
  `bookkeeping_block.snap ↔ BOOKKEEPING_BLOCK_VERSION`,
  `tx_meta_block.snap ↔ TX_META_BLOCK_VERSION`,
  `sync_state_block.snap ↔ SYNC_STATE_BLOCK_VERSION`. Workflow paths
  filter is scoped to the wallet-state crate plus the workflow file
  itself, so unrelated PRs skip the job entirely. Design choices
  surfaced in §3.4: (a) the snapshot is schema JSON, not postcard
  bytes — a hex diff is opaque to a reviewer, whereas a `NamedType`
  diff names every field and spells out its `DataModelType`; (b) the
  schema-stability contract leans on `postcard-schema`'s SemVer
  (pinned `0.2`), because the `NamedType` representation is part of
  the crate's public API; (c) the mirror-struct pattern is preferred
  over upstream-patching `postcard_schema` to understand
  `#[serde(with)]` because it is local, reviewable, and does not couple
  us to an upstream release cadence. Exit criteria met: five snapshot
  files exist, the assert-test passes on a clean checkout, a deliberate
  field rename produced a unified diff pointing at the exact node
  (verified locally against a scratch `#[serde(rename = "restore_height")]`
  on `SyncStateBlock::restore_from_height`), and the workflow's
  grep-logic dry-run correctly accepts a `pub const … = N → N+1` diff
  and rejects source-file edits that leave the declaration line
  untouched.
- **CI benchmark gate — iai-callgrind per-PR + rolling baseline on
  `bench-baseline` (commit 3 of the mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.3).**
  New `ci/benchmarks` workflow
  ([`.github/workflows/benchmarks.yml`](../.github/workflows/benchmarks.yml))
  running on PRs into `dev` (the gate) and pushes to `dev` (the
  rolling-baseline updater). On a PR: `ubuntu-latest` runs the
  full five-bench iai-callgrind harness via
  `scripts/bench/capture_rust_baseline.sh` (~8-10 min, cached
  cargo registry + target dir), diffs the resulting
  `shekyl_rust_v0.json` against the tip of the orphan
  `bench-baseline` branch's `baseline.json` via
  [`scripts/bench/compare.py`](../scripts/bench/compare.py), and
  upserts a Markdown PR comment via
  [`scripts/bench/post_comment.py`](../scripts/bench/post_comment.py).
  Threshold table enforced mechanically: `crypto_bench_*` ±5% warn
  / ±15% fail (bidirectional — speed-ups are suspicious on
  constant-time paths too), `hot_path_bench_*` +5% warn / +15%
  fail (slowdown-only), missing-bench-in-PR = fail. On any fail a
  second job re-runs the criterion sibling of the tripped bench
  under `samply record` and uploads a `profile.json` artifact for
  flamegraph review. Bootstrap: the first PR before the
  `bench-baseline` branch exists gets a `bootstrap-pending`
  comment and the gate passes; the first subsequent push to `dev`
  creates the branch with a bot-authored orphan commit. Design
  choices documented in §3.3 "Implementation notes": (a) Tier 1
  only — criterion wall-clock numbers are rendered in the comment
  as an informational table but do not trip the gate (the Tier 2
  upgrade to dedicated-runner wall-clock is tracked in §6.1);
  (b) C++ Google Benchmark is **not** wired in this commit
  because only `BM_balance_compute` ships live on the C++ side and
  it is wall-clock (same Tier-2 bucket as criterion); (c) the gate
  diffs against `bench-baseline/baseline.json` directly rather
  than re-running the bench on the baseline commit, because
  iai-callgrind instruction counts are machine-independent for
  deterministic code (Valgrind VEX IR, not native cycles) — saves
  ~8 min of CI per PR and the rolling baseline is always at most
  one dev-merge cycle stale. The compare report schema
  (`shekyl_rust_v0_compare_v1`) is its own versioned envelope so a
  future schema bump on the capture side does not silently drift
  the comparator. Companion documentation:
  [`docs/benchmarks/README.md`](benchmarks/README.md) gains a
  full "CI integration" section with per-PR flow, threshold
  routing, rolling-baseline semantics, and a "When a gate trips"
  triage runbook. Permissions are scoped per-job (read-only at
  top level; `pull-requests: write` only on the comment-posting
  job; `contents: write` only on the baseline-updater job), using
  the default `GITHUB_TOKEN` — no PAT, no self-hosted runner, no
  secret provisioning required.
- **Provisional laptop-captured `shekyl_rust_v0` baseline
  (follow-up to hardening-pass commit 2).** The harness commit's
  CHANGELOG entry deferred the frozen `shekyl_rust_v0.json` +
  `shekyl_rust_v0.iai.snapshot` to a reference-machine capture. To
  unblock commit 3 (CI threshold gate), those two files are landed
  here as a **laptop capture** on the commit author's host; the
  envelope records the exact CPU model, kernel, and toolchain
  (`captured_on.*` fields) so the "provisional" status is
  self-documenting. The iai-callgrind instruction-count columns are
  stable across back-to-back runs on that host (the §3.2 determinism
  criterion is met), so the baseline is a valid slowdown detector
  for same-host re-captures; the criterion wall-clock columns are
  soft numbers that CPU frequency scaling and background load will
  drift, and the reference-machine re-capture will overwrite them.
  Schema is stable across the swap (`shekyl_rust_v0`), so commit 3's
  comparison script does not need to branch. The capture-script
  probe for `iai-callgrind-runner` is also fixed in the same
  landing: the tool's `--version` flag exits 1 outside the
  cargo-bench handshake protocol, so the envelope's
  `iai_callgrind_runner_version` field was previously `"unknown"`;
  it now resolves via `cargo install --list` with a fallback through
  the runner's own error banner.
  [`docs/benchmarks/README.md`](benchmarks/README.md) gains a
  "Provisional laptop baseline" subsection naming the policy
  relaxation and the exit condition for it.
- **Rust wallet-state benchmark harness — criterion + iai-callgrind
  (commit 2 of the mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.2).**
  Five hot paths from the §3.1 list, each shipped with a
  `criterion` binary (wall-clock, Tier-2 metric) and an
  `iai-callgrind` sibling (deterministic instruction-count + cache-
  miss metrics, Tier-1 metric that CI will gate on in commit 3):
  `shekyl-engine-state::{ledger, balance}`,
  `shekyl-engine-file::open`, `shekyl-scanner::scan_block`,
  `shekyl-tx-builder::transfer_e2e`. Naming convention enforced:
  `crypto_bench_*` (bidirectional ±5% warn / ±15% fail) for
  anything touching curve25519, ML-DSA-65, Argon2id, or ChaCha20-
  Poly1305; `hot_path_bench_*` (slowdown-only) for postcard serde,
  balance compute, and scanner bookkeeping. All ten harnesses
  compile under `cargo check --benches`, run locally under
  `cargo bench -p <crate> --bench <name>`, and — on a host with
  `valgrind` + `iai-callgrind-runner` on `PATH` — produce
  byte-identical instruction counts across back-to-back runs
  (§3.2 exit criterion). One deliberate deviation from production
  code is documented: the `transfer_e2e_iai` bench bypasses
  `HybridEd25519MlDsa::sign` and inlines the two sign steps with
  `fips204::ml_dsa_65::try_sign_with_seed` +
  `try_keygen_with_rng(seeded)` because the production wrapper's
  `OsRng` draws inside ML-DSA-65 keygen + rejection-sampling loop
  produced ~16% instruction-count variance on the sign call and
  ~66% variance once keygen was accounted for, both violating the
  determinism criterion. The FIPS-204 deterministic variant
  exercises the identical signing primitives (same NTT, same
  rejection predicates, same packing); the criterion sibling
  preserves the randomized production path so the human-facing
  wall-clock number is honest. Known gap: the full
  `sign_transaction` call including the FCMP++ membership proof is
  **not** benched, because a deterministic curve-tree path fixture
  keyed to a synthetic tree root is its own scope of work; the
  manifest §6.1 tracks this and names the un-gap conditions for a
  future `shekyl_rust_v1` schema bump. Companion artifacts:
  [`docs/benchmarks/shekyl_rust_v0.manifest.md`](benchmarks/shekyl_rust_v0.manifest.md)
  (per-bench operation lists, fixture shapes, six documented known
  gaps, apples-to-oranges notes against the C++ baseline),
  [`scripts/bench/capture_rust_baseline.sh`](../scripts/bench/capture_rust_baseline.sh)
  (reference-machine capture wrapper — sibling of
  `capture_cpp_baseline.sh` from commit 1 — emits a schema-versioned
  `shekyl_rust_v0.json` envelope with toolchain + host CPU +
  git-rev metadata alongside a raw `shekyl_rust_v0.iai.snapshot`
  text artifact),
  [`docs/benchmarks/README.md`](benchmarks/README.md) updated with
  a "Capturing the Rust baseline" section and the shipped
  file-layout listing. Workspace impact is dev-dep-only:
  `criterion` + `iai-callgrind` land as `[dev-dependencies]` on
  the four crates that own a bench (`shekyl-engine-state`,
  `shekyl-engine-file`, `shekyl-scanner`, `shekyl-tx-builder`);
  the `shekyl-scanner` bench gains a self-referential
  `shekyl-scanner = { path = ".", features = ["test-utils"] }`
  dev-dep so `WalletOutput::new_for_test` +
  `RecoveredWalletOutput::new_for_test` are available in the
  bench without exposing them to downstream consumers. The frozen
  `shekyl_rust_v0.json` is captured on a reference machine by the
  commit author and landed as a follow-up — this commit ships the
  harness, not the numbers, because the reference machine is part
  of the measurement (same discipline as commit 1).
- **Wallet2 C++ baseline benchmark harness
  (`tests/wallet_bench/`, commit 1 of the mid-rewire hardening pass,
  [`docs/MID_REWIRE_HARDENING.md`](MID_REWIRE_HARDENING.md) §3.1).**
  Google Benchmark v1.9.1 harness fetched via `FetchContent`,
  opt-in behind `-DBUILD_SHEKYL_WALLET_BENCH=ON` (OFF by default so
  normal contributors do not pay the cold-build cost). Of the five
  hot paths identified in §3.1, **one ships live on this tree**
  (`BM_balance_compute`, N ∈ {100, 1000, 10000}, O(n) `balance()`
  iteration over a seeded synthetic transfer set) and **two are
  scaffolded-but-gated** with `state.SkipWithError(...)`
  (`BM_open_cold`, `BM_cache_roundtrip`): those two depend on
  `wallet2::generate` → `store_to` → `load` round-tripping, which
  is broken on this tree and reproduced by the already-failing unit
  test `wallet_storage.store_to_mem2file`. Root-causing the
  wallet2 regression is the work scope of hardening-pass commits
  `2l` / `2m-keys` / `2m-cache`; patching it here would violate the
  "clear separations" invariant. Un-skipping is a one-line change
  in each bench function when those commits land. Fixtures use a
  pinned seed (`0xBEEFF00DCAFEBABE`) so two runs produce
  byte-identical inputs; the bench defines its own
  `wallet_accessor_test` in `tests/wallet_bench/bench_fixtures.h`
  (matching the existing friend declaration in `src/wallet/wallet2.h`,
  disjoint from the same-named class in `tests/core_tests/wallet_tools.h`
  — the two headers are never included in the same TU) with a minimal
  surface: `m_transfers` get, `get_cache_file_data`, `load_wallet_cache`. Two of the Five (`scan_block_K`,
  `transfer_e2e_1in_2out`) ship only in the Rust harness from
  commit 3.2: wallet2's scanner and FCMP++ proof paths are
  daemon-coupled and have no hermetic provisioning path; the
  architecturally honest move is to acknowledge the gap in
  `docs/MID_REWIRE_HARDENING.md` §3.1 and §4.3 rather than
  reimplement daemon-side synthetic-tree logic in code that is
  deleted in 2m-cache.
  Companion artifacts:
  [`docs/benchmarks/wallet2_baseline_v0.manifest.md`](benchmarks/wallet2_baseline_v0.manifest.md)
  (prose manifest: every operation in each live bench's hot loop,
  every I/O boundary, apples-to-oranges notes against Rust, and the
  un-skip criteria for the two gated paths),
  [`docs/benchmarks/README.md`](benchmarks/README.md) (capture
  procedure + baseline-update policy),
  [`scripts/bench/capture_cpp_baseline.sh`](../scripts/bench/capture_cpp_baseline.sh)
  (reference-machine capture wrapper emitting a schema-versioned
  JSON envelope with toolchain + host CPU + git-rev metadata),
  [`tests/wallet_bench/README.md`](../tests/wallet_bench/README.md)
  (local build + run instructions + known gaps). The frozen
  `wallet2_baseline_v0.json` is captured on a reference machine by
  the commit author and landed as a follow-up — this commit ships
  the harness, not the numbers, because the reference machine is
  part of the measurement.
- **Boost `program_options` link-time dep on `libcommon`
  (`src/common/CMakeLists.txt`).** `removed_flags.cpp` calls
  `boost::program_options::error_with_option_name::get_option_name()`,
  which inlines `get_canonical_option_name` and therefore requires
  the `libboost_program_options` symbol to resolve at link time
  (`libcommon.so` is linked with `-Wl,--no-undefined`). The dep was
  missing since `removed_flags` landed and only surfaced during a
  clean rebuild triggered by the benchmark harness above. Fix is a
  one-line `PRIVATE ${Boost_PROGRAM_OPTIONS_LIBRARY}` in
  `src/common/CMakeLists.txt`. No behavior change outside CMake.

### Chore

- **Workspace `cargo fmt --all` baseline (PR 0.5 of the V3 wallet
  rewrite plan,
  [`.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md`](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md)
  Phase 0).** Five files (`rust/shekyl-ffi/src/wallet_file_ffi.rs`,
  `rust/shekyl-ffi/src/wallet_ledger_ffi.rs`,
  `rust/shekyl-scanner/benches/scan_block.rs`,
  `rust/shekyl-tx-builder/benches/transfer_e2e.rs`,
  `rust/shekyl-engine-file/src/handle.rs`) had accumulated hand-edited
  formatting drift before this plan started; `cargo fmt --all --check`
  flagged them on `dev`. Mechanical, fmt-only run; no logic, behaviour,
  or API change. Lands before Phase 1 begins so subsequent rewrite PRs
  can use `cargo fmt --all --check` as a cheap branch-hygiene signal
  without wading through pre-existing drift. Drift cause was hand-edits
  bypassing fmt (verified: `git log --follow` on each file shows the
  drifting hunks were introduced under the same `rustfmt` toolchain in
  use today), so unconditional `cargo fmt --all` is the correct fix —
  no `#[rustfmt::skip]` warranted.

- **Phase 0 PR 0.6 planning + FOLLOWUPS scope adjustments
  (`chore/phase0-pr06-vendor-bump-planning`).** Split the
  `monero-oxide` re-pin question into two distinct operations and
  scoped them differently:
  - **Operation A — vendor-bump `87acb57` → `3933664` (fork tip).**
    Mechanical, cheap, none crypto-substantive except `182b648`'s
    base58 decoder hardening. **Added as PR 0.6 to Phase 0 of the V3
    wallet rewrite plan.** Total Phase 0 grows from five PRs to six.
  - **Operation B — un-pin / 40-commit upstream merge.** Stays as a
    V3.1.x peer plan, **not** scoped to Phase 0. The active correctness
    bug `00bafcf` (`HelioseleneField::invert` Veridise edge case) does
    not change this assessment: the bug exists today on `dev`, it is
    below the wallet stack's API surface, and the rewrite's Phase 1
    API shape does not depend on it. The un-pin runs in parallel with
    rewrite Phases 1–3 if bandwidth allows.

  Plan adjustments
  ([`.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md`](../.cursor/plans/shekyl_v3_wallet_rust_rewrite_3ecef1fb.plan.md)):
  (1) new PR 0.6 section with cost-ceiling discipline (bail out if
  base58 review or workspace verification surfaces concerns); (2)
  half-day review gate expanded from one item to five (PR 0.4 vendor
  status, PR 0.3 daemon-side findings, FOLLOWUPS V3.1+ section,
  cross-cutting locks confirmation, and **new item 5** confirming
  whether un-merged-upstream commits affect Phase 1 Wallet API shape);
  (3) Phase 1 logging deliverable now absorbs the daemon-side
  staticlib `tracing` silently-dropped follow-up — the same subscriber
  init solves both the wallet stack and the daemon staticlib in one
  deliverable; (4) Phase 5 commit message inventory now explicitly
  closes two V3.2 follow-ups (`shekyl-cli` key image binary format —
  no Monero binary-format port; `wallet_tools.cpp` mixin/decoy — swept
  with `tests/unit_tests/wallet*.cpp`); (5) Phase 3b deliverables
  flag an optional `--format=qr-chunks` on the typed bundles for
  air-gapped UX, replacing the V3.2 hex-blob QR follow-up;
  (6) bumped Phase 0 PR count in the Branching cadence section.

  FOLLOWUPS adjustments ([`docs/FOLLOWUPS.md`](FOLLOWUPS.md)): the
  V3.1+ section gains an at-a-glance index table (absorbed /
  closed-by-Phase-5 / cross-linked / independent) used by review-gate
  item 3; the `monero-oxide` un-pin entry rewritten to describe
  Operation A vs Operation B with cross-links in both directions; the
  three V3.2 entries that get explicit closure (shekyl-cli key image
  binary, `wallet_tools.cpp` mixin, daemon staticlib `tracing`) carry
  inline closure notes pointing to the rewrite phase that absorbs or
  closes them; the V3.2 hex-blob QR entry annotated to die with the
  hex format in favour of the typed bundles.

  Decision-log entry
  ([`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md)):
  new entry "monero-oxide re-pin: split into Operation A (Phase 0)
  and Operation B (un-pin V3.1.x plan)" pinning the rationale for why
  the active correctness bug doesn't force Operation B into Phase 0,
  and naming the alternatives considered (fold both into Phase 0,
  defer both to V3.1.x, fold Operation A into PR 0.4) and why each
  was rejected.

  No code changes in this PR — planning + cross-link maintenance
  only. PR 0.6 (the actual vendor-bump) lands in a subsequent PR.

- **Phase 0 audit cleanup (`chore/phase0-audit-cleanup`).** Three
  small follow-ups surfaced by the post-merge comprehensive audit of
  `dev` against the V3 wallet rewrite plan's Phase 0 expectations:
  (1) consolidated the duplicate `### Documentation` heading under
  `[Unreleased]` that was a rebase artefact across PR 0.2 / PR 0.3 /
  PR 0.4 — three entries moved up into the canonical section, no
  content lost; (2) added a back-link in
  [`docs/SHEKYLD_PREREQUISITES.md`](SHEKYLD_PREREQUISITES.md)
  pointing forward to the two consuming
  [`docs/V3_WALLET_DECISION_LOG.md`](V3_WALLET_DECISION_LOG.md)
  entries (positional fee mapping, `fee_policy_version` absence) and
  the daemon-side V3.1 follow-up in
  [`docs/FOLLOWUPS.md`](FOLLOWUPS.md), so the audit's downstream
  consumers are reachable from the audit doc itself; (3) fixed a
  pre-existing `clippy::needless_return` lint in
  `rust/shekyl-engine-file/src/handle.rs::is_cross_device_error`
  (introduced under commit `2l.a`, not by Phase 0) for readability.
  Recorded a follow-up in
  [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) noting that the workspace as a
  whole is **not** `clippy --workspace -- -D warnings` clean
  (`shekyl-ffi` carries ~12 inherited warnings from its FFI shape)
  and that a dedicated cleanup pass + CI gate belongs to V3.1.x.

### Fixed

- **`shekyl_account_public_address_check` argument-order mismatch
  between Rust definition and C-side declaration** (Track 0a CI
  triage, 2026-04-28). The Rust definition in
  [`rust/shekyl-ffi/src/account_ffi.rs`](../rust/shekyl-ffi/src/account_ffi.rs)
  takes `(pqc_pk_ptr, view_pk_ptr)`; the C header in
  [`src/shekyl/shekyl_ffi.h`](../src/shekyl/shekyl_ffi.h) declared
  `(view_pub_ptr, pqc_public_key_ptr)`, and the one C++ caller in
  [`src/cryptonote_basic/cryptonote_basic_impl.cpp`](../src/cryptonote_basic/cryptonote_basic_impl.cpp)
  followed the wrong order. Every decode therefore ran the FIPS-203
  well-formedness check on garbage bytes, surfacing in CI as 14
  `uri.*` unit_tests failures with the log line
  `cn: Address failed v1 canonical invariant check (view_pub <->
  X25519 prefix or malformed ML-KEM-768 encapsulation key)`.
  Introduced in commit `0092a8da1` ("ffi,cryptonote_basic: pin
  m_pqc_public_key format and publish v1 account FFI"); reached
  `dev` only at the `feat/wallet-account-rewire` merge `30db140fe`
  (2026-04-22). The Rust unit tests at
  `rust/shekyl-ffi/src/account_ffi.rs:954,975` use the correct
  `(pqc, view)` order and never caught the C-side divergence. Per
  `.cursor/rules/10-shekyl-first.mdc`, Rust is the source of truth;
  the fix aligns the C header and the C++ caller. Two files
  touched, no fixture regeneration; the previously-failing 14
  `uri.*` tests are themselves the regression test (FAIL → PASS).
  Local verification: 858/870 unit_tests passing after the fix
  (was 854/870), the 2 remaining failures are
  `wallet_storage.{store_to_mem2file, change_password_mem2file}`
  tracked in `docs/CI_BASELINE.md` Cluster B and
  `docs/FOLLOWUPS.md` (V3.1, wallet2 hardening-pass close).

- **CI baseline established as
  [`docs/CI_BASELINE.md`](./CI_BASELINE.md)** (Track 0e CI triage,
  2026-04-28). Records the documented list of known-failing C++
  tests with diagnoses, close conditions, and FOLLOWUPS row
  pointers (Cluster A — `uri.*`, fixed; Cluster B —
  `wallet_storage`, deferred to V3.1 wallet2 hardening-pass;
  Cluster C — `core_tests gen_*`, deferred to V3.1 chaingen-harness
  rewrite or V3.2 `wallet2.cpp` removal; Cluster D —
  `shekyl-oxide divergence` canary, currently green). The document
  also pins the interim `shekyl-oxide` divergence-sync policy
  (explicit trust assumption + spot-check discipline scaling with
  window size) and the **pre-enforcement noise-floor rule** that
  reviewers apply today: any failure outside the documented list
  blocks PR merges to `dev` until investigated, with mechanical
  enforcement (a required-status-check on the failing-test set)
  tracked separately as a follow-up. Linked from
  [`docs/CONTRIBUTING.md`](./CONTRIBUTING.md) under "CI baseline";
  CI status is contributor surface, not first-impression surface,
  so the link does not appear in the top-level README. The full
  Track 0 plan (CI triage ahead of audit hygiene and Stage 1 spec)
  is the source of these entries.

- **`apply_scan_result_to_state` strict-contract enforcement (Phase
  2a `refresh_scan_loop` bundle, Branch 1).** Closes the PR #16
  Copilot-review finding tracked in `docs/FOLLOWUPS.md` *V3.0 →
  "`apply_scan_result` strict-contract enforcement (refresh
  commit)"* (now retired to *Recently resolved*). The merge in
  [`rust/shekyl-engine-core/src/engine/merge.rs`](../rust/shekyl-engine-core/src/engine/merge.rs)
  previously had two defensive-coding gaps:
  1. `block_hashes` was collected via `BTreeMap::insert`, silently
     overwriting duplicate height entries instead of rejecting them.
  2. `new_transfers` / `spent_key_images` / `block_hashes` entries
     with heights outside `processed_height_range` were silently
     dropped at scope end (the per-height `BTreeMap::remove` loop
     consumed only in-range entries; out-of-range residue fell off
     the stack uninspected).

  Both are producer-bug signals, not concurrent-mutation races.
  `apply_scan_result_to_state` now pre-validates `block_hashes`
  for length-matches-range, in-range, no-duplicates, every covered
  height present, and post-loop drains the per-height per-hash
  maps to assert no out-of-range residue remains. Contract
  violations surface as the new
  `RefreshError::MalformedScanResult { reason: &'static str }`
  variant; this is distinct from
  `RefreshError::ConcurrentMutation` (which signals "the wallet
  moved under the producer; safe to retry") because a malformed
  scan result indicates the producer itself is broken and retry
  cannot help. Decision Log entry
  *"`MalformedScanResult`: producer-bug signal vs.
  `ConcurrentMutation`"* (2026-04-26) pins the boundary. New
  tests: `block_hashes_length_mismatch`,
  `block_hashes_duplicate_height`, `block_hashes_out_of_range`,
  `block_hashes_missing_height`,
  `transfer_out_of_range_block_height`,
  `key_image_out_of_range_block_height`.

- **`shekyl-engine-state` `ledger` / `ledger_iai` benches: pin
  `BlockchainTip.synced_height` to the synthetic transfers' max
  `block_height`.** The benches under
  [`rust/shekyl-engine-state/benches/ledger.rs`](../rust/shekyl-engine-state/benches/ledger.rs)
  and
  [`rust/shekyl-engine-state/benches/ledger_iai.rs`](../rust/shekyl-engine-state/benches/ledger_iai.rs)
  were authored against `WalletLedger::empty()` (commit `a9a81a17e`)
  before invariant I-1 (`tip-height-not-below-transfer`) was wired
  into `WalletLedger::from_postcard_bytes` by hardening-pass commit 6
  (`def7d3379`, "feat(wallet-state):
  WalletLedger::check_invariants"). `build_ledger` was inheriting
  `tip.synced_height = 0` from the empty constructor while the
  synthetic transfers carried `block_height ∈ [1_000, 1_000 + N)`,
  so the deserialize half of the round-trip panicked with
  `WalletLedgerError::InvariantFailed { invariant:
  "tip-height-not-below-transfer", … }` on every iteration. The fix
  reconstructs the `LedgerBlock` with `tip.synced_height =
  max(transfers[*].block_height)` (and a non-`None` `tip_hash`) so
  the fixture is invariant-coherent before postcard sees it. The
  outdated `docs/FOLLOWUPS.md` entry that claimed four iai-callgrind
  targets failed to *compile* against the post-`RuntimeWalletState`
  fold has been replaced with a re-review entry capturing the actual
  finding (see *"Phase 1 bench harness re-review post-`RuntimeWalletState`
  fold (April 26, 2026)"*). All ten core benches under
  `capture_rust_baseline.sh` now build and smoke-run cleanly.

- **`source archive` CI job: pin `git describe` to release tags
  (`v*`).** The branch-archival policy in
  [`.cursor/rules/06-branching.mdc`](../.cursor/rules/06-branching.mdc)
  rule 5 has accumulated seven `archive/<branch>-<date>` annotated
  tags since 2026-04-13 (four of them on 2026-04-25, on commits that
  are merge-ancestors of `dev`). The `source-archive` job in
  [`.github/workflows/build.yml`](../.github/workflows/build.yml)
  was calling plain `git describe`, which returns the *closest
  reachable tag*. Once an `archive/*` tag became the closest tag to
  `dev`, `VERSION="shekyl-$(git describe)"` started resolving to
  e.g. `shekyl-archive/phase0-pr06-oxide-vendor-bump-2026-04-25`,
  whose `/` was interpreted as a directory by `git-archive-all`,
  failing with `[Errno 2] No such file or directory:
  '…/shekyl-archive/<branch>-<date>.tar'`. The job had failed on
  every push for ~2 hours before this fix, including PR #16's
  source-archive run. Fix is a one-line filter
  (`git describe --match 'v*'`) that ignores branch-archival tags
  and keeps `VERSION` shaped like `shekyl-vX.Y.Z-N-gSHA`. Verified
  locally: `git describe origin/dev` returns
  `archive/phase0-pr06-oxide-vendor-bump-2026-04-25` (broken),
  `git describe --match 'v*' origin/dev` returns
  `v3.1.0-alpha.3-135-g39981643f` (correct). No behavior change for
  branches with a `v*` tag in their ancestry, which is every branch
  off `dev` since the first release tag.

### Security

- **`rand` 0.8.5 → 0.8.6** in
  [`rust/Cargo.lock`](../rust/Cargo.lock) (RUSTSEC-2026-0097 /
  GHSA-cq8v-f236-94qc, severity Low). The advisory describes an
  unsoundness in `ThreadRng::TryRng` that can produce aliased
  mutable references — Undefined Behaviour — when all of the
  following hold simultaneously: (a) the `log` and `thread_rng`
  features are enabled, (b) a custom `log::Logger` is installed,
  (c) the custom logger calls `rand::rng()` /
  `rand::thread_rng()` and any `TryRng` (formerly `RngCore`)
  method on it, and (d) `ThreadRng` reseeds while called from
  inside the logger.

  This bump is **defense-in-depth, not active-vulnerability fix**:
  the project's custom logger lives in
  [`shekyl-logging`](../rust/shekyl-logging/) and a workspace-wide
  audit confirmed it does not call `rand::rng()` or
  `rand::thread_rng()` from any logger code path. The exploit
  precondition (c) is therefore not reachable from current shekyl
  code. The bump still lands so that future logger work does not
  accidentally reach into the unsoundness window.

  Application is a one-line `Cargo.lock` change
  (`cargo update --precise 0.8.6 -p rand@0.8.5`) plus the
  cascading edge updates in seven downstream consumers'
  dependency blocks (`monero-rpc-utils`, `chacha20poly1305`,
  `shekyl-crypto-pq`, `shekyl-engine-core`, `shekyl-fcmp`,
  `shekyl-staking`, `fcmp_pp`). No source changes; the workspace
  constraints (`rand = "0.8"`, caret-bounded) accept the bump
  without Cargo.toml edits.

  The companion advisory `RUSTSEC-2026-0097` against the
  fuzz-only lockfile
  ([`rust/shekyl-crypto-pq/fuzz/Cargo.lock`](../rust/shekyl-crypto-pq/fuzz/Cargo.lock))
  is intentionally **not** addressed in this PR. That lockfile
  is stale relative to the workspace (path-dep version markers
  still at `v2.0.0` pre-Wallet→Engine rename); a precise rand
  bump there cascades into ~50 lines of unrelated lockfile
  refresh churn. The exploit precondition is equally
  unreachable from fuzz harness code, and the cleanup belongs
  with the next routine fuzz-Cargo.lock hygiene pass rather
  than slipped into this focused security bump.

  `cargo audit` exits clean against the bumped lockfile (the
  RUSTSEC entry no longer matches any resolved version);
  Cargo.toml constraints unchanged; `cargo check --workspace
  --tests`, `cargo fmt --all -- --check`, and
  `cargo clippy --workspace --all-targets --keep-going --
  -D warnings` all exit 0.

  Two further open dependabot alerts on
  `Shekyl-Foundation/shekyl-core` are stale and self-clear on the
  next `main` rescan: `rustls-webpki` GHSA-82j2-j2ch-gfr8
  (already at the patched `0.103.13` in the workspace lockfile)
  and `cryptography` (pip) CVE-2026-39892 (the alert points at
  `tools/reference/requirements.txt`, which no longer exists in
  the repo). Neither requires a code change.

### Documentation

- **Stage 1 PR 4 (`RefreshEngine`) — Round 5 substrate-decision
  amendment (no-Mock substrate for C6).**
  (`feat/stage-1-pr4-refresh-engine`, 2026-05-20). Doc-only
  amendment to
  [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](design/STAGE_1_PR_4_REFRESH_ENGINE.md)
  landed mid-Phase-1 between C5β (legacy producer scaffolding
  deletion) and C6 (test substrate). The Round 4 §7.X C6 plan
  ("`MockRefresh` test substrate; mirrors `MockDaemon` /
  `MockLedger` from PR 1 / PR 2") is **stale prose** from before
  PR 3 §2.1.2's Mock-X rejection landed; building `MockRefresh`
  would re-instantiate the parallel-implementation anti-pattern
  PR 3 rejected as a category and compound the Mock-X debt that
  [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) already scheduled to be
  paid down. The amendment dispositions:

  1. **C6 replaces `MockRefresh` with `FaultInjecting<R:
     RefreshEngine>`.** Composable wrapper around the production
     `LocalRefresh` (landed at C4); queues `RefreshError::Cancelled`
     / `Io` / `InternalInvariantViolation` for failure injection
     at the trait boundary; composes against any current or future
     `R` implementor without per-impl parallel-Mock proliferation.

  2. **Retroactive Mock-X cleanup of `MockLedger` lands in PR 4
     C6β** (not deferred to PR 5). Extracts the existing
     `MockLedger` body into `FaultInjecting<L: LedgerEngine>`;
     adds `LocalLedger::from_test_blocks(...)` constructor
     replacing the parallel-implementation `MockLedger::new(...)`
     surface. Current `MockLedger` is structurally already a
     `FaultInjecting<LocalLedger>`-shaped wrapper (delegating to
     the canonical `apply_scan_result_to_state`); the cleanup is
     mostly extraction-and-rename, not a re-implementation.
     Closes [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) lines 578–604.

  3. **`MockDaemon` → `TestDaemon` rename lands in PR 4 C6γ**
     alongside C6β. Mechanical rename only — the structural
     shape is already correct (alternative real implementation
     serving canned / cached test responses without network
     connectivity); only the `Mock` naming was the bug. Closes
     [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) lines 606–620.

  The amendment is **not** a round reopening per the §7 amendment
  framing: it does not revisit any trait-surface contract pin,
  attack-surface disposition, or commit-decomposition ordering
  decision; it replaces stale C6 substrate prose with the binding
  no-Mock shape PR 3 §2.1.2 settled. The α-disposition, the
  F1–F13 dispositions, and the C0–C5 / C7 / C8 commit prose are
  all unchanged.

  The no-Mock rationale is re-iterated explicitly in §6 of the
  design doc (new "Test-substrate discipline — no-Mock substrate
  inheritance from PR 3 §2.1.2" subsection) and in the §7.X C6
  prose, naming the five failure modes the Mock-X pattern
  instantiates: (1) attack surface from test-only types in
  production code; (2) conflation of test-controlled inputs to
  real implementations with substitute implementations; (3)
  inherited-Monero pattern that has produced real bugs in the
  inherited codebase; (4) foreclosure of composition with future
  trait implementors; (5) tests verifying against fake semantics
  rather than real semantics, degrading the coverage claim.

  Rationale anchor:
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  §"cost-benefit-defer-to-later anti-pattern" names the
  architectural-integrity-now disposition as the default for
  security-load-bearing substrate work pre-genesis;
  [`15-deletion-and-debt.mdc`](../.cursor/rules/15-deletion-and-debt.mdc)
  pre-genesis discount applies. Cross-references:
  [`docs/design/STAGE_1_PR_3_KEY_ENGINE.md`](design/STAGE_1_PR_3_KEY_ENGINE.md)
  §2.1.2 (Mock-X rejection rationale + five named failure modes),
  §2.1.5 (four-pattern pre-flight checklist future per-trait PRs
  inherit).

  Files touched (doc-only):
  `docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md` (Status banner;
  new §6 no-Mock substrate inheritance discipline subsection;
  test-substrate preservation list rewritten; §7.X C6/C7/C8 prose
  updated), `docs/FOLLOWUPS.md` (two retroactive Mock-X cleanup
  entries pinned to PR 4 C6β/C6γ; fix the prior bug that called
  PR 4 `PendingTxEngine` — PR 4 is `RefreshEngine`; PR 5 is
  `PendingTxEngine`), and this CHANGELOG entry.

- **Stage 1 PR 4 (`RefreshEngine`) — Round 5 sub-pin extension
  + amendment-layering coherence pass (F-Mock-1 through F-Mock-8
  + Option (i) wrapper API + two-enum architecture pin).**
  (`feat/stage-1-pr4-refresh-engine`, 2026-05-20). Doc-only
  follow-up to the Round 5 substrate-decision amendment above.
  Same-day review pass surfaced eight Mock-X-substrate findings
  (F-Mock-1 through F-Mock-8) on the Round 5 amendment, then
  ran an amendment-layering coherence pass against the
  post-Round-5 substrate to surface forward-pointer gaps and
  paradigm-language conflations. The pass landed four
  substantive sharpenings, four minor audit-trail notes, a new
  §6.1 "Test-substrate paradigm pin" subsection, and a new
  §6.1.1 "Two-enum architecture (RefreshEngine-specific positive
  pattern)" sub-section pinning the producer-internal /
  trait-surface error-enum split as a positive architectural
  reference and forward-template for future per-trait PRs.
  None reopen any Round 1–4 disposition or the Round 5
  amendment itself; the sub-pin refines the Round 5 C6
  substrate so the Phase 1 author implements against an
  explicit pin rather than reverse-engineering from tests.

  **Substantive dispositions (F-Mock-1 through F-Mock-4 +
  Option (i) wrapper API + two-enum architecture).**

  1. **F-Mock-1 — `cfg`-gating symmetry (Option (a)).** All four
     C6 surfaces (`FaultInjecting<R: RefreshEngine>`,
     `Engine::replace_refresh`, `FaultInjecting<L: LedgerEngine>`,
     `LocalLedger::from_test_blocks`) are gated uniformly
     `#[cfg(any(test, feature = "test-helpers"))]`. The
     `test-helpers` feature is introduced as part of C6α's
     scope per the F-Mock-7 disposition, with a rationale
     comment matching the existing `bench-internals` precedent
     at [`rust/shekyl-engine-core/Cargo.toml`](../rust/shekyl-engine-core/Cargo.toml)
     lines 223–227.

  2. **F-Mock-2 — `FaultInjecting` queue contract.** Wrapper-
     internal queue (not actor mailbox) holding `RefreshError`
     values directly per Option (i) below. Contract: FIFO
     ordering; `queued_failures(&self) -> usize` drain
     inspector per the existing
     [`MockLedger::queued_failures`](../rust/shekyl-engine-core/src/engine/test_support.rs)
     precedent; `debug_assert!`-on-Drop for non-empty queue
     (panic-on-leftover in test/debug builds); reentrance pops
     the head per the "pop head if non-empty" semantics.

  3. **F-Mock-3 + F-Mock-3-sharpening + Option (i) wrapper
     API.** The wrapper carries `type Error = RefreshError`
     (not `R::Error`) and queues `RefreshError` values
     directly, uniform across all `R`. Cross-wrapper symmetry
     justifies the choice:
     `FaultInjecting<L: LedgerEngine>` must queue `RefreshError`
     by trait necessity (per
     [`engine/traits/ledger.rs:270–273`](../rust/shekyl-engine-core/src/engine/traits/ledger.rs)
     — `apply_scan_result` returns `Result<(), RefreshError>`
     with no `Self::Error` indirection), so
     `FaultInjecting<R>` queuing `RefreshError` matches.

     **Empirical variant enumeration (per source).** Of the
     six `RefreshError` variants at
     [`engine/error.rs:148`](../rust/shekyl-engine-core/src/engine/error.rs),
     three are reachable from a `RefreshEngine` impl's
     `Self::Error` via the `From` conversion: `Cancelled`
     (unit), `Io(IoError)` (payload), and
     `InternalInvariantViolation { context: &'static str }`
     (payload constructed at the `From` impl site per
     [`engine/local_refresh.rs:368–384`](../rust/shekyl-engine-core/src/engine/local_refresh.rs)).
     Three are orchestrator-constructed only:
     `MalformedScanResult { reason }` (constructed
     **exclusively** by the merge layer at
     [`engine/merge.rs:315–451`](../rust/shekyl-engine-core/src/engine/merge.rs)
     when scan-result internal-shape invariants fail —
     superseding the doc's prior framing that grouped it with
     `Cancelled` / `Io` as trait-reachable),
     `ConcurrentMutation { wallet, result }` (constructed at
     the merge gate), and `AlreadyRunning` (constructed at the
     binary-layer single-flight). Under Option (i) direct
     injection the wrapper can inject any of the six variants
     into the orchestrator surface; for
     `InternalInvariantViolation` both direct injection
     (testing producer-returned-then-orchestrator-propagated
     path) and **cause injection** (driving causes through
     `FaultInjecting<LocalLedger>::queue_concurrent_mutation`
     per F-Mock-2 to exhaust the retry budget at orchestrator-
     side construction sites in `engine/refresh.rs`) are
     legitimate test classes.

  4. **F-Mock-4 — `MockLedger`-structurally-already-`FaultInjecting`
     verification gate anchored.** The Round 5 amendment's
     load-bearing claim ("current `MockLedger` is structurally
     already a `FaultInjecting<LocalLedger>`-shaped wrapper") is
     anchored to source at
     [`engine/test_support.rs:773–812`](../rust/shekyl-engine-core/src/engine/test_support.rs):
     `MockLedger::apply_scan_result` (line 792) pops from
     `concurrent_mutation_queue` (line 794); on empty-queue,
     delegates to the canonical `apply_scan_result_to_state`
     (line 810). Future re-readers don't have to re-verify;
     C6β scope is bounded as anticipated.

  **Two-enum architecture pin (§6.1.1).** The `RefreshEngine`
  trait carries a deliberate two-enum architecture worth
  pinning as a positive architectural reference and forward-
  template for future per-trait PRs. Producer-internal
  [`LocalRefreshError`](../rust/shekyl-engine-core/src/engine/local_refresh.rs)
  is `pub(crate)`, unit-variant-only by convention, four
  variants (`Cancelled`, `Io`, `Malformed`, `Internal`).
  Orchestrator-facing
  [`RefreshError`](../rust/shekyl-engine-core/src/engine/error.rs)
  is `pub`, payload-bearing throughout. The `From` impl
  boundary at
  [`engine/local_refresh.rs:368–384`](../rust/shekyl-engine-core/src/engine/local_refresh.rs)
  is where payload information is constructed or discarded.
  The architectural cleanness this delivers — payload
  guarantees enforced by the type system at the conversion
  boundary, not by convention at every producer return site —
  makes the trait surface auditable in a way single-enum
  architectures cannot match. The pattern is shape-applicable
  to traits whose canonical method signatures return
  `Result<_, Self::Error>` with `Self::Error: Into<OrchestratorError>`;
  it is **not** load-bearing for traits whose canonical method
  signatures return `Result<_, OrchestratorError>` directly
  (per the `LedgerEngine` precedent). Per-trait PR pre-flight
  checks include "does this trait have an impl-side
  `Self::Error` indirection, and if so, is the producer-internal
  enum unit-variant-only?" as a substrate-application check
  alongside the four-pattern no-Mock pre-flight per PR 3
  §2.1.5.

  **Test-substrate implications (two test classes named
  explicitly).** Two test classes follow from the two-enum
  architecture, both load-bearing for C6α's smoke-test coverage:

  - **Class 1 — wrapper-based trait-surface tests.** Tests
    use `FaultInjecting<R: RefreshEngine>` to inject
    `RefreshError` values directly (per Option (i) wrapper
    API); verify the orchestrator handles each variant
    correctly. Lives in C6α's new
    `fault_injecting_refresh.rs` test module plus the
    trait-dispatched `Engine` integration tests.
    Sub-properties: empty-queue passthrough; single-injection-
    then-delegation; multi-injection FIFO ordering;
    queue-drain-on-teardown (with Drop-time `debug_assert!`
    `#[should_panic]` separately verified).

  - **Class 2 — From-conversion tests against `LocalRefresh`.**
    Tests drive `LocalRefresh` directly via the `pub(crate)`
    producer-internal surface to produce each
    `LocalRefreshError` variant; verify the
    `From<LocalRefreshError>` impl produces the correct
    `RefreshError` variant. Lives in
    [`local_refresh.rs`](../rust/shekyl-engine-core/src/engine/local_refresh.rs)'s
    existing tests module per the
    [`local_refresh_error_maps_to_refresh_error`](../rust/shekyl-engine-core/src/engine/local_refresh.rs)
    test precedent; **sibling to Class 1, not a replacement**
    because the wrapper bypasses the `From` conversion by
    injecting `RefreshError` directly under Option (i).

  **Amendment-forward-pointer convention (recorded as
  meta-discipline).** The coherence pass surfaced the
  pre-Phase-0c forward-pointer gap as a **recurrence pattern**
  — the same class of finding F-Mock-3 surfaced from one
  angle, present at three sites (the Status banner's Round 2
  reframe paragraph; §3.1's two-channel error surface prose;
  §4 Phase 0c's inline comment) all carrying the Round 2
  reframe's "unit-variant-only; no payload of any kind"
  framing that the Phase 0c amendment later refined. Three
  additive forward-pointers added at those sites preserve
  each round's historical record (what was decided at that
  round) while resolving the ambiguity (what the current
  binding contract is). The convention is recorded as a
  **meta-discipline** alongside
  [`21-reversion-clause-discipline.mdc`](../.cursor/rules/21-reversion-clause-discipline.mdc)'s
  named-criteria principle: any future amendment that narrows
  or refines an earlier round's contract lands its own
  forward-pointer at the earlier site. The two disciplines
  are complementary — reversion-clauses make rejection-
  dispositions readable across substrate changes;
  forward-pointers make narrowing-amendments readable across
  layered rounds. Both are about making layered prose
  readable across time.

  **Minor dispositions (F-Mock-5 through F-Mock-8).** F-Mock-5
  adds an explicit C6β migration table mapping `MockLedger`'s
  four public test-affordance methods (`with_seed`,
  `with_seed_and_state`, `queue_concurrent_mutation`,
  `queued_failures`) to their post-migration homes and corrects
  the prior "replaces `MockLedger::new(...)`" prose error (the
  constructor is `with_seed` / `with_seed_and_state`, not
  `new`). F-Mock-6 adds a Phase 1 author commit-message-template
  note to C6γ enumerating the `MockDaemon` test affordances
  surviving the rename unchanged. F-Mock-7 confirms the
  `test-helpers` feature does not currently exist in
  [`Cargo.toml`](../rust/shekyl-engine-core/Cargo.toml) and pins
  the introduction as part of C6α's scope. F-Mock-8 enumerates
  C6α smoke-test property classes by name across the two
  test-class structure above.

  **V3.1 ledger-generator FOLLOWUPS entry (sub-pin extension
  Decision 4: coordinated `TestLedgerBuilder` substrate
  design).** The three V3.x invariant-test FOLLOWUPS entries
  (tx-validation, FCMP++ tx-pool, staking lifecycle at
  [`docs/FOLLOWUPS.md`](FOLLOWUPS.md) lines 2411–2438) share a
  common test-infrastructure need beyond what PR 4 C6β's
  `LocalLedger::from_test_blocks` covers. The sub-pin lands a
  new V3.1 substrate-design FOLLOWUPS entry pinning the
  coordinated-design disposition: build one `TestLedgerBuilder`
  / `TestBlockBuilder` / `TestTransactionBuilder` substrate
  designed **before** the first daemon Rust port lands (cost
  asymmetry from
  [`16-architectural-inheritance.mdc`](../.cursor/rules/16-architectural-inheritance.mdc)
  "cost-benefit-defer-to-later anti-pattern"); design to be
  forward-composable with PR 4 C6β's
  `LocalLedger::from_test_blocks` signature; flag the
  structurally-valid-but-semantically-stubbed middle-ground
  option in the V3.1 design conversation rather than defaulting
  to a binary "Need A or full Need B" framing.

  The sub-pin extension is **not** a round reopening: no
  Round 1–4 disposition, attack-surface pin, or commit-
  decomposition ordering is touched; only the Round 5 C6
  substrate and the layered-amendment prose are refined.
  α-disposition, F1–F13 dispositions, Round 5 amendment, and
  C0–C5 / C7 / C8 commit prose remain unchanged; the C6
  sub-decomposition (C6α / C6β / C6γ) gains the F-Mock
  dispositions inline.

  Files touched (doc-only):
  `docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md` (Status banner
  Round 5 sub-pin extension paragraph + coherence-pass
  paragraph + amendment-forward-pointer convention recording;
  three forward-pointer additions at the layered-amendment
  sites; new §6.1 paradigm pin + §6.1.1 two-enum architecture
  pin; §6 preservation list `FaultInjecting<R>` /
  `FaultInjecting<L>` / `TestDaemon` entries updated; §7.X
  C6α wrapper-definition / F-Mock-3-sharpening / F-Mock-2
  queue contract / F-Mock-7 `test-helpers` feature /
  F-Mock-8 smoke-test prose all updated; §7.X C6β migration
  table added; §7.X C6γ commit-message template note added),
  `docs/FOLLOWUPS.md` (new V3.1 coordinated `TestLedgerBuilder`
  substrate-design entry), and this CHANGELOG entry.

- **Stage 1 PR 3 (`KeyEngine`) M3a pre-flight closures landed.**
  The four open `STAGE_1_PR_3_KEY_ENGINE.md` dispositions Round 4
  deliberately deferred — the handle-model emergent attack
  surface Round 3 surfaced — closed as a coupled disposition
  cluster:

  - **§7.11 (handle persistence) = option (3) deterministic from
    ciphertext.** Handle is `cSHAKE256(view_secret || tx_hash ||
    output_index_le_bytes(8))` with customization
    `"shekyl/output-handle-v1"`, 16-byte output. The Round-3 lean
    toward (1) ephemeral was amended; the four-question coupled
    cluster collapses from this one disposition.
  - **§7.12 (handle unforgeability / A7) = cSHAKE256-based
    deterministic derivation.** A7 closes by construction
    (cSHAKE256 with `view_secret` in the input phase is a PRF in
    `view_secret` under standard assumptions). Implementation
    crate: `sha3 = "0.10"` (already a workspace dep) with the
    `zeroize` feature flag enabled, giving `Sha3State`
    wipe-on-drop discipline structurally per `35-secure-memory.mdc`.
  - **§7.10 (memory-pressure / A6) = dissolved by §7.11=(3).** No
    table; no growth target; no eviction policy.
  - **§7.13 (concurrency / Pattern-5) = dissolved by §7.11=(3).**
    No shared mutable state; pure per-call sponge-state mutation
    only.

  `STAGE_1_PR_3_MIGRATION_PLAN.md` §3.1 amended to cite the
  closures and revise the M3a scope (no `HandleTable` data
  structure; `derive_output_handle` pure function instead;
  `source_ciphertext` + `output_handle` added to
  `TransferDetails` at M3b alongside the legacy fields, with
  legacy fields removed at M3d). M3a feat branch cleared to cut.
  Documentation-only change; no code shipped.

## [3.1.0-alpha.5] - 2026-04-22

### Security

- **Retired 32-bit build targets (`v3.1.0-alpha.5`, Chore #3). Shekyl is
  now 64-bit only, on security grounds — not on maintenance grounds.**
  Shekyl's Post-Quantum primitives — `fips203` (ML-KEM-768) and
  `fips204` (ML-DSA-65), consumed on the hot path by `shekyl-crypto-pq`
  and `shekyl-tx-builder` — state their constant-time guarantees
  against native 64-bit arithmetic. On 32-bit targets the compiler
  lowers `u64` operations through compiler-emitted libgcc helpers
  (`__muldi3`, `__udivdi3`, `__ashldi3`) with no constant-time
  guarantee, plus variable-latency `u64` multiply on common 32-bit ARM
  cores (Cortex-A series). That is a CT violation introduced by the
  code generator, not the source — exactly the class source-level CT
  audits cannot catch. **KyberSlash (Bernstein et al., 2024)**
  demonstrates remote-timing key recovery against ostensibly
  constant-time Kyber implementations broken by non-CT division; the
  Cortex-M4 Kyber timing-attack line (2022–2024) is supporting
  context. **The X25519+ML-KEM hybrid does not save us**: "hybrid is
  secure if either half is secure" protects against algorithmic
  breaks, not side-channel breaks — if ML-KEM leaks its secret via
  timing on 32-bit, X25519 is offline-attackable against captured
  ciphertexts with unlimited attacker time. **FCMP++ proof generation
  has not been audited for constant-time properties on 32-bit
  targets, and Shekyl will not take responsibility for that audit
  across all 32-bit toolchains we would otherwise ship** (policy
  framing, not speculation). `MDB_VL32` (LMDB's 32-bit paged-mmap
  mode) and the `src/crypto/slow-hash.c` 32-bit software fallback are
  untested consensus-adjacent storage and PoW paths respectively.

  **32-bit Shekyl wallet users were at meaningfully elevated risk of
  key extraction compared to 64-bit users; supporting the platform
  was a tacit lie about the security posture of users on it.** This
  is the correction.

  **Node-only operation is also retired.** A future contributor will
  argue "I just want to run a 32-bit pruned node on a Pi, I'm not
  doing wallet operations, the CT argument doesn't apply." That is
  partially true — node code does not touch secret PQC keys. But
  `MDB_VL32` paging against a multi-GB chain makes sync time measured
  in weeks (not a supported posture), and shipping a 32-bit daemon
  binary creates a reasonable user expectation that wallet operation
  is supported, which it is not. The operational complexity of
  splitting "32-bit daemon supported, 32-bit wallet refused"
  outweighs any benefit.

  **Four independent tripwires (defense-in-depth):**

  1. **Tripwire D — `CMakeLists.txt`.** C++-side configure gate:
     `message(FATAL_ERROR …)` on `NOT CMAKE_SIZEOF_VOID_P EQUAL 8`,
     placed before any `find_package` / `include` /
     `add_subdirectory` so configure fails early with the CT
     argument in the message. Exercised on every PR to `dev` by
     `.github/workflows/cmake-gate-test.yml` + `tests/cmake-gate-test/`,
     which drives CMake with a fake 32-bit toolchain and asserts
     non-zero exit, gate message + KyberSlash citation in stderr,
     and no `find_package` chatter (so a PR that moves the gate
     below a probe also fails the test).
  2. **Tripwire A — `rust/shekyl-crypto-pq/src/lib.rs`.** Primary
     `compile_error!` on `not(target_pointer_width = "64")`, since
     this crate is the ML-KEM-768 / ML-DSA-65 consumer. The gate
     that fires in practice on a 32-bit Rust build.
  3. **Tripwire B — `rust/shekyl-ffi/src/lib.rs`.**
     Structural-not-observable: duplicated by design to preserve
     the refusal at the FFI seam under a future refactor that
     might split this crate from `shekyl-crypto-pq`. **Do not
     delete this gate on the grounds that it "never fires" — its
     value is structural, not observable**; see the comment block
     on the tripwire and `docs/audit_trail/RESOLVED_260419.md`
     §"Chore #3".
  4. **Tripwire C — `rust/shekyl-tx-builder/src/lib.rs`.** Direct
     `fips204` (ML-DSA-65) consumer on the transaction-signing hot
     path; independent of Tripwire A so a future refactor that
     narrows the dependency shape cannot silently drop the
     refusal.

  **Deleted, not `#if 1`-ed out.** Every 32-bit-conditional block
  removed in this chore was deleted outright. Dead
  `#if ARCH_WIDTH == 64` / `#ifdef __i386__` / `#ifdef __arm__`
  scaffolding invites future contributors to assume a meaningful
  32-bit alternative exists somewhere and reason about it; the
  whole point of the retirement is to foreclose that reasoning.

  **What went away.** Build system:
  `cmake/32-bit-toolchain.cmake`; the six 32-bit `Makefile` targets
  that actually existed on `dev` (`release-static-win32`,
  `debug-static-win32`, `release-static-linux-i686`,
  `release-static-linux-armv6`, `release-static-linux-armv7`,
  `release-static-android-armv7`); `BUILD_64` / `DEFAULT_BUILD_64` /
  `ARCH_WIDTH` / `ARM_TEST` / `ARM6` / `ARM7` machinery and the
  Clang+32 `libatomic` workaround in the root `CMakeLists.txt`; the
  `-D BUILD_64=ON` argument on all remaining 64-bit `Makefile`
  targets; `ARCH_WIDTH != 32` conditional in
  `src/blockchain_utilities/blockchain_import.cpp` (body retained,
  guard deleted); `-D MDB_VL32` in
  `external/db_drivers/liblmdb/CMakeLists.txt` (vendored `mdb.c`
  `MDB_VL32` code paths are now unreachable in Shekyl builds and
  deliberately left unpatched in-tree — see
  `docs/VENDORED_DEPENDENCIES.md` §"`MDB_VL32` — 32-bit retirement
  note" for the future-update drill); `contrib/depends/` toolchain
  template `i686` / `armv7` / `BUILD_64` / `LINUX_32` branches,
  package recipes for `boost` / `openssl` / `android_ndk` / the
  arch-asymmetric `_cflags_mingw32+="-D_WIN32_WINNT=0x600"` line in
  `unbound.mk`, `README.md` host list, `.gitignore` `i686*` / `arm*`
  entries, `packages.md` example; `cmake/BuildRust.cmake` all
  non-64-bit `CMAKE_SYSTEM_PROCESSOR` branches; gitian configs
  (`gitian-linux.yml`, `gitian-android.yml`, `gitian-win.yml`)
  32-bit hosts and MinGW alternatives.

  C/C++ conditionals: `src/common/compat/glibc_compat.cpp`
  `__wrap___divmoddi4` block and `__i386__`/`__arm__` glob symver
  arms (plus the corresponding `-Wl,--wrap=__divmoddi4` linker flag
  in the root `CMakeLists.txt`); `src/crypto/slow-hash.c` outer
  guard narrowed from `__arm__ || __aarch64__` to `__aarch64__` and
  the 32-bit fallback `cn_slow_hash_{allocate,free}_state` stubs
  removed; `src/crypto/CryptonightR_JIT.{c,h}`,
  `src/crypto/CryptonightR_template.h` x86 gates narrowed from
  `__i386 || __x86_64__` to `__x86_64__`;
  `src/cryptonote_basic/miner.cpp` FreeBSD APM gates narrowed from
  `__amd64__ || __i386__ || __x86_64__` to
  `__amd64__ || __x86_64__`;
  `src/blockchain_db/lmdb/db_lmdb.h` `__arm__` `DEFAULT_MAPSIZE`
  branch removed; `src/blockchain_db/lmdb/db_lmdb.cpp`
  `MISALIGNED_OK` gate narrowed to `__x86_64` only.
  **Disambiguation:** `tests/hash/main.cpp:192,206`
  `<emmintrin.h>` SSE-intrinsic gates are x86_64 arch gates, not
  32-bit gates, and are **not** deleted — an earlier draft of
  `STRUCTURAL_TODO.md` lumped them with the 32-bit retirement
  imprecisely.

  Rust: three `compile_error!` tripwires (A/B/C, above);
  `rust/shekyl-oxide/crypto/helioselene/benches/helioselene.rs`
  `target_arch = "x86"` branches collapsed to `x86_64` only.

  CI: `.github/workflows/depends.yml` ARM v7 stub replaced with a
  pointer to this chore; new `.github/workflows/cmake-gate-test.yml`
  + `tests/cmake-gate-test/` enforcing Tripwire D placement.

  Docs: `README.md`, `docs/INSTALLATION_GUIDE.md`,
  `docs/RELEASING.md`, and `docs/COMPILING_DEBUGGING_TESTING.md`
  are now 64-bit-only; `docs/VENDORED_DEPENDENCIES.md` carries the
  `MDB_VL32` future-update note; `docs/STRUCTURAL_TODO.md` §"32-bit
  targets cannot safely run Shekyl" is the canonical reviewer-facing
  copy; `docs/audit_trail/RESOLVED_260419.md` §"Chore #3
  (v3.1.0-alpha.5) — 32-bit target retirement: security closure"
  carries the closure narrative.

  **Supported architectures going forward:** `x86_64`, `aarch64`
  (Linux and Apple Silicon), `riscv64` (Gitian). `armhf`, `armv7`,
  `armv6`, `i686`, `i386` are out of scope — not deferred, not
  "maybe later," out of scope. Users on 32-bit hardware must not
  run Shekyl wallets; node operation on 32-bit hardware is not
  supported either. Operators on ARM32 / i686 hardware should plan
  a migration to 64-bit before upgrading past `v3.1.0-alpha.5`.

  *Maintenance benefits are real but secondary:* every 32-bit
  carve-out in `STRUCTURAL_TODO.md` §"bit-width carve-out without
  coverage" is eliminated in one chore, closing the dead-scaffolding
  pattern that motivated the §.

### Changed

- **Shekyl Foundation institutional release-signing key adopted.**
  `v3.1.0-alpha.5` is the first release signed by the Shekyl Foundation
  institutional signing key (subkey fingerprint `3778 B4C8 63C6 1512
  B5FC 2203 6914 D748 23DD A8DC`, long ID `6914D74823DDA8DC`; primary
  fingerprint `F5F7 5A47 70C9 4FE1 D5A5 AE59 844E 424F 9866 4F44`,
  long ID `844E424F98664F44`). The primary certification key is held
  offline; the signing subkey is hardware-backed (OpenPGP applet) with
  a two-year expiry (2028-04-18) enforcing a rotation cadence.

  Previous alphas (`v3.1.0-alpha.3`, `v3.1.0-alpha.4`) were signed with
  Rick Dawson's personal maintainer key and remain verifiable against
  that key — prior signatures are not invalidated. Going forward,
  maintainer keys remain a valid *additive* fallback for release-tag
  signing when the institutional key is unavailable (documented
  exception, not default path); they continue to be the right tool for
  commit signing, where authorship-attribution is the question.

  `docs/SIGNING.md` is rewritten as the canonical, self-contained
  reference: both key blocks inline (no loose `.asc` files), an
  explicit step-by-step release-tag signing ceremony with pre-flight
  checks, expected-output annotations, a failure-mode table, and a
  separate downstream-verification path. `docs/RELEASING.md` §3
  (tag creation) now points at the SIGNING.md ceremony and captures
  the minimum command sequence (`gpg --card-status` → `git tag -u
  6914D74823DDA8DC -a -s …` → `git verify-tag` before push) as a
  summary, not a replacement. Resolves the `docs/SIGNING.md`
  §"Future: Foundation institutional signing key" deferral that had
  been carried forward from V3.1 on the premise that institutional
  signing required ceremony (offline primary, hardware-backed subkey,
  bounded expiry) before it added value over a plain personal-key
  setup; those prerequisites are now in place.

- **Logging output format (breaking change, all binaries).**
  Chore #2 of the `easylogging++` retirement completes the
  migration started in V3.1 alpha.4: `shekyld`, `shekyl-wallet-rpc`,
  `shekyl-cli`, and every other in-tree binary now emit through the
  same Rust `tracing-subscriber` stack. The default formatter is
  `tracing_subscriber::fmt::layer`, and its line shape is *not*
  byte-compatible with the vendored `easylogging++` layout it
  replaces:

  ```
  # Before (easylogging++ default format string):
  2026-04-19 14:23:11.042    INFO    global   src/daemon/main.cpp:322    Shekyl 'Codename' (v3.1.0-alpha.3-release)

  # After (tracing-subscriber fmt::layer default):
  2026-04-19T14:23:11.042123Z  INFO global: Shekyl 'Codename' (v3.1.0-alpha.3-release)
  ```

  Timestamps are RFC 3339 UTC (not local time with microseconds),
  level tokens are full words (`ERROR` / `WARN` / `INFO` /
  `DEBUG` / `TRACE`, not the `E` / `W` / `I` / `D` / `V` single
  letters), the target appears as a structured `target:` field, and
  source location (`file:line`) is elided by default.
  Log-scraping tooling that parsed the prior format byte-for-byte
  must be updated; `docs/USER_GUIDE.md` §"Logging" documents the
  new shape for operators.

- **`MONERO_LOGS` → `SHEKYL_LOG` (env-var rename).** Every in-tree
  consumer of `MONERO_LOGS` now reads `SHEKYL_LOG` instead. This
  closes the C++-side half of the per-`.cursor/rules/93-legacy-
  symbol-migration.mdc` rename — Chore #1 (V3.1 alpha.4) already
  migrated the Rust binaries. `SHEKYL_LOG` accepts the same
  `tracing-subscriber`-compatible directive grammar as Chore #1
  (bare levels, per-target overrides, module-qualified targets)
  *plus* the legacy easylogging++ category grammar
  (`net.p2p:DEBUG,wallet.wallet2:INFO`, numeric `0..=4` presets,
  `+`/`-` modifiers) routed through the Rust-side translator. The
  legacy grammar is preserved on purpose: the ~1,345 `MINFO` /
  `MDEBUG` / etc. call sites in `src/` and `contrib/` ship
  category strings in that grammar, and operator runbooks doing
  `SHEKYL_LOG='*:DEBUG,net.p2p:TRACE'` must keep working with no
  downstream edits.

  **Operator action required before upgrading past V3.x alpha.0:**
  scripts, systemd units, Docker/Podman compose files, or launch
  plists that set `MONERO_LOGS=...` will silently become no-ops.
  Add a `SHEKYL_LOG=...` line alongside each `MONERO_LOGS=...`
  line before cutting over (both can coexist on pre-Chore-#2
  builds so the rollover is safe).

- **Log target separator normalized to `::`.** Targets that used to
  render in the easylogging++ output as `net.p2p` / `daemon.rpc`
  now appear as `net::p2p` / `daemon::rpc` in every
  `tracing-subscriber`-rendered line. The FFI boundary
  (`shekyl_log_emit` / `shekyl_log_level_enabled` in
  `rust/shekyl-logging/src/ffi.rs`) rewrites dot-separated category
  names into Rust-idiomatic module-path form before handing the
  event to the dispatcher, matching the form the legacy-grammar
  translator emits into EnvFilter directives
  (`net::p2p=trace`). Without this, every category-scoped emit
  from the C++ shim (`MCINFO("net.p2p", …)`,
  `MCLOG(level, "daemon.rpc", …)`, …) would silently fall through
  to the bare default clause because EnvFilter compares target
  strings byte-for-byte. Operator-supplied `SHEKYL_LOG` directives
  continue to accept both spellings — the legacy-grammar translator
  rewrites `.` to `::` on the way in, so
  `SHEKYL_LOG='*:WARNING,net.p2p:TRACE'` and
  `SHEKYL_LOG='warn,net::p2p=trace'` behave identically. Only the
  rendered output changes. Log-scraping pipelines that grep for
  `target=net\.p2p` need to grep for `target=net::p2p` (or, per
  the format-break entry above, `net::p2p:` at the front of the
  fields block) instead.

- **`shekyld` default log sink moved to `~/.shekyl/logs/`.**
  Under `chore/cxx-logging-consolidation`, the daemon's default
  `--log-file` path changed from `<data_dir>/shekyld.log` (next to
  the blockchain database) to `~/.shekyl/logs/shekyld.log`,
  resolved through the Rust FFI's `shekyl_log_default_path`.
  Testnet/stagenet/regtest runs use the suffixed base names
  `shekyld-testnet.log` / `shekyld-stagenet.log` /
  `shekyld-regtest.log` so the three networks can run
  side-by-side without clobbering each other's log. Rotation
  defaults to ~100 MB × 50 archives, and the live file plus
  every rotated archive are forced to POSIX mode `0600` on Unix
  — operator-tunable permissions are not a supported knob.
  Operators who want to keep the legacy next-to-data-dir layout
  can pass `--log-file` explicitly; the override path is
  unchanged.

- **CMake Python discovery modernized (Chore #3 follow-up).**
  `include(FindPythonInterp)` at the top of `CMakeLists.txt` is
  replaced with `find_package(Python3 COMPONENTS Interpreter REQUIRED)`
  as a single, early, authoritative discovery pass; two downstream
  shadowing call sites (`find_package(Python3 ...)` before the
  economics-params generator and `find_package(PythonInterp)` before
  the tests subdir) are deleted. The legacy `PYTHON_EXECUTABLE` and
  `PYTHONINTERP_FOUND` variables are aliased post-discovery so
  consumers under `tests/difficulty/CMakeLists.txt`,
  `tests/block_weight/CMakeLists.txt`, and the `cmake/CheckTrezor.cmake`
  fallback arm continue to work without a cascading migration. The
  `cmake_policy(SET CMP0148 OLD)` migration-debt carve-out that
  preserved the deprecated module on CMake ≥ 3.27 is removed in the
  same commit — there is no legacy module left to un-deprecate.
  Resolves the Copilot review comment on PR #15; addresses
  `docs/CHANGELOG.md` V3.1.0-alpha.3 entry's own callout of the
  same migration debt.

### Removed

- **`MONERO_LOG_FORMAT` env var (no replacement).** The custom
  format string that `MONERO_LOG_FORMAT` used to seed on the
  easylogging++ tree is no longer a tunable. Formatting is owned
  by the Rust subscriber's layer stack (`fmt::layer`,
  optionally stacked with `tracing-subscriber` feature flags at
  build time), not by an operator env var. There is no V3.x
  alpha.0 replacement and no intent to re-add one — if you have
  a log-format requirement that RFC 3339 UTC does not satisfy,
  file an issue rather than patching the format string.

- **Vendored `external/easylogging++/` tree.** Deleted in
  `ded9875b6`. All call sites that reached `el::Logger` /
  `el::Configurations` / `el::base::Writer` etc. directly have
  been rewritten to route through the `shekyl_log_emit` /
  `shekyl_log_level_enabled` FFI in `src/shekyl/shekyl_log.h`.
  The `el::` namespace survives only as a thin typedef-only
  compatibility shim in `contrib/epee/include/misc_log_ex.h`
  (`el::Level`, `el::Color`, `el::base::DispatchAction`) so the
  existing `MINFO` / `MDEBUG` / `MWARNING` / `MCINFO` macros
  expand without touching the ~1,345 call sites. Closes the
  `STRUCTURAL_TODO.md` §"Replace easylogging++ with a maintained
  logger" item (both chores); swept narrative in
  `docs/audit_trail/RESOLVED_260419.md`.

- **`src/rpc/rpc_version_str.{h,cpp}` and its unit test
  (`tests/unit_tests/rpc_version_str.cpp`), inherited from Monero.** The
  daemon constructs its own version string deterministically in
  `cmake/GitVersion.cmake` from the annotated tag on HEAD, then emits
  `SHEKYL_VERSION_FULL` over RPC as an opaque value. The validator
  regex was a Monero-era sanity check that parsed that string back
  against a hardcoded pattern — "protecting" consumers from a failure
  mode that the CMake construction logic already makes impossible.

  Exposed on the `v3.1.0-alpha.3` tag-push CI run
  ([#394](https://github.com/Shekyl-Foundation/shekyl-core/actions/runs/24637252528),
  `test-ubuntu` matrix): on a tagged build, `SHEKYL_VERSION_FULL`
  resolves to `3.1.0-alpha.3-release`, and the regex (adapted from
  Monero but never taught SemVer 2.0.0 §9 dotted pre-release
  identifiers) rejects the dot in `-alpha.3`. Every tagged release
  using `-alpha.N` / `-beta.N` / `-rc.N` numbering would trip the same
  assertion — so every tagged release with this file in tree is
  inherently broken, which is enough of a tell that the file is wrong
  to have on disk.

  Per `.cursor/rules/60-no-monero-legacy.mdc` "ask why is this here?"
  — this is an inherited assertion against a Shekyl-owned invariant.
  The invariant is enforced by `cmake/GitVersion.cmake`; the daemon
  should not re-parse its own output to re-check it. `rpc_command_executor.cpp`
  keeps the empty-string guard (`if (res.version.empty())`) so the CLI
  still reports "version not available" when the RPC response lacks a
  version, but no longer attempts to format-validate the string it
  receives.

### Fixed

- **Tagged-release `ci/gh-actions/cli` jobs on `test-ubuntu` matrix.**
  Follows from the `rpc_version_str` removal above. `v3.1.0-alpha.3`
  shipped with the daemon, wallet, and source archive built cleanly,
  but its tag-push CI ran red on this single unit test; `v3.1.0-alpha.4`
  will be the first alpha whose tag-push CI is green end-to-end.

- **Tripwire D processor regex broadened; gate-test probe assertion
  tightened (Chore #3 fixup).** The `CMAKE_SYSTEM_PROCESSOR` arm of
  the 64-bit-only gate in `CMakeLists.txt` previously used
  `armv[67]l?`, which only matches `armv[67]` and `armv[67]l` exactly —
  real toolchains also emit `armv7-a`, `armv7a`, `armv7ve`, `armv7hf`,
  `armv6kz`, `armv5te`, etc., which are all 32-bit ARM profiles.
  Broadened to `armv[567].*` so the "defense-in-depth" half of the
  predicate (which fires when `CMAKE_SIZEOF_VOID_P` is misreported as 8
  on a 32-bit target) actually covers those variants. 64-bit names
  (`aarch64`, `arm64`, `armv8*` in AArch64 mode) remain outside the
  pattern by construction. Companion tightening in
  `tests/cmake-gate-test/run.sh`: the probe-chatter assertion now
  also catches `-- Performing Test ...` (from `CheckCCompilerFlag` /
  `CheckCXXCompilerFlag` / `CheckLinkerFlag`), matching the set of
  modules actually relocated below the gate; `-- Detecting C/CXX
  compiler ABI info` is deliberately NOT caught because those lines
  come from `project()` itself, which runs before the gate by
  construction (the gate's `CMAKE_SIZEOF_VOID_P` predicate is
  populated by `project()`'s own compiler probe). Resolves the
  second Copilot review on PR #15.

- **`contrib/depends` Win64 unbound build restored (Chore #3 fixup).**
  The `$(package)_cflags_mingw32+=-D_WIN32_WINNT=0x600` line in
  `contrib/depends/packages/unbound.mk` was deleted in the Chore #3
  build-system commit under the mistaken framing of "arch-asymmetric
  32-bit MinGW carve-out." The `_mingw32` suffix in `contrib/depends`
  is the OS segment of the host triple, not an architecture gate: it
  matches every `*-w64-mingw32` host including `x86_64-w64-mingw32`.
  Unbound 1.19.1's `util/netevent.c` uses `WSAPoll` / `POLLOUT` /
  `POLLERR` / `POLLHUP` unconditionally and requires
  `_WIN32_WINNT >= 0x0600` to be defined before `<winsock2.h>` is
  included; the vendored `x86_64-w64-mingw32` toolchain does not
  default this the way MSYS2 pacman toolchains do, so the deletion
  broke the `depends.yml` Win64 lane (the `build.yml` MSYS2 and MSVC
  lanes use different toolchain pathways and stayed green). Line
  restored with the scope unchanged — only one MinGW host remains
  after Chore #3, and the flag belongs on it.

### Known regressions

- **`MLOG_SET_THREAD_NAME(label)` no longer reaches the log stream.**
  The macro still compiles and still evaluates its argument (so
  `-Wunused-value` stays quiet at the call sites), but the label
  (`[SRV_MAIN]` from `abstract_tcp_server2.inl`, `[miner N]` from
  `miner.cpp`, `DLN` from `download.cpp`) does not appear in emitted
  events. easylogging++ used this hook to stamp a semantic label
  into every subsequent log line; the Rust `tracing-subscriber`
  formatter reads the OS-level thread name instead (via the
  platform `pthread_getname_np` / `GetThreadDescription` path), and
  those names are not being populated in Chore #2. Restoring
  semantic thread labels — either by teaching the C++ shim to call
  `pthread_setname_np` + Windows equivalents, or by routing the
  label through the Rust subscriber as a `span` field — is tracked
  as a V3.2 follow-up in `docs/FOLLOWUPS.md`. The impact is
  diagnostic only: thread-scoped log lines now show a generic
  thread ID instead of the human-readable label the prior format
  carried.

## [3.1.0-alpha.3] - 2026-04-19

### Added

- **Release signing policy and maintainer keys (`docs/SIGNING.md`).**
  New document establishing that every release tag from `v3.1.0-alpha.3`
  onward is a signed annotated tag created with `git tag -a -s`. It
  records the initial maintainer signing key (Rick Dawson, ed25519
  `FEFEC7EF9952D40C`, ASCII-armored public key embedded in the doc so
  downstream verifiers can import it from the repo without trusting a
  keyserver lookup), and documents verification with `git verify-tag`,
  the reproducible-build cross-check that tag verification does not
  subsume, procedures for adding new maintainer keys, rotation,
  retirement, revocation, key hygiene expectations (passphrase,
  offline revocation certificate, hardware token or encrypted
  storage, GitHub registration), and the rationale for GPG over SSH
  signing or Sigstore at this stage. Earlier alpha tags
  (`v3.1.0-alpha.1`, `v3.1.0-alpha.2`) predate this policy and are
  not signed; their authenticity is established by branch topology
  and reproducible Guix builds.

### Changed

- **Branch policy mandates signed annotated release tags and
  non-fast-forward merges from `dev` to `main`.**
  `.cursor/rules/06-branching.mdc` was updated to require that `main`
  advance only via a merge commit (`git merge --no-ff dev`, GitHub
  "Create a merge commit") with a signed annotated tag placed on the
  resulting merge commit. Fast-forward, rebase-and-merge,
  squash-and-merge, and force-push to `main` are now explicitly
  forbidden. The rule cross-links to `docs/SIGNING.md` at both the
  Hard rule 1 mention and the Release flow step 4 mention so a
  maintainer reading the policy lands on the signing doc. A new
  "Rationale (why merge commit, not fast-forward)" section was added
  to capture the reasoning so the decision is not re-litigated each
  cycle.

- **`docs/FOLLOWUPS.md` tracks Shekyl Foundation institutional
  signing key as V3.1.x+ item.** Records the V3.1 decision: release
  signing uses maintainer keys, not an institutional Foundation key,
  until the Foundation has multi-maintainer operational structure
  (two or more active release maintainers). Cross-referenced from
  `docs/SIGNING.md` §"Future: Foundation institutional signing key".

### Security

- **Bump `cryptography` from `44.0.2` to `46.0.6`** in
  `tools/reference/requirements.txt` to clear two Dependabot advisories
  indexed 2026-04-13:
  - [GHSA-r6ph-v2qm-q3c2](https://github.com/advisories/GHSA-r6ph-v2qm-q3c2)
    (high): missing subgroup validation for SECT curves could allow a
    small-subgroup attack during ECDH.
  - [GHSA-m959-cc7f-wv43](https://github.com/advisories/GHSA-m959-cc7f-wv43)
    (low): incomplete DNS name constraint enforcement on peer names.

  **Not exploitable against Shekyl users.** `cryptography` is pulled in
  only by `tools/reference/derive_output_secrets.py`, a developer-only
  HKDF test-vector generator that never ships in any binary and is not
  on a consensus path at runtime. Inspection shows the
  `cryptography.hazmat.primitives.{hashes,kdf.hkdf}` imports in that
  script are unused — all HKDF logic is hand-rolled with stdlib
  `hmac`/`hashlib` — so the bump cannot change its output. Verified by
  regenerating `docs/test_vectors/PQC_OUTPUT_SECRETS.json` under the
  new version in a clean venv; SHA-256 matches byte-for-byte
  (`1159cb6de2ce3fa4af5d7a8f88eac71ed35c8f00ebf297a4d9259439b6477163`).

- **Accept seven `rand 0.8.5` Dependabot alerts as risk-tolerated.**
  [GHSA-cq8v-f236-94qc](https://github.com/advisories/GHSA-cq8v-f236-94qc)
  ("Rand is unsound with a custom logger using rand::rng()") indexes
  against the five workspace crates that pin `rand = "0.8"` plus two
  `Cargo.lock` files. CVSS is 0 on all seven; the actual exploit
  requires calling `rand::rng()` (a 0.9+ thread-local RNG API that
  does not exist in 0.8) while a custom `log::Log` implementation is
  installed. Shekyl uses `rand::rngs::OsRng` directly and
  `rand_chacha::ChaCha20Rng::from_seed` for deterministic derivation,
  and the daemon installs no custom `log::Log`, so no Shekyl code
  path reaches the vulnerable code. Migrating to `rand = "0.9"`
  cascades into bumping `curve25519-dalek` 4 → 5 plus several other
  crypto crates; per `.cursor/rules/20-rust-vs-cpp-policy.mdc` that
  is a planning activity with its own design doc and review cycle,
  tracked in `docs/FOLLOWUPS.md` §"rand 0.9 migration and
  curve25519-dalek 5 cascade" with target V3.1.x. Alerts #3 through
  #9 dismissed on GitHub with reason "risk tolerated" and a link to
  the follow-up.

### Changed

- **`wallet2_ffi` no longer carries wallet-directory state.** Removed
  `wallet2_ffi_set_wallet_dir` and the `wallet_dir` field on
  `wallet2_handle`. The four wallet-file FFI entry points
  (`wallet2_ffi_create_wallet`, `wallet2_ffi_open_wallet`,
  `wallet2_ffi_restore_deterministic_wallet`,
  `wallet2_ffi_generate_from_keys`) now take a full `wallet_path`
  parameter in place of the bare `filename` that was joined with
  `wallet_dir` using a hardcoded `"/"` separator. Path construction was
  inherited Monero `wallet_rpc_server` scaffolding and produced
  mixed-separator paths on Windows (`C:\Users\x\...\...//My Wallet.keys`).
  Callers now join paths in Rust via `PathBuf::join`, which is
  platform-correct on every target. The legacy C++
  `wallet_rpc_server.cpp` keeps its own `wallet_dir` state and is
  unaffected — it does not go through the FFI. The `shekyl-cli`
  `WalletContext` now holds the directory and joins filenames before
  each call; the `shekyl-wallet-rpc` Rust shim keeps
  `ServerConfig.wallet_dir` for the V3.2 cutover when its handlers
  will own wallet-file creation. `validate_filename` was narrowed and
  renamed to `validate_wallet_path` (empty-path check only) —
  path-component validation is the caller's responsibility now that
  the caller also owns the directory.

- **Nightly `proptest-exhaustive` job tuned and extended to `dev`.** Dropped
  `PROPTEST_CASES` from `1_000_000` to `200_000` — the old value could not
  finish inside the 30-minute runner cap on `ubuntu-latest` (ML-KEM-768
  keygen per case dominates wall time, the run was being cancelled not
  failed). Raised `timeout-minutes` to `180` so the job has real headroom,
  and added a branch matrix `[main, dev]` with per-branch cache keys so
  nightly coverage tracks both active histories instead of only the default
  branch. Actual elapsed time is surfaced via the job's `::notice::`
  annotation so the 200k / 180m bracket can be tightened once we have real
  data. See `.github/workflows/nightly.yml`.

## [3.1.0-alpha.2] - 2026-04-17

> Retroactive CHANGELOG entry. The v3.1.0-alpha.2 tag was created without
> promoting `[Unreleased]` first; the bullets below were subsequently
> split out from `[Unreleased]` during the alpha.3 release cycle. The
> split is based on the commit range `v3.1.0-alpha.1..v3.1.0-alpha.2`;
> content is verbatim from the original `[Unreleased]` copy and has
> not been edited retrospectively.

### Removed

- **Daemonizer layer.** Deleted `src/daemonizer/` (POSIX `fork()` detach,
  Windows Service Control Manager registration, console-control glue)
  and the four thin wrapper classes in `src/daemon/` (`t_core`,
  `t_protocol`, `t_p2p`, `t_rpc`) plus the executor shim. Background
  execution is now delegated to systemd (Linux), launchd (macOS), Task
  Scheduler (Windows), or the Tauri sidecar (GUI wallet); in-process
  forking and Windows service registration were untested code paths
  touching privilege boundaries and file-descriptor lifetimes, so their
  removal is a security improvement in addition to an audit-surface
  reduction. The removal also breaks the circular include chain where
  `daemon/command_line_args.h` transitively pulled `windows.h` into
  most of the codebase. Closes FOLLOWUPS.md §"windows-daemonizer-cleanup"
  and STRUCTURAL_TODO.md §"Daemonizer removal".
- **Daemonizer CLI flags:** `--detach`, `--pidfile`, `--install-service`,
  `--uninstall-service`, `--start-service`, `--stop-service`,
  `--run-as-service`. Both `shekyld` and `shekyl-wallet-rpc` accept
  these only long enough to print a migration message pointing at
  platform service managers (see `src/common/removed_flags.{h,cpp}`,
  marked `TODO(v3.2)` for deletion alongside the `shekyl-wallet-rpc`
  Rust cutover). `--non-interactive` is preserved in both binaries.

### Changed

- **Daemon orchestration class renamed.** `daemonize::t_daemon` is now
  `daemonize::Daemon` in `shekyld`, and `shekyl-wallet-rpc`'s unrelated
  inline class is now `WalletRpcDaemon`. The two binaries no longer
  share a type name, clarifying audit scope and the V3.2 Rust cutover
  plan.
- **Default data directory resolution moved to `src/common/`.** The
  admin-vs-user `CSIDL_*` branching formerly in `daemonizer` now lives
  in `common/daemon_default_data_dir.{h,cpp}`, preserving the exact
  path `shekyld` resolved before V3.1. Pinned by a new
  `daemon_default_data_dir` unit test so a future refactor cannot
  silently point operators at an empty data directory.
- MSVC CI job now builds `--target daemon wallet` instead of just
  `--target wallet`, matching what the GUI wallet release workflow
  actually compiles. Future MSVC regressions in daemon code will be
  caught in shekyl-core CI rather than surfacing in the GUI wallet
  release after an hour of compilation.

### Fixed

- Fixed probabilistic flake in
  `shekyl-crypto-pq::multisig_receiving::tests::scan_wrong_participant_ciphertext_fails`.
  The view tag hint is a single byte by design (fast scanner pre-filter),
  so a wrong-ciphertext decapsulation had ~1/256 chance of producing a
  hint that collided with the published one, causing the test's
  rejection assertion to fail. Test now retries keypair generation
  (bounded to 64 attempts) until the wrong-ciphertext hint actually
  differs, so the rejection path is exercised deterministically. No
  protocol or code change; scan semantics are unchanged.
- Made all `src/daemon/` headers self-contained for MSVC portability:
  `protocol.h` (6 missing includes), `p2p.h` (2), `daemon.h` (2),
  `rpc.h` (2). These headers relied on include ordering from their
  callers, which GCC/Clang tolerated but MSVC rejects.
- Fixed `#ifdef` inside `MERROR()` macro argument in `core_rpc_server.cpp`
  (undefined behavior, C2059 on MSVC). Replaced with literal function name.
- Explicitly captured `handshake` in lambda in
  `abstract_tcp_server2.inl` (C3493 on MSVC).
- Explicitly captured `credits_per_hash_threshold` in lambda in
  `core_rpc_server.cpp` (C3493 on MSVC).
- SFINAE-constrained `network_address` template constructor in
  `net_utils_base.h` to prevent MSVC eager instantiation (C2039).

## [3.1.0-alpha.1] - 2026-04-15

First public alpha release. First green CI in repository history.

This release establishes the Shekyl versioning scheme: software versions
follow SemVer independently per repo; the protocol version is a separate
integer (`protocol_version = 3`). See `docs/VERSIONING.md` for the full
scheme. The version jump from prior tags (v3.0.x-RC series) to 3.1.0
reflects the addition of FROST-style multisig to the feature set.

### Highlights

- **FCMP++ end-to-end test suite passing.** The full prove-sign-verify
  pipeline works across C++ and Rust via FFI, validated by 10-iteration
  randomized round-trip tests and C++ unit tests on Ubuntu 22.04/24.04,
  Arch Linux, macOS, and Windows.

- **Five FCMP++ integration bugs fixed.** Root causes documented in
  `docs/FOLLOWUPS.md` audit trail: FFI depth/layers off-by-one, branch
  extraction loop bound, missing point-to-scalar conversion, leaf count
  off-by-one, key image y-normalization breaking batch verification.
  Additionally, a sixth bug (FFI depth-to-layers convention ambiguity)
  was found and fixed during CI stabilization.

- **V3.1 multisig protocol specified and implemented.** FROST-style
  coordinator-less multisig with hybrid PQC signing, specified in
  `docs/PQC_MULTISIG.md` and wire format in
  `docs/SHEKYL_MULTISIG_WIRE_FORMAT.md`. 93 unit tests, 19 integration
  tests, 11 fuzz harnesses.

- **Versioning scheme established.** `docs/VERSIONING.md` defines SemVer
  for software versions and a separate integer protocol version.
  `SHEKYL_PROTOCOL_VERSION` constant added to `cryptonote_config.h`,
  exposed via `--version` output and `/get_info` RPC.

## Unreleased

### ✨ Added

- **PQC Multisig V3.1: equal-participants protocol implementation.**
  Full implementation of the coordinator-less multisig protocol as
  specified in `PQC_MULTISIG.md`. Key components:
  - `MultisigKeyContainer` v1.1 with `spend_auth_version` field and
    `multisig_group_id` v1.1 (includes version byte)
  - `rotating_prover_index`: cryptographic hash-based prover assignment
  - 8 HKDF-derived key/nonce labels for domain-separated derivation
  - `construct_multisig_output_for_sender`, `scan_for_multisig_output`,
    `validate_multisig_output_i7` for output lifecycle
  - `GriefingTracker`: per-output cost bounding for invalid outputs
  - `shekyl1m` Bech32m address format with file-based handling and
    3-representation fingerprint
  - `SpendIntent`: 14-check validation pipeline (structural, temporal,
    chain state, balance)
  - `ProverOutput`, `SignatureShare`, `ProverReceipt`: prover and
    signing flow types with equivocation detection
  - Honest-signer invariants I1–I7 enforcement
  - `MultisigEnvelope` with 11 message types and AEAD encryption
    (ChaCha20-Poly1305 with HKDF-derived keys)
  - Per-intent state machine (8 states: Proposed → Broadcast + terminal)
  - `HeartbeatTracker`: liveness, censorship, and sync anomaly detection
  - `CounterProof`: 8-rule chain evidence verification for counter recovery
  - C++ `tx_extra` tags 0x08, 0x09, 0x0A for multisig metadata
  - FFI: `shekyl_pqc_verify_with_group_id` for defense-in-depth
  - Consensus: scheme_id consistency enforcement across transaction inputs

- **PQC Multisig V3.1: GUI components (shekyl-gui-wallet).**
  7 React components for the multisig UX:
  - `FingerprintBadge`: grouped hex fingerprint with copy and metadata
  - `ProverView`: per-participant prover assignment breakdown
  - `LossAcknowledgment`: mandatory 1/N loss checkbox
  - `AddressProvenance`: fingerprint history with change detection
  - `RelayConfig`: multi-relay management with operator diversity
  - `ViolationAlert`: I1–I7 violation display with auto-abort
  - `SigningDashboard`: real-time intent state with sign/veto actions

- **PQC Multisig V3.1: test infrastructure.**
  - 93 unit tests across all V3.1 modules
  - 19 integration tests (functional, adversarial, determinism)
  - 4 cross-platform determinism canaries with pinned byte prefixes
  - 11 fuzz harnesses (wallet-core) covering serialization, encryption,
    state machine, validation, and verification
  - Criterion benchmarks for intent_hash, encryption, serialization,
    fingerprint computation, and assembly consensus

- **`docs/MULTISIG_OPERATIONS.md`**: end-user operations guide covering
  group setup, receiving, spending, recovery, relay configuration, and
  security considerations.

- **`docs/AUDIT_SCOPE.md`**: expanded to include V3.1 multisig attack
  surface (KDF, prover assignment, invariants, AEAD, CounterProof,
  griefing defense).

- **`docs/SHEKYL_MULTISIG_WIRE_FORMAT.md`**: standalone portable wire
  format spec for the V3.1 multisig protocol. Covers MultisigEnvelope
  binary layout, SpendIntent canonical serialization, 11 message type
  discriminants, AEAD parameters (ChaCha20-Poly1305 with HKDF-SHA256),
  DecryptedPayload encoding, chain state fingerprint computation,
  file transport conventions, and conformance requirements. Enables
  third-party wallet implementations without reading the full spec.

- **GroupDescriptor**: canonical JSON backup file format for multisig
  groups. One file contains everything needed to restore a group from
  seeds (group_id, threshold, pubkeys, relays, fingerprint). Rust type
  in `shekyl-wallet-core`, Tauri export/import commands, and GUI
  component in `shekyl-gui-wallet`.

- **Failure-mode UX**: Multisig page restructured with 6 failure-mode
  alert banners (unresponsive co-signer, counter divergence, relay
  disconnect, fingerprint change, stuck intent, CounterProof failure).
  All Phase 3 components (SigningDashboard, ViolationAlert, ProverView,
  FingerprintBadge, LossAcknowledgment, AddressProvenance, RelayConfig)
  wired into the Multisig page.

- **File-based transport**: promoted from placeholder to first-class GUI
  option with Tauri file I/O commands and functional import/sign/export
  workflow. Equal prominence with relay transport.

- **Fee impact analysis**: added to MULTISIG_OPERATIONS.md with tx size
  comparison, per-input/per-output overhead, Bitcoin comparison, and
  economic viability analysis for small transactions.

- **Address format discipline**: cursor rule
  `65-address-format-discipline.mdc` codifying that `shekyl1m` is the
  sole multisig HRP for V3.x, with version bytes as the extension
  mechanism.

### 📚 Documentation

- **`docs/MULTISIG_OPERATIONS.md`**: expanded from 222-line protocol
  reference to ~500-line comprehensive operations guide with decision
  framework, 3 operational playbooks, 6 failure recovery guides,
  threat model worksheet, and honest limitations section.

- **`docs/FOLLOWUPS.md`**: added hardware wallet constraints (ML-DSA-65
  computation cost on Cortex-M, screen constraints, vendor outreach)
  and headless co-signer service reference implementation, both
  targeting V3.2.

- **GUI wallet cursor rules**: added `81-no-protocol-knowledge.mdc`
  (users never see FCMP++, KEM, HKDF in the UI) and
  `82-failure-mode-ux.mdc` (every feature must enumerate failure modes
  before implementation, failure states get dedicated UI).

### 🔒 Security

- **Zeroize ephemeral multisig signing seeds.** `ed_seed` and `ml_seed`
  stack copies in `construct_multisig_output_for_sender` are now wrapped
  in `Zeroizing<[u8; 32]>`, ensuring automatic zeroing on drop. Closes
  a theoretical side-channel surface from FOLLOWUPS.md V3.1 audit response.

- **`PersistedMultisigOutput` Debug redaction.** The `Debug` derive on
  `PersistedMultisigOutput` was replaced with a manual implementation that
  redacts `my_shared_secret` (64-byte KEM-derived material). Prevents
  accidental secret exposure through `dbg!` or structured logging.

- **`validate_balance` checked arithmetic.** `SpendIntent::validate_balance`
  now uses `checked_add` for input sums, output sums, and fee addition.
  Previously used wrapping `sum()` — crafted u64 values could wrap both
  sides to the same value and pass the equality check.

- **HKDF derivations return `Result`.** `derive_multisig_kem_seed` and
  `derive_participant_kem_randomness` now return `Result<..., CryptoError>`
  instead of panicking via `.expect()` on the transaction construction path.

- **`eprintln!` removed from `shekyl_fcmp_verify` FFI.** Two diagnostic
  `eprintln!` calls in the FCMP verification FFI path have been removed.
  The C++ caller already logs verification failures; the Rust-side stderr
  output was redundant and failed the CI lint.

### 🐛 Fixed

- **FCMP++ FFI: move depth-to-layers conversion to C++ callers.**
  `shekyl_fcmp_prove` and `shekyl_fcmp_verify` previously converted
  LMDB depth to upstream `layers` internally (`layers = depth + 1`).
  This created an ambiguous contract where the same `tree_depth`
  parameter meant different things in different FFI functions. Now both
  functions accept the upstream `layers` count directly; C++ callers
  (`blockchain.cpp`, `rctSigs.cpp`) perform `depth + 1` before calling.
  `shekyl_sign_fcmp_transaction` still accepts LMDB depth and converts
  internally (wallet callers pass LMDB depth). Added diagnostic tracing
  to `proof::verify` for `FcmpPlusPlus::read` and key image
  decompression failures. Fixed `validate.rs` c1/c2 alternation comment
  (the formula was correct but had been transiently swapped during
  refactoring). Tests simplified to single-layer Selene root (layers=1)
  to match the Rust unit test convention.

- **CI: fix `cargo audit` failure from RUSTSEC-2026-0098/0099.** Bumped
  `rustls-webpki` 0.103.10 -> 0.103.12 and `rand` 0.9.2 -> 0.9.4 in
  `Cargo.lock`. Added `rust/audit.toml` to acknowledge `rand` 0.8.5
  (RUSTSEC-2026-0097, not applicable: Shekyl uses `OsRng`, not
  `rand::rng()` with a custom logger).

- **Remove dead `verify_transaction_pqc_auth` one-arg overload.** The
  no-argument overload in `tx_pqc_verify.cpp` had zero callers — the
  sole production caller (`blockchain.cpp`) uses the two-arg form with
  `expected_scheme_id`. Replaced with a default parameter. Per
  `15-deletion-and-debt.mdc`: dead code goes.

- **Fix stale `shekyl_ffi.h` `shekyl_pqc_verify_debug` comment.** The
  error code documentation (0-4) did not match the Rust `PqcVerifyError`
  enum (0-11). Updated to reflect the actual `repr(u8)` discriminants.

- **Reconcile FOLLOWUPS.md and STRUCTURAL_TODO.md.** Marked 5 items in
  STRUCTURAL_TODO as resolved (code already fixed). Corrected the
  `expected_scheme_id` FOLLOWUPS entry (parameter is actively used by
  `blockchain.cpp`, contrary to the prior note). Marked `rpassword` audit
  as covered by CI.

### 🔄 Changed

- **FFI: verification functions return typed `u8` error codes instead of
  `bool`.** `shekyl_pqc_verify`, `shekyl_pqc_verify_with_group_id`, and
  `shekyl_fcmp_verify` now return 0 on success and a nonzero error
  discriminant on failure. PQC verify uses `PqcVerifyError` codes 1-11;
  FCMP verify uses `VerifyError` codes 1-7. Error codes are available in
  all build modes, eliminating the debug-only double-call pattern. C++
  callers (`tx_pqc_verify.cpp`, `blockchain.cpp`) updated to log error
  codes unconditionally. Per `30-ffi-discipline.mdc`.

- **Clippy lint rename: `unchecked_duration_subtraction` →
  `unchecked_time_subtraction`.** Updated in workspace `Cargo.toml` to
  track the upstream rename.

### 🗑️ Removed

- **`shekyl_pqc_verify_debug` deleted.** Now that production
  `shekyl_pqc_verify` returns typed error codes, the debug-only variant
  is redundant. All call sites and the `#ifndef NDEBUG` C header guard
  removed.

### 🐛 Fixed (continued)

- **All Rust clippy warnings resolved in `shekyl-crypto-pq`.** Fixed 1
  error (`missing_fields_in_debug` in `PersistedMultisigOutput`) and 13
  warnings: `op_ref` (11 sites in `kem.rs`, `montgomery.rs`, `output.rs`),
  `needless_range_loop` and `unnecessary_map_or` (in
  `multisig_receiving.rs`), `uninlined_format_args` (in `output.rs`
  tests). Also ran `cargo fmt` across workspace.

- **FCMP++ proof verification: five integration bugs fixed, first green CI.**
  The FCMP++ core tests (`gen_fcmp_tx_valid`, `gen_fcmp_tx_double_spend`,
  `gen_fcmp_tx_reference_block_too_old`, `gen_fcmp_tx_reference_block_too_recent`,
  `gen_fcmp_tx_timestamp_unlock_rejected`) have never passed since integration.
  Root causes identified and fixed:
  1. **FFI depth/layers off-by-one.** LMDB stores 0-indexed `tree_depth`;
     the upstream library expects 1-indexed `layers` count.
     Fix: `layers = tree_depth + 1` at the FFI boundary.
  2. **C++ branch extraction loop was `< depth` instead of `<= depth`.**
     Both `genRctFcmpPlusPlus` and `assemble_tree_path_for_output` skipped
     the root layer's branch data. Fix: `layer <= tree_depth` in both.
  3. **Point-to-scalar conversion missing in witness construction.**
     Raw LMDB point hashes were passed as branch siblings without converting
     to cycle scalars. Fix: `selene_to_helios_scalar` / `helios_to_selene_scalar`
     applied during `genRctFcmpPlusPlus` branch assembly.
  4. **`compute_leaf_count_at_height` off-by-one.** Maturity comparison used
     `<= target_height + 1` while LMDB's `drain_pending_tree_leaves` uses
     `<= current_height`. Fix: removed the `+ 1` to match LMDB semantics.
  5. **`key_image_y_normalize` broke Ed25519 batch verification.** The
     normalization (clearing byte 31 sign bit) modified the key image away
     from the true `x * Hp(O)` used by the Rust prover. Fix: deleted
     `key_image_y_normalize` entirely — FCMP++ key images are not
     y-normalized.
  6. **PQC signing payload computed before all public keys were derived.**
     `get_transaction_signed_payload` hashes all inputs' `hybrid_public_key`
     values, but the single-loop approach signed early inputs before later
     keys existed. Fix: two-phase PQC signing (derive all keys, then sign
     all inputs).
  All 5 FCMP++ core tests, 4 staking tests, 28 FCMP unit tests, and 45
  Rust `shekyl-fcmp` tests now pass. This is the first green CI in the
  repository's history.

- **Consensus-critical: curve tree leaf ordering bug (DB v6 → v7).**
  `pending_tree_leaves` used `MDB_DUPSORT` on 128-byte leaf data, causing
  outputs with the same maturity height to drain into the curve tree in
  byte-sorted order rather than `global_output_index` order. This broke the
  implicit `global_output_index == tree_leaf_index` assumption that every
  caller of `get_curve_tree_leaf()` relied on. Replaced with 16-byte
  composite keys `BE(maturity) || BE(output_index)` enforcing canonical
  drain order. Same restructuring applied to `pending_tree_drain`. Added
  explicit bidirectional mapping tables (`output_to_leaf`, `leaf_to_output`)
  and a `block_pending_additions` journal for robust `pop_block` reversal.
  DB schema bumped to v7 (incompatible with v6 — requires resync).

- **`get_curve_tree_leaf()` parameter was silently misnamed.**
  The function accepted `global_output_index` in its signature but actually
  looked up by tree position. Renamed to `get_curve_tree_leaf_by_tree_position()`
  and added `get_curve_tree_leaf_by_output_index()` (double lookup via mapping
  table). All callers updated — compile errors catch any missed sites.

- **`check_stake_claim_input` now recomputes and verifies the stored leaf.**
  Previously the stake claim gate only checked bounds
  (`staked_output_index < leaf_count`). Now the stored leaf is retrieved via
  the output→leaf mapping and bytewise-compared to a leaf recomputed from
  the output's `(output_key, commitment, h_pqc)`. This binds the claim to
  the actual output data in the tree.

### ✨ Added

- **`src/blockchain_db/shekyl_types.h`**: Strongly-typed identifiers
  (`TreePosition`, `OutputIndex`, `MaturityHeight`, `BlockHeight`) and
  LMDB key/value encoders (`PendingLeafKey`, `DrainKey`, `DrainValue`,
  `BlockPendingKey`, `BlockPendingValue`) for curve-tree state. Designed
  for 1:1 translation to Rust newtypes and heed `BytesEncode`/`BytesDecode`.

- **4 new regression tests** in `deferred_insertion.cpp`:
  same-maturity drain order by output_index, block_pending_additions
  journal round-trip, output↔leaf mapping round-trip, pop_block
  journal-driven reversal simulation.

### 📋 Protocol

- **X25519 public key derived from Ed25519 view key.**
  The X25519 public key used in the hybrid KEM classical component is the
  Edwards→Montgomery image of the Ed25519 view public key:
  `x25519_pub = (1 + y) / (1 - y) mod p`. It is not carried in the address
  or generated independently. The Bech32m address PQC segments carry ML-KEM
  material exclusively. See `POST_QUANTUM_CRYPTOGRAPHY.md` §X25519 Binding
  to View Key.

- **Unclamped Montgomery DH (not RFC 7748 X25519).**
  The classical KEM component performs `Scalar * MontgomeryPoint` with the
  Ed25519 view scalar as the private input. RFC 7748 scalar clamping is not
  applied because the view scalar is already reduced mod `ℓ`; clamping
  would mutate it and desynchronize sender/receiver derivation. See
  `POST_QUANTUM_CRYPTOGRAPHY.md` §DH Semantics.

- **Low-order Montgomery point rejection (validation rule).**
  Recipients MUST reject low-order Montgomery points on `kem_ct_x25519`
  before performing DH: `if (8 * point).is_identity() → reject`. This
  replaces RFC 7748 clamping's cofactor-clearing role. Sender-side check
  on the derived recipient X25519 pub is defense-in-depth. See
  `POST_QUANTUM_CRYPTOGRAPHY.md` §DH Semantics.

- **`m_pqc_public_key` layout invariant: 1216 bytes.**
  `X25519_pub[0..32] || ML-KEM-768_ek[32..1216]` where `X25519_pub` is
  derived (never transmitted). Canonical assemblers:
  `get_account_address_from_str`, `generate_pqc_key_material`. Runtime
  checks enforce exact size at every split site.

- **Wallet key consistency invariant.**
  `m_pqc_secret_key[0..32] == m_view_secret_key`. Wallet refuses to open
  on mismatch.

- **X25519 derivation test vectors published.**
  `docs/test_vectors/PQC_TEST_VECTOR_005_X25519_DERIVATION.json` pins the
  Ed25519→X25519 derivation, unclamped DH shared secrets, low-order
  rejection inputs, and Edwards rejection inputs for third-party
  implementers.

### ✨ Added

- **`montgomery.rs`**: Edwards→Montgomery conversion, unclamped scalar
  interpretation, low-order point detection. (`shekyl-crypto-pq`)
- **`shekyl_view_pub_to_x25519_pub` FFI export** for C++ callers.
  (`shekyl-ffi`)
- **Genesis reproducibility artifacts**: `verify_genesis.py` script and
  `GENESIS_BUILD_INFO.txt`. (`shekyl-dev/tools/genesis_builder/`)

### 🔄 Changed

- **`genesis_builder` print_usage updated to Bech32m.**
  Usage example now shows `<bech32m>` addresses instead of `<base58>`.

### 🐛 Fixed

- **Fixed `core_tests` FCMP++ proof verification failures.**
  `gen_fcmp_tx_valid`, `gen_fcmp_tx_double_spend`, and `gen_staking_lifecycle`
  all failed with "FCMP++ proof verification failed" because test-chain block
  headers carried a placeholder `curve_tree_root` (`selene_hash_init`) while
  witness paths were assembled from the real LMDB tree. Added per-height curve
  tree root storage (`m_curve_tree_roots` LMDB table) so both the prover and
  verifier read the correct historical root for any reference block height.
  Also aligned `compute_leaf_count_at_height` in `chaingen.cpp` with production
  `collect_outputs` logic (output-type filtering and `outPk` bounds checks).

- **Reverted `vcpkg.json` manifest that broke MSVC CI.**
  Commit `397817b` introduced a `vcpkg.json` with `"builtin-baseline": null`,
  which caused the MSVC CI job to fail (vcpkg auto-detected the manifest and
  rejected the null baseline). The CI workflow already manages vcpkg
  dependencies via explicit CLI invocation. Deleted the manifest to restore
  the working state.

- **Restored and upgraded `JsonSerialization.FcmpPlusPlusTransaction` test.**
  Replaced ring-style `make_transaction` with `make_fcmp_transaction()` that
  constructs a real v3 FCMP++ transaction via the full Rust FFI signing
  pipeline: KEM keypair generation, output construction, scan-and-recover,
  curve tree leaf/root building, FCMP++ proof signing and verification, and
  PQC auth signing. The test now exercises real cryptographic operations
  (not stubs) before round-tripping through JSON serialization. Deprecated
  `wallet_tools::gen_tx_src` with migration note pointing to the FCMP++
  pipeline in `chaingen.cpp`.

- **Fixed `rctSig` JSON serializer missing `message` and `referenceBlock`.**
  The JSON round-trip for `rct::rctSig` did not serialize the `message` field
  (tx prefix hash) or the `referenceBlock` field (for `RCTTypeFcmpPlusPlusPqc`).
  Both are part of the binary wire format in `rctTypes.h` but were silently
  lost during JSON serialization. Added `message` to all rctSig JSON output
  and `referenceBlock` for FCMP++ transactions. Discovered by the
  `FcmpPlusPlusTransaction` JSON round-trip test.

- **`on_get_curve_tree_path` RPC consistency fix.** The RPC handler read
  `leaf_count` from tip state but returned a `reference_block` several blocks
  behind tip. If the tree grew in between, the returned leaf data and layer
  hashes did not match the reference block's `curve_tree_root`. Fixed by
  computing `ref_leaf_count` at `reference_height` via drain journal, capping
  all reads to that count, and applying boundary-chunk hash trimming for
  sibling chunks that changed since the reference block. Mirrors the fix
  already applied to the test harness in `chaingen.cpp`.

- **MSVC portability batch.** Expanded `src/common/compat.h` with centralized
  platform-conditional includes for `unistd.h`/`io.h`, `dlfcn.h`, and
  `sys/mman.h`. Added `AND NOT MSVC` guards to `monero_enable_coverage`
  (GCC-only `--coverage` flags) and `enable_stack_trace` (GNU `ld`
  `-Wl,--wrap=__cxa_throw`). Fixed `bootstrap_file.cpp` `long` types to
  `std::streamoff`/`uint64_t` for LLP64 correctness. Fixed unsigned negation
  in `wallet2.cpp:772` (`std::advance(left, -N)` where N is `size_t`) with
  `static_cast<ptrdiff_t>`. Created root `vcpkg.json` manifest for
  deterministic dependency management.

- **FCMP++ test harness: tree state mismatch.** `assemble_tree_path_for_output`
  and `construct_fcmp_tx` in `tests/core_tests/chaingen.cpp` read the current
  (tip) curve tree state but the verifier checks against the reference block's
  historical tree root. Fixed by computing `ref_leaf_count` at the reference
  block height and capping all leaf/layer reads to that count, with boundary
  chunk hash trimming via `shekyl_curve_tree_hash_trim_selene` for siblings
  that changed since the reference block. Also fixed a layer offset bug where
  sibling hashes were read from `layer` instead of `layer - 1`.

- **FCMP++ test harness: staking tests missing FCMP++ pipeline.**
  `gen_staking_lifecycle` and `gen_stake_all_tiers` used `construct_staked_tx`
  which produced stub RCT signatures without FCMP++ proofs or PQC auth.
  Rewritten to use callback-based testing (like `gen_fcmp_tx_valid`) with a
  new `construct_fcmp_staked_tx` that routes through the full FCMP++ proving
  and PQC signing pipeline via `apply_fcmp_pipeline`.

### 🔄 Changed

- **Unified constant-time comparison for all 32-byte crypto types.**
  `public_key`, `key_image`, and `hash` now use `crypto_verify_32` via
  `CRYPTO_MAKE_HASHABLE_CONSTANT_TIME` instead of `memcmp`-based
  `CRYPTO_MAKE_HASHABLE`. Eliminates the footgun of a developer choosing
  the non-constant-time macro for a new secret-bearing 32-byte type.

- **Added `ct_signatures` type alias.** `using ct_signatures = rct::rctSig;`
  added in `cryptonote_basic.h` as the starting point for migrating away
  from the Monero-era `rct_signatures` name. Full caller migration and
  `rct::` namespace rename deferred to V4.

- **Documented alternative tokens decision.** Keeping `/FIiso646.h`
  workaround for MSVC; mechanical replacement of `not`/`and`/`or` is
  high-effort, low-value. Recorded in STRUCTURAL_TODO.md.

- **Workspace-wide clippy cleanup.** Resolved all `cargo clippy --all-targets
  --no-deps -- -D warnings` errors across the Rust workspace (14 crates,
  52 files). Key changes: replaced `as u128` casts with `u128::from()`,
  added `#[allow]` for intentional truncation in economics/FFI code,
  marked FFI `extern "C"` functions `unsafe` with `# Safety` docs,
  replaced redundant closures with method references, used `let...else`,
  switched `from_slice` to `GenericArray::from()` in chacha20poly1305,
  changed `&Vec<T>` to `&[T]` in public APIs. No behavioral changes.

### ✨ Added

- **Fuzz target for `derive_output_secrets`.** New `fuzz_derive_output_secrets`
  cargo-fuzz harness in `rust/shekyl-crypto-pq/fuzz/`. Exercises arbitrary
  `combined_ss` inputs (up to 1200 bytes) and output indices; asserts
  determinism, non-zero ho/y scalars, and absence of panics on
  truncated/oversized input. Closes FOLLOWUPS.md fuzz-derivation item.

- **Witness header round-trip test.** New `witness_header_build_then_parse_roundtrip`
  test in `rust/shekyl-ffi/` with locked vectors in
  `docs/test_vectors/WITNESS_HEADER.json`. Proves `shekyl_fcmp_build_witness_header`
  (writer) and `parse_prove_witness` (reader) agree byte-for-byte on all 8
  header fields `[O:32][I:32][C:32][h_pqc:32][x:32][y:32][z:32][a:32]`.
  Closes FOLLOWUPS.md witness-roundtrip item.

### 📚 Documentation

- **y=0 consensus check resolved as infeasible.** Documented that a
  consensus-level rejection of outputs with `y=0` T-component cannot be
  implemented: the verifier does not know `y` (it is a KEM-derived secret)
  and testing whether `O` lies in the G-only subgroup requires knowing the
  DL between G and T. Defense is structural via `derive_output_secrets`
  hard-assert and fuzz coverage. Closes FOLLOWUPS.md y=0-consensus item.

- **scheme_id binding analysis corrected in `PQC_MULTISIG.md`.** The
  `expected_scheme_id` parameter in `verify_transaction_pqc_auth` is unused
  because FCMP++ hides which output is being spent. Scheme downgrade
  protection is provided by the `h_pqc` curve tree leaf commitment —
  the FCMP++ proof binds `H(hybrid_public_key)` to the leaf, making a
  downgrade require a Blake2b-512 collision. Updated Attack 1 mitigation
  description and `POST_QUANTUM_CRYPTOGRAPHY.md` accordingly.

- **FOLLOWUPS.md and STRUCTURAL_TODO.md audit and cleanup.**
  Marked 5 stale items as resolved (2 in FOLLOWUPS, 3 in STRUCTURAL_TODO):
  `signing_round_trip.rs` now exercises FFI, `AUDIT_SCOPE.md` exists,
  C++20-isms audit complete, easylogging++ MSVC fully fixed, `wallet2.h:2324`
  bool/char pattern removed by wallet refactoring. Updated 2 stale references:
  `simplewallet.cpp` deleted (removed from `long` type sites and `memcmp`
  resolution list), `wallet2.cpp:782` shifted to line 772. Updated test
  `memcmp` count from 84 to ~90. Annotated `expected_scheme_id` removal as
  deferred to PQC multisig PR.

### 📚 Documentation

- **Cross-repo documentation audit.** Comprehensive review across all five
  Shekyl repos fixing stale references, Monero-era branding, completed-but-
  unchecked items, and broken cross-references. Key changes:
  - `README.md`: Removed Monero CI badges (Coverity, OSS Fuzz, Coveralls),
    stale distribution packages (`apt install monero`, etc.), Raspberry Pi
    Jessie instructions, 2022-era pruning sizes, `monerod.conf` references.
    Fixed research section cross-references to shekyl-dev repo.
  - `proxies.md`: Renamed "Monero ecosystem" to "Shekyl ecosystem".
  - `DOCUMENTATION_TODOS_AND_PQC.md`: Fixed FCMP++ "Phase 8" references
    (doc exists), CryptoNight reference (Shekyl uses RandomX from genesis),
    `CURVE_TREE_OPERATIONS.md` reference (covered in `FCMP_PLUS_PLUS.md`),
    v2.0 tx references (should be v3).
  - `INSTALLATION_GUIDE.md`: `FCMP_PLUS_PLUS.md` exists, not "planned."
  - `V4_DESIGN_NOTES.md`: Checked boxes for items done in V3.
  - `RELEASE_CHECKLIST.md`: Marked wallet/exchange/pool entries as
    placeholders for Shekyl-specific partners.
  - `FOLLOWUPS.md`: Added items for fuzz harness on `derive_output_secrets`,
    witness header round-trip test, y=0 consensus check, and
    `AUDIT_SCOPE.md` creation.
  - KEM plan: Updated 18 todo items from `pending` to `completed` matching
    actual codebase state.

### 🗑️ Removed

- **`tests/unit_tests/address_from_url.cpp` deleted.** The test referenced
  `MONERO_DONATION_ADDR` (removed constant) and tested Monero OpenAlias DNS
  resolution against `donate.getmonero.org`. Both the constant and the DNS
  endpoint are irrelevant to Shekyl; the test broke the macOS CI build.

- **`simplewallet` (shekyl-wallet-cli) deleted.** The 9,126-line C++ interactive
  wallet REPL has been removed. Its replacement, `shekyl-cli` (Rust), was
  already at full parity for all actively-used commands. Removed
  `src/simplewallet/` directory, CMake target, CI artifact references, and
  Windows installer entries. The `translations/` directory retains
  simplewallet-era `.ts` strings as dead entries within shared i18n files.

- **`wallet/api/` C++ wrapper layer deleted.** The 3,909-line Monero-era C++
  wrapper (`wallet2_api.h` and 10 implementation files) had no production
  consumer -- the GUI uses `wallet2_ffi` via `shekyl-wallet-rpc` (Rust). Removed
  `src/wallet/api/` directory, `tests/libwallet_api_tests/`, and the
  `add_subdirectory(api)` entry from `src/wallet/CMakeLists.txt`. Cleaned up
  stale `#include "wallet/api/*.h"` references in `object_sizes.cpp` and
  `address_from_url.cpp`.

### 🐛 Fixed

- **19 `core_tests` failures and SEGFAULT from v3 transaction incompatibility.**
  The test framework's `construct_miner_tx_manually` was hardcoded to produce v2
  transactions without PQC output construction, causing 16 block validation tests
  to fail during generation and a SEGFAULT in `tx_validation` tests. Rewrote the
  function to perform genuine v3 output construction via `shekyl_construct_output`
  FFI. Added `append_v3_output_to_miner_tx` helper for tests that add outputs to
  coinbase. Fixed `fill_tx_sources` to populate `ho`/`v3_ho_valid` on source
  entries via `try_v3_scan_output`. Removed stale classical key derivation from
  view tag tests. Fixed serialization consistency in tests that modify
  `vout`/`vin` without updating `rct_signatures` fields.

- **Non-exhaustive `TxBuilderError` match in FFI error-code mapping.**
  Commit `aff9f777` added `TreeDepthTooLarge(u8)` to `TxBuilderError` but did
  not add the corresponding arm to `tx_builder_error_code()` in `shekyl-ffi`,
  breaking CI compilation on all platforms. Added `TreeDepthTooLarge(_) => -27`.

## [core-v3.1.0] - 2026-04-13

### 🔄 Changed

- **Dev merged into main.** 128 commits from `dev` promoted to `main`
  including: FCMP++ curve-tree integration, hybrid PQC KEM scanning,
  shekyl-cli full parity, shekyl-address Bech32m encoding, native Rust
  transaction signing, staking enhancements, wallet/api removal, and
  ZeroMQ cleanup. Tagged as `core-v3.1.0` for GUI wallet CI pinning.

### ✨ Added

- **`shekyl-cli` full parity with simplewallet (40 of 81 commands).** The
  `rust/shekyl-cli/` crate now covers all actively-used simplewallet
  functionality. Key additions since the initial scaffold:
  - **Security-hardened UX**: `display.rs` for secret display with TTY
    checks, multiplexer warnings, best-effort scrollback clear, and honest
    residual-scrollback warning. `errors.rs` for JSON-RPC error sanitization
    (strips paths/hex; `--debug` routes raw errors to stderr or 0600 log
    file, never stdout). Context-specific `confirm_dangerous()` tokens for
    destructive operations (sweep amount, address prefix, acknowledgment
    phrase).
  - **Stateless account model**: `ReplSession` holds session-default
    account on REPL stack; `ResolvedCommand` enum resolves `--account N` at
    parse time. No wallet-level current-account state.
    `--subaddr-index`/`--subaddr-indices` for subaddress selection.
  - **Independent daemon client**: `daemon.rs` using ureq (rustls backend,
    pinned) for `chain_health`. SOCKS stream isolation via distinct auth
    username. `--daemon-ca-cert` and `--proxy` CLI flags. Differentiated
    error reporting (5 failure modes).
  - **Staking**: `stake`, `unstake`, `claim`, `staking_info`, `chain_health`.
  - **Keys**: `viewkey`, `spendkey` with terminal safety; `export_key_images`
    (0600 permissions, `--since-height`, `--all`); `import_key_images` with
    format validation.
  - **Proofs**: `get_tx_key`, `check_tx_key`, `get_tx_proof`,
    `check_tx_proof`, `get_reserve_proof`, `check_reserve_proof`.
  - **Wallet ops**: `password` (old-first with fast-fail validation),
    `rescan` (`confirm_dangerous`), `sweep_all` (privacy warning),
    `show_transfer`.
  - **Offline signing**: `describe_transfer`, `sign_transfer`,
    `submit_transfer`; `--do-not-relay` on `transfer`.
  - **Signing**: `sign`, `verify` (domain separation documented),
    `version`, `wallet_info` (no filename).
  - **Input validation**: `validate.rs` with hex, txid, address, and
    input-length validators.
  - **Fuzz tests**: `proptest` dev-dependency with 14 property tests for
    amount parsing, hex validation, address validation, and argument
    parsing.
  - **Parity matrix**: `docs/CLI_PARITY_MATRIX.md` maps all 81
    simplewallet commands to shekyl-cli equivalents or explicit out-of-scope
    with reasons. Phase 3 deletion gate defined.
  - **Categorized help** with per-command usage docs and domain-separation
    note on sign/verify.

- **CI gate: `dalek-ff-group` version isolation.** Added a workflow step that
  asserts `shekyl-ffi`'s normal dependency tree never pulls in
  `dalek-ff-group` v0.4. The 0.4 version is allowed transitively inside
  `ciphersuite` internals but must never be used directly by Shekyl code.

- **CI lint: no debug macros in production Rust.** Added a workflow step that
  rejects `eprintln!`, `dbg!`, and `println!` in production Rust code
  (excluding test modules, build scripts, binary entry points, and the
  economics simulator). Prevents accidental debug logging from reaching
  production builds.

- **CI lint: BOOST_FOREACH guard.** Added a workflow step that fails if any
  `BOOST_FOREACH` usage is reintroduced via upstream cherry-picks. All 31
  prior instances were replaced with range-based for loops.

### 🔄 Changed

- **CI lint: exclude `shekyl-cli` from debug-macro ban.** The interactive
  CLI REPL legitimately uses `println!`/`eprintln!` for terminal output.
  The lint now skips `rust/shekyl-cli/` to avoid false positives on
  binary crate I/O.

### 🐛 Fixed

- **[CONSENSUS] Genesis TX blobs upgraded to v3 wire format.** The hardcoded
  `GENESIS_TX` hex in `cryptonote_config.h` (mainnet, testnet, stagenet)
  was still in the legacy v2 format, missing the `enc_amounts` and `outPk`
  arrays required by the current `serialize_rctsig_base`. Updated all three
  blobs to v3 (`tx.version = 3`) with zero-filled `enc_amounts`/`outPk`
  for `RCTTypeNull` coinbase. This was the root cause of `core_tests`
  SEGFAULT, `block_weight` failure, and wallet init failures in CI.

- **JSON serialization now includes `enc_amounts`/`commitments` for
  `RCTTypeNull` coinbase.** The `toJsonValue`/`fromJsonValue` for
  `rct::rctSig` previously skipped these fields for `RCTTypeNull`, but the
  binary wire format serializes them for all RCT types since the v3 format
  change. This caused JSON round-trip failures for coinbase transactions.

- **`HTTP_Client_Auth.MD5_auth` test used hardcoded empty cnonce.** The test
  computed the expected MD5 digest with `cnonce=""` while the production
  `http_auth.cpp` generates a random cnonce. Fixed to extract the actual
  cnonce from the parsed auth response.

### 🗑️ Deprecated

- **`test::make_transaction` ring-style helper.** The helper constructs
  Monero-era ring-signature source entries incompatible with v3/FCMP++
  transaction construction. `BulletproofPlusTransaction` is `GTEST_SKIP`'d
  pending FCMP++ test infrastructure.

- **[CONSENSUS-ADJACENT] Branch layer depth validation off-by-one in
  `shekyl-tx-builder`.** The rule `c1 + c2 == depth` was corrected to
  `c1 + c2 + 1 == depth` (layer 0 is the leaf hash and has no branch
  entry). The previous rule incorrectly rejected valid witnesses at
  depth=1 and accepted structurally wrong branch counts at all other
  depths. Discovered by the FFI signing round-trip test introduced in
  this release. Verifier side verified: uses proof-structure-implicit
  depth enforcement (no explicit c1/c2 check needed). Additionally,
  validation now enforces the spec-correct C1/C2 alternation split
  (`c1 == c2` or `c1 == c2 + 1`), the error.rs doc was corrected
  (previously stated the relationship backwards), and `MAX_TREE_DEPTH=24`
  was added as a named constant in `shekyl-fcmp` with enforcement in both
  prover and verifier. See FOLLOWUPS.md for the full audit trail.

### ✅ Testing

- **FFI signing round-trip test rewritten to use `shekyl_sign_fcmp_transaction`.**
  `rust/shekyl-ffi/tests/signing_round_trip.rs` now exercises the full C-ABI
  FFI boundary: KEM keypair generation, output construction, output scanning,
  curve tree leaf/root computation, JSON serialization of `FcmpSignInput` +
  `OutputInfo`, signing via `shekyl_sign_fcmp_transaction`, and verification
  via `shekyl_fcmp_verify`. Runs 10 iterations with different random seeds.
  Previously called `proof::prove` directly, bypassing FFI JSON parsing, key
  derivation, and buffer management.

### 📚 Documentation

- **FFI header upgraded to `///` doc comments (Phase 6 completion).** Converted all
  `//` function and struct documentation comments in `src/shekyl/shekyl_ffi.h` to
  `///` Doxygen-style. Covers all ~70 FFI exports: output construction/scanning,
  key image computation, FCMP++ prove/verify, wallet proofs, cache encryption,
  KEM operations, Bech32m encoding, curve tree hashing, seed derivation, and
  daemon RPC. Rewrote the `SHEKYL_PROVE_WITNESS_HEADER_BYTES` comment from
  `DEPRECATED`/`TODO` language to document its role as test infrastructure for
  `genRctFcmpPlusPlus` in `core_tests`.

### 🔄 Changed

- **`simplewallet` marked deprecated.** Added a yellow deprecation banner to
  `simplewallet.cpp` startup: "shekyl-wallet-cli is deprecated and will be
  removed. Use shekyl-cli instead." No new features will be added; the binary
  will be deleted once `shekyl-cli` reaches parity.

- **Axum RPC binds to standard port.** When `--no-rust-rpc` is not set, the
  Axum daemon RPC server now binds to the standard RPC port (11029/12029/13029)
  and the epee HTTP listener is skipped. Falls back to epee on Axum startup
  failure. Previously Axum bound to `epee_port + 10000`.

- **Production `eprintln!` removed from Rust FFI.** Replaced 6 `eprintln!`
  calls in `shekyl-ffi/src/lib.rs` error handlers with silent error
  suppression (the C++ caller checks the bool return). Converted 1
  `eprintln!` in `shekyl-daemon-rpc/src/ffi_exports.rs` to `tracing::error!`.

- **Test code migrated to remove all calls to deleted crypto/device functions.**
  Updated 14 test files across `tests/crypto/`, `tests/unit_tests/`,
  `tests/core_tests/`, `tests/performance_tests/`, `tests/trezor/`, and
  `tests/benchmark.cpp` to remove references to `derive_public_key`,
  `derive_secret_key`, `derivation_to_scalar`, `derive_subaddress_public_key`,
  `derive_view_tag`, `is_out_to_acc`, `lookup_acc_outs`, `ecdhDecode`,
  `ecdhHash`, `genCommitmentMask`, `generate_key_image_helper`, and
  `generate_output_ephemeral_keys`. Where inline key derivation was needed
  (block/miner-tx construction tests), local helpers using Ed25519 primitives
  (`hash_to_scalar`, `ge_scalarmult_base`, `sc_add`) replace the deleted
  functions. Legacy output scanning in `chaingen.cpp` and `chain_switch_1.cpp`
  falls through to the v3 scan path. All `additional_tx_keys` parameters
  removed from `construct_tx_and_get_tx_key` call sites. Benchmark harnesses
  for `derive_subaddress_public_key` and per-tx scanning removed.

### 🗑️ Removed

- **Complete ZMQ removal.** Deleted the entire ZeroMQ subsystem: ZMQ pub/sub
  (`zmq_pub.cpp`), ZMQ RPC server (`zmq_server.cpp`, `daemon_handler.cpp`,
  `daemon_messages.cpp`), low-level ZMQ helpers (`net/zmq.cpp`), message schema
  (`message.cpp`, `daemon_rpc_version.h`, `rpc/fwd.h`), and the `rpc_pub`,
  `daemon_rpc_server`, `daemon_messages` CMake targets. Removed `libzmq`
  build dependency from root CMakeLists, `contrib/depends`, and all link
  targets. Deleted 3 test files (`zmq_rpc.cpp`, `txpool.py`,
  `python-rpc/framework/zmq.py`) and the `zeromq.mk` depends recipe with its
  patches. Removed `--zmq-rpc-bind-ip`, `--zmq-rpc-bind-port`, `--zmq-pub`,
  `--no-zmq` CLI arguments. ZMQ was a duplicate, unauthenticated RPC surface
  inherited from an abandoned Monero "migrate RPC to ZMQ" effort. It had zero
  first-party consumers, leaked `do_not_relay` transactions, and its tests had
  been broken for 82+ consecutive CI runs, polluting the test signal during
  the FCMP++ migration. Ports 11025/12025/13025 are now reserved.
  Re-audit follow-up: removed stale `#include "rpc/daemon_messages.h"` and
  two ZMQ-schema-dependent tests (`DaemonInfo`, `HandlerFromJson`) from
  `json_serialization.cpp`, and fixed daemon link order (`rpc` after
  `${SHEKYL_DAEMON_RPC_LINK_LIBS}`) to resolve circular FFI back-references
  previously satisfied transitively through `daemon_rpc_server`.

- **`wallet/api/` C++ wrapper layer deleted (~3,900 lines).** The
  `src/wallet/api/` directory (22 files) wrapped `wallet2` for GUI consumption.
  With the Tauri GUI using `wallet2_ffi` via Rust, no production consumer
  remained. Removed the directory, `add_subdirectory(api)` from wallet
  CMakeLists, `wallet/api` includes and sizeof reporters from
  `object_sizes.cpp`, broken includes in `subaddress.cpp` and trezor tests,
  `wallet_api` link target from trezor CMakeLists, and CI `--target wallet_api`
  build steps.

- **`libwallet_api_tests/` test suite deleted (~1,300 lines).** Removed the
  `tests/libwallet_api_tests/` directory and its CMake entry. Cleaned up the
  Makefile's `libwallet_api_tests` ctest exclusions (originally disabled for
  Issue #895, now fully removed). Also removed the `wallet_api_tests` class
  and implementation from trezor tests.

- **`load_deprecated_formats` / `is_deprecated` dead code excised (Phase 6
  completion).** Removed the `is_deprecated()` method, `is_old_file_format`
  member, `m_load_deprecated_formats` member and its getter/setter from
  `wallet2.h`. Deleted the `is_deprecated()` definition, JSON save/load of
  `load_deprecated_formats`, the non-JSON wallet keys file fallback (now a hard
  error), and the boost `portable_binary_iarchive` version `\003`/`\004`
  branches in `parse_unsigned_tx_from_str` and `parse_tx_from_str` from
  `wallet2.cpp`. Removed the `set_load_deprecated_formats` command, its
  `CHECK_SIMPLE_VARIABLE` entry, settings display line, and the `is_deprecated()`
  upgrade flow from `simplewallet.cpp`/`.h`. Shekyl is v3-from-genesis; there are
  no legacy non-JSON wallet files or boost-serialized transaction blobs to load.

- **`additional_tx_keys` / `additional_tx_pub_keys` infrastructure fully
  removed.** Deleted member variables, struct fields, serialization entries, and
  function parameters referencing additional transaction keys from `wallet2.h`,
  `wallet2.cpp`, `cryptonote_tx_utils.h/.cpp`, `cryptonote_format_utils.h`,
  `device.hpp`, `device_default.hpp/.cpp`, and `device_ledger.hpp/.cpp`. In
  `wallet2.cpp`, removed all `additional_tx_pub_keys` / `additional_tx_keys`
  local variables, derivation computation loops, `m_additional_tx_keys` map
  operations, `etd.m_additional_tx_keys` export/import paths, and updated
  function definitions (`get_tx_key_cached`, `get_tx_key`, `set_tx_key`,
  `check_tx_key`, `get_tx_proof`) to match the simplified header signatures. The
  `conceal_derivation` device method implementations were updated to match
  the simplified signatures (no additional keys/derivations parameters). The
  `ABPkeys` struct no longer carries `additional_key`. Cleaned up all remaining
  call sites across `wallet2_ffi.cpp`, `wallet/api/wallet.cpp`,
  `simplewallet.cpp`, `wallet_rpc_server.cpp`, and `trezor/protocol.cpp` —
  removing additional-key parsing loops, serialization, and pass-through
  parameters. `get_additional_tx_pub_keys_from_extra` is now an inline stub
  returning an empty vector. In V3, per-output KEM ciphertexts replace
  additional tx keys; there is only one tx pubkey per transaction.

- **`derive_public_key`, `derive_secret_key`, and `derivation_to_scalar` removed
  from the device interface chain.** Deleted the pure virtual declarations from
  `device.hpp` and all override implementations from `device_default` and
  `device_ledger`. Also deleted `derive_public_key` and `derive_secret_key` from
  `crypto.cpp`/`crypto.h` (kept `derivation_to_scalar` in crypto, still needed by
  `derive_subaddress_public_key`). Removed associated performance test files.
  These Keccak-based one-component key derivation helpers are superseded by the
  V3 HKDF two-component output key derivation in `cryptonote_tx_utils`.

- **`out_can_be_to_acc`, `is_out_to_acc_precomp`, and `derive_view_tag` dead
  code removed.** Deleted the Keccak-based `out_can_be_to_acc` and
  `is_out_to_acc_precomp` functions from `cryptonote_format_utils`, the
  `derive_view_tag` function from `crypto`, and the `derive_view_tag` virtual
  method from the device interface chain (`device.hpp`, `device_default`,
  `device_ledger`). Removed associated performance tests. These functions were
  superseded by the X25519/HKDF view-tag derivation path in the V3 transaction
  format.

- **`ecdhHash` and `genCommitmentMask` dead code removed.** Deleted the
  `ecdhHash` and `genCommitmentMask` function definitions from `rctOps.cpp`,
  their declarations from `rctOps.h`, the `genCommitmentMask` virtual method
  from the device interface chain (`device.hpp`, `device_default`,
  `device_ledger`), and the `ecdhDecode` unit test that depended on them.
  These Keccak-based helpers were superseded by HKDF-derived amount encryption
  in V3.

- **Ring signature / decoy infrastructure removed from wallet2.** Removed
  `fake_outs_count` parameters from `create_transactions_2`,
  `create_transactions_all`, `create_transactions_single`, and
  `create_transactions_from`. Removed `transfer_selected_rct`'s
  `fake_outputs_count` and `outs` parameters. Deleted `get_output_relatedness`,
  `outs_unique`, `m_print_ring_members`, and `m_rings` bookkeeping. FCMP++
  eliminates ring signatures, making decoy selection and output relatedness
  scoring dead code.

### 🔒 Security

- **`m_combined_shared_secret` changed to `scrubbed_arr<uint8_t, 64>` (Phase 6,
  Gate 3).** Replaced `std::vector<uint8_t>` with `tools::scrubbed_arr<uint8_t, 64>`
  in both `transfer_details` and `exported_transfer_details`. This ensures
  zero-on-drop semantics consistent with `m_y` and `m_mask`. A boolean
  `m_combined_shared_secret_set` flag replaces size-based emptiness checks. All
  serialization (epee and Boost) updated with safe vector round-trip conversion.

- **WalletState invariant enforcement (Phase 6, Gate 5b).** Added
  `check_invariants()` to `WalletState` verifying 8 structural properties
  (balance consistency, spendable/spent partition, key image correspondence, etc.).
  `debug_assert!` fires after every mutation in debug builds. Property test (Gate 5c)
  exercises random operation sequences against invariant checks.

### ✨ Added

- **PQC output round-trip property tests (Phase 6, Gate 1).** `prop_round_trip.rs`
  exercises `construct_output` → `scan_output_recover` → `derive_proof_secrets` →
  `compute_key_image` with random keys and amounts via `proptest`. Asserts
  determinism (same inputs → identical outputs) and non-zero secrets (`ho`, `y`,
  `z`, `k_amount`, `key_image`). Includes boundary cases for `amount=0` and
  `amount=u64::MAX`. Runs with `--release` in CI.

- **Wallet cache AEAD tests (Phase 6, Gate 2).** `cache_crypto.rs` covers
  encrypt/decrypt round-trip, version mismatch detection (returns -1 before AEAD
  decryption attempt), wrong-key auth failure, empty ciphertext, and truncated
  ciphertext. Sub-case A2 proves version check ordering by corrupting ciphertext
  and asserting version mismatch fires first.

- **100-iteration signing round-trip stress test (Phase 6, Gate 4).**
  `test_gate4_signing_round_trip_100` in `proof_round_trip.rs` runs full outbound
  prove+verify cycle 100 times with unique randomness per iteration.

- **`unmark_spent` unit tests (Phase 6, Gate 5a).** Five tests covering: reversal
  to spendable pool, unknown key image noop, idempotent on already-unspent, partial
  set behavior, and invariant preservation after unmark.

- **Random-sequence invariant property test (Phase 6, Gate 5c).** `proptest` drives
  random sequences of `AddOutputs`, `MarkSpent`, `UnmarkSpent`, `Freeze`, `Thaw`,
  and `Reorg` operations, asserting `check_invariants()` after each step.

- **Sync bookkeeping tests (Phase 6, Gate 7).** Mock-block-driven tests for
  `WalletState` mutations: progress monotonicity, spend detection, reorg state
  restoration, empty block height advancement, and spend/unmark round-trip.
  Explicitly documented as bookkeeping-only (not integration against a real daemon).

- **CI grep gates (Phase 6).** Seven blocking grep gates in `build.yml`:
  `shekyl_y` absence, `derivation_to_y_scalar` absence, legacy RCT type absence,
  v1/v2 tx version branch absence, `HASH_KEY_TXPROOF` absence,
  `combined_shared_secret` confinement to wallet boundary,
  `ecdhEncode`/`ecdhDecode` confinement to Ledger gate. All run without
  `continue-on-error`.

- **FFI header documentation (Phase 6).** `shekyl_ffi.h` now has Doxygen-style
  file-level documentation covering the memory model, secret handling conventions,
  and error reporting contract.

### 🗑️ Removed

- **`derivation_to_y_scalar` deleted (Phase 6).** Removed the function body from
  `crypto.cpp`, declarations from `crypto.h`, and all call sites in
  `derive_public_key` and `derive_subaddress_public_key`. The `"shekyl_y"` salt
  no longer appears in the binary.

- **Test stubs 9-10 deleted (Phase 6).** Removed `#[ignore]` placeholder tests
  `test_09_watch_only_outbound_proof_error` and
  `test_10_restored_wallet_outbound_proof_error` from `proof_round_trip.rs`.
  Future implementations tracked in `WALLET_STATE_MIGRATION.md`.

- **Dead v1/v2 transaction branches in consensus (Phase 5).**
  `check_tx_outputs` now rejects `tx.version < 3` instead of `< 2`.
  Removed redundant `if (tx.version >= 2)` zero-amount guard (now
  unconditional). Tightened coinbase version check from `>= 2` to `>= 3`.
  Removed dead `tx.version < 3` early return in `check_commitment_mask_valid`.
  Commitment mask checks are now unconditional (version is always >= 3).

- **Dead legacy code excision (Phase 6 completion).**
  Deleted `decodeRctSimple` and its overload from `rctSigs.cpp/.h`.
  Deleted `tools::decodeRct` wrapper and all callers in `wallet2.cpp`.
  Deleted `generate_output_ephemeral_keys`
  declaration from `cryptonote_tx_utils.h`. Deleted `tx_proof.cpp` unit test
  (referenced removed `crypto::generate_tx_proof_v1`). Deleted
  `is_out_to_acc.h` performance test and its registrations.

- **`generate_key_image_helper` / `generate_key_image_helper_precomp` fully
  removed.** Migrated remaining production callers in `wallet2.cpp`
  (`export_key_images`, two `import_outputs` overloads) to the v3 HKDF path
  via `shekyl_derive_proof_secrets` FFI. Replaced dead `else` branch in
  `cryptonote_tx_utils.cpp::construct_tx_with_tx_key` with a hard error.
  Replaced `scan_output`'s `generate_key_image_helper_precomp` call with a
  v3-only assertion (function is dead for v3 scanning). Deleted both function
  definitions from `cryptonote_format_utils.cpp/.h`, the `compute_key_image`
  virtual method from `device.hpp` and its Trezor override in
  `device_trezor.hpp/.cpp`. Updated test callers in `chaingen.cpp` and
  `tx_validation.cpp` to use v3 `sc_add(ho, b)` derivation.

### 🔒 Security (Phase 5 Audit Notes)

- **Consensus hardening: commitment mask validation verified (Phase 5).**
  Audited `check_commitment_mask_valid` in `blockchain.cpp`: confirms
  rejection of identity commitment (mask=0, amount=0), generator-point
  commitment (mask=1, amount=0), and coinbase `zeroCommit(amount)` form
  (mask=1, any amount). Called unconditionally for both miner transactions
  and regular transactions.

- **y=0 defense-in-depth verified (Phase 5).** Confirmed construction-time
  `assert!(y != [0u8; 32])` and `assert!(ho != [0u8; 32])` in
  `derive_output_secrets` (Rust, release-mode assert). Both sender
  (`construct_output`) and receiver (`scan_output_recover`) hit the same
  assert. Documented in `POST_QUANTUM_CRYPTOGRAPHY.md` with full defense
  stack analysis.

### ✨ Added

- **GUI wallet native-sign activation (Phase 4a).** Added `native-sign`
  feature to the GUI wallet's `shekyl-wallet-rpc` dependency. The transfer
  path is now: C++ prepare → Rust sign → C++ finalize.

- **Scanner keys FFI export (Phase 4b).** Added `wallet2_ffi_get_scanner_keys`
  to the wallet2 FFI layer, returning all keys needed by the Rust scanner
  (spend/view secrets, X25519 SK, ML-KEM DK) as JSON. Added `get_scanner_keys`
  wrapper method to `Wallet2`.

- **Hybrid PQC KEM scanner (Phase 3a).** `shekyl-scanner` now scans blocks
  using the V3 two-component key derivation: X25519 + ML-KEM-768 hybrid
  KEM. The `InternalScanner::scan_transaction` pipeline parses
  `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` (0x06), applies X25519 view-tag
  pre-filtering (~99.6% rejection), and calls `scan_output_recover` for
  full KEM decapsulation, HKDF secret derivation, amount decryption, and
  B' recovery. Key images are computed natively in Rust via
  `hash_to_point` + `compute_output_key_image`. Legacy ECDH scan path
  removed.

- **`RecoveredWalletOutput` struct.** New scan result type carrying all
  KEM-derived secrets (`ho`, `y`, `z`, `k_amount`, `combined_shared_secret`),
  the computed `key_image`, and decrypted `amount` alongside the base
  `WalletOutput`. Implements `ZeroizeOnDrop` — secrets are wiped when the
  struct leaves scope.

- **`TransferDetails` PQC fields and `eligible_height`.** Extended with
  `ho`, `y`, `z`, `k_amount`, `combined_shared_secret` (all `Zeroizing`)
  and `eligible_height: u64` (`block_height + SPENDABLE_AGE`). Outputs
  below `eligible_height` are immature (no curve-tree path) and cannot be
  spent. `is_spendable()` enforces this gate.

- **`WalletState` KEM-aware processing.** `process_scanned_outputs` now
  populates all PQC fields from `RecoveredWalletOutput`, sets key images at
  scan time, and performs duplicate output key detection (burning bug).
  `spendable_outputs` filters on `eligible_height`.

- **`unmark_spent` for rollback.** `WalletState::unmark_spent` reverses
  spent marks on outputs whose signing round succeeded but whose finalize
  step failed (daemon rejection, relay timeout). Prevents phantom-spent
  balance loss.

- **Background sync loop (Phase 3b).** `shekyl-scanner::sync::run_sync_loop`
  polls the daemon RPC for new blocks, feeds them through the hybrid KEM
  scanner, detects spent outputs via key-image matching against block inputs,
  and emits `SyncProgress` events after each block. Cancellation-safe via
  `tokio_util::CancellationToken`. Configurable flush interval: every 100
  blocks on desktop, every block on mobile (OS can kill without warning).

- **`BalanceSummary` uses `eligible_height`.** Timelock categorization now
  reads `td.eligible_height` directly instead of recomputing from
  `block_height + DEFAULT_LOCK_WINDOW`.

- **`ViewPair` extended with KEM keys.** Added `x25519_sk` and `ml_kem_dk`
  fields to `ViewPair` for hybrid KEM decapsulation. The scanner requires
  both the X25519 secret and ML-KEM decapsulation key.

### 🐛 Fixed

- **Stale `fake_outs_count` arguments in wallet transaction creation.**
  Removed vestigial `0` (decoy count) from 9 call sites across
  `wallet2_ffi.cpp`, `wallet_rpc_server.cpp`, and `wallet/api/wallet.cpp`
  that no longer match `create_transactions_2`, `create_transactions_all`,
  and `create_transactions_single` signatures after ring removal.

- **Test compilation: `wallet_tools.cpp` and `transactions_flow_test.cpp`.**
  Replaced removed `td.is_rct()` calls with `true` (all Shekyl outputs are
  RCT), changed `tools::wallet2::get_outs_entry` to the local typedef from
  `chaingen.h`, and removed stale `mix_in_factor` argument in the functional
  test.

- **PQC doc label error.** Fixed incorrect HKDF label reference in
  `POST_QUANTUM_CRYPTOGRAPHY.md`: the output-key check uses `ho` with label
  `shekyl-output-x`, not `shekyl-pqc-output` (which is the ML-DSA seed
  label).

- **Test compilation: `json_serialization.cpp` aggregate init.**
  Replaced brace-enclosed initializer list for `tx_source_entry` with explicit
  member assignment. The struct is no longer an aggregate (user-declared
  destructor for `ho` wiping) and the old initializer also referenced a removed
  `real_out_additional_tx_keys` field.

- **Multi-output scan bug.** Removed erroneous `break` in
  `InternalScanner::scan_transaction` that exited the output iteration loop
  after finding the first matching output. Transactions with multiple wallet
  outputs (e.g., payment + change) now detect all of them.

- **Reorg handling in `handle_reorg`.** Rewrote `WalletState::handle_reorg`
  to use `(height, hash)` pairs instead of treating height as a direct vector
  index. Correctly handles non-genesis-aligned and sparse sync histories.
  `synced_height` is now derived from the last remaining block entry.

- **Reorg detection in sync loop.** `run_sync_loop` now compares each incoming
  block's `header.previous` hash against the wallet's stored hash for the
  prior height. On mismatch, walks backwards to find the fork point and calls
  `handle_reorg` before resuming.

- **Block fetch retry with backoff.** Per-block `get_scannable_block_by_number`
  calls now retry up to 5 times with exponential backoff (500ms initial,
  capped at 30s) instead of immediately aborting the sync loop on transient
  failures.

- **Secure memory wiping.** `TransferDetails` now implements both `Zeroize`
  (covering all fields including `key`, `commitment`, and `fcmp_precomputed_path`)
  and `Drop` (calls `zeroize()` on drop). `WalletState` implements `Drop` to
  wipe all transfers, key images, pub keys, and block hashes. Removed unsafe
  `#[derive(Clone, Debug)]` from `TransferDetails`; `Debug` is now manual and
  redacts secret fields.

- **Misleading payment ID comment.** Corrected comment in `scan.rs` that
  incorrectly described ECDH-based XOR decryption for payment IDs; V3
  transactions do not use encrypted payment IDs.

- **Always-true pattern in sync loop.** Removed `if let Some(tx_hashes) =
  Some(&scannable.block.transactions)` which was a no-op guard. Block
  transactions are now iterated directly.

### 🔄 Changed

- **`EncryptedAmount` wire format fix.** The Rust `EncryptedAmount` struct
  (in `shekyl-oxide::fcmp`) now correctly includes both `amount: [u8; 8]`
  and `amount_tag: u8`, matching the C++ 9-byte wire format. Previously
  only the 8-byte amount was read, causing silent data misalignment.

- **`Scanner::new` signature.** Now requires the wallet's `spend_secret`
  (`Zeroizing<[u8; 32]>`) for native key image computation at scan time.
  Both `Scanner::new` and `GuaranteedScanner::new` updated.

- **Deterministic KEM encapsulation from `tx_key_secret`.** `construct_output`
  now derives X25519 ephemeral keys and ML-KEM ciphertexts deterministically
  via HKDF-SHA-512 (`derive_kem_seed`), eliminating the need to cache
  per-output shared secrets. The sender can re-derive `combined_ss` at proof
  time from `tx_key_secret` and public data.

- **Proof pipeline helpers in `shekyl-crypto-pq`.** Seven new functions:
  `rederive_combined_ss`, `derive_proof_secrets`, `derive_output_key`,
  `recover_recipient_spend_pubkey`, `decrypt_amount`,
  `compute_output_key_image`, and `compute_output_key_image_from_ho`. These
  support the V3 tx_proof / reserve_proof / key-image protocols. The narrow
  `ProofSecrets(ho, y, z, k_amount)` projection ensures `combined_ss` never
  crosses the FFI boundary.

- **`ProofSecrets` widened to include `z`.** The Pedersen commitment mask is
  now part of the proof secrets projection, enabling direct `C = z*G +
  amount*H` verification in TX proofs. `derive_proof_secrets` passes `z`
  through instead of discarding it.

- **`shekyl-proofs` crate: full Phase 1a implementation.** Three modules:
  - `dleq.rs`: Two-base Schnorr DLEQ proof with domain separator
    `shekyl-reserve-proof-dleq-v1` and full base binding in the challenge
    hash (`G`, `Hp(O)`, `R1`, `R2`, `P`, `I`, `msg`). 6 unit tests.
  - `tx_proof.rs`: Outbound (101+128N bytes) and inbound (69+128N bytes)
    proof generation and verification. Domain-separated Schnorr signatures
    (`shekyl-outbound-tx-proof-v1`, `shekyl-inbound-tx-proof-v1`). Per-output
    `ho`, `y`, `z`, `k_amount` with algebraic output key and commitment checks.
  - `reserve_proof.rs`: Reserve proof (69+192N bytes) with per-output DLEQ
    key image binding. `enc_amount` sourced from blockchain, not from proof.
  - Version assertion (v1) before any cryptographic work. 4-byte output_count
    (u32 LE) supporting up to 2³²−1 outputs per proof.
  - 10-point round-trip test skeleton (exit criterion for Phase 5, `#[ignore]`).

- **FCMP_PLUS_PLUS.md section 21: Wallet Proof Structure.** Genesis-native
  proof design rationale. Documents the Schnorr/KEM decomposition, reserve
  proof DLEQ requirement, HKDF binding argument for z-omission in reserve
  proofs, and the `enc_amount`-from-chain invariant.

- **Phase 1b FFI exports (PR-wallet).** New exports in `shekyl_ffi.h`:
  - `shekyl_scan_and_recover`: Merged scan + key image in one call. All
    secret outputs write directly into `transfer_details` fields (no
    intermediate scratch buffers). `persist_combined_ss` flag controls
    whether `combined_ss` is returned or wiped internally (hot vs cold).
  - `shekyl_compute_output_key_image` / `_from_ho`: Key image computation
    for the 2 remaining sites (stake claim, tx_source_entry).
  - `shekyl_sign_fcmp_transaction`: Collapsed signing. C++ passes wallet
    master spend key `b` + per-input `{combined_ss, output_index, ...}`.
    Rust derives `x = ho + b` and `y` internally via HKDF. C++ never
    touches `x`.
  - `shekyl_derive_proof_secrets`: Helper writing `ho`, `y`, `z`,
    `k_amount` directly to caller-provided destination addresses.
  - `shekyl_encrypt_wallet_cache` / `shekyl_decrypt_wallet_cache`: AEAD
    encryption with AAD binding on `cache_format_version`. Distinct error
    codes for version mismatch (-1), auth failure (-2), and format error (-3).
  - 6 proof FFI exports: `shekyl_generate_tx_proof_outbound`,
    `shekyl_verify_tx_proof_outbound`, `shekyl_generate_tx_proof_inbound`,
    `shekyl_verify_tx_proof_inbound`, `shekyl_generate_reserve_proof`,
    `shekyl_verify_reserve_proof`. Signatures stabilized; wiring to
    `shekyl-proofs` internals deferred to Phase 2e.

- **`shekyl-chacha` AEAD extension.** Added `chacha20poly1305` (v0.10)
  support: `encrypt_with_aad` and `decrypt_with_aad` wrapping
  XChaCha20-Poly1305. No hand-rolled AEAD — nonce handling, constant-time
  tag comparison, and AD framing delegated to audited crate. 6 new tests.

- **`RecoveredOutput` now includes `combined_ss`.** The scan result carries
  the 64-byte combined shared secret so the merged scan FFI can optionally
  persist it without re-doing KEM decapsulation. Wiped by `ZeroizeOnDrop`.

- **ML-KEM shared secret `Zeroizing` wrap (W5 fix).** All 4 production
  sites where `ml_ss.into_bytes()` produces a bare stack-local now wrap
  the result in `Zeroizing<[u8; 32]>`, ensuring the ML-KEM shared secret
  bytes are zeroed on scope exit. Closes the W5 correlation leak.

- **Fixed stale `shekyl_construct_output` C header.** Added missing
  `tx_key_secret` parameter to match the Rust implementation.

- **KEM derivation KAT vectors.** `docs/test_vectors/KEM_DERIVE_V1_KAT.json`
  with 8 pinned vectors for `derive_kem_seed`. Serves as tripwire against
  silent behavior changes from `fips203` or `curve25519-dalek` upgrades.

- **`fips203` exact version pin.** Pinned to `=0.4.3` with audit comment
  explaining the `DummyRng::fill_bytes = unimplemented!()` risk.

- **Fuzz target for `derive_output_key`.** Exercises `derive_output_key` and
  `recover_recipient_spend_pubkey` round-trip with fuzzer-supplied inputs.

- **Ledger V3 hard gate.** `device_ledger.cpp` now has a `#error` that fires
  when `WITH_DEVICE_LEDGER` is defined, preventing silently broken builds.
  The Ledger APDU protocol has not been updated for V3 two-component keys.

- **Fuzz target for malformed KEM ciphertexts on scan.** New
  `fuzz_scan_malformed_ct` exercises corrupted, truncated, and random ML-KEM
  ciphertexts through `scan_output_recover` with a valid wallet KEM secret.
  Validates ML-KEM implicit rejection + downstream algebraic checks fail
  closed without panics or timing leaks.

### 📚 Documentation

- **Security properties of the derivation** section in
  `docs/POST_QUANTUM_CRYPTOGRAPHY.md`. Documents the y==0 defense-in-depth
  stack (construction assert + probabilistic impossibility + fuzz coverage),
  explains why a wire-level y==0 check is impossible, documents malformed
  KEM ciphertext handling through ML-KEM implicit rejection, view-tag
  pre-filter behavior on adversarial match grinding, and the wallet cache
  version gate requirement for PR-wallet.

- **Tightened malformed KEM ciphertext framing.** Reframed `amount_tag` as
  a ~99.6% cheap pre-filter (performance optimization), not a security gate.
  Commitment algebraic check `C == z*G + amount*H` is the soundness barrier.
  Documented structural independence of the two algebraic checks (different
  HKDF labels, different scalar families).

- **Wallet cache version gate hardened.** Added mandatory AAD binding
  (include `cache_format_version` in XChaCha20-Poly1305 AAD to prevent
  version-confusion attacks) and hard no-migration policy (delete and resync
  from seed, never in-place migration).

### 🗑️ Removed

- **`ecdhTuple` / `ecdhEncode` / `ecdhDecode` removal.** Deleted the
  Monero-era ECDH amount-masking struct and encode/decode functions from
  `rctTypes.h`, `rctOps.h/.cpp`, `device.hpp`, `device_default.hpp/.cpp`,
  `device_ledger.hpp/.cpp`, and the Trezor protocol files. The
  `enc_amount_to_ecdh_compat` shim is deleted.

- **`check_tx_key_helper` / `is_out_to_acc` deletion.** Both overloads of
  `wallet2::check_tx_key_helper` and `wallet2::is_out_to_acc` removed.
  These used `derive_public_key` (Keccak Category 1) and the old ecdhDecode
  path. Replaced by KEM-based proof FFI round-trip in `check_tx_key`.

- **`crypto::generate_tx_proof` / `generate_tx_proof_v1` / `check_tx_proof`
  deletion.** Monero-era DH-based Schnorr proof functions removed from
  `crypto.cpp`, `crypto.h`, `device_default.cpp`, `device_ledger.cpp`,
  `device.hpp`, and derived device headers. `HASH_KEY_TXPROOF_V2` removed
  from `cryptonote_config.h`.

- **`ecdh.rs` module stub cleanup.** Removed orphaned `mod ecdh` declaration
  and associated test functions from `shekyl-tx-builder` (module file was
  previously deleted, declaration left behind).

- **V3-from-genesis Boost serialization purge (`wallet2.h`).** Deleted all
  `if (ver < N)` migration branches from Boost `serialize` functions for
  `transfer_details`, `unconfirmed_transfer_details`, `confirmed_transfer_details`,
  `payment_details`, `address_book_row`, `unsigned_tx_set`, `signed_tx_set`,
  `tx_construction_data`, and `pending_tx`. Deleted the `initialize_transfer_details`
  helper (both saving and loading overloads). Reset all `BOOST_CLASS_VERSION`
  macros to 1 (genesis version). Added `assert(ver == 1)` guards. Epee cache
  envelope `if (version < N)` branches also removed, replaced with
  `assert(version == 2)`. Staking fields (`m_staked`, `m_stake_tier`,
  `m_stake_lock_until`, `m_last_claimed_height`) and new Phase 2b field
  (`m_k_amount`) added to the `transfer_details` Boost serializer. Legacy
  `m_rct` field no longer serialized (previously removed from struct).

### 🔄 Changed

- **Phase 2e: Proof functions collapsed to Rust FFI (PR-wallet).** All six
  wallet proof functions (`get_tx_proof`, `check_tx_proof`, `get_reserve_proof`,
  `check_reserve_proof`) now delegate to the `shekyl-proofs` Rust crate via
  the FFI bridge. `check_tx_key` also uses the FFI round-trip (generate outbound
  proof + verify with on-chain data). The intermediate C++ helpers
  `check_tx_key_helper` (both overloads) and `is_out_to_acc` have been deleted.
  New `gather_on_chain_proof_data` helper extracts output keys, commitments,
  encrypted amounts, and KEM ciphertexts from transactions for proof
  verification. Reserve proof wire format now includes output locators
  (txid + index_in_tx) as a header so the verifier can independently fetch
  on-chain data from the daemon.

- **Phase 2f: Category 1 Keccak deletions (PR-wallet).** Deleted Monero-era
  DH-based proof functions from the crypto layer: `crypto::generate_tx_proof`,
  `crypto::generate_tx_proof_v1`, `crypto::check_tx_proof`, along with their
  device implementations (device_default, device_ledger) and virtual interface
  declarations. Removed `HASH_KEY_TXPROOF_V2` from `cryptonote_config.h`.
  Removed orphaned `ecdh.rs` module declaration and tests from
  `shekyl-tx-builder`. Remaining Category 1 functions (`derive_public_key`,
  `derivation_to_scalar`, `derive_subaddress_public_key`, `decodeRctSimple`)
  still have live callers in scan/sign paths and are deferred to Phase 3
  migration. `ecdhHash` and `genCommitmentMask` have been removed.

- **Phase 2d: Collapsed signing via `shekyl_sign_fcmp_transaction` (PR-wallet).**
  The CLI wallet's `transfer_selected_rct` now calls the Rust collapsed
  signing FFI instead of C++ `genRctFcmpPlusPlus`. C++ builds JSON arrays
  of `FcmpSignInput` (per-input `combined_ss`, `output_index`, tree layers)
  and `OutputInfo` (per-output `commitment_mask`, `enc_amount`), then
  unpacks the returned `SignedProofs` (BP+ blob, FCMP++ proof, pseudo-outs,
  commitments, enc_amounts) into `tx.rct_signatures`. Rust owns all
  witness assembly — C++ never touches the ephemeral spend secret `x`.
  `genRctFcmpPlusPlus` is deprecated (retained only for `chaingen.cpp`
  test infrastructure).

- **Rust `sign_transaction` updated for v3 HKDF semantics (PR-wallet).**
  `OutputInfo` now carries `commitment_mask: [u8; 32]` and `enc_amount:
  [u8; 9]` (pre-derived by `construct_output`), replacing the old
  `amount_key` field. `SignedProofs.enc_amounts` widened from 8 to 9 bytes.
  The signing pipeline uses pre-derived HKDF masks for BP+ instead of
  generating random ones, and uses pre-encrypted amounts instead of
  Keccak-based ECDH encoding.

- **`wallet2_ffi.cpp` `enc_amounts` field name fix.** The native-sign
  finalize path now reads `enc_amounts` from Rust `SignedProofs` JSON
  (was incorrectly reading `ecdh_amounts`).

- **`enc_amounts` field comment updated in `rctTypes.h`.** Clarifies that
  byte [8] is the HKDF-derived `amount_tag` AAD, documents the Rust scanner
  validation behavior (reject on mismatch), and removes the stale
  `RESERVED_AMOUNT_TAG_PLACEHOLDER` reference.

- **Comprehensive CLI User Guide (`docs/USER_GUIDE.md`).** Covers all shipped
  executables, daemon operation (flags, config file, console commands), wallet
  CLI (create, restore, send, receive, proofs), staking (tiers, unstake,
  claim, accrual rules), mining, PQC multisig (file-based workflow, size
  table), anonymity networks (Tor/I2P), wallet RPC, blockchain utilities,
  security/backup, and troubleshooting. Mirrors the GUI wallet guide structure
  for easy cross-referencing.

- **C++/Rust cross-validation test for `total_weighted_stake`.** New test in
  `staking.cpp` constructs the same staker set via both the C++ 128-bit cache
  accumulation and the Rust FFI, then asserts byte-equality of the results.
  Prevents spec/impl drift regression.

- **`u128` saturation test.** Demonstrates that the u128 weighted stake does NOT
  saturate where u64 would (100M stakers at 100 SKL, tier 2), and verifies
  reward computation remains correct with the large denominator.

- **LMDB write atomicity audit.** Comprehensive audit of all `BlockchainLMDB`
  write paths (block connect, block pop, txpool, alt blocks, staking, FCMP++
  curve tree). Documented in `docs/LMDB_WRITE_ATOMICITY_AUDIT.md`. Found and
  fixed a missing `lock.commit()` in `get_relayable_transactions` (Dandelion++
  timestamp rollback bug) and added a defensive `db_wtxn_guard` around the
  staker accrual reversal in `pop_block_from_blockchain`.

- **LMDB schema reference (`docs/LMDB_SCHEMA.md`).** Complete documentation of
  all 28 sub-databases: LMDB names, open flags, custom comparators, key/value
  byte layouts with struct field offsets, read/write access patterns, and hard
  fork version introduction. Standalone audit value and prerequisite for the
  eventual heed migration.

- **Vendored dependency tracking (`docs/VENDORED_DEPENDENCIES.md`).** Documents
  the vendored LMDB version (0.9.70, based on OpenLDAP `mdb.master` branch),
  applied upstream patches (ITS#9385, ITS#9496, ITS#9500, etc.), CVE review
  (CVE-2026-22185 does not affect us), and the `mdb.master` vs `mdb.master3`
  branch distinction relevant to future heed migration.

- **V4 design notes (`docs/V4_DESIGN_NOTES.md`).** Records the heed LMDB
  migration deferral with detailed reasoning (shared-write risk, schema drift,
  map resize race conditions) and the recommended approach for V4 (single
  Rust-owned Env, no split write ownership, full BlockchainLMDB unit cutover).

- **Additional C++ conservation-invariant tests.** Six new tests in
  `tests/unit_tests/staking.cpp`: weighted denominator >= raw sum invariant,
  tier-0 weight equality, higher-tier strict inequality, zero-staker burn path,
  single-staker full capture, dust staker conservation, multi-block claim range
  conservation, and MAX_CLAIM_RANGE boundary validation.

- **`shekyl-wallet-core` crate.** New Rust crate providing transaction builder
  plans for stake, unstake, and claim operations. Includes `ClaimTxBuilder` for
  constructing claim transaction plans with automatic MAX_CLAIM_RANGE splitting,
  and `ClaimAndUnstakePlan` for the two-step drain-then-unstake workflow.

- **Coin selection module (`shekyl-scanner/coin_select.rs`).** Min-relatedness
  output selection algorithm that prefers combining outputs with fewer shared
  metadata fingerprints (tx hash, block height, subaddress, tier) for improved
  on-chain privacy. Supports dust separation and configurable selection criteria.

- **Output freezing and coin control.** `WalletState` now supports freeze/thaw
  of individual outputs by index or key image, with frozen outputs excluded from
  spendable candidate lists. New `spendable_outputs()` method with optional
  account, subaddress, and minimum amount filters.

- **Staker pool tracking in Rust (`shekyl-scanner/staker_pool.rs`).** Wallet-side
  `StakerPoolState` mirrors per-block accrual records from the daemon, enabling
  local reward estimation without RPC round-trips. Supports reorg handling and
  conservation invariant checking.

- **Claim watermark tracking.** `TransferDetails` now carries `last_claimed_height`
  for monotonic claim watermark management. `WalletState` exposes
  `update_claim_watermark()`, `claimable_outputs()`, and
  `claimable_rewards_summary()` methods. New `ClaimableInfo` struct provides
  per-output claim state including accrual frozen status.

- **New RPC methods.** `get_claimable_stakes`, `get_unstakeable_outputs`,
  `freeze`, and `thaw` added to the Rust scanner-backed RPC handler. All four
  are routed through the Rust scanner when `rust-scanner` feature is active.

- **GUI wallet staking bridge.** `wallet_bridge.rs` extended with
  `get_scanner_claimable_stakes`, `get_scanner_unstakeable_outputs`,
  `scanner_freeze`, and `scanner_thaw` for Tauri frontend integration.

- **Staking transaction types in `shekyl-oxide`.** `Input::StakeClaim` variant
  (binary tag 0x03) and `Output::staking: Option<StakingMeta>` (binary tag 0x04)
  added with full binary serialization/deserialization. `StakingMeta` carries
  the `lock_tier` field (`lock_until` is computed dynamically).

- **Property-based staking tests.** 11 new property tests in `shekyl-staking`:
  conservation across uniform/mixed/stress scenarios, proportionality, floor
  division safety, weight function validation, multi-block accumulation bounds,
  and adversarial edge cases.

- **`shekyl-chacha` crate.** New Rust crate providing XChaCha20 (192-bit nonce)
  stream cipher for wallet and cache file encryption. Wraps the NCC-audited
  RustCrypto `chacha20` crate. Exported via FFI as `xchacha20()`, replacing
  the C implementation in `chacha.c`.

- **KEM-derived output secrets (`OutputSecrets`).** New Rust infrastructure in
  `shekyl-crypto-pq/src/derivation.rs` derives per-output secrets (`ho`, `y`,
  `z`, `k_amount`, `view_tag_combined`, `amount_tag`, `ml_dsa_seed`) from the
  combined X25519 + ML-KEM shared secret via HKDF-SHA-512 with distinct info
  labels. Includes `derive_view_tag_x25519` for fast wallet scan pre-filtering
  without ML-KEM decapsulation. FFI exports: `shekyl_derive_output_secrets`,
  `shekyl_derive_view_tag_x25519`.

- **Cross-language HKDF test vectors.** Python reference implementation
  (`tools/reference/derive_output_secrets.py`) generates locked JSON test
  vectors (`docs/test_vectors/PQC_OUTPUT_SECRETS.json`). Rust unit tests
  validate byte-for-byte against these vectors.

- **Witness header constant.** `SHEKYL_PROVE_WITNESS_HEADER_BYTES = 256`
  defined in both `shekyl_ffi.h` and `shekyl-ffi/src/lib.rs`, replacing all
  magic literal 256 values.

- **Consensus `mask=1` placeholder.** `check_commitment_mask_valid()` wired
  into `check_tx_outputs` for all v3 transactions. Returns accept-all now;
  PR-construct will flip to reject `zeroCommit` form for non-coinbase.

- **HKDF label registry.** `docs/POST_QUANTUM_CRYPTOGRAPHY.md` now documents
  all HKDF salt/info pairs for the per-output derivation stream and the
  separate X25519-only view tag derivation.

- **Unified Rust output construction (`construct_output`).** New
  `shekyl-crypto-pq/src/output.rs` implements `construct_output` (KEM
  encapsulation + HKDF → two-component key `O = ho*G + B + y*T`, Pedersen
  commitment `C = z*G + amount*H`, encrypted amount, view tag, PQC leaf
  hash) and `scan_output_recover` (KEM decapsulation + HKDF → recovered
  spend key `B' = O - ho*G - y*T` for subaddress lookup, plus all per-output
  secrets). FFI exports: `shekyl_construct_output`, `shekyl_scan_output_recover`.

- **PQC signing in Rust (`sign_pqc_auth`).** ML-DSA-65 keypair is derived,
  used, and wiped entirely within Rust. The secret key never crosses the
  FFI boundary. FFI export: `shekyl_sign_pqc_auth`.

- **FCMP++ witness header assembly in Rust.** The 256-byte witness header
  (`[O:32][I:32][C:32][h_pqc:32][x:32][y:32][z:32][a:32]`) is now assembled
  via `shekyl_fcmp_build_witness_header` with a typed `ProveInputFields`
  struct, replacing 8 raw `memcpy` calls in C++.

- **`construct_miner_tx` and `construct_tx_with_tx_key` rewired to Rust.**
  Both v3 output construction paths now call `shekyl_construct_output` per
  output in a unified loop. KEM ciphertexts and PQC leaf hashes are written
  to `tx_extra`. The legacy `derivation_to_y_scalar` path is retired on all
  construction paths.

- **Wallet scanner uses `scan_output_recover`.** `wallet2::process_new_transaction`
  has a v3-specific scanning path that calls `shekyl_scan_output_recover`
  for KEM decapsulation, HKDF derivation, amount recovery, and subaddress
  lookup. Key images are computed as `(ho + b_spend) * Hp(O)`.

- **X25519-derived view tag.** Per-output view tags are now derived from the
  X25519 shared secret only (no ML-KEM needed), enabling fast wallet scan
  pre-filtering. Written during construction, checked first during scanning.

- **`additional_tx_keys` removed for v3.** `need_additional_txkeys` is false
  for `tx.version >= 3`. The `additional_tx_public_keys` field is no longer
  populated or consumed in v3 construction or scanning.

- **Real Pedersen commitments for coinbase (`RCTTypeNull`).** `outPk` and
  `enc_amounts` are now serialized for `RCTTypeNull` transactions.
  `blockchain_db.cpp` uses the on-chain `outPk[i].mask` for v3+ coinbase
  instead of computing `zeroCommit(amount)`.

- **`check_commitment_mask_valid` enforced.** Rejects trivial commitment
  masks (`z = 0` or `z = 1`) for all non-coinbase v3 outputs. Called from
  both `check_tx_outputs` and `prevalidate_miner_transaction`.

- **PQC salt consolidation.** All per-output PQC key derivation now uses the
  unified `OutputSecrets.ml_dsa_seed` from salt B
  (`shekyl-output-derive-v1`). The legacy `HKDF_SALT_PQC_DERIVE` salt A is
  deleted. **Testnet reset required** — invalidates all existing `h_pqc`.

- **Chaingen test infrastructure updated for v3.** `init_output_indices`,
  `fill_tx_sources`, `init_spent_output_indices`, and `construct_fcmp_tx`
  now use `shekyl_scan_output_recover` for HKDF-based output ownership
  detection, mask recovery, and key image computation.

- **`genRctFcmpPlusPlus` uses HKDF commitment masks.** The function now accepts
  pre-computed HKDF `z` scalars (`commitment_masks`) and pre-computed encrypted
  amounts (`enc_amounts_precomputed`) instead of re-deriving them internally via
  Keccak. This fixes a critical mismatch where BP+ proofs used Keccak-derived
  masks while `scan_output` expected HKDF-derived values. The old `amount_keys`
  parameter is removed. **Testnet reset required** — on-chain commitments and
  encrypted amounts are now HKDF-derived, incompatible with prior Keccak format.

- **Stake claim outputs use `shekyl_construct_output`.** The wallet's
  `create_stake_claim_tx` now constructs outputs via the unified Rust HKDF path,
  producing correct output keys, view tags, KEM ciphertexts, leaf hashes, and
  `enc_amounts` with `amount_tag`. BP+ blinding factors remain constrained by
  the `zeroCommit` pseudo-out balance equation (sum to N).

- **Chaingen PQC signing via `shekyl_sign_pqc_auth`.** Core test
  `construct_fcmp_tx` now uses the high-level FFI that derives, signs, and wipes
  the ML-DSA secret key entirely inside Rust. The raw `shekyl_pqc_sign` call
  (which accepted the secret key as a C++ byte pointer) is replaced.

- **`zeroCommit` dead code removed from DB layer.** `blockchain_db.cpp` and
  `db_lmdb.cpp` no longer fall back to `zeroCommit(amount)` for output
  commitments. All outputs (including coinbase) use on-chain `outPk[i].mask`.
  The `pre_rct_outkey` branch in LMDB now throws for `amount != 0` (Shekyl
  has no pre-RCT outputs).

- **RCTTypeNull round-trip serialization test.** New test in
  `tests/unit_tests/serialization.cpp` verifies that `RCTTypeNull` transactions
  with populated `outPk` and `enc_amounts` (8-byte amount + 1-byte `amount_tag`)
  survive binary serialize/deserialize round-trip.

- **libFuzzer harness for `construct_output`.** New fuzz target
  `fuzz_construct_output` in `rust/shekyl-crypto-pq/fuzz/` exercises
  `construct_output` + `scan_output` round-trip with arbitrary spend keys,
  amounts, corrupted `enc_amount`, and wrong `amount_tag`.

- **libFuzzer harness for malformed KEM keys.** New fuzz target
  `fuzz_construct_output_malformed_kem` feeds arbitrary bytes as X25519
  and ML-KEM-768 encapsulation keys to `construct_output`. Exercises
  wrong-length, oversized, and garbage KEM public key inputs to ensure
  the function returns `Err`, never panics.

- **PQC leaf hash known-answer test.** New JSON fixture
  `docs/test_vectors/PQC_LEAF_HASH_KAT.json` (8 vectors) pins the output of
  `derive_pqc_leaf_hash(combined_ss, output_index)`. Rust KAT test validates
  byte-for-byte against the fixture.

- **Coinbase `check_commitment_mask_valid` hardened.** For `RCTTypeNull` (coinbase)
  outputs, the consensus check now rejects commitments that equal
  `zeroCommit(public_amount)` (i.e. `C = G + amount*H`), preventing miners
  from constructing trivial-mask coinbases that leak amount to observers.
  Non-coinbase defense-in-depth checks (identity and G) are retained.

- **Dead Keccak y-scalar fallback removed from wallet scanner.** The
  `else if (tx.vout[o].amount == 0)` and `else if (miner_tx)` branches that
  fell back to `derivation_to_y_scalar` are removed. Shekyl is v3 from genesis;
  all matched outputs must succeed the HKDF scan path. A hard
  `wallet_internal_error` is thrown if `v3_hkdf_scanned` is false, preventing
  silent domain fallback that would produce unspendable outputs.

- **Legacy coinbase construction path removed.** `construct_miner_tx` now
  asserts PQC key presence with a clear error message (`CHECK_AND_ASSERT_MES`)
  before entering the output construction loop, instead of falling back to
  legacy Keccak `derive_public_key` / `derive_view_tag` which would produce
  an invalid (unscannable, missing `outPk`/`enc_amounts`) coinbase. All Shekyl
  addresses carry PQC keys from genesis.

- **Genesis coinbase builder uses `shekyl_construct_output`.**
  `build_genesis_coinbase_from_destinations` now constructs outputs via the
  Rust HKDF path, producing correct HKDF-derived output keys, view tags,
  commitments, encrypted amounts with `amount_tag`, KEM ciphertexts, and
  PQC leaf hashes. The legacy Keccak derivation path is removed.

- **Legacy `additional_tx_public_keys` dead code removed.** The
  `need_additional_txkeys` logic, `additional_tx_public_keys` vector, and
  pre-v3 output derivation loop in `construct_tx_with_tx_key` are deleted.
  V3 replaces per-output additional tx keys with KEM ciphertext (tag 0x06).

### 🔄 Changed

- **`transfer_details::m_mask` type changed.** `rct::key` → `crypto::secret_key`
  for automatic zeroization on drop. All RCT call sites use explicit
  `rct::sk2rct()` / `rct::rct2sk()` conversion. Binary-compatible (same
  32-byte layout).

- **`ecdhInfo` replaced by `enc_amounts`.** The per-output encrypted amount
  format changes from `ecdhTuple` (64 bytes: 32 mask + 32 amount) to
  `std::array<uint8_t, 9>` (8 bytes XOR-encrypted amount + 1 byte amount
  tag). Affects `rctSigBase`, all serialization paths (binary, boost, JSON),
  and transaction construction (`genRctFcmpPlusPlus`, `fill_construct_tx_rct_stub`,
  wallet claim construction).

- **`ecdhEncode` removed.** The ECDH encoding function is deleted from
  `rctOps`, `device.hpp`, and `device_default`. Transaction construction now
  writes `enc_amounts` directly via Rust HKDF-based output construction.
  `ecdhDecode` is retained as a scanner shim until the wallet migrates to
  Rust `scan_output`. `ecdhHash` and `genCommitmentMask` have been fully
  removed from `rctOps`, the device interface chain, and tests.

- **FROST SAL deferred to V4.** Per-output HKDF-derived `y` is incompatible
  with DKG group-shared `y`. FROST SAL section in `docs/PQC_MULTISIG.md`
  marked as deferred with V4 resolution path (Carrot-style address scheme).

### 🐛 Fixed

- **`sc_check()` signed left-shift undefined behavior.** `signum(...) << k` on
  `int64_t` in `crypto-ops.c` is UB when the result is negative. Introduced
  `signed_lshift()` helper that uses multiplication on non-GCC compilers.
  Ported from monero@c5be4dd.

- **`wallet2::verify_password()` logic inversion.** Background wallet detection
  used `HasParseError() && IsObject()` instead of `!HasParseError() && IsObject()`,
  causing background wallets to fail password verification. Added the missing `!`.
  Ported from monero@b19cd82.

- **HTTP digest auth missing client nonce (`cnonce`).** The epee HTTP client sent
  an empty `cnonce` with `qop=auth`, weakening the digest exchange against replay
  attacks. Now generates a random 16-byte cnonce via `RAND_bytes` and includes it
  in the response hash and Authorization header. Ported from monero@3d6b9fb.

- **Critical: SAL `y` / commitment mask `z` conflation in FCMP++ prover.**
  `wallet2.cpp` passed `td.m_mask` (Pedersen commitment mask) as `spend_key_y`
  to the FCMP++ prover, but SAL requires `y` such that `O = xG + yT`. Since
  legacy outputs had `y = 0` and `z != 0`, `OpenedInputTuple::open` always
  failed. Fixed by migrating to two-component output keys (`O = xG + yT`)
  where `y = Hs_y(derivation || i)`, and passing `z` as a separate
  `commitment_mask` field. Affects every spend on the chain — this was the
  root cause of all FCMP++ proof generation failures.

- **Coinbase commitment mask in test harness.** `fill_tx_sources` in
  `chaingen.cpp` set `ts.mask = rct::zero()` for coinbase, but
  `zeroCommit(amount) = G + amount*H` has mask = scalar 1. Fixed to
  `rct::identity()`.

- **Critical: u64 saturation in `total_weighted_stake` (Bug 7).** The in-memory
  cache and LMDB `staker_accrual_record` used `uint64_t` for the tier-weighted
  stake denominator. With 12-decimal atomic units and tier multipliers > 1.0,
  this saturates at ~18.4M SHEKYL of weighted stake — well below moderate
  adoption. Reward computation collapses to a meaningless ceiling once saturated.
  Fixed by widening to u128 end-to-end: in-memory cache uses lo/hi u64 pairs
  with proper carry arithmetic, LMDB record gains `total_weighted_stake_hi`
  field (32→40 bytes), FFI `shekyl_calc_per_block_staker_reward` accepts lo/hi
  parameters, and Rust `AccrualRecord`/`StakeRegistry::total_weighted_stake()`
  return u128.

- **Critical: back-dating exploit on first claim (Bug 3).** `check_stake_claim_input`
  only enforced `from_height == watermark` when watermark > 0. For the first
  claim (no watermark), `from_height` was unconstrained. An attacker could stake
  at block N, then submit a claim with `from_height = 0`, walking 10,000
  historical blocks and collecting rewards against denominators that never
  included the attacker's output. Fixed by looking up the staked output's
  creation height and requiring `from_height >= creation_height` when no
  watermark exists.

- **Critical: inter-tx pool sufficiency race within a block (Bug 4).** The per-tx
  pool balance check in `check_tx_inputs` reads the pre-block pool balance, so
  five claim txs each claiming 1000 against a pool of 3000 all individually pass.
  The silent-skip path in `add_transaction_data` then lets over-claimed txs
  through without decrementing the pool. Fixed with two changes: a block-level
  aggregate pool check in `handle_block_to_main_chain` that sums all claim
  amounts across ALL txs and rejects the block if the total exceeds the pool,
  plus converting the silent-skip path in `add_transaction_data` to a hard throw
  (dead code if validation is correct, fatal if not).

- **Reorg watermark restoration loses data (Bug 5).** `remove_transaction` used
  `from_height == 0` as the signal for "first claim, remove watermark." But
  `from_height` for a first claim is typically the creation height (non-zero).
  Fixed by looking up the staked output's creation height to distinguish first
  claims from subsequent claims.

- **Reorg pool reversal direction wrong for no-staker blocks (Bug 6).**
  `pop_block_from_blockchain` unconditionally subtracted accrued inflow from
  `pool_balance`, but for no-staker blocks the inflow was burned (not added to
  pool). Popping such a block caused a spurious pool underflow. Fixed by reading
  the accrual record's `total_weighted_stake`: if zero, subtract from
  `total_burned` instead of `pool_balance`.

- **Empty-staker-set accrual audit trail.** The `actually_destroyed` field in
  the persisted accrual record did not reflect the no-staker burn because the
  record was written before the burn decision. Fixed by moving `add_staker_accrual`
  to after the no-staker burn path, so the record captures the full
  `actually_destroyed` value.

- **Dandelion++ relay timestamp rollback.** `get_relayable_transactions` in
  `tx_pool.cpp` was missing `lock.commit()`, causing all stem/forward timestamp
  updates to be silently rolled back by the `LockedTXN` destructor. Transactions
  in Dandelion++ stem/forward states could be re-relayed with stale timing data,
  degrading transaction-origin privacy. Fixed by adding the missing commit.

- **Staker accrual reversal without write transaction guard.** The staker pool
  balance and burn total reversal in `pop_block_from_blockchain` relied on the
  caller's batch context for a write transaction but had no defensive guard.
  While all current production callers maintain a batch, a future caller without
  one would crash or produce undefined behavior. Fixed by wrapping the reversal
  block in `db_wtxn_guard`.

- **Critical: weighted denominator bug in staker reward accrual.** The per-block
  `total_weighted_stake` was computed from raw staked amounts instead of
  tier-weighted amounts, causing proportional over-distribution (up to +100% when
  all stakers use the Long tier). Fixed by introducing separate caches for raw
  and tier-weighted stake amounts in `blockchain.h`/`blockchain.cpp`.

- **Claim timing: lock conflated with claimability.** `check_stake_claim_input`
  incorrectly rejected claims when `lock_until > current_height`, making rewards
  unclaimable during the lock period. Fixed by removing the lock-based rejection
  and adding `to_height <= min(current_height, lock_until)` enforcement. Wallet
  filters updated to include both locked and matured-but-unspent outputs.

- **Zero-staker blocks: unclaimed pool accumulation.** When no stakers existed,
  staker emission and fee pool amounts accumulated in `staker_pool_balance`
  indefinitely. Fixed to burn these amounts when `total_weighted_stake == 0`.

- **Staked outputs incorrectly spendable.** `is_spendable()` allowed spending
  staked outputs after maturity. Fixed: staked outputs are never directly
  spendable -- they must go through the unstake path.

- **Claim watermark not persisted.** Added `m_last_claimed_height` to
  `transfer_details` (C++ wallet) and `TransferDetails` (Rust scanner) with
  serialization. FFI layer now calls `stage_claim_watermarks()` after
  broadcasting claim transactions.

- **Critical: stake tx only mineable in exact creation block (Bug 13).**
  `handle_block_to_main_chain` validated staked outputs with strict equality
  `staked.lock_until == blockchain_height + lock_blocks`. Since the wallet
  signed `lock_until = current_height + lock_blocks`, any mempool latency made
  every honest stake tx permanently unminable. Fixed by removing `lock_until`
  from the on-chain `txout_to_staked_key` struct entirely. The effective lock
  expiry is now computed dynamically as `creation_height + tier_lock_blocks` at
  every check site. Removes ~8 bytes per staked output and eliminates the
  signing-time/mining-time mismatch bug class.

- **High: mempool admits unminable stake txs (Bug 12).** Pool admission
  checked tier validity and non-zero `lock_until` but not the strict equality
  that block validation enforced. Honest and malicious stake txs passed
  admission but were rejected at block-add time, causing miners to waste work
  on blocks that would be rejected. Resolved by the Bug 13 fix: with no
  on-chain `lock_until`, the entire validation path is removed.

- **Medium: off-by-one at upper lock boundary (Bug 11).** The accrual scan
  excluded an output at block `lock_until` (`<= eval_height`), but claim
  validation accepted `to_height <= lock_until`. A staker could claim a
  one-block reward at `lock_until` against a denominator that didn't include
  their weight. Fixed by changing the accrual scan to `effective_lock_until <
  eval_height` (inclusive upper bound) and scheduling unlock subtraction at
  `effective_lock_until + 1`. `lock_blocks = N` now means exactly N blocks of
  accrual.

- **Medium: unstake forfeits unclaimed rewards (Bug 8).**
  `create_unstake_transaction` jumped straight to `create_transactions_from`
  without checking for unclaimed reward backlog. A user who staked for the
  long tier and never claimed would silently forfeit all accrued rewards.
  Fixed: the wallet now refuses to unstake if any target output has
  `m_last_claimed_height < min(current_height, effective_lock_until)` and
  instructs the user to claim first.

- **Minor: local claim watermark advanced on broadcast, not confirmation.**
  `update_claim_watermarks` (now `stage_claim_watermarks`) committed the
  watermark immediately after broadcast. If the tx was dropped or never
  confirmed, the local watermark diverged from consensus. Fixed with an
  in-flight tracking system: claims are staged in `m_pending_claim_watermarks`
  at broadcast, committed by `confirm_claim_watermarks` when the tx appears in
  a confirmed block during scan, and expired by
  `expire_pending_claim_watermarks` after 100 unconfirmed blocks.

### 🔄 Changed

- **Wallet encryption upgraded from ChaCha20 (64-bit nonce) to XChaCha20 (192-bit
  nonce).** The 24-byte nonce eliminates collision risk for randomly-generated
  nonces. Implementation moved from C (`chacha.c`) to Rust (`shekyl-chacha`
  crate) using the NCC-audited RustCrypto `chacha20` crate. `CHACHA_IV_SIZE`
  increased from 8 to 24 bytes. Wallet keys files and cache files now use
  XChaCha20 exclusively.

- **Two-component output keys (`O = xG + yT`).** All output public keys now
  include a domain-separated `y` component along generator `T`, satisfying the
  FCMP++ SAL proof's `OpenedInputTuple::open` constraint. Previously, outputs
  were single-component (`O = xG + 0·T`) and the wallet incorrectly passed
  the Pedersen commitment mask `z` as the SAL `y`, causing proof generation to
  fail. The y-scalar uses the `"shekyl_y"` domain separator in `crypto.cpp`.
  The commitment mask `z` is now passed separately in the 256-byte witness
  header at offset 192. `transfer_details` stores `m_y` (boost serial v14).
  Two regression tests in `proof.rs` verify that the old bug (y=mask) fails
  and the correct path (y=real) succeeds.

- **`MAX_TX_EXTRA_SIZE` (24576 bytes).** The previous Monero-era cap (1060) was
  too small for FCMP++ `tx_extra` payloads (hybrid KEM ciphertexts ~1120 B per
  output, PQC leaf hashes, pubkey/nonce). Construction of v3 spends failed once
  PQC fields were appended; the pool and `construct_tx` checks now allow the
  larger bound.
- **`construct_tx` RCT/PQC stubs.** v3 spends require `|pqc_auths| == |vin|`
  for binary serialization, and `RCTTypeFcmpPlusPlusPqc` needs BP+, ECDH, and
  pseudo-out vectors sized to inputs/outputs. `construct_tx` now assigns stub
  `pqc_authentication` entries and calls `rct::fill_construct_tx_rct_stub()`
  (dummy Bulletproofs+, ECDH encoding, Pedersen pseudo-outs) so
  `get_transaction_hash` and JSON/blob round-trips succeed before the wallet
  replaces the RCT payload with `genRctFcmpPlusPlus()`.

### 🗑️ Removed

- **`shekyl_fcmp_derive_pqc_keypair` FFI function.** Deleted the Rust FFI
  function and its C declaration. This function returned the ML-DSA secret key
  to C++, violating the security invariant that PQC secrets stay in Rust.
  Replaced by `shekyl_derive_pqc_leaf_hash` (returns only h_pqc) and
  `shekyl_derive_pqc_public_key` (returns only the public key).

- **`derive_pqc_keypair`, `derive_hybrid_pqc_keypair`, `DerivedPqcKeypair`,
  `DOMAIN_PQC_OUTPUT` from `shekyl-crypto-pq`.** These legacy derivation
  functions used the old salt A (`shekyl-pqc-derive-v1`) and returned secret
  key material. All callers now use `derive_output_secrets` (salt B) +
  `keygen_from_seed` or the higher-level `sign_pqc_auth_for_output`.

- **`derived_pqc_secret_keys`, `derived_pqc_public_keys`, `claim_signing_sks`
  vectors in `wallet2.cpp`.** These C++ vectors held PQC secret keys in wallet
  memory. All 4 call sites migrated to `shekyl_derive_pqc_leaf_hash` +
  `shekyl_sign_pqc_auth`, which derive and zeroize internally in Rust.

- **`pqc_secret_keys` from `native_sign_state` (`wallet2.h`).** The deferred
  native-signing path no longer stores PQC secret keys. The Rust tx-builder
  receives `combined_ss` + `output_index` and derives keys internally.

- **`SpendInput::pqc_secret_key` from `shekyl-tx-builder`.** Replaced with
  `combined_ss: Vec<u8>` (64 bytes) and `output_index: u64`. The Rust
  `sign_pqc_auths` function now calls `sign_pqc_auth_for_output` internally.

- **4 legacy Monero fixture tests in `serialization.cpp`.** Removed
  `portability_wallet`, `portability_outputs`, `portability_unsigned_tx`,
  `portability_signed_tx`. These tested Monero-era wallet/tx formats that
  Shekyl does not support (no backward compatibility).

- **10 Monero-specific long-term block weight tests.** Removed all tests from
  `long_term_block_weight.cpp` (`empty_short` through `cache_matches_true_value`).
  Monero-specific weight baselines do not apply to Shekyl economics.

- **`chacha.c` (C ChaCha implementation).** Replaced by the Rust `shekyl-chacha`
  crate via FFI. The C implementation had a strict aliasing violation in its
  `U8TO32_LITTLE`/`U32TO8_LITTLE` macros (pointer cast to `uint32_t*`).

- **ChaCha8 dead code.** All `crypto::chacha8()` call sites in `wallet2.cpp`
  were Monero backward-compatibility fallbacks for reading pre-2018 wallet
  files. Shekyl has no legacy wallets; these paths were unreachable.

### 🔒 Security

- **ML-DSA secret keys never cross the FFI boundary.** All wallet PQC signing
  paths now use `shekyl_sign_pqc_auth` (Rust FFI) or `sign_pqc_auth_for_output`
  (Rust tx-builder), which derive the keypair from `combined_ss` + `output_index`,
  sign, and zeroize the secret key — all within Rust. No ML-DSA secret key bytes
  exist in C++ memory at any point. This eliminates the largest PQC secret key
  exposure surface (~4064 bytes per input) from the wallet process.

- **XChaCha20 192-bit nonces for wallet encryption.** Upgraded from the DJB
  ChaCha20 64-bit nonce to XChaCha20 192-bit nonce, eliminating nonce collision
  risk for randomly-generated nonces. The previous 64-bit nonce was safe for
  Shekyl's usage pattern but the larger nonce provides a wider safety margin.

- **Secure memory hardening (project-wide).** Systematic implementation of the
  `secure-memory.mdc` rule across Rust and C++ codebases:
  - `shekyl_buffer_free` now uses `zeroize` crate instead of `std::ptr::write_bytes`,
    preventing the compiler from optimizing away the secret-wiping write.
  - `native_sign_state::clear()` in `wallet2.h` now `memwipe`s all secret fields
    (`spend_key_x`, `spend_key_y`, `h_pqc`, `amount_key`, `pqc_secret_keys`) before
    clearing vectors.
  - Added `prctl(PR_SET_DUMPABLE, 0)` to daemon (`main.cpp`), simplewallet, and
    `wallet2_ffi_create()` to prevent core dumps containing key material on Linux.
  - Passwords, seeds, spend keys, and view keys in `wallet2_ffi.cpp` JSON-RPC dispatch
    now use `memwipe` scope guards to wipe temporary `std::string` buffers after use.
  - New `shekyl_madvise_dontdump` FFI function (`MADV_DONTDUMP` on Linux, no-op elsewhere)
    declared in `shekyl_secure_mem.h`.
  - PQC long-lived secret keys (`m_pqc_secret_key`) are now `mlock`ed and
    `madvise(MADV_DONTDUMP)`ed after generation and decryption, and `memwipe`d +
    `munlock`ed on `forget_spend_key()`.

- **Dev branch audit: Tier 1-6 security and code hardening.** Comprehensive
  re-audit of the dev branch with 22 findings addressed:
  - **PQC secret key lifecycle (Tier 1).** Added `~account_keys()` destructor
    that wipes all secret keys (classical + PQC) and munlocks PQC material.
    Fixed `create_from_keys` and `set_null` to wipe+unlock PQC secrets before
    clearing. Prevents secrets from lingering in freed heap memory.
  - **Debug trait on secret key types (Tier 1).** Removed `#[derive(Debug)]`
    from `HybridSecretKey`, `HybridKemSecretKey`, and `SharedSecret`. All now
    implement manual `Debug` printing `[REDACTED]` to prevent log leakage.
  - **Proof generation panic removal (Tier 1).** Replaced 12
    `ScalarDecomposition::new(...).unwrap()` calls in `proof.rs` with
    `?`-propagated `ProveError::ScalarDecompositionFailed`. Zero-scalar blinding
    factors now return a clean error instead of panicking the wallet.
  - **RELEASE-BLOCKER resolution (Tier 1).** Evaluated and downgraded all 6
    RELEASE-BLOCKER comments in shekyl-oxide to TODO with documented
    justifications. None were correctness or security blockers.
  - **FROST multisig feature-gated (Tier 1).** All FROST SAL and DKG FFI
    functions gated behind `#[cfg(feature = "multisig")]`. Production builds
    exclude multisig code unless the feature is enabled. C++ `#ifdef
    SHEKYL_MULTISIG` blocks have been removed from `shekyl_ffi.h`,
    `wallet2.h/cpp`, and `wallet2_ffi.cpp` — FROST multisig is now
    consumed exclusively through the Rust wallet crates.
  - **CString unwrap removal (Tier 2).** Replaced all `CString::new().unwrap()`
    in `shekyl-wallet-rpc` with `to_cstring()` helper returning `WalletError`.
    Fixed `Mutex::lock().unwrap()` in server.rs to return JSON-RPC error on
    lock poisoning.
  - **Sign function zeroization (Tier 2).** `HybridEd25519MlDsa::sign()` now
    wraps temporary secret arrays in `Zeroizing<[u8; N]>` for automatic cleanup.
  - **hex_to_key temp buffer wiped (Tier 2).** Added `memwipe` scope guard
    to `hex_to_key` in `wallet2_ffi.cpp`.
  - **PQC verify debug gated (Tier 2).** `shekyl_pqc_verify_debug` now only
    compiled with `debug_assertions` or `debug-verify` feature to prevent use
    as a signature oracle in production.
  - **Free-string wipe (Tier 2).** `wallet2_ffi_free_string` now wipes the
    buffer before freeing, protecting against secret-bearing JSON residue.
  - **Buffer free contract documented (Tier 2).** `shekyl_buffer_free` len
    safety contract documented in both Rust doc-comment and C header.
  - **Claim builder silent wrong index (Tier 2).** `position(...).unwrap_or(0)`
    replaced with explicit `TransferNotFound` error in `claim_builder.rs`.
  - **deny(unsafe_code) added (Tier 3).** Added to 5 pure-Rust crates:
    `shekyl-consensus`, `shekyl-economics`, `shekyl-staking`,
    `shekyl-crypto-hash`, `shekyl-crypto-pq`.
  - **Workspace lints inherited (Tier 3).** `[lints] workspace = true` added
    to 11 Shekyl-first crates for consistent Clippy enforcement.
  - **Legacy naming cleanup (Tier 4).** Renamed `MONERO_DEFAULT_LOG_CATEGORY`
    to `SHEKYL_DEFAULT_LOG_CATEGORY` across 128 files.
  - **FCMP++ edge-case tests (Tier 5).** Added 9 parametrized tests covering
    boundary input counts, missing tree paths, empty proof data, count
    mismatches, zero tree depth, and wrong signable_tx_hash.
  - **CI improvements (Tier 6).** Added `.env` to `.gitignore`, created
    explicit CodeQL workflow targeting both `dev` and `main` branches,
    added `permissions: contents: read` to `build.yml`.

- **Base58 overflow and non-canonical encoding fix (monero-oxide fork).**
  `shekyl-base58::decode()` now uses `checked_add` to prevent integer overflow
  during character accumulation, and rejects non-canonical encodings where
  unused high bytes of the decoded sum are non-zero. Defense-in-depth measure;
  Shekyl production addresses use Bech32m.

- **Cargo profile hardening (both Rust workspaces).** All profiles (dev,
  release, test, bench) now enforce `overflow-checks = true` in both the
  monero-oxide fork `Cargo.toml` and the Shekyl `rust/Cargo.toml`. Dev and
  release profiles additionally set `panic = "abort"`.

- **HKDF domain-separated salts for PQC key derivation.** All HKDF-SHA-512
  calls in `shekyl-crypto-pq` now use explicit fixed salts (`shekyl-pqc-derive-v1`,
  `shekyl-master-derive-v1`) instead of `None`. Strengthens domain separation
  and prevents cross-protocol seed reuse if the same combined shared secret
  appears in other contexts.

- **`FrostSalSession` secret deduplication.** Removed the redundant `x`
  (spend secret scalar) from `FrostSalSession` struct fields. Previously the
  secret was stored both in the struct and inside `SalAlgorithm`, with only
  the struct copy explicitly zeroized on drop. Now the secret lives solely
  inside the algorithm, eliminating the unprotected duplicate.

- **Levin double-compression guard.** `try_compress_message` now checks
  `LEVIN_PACKET_COMPRESSED` in the input header before compressing. Prevents
  double-compression of already-compressed messages in future refactors.

- **Divisor degree underflow assertions.** `Divisor::div` now asserts that
  `self.a.degree >= rhs.degree` and `self.b.degree >= rhs.degree` before
  `usize` subtraction, converting silent wraparound into a clear panic with
  diagnostic context.

- **Interpolator allocation bounds fix.** `Interpolator::interpolate` now
  allocates the output coefficient vector using the domain size
  (`self.lagrange_polys.len()`) instead of `evals.len()`, preventing trailing
  zeros from inflating the vector when callers provide excess evaluations.

- **`member_of_list` witness construction hardened.** Replaced
  `next_eval.unwrap()` with `carry_eval.zip(next_eval)` in the FCMP++ circuit
  gadget, eliminating a potential panic if evaluation invariants change.

### ✨ Added

- **`shekyl-tx-builder` crate.** New Rust crate (`rust/shekyl-tx-builder/`)
  consolidating Bulletproofs+ range proofs, FCMP++ full-chain membership proof
  construction, ECDH amount encoding, and PQC (ML-DSA-65) signing into a single
  native Rust call path. Replaces the prior C++ → Rust → C++ → Rust FFI
  round-trip for proof generation. Includes 19 unit tests covering validation
  edge cases (0 inputs, overflow amounts, empty trees, wrong-length PQC keys)
  and ECDH encoding round-trips. All secret key material is wrapped in
  `zeroize::Zeroizing` and wiped on drop.

- **`shekyl_sign_transaction` FFI export.** New C ABI function in `shekyl-ffi`
  wrapping `shekyl-tx-builder::sign_transaction()`. Accepts JSON-serialized
  inputs/outputs, returns a `ShekylSignResult` with either JSON proofs or a
  structured error code and message. Declared in `shekyl_ffi.h`.

- **Wallet RPC `native-sign` feature.** `shekyl-wallet-rpc` gains an optional
  `native-sign` Cargo feature that enables `transfer_native()` — a pure-Rust
  transfer path using `shekyl-tx-builder` directly, eliminating C++ proof FFI
  round-trips. The split pipeline uses `wallet2_ffi_prepare_transfer` (C++ →
  JSON) → `shekyl-tx-builder::sign_transaction` (pure Rust) →
  `wallet2_ffi_finalize_transfer` (JSON → C++).

- **`wallet2_ffi_prepare_transfer` / `wallet2_ffi_finalize_transfer` implemented.**
  Full C++ implementation of the split transfer pipeline. `prepare_transfer`
  activates native-sign mode in `transfer_selected_rct` (skipping C++ proof
  generation), gathers per-input signing data (secret keys, tree paths parsed
  into c1/c2 branch layers, leaf chunks, PQC key material), per-output data
  (dest keys, amount keys), tree context (reference block, curve tree root,
  depth), and serializes everything as hex-encoded JSON matching the Rust
  `SpendInput`/`OutputInfo`/`TreeContext` types. `finalize_transfer` receives
  the Rust-generated `SignedProofs` JSON, manually reconstructs the BP+ struct
  from the Rust blob (handling the V-field format difference), inserts all
  proofs into `tx.rct_signatures`, performs PQC signing using stored secret
  keys, and commits/broadcasts the transaction. Fee estimation uses
  `shekyl_fcmp_proof_len()` to pad the stub FCMP++ proof to the correct
  estimated size.

- **Native-sign mode in `wallet2::transfer_selected_rct`.** New
  `m_native_sign_mode` flag and `native_sign_state` struct on `wallet2`.
  When enabled, `transfer_selected_rct` skips `genRctFcmpPlusPlus` and PQC
  signing, instead storing all signing data for the Rust path. Tree path
  blobs are parsed into structured c1/c2 branch layers. Padded stub proofs
  provide accurate fee estimation.

- **Hex serde for `shekyl-tx-builder` types.** All `[u8; 32]`, `Vec<u8>`,
  and `Vec<[u8; 32]>` fields on `SpendInput`, `OutputInfo`, `TreeContext`,
  `SignedProofs`, `LeafEntry`, and `PqcAuth` now serialize/deserialize as hex
  strings via custom serde modules. This enables clean JSON interop with the
  C++ FFI layer which produces hex-encoded cryptographic keys and blobs.

- **Secure memory Cursor rule.** Added `.cursor/rules/secure-memory.mdc`
  codifying project-wide conventions for cryptographic secret zeroization in
  both Rust (`Zeroizing<T>`, `ZeroizeOnDrop`) and C++ (`memwipe`, scope guards,
  `wipeable_string`), FFI boundary ownership, and OS-level protections (`mlock`,
  `prctl(PR_SET_DUMPABLE, 0)`, `MADV_DONTDUMP`).

- **Vendored monero-oxide protocol crates.** Completed the vendored crate set
  in `rust/shekyl-oxide/`: added `shekyl-primitives` (Keccak-256, Pedersen
  commitments), `shekyl-bulletproofs` (BP+ range proofs), the root `shekyl-oxide`
  crate (transaction/block types, FCMP module), `shekyl-rpc` (daemon RPC trait,
  `ScannableBlock`), and `shekyl-simple-request-rpc` (HTTP transport). Resolved
  the `shekyl-address` naming collision by removing the oxide base58 address
  dependency from the vendored RPC crate (Shekyl uses Bech32m exclusively).
  Added crypto-heavy crate optimizations to `[profile.dev.package]` and
  workspace-level clippy lints for the oxide crates.

- **`shekyl-scanner` crate.** New Rust crate (`rust/shekyl-scanner/`) providing
  a native transaction scanner with Shekyl-specific extensions. Ported the core
  scanning pipeline from monero-oxide (SharedKeyDerivations, Extra parsing,
  ViewPair, per-block/per-tx/per-output ECDH scan loop) and extended it with:
  - PQC KEM ciphertext parsing (tx_extra tag 0x06) and leaf hash parsing (0x07)
  - Staking output detection and balance categorization (matured/locked tiers)
  - `TransferDetails` struct with FCMP++ path precompute, combined PQC shared
    secret, and spend tracking fields
  - `WalletState` for in-memory transfer management with key image dedup, spend
    detection, and reorg handling
  - `BalanceSummary` with staking-aware breakdown (total, unlocked, timelocked,
    staked matured/locked, frozen)

- **Split RPC routing (`rust-scanner` feature).** `shekyl-wallet-rpc` now
  supports a `rust-scanner` feature flag that routes scanner-backed read-only
  methods (get_balance, get_transfers, incoming_transfers, get_height,
  get_staked_outputs, get_staked_balance) to native Rust handlers via
  `shekyl-scanner`, while all mutation methods continue through the C++ FFI.
  Added `ScannerState`, `dispatch_with_scanner()`, and typed scanner handlers.

- **GUI wallet scanner integration.** Updated `wallet_bridge.rs` in
  `shekyl-gui-wallet` to include a `ScannerState` alongside the FFI `Wallet2`
  handle. Added `get_scanner_balance()`, `get_scanner_staked_outputs()`, and
  `get_scanner_height()` bridge methods for future scanner-backed queries.

- **`shekyl-encoding` crate.** New standalone Rust crate (`rust/shekyl-encoding/`)
  for general-purpose Bech32m blob encoding and decoding with arbitrary HRPs.
  Defines HRP constants for wallet proofs (`shekylspendproof`, `shekyltxproof`,
  `shekylreserveproof`, `shekylsig`, `shekylmultisig`, `shekylsigner`).

- **`shekyl-address` crate.** New standalone Rust crate (`rust/shekyl-address/`)
  for network-aware segmented Bech32m address encoding. Defines `Network` enum
  (Mainnet, Testnet, Stagenet) with HRP lookup tables for classical (`shekyl`,
  `tshekyl`, `sshekyl`) and PQC (`skpq`/`skpq2`, `tskpq`/`tskpq2`,
  `sskpq`/`sskpq2`) segments. `ShekylAddress` supports `encode()`, `decode()`,
  and `decode_for_network()`.

- **Generic Bech32m blob FFI.** `shekyl_encode_blob()` and `shekyl_decode_blob()`
  FFI functions allow C++ to encode/decode arbitrary binary data with
  purpose-specific HRPs, replacing all direct Base58 calls in wallet proofs.

- **Network-aware address FFI.** `shekyl_address_encode()` and
  `shekyl_address_decode()` now accept/return a `network` parameter (0=mainnet,
  1=testnet, 2=stagenet) for HRP-based network discrimination.

- **Shekyl-first development rule.** Added `.cursor/rules/shekyl-first-development.mdc`
  codifying that Shekyl core is the authoritative codebase and the monero-oxide
  fork is a disposable downstream consumer.

- **FROST SAL threshold signing for FCMP++ multisig.** New `frost_sal`
  module in `shekyl-fcmp` wraps upstream `SalAlgorithm<Ed25519T>` for
  threshold Spend-Auth-and-Linkability proofs. `FrostSalSession` manages
  per-input FROST state; `prove_with_sal()` constructs FCMP++ proofs from
  pre-aggregated SAL pairs. FFI functions (`shekyl_frost_sal_session_new`,
  `_get_rerand`, `_aggregate_and_prove`, `_session_free`) expose the session
  lifecycle to C++. The `multisig` feature flag enables FROST dependencies
  (`modular-frost`, `transcript`, `rand_chacha`).

- **FROST DKG key management.** New `frost_dkg` module in `shekyl-fcmp`
  provides `SerializedThresholdKeys` for `ThresholdKeys<Ed25519T>`
  serialization/deserialization, group key extraction, and parameter
  validation. FFI functions (`shekyl_frost_keys_import`, `_export`,
  `_group_key`, `_validate`, `_free`) manage threshold keys from C++.

- **Variable-length FCMP++ witness wire format.** `shekyl_fcmp_prove` FFI
  now accepts a single `witness_ptr`/`witness_len` blob containing per-input
  fixed headers, leaf chunk Ed25519 output data, and Helios/Selene branch
  layers. `genRctFcmpPlusPlus` in `rctSigs.cpp` serializes the full witness.

- **Daemon RPC `chunk_outputs_blob`.** `get_curve_tree_path` response now
  includes per-chunk compressed Ed25519 output data (O, I=Hp(O), C,
  H(pqc_pk)) enabling the wallet to pass full output points to the prover.

- **C++ wallet FROST multisig integration (removed).** Previously added
  C++ FROST integration in `wallet2.cpp` (`prepare_multisig_fcmp_proof`,
  `export_multisig_signing_request`, `import_multisig_signatures`, threshold
  key import/export). This C++ code has been replaced by the Rust-native
  wallet crates and all `#ifdef SHEKYL_MULTISIG` blocks have been removed
  from `wallet2.h/cpp`, `wallet2_ffi.cpp`, and `shekyl_ffi.h`.

- **`FrostSigningCoordinator` for multi-input nonce aggregation.** New
  coordinator in `shekyl-fcmp/src/frost_sal.rs` manages per-input preprocess
  collection, nonce sum computation, share collection, and final aggregation
  into `SpendAuthAndLinkability` pairs for `prove_with_sal()`.

- **Full FROST DKG ceremony via `MultisigDkgSession`.** New wallet-level
  wrapper in `shekyl-wallet-core/src/multisig/dkg.rs` drives the `dkg-pedpop`
  `KeyGenMachine` state machine through all three rounds with type-safe
  transitions: `generate_coefficients` → `generate_secret_shares` →
  `calculate_share` → `complete`. DKG messages are exchanged as byte buffers
  (file-based, air-gap compatible).

- **`MultisigSigningSession` for wallet-level FROST orchestration.** New
  session in `shekyl-wallet-core/src/multisig/signing.rs` wraps per-input
  `FrostSalSession` instances and a `FrostSigningCoordinator`, providing
  hex-encoded preprocess/share exchange for transport-agnostic signing.

- **`MultisigGroup` with PQC keypair management.** New type in
  `shekyl-wallet-core/src/multisig/group.rs` stores threshold keys,
  group metadata, and PQC hybrid keypairs with automatic zeroization
  on drop. Supports serialization/deserialization for wallet storage.

- **FROST multisig RPC endpoints.** 9 new JSON-RPC methods in
  `shekyl-wallet-rpc/src/multisig_handlers.rs` for FROST signing
  coordination: `multisig_register_group`, `multisig_list_groups`,
  `multisig_create_signing`, `multisig_sign_preprocess`,
  `multisig_sign_add_preprocess`, `multisig_sign_nonce_sums`,
  `multisig_sign_own`, `multisig_sign_add_shares`,
  `multisig_sign_aggregate`. All byte fields hex-encoded. DKG is
  intentionally excluded from RPC (file-based only).

- **`SalLegacyAlgorithm` and `legacy_multisig` removed from shekyl-oxide.**
  Deleted the legacy Monero multisig SAL algorithm and test module from the
  vendored `shekyl-oxide/fcmp/fcmp++` crate. Only the modern `SalAlgorithm`
  (used by `FrostSalSession`) is retained.

- **16+ new Rust tests for FROST.** 4 `frost_sal` unit tests (session
  creation, pseudo-out distinctness, identity rejection, field roundtrip),
  6 `FrostSigningCoordinator` tests (wrong preprocess count, shares before
  nonces, duplicate shares, nonce sums timing, point addition, bytes
  roundtrip), 2 `FrostSalSession` negative tests, 4 `frost_dkg` unit tests
  (serialization roundtrip, group key extraction, parameter validation,
  byte-level roundtrip), 8 FFI lifecycle tests (null safety, invalid data
  rejection, session handle management), 5 `shekyl-wallet-core` multisig
  tests (DKG 2-of-3 and 3-of-5 roundtrips, DKG state machine errors,
  group serialization, threshold keys roundtrip).

- **FCMP++ prove/verify round-trip test.** `prove_verify_roundtrip()` in
  `rust/shekyl-fcmp/src/proof.rs` exercises the full stack: random key
  generation, single-leaf tree root computation, `prove()`, `verify()`, and
  negative tests (tampered key image, wrong tree root).

### 🐛 Fixed

- **Suppressed vendored crate warnings.** Fixed `dead_code` warning for
  `InconsistentWitness` variant in `generalized-bulletproofs` (only constructed
  under `debug_assertions`) with `#[cfg_attr(not(debug_assertions), allow(dead_code))]`.
  Fixed deprecated `GenericArray::as_slice()` in `helioselene` ciphersuite by
  replacing with `as_ref()`.

- **Stake-claim vs `verRctSemanticsSimple` conflict.** Stake-claim transactions
  use `RCTTypeFcmpPlusPlusPqc` but have no FCMP++ membership proof (they prove
  ownership via PQC auth on public amounts). `ver_non_input_consensus` now
  excludes stake-claim-only transactions from the RCT semantics batch that
  rejects empty `fcmp_pp_proof`.

- **`genRctFcmpPlusPlus` hard-fail on proof failure.** Previously logged and
  returned an `rctSig` with an empty proof when `shekyl_fcmp_prove` failed; now
  throws `CHECK_AND_ASSERT_THROW_MES` so the wallet catches the error
  immediately rather than producing an invalid transaction.

- **PQC leaf scalar now uses proper Selene field reduction.** `PqcLeafScalar::from_pqc_public_key`
  and `hash_pqc_public_key` previously truncated Blake2b-512 to 32 bytes and
  cleared bit 255, which could produce non-canonical values exceeding the
  Selene base field modulus. Now uses `HelioseleneField::wide_reduce` on the
  full 64-byte hash for unbiased, canonical field elements.

- **Deterministic PQC keygen stability.** Replaced `rand::rngs::StdRng` with
  `rand_chacha::ChaCha20Rng` for ML-DSA-65 keypair derivation. `StdRng`'s
  underlying algorithm is not a stability guarantee across `rand` versions,
  which could break wallet-restore-from-seed.

- **Bech32m variant enforcement.** `decode_blob` now strictly enforces the
  Bech32m checksum variant instead of accepting both Bech32 and Bech32m.
  Removed unused `EncodingError::EmptyData` variant.

### 🔒 Security

- **FrostSalSession spend secret zeroized on drop.** The FROST SAL session's
  spend secret scalar is zeroized when the session is dropped, per the
  project-wide secure memory rule. After the `FrostSalSession` secret
  deduplication (see Changed), the secret lives solely inside the
  `SalAlgorithm` and is zeroized through its `Drop` impl.

- **RELEASE-BLOCKER resolved in circuit gadgets.** The `incomplete_add_pub`
  function in the FCMP++ circuit already receives parameters typed as `OnCurve`,
  which guarantees the on-curve constraint. Replaced the
  `RELEASE-BLOCKER(shekyl)` comment with documentation explaining why no
  additional constraint is needed.

- **Pruning watermark hardening.** `BlockchainLMDB::prune_tx_data()` now
  fails the current batch on missing transaction rows (`TX_DNE`) instead of
  logging and continuing, so `tx_prune_next_block` cannot advance on partial
  pruning.

- **FCMP++ compile-path compatibility fixes.** Updated wallet/core-test FCMP++
  construction callsites for the current `genRctFcmpPlusPlus` leaf-chunk API,
  and added explicit cached-chunk to `rct::fcmp_chunk_entry` conversion in
  wallet construction to keep GCC 14 builds green.

- **CI portability and fuzz gate hardening.** Replaced GNU-only `xargs -r`
  usage in Cargo absolute-path guard with a portable shell loop, and added a
  required fuzz-harness inventory smoke gate in Rust CI.

- **Stale fuzz targets updated.** `fuzz_fcmp_proof_deserialize` and
  `fuzz_tx_deserialize_fcmp_type7` now pass the required `signable_tx_hash`
  7th argument to `verify()`. `fuzz_block_header_tree_root` rewritten for the
  current `ProveInput` struct and 4-arg `prove()` signature.

- **`prune_tx_data` miner output lookup.** When storing output-pruning metadata,
  RCT coinbase outputs are keyed under amount `0` in LMDB (same as
  `add_transaction`); pruning now uses that amount for `get_output_key` instead
  of the plaintext `vout.amount`, avoiding `OUTPUT_DNE` during prune for
  miner transactions.

### 🗑️ Removed

- **RingCT-era dead code excision (C++ wallet).** Comprehensive removal of
  ring-signature infrastructure that is structurally unreachable on an FCMP++
  chain. Deleted: `gamma_picker` class and `GAMMA_SHAPE`/`GAMMA_SCALE`
  constants, `transfer_selected` (non-RCT overload), `wallet2::get_outs`
  decoy-fetching overloads (~700 lines), `tx_add_fake_output`,
  `select_available_mixable_outputs`, `select_available_outputs_from_histogram`,
  `get_spend_proof`/`check_spend_proof` (ring-sig-dependent proofs),
  `get_min_ring_size`/`get_max_ring_size`, `m_confirm_non_default_ring_size`
  preference, the entire `ringdb.h`/`ringdb.cpp` subsystem (LMDB ring
  database), ring commands in simplewallet, spend proof RPC endpoints and FFI
  dispatch, `boroSig` struct from `rctTypes.h`, unreachable
  `hf_version < HF_VERSION_FCMP_PLUS_PLUS_PQC` branch in
  `cryptonote_tx_utils.cpp`, `blockchain_blackball` utility, and
  `output_selection.cpp` unit test. Removed LMDB link dependency from wallet
  CMake target.

- **Decoy and ring_size removal from Rust RPC.** Removed `ring_size: u32`
  parameter from `shekyl-wallet-rpc` transfer API (`types.rs`, `wallet.rs`,
  `ffi.rs`), from the C++ FFI boundary (`wallet2_ffi.h`/`.cpp`), and from the
  C++ wallet RPC `estimate_tx_size_and_weight` command definition. Deleted
  `Decoys` struct, `MAX_RING_SIZE` constant, `DecoyRpc` trait and blanket
  implementation, `OutputInformation` struct, `rpc_point` helper, and
  `test_decoy_rpc` test from `shekyl-oxide`. Removed
  `/get_output_distribution.bin` route from `shekyl-daemon-rpc`.

- **Bulletproof v1 ("Original") deletion.** Deleted the entire `original/`
  module tree and its tests from `shekyl-bulletproofs`. Removed
  `Bulletproof::Original` enum variant, v1 `prove()`/`read()` functions,
  v1 match arms in `verify`/`batch_verify`/`write_core`, and the standalone
  `BulletproofsBatchVerifier` struct. Cleaned up dead `inner_product` and
  `mul_vec` methods that were only used by v1 code.

- **Light wallet support removed.** Deleted all `m_light_wallet` state,
  `set_light_wallet`, `light_wallet_login`, `light_wallet_get_outs`,
  `import_outputs`, `get_unspent_outs`, `submit_raw_tx`, and all
  `if (m_light_wallet)` branches from `wallet2.cpp`/`.h`. Deleted
  `wallet_light_rpc.h` entirely. Removed light wallet API from
  `wallet2_api.h`/`wallet.h`/`wallet.cpp`. Fundamentally incompatible with
  FCMP++ privacy model (sends view keys to remote server).

### 🔄 Changed

- **MLSAG naming debt resolved.** Renamed `get_pre_mlsag_hash` to
  `get_tx_prehash`, `mlsag_prehash`/`mlsag_prepare`/`mlsag_hash`/`mlsag_sign`
  to `tx_prehash`/`tx_prepare`/`tx_hash`/`tx_sign` across the device interface
  hierarchy (`device.hpp`, `device_default.hpp`/`.cpp`, `device_ledger.hpp`/`.cpp`),
  `rctSigs.cpp`/`.h`, and `protocol.cpp`. Renamed Ledger `INS_MLSAG` constant
  to `INS_TX_SIGN`. These functions are live code repurposed for FCMP++
  transaction hashing; the names now reflect their actual role.

- **Base58 encoding removed entirely.** Deleted `src/common/base58.{h,cpp}`,
  `tests/unit_tests/base58.cpp`, `tests/fuzz/base58.cpp`, and all CMake
  references. Removed `CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX`,
  `CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX`, and
  `CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX` constants from all network
  namespaces and `config_t`. No code path accepts or produces Base58 strings.

- **Legacy address structs removed.** `integrated_address`,
  `legacy_account_public_address`, and `legacy_integrated_address` structs
  removed from `cryptonote_basic_impl.cpp`. Subaddress and integrated address
  logic removed from address encoding/decoding chokepoints.

### 🔄 Changed

- **Rust naming convention cleanup.** Fixed phantom FFI function reference in
  `shekyl_pqc_verify` doc comment (referenced non-existent
  `shekyl_pqc_verify_multisig_with_group_id`, now points to
  `shekyl_pqc_multisig_group_id`). Renamed Windows `SystemInfo.dw_page_size`
  to `page_size` (drop Hungarian notation). Renamed `shekyl-wallet-rpc-rs`
  binary to `shekyl-wallet-rpc` (drop `-rs` suffix per Rust API Guidelines).

- **Address encoding migrated to Bech32m.** `get_account_address_as_str()` and
  `get_account_address_from_str()` now call Rust FFI (`shekyl_address_encode`,
  `shekyl_address_decode`) for network-aware Bech32m encoding. The `subaddress`
  parameter is retained for API compatibility but ignored. `address_parse_info`
  fields `is_subaddress` and `has_payment_id` are always false.

- **Wallet proofs use Bech32m blob encoding.** Spend proofs, tx proofs (in/out),
  reserve proofs, message signatures, multisig signatures, and signer keys are
  now encoded with purpose-specific HRPs via `shekyl_encode_blob` /
  `shekyl_decode_blob` FFI. Version headers (`SpendProofV1`, `InProofV2`, etc.)
  removed; the HRP now serves as the type discriminator.

- **`shekyl-crypto-pq` re-exports `shekyl-address`.** The `address` module in
  `shekyl-crypto-pq` is now a re-export of the standalone `shekyl-address` crate.
  The old `shekyl-crypto-pq/src/address.rs` has been deleted.

- **Tx-data prune watermark.** `prune_tx_data` now stores `tx_prune_next_block`
  (exclusive next height) instead of ambiguous `last_pruned_tx_data_height`
  values; legacy keys migrate on read/write. LMDB unit tests live in
  `tests/unit_tests/tx_data_pruning_lmdb.cpp` (minimal block builder only; does
  not link `tests/core_tests/chaingen.cpp` into `unit_tests`, avoiding duplicate
  object code and macOS linker unwind/diagnostic issues in CI).

- **FCMP++ Rust dependency source moved in-repo.** `shekyl-fcmp` now consumes
  vendored `shekyl-oxide` crates via path dependencies under
  `rust/shekyl-oxide/` instead of git dependencies plus local absolute-path
  `[patch]` overrides. This removes host-specific Cargo path failures in CI and
  keeps builds fully repo-local.

- **Upstream sync and portability guardrails.** Added vendored snapshot metadata
  at `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`, a divergence workflow
  (`.github/workflows/shekyl-oxide-divergence.yml`), and build workflow checks
  that fail on absolute local paths in Cargo manifests/config.

### ✨ Added

- **`--prune-blockchain` transaction-data pruning.** LMDB v6 adds `txs_pqc_auths`
  (split from `txs_pruned` at `pqc_auths_offset`), implements `prune_tx_data`
  (batch 256 blocks, output metadata, watermark, TOCTOU height check), default
  depth `CRYPTONOTE_TX_PRUNE_DEPTH` (5000), `pop_block` guard when verification
  data is gone, continuous pruning via `update_blockchain_pruning`, RPC
  `get_transactions.pruned` and `get_info.tx_prune_height`.

- **Staking FFI and config-driven tier parameters.** `shekyl-staking` now
  generates tier lock durations, yield multipliers, and max stake-claim range
  from `config/economics_params.json` at build time (aligned with
  `shekyl-economics`). New FFI: `shekyl_calc_per_block_staker_reward` (128-bit
  division with optional overflow flag), `shekyl_stake_tier_count`,
  `shekyl_stake_tier_name`, `shekyl_stake_max_claim_range`. C++ uses these in
  `blockchain.cpp`, `core_rpc_server.cpp`, and `simplewallet` instead of
  duplicating tier strings or inline `mul128`/`div128_64` reward math.

- **FCMP++ transaction construction helper (`construct_fcmp_tx`).** New chaingen
  helper in `tests/core_tests/chaingen.cpp` that builds fully valid FCMP++
  transactions during core test replay: tree path assembly from the live LMDB
  curve tree, `genRctFcmpPlusPlus` proof generation, KEM decapsulation for
  per-input PQC keypair derivation, and PQC auth signing. This unblocks 30+
  disabled core tests that relied on the old `construct_tx_rct` stub.

- **FCMP++ core test generators (Phase 7).** Five new tests in
  `tests/core_tests/fcmp_tests.cpp`:
  - `gen_fcmp_tx_valid`: end-to-end FCMP++ transaction construction and pool
    acceptance during replay
  - `gen_fcmp_tx_double_spend`: second FCMP++ spend of the same output rejected
  - `gen_fcmp_tx_reference_block_too_old`: stale referenceBlock rejected
  - `gen_fcmp_tx_reference_block_too_recent`: too-recent referenceBlock rejected
  - `gen_fcmp_tx_timestamp_unlock_rejected`: timestamp-based `unlock_time` rejected

- **Verification caching unit tests.** Six new GTest cases in
  `tests/unit_tests/fcmp.cpp` validating `compute_fcmp_verification_hash`
  determinism, sensitivity to proof/referenceBlock/key-image changes, null return
  for non-FCMP++ types, and multi-input handling.

- **Deferred insertion boundary tests.** New `tests/unit_tests/deferred_insertion.cpp`
  with tests for: outputs not drainable before maturity, coinbase maturity window
  (60 blocks), regular tx maturity window (10 blocks), drain journal atomicity
  round-trip, and insertion ordering determinism across two DB instances.

- **Pending tree add/pop stress test.** New `tests/unit_tests/pending_tree_fuzz.cpp`
  with randomized stress test (100 random leaves, multi-height draining),
  add/remove round-trip, drain journal CRUD, and leaf removal correctness.

- **`fuzz_tx_deserialize_fcmp_type7` Rust fuzz target.** New cargo-fuzz target in
  `rust/shekyl-fcmp/fuzz/` that exercises FCMP++ proof verification with
  transaction-structured random inputs: pseudoOuts, proof blobs, PQC hashes,
  corrupted type bytes, empty proofs, and mismatched input counts.

- **Comprehensive staking test suite.** New test coverage across C++ and Rust:
  - `tests/unit_tests/staking.cpp`: 20+ GTest unit tests covering
    `txin_stake_claim` and `txout_to_staked_key` serialization round-trips,
    reward integer math (including `mul128`/`div128_64` vs `double` divergence
    at large values), helper function coverage (`get_inputs_money_amount`,
    `check_inputs_overflow`, `check_inputs_types_supported`,
    `get_output_staking_info`, `set_staked_tx_out`), stake weight/tier FFI
    validation, and variant type handling.
  - `tests/core_tests/staking.cpp` + `staking.h`: 18 chaingen core tests
    covering staking lifecycle (stake output creation), invalid claim
    rejection (inverted range, oversized range, future height, wrong
    watermark, wrong amount, non-staked output, output not in tree), lock
    period enforcement (invalid tier), rollback
    correctness (pool balance, watermark), txpool handling, sorted-input
    enforcement, and multi-tier staking.
  - `rust/shekyl-staking/src/tiers.rs`: 10 edge-case tests including
    exhaustive invalid tier ID rejection, ordering invariants for yield
    multiplier and lock blocks, contiguous ID verification, and positive
    parameter assertions.
  - `rust/shekyl-staking/fuzz/fuzz_targets/fuzz_claim_reward.rs`: cargo-fuzz
    target that generates random accrual records and verifies reward
    computation invariants (no overflow, reward <= pool, weight monotonicity,
    cumulative bounds).

### 🔄 Changed

- **Universal deferred curve-tree insertion (Decision 15).** All outputs
  (coinbase, regular, staked) now enter the `pending_tree_leaves` table at
  creation and drain into the curve tree only after their type-specific
  maturity height (coinbase: +60, regular: +10, staked: max(effective_lock_until, +10)).
  The `pending_staked_*` identifiers were renamed to `pending_tree_*` across
  all database interfaces. The drain journal (`pending_tree_drain`) now stores
  full 136-byte entries (maturity_height + leaf_data) for exact `pop_block`
  reversal instead of just a drain count. `pop_block` restores drained leaves
  to pending and removes the popped block's own pending entries.

- **FCMP_REFERENCE_BLOCK_MIN_AGE reduced to 5 (Decision 14).** With maturity
  enforced by deferred tree insertion, MIN_AGE now serves only as a reorg
  safety margin (5 blocks ≈ 10 minutes). The old static_asserts tying
  MIN_AGE to unlock windows have been removed.

- **Timestamp-based `unlock_time` rejected (Decision 13).** Transactions
  with `unlock_time >= CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL` (500M) are now
  rejected in `check_tx_outputs`. Only height-based lock times are accepted.

- **`prune_tx_data` status clarification.** The output-metadata pruning loop
  in `db_lmdb.cpp` is a plumbing-only stub (`TODO(phase6f)`). The
  `store_output_metadata`, `get_output_metadata`, and `is_output_pruned`
  interfaces are live, but the block-iteration pruning loop does not execute.

### 🗑️ Removed

- **Vestigial hard fork constants.** Removed `HF_VERSION_CLSAG` and
  `HF_VERSION_MIN_V2_COINBASE_TX` from `cryptonote_config.h`. All test
  references replaced with literal `1`.

- **Legacy tests incompatible with FCMP++ consensus.** Disabled 30+ core
  and unit tests that relied on Monero-era transaction construction
  (`RCTTypeBulletproofPlus`, CLSAG ring signatures, v1/v2 transactions):
  - `tests/core_tests/chaingen_main.cpp`: Disabled `gen_simple_chain_001`,
    `gen_simple_chain_split_1`, `gen_chain_switch_1`, `gen_ring_signature_1`,
    `gen_ring_signature_2`, all `txpool_*` tests, all `gen_double_spend_*`
    tests, `gen_block_reward`, all `gen_bpp_*` Bulletproofs+ tests, and
    several `gen_tx_*` tests whose setup required valid user transactions.
    These tests construct transactions via `MAKE_TX`/`construct_tx_rct`
    which produce `RCTTypeFcmpPlusPlusPqc` stubs with empty `pqc_auths`,
    rejected by `check_tx_inputs` even in FAKECHAIN mode.
  - `tests/unit_tests/bulletproofs.cpp`: All three weight tests
    (`weight_equal`, `weight_more`, `weight_pruned`) prefixed with
    `DISABLED_` and hex blobs removed. Shekyl's `rctSigBase` serialization
    rejects any type other than `RCTTypeFcmpPlusPlusPqc` (type 7), so old
    `RCTTypeBulletproofPlus` (type 6) blobs fail to deserialize.
  - Re-enabling requires a chaingen FCMP++ transaction generator that
    produces valid PQC auth signatures and curve-tree membership proofs.

### 🔄 Changed

- **Upstream monero-oxide dependencies renamed to shekyl-oxide.** Updated
  `shekyl-fcmp/Cargo.toml` and all Rust source files to use the renamed
  packages from the monero-oxide fork (`monero-fcmp-plus-plus` →
  `shekyl-fcmp-plus-plus`, `monero-generators` → `shekyl-generators`).
  `Cargo.lock` advanced from pin `92af05e` to `416d8d1` which includes the
  complete `monero-oxide/` → `shekyl-oxide/` directory and package rename.

- **`shekyl-fcmp` crate cleanup.** Removed unused `sha2` and `shekyl-crypto-pq`
  dependencies from `rust/shekyl-fcmp/Cargo.toml`. Renamed the misleading
  `ProveError::InputCountMismatch` variant to `ProveError::PqcHashMismatch`
  with a clear `input_index` field indicating which input has a mismatched
  leaf `h_pqc` vs `pqc_auth` commitment.

### 🐛 Fixed

- **Private member access in pending tree unit tests.** Fixed 18 compile
  errors in `pending_tree_fuzz.cpp` and 4 in `deferred_insertion.cpp` on
  macOS CI where calls to `add_pending_tree_leaf`, `drain_pending_tree_leaves`,
  `add_pending_tree_drain_entry`, `get_pending_tree_drain_entries`,
  `remove_pending_tree_drain_entries`, and `remove_pending_tree_leaf` were
  calling private overrides on `BlockchainLMDB`. Changed all test methods
  to use `BlockchainDB&` references, accessing the public base class interface.

- **CI compile errors across all platforms.** Fixed compilation failures in
  the new staking and FCMP++ test suites:
  - `tests/core_tests/staking.cpp`: Added missing `fill_tx_sources`
    declaration to `chaingen.h` and moved `Blockchain::check_stake_claim_input`
    from the private section to the public API so core tests can call it
    without `IN_UNIT_TESTS`.
  - `tests/unit_tests/fcmp.cpp`: Fixed serialization calls to use
    `do_serialize(ar, v)` instead of non-existent `v.serialize(ar)` member;
    replaced `binary_archive<false>(istringstream&)` with the correct
    `binary_archive<false>(span<const uint8_t>)` constructor; fixed
    `shekyl_pqc_verify` call to include the required `scheme_id` first
    argument and corrected parameter order.
  - `tests/unit_tests/staking.cpp`: Same `binary_archive<false>` constructor
    fix — replaced `istringstream` with `epee::span<const uint8_t>` in all
    four serialization round-trip tests.
  - macOS CI: Added `zstd` to Homebrew dependencies and fixed CMake to use
    `PkgConfig::ZSTD` imported target instead of bare library name, resolving
    `ld: library 'zstd' not found` on macOS Homebrew where the library lives
    in a non-standard path (`/opt/homebrew/lib`).

- **RPC estimate_claim_reward floating-point precision bug.** The
  `on_estimate_claim_reward` RPC handler used `double`-precision arithmetic
  for reward estimation, which diverges from the consensus `mul128`/`div128_64`
  path when `total_weighted_stake > 2^53`. Fixed to use identical 128-bit
  integer math, ensuring wallet reward estimates always match consensus.

### 🐛 Fixed

- **FCMP++ wallet precompute metadata and input consistency checks.**
  `transfer_selected_rct` and multisig proof prep now read tree depth from
  RPC metadata (`tree_depth`) instead of `path_blob[0]`, enforce that all
  selected inputs share the same reference block/depth snapshot, and reject
  empty precomputed paths. This fixes silent spend-construction failures.

- **Stake-claim input routing in consensus verification.**
  `Blockchain::check_tx_inputs` now routes pure `txin_stake_claim`
  transactions through the claim-specific input checks before generic FCMP++
  `txin_to_key` validation, preventing incorrect rejection of valid
  stake-claim transactions that use `RCTTypeFcmpPlusPlusPqc`.

- **Stake-claim reward math overflow defense.** Added a defensive `q_hi != 0`
  check after `div128_64` in claim reward computation, rejecting impossible
  overflow states instead of silently truncating.

- **Claim transaction PQC signing correctness/performance.** Removed wallet
  master-key fallback for claim input signing and now require per-output
  shared-secret rederivation for all claim inputs. Claim signing keypairs are
  derived once per input and reused for both `pqc_auths` public key and
  signature generation.

- **Curve-tree path RPC returns spendable reference block.**
  `get_curve_tree_path` now returns a `reference_block` at least
  `FCMP_REFERENCE_BLOCK_MIN_AGE + 1` behind tip, avoiding immediate mempool
  rejection of freshly built transactions that used a too-recent tip anchor.

- **PQC derivation index correctness and duplicate derivation overhead.**
  Spend-path and multisig PQC key derivation now use
  `m_internal_output_index` (matching KEM encapsulation/decapsulation) and
  derive each per-input keypair once per transaction, reusing it for both
  `H(pqc_pk)` and signing.

- **Staked-output FCMP++ path precompute filtering.**
  Wallet precompute/incremental updates now skip still-locked staked outputs
  (`m_stake_lock_until > current_height`) to avoid daemon path lookup errors.

- **Stake-claim rollback completeness.** `BlockchainDB::remove_transaction`
  now fully reverses `txin_stake_claim` state on reorg: watermark is restored
  to its pre-claim value (or removed for first-time claims) and the claimed
  amount is credited back into the staker reward pool. Previously only the
  spent key was removed, leaving claim-progress accounting permanently
  advanced after a reorg.

- **Txpool key-image handling for stake claims.** All six txpool functions
  that walk transaction inputs (`insert_key_images`,
  `remove_transaction_keyimages`, `have_tx_keyimges_as_spent`,
  `have_key_images`, `append_key_images`, `mark_double_spend`) now handle
  `txin_stake_claim` inputs alongside `txin_to_key`. Previously they used
  `CHECKED_GET_SPECIFIC_VARIANT(..., txin_to_key, ...)` which caused
  immediate false-return on any stake-claim input, breaking mempool
  bookkeeping for claim transactions.

- **`remove_transaction_keyimages` no longer returns early on error.**
  The function now continues removing remaining key images instead of
  aborting at the first mismatch, eliminating the partial-cleanup semantics
  noted by the long-standing FIXME.

- **Core helper support for `txin_stake_claim`.** `get_inputs_money_amount`
  and `check_inputs_overflow` now handle both `txin_to_key` and
  `txin_stake_claim` input variants instead of failing on the latter. These
  are called unconditionally for all transactions (via `check_money_overflow`),
  so the old hard-cast to `txin_to_key` would reject any transaction
  containing a stake claim.

### 🔒 Security

- **FFI buffer zeroization before free.** `shekyl_buffer_free` now wipes
  buffer contents prior to deallocation, reducing secret-key residue risk in
  allocator-managed memory.

- **Wallet KEM key management fix.** `generate_pqc_key_material()` now
  generates `HybridX25519MlKem` KEM keypairs via `shekyl_kem_keypair_generate()`
  instead of `HybridEd25519MlDsa` signing keypairs. The wallet-level PQC
  keys (`m_pqc_public_key` / `m_pqc_secret_key`) are encapsulation/decapsulation
  keys; per-output ML-DSA-65 signing keys are always derived from the KEM
  shared secret at spend time.

- **Full hybrid ciphertext storage in tx_extra tag 0x06.** All KEM
  encapsulation sites (coinbase, claim, regular transfers) now store the
  complete 1120-byte hybrid ciphertext (`x25519_ephemeral_pk[32] || ml_kem_ct[1088]`)
  instead of only the ML-KEM portion. This enables correct hybrid
  decapsulation during wallet scanning and seed restore.

### ✨ Added

- **FCMP++ wallet transaction construction (Phase 5).** `transfer_selected_rct`
  now builds transactions using full-chain membership proofs instead of ring
  signatures:
  - Inputs contain only the real output (no decoy selection).
  - `genRctFcmpPlusPlus` generates the combined Bulletproofs+ and FCMP++
    membership proof.
  - Per-input PQC auth signatures use ML-DSA-65 keypairs derived from the
    KEM shared secret and output index.
  - `construct_tx_with_tx_key` adds KEM encapsulation (tag 0x06) and
    `H(pqc_pk)` leaf hashes (tag 0x07) for each output, and skips
    wallet-level PQC signing.

- **KEM decapsulation during wallet scanning.** `process_new_transaction`
  now extracts hybrid KEM ciphertexts from `tx_extra` tag 0x06, calls
  `shekyl_kem_decapsulate` with the wallet's KEM secret keys, and stores
  the resulting 64-byte combined shared secret in `transfer_details::m_combined_shared_secret`.
  This enables per-output PQC key derivation at spend time.

- **FCMP++ fee estimation.** `estimate_rct_tx_size` now accounts for the
  FCMP++ membership proof size (`shekyl_fcmp_proof_len`), per-input PQC
  auth envelopes (~5400 bytes each), and per-output KEM ciphertexts and
  leaf hashes.

- **GUI wallet QR code.** Receive page now renders a real QR code encoding
  the full FCMP++ Bech32m address via `qrcode.react`.

- **GUI wallet fee preview.** Send page shows an estimated transaction fee
  before submission, debounced as the user types.

### 🗑️ Removed

- **CLSAG device interface methods.** Removed `clsag_prepare`, `clsag_hash`,
  and `clsag_sign` virtual methods from `device.hpp` and all implementations
  (`device_default.cpp`, `device_ledger.cpp`). Shekyl never supported CLSAG;
  the device interface now only exposes FCMP++ methods.

- **`get_outs` / `get_outs.bin` RPC endpoints.** Removed the ring member
  fetching endpoints from the C++ daemon (`core_rpc_server`), the FFI dispatch
  tables (`core_rpc_ffi.cpp`), and the Rust daemon RPC (`shekyl-daemon-rpc`).
  FCMP++ uses full-chain membership proofs; there is no decoy selection.

- **Dead hard fork constants.** Removed `HF_VERSION_MIN_MIXIN_4/6/10/15`,
  `HF_VERSION_SAME_MIXIN`, `HF_VERSION_ENFORCE_MIN_AGE`,
  `HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY`,
  `HF_VERSION_REJECT_SIGS_IN_COINBASE`, `HF_VERSION_ENFORCE_RCT`,
  `HF_VERSION_DETERMINISTIC_UNLOCK_TIME` from `cryptonote_config.h`. These
  were defined but never referenced in production code. `HF_VERSION_CLSAG`
  and `HF_VERSION_MIN_V2_COINBASE_TX` are retained for test compilation
  until Phase 7 rewrites the legacy tests.

### ✨ Added

- **Zstd compression for Levin P2P relay (Phase 6e).** P2P payloads above
  256 bytes are transparently compressed with zstd (level 1) before relay.
  A new `LEVIN_PACKET_COMPRESSED` flag (0x10) in the Levin header marks
  compressed frames. Peers negotiate compression via
  `P2P_SUPPORT_FLAG_ZSTD_COMPRESSION` (0x02) in the handshake support flags.
  Reduces relay bandwidth by ~10-20% for FCMP++ transactions, especially
  important for Tor/I2P connections. Compression is optional at compile time
  (requires libzstd); decompression always succeeds if the flag is set.

### 📚 Documentation

- **Updated `DAEMON_RPC_RUST.md`.** Fixed stale references to `get_outs.bin`
  and `get_curve_tree_root`; corrected endpoint counts and cutover test steps.

### 🐛 Fixed

- **`rct::key` missing `operator!=`.** Added `operator!=` to the `key`
  struct in `rctTypes.h`. The operator was present for cross-type
  comparisons (`rct::key` vs `crypto::public_key`) but not for
  `rct::key` vs `rct::key`, causing compilation failures on all
  platforms when comparing pseudo-outs to expected zero-commitments in
  the stake claim verification path.

- **MSVC `binary_archive` constructor mismatch.** Fixed `wallet2.cpp`
  to use `epee::strspan<std::uint8_t>` instead of `std::istringstream`
  for constructing `binary_archive<false>`, which MSVC could not resolve.

- **Memory leak on exception in PQC auth signing.** Added RAII scope
  guard for `ShekylPqcKeypair` buffers in `transfer_selected_rct`
  Phase C, ensuring Rust-allocated key material is freed even if
  `THROW_WALLET_EXCEPTION_IF` throws mid-loop.

- **Secret key material not wiped on KEM decapsulation failure.** The
  stack buffer in `process_new_transaction` KEM decapsulation is now
  wiped unconditionally (success or failure), preventing partial key
  material from lingering on the stack.

- **Shadowed `tx_extra_fields` variable in KEM decapsulation.** Removed
  redundant inner `tx_extra_fields` reference that shadowed the outer
  one in `process_new_transaction`, using the already-resolved outer
  reference instead.

### 🔄 Changed

- **Decoy selection functions are dead code.** `get_outs`,
  `tx_add_fake_output`, and `light_wallet_get_outs` in `wallet2.cpp` are
  no longer called from the active transfer path. They remain in the
  codebase for reference and will be removed in a follow-up cleanup.

- **Claim transaction indistinguishability (Phase 4 — CRITICAL).** Rewrote
  `wallet2::create_claim_transaction()` to produce privacy-preserving claim
  transactions that blend into the anonymity set:
  - Uses `RCTTypeFcmpPlusPlusPqc` with Bulletproofs+ range proofs instead
    of `RCTTypeNull` with plaintext amounts.
  - Adds a dummy change output (amount = 0) to match the standard 2-output
    transaction structure, preventing structural fingerprinting.
  - Performs hybrid KEM derivation (X25519 + ML-KEM-768) via
    `shekyl_fcmp_derive_pqc_keypair()` for per-output PQC keys instead of
    reusing the wallet master PQC key.
  - Embeds ML-KEM ciphertexts in `tx_extra` under tag `0x06` and
    `H(pqc_pk)` leaf hashes under new tag `0x07`.
  - Signs with per-output KEM-derived PQC keys, not the wallet-level key.
  - Sets deterministic pseudo-outs (`zeroCommit(claim_amount)`) for each
    stake claim input to satisfy the Bulletproofs+ balance check.

- **Consensus rejects `RCTTypeNull` for non-coinbase v3 transactions.**
  `check_tx_inputs` now enforces that only coinbase (`txin_gen`) may use
  `RCTTypeNull`. All other v3 transactions (including stake claims) must
  use `RCTTypeFcmpPlusPlusPqc` with confidential amounts. Claim
  transactions are validated within the FCMP++ handler with their own
  sub-path that verifies pseudo-out determinism, PQC ownership, and pool
  balance while skipping the membership proof (which is not applicable to
  `txin_stake_claim` inputs).

### ✨ Added

- **`TX_EXTRA_TAG_PQC_LEAF_HASHES` (`0x07`).** New `tx_extra` field
  (`tx_extra_pqc_leaf_hashes`) stores per-output `H(pqc_pk)` values —
  the 32-byte Blake2b-512 hashes of each output's derived ML-DSA-65
  public key. Used by curve tree insertion to commit the correct PQC
  ownership hash to each leaf instead of a zero placeholder.

- **Curve tree leaves use actual `H(pqc_pk)` from `tx_extra`.** The
  `collect_outputs` / `make_leaf` path in `blockchain_db.cpp` now extracts
  `H(pqc_pk)` values from the `0x07` tag, replacing the zero placeholder
  that was previously committed to the 4th leaf scalar. This enables the
  PQC ownership cross-check for stake claim verification.

- **Coinbase transactions emit `H(pqc_pk)` leaf hashes.** `construct_miner_tx`
  now derives per-output PQC keypairs via KEM shared secrets and includes
  their `H(pqc_pk)` values in the `0x07` `tx_extra` field alongside the
  existing KEM ciphertexts in `0x06`.

### 🔒 Security

- **Integer-only stake reward computation.** Replaced floating-point
  arithmetic (`(double)total_reward * weight / total_weighted_stake`) with
  128-bit integer math (`mul128`/`div128_64`) in `check_stake_claim_input`
  to eliminate rounding errors that could cause determinism mismatches
  across platforms.

- **Batch pool balance validation for stake claims.** Moved the staker
  pool balance check from per-claim (`check_stake_claim_input`) to a
  batch check in `check_tx_inputs` that sums all claim amounts first.
  Prevents multiple claims in the same block from independently passing
  the balance check and overdrawing the pool.

- **PQC ownership cross-check on stake claims.** Each `txin_stake_claim`
  now verifies that the `H(pqc_pk)` stored in the curve tree leaf (bytes
  96–128) matches `shekyl_fcmp_pqc_leaf_hash(pqc_auths[i].hybrid_public_key)`,
  preventing reward claims for outputs the claimer does not own the PQC
  key for.

### 🐛 Fixed

- **Stake claim key image cleanup on reorg.** `remove_transaction` in
  `blockchain_db.cpp` now handles `txin_stake_claim` key images in
  addition to `txin_to_key`, preventing stale key images from persisting
  after block pops.

### 🔄 Changed

- **Sorted input enforcement extended to stake claims.** The
  sorted-inputs check in `check_tx_inputs` now covers both `txin_to_key`
  and `txin_stake_claim` key images, ensuring consistent ordering rules
  across all input types.

- **Third-party headers treated as SYSTEM includes.** `external/`, `external/rapidjson`,
  `external/easylogging++`, and `external/supercop` are now `-isystem` in CMake,
  suppressing `-Wsuggest-override` and other warnings from third-party code while
  keeping strict warnings for first-party code.

### 🗑️ Removed

- **Dead `check_ring_signature` function.** Removed unused ring signature
  verification from `blockchain.cpp` and its declaration from
  `blockchain.h`. Shekyl uses FCMP++ from genesis; ring signatures are
  never validated.

- **Dead `expand_transaction_2` function.** Removed the no-op transaction
  expansion function from `blockchain.cpp` and its declaration from
  `blockchain.h`. FCMP++ does not use mixRing expansion.

- **Dropped `serde_json` dev-dependency from `shekyl-fcmp`.** Replaced the JSON
  round-trip test with a byte-level serialization check, reducing the dev-dep
  surface.

### 📚 Documentation

- Synced `docs/FCMP_PLUS_PLUS.md` curve-tree text with consensus: outputs are
  indexed at creation; maturity is enforced via `referenceBlock` and other
  rules, not by delaying leaf insertion.
- Clarified `docs/POST_QUANTUM_CRYPTOGRAPHY.md` to use `pqc_auths` (per-input)
  terminology consistently.
- Documented mempool FCMP verification-cache id: `compute_fcmp_verification_hash`
  binds proof + `referenceBlock` + key images (comment in `blockchain.cpp`).
- Noted the monero-oxide commit pin in `rust/shekyl-fcmp/Cargo.toml` comments
  (lockfile remains authoritative).
- Updated `docs/STAKER_REWARD_DISBURSEMENT.md` with integer arithmetic, batch
  pool check, PQC cross-check, and sorted input consensus rules.

### ✨ Added

- **Block-inclusion FCMP++ cache fast path.** When a transaction was previously
  verified in the mempool and arrives in a block, `check_tx_inputs` skips the
  expensive `shekyl_fcmp_verify` FFI call (~35ms/input) while still running all
  structural checks (referenceBlock, depth, key images, PQC auth).

- **`construct_leaf` now accepts PQC key hash parameter.** The Rust FFI
  function `shekyl_construct_curve_tree_leaf` takes a 4th `h_pqc_ptr` argument
  (32 bytes) to set the 4th leaf scalar.  Callers pass zero bytes until
  per-output PQC commitments are wired in Phase 3.

- **Deferred staked leaf insertion infrastructure.**
  Added `pending_staked_leaves` (LMDB DUPSORT/DUPFIXED table keyed by
  `lock_until_height` with 128-byte leaf values) and `pending_staked_drain`
  (block_height → drain count) tables to the blockchain database layer.
  Five new methods on `BlockchainDB`: `add_pending_staked_leaf`,
  `drain_pending_staked_leaves`, `set_pending_staked_drain_count`,
  `get_pending_staked_drain_count`, and `remove_pending_staked_drain_count`.
  This enables staked outputs whose `effective_lock_until > block_height` to be parked
  in a pending table and batch-inserted into the curve tree when they mature.

- **Comprehensive FCMP++ test suite and fuzz targets (Phase 7).**
  Added 6 `cargo-fuzz` targets across `rust/shekyl-fcmp/fuzz/` (proof
  deserialization, curve tree leaf hashing, block header tree root mismatch)
  and `rust/shekyl-crypto-pq/fuzz/` (Bech32m address decoding, KEM
  decapsulation with corrupted ciphertexts). Extended Rust unit tests in
  `proof.rs`, `tree.rs`, `leaf.rs`, `kem.rs`, `address.rs`, and
  `derivation.rs` covering prove/verify round-trips, hash grow/trim inverse
  properties, boundary values, and cross-crate consistency. Extended C++ unit
  tests in `tests/unit_tests/fcmp.cpp` with RCTTypeFcmpPlusPlusPqc
  serialization round-trip, key image y-normalization, referenceBlock
  staleness constants, and empty proof rejection. Added PQC rederivation
  criterion benchmark (`rust/shekyl-crypto-pq/benches/pqc_rederivation.rs`)
  targeting < 100ms per output for the full ML-KEM-768 decapsulation +
  HKDF-SHA-512 + ML-DSA-65 keygen pipeline.

- **Stressnet tooling for FCMP++ pre-audit gate (Phase 7.7).**
  Added `tests/stressnet/` with configuration, load generator, and monitoring
  scripts for a 4-week sustained-load testnet. The stressnet exercises curve
  tree growth, verification caching, wallet restore correctness, pruned vs.
  full node storage, staking lifecycle, and block validation latency under
  near-block-weight-limit load. Includes `config.yaml` with load profiles,
  `load_generator.py` for synthetic transaction submission, and `monitor.py`
  for real-time metric collection, consensus checking, and daily report
  generation.

- **Security audit scope document (Phase 9).**
  Added `docs/AUDIT_SCOPE.md` defining the scope for a third-party security
  review of the 4-scalar leaf circuit modification. Covers soundness,
  zero-knowledge, and completeness verification for the `H(pqc_pk)` extension,
  Shekyl fork modifications to monero-fcmp-plus-plus, PQC commitment binding,
  and the FFI verification boundary. Includes materials list, auditor guidance
  questions, success criteria, and timeline.

- **Mainnet gate: stressnet and audit prerequisites in release checklist.**
  Updated `docs/RELEASE_CHECKLIST.md` with "Stressnet stable for 4 consecutive
  weeks" and "4-scalar leaf circuit audit completed" as hard prerequisites
  for mainnet launch.

### 🔄 Changed

- **Renamed `src/ringct/` to `src/fcmp/` for naming consistency.**
  Shekyl does not use ring signatures; the directory now reflects the actual
  FCMP++ confidential transaction system.  CMake targets renamed from
  `ringct`/`ringct_basic` to `fcmp`/`fcmp_basic`.  All `#include "ringct/..."`
  paths updated across 44 source and test files.  Log categories, user-facing
  strings ("RingCT" → "FCMP"), JSON keys, and documentation updated.
  The `rct::` namespace is preserved for now as a separate future rename.

- **Unified coinbase transaction version to v3.**
  `construct_miner_tx` and `build_genesis_coinbase_from_destinations` now emit
  `tx.version = 3`, matching regular FCMP++ transactions.  All `miner_tx &&
  tx.version == 2` checks have been widened to `>= 2` across `blockchain_db`,
  `blockchain`, `wallet2`, and test infrastructure.  The `pqc_auths`
  serialization gate (`!txin_gen`) already excluded coinbase, so v3 coinbase
  serializes identically to v2 minus the version byte.

### 🐛 Fixed

- **Fixed wallet API compilation errors after ring-signature removal.**
  `wallet/api/wallet.cpp` still referenced the undefined `fake_outs_count`
  variable and called `estimate_fee` with the old 12-argument signature.
  Replaced `fake_outs_count` with `0` (FCMP++ has no decoys) and updated
  `estimateTransactionFee` to use the simplified 8-argument `estimate_fee`
  signature with hardcoded `use_per_byte_fee=true`, `use_rct=true`,
  `use_view_tags=true`.

- **Fixed CI build failure from removed legacy RCT types in test files.**
  Stripped all references to removed `rct::Bulletproof`, `rct::RCTConfig`,
  `rct::RangeProofType`, `rct::RCTTypeBulletproofPlus`, `rct::clsag`,
  `rct::proveRctCLSAGSimple`/`verRctCLSAGSimple`, and `rct::genRctSimple`
  from: `chaingen.h`/`.cpp`, `bulletproof_plus.cpp`/`.h`, `chain_switch_1.cpp`,
  `wallet_tools.h`/`.cpp`, `bulletproofs.cpp` (unit), `ringct.cpp` (unit),
  `serialization.cpp` (unit), `ver_rct_non_semantics_simple_cached.cpp`,
  `json_serialization.cpp`, `fuzz/bulletproof.cpp`, and all performance test
  headers.  Removed legacy-only test cases; updated shared test helpers to drop
  `RangeProofType`/`bp_version` parameters.

### 🗑️ Removed

- **Dead verification cache code (`verRctNonSemanticsSimple`, `ver_rct_non_semantics_simple_cached`).**
  Removed the stub `verRctNonSemanticsSimple` from `rctSigs.cpp/.h` (returned `true`
  unconditionally), the `ver_rct_non_semantics_simple_cached` wrapper and its
  `ver_rct_non_sem` helper from `tx_verification_utils.cpp/.h`, the unused
  `rct_ver_cache_t` type alias and `m_rct_ver_cache` member from `Blockchain`,
  and the dead `RCT_CACHE_TYPE` constant from `check_tx_inputs`.  Real FCMP++
  verification lives in `check_tx_inputs` (blockchain.cpp) and the mempool
  uses `compute_fcmp_verification_hash` for caching.

### 🔒 Security

- **CRITICAL: PQC signed payload now binds to prunable FCMP++ data (Phase 4c).**
  `get_transaction_signed_payload` now includes `H(serialize(RctSigPrunable))`
  in the signed payload, binding PQC signatures to the FCMP++ proof, pseudoOuts,
  curve_trees_tree_depth, and Bulletproofs+.  Without this, an attacker could
  substitute different prunable data without invalidating PQC signatures,
  breaking the dual-layer security model.

- **CRITICAL: Wired stake claim validation in `check_tx_inputs` (Phase 4e audit fix).**
  The non-FAKECHAIN gate in `check_tx_inputs` rejected all `RCTTypeNull`
  transactions, which includes pure stake-claim txs.  The gate now allows
  `RCTTypeNull` transactions through when all inputs are `txin_stake_claim`.
  Additionally, the `RCTTypeNull` switch case now calls `check_stake_claim_input`
  for each claim input and checks key image double-spend — previously it
  `break`ed without any validation.

- **HIGH: Bound all inputs' H(pqc_pk) hashes into PQC signed payload.**
  `get_transaction_signed_payload` now appends `H(pqc_pk_0) || ... || H(pqc_pk_{N-1})`
  after the per-input header blob, preventing key-substitution attacks where an
  attacker replaces one input's PQC key without invalidating other signatures.

- **MEDIUM: Stake claim curve tree leaf verification (Phase 4e).**
  `check_stake_claim_input` now verifies the staked output's leaf is present
  in the curve tree by checking `staked_output_index < get_curve_tree_leaf_count()`
  and reading the leaf with `get_curve_tree_leaf()`.  Previously, only the
  lock period check was performed, which didn't guarantee the leaf had been
  inserted into the tree.

- **MEDIUM: PQC `auth_version` and `flags` consensus enforcement.**
  `verify_transaction_pqc_auth` now rejects `auth_version != 1` and
  `flags != 0`, enforcing spec steps 6a/6c. Previously these fields were
  serialized and signed over but never validated.

- **LOW: Single-signer `hybrid_public_key` size enforcement.**
  `verify_transaction_pqc_auth` now verifies single-signer key blobs are
  exactly `HYBRID_SINGLE_KEY_LEN` (1996 bytes). Previously only multisig
  keys had size bounds checks; single-signer keys relied solely on the FFI
  call to reject malformed keys.

- **LOW: Added deserialization size bounds for `pqc_authentication` blobs.**
  `hybrid_public_key` and `hybrid_signature` vectors are now rejected during
  deserialization if they exceed `PQC_MAX_PUBLIC_KEY_BLOB` or
  `PQC_MAX_SIGNATURE_BLOB`, preventing memory-exhaustion attacks via
  oversized PQC fields.

### 🐛 Fixed

- **HIGH: Fixed `pop_block()` off-by-one for staked-output curve tree removal.**
  The height used for staked-output eligibility checking was captured *after*
  `remove_block()`, using the post-pop height instead of the removed block's
  height.  This caused a mismatch with `add_block()`'s logic: outputs added at
  the exact lock boundary were inserted during add but not removed during pop,
  leaving orphaned leaves in the curve tree.

- **HIGH: Fixed `pseudoOuts` serialization mismatch in generic `rctSigBase`.**
  The generic `BEGIN_SERIALIZE_OBJECT()` path in `rctSigBase` unconditionally
  included `pseudoOuts`, even for `RCTTypeFcmpPlusPlusPqc` where pseudo-outs
  live in the prunable section.  Now gated with
  `if (type != RCTTypeFcmpPlusPlusPqc)` to match the custom serializer.

- **MEDIUM: `get_curve_tree_path` RPC now fails on missing layer hashes.**
  Previously, a failed `get_curve_tree_layer_hash()` silently inserted zeros
  into the proof path, potentially generating invalid proofs from inconsistent
  DB state.  Now returns `CORE_RPC_ERROR_CODE_INTERNAL_ERROR`.



- **CRITICAL: Fixed incorrect existing_child in internal layer hash propagation**
  (`grow_curve_tree`).  When updating an existing child chunk's hash, the
  parent's Pedersen commitment was computed with `existing_child = 0` instead of
  the previous cycle-scalar.  This produced wrong chunk hashes for any block
  that updated (rather than created) a child chunk.  The fix tracks both old and
  new hashes through `updated_chunk_t` and passes the previous cycle-scalar to
  `hash_grow`.

- **CRITICAL: Replaced O(N) `trim_curve_tree` with incremental `hash_trim`.**
  Reorgs previously read all remaining leaves, cleared the tree, and rebuilt
  from scratch — a liveness risk at scale.  The new implementation uses
  `hash_trim_selene`/`hash_trim_helios` FFI to surgically update only the
  affected chunks, then propagates the old→new deltas up through internal layers.
  Complexity is now O(removed × log N).

- **CRITICAL: Enforced output maturity via `FCMP_REFERENCE_BLOCK_MIN_AGE`.**
  Outputs enter the curve tree at creation time (maximising the anonymity set).
  Maturity is enforced at spending time by requiring the reference block to be
  at least `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (60) blocks behind the tip.
  Added `static_assert`s in `cryptonote_config.h` to prevent regression.

- **HIGH: Validated meta reads in `save_curve_tree_checkpoint`.**  The function
  now checks that root, depth, and leaf_count were all successfully read from
  meta before storing a checkpoint.  If any value is missing or leaf_count is 0,
  the checkpoint is skipped with a log warning instead of storing a corrupt
  zero-valued checkpoint.

### 🔄 Changed

- **Consensus: `curve_trees_tree_depth` validation now accepts `<= current`.**
  The referenceBlock's tree may have fewer layers than the current tip (depth
  is monotonically non-decreasing).  The strict `!=` check was replaced with a
  range check `(0, current_depth]`, and the FCMP++ proof verifier provides the
  authoritative depth validation.

- **Consensus: Removed ring-based validation path from `check_tx_inputs`.**
  Shekyl starts at genesis with FCMP++; the legacy ring-signature per-input
  validation is unreachable dead code.  The `else` branch now immediately
  rejects non-FCMP++ transactions with a clear error message.

- **Coinbase KEM: Added warning when miner address lacks PQC public key.**
  If a miner's address has no PQC key at the FCMP++ hard fork, a warning is
  logged noting that the output will have `H(pqc_pk) = 0` in the curve tree —
  a distinguishable pattern.

- **RPC: Replaced hardcoded chunk widths with FFI calls.**
  `get_curve_tree_path` now calls `shekyl_curve_tree_selene_chunk_width()` and
  `shekyl_curve_tree_helios_chunk_width()` instead of using static constants.

- **RPC: Added `reference_height` and `leaf_count` to `get_curve_tree_path`
  response.**  Wallets can now verify response freshness and detect stale paths
  without parsing the reference block hash.

- **RPC: Added `MAX_OUTPUTS_PER_RPC_REQUEST` (64) rate limit** to
  `get_curve_tree_path` to prevent abuse from unbounded requests.

### ✨ Added

- **RPC: `get_curve_tree_info` endpoint** returns root hash, depth, leaf count,
  and chain height for the current curve tree state.

- **RPC: `get_curve_tree_checkpoint` endpoint** retrieves a stored checkpoint
  (root, depth, leaf_count) at a given block height, needed for fast-sync.

### 📚 Documentation

- Documented `verRctNonSemanticsSimple` stub status: the FCMP++ membership
  proof is verified in the main consensus path (`check_tx_inputs`), not in the
  verification-caching path.  Added TODO for Phase 5 unification.
- ~~Documented coinbase `tx.version = 2` rationale~~ — superseded: coinbase
  is now version 3, unified with regular transactions.
- Documented LMDB post-delete cursor contract (`MDB_GET_CURRENT` after
  `mdb_cursor_del` returns the next item) in pruning and GC loops.
- Added `ct_layer_chunk_key` bit-layout comment explaining the 8-bit layer /
  56-bit chunk index encoding for LMDB integer keys.
- Documented `construct_leaf` zero 4th scalar (H(pqc_pk)) and the tree rebuild
  requirement when PQC per-output keys are activated.
- Documented depth tracking semantics (root layer index, not layer count) and
  root detection invariant in `grow_curve_tree`.
- Added TODO for async/batched checkpoint+pruning in `add_block`.
- Documented `get_curve_tree_root` empty-tree return semantics (returns
  `hash_init`, callers should check `leaf_count`).

### 🗑️ Removed

- **Legacy RCT and mixin references stripped from wallet layer.** Completed
  the wallet-side refactor removing all references to legacy ring sizes,
  `adjust_mixin`, `default_mixin`, `m_default_mixin`, `RCTConfig`, and
  mixin-count parameters:
  - `wallet2.h`: Removed `estimate_fee` mixin/bulletproof/clsag params,
    `adjust_mixin()`, `default_mixin()` getter/setter, `m_default_mixin`
    member, `rct_config` from `pending_tx` and `transfer_selected_rct`.
  - `wallet2.cpp`: Removed mixin from `estimate_rct_tx_size`,
    `estimate_tx_size`, `estimate_tx_weight`, `estimate_fee` signatures
    and all call sites. Removed `adjust_mixin()` definition, JSON
    serialization of `default_mixin`, constructor initialization. Removed
    `const bool clsag/bulletproof/bulletproof_plus = true` patterns.
  - `wallet_errors.h`: Removed `mixin_count` field from
    `not_enough_outs_to_mix` error struct.
  - `wallet2_ffi.cpp`: Replaced `adjust_mixin` calls with constant `0`.
  - `wallet_rpc_server.cpp`: Replaced `adjust_mixin` calls with constant `0`.
  - `wallet2_api.h`, `wallet.h`, `wallet.cpp`: Removed `mixin_count`
    parameter from `createTransaction` and `createTransactionMultDest`.
  - `unsigned_transaction.cpp`: Simplified `mixin()` and `minMixinCount()`
    to always return 0 (FCMP++ has no explicit mixin).
  - `simplewallet.cpp`: Removed ring-size parsing, `adjust_mixin` calls,
    and `default_mixin` display. All fake_outs_count set to 0.
- **Legacy RCT references stripped from all src/ files.** Removed all
  remaining references to CLSAG, legacy RCT types, `RCTConfig`, `mixRing`,
  and `low_mixin` from device drivers, Trezor protocol, RPC handlers,
  blockchain verification, transaction utilities, wallet, and serialization:
  - `device_ledger.cpp`: Removed `INS_CLSAG` define, legacy type branches
    in `mlsag_prehash`, replaced `clsag_prepare`/`clsag_hash`/`clsag_sign`
    with FCMP++ TODO stubs.
  - `protocol.cpp`/`protocol.hpp` (Trezor): Removed `rct::Bulletproof`
    variant, `is_simple()`/`is_req_bulletproof()`/`is_bulletproof()`/
    `is_clsag()` helpers, `mixRing` resize, CLSAG deserialization in
    `step_final_ack`. Added `is_fcmp_pp()` helper.
  - `core_rpc_server.cpp`/`core_rpc_server_commands_defs.h`: Removed
    `low_mixin` field and its assignment from send_raw_tx response.
  - `daemon_handler.cpp`: Removed `m_low_mixin` error branch.
  - `verification_context.h`: Removed `m_low_mixin` from
    `tx_verification_context`.
  - `blockchain.cpp`: Replaced legacy mixin-checking branch with a reject
    gate for non-FCMP++ transactions (Shekyl only supports FCMP++).
  - `cryptonote_tx_utils.h`/`.cpp`: Removed `rct::RCTConfig` parameter
    from `construct_tx_with_tx_key` and `construct_tx_and_get_tx_key`.
    Replaced `genRctSimple` call with FCMP++ proof generation stub.
    Removed `mixRing` construction.
  - `cryptonote_format_utils.cpp`: Removed `is_rct_bulletproof`/
    `is_rct_clsag` calls, simplified BP+ weight calculations.
  - `cryptonote_boost_serialization.h`: Removed serialization functions
    for `rct::rangeSig`, `rct::Bulletproof`, `rct::mgSig`, `rct::clsag`,
    `rct::RCTConfig`, `rct::boroSig`. Simplified `rctSigBase` and
    `rctSigPrunable` serialization to only handle FCMP++.
  - `tx_verification_utils.h`/`.cpp`: Removed `mix_ring` parameter from
    `ver_rct_non_semantics_simple_cached`. Removed `expand_tx_and_ver_rct_non_sem`,
    `calc_tx_mixring_hash`, and `is_canonical_bulletproof_layout`.
  - `json_object.h`/`.cpp`: Removed JSON serialization for `rct::rangeSig`,
    `rct::Bulletproof`, `rct::boroSig`, `rct::mgSig`, `rct::clsag`.
    Removed legacy prunable fields from `rctSig` JSON output.
  - `wallet2.h`: Removed `rct_config` field from `tx_construction_data`
    serialization and the version-gated `RangeProofPaddedBulletproof`
    defaults in Boost serialization.
  - `wallet2.cpp`: Fixed `construct_tx_and_get_tx_key` call site that
    still passed `{}` where the removed `rct_config` parameter was.
  - `bulletproofs.h`/`.cc`: Gutted non-plus Bulletproof PROVE/VERIFY
    functions — the `rct::Bulletproof` struct was already removed from
    `rctTypes.h`, making these 1000+ lines of dead code.
- **Legacy RCT types stripped from core.** Removed `RCTTypeFull` (1),
  `RCTTypeSimple` (2), `RCTTypeBulletproof` (3), `RCTTypeBulletproof2` (4),
  `RCTTypeCLSAG` (5), and `RCTTypeBulletproofPlus` (6) from the enum.
  Only `RCTTypeNull` (0) and `RCTTypeFcmpPlusPlusPqc` (7) remain.
- Deleted structs: `mgSig`, `clsag`, `rangeSig`, `Bulletproof` (non-plus),
  `RangeProofType` enum, and `RCTConfig`.
- Removed `mixRing` member from `rctSigBase` and `mixin` parameter from
  `serialize_rctsig_prunable`.
- Removed from `rctSigPrunable`: `rangeSigs`, `bulletproofs` (non-plus),
  `MGs`, `CLSAGs` vectors and their serialization blocks.
- Removed functions: `CLSAG_Gen`, `proveRctCLSAGSimple`,
  `verRctCLSAGSimple`, `genRctSimple` (both overloads),
  `populateFromBlockchainSimple`, `getKeyFromBlockchain`,
  `is_rct_simple`, `is_rct_bulletproof`, `is_rct_borromean`, `is_rct_clsag`,
  `proveRangeBulletproof`, `verBulletproof`, `make_dummy_bulletproof`,
  `make_dummy_clsag`.
- Removed `HASH_KEY_CLSAG_ROUND`, `HASH_KEY_CLSAG_AGG_0`,
  `HASH_KEY_CLSAG_AGG_1`, and `HASH_KEY_TXHASH_AND_MIXRING` from
  `cryptonote_config.h`.
- Removed VARIANT_TAG entries for `mgSig`, `rangeSig`, `Bulletproof`,
  and `clsag`.
- Simplified `get_pre_mlsag_hash` to only handle `RCTTypeFcmpPlusPlusPqc`.
- Simplified `verRctSemanticsSimple` and `verRctNonSemanticsSimple` to
  only accept FCMP++ transactions (no CLSAG/ring verification path).

### 🔄 Changed

- **FCMP++ Phase 3: Per-input PQC authorization vector.** Replaced
  `std::optional<pqc_authentication> pqc_auth` with
  `std::vector<pqc_authentication> pqc_auths` on `cryptonote::transaction`
  (one `pqc_authentication` per input). Updated binary, Boost, and JSON
  serialization, transaction hash (`cn_fast_hash` of serialized
  `pqc_auths`), per-input PQC verification, and wallet/RPC signing paths.

### ✨ Added

- **FCMP++ (Full-Chain Membership Proofs): complete implementation across
  Phases 1–6.**
  Shekyl replaces ring signatures (CLSAG) with FCMP++ from genesis. Every
  spend proves membership in the entire UTXO set via a Helios/Selene curve
  tree, giving every transaction full-chain anonymity instead of 16-decoy
  ring ambiguity. Combined with hybrid post-quantum spend authorization
  (Ed25519 + ML-DSA-65), this makes Shekyl the first cryptocurrency to offer
  full-UTXO-set anonymity with quantum-resistant ownership.

  Key components delivered:
  - **Rust foundation (Phase 1):** `shekyl-fcmp` crate wrapping upstream
    `monero-fcmp-plus-plus` with 4-scalar leaf type `{O.x, I.x, C.x,
    H(pqc_pk)}`. Hybrid X25519 + ML-KEM-768 KEM with HKDF-SHA-512.
    Bech32m segmented address encoding. Per-output PQC key derivation.
    15 FFI exports. Security audit (zero vulnerabilities, zero unsafe in
    first-party code). Reproducible builds with pinned Cargo.lock.
  - **Transaction format (Phase 3):** `RCTTypeFcmpPlusPlusPqc = 7` with
    `referenceBlock`, `curve_trees_tree_depth`, and `fcmp_pp_proof` fields.
    `curve_tree_root` commitment in every block header.
  - **Consensus verification (Phase 4):** 7-step verification order in
    `check_tx_inputs` — referenceBlock age, tree depth, key image
    y-normalization, FCMP++ proof via Rust FFI, PQC signature verification,
    BP+ range proofs. Mempool verification caching (`fcmp_verification_hash`
    in `txpool_tx_meta_t`). Staked output curve-tree leaves.
  - **Curve tree database (Phase 2):** Full `get_curve_tree_path` RPC
    implementation assembling real Merkle paths (leaf scalars + per-layer
    sibling hashes with position encoding). Selective pruning of
    intermediate tree layers between checkpoints, wired into `add_block`
    after `save_curve_tree_checkpoint`. Old checkpoint garbage collection.
  - **Wallet integration (Phase 5):** `genRctFcmpPlusPlus()` proof
    construction. `get_curve_tree_path` RPC. Tree-path precomputation
    and incremental update in wallet refresh loop. PQC key rederivation from
    stored shared secret. Restore-from-seed PQC rederivation.
  - **Infrastructure (Phase 6):** Hardware device FCMP++ stubs. CI pipeline
    for Rust workspace build, FCMP crate, determinism check, Bech32m tests.
    `output_pruning_metadata_t` and `m_output_metadata` LMDB table for
    transaction pruning. LMDB curve tree schema (leaves, layers, meta,
    checkpoints). Checkpoint every 10,000 blocks for fast-sync resumption.

  See `docs/FCMP_PLUS_PLUS.md` for the full specification.

- **FCMP++ Phase 3: KEM ciphertext `tx_extra` and coinbase self-encapsulation.**
  - `tx_extra_pqc_kem_ciphertext` with tag `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT`
    (`0x06`): payload `blob` is the concatenation of N ML-KEM-768 ciphertexts
    (1088 bytes each), one per output in order.
  - **Coinbase:** When the miner address has a PQC key and the hard-fork
    version is at least `HF_VERSION_FCMP_PLUS_PLUS_PQC`, `construct_miner_tx`
    performs KEM self-encapsulation to the miner’s own address per coinbase
    output (same tag and derivation semantics as normal transfers), then
    wipes the shared secret after use.

- **FCMP++ Phase 5e: Wallet precomputation of curve tree paths.**
  - Added `fcmp_precomputed_path` struct to `wallet2.h` caching per-output
    tree path, root hash at precompute time, and precompute height.
  - Added `m_fcmp_precomputed_paths` runtime cache (not serialized) and
    `m_fcmp_last_precompute_height` watermark to `wallet2`.
  - `precompute_fcmp_paths()` fetches tree paths for all unspent outputs
    via the `get_curve_tree_path` daemon RPC endpoint.
  - `update_fcmp_paths_incremental(new_height)` extends existing paths
    and adds newly discovered outputs, pruning paths for spent outputs.
  - Incremental path update is hooked into the wallet refresh loop,
    triggering after sync catches up if blocks were fetched.
  - Progress callbacks (`on_fcmp_path_precompute_progress`) fire during
    both initial and incremental precomputation.
- **FCMP++ Phase 5.5: Wallet sync and restore-from-seed PQC support.**
  - `transfer_details::m_combined_shared_secret` (64 bytes) stores the
    hybrid KEM shared secret needed to rederive per-output PQC keys.
  - `rederive_pqc_keys_for_output(td)` calls `shekyl_fcmp_derive_pqc_keypair`
    via FFI to validate keypair derivation from stored shared secret.
  - `rederive_all_pqc_keys()` iterates all transfers with stored shared
    secrets and rederives PQC keys, with progress callback
    `on_pqc_rederivation_progress`.
  - Restore-from-seed triggers full PQC key rederivation on first refresh
    after sync completes.

### 🐛 Fixed

- **Curve tree pop_block over-trim:** `pop_block` previously counted all
  `tx.vout` entries when computing how many leaves to trim, but `add_block`
  skips outputs that fail type checks (unknown target types), locked staked
  outputs, and outputs whose FFI leaf construction fails. The trim count now
  mirrors the same filtering logic used in the grow path, preventing tree
  desynchronization during reorgs.
- **Curve tree pruning correctness:** `prune_curve_tree_intermediate_layers`
  was deleting all intermediate layer entries instead of selectively pruning
  only chunks fully below the previous checkpoint boundary. Fixed to compute
  the chunk boundary from the previous checkpoint's `leaf_count` and only
  remove sealed entries. Also added garbage collection of stale checkpoint
  records (only the two most recent are kept).
- **LMDB output metadata: removed undefined behavior in cursor macros.**
  - `store_output_metadata` now uses `mdb_put` directly with `m_write_txn`
    instead of the `CURSOR()` macro which required `m_cursors` to be in
    scope.
  - `get_output_metadata` and `prune_tx_data` now use `m_txn` (from
    `TXN_PREFIX_RDONLY`) instead of `txn_ptr` (from `TXN_PREFIX`).
  - Removed unused `m_txc_output_metadata` cursor field and
    `m_cur_output_metadata` macro from `db_lmdb.h`.
- **Wallet FCMP++ path precomputation: fixed undefined behavior.**
  - Replaced `reinterpret_cast<std::string&>` on `std::vector<uint8_t>` with
    a proper intermediate `std::string` copy in both `precompute_fcmp_paths`
    and `update_fcmp_paths_incremental`.

- **FCMP++ Phase 6c: CI pipeline updates.**
  - Added x86_64 architecture verification step to the `rust-audit-and-test`
    CI job in `.github/workflows/build.yml`.
  - Added explicit `cargo build --locked -p shekyl-fcmp` step to verify the
    FCMP++ crate builds as part of the Rust workspace.
  - Added dedicated Bech32m address encoding test step that runs
    `shekyl-crypto-pq` address tests with visible CI output.
  - The monero-oxide git dependency is cached via `~/.cargo/git` in the
    existing Cargo cache key (`rust-${{ hashFiles('rust/Cargo.lock') }}`).
  - Determinism check (build twice, diff `libshekyl_ffi.a` hashes) and
    `cargo audit` remain in place.
- **FCMP++ Phase 6f: Transaction pruning mode (skeleton).**
  - Added `output_pruning_metadata_t` packed struct to `blockchain_db.h`
    storing per-output scan data (pubkey, commitment, unlock_time, height,
    pruned flag) for wallet scanning after transaction pruning.
  - Added abstract interface in `BlockchainDB`: `store_output_metadata()`,
    `get_output_metadata()`, `is_output_pruned()`, `prune_tx_data()`.
  - Added `m_output_metadata` LMDB table (keyed by `global_output_index`)
    in `db_lmdb.h` and `db_lmdb.cpp` with cursor, rflag, and DBI member.
  - LMDB implementation: `store_output_metadata` and `get_output_metadata`
    are fully wired; `is_output_pruned` delegates to `get_output_metadata`;
    `prune_tx_data` validates depth against `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`
    and reads/writes a `last_pruned_tx_data_height` watermark in the
    properties table to skip already-processed blocks on subsequent runs.
    The block-iteration pruning loop is documented as a TODO skeleton.
  - `--prune-blockchain` CLI flag now also triggers `prune_tx_data()` in
    `cryptonote_core.cpp`, running output-metadata pruning alongside
    Monero's existing stripe-based pruning.
  - Test DB (`testdb.h`) updated with no-op stubs for all four new methods.
- **FCMP++ Phase 4b: Mempool verification caching.**
  - Added `fcmp_verification_hash` (32-byte `crypto::hash`) and
    `fcmp_verified` (1-bit flag) to `txpool_tx_meta_t` in
    `src/blockchain_db/blockchain_db.h`, carved from the existing
    76-byte padding (now 44 bytes).  Struct stays 192 bytes.
  - New `Blockchain::compute_fcmp_verification_hash()` computes a
    deterministic cache key from `hash(proof || referenceBlock || key_images)`.
  - `tx_memory_pool::add_tx` stores the cache hash on successful FCMP++
    verification.
  - `tx_memory_pool::is_transaction_ready_to_go` checks the cached hash
    via `is_fcmp_verification_cached()` and seeds `m_input_cache` to
    skip re-running `shekyl_fcmp_verify()` for previously-verified
    mempool transactions.
  - Added `static_assert` guards at the `memcmp` site on
    `txpool_tx_meta_t` (tx_pool.cpp line 1656) enforcing
    trivially-copyable layout and 192-byte struct size.
  - All padding and new fields are zero-initialized at every meta
    construction site.
- **FCMP++ Phase 4e: Staking consensus rules for FCMP++.**
  - `collect_outputs` in `blockchain_db.cpp::add_block` now handles
    `txout_to_staked_key` outputs using the same 4-scalar leaf format
    `{O.x, I.x, C.x, H(pqc_pk)}`.
  - Deferred insertion: staked outputs only enter the curve tree when
    `block_height >= effective_lock_until`.  Outputs still within their lock
    period are stored in the `pending_staked_leaves` DB table and
    inserted into the curve tree when they mature (see deferred
    staked leaf insertion entry below).
  - `check_stake_claim_input` validates claims against the staked output's
    `effective_lock_until` (`creation_height + tier_lock_blocks`) and enforces
    `to_height <= min(current_height, effective_lock_until)`.
- **FCMP++ Phase 5: Wallet transaction construction skeleton.**
  - Added `rct::genRctFcmpPlusPlus()` in `src/fcmp/rctSigs.cpp` — builds
    an FCMP++ `rctSig` with `RCTTypeFcmpPlusPlusPqc`, Bulletproofs+ range
    proofs, balanced pseudo-outputs, and invokes `shekyl_fcmp_prove()` via
    FFI to generate the membership proof.
  - Declared the new function in `src/fcmp/rctSigs.h`.
  - Added `COMMAND_RPC_GET_CURVE_TREE_PATH` RPC command in
    `src/rpc/core_rpc_server_commands_defs.h` — accepts output indices and
    returns Merkle paths from the curve tree (stub handler for now).
  - Wired `get_curve_tree_path` JSON-RPC endpoint in
    `src/rpc/core_rpc_server.h` and `src/rpc/core_rpc_server.cpp`.
  - Added TODO scaffolding in `src/wallet/wallet2.cpp` at the decoy
    selection (`get_outs`), transaction construction
    (`construct_tx_and_get_tx_key`), and fee estimation
    (`estimate_tx_weight`) sites, documenting how FCMP++ replaces ring
    signatures in the wallet transfer flow.
- **FCMP++ Phase 6a: Hardware device stubs.**
  - Added `fcmp_prepare`, `fcmp_proof_start`, and `fcmp_proof_add_input`
    virtual methods to `hw::device` (base class) with default `return false`
    implementations for unsupported devices.
  - Software device (`device_default`) returns `true` (scaffolding for Rust
    FFI delegation).
  - Ledger device (`device_ledger`) logs an informative error and returns
    `false`, guiding users to software wallets until Ledger firmware gains
    FCMP++ support.
  - Trezor inherits the base-class defaults (unsupported) without code changes.
  - Updated `RELEASE_CHECKLIST.md` to document hardware wallet readiness status.
- **FCMP++ Phase 4a: Verification in `check_tx_inputs`.**
  - Added `RCTTypeFcmpPlusPlusPqc` verification path in
    `Blockchain::check_tx_inputs` (`src/cryptonote_core/blockchain.cpp`).
  - `referenceBlock` age validation: confirmed within
    `[tip - MAX_AGE, tip - MIN_AGE]` using DB block lookup.
  - `curve_trees_tree_depth` validated against the current tree state.
  - Key offsets verified empty for all FCMP++ inputs.
  - Key image y-normalization enforced (sign bit of byte 31 cleared).
  - Input count bounded by `FCMP_MAX_INPUTS_PER_TX`.
  - `shekyl_fcmp_verify()` FFI call wired up with key images, pseudo
    outputs, and proof blob.
  - Per-input `pqc_auths` verification left as documented TODO pending
    the per-input auth field migration.
- **FCMP++ Phase 4a-pre: PQC auth binding specification.**
  - New `docs/FCMP_PLUS_PLUS.md` formally documents the dual-layer
    binding model, per-input signed payload layout, and 7-step consensus
    verification order for `RCTTypeFcmpPlusPlusPqc` transactions.
- **FCMP++ Phase 3.5: Curve tree root in block header (consensus-critical).**
  - Added `curve_tree_root` (`crypto::hash`) field to `block_header` in
    `src/cryptonote_basic/cryptonote_basic.h`, initialized to `null_hash`.
  - Field is always serialized (genesis-native, no version gating) in both
    the binary archive (`BEGIN_SERIALIZE`) and Boost serialization.
  - Block template creation (`Blockchain::create_block_template`) snapshots
    the current DB curve tree root into the header.
  - Block validation (`Blockchain::handle_block_to_main_chain`) verifies
    `curve_tree_root` matches the locally-computed tree root after
    `add_block` grows the tree; rejects the block on mismatch.
  - RPC `block_header_response` now includes `curve_tree_root` hex string.
  - Test generator (`chaingen.cpp`) sets `curve_tree_root` to `null_hash`
    in `construct_block` and `construct_block_manually`.
- **FCMP++ Phase 3: Transaction format for FCMP++ PQC.**
  - Added `RCTTypeFcmpPlusPlusPqc = 7` to the RCT type enum in
    `src/fcmp/rctTypes.h` — Shekyl's only non-coinbase transaction type.
  - Added `referenceBlock` (block hash anchoring the curve tree snapshot)
    to `rctSigBase`, serialized only for the new type.
  - Added `curve_trees_tree_depth` and `fcmp_pp_proof` (opaque FCMP++ proof
    blob) to `rctSigPrunable`, replacing CLSAG ring signatures for the new type.
  - Added `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` (0x06) to `tx_extra.h` for
    per-output ML-KEM-768 ciphertexts.
  - Added `key_image_y_normalize()` to `crypto.h`/`crypto.cpp` — clears the
    sign bit of a key image's y-coordinate as required by FCMP++.
  - Added `is_rct_fcmp_pp_pqc()` helper to `rctTypes.h`/`rctTypes.cpp`.
  - Updated serialization helpers (`serialize_rctsig_base`,
    `serialize_rctsig_prunable`) and type classifier functions
    (`is_rct_simple`, `is_rct_bulletproof_plus`) to handle the new type.
- **FCMP++ Phase 2e: Curve tree checkpoint strategy.**
  - New `BlockchainDB` virtual methods: `save_curve_tree_checkpoint`,
    `get_curve_tree_checkpoint`, `get_latest_curve_tree_checkpoint_height`,
    `prune_curve_tree_intermediate_layers`.
  - LMDB implementation with `curve_tree_checkpoints` table (MDB_INTEGERKEY),
    storing root[32] + depth[1] + leaf_count[8] per checkpoint.
  - Automatic checkpoint every `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL` (10 000)
    blocks during `add_block`, enabling fast-sync resumption.
  - Configurable interval via `cryptonote_config.h` constant.
- **FCMP++ Phase 2f: Curve tree pruning strategy.**
  - `prune_curve_tree_intermediate_layers` removes recomputable internal hash
    layers between checkpoints, preserving leaves and the root layer to reduce
    storage overhead.
- **FCMP++ Phase 1: Rust foundation crates.**
  - New `rust/shekyl-fcmp/` crate wrapping upstream `monero-fcmp-plus-plus`
    (from `Shekyl-Foundation/monero-oxide` fork, `fcmp++` branch) with
    4-scalar curve tree leaf type `{O.x, I.x, C.x, H(pqc_pk)}`.
  - Implemented `HybridX25519MlKem` (X25519 + ML-KEM-768 FIPS 203) in
    `shekyl-crypto-pq/src/kem.rs` with HKDF-SHA-512 shared-secret
    combination and master-seed key derivation.
  - Implemented Bech32m segmented address encoding
    (`shekyl1<classical>/skpq1<pqc_a>/skpq21<pqc_b>`) in
    `shekyl-crypto-pq/src/address.rs`, keeping each segment within
    Bech32m's proven checksum range.
  - Implemented per-output PQC keypair derivation (HKDF-Expand → ML-DSA-65
    deterministic keygen) in `shekyl-crypto-pq/src/derivation.rs`.
  - Added 15 new FFI exports to `shekyl-ffi` for FCMP++ proofs, KEM
    operations, address encoding, and seed derivation.
  - Added FCMP++ consensus constants to `cryptonote_config.h`:
    `HF_VERSION_FCMP_PLUS_PLUS_PQC`, `FCMP_REFERENCE_BLOCK_MAX_AGE` (100),
    `FCMP_REFERENCE_BLOCK_MIN_AGE` (2), `FCMP_MAX_INPUTS_PER_TX` (8).
  - Updated `BuildRust.cmake` with `--locked` flag for reproducible builds.
- **FCMP++ Phase 1a.1: Security review of forked monero-oxide crates.**
  - `cargo audit`: 226 crate dependencies scanned, zero vulnerabilities found.
  - `unsafe` block audit: zero `unsafe` in first-party monero-oxide workspace
    code (helioselene, ec-divisors, generalized-bulletproofs, fcmps,
    monero-oxide). Only 4 `unsafe` blocks exist in helioselene benchmarks
    (`_rdtsc()` for cycle counting, not in library code). `dalek-ff-group`
    (crates.io dependency) also has zero `unsafe` blocks.
  - Veridise audit status: FCMPs circuit audited by Veridise (June 2025);
    Generalized Bulletproofs security proofs by Cypher Stack; Divisor proofs
    reviewed by both Veridise and Cypher Stack. Pinned commit `92af05e0` is
    post-audit. Helioselene and ec-divisors are not yet independently audited.
    Multi-phase integration audit (seraphis-migration/monero#294) is in
    planning.
- **FCMP++ Phase 1a.2: Rust reproducible builds.**
  - `Cargo.lock` pins all git dependencies to exact commit hash `92af05e0`.
  - Double-build determinism verified: `libshekyl_ffi.a` hash identical across
    consecutive builds on x86_64.
  - Added CI job `rust-audit-and-test` to `.github/workflows/build.yml` with
    cargo audit, workspace tests, and determinism check (build twice, diff).
  - Documented x86_64-only build requirement and Guix integration status in
    `docs/COMPILING_DEBUGGING_TESTING.md`.

### 🔄 Changed

- **P2P reorg functional test uses deadline-based polling.** Replaced three
  fixed-sleep polling sites in `test_p2p_reorg()` (`time.sleep(10)` x2,
  `loops = 100` counter) with 240 s deadline + 0.25 s interval polling,
  matching the pattern already used in `test_p2p_tx_propagation()`.
  Adapted from upstream Monero #9795.

### ✨ Added

- **Extra compiler warnings and hardening flags.** Added `-Wredundant-decls`,
  `-Wdate-time`, `-Wimplicit-fallthrough`, `-Wunreachable-code` (common);
  `-Woverloaded-virtual`, `-Wsuggest-override` (C++ only); `-Wgnu`,
  `-Wshadow-field`, `-Wthread-safety`, `-Wloop-analysis`,
  `-Wconditional-uninitialized`, `-Wdocumentation`, `-Wself-assign` (Clang);
  `-Wduplicated-branches` (GCC). Added security protections:
  `-fno-extended-identifiers`, `-fstack-reuse=none`, and ARM64 branch
  protection (`-mbranch-protection=bti` on macOS, `standard` elsewhere).
  Adapted from upstream Monero #9858.
- **Linker dead-code stripping.** Added `-ffunction-sections -fdata-sections`
  to compile flags and `-Wl,--gc-sections` (Linux) / `-Wl,-dead_strip`
  (macOS) to linker flags, enabling the linker to strip unreferenced
  functions and data. Inspired by upstream Monero #9898 author's findings
  (~14 MiB reduction in Docker images).

### 📚 Documentation

- **Upstream Monero PR triage.** Replaced the stale "To be done (and merged)"
  section in `COMPILING_DEBUGGING_TESTING.md` with a structured triage table
  covering applied PRs (#6937, #9762, #9795, #9858, #9898) and tracked-for-
  future-work PRs (#10157, #10084, #9801) with STRUCTURAL_TODO.md cross-refs.
- **FCMP++ documentation rework (Phase 0.5a).** Reworked all core documentation
  to reflect FCMP++ as the membership proof system from genesis. Replaced CLSAG
  and ring signature references with FCMP++ full-chain membership proof language.
  Updated PQC spec for per-input pqc_auths, per-output KEM derivation, Bech32m
  addresses, and curve tower architecture. Retired V4 lattice ring signature
  roadmap. Updated V3_ROLLOUT.md size estimates for ~23 KB typical transactions.
  Added FCMP++ items to RELEASE_CHECKLIST.md.

### 🐛 Fixed

- **Re-enabled `gen_block_reward` core test with Shekyl economics.**
  Rewrote `check_block_rewards()` in `block_reward.cpp` to verify miner
  outputs against Shekyl's four-component economics formula (release
  multiplier + emission split + fee burn) instead of legacy Monero fixed
  expectations. Updated `construct_miner_tx_by_weight` to pass explicit
  economics parameters. Fixed `construct_block` and
  `construct_block_manually` in `chaingen.cpp` to pass
  `circulating_supply=already_generated_coins` to `construct_miner_tx`,
  preventing parameter mismatch between test generator and validator.
  80 core_tests now pass (was 79).

- **MSVC C4334: 23 `1 << n` sites widened to `1ULL << n` in consensus
  code.** Fixed potential undefined behavior (signed 32-bit overflow if
  shift amount ever reaches 32) in `cryptonote_format_utils.cpp` (3),
  `bulletproofs.cc` (6), `bulletproofs_plus.cc` (6), `rctTypes.cpp` (5),
  `rctSigs.cpp` (2), and `multiexp.cc` (2).

- **MSVC C4333 right-shift warning in UTF-8 helpers.** Changed `wint_t cp` to
  `uint32_t cp` in `src/common/util.cpp` `get_string_prefix_by_width()`, and
  added an explicit `static_cast<uint32_t>` on the transform result in
  `src/common/utf8.h` `utf8canonical()`. On MSVC, `wint_t` is 16-bit
  `unsigned short`, so `cp >> 18` shifted by more than the type's width.

- **Remaining HF17 references corrected to HF1.** Fixed stale Monero-era
  `HF17` / `HF_VERSION_SHEKYL_NG = 17` references in `POST_QUANTUM_CRYPTOGRAPHY.md`
  (scheme registry, rollout notes, V4 roadmap), `PQC_MULTISIG.md` (V3 heading,
  V4 scheme table, activation target), `V3_ROLLOUT.md` (title, consensus gate,
  node checklist), and `STAKER_REWARD_DISBURSEMENT.md`. Also corrected `HF18`
  references to `HF2` in multisig V4 rollout tables. The source code constant
  `HF_VERSION_SHEKYL_NG` was already correctly defined as `1` in
  `cryptonote_config.h`; only documentation was affected.

- **CMake Boost detection on CMake 3.30+**: The built-in `FindBoost.cmake`
  module was removed in CMake 3.30. Restructured Boost detection to try
  CONFIG mode first (finding `BoostConfig.cmake` installed by b2), falling
  back to MODULE on older CMake. Fixes `contrib/depends` builds on Ubuntu
  24.04 runners with CMake ≥ 3.30.

### 🗑️ Removed

- **Classical multisig wallet RPC commands.** Removed all 9 Monero-inherited
  multisig RPC endpoints (`is_multisig`, `prepare_multisig`, `make_multisig`,
  `export_multisig_info`, `import_multisig_info`, `finalize_multisig`,
  `exchange_multisig_keys`, `sign_multisig`, `submit_multisig`) from the
  wallet RPC server. Removed `multisig_txset` fields from transfer and sweep
  response structs. Removed the `CHECK_MULTISIG_ENABLED` macro and
  `multisig/multisig.h` dependency. Classical secret-splitting multisig is
  replaced by PQC-only authorization (`scheme_id = 2`); see
  `docs/PQC_MULTISIG.md`.
- **Classical multisig simplewallet CLI commands.** Removed all multisig and
  MMS (Multisig Messaging System) commands from `simplewallet`: `prepare_multisig`,
  `make_multisig`, `exchange_multisig_keys`, `export_multisig_info`,
  `import_multisig_info`, `sign_multisig`, `submit_multisig`,
  `export_raw_multisig_tx`, and all `mms` subcommands. Removed
  `--generate-from-multisig-keys` and `--restore-multisig-wallet` CLI flags.
  Removed `enable-multisig-experimental` wallet setting. Removed
  `wallet/message_store.h` dependency. The `transfer_main`/`called_by_mms`
  indirection was collapsed into a single `transfer` method.
- **Classical multisig test and device_trezor remnants.** Removed stale
  multisig references from test infrastructure: `m_multisig*` wallet resets
  in `wallet_tools.cpp`, `multisig_sigs.clear()` in Trezor tests,
  `multisig_txset` assertion in `cold_signing.py`, and deleted
  `tests/functional_tests/multisig.py`. Removed `multisig` from the
  functional test default list. Cleaned up device_trezor protocol:
  removed `translate_klrki`, `MoneroMultisigKLRki` alias, `m_multisig`
  member, and multisig cout decryption in `Signer::step_final_ack`.
  Removed `mms_error`, `no_connection_to_bitmessage`, and
  `bitmessage_api_error` error classes from `wallet_errors.h`.
- **Classical multisig wallet API layer.** Removed all classical multisig
  code from the public wallet API: `MultisigState` struct, virtual multisig
  declarations (`multisig`, `getMultisigInfo`, `makeMultisig`,
  `exchangeMultisigKeys`, `exportMultisigImages`, `importMultisigImages`,
  `hasMultisigPartialKeyImages`, `restoreMultisigTransaction`,
  `publicMultisigSignerKey`, `signMultisigParticipant`,
  `multisigSignData`, `signMultisigTx`). Removed multisig helper functions
  and multisig threshold check from PendingTransaction commit path.
  Removed multisig guard from the background-sync validation macro.
- **Classical multisig wallet core (`wallet2.cpp`).** Removed all classical
  multisig code from the wallet core: `#include "multisig/..."` headers,
  `MULTISIG_UNSIGNED_TX_PREFIX`/`MULTISIG_EXPORT_FILE_MAGIC`/`MULTISIG_SIGNATURE_MAGIC`
  constants, `m_multisig`/`m_multisig_threshold`/`m_multisig_rounds_passed`/
  `m_enable_multisig`/`m_message_store`/`m_mms_file` member initializations,
  `num_priv_multisig_keys_post_setup`, `get_multisig_seed`, multisig restore
  path in `generate()`, `make_multisig`, `exchange_multisig_keys`,
  `get_multisig_first_kex_msg`, `multisig()`, `has_multisig_partial_key_images`,
  `frozen(multisig_tx_set)`, all `save/parse/load/sign_multisig_tx` overloads,
  the multisig transaction builder path in `transfer_selected_rct`,
  `export_multisig`, `import_multisig`, `update_multisig_rescan_info`,
  `get_multisig_signer_public_key`, `get_multisig_signing_public_key`,
  `get_multisig_k`, `get_multisig_kLRki`, `get_multisig_composite_kLRki`,
  `get_multisig_composite_key_image`, `get_multisig_wallet_state`,
  `sign_multisig_participant`, JSON serialization/deserialization of multisig
  fields, MMS file handling, and all scattered `m_multisig` guard branches.
- **Classical multisig `m_key_image_partial` remnants.** Removed the
  `m_key_image_partial` bitfield from `exported_transfer_details` and all
  code references in `wallet2.cpp` and `simplewallet.cpp`. Since classical
  multisig was removed, partial key images can never exist; all guard
  conditions (`!known || partial`, `known && !partial`, standalone partial
  checks) were simplified to reference only `m_key_image_known`. Removed
  the dead `old_mms_file` cleanup block from `wallet2::store_to`.

### ✨ Added

- **Daemon RPC migrated to Rust/Axum (Phase 1).** The daemon HTTP RPC transport
  is now served by the `shekyl-daemon-rpc` Rust crate using Axum, replacing
  `epee::http_server_impl_base`. All 90 endpoints (33 JSON REST, 9 binary,
  48 JSON-RPC 2.0) are routed through Axum with PQC-ready 10 MiB body limits,
  CORS, and restricted-mode enforcement. The C++ `core_rpc_server` handler
  logic is unchanged and accessed via a `core_rpc_ffi` C ABI facade. Enabled
  by default; `--no-rust-rpc` falls back to the legacy epee HTTP server.
  JSON REST endpoints accept both GET and POST (matching epee). Binary
  endpoints return 400 on parse failure (matching epee's MAP_URI_AUTO_BIN2).
  Validated on live testnet: 23/25 pass, 2 expected diffs
  (`rpc_connections_count`), 2 binary skips (empty-POST → 400 on both).
  Validation harness at `tests/rpc_comparison/compare_rpc.sh`;
  test data in `shekyl-dev/data/rpc_comparison/`.
- **PQC multisig core (scheme_id=2).** Implemented M-of-N hybrid Ed25519 +
  ML-DSA-65 multisig in Rust. Includes `MultisigKeyContainer`,
  `MultisigSigContainer`, `multisig_group_id`, and a 10-check adversarial
  verification pipeline. Maximum 7 participants (consensus constant). Domain
  separator: `shekyl-multisig-group-v1`.
- **PQC multisig FFI bridge.** Extended `shekyl_pqc_verify` to accept
  `scheme_id` and dispatch between single-signer (1) and multisig (2) paths.
  Added `shekyl_pqc_verify_debug` for diagnostic error codes and
  `shekyl_pqc_multisig_group_id` for group identity computation.
- **Scheme downgrade protection.** New `tx_extra_pqc_ownership` tag (0x05)
  records the expected PQC scheme and group ID for each output, preventing
  attackers from spending multisig-protected outputs with single-signer
  transactions.
- **Wallet multisig coordination.** New wallet2 methods for PQC multisig:
  `create_pqc_multisig_group`, `export_multisig_signing_request`,
  `sign_multisig_partial`, `import_multisig_signatures`. File-based JSON
  signing protocol. Wallet serialization version bumped to 32.
- **Cargo-fuzz harnesses.** 4 fuzz targets for multisig deserialization and
  verification (`fuzz_multisig_key_blob`, `fuzz_multisig_sig_blob`,
  `fuzz_multisig_verify`, `fuzz_group_id`), each validated at 10M iterations
  with zero panics.
- **PQC multisig subset-signing test.** Added `valid_subset_signing_3_of_5`
  test to `shekyl-crypto-pq` verifying that any valid 3-of-5 signer subset
  produces a valid multisig through the full 10-check verification pipeline.
- **PQC multisig test vectors.** Published
  `docs/PQC_TEST_VECTOR_002_MULTISIG.json` with canonical encoding sizes,
  wire-format sizes, verification pipeline checks, the 10-check pipeline,
  size regression data, and adversarial test cases for `scheme_id = 2`.
- **MSVC wallet-core build path**: `BuildRust.cmake` now selects the
  `x86_64-pc-windows-msvc` Rust target when CMake is driven by MSVC,
  enabling the Tauri GUI wallet to link against shekyl-core on Windows.
  The existing MinGW cross-compilation path for headless binaries is
  unchanged.
- **CI: Windows MSVC wallet-core job** (`build-windows-msvc`): New CI
  lane builds the wallet-core static libraries with Visual Studio / MSVC
  via vcpkg, validating the MSVC portability patches on every push.
- **Unified Gitian release pipeline.** The `gitian` workflow is now the sole
  release pipeline, replacing the separate `release-tagged` workflow. Gitian
  builds produce reproducible binaries; a new `package-and-publish` job
  creates `.deb`/`.rpm` packages, a Windows NSIS installer, source archive,
  and `SHA256SUMS`, then publishes the GitHub Release. Eliminates duplicate
  cross-compilation and host-toolchain issues.
- **Source archive in GitHub Releases.** The packaging job produces
  `shekyl-vX.Y.Z-source.tar.gz` containing the full source tree with all
  submodules, attached to each release alongside the binaries.

### 🔄 Changed

- **`shekyl_pqc_verify` FFI signature change.** Now requires `scheme_id` as
  first parameter for scheme dispatch.
- **`depends.yml` demoted to PR-only.** The cross-compilation CI workflow now
  runs only on pull requests (and manual dispatch), not on every push. Saves
  significant CI minutes; Gitian catches cross-platform issues at release time.
- **`release-tagged.yml` disabled.** The Gitian pipeline now handles all
  release artifacts. The old workflow is preserved as `.disabled` for one
  release cycle.
- **Gitian reproducible builds: migrated from Ubuntu 18.04 (Bionic) to 22.04
  (Jammy).** All five build descriptors (`gitian-linux.yml`, `gitian-win.yml`,
  `gitian-osx.yml`, `gitian-android.yml`, `gitian-freebsd.yml`),
  `gitian-build.py`, and `dockrun.sh` now target Jammy. Drops GCC 7 and
  Python 2 dependencies in favour of the distro-default GCC 11 and Python 3.
  Upgrades FreeBSD cross-compiler from Clang 8 to Clang 14. Removes
  Bionic-specific workarounds (i686 asm symlink hack, glibc `math-finite.h`
  hack). Adds `linux-libc-dev:i386` for native i686 headers. C++17 is now
  fully supported by the Gitian toolchain.

### 🐛 Fixed

- **Comprehensive compiler warning cleanup across all CI platforms.** Eliminated
  ~30 unique warnings inherited from Monero across Linux, macOS, Windows, and
  Arch Linux CI builds:
  - Removed dead code: `add_public_key` (format_utils), `keys_intersect`
    (wallet2), unused `addressof` template specialization (crypto test),
    unused `max_block_height` variable (protocol_handler).
  - Fixed `oaes_lib.c`: replaced deprecated `ftime()` with `gettimeofday()`,
    corrected transposed `calloc` argument order (5 call sites).
  - Fixed `rx-slow-hash.c`: added `(void)` to K&R-style function definitions.
  - Suppressed GCC false positive `-Wstringop-overflow` in `tree-hash.c`.
  - Replaced deprecated `strand::wrap()` with `boost::asio::bind_executor()`
    in `levin_notify.cpp`.
  - Suppressed GCC `-Wuninitialized` for safe circular-reference constructors
    in `cryptonote_core.cpp` and `long_term_block_weight.cpp`.
  - Added default member initializers to `BulletproofPlus` (rctTypes.h),
    `transfer_details` and `payment_details` (wallet2.h) to silence
    `-Wmaybe-uninitialized`.
  - Fixed Windows: removed unused variables in `windows_service.cpp`,
    eliminated `-Wcast-function-type` in `util.cpp` via `void*` intermediate
    cast, fixed `-Wtype-limits` in `utf8.h` by using `uint32_t` instead of
    `wint_t` for code points.
  - Suppressed intentional uninitialized read in `memwipe.cpp` test.
  - Set `MACOSX_DEPLOYMENT_TARGET` for native Darwin Cargo builds in
    `BuildRust.cmake` to eliminate 672 linker warnings from `ring` crate.
- **CI link errors: separated `shekyl-daemon-rpc` from `shekyl-ffi`.** The daemon
  RPC Axum crate was bundled into `libshekyl_ffi.a`, causing `undefined reference
  to core_rpc_ffi_*` on non-daemon targets (gen-ssl-cert, wallet-crypto-bench,
  etc.) across all 5 CI platforms. Moved FFI exports (`shekyl_daemon_rpc_start`,
  `shekyl_daemon_rpc_stop`) into a new `ffi_exports.rs` within the daemon-rpc
  crate, which now produces its own `libshekyl_daemon_rpc.a` staticlib. Only the
  daemon target links both libraries. `BuildRust.cmake` updated with a second
  cargo build step and `SHEKYL_DAEMON_RPC_LINK_LIBS`.
- **Wallet: `--daemon-port` help text referenced Monero port 18081.** Updated to
  Shekyl's default RPC port 11029.
- **Wallet: `account_public_address` equality after PQC.** Destination and
  change-address checks used `memcmp` on the whole struct; `m_pqc_public_key`
  is a `std::vector`, so equality was wrong when keys matched but allocations
  differed. All such sites now use `operator==` / `!=`. Added a
  `static_assert` that the type is not trivially copyable to discourage raw
  `memcmp` regressions.
- **Wallet / Ledger: constant-time comparison for 32-byte secrets.**
  `wallet2::is_deterministic` and Ledger HMAC secret lookup now use
  `crypto_verify_32` instead of `memcmp`.
- **MSVC: add `<io.h>` and POSIX guards in `util.cpp`.** Added `<io.h>`
  for `_open_osfhandle`/`_close`, expanded MinGW conditionals to cover
  MSVC for `setenv`→`putenv`, `mode_t`/`umask`, and `closefrom`→no-op.
- **MSVC: replace `__thread` with `thread_local` in `perf_timer.cpp` and
  `threadpool.cpp`.** GCC's `__thread` is not supported by MSVC.
- **MSVC: rename `xor` parameter in `slow-hash.c` to `xor_pad`.** MSVC
  treats `xor` as a reserved keyword in C mode. Both the x86/SSE and
  ARM/NEON variants of `aes_pseudo_round_xor()` were affected.
- **MSVC: fix iterator-to-pointer cast in `http_auth.cpp`.** MSVC
  `boost::as_literal()` iterator is a class, not a raw pointer. Used
  `&*data.begin()` to obtain the address.
- **MSVC: guard `unbound.h` include and usage in `util.cpp`.** The
  include and `unbound_built_with_threads()` function/call were not
  wrapped in `HAVE_DNS_UNBOUND`, causing a missing-header error.
- **MSVC: guard `unistd.h` in easylogging++.** The third-party logging
  library unconditionally included `<unistd.h>` which does not exist on
  MSVC.
- **MSVC: add `<io.h>` include for `_isatty` in `mlog.cpp`.** The WIN32
  code path uses `_isatty`/`_fileno` which require `<io.h>` on MSVC.
- **MSVC: fix `boost::iterator_range` conversion in `http_auth.cpp`.**
  Boost 1.90 `as_literal()` returns an iterator type that does not
  implicitly convert to `iterator_range<const char*>` on MSVC. Changed to
  `auto` deduction.
- **MSVC: add `<cwctype>` include for `std::towlower` in
  `language_base.h`.** MSVC does not transitively include wide-character
  utilities through other Boost headers.
- **MSVC: fix rvalue binding in portable_storage serialization.** Changed
  `array_entry_t::insert_first_val` and `insert_next_value` from strict
  rvalue-reference parameters (`t_entry_type&&`) to pass-by-value, allowing
  lvalue forwarding from `portable_storage::insert_first_value` /
  `insert_next_value` to work correctly under MSVC template deduction.
- **MSVC: force-include `<iso646.h>` for C++ alternative tokens.** The
  codebase uses `not`, `and`, `or` extensively (hundreds of sites). MSVC
  does not recognise these as keywords by default. Added `/FIiso646.h` to
  the MSVC compile definitions so they are defined in every translation
  unit.
- **MSVC: enable conformant preprocessor (`/Zc:preprocessor`).** MSVC's
  traditional preprocessor breaks nested `__VA_ARGS__` forwarding in the
  `THROW_ON_RPC_RESPONSE_ERROR` macro chain, causing `throw_wallet_ex`
  template deduction failures. Added `/Zc:preprocessor` to MSVC compile
  flags and removed the obsolete Boost.Preprocessor-based `throw_wallet_ex`
  fallback in favour of the standard variadic template version.
- **Gitian: enable `universe` repository and remove apt proxy in Docker base
  image.** The `ubuntu:jammy` Docker image only enables `main restricted` by
  default; `gitian-build.py` now patches the base image after `make-base-vm`
  to add `universe` and remove the `apt-cacher-ng` proxy configuration
  (`/etc/apt/apt.conf.d/50cacher`). The proxy routes all apt traffic through
  `172.17.0.1:3142` which is unreliable on ephemeral CI runners, causing
  persistent 503 failures during package installation. Uses `docker build`
  (not run+commit) to preserve the image's CMD/USER metadata.
- **Gitian Linux: fix i386-dependent package installation.** The i386
  architecture is now enabled in the Docker base image (via `gitian-build.py`'s
  `docker build` step) along with passwordless `sudo` for the `ubuntu` user,
  allowing `linux-libc-dev:i386`, `gcc-multilib`, and `g++-multilib` to be
  installed normally via the descriptor's `packages:` section.
- **Gitian macOS: add `libtinfo5` and `python-is-python3`, remove `python`
  from `FAKETIME_PROGS`.** The pre-built Clang 9 cross-compiler requires
  `libtinfo.so.5`. The `python` faketime wrapper broke CMake's
  `FindPythonInterp` version detection in the `native_libtapi` build (empty
  `PYTHON_VERSION_STRING`); removing `python` from the faketime wrappers
  fixes this while preserving timestamp reproducibility for `ar`, `ranlib`,
  `date`, `dmg`, and `genisoimage`.
- **Gitian Android: add `python-is-python3`.** Android NDK r17b scripts use
  `#!/usr/bin/env python` which does not exist on Jammy without this package.
- **Gitian macOS: fix Rust `ring` crate cross-compilation.** `BuildRust.cmake`
  incorrectly overrode the macOS cross-compiler with the Linux system `clang`
  when cross-compiling for Darwin, causing the `ring` crate to include
  Linux-only `cet.h`. Now only uses system clang on native macOS builds.
- **Gitian Windows: drop i686 (32-bit) target.** The i686-pc-windows-gnu Rust
  target has an unresolved `GetHostNameW@8` symbol against MinGW's `ws2_32`.
  Since the release workflow only targets x86_64, the 32-bit Gitian build is
  removed.
- **macOS cross-build: exclude `-fcf-protection=full`.** Intel CET is x86
  Linux only; the flag defines `__CET__` which triggers `#include <cet.h>` in
  the `ring` crate's assembly, but `cet.h` does not exist in the macOS SDK.
  Now excluded for all Apple targets.
- **macOS aarch64 cross-build: set `MACOSX_DEPLOYMENT_TARGET=10.16`.**
  Clang 9 (depends cross-compiler) does not recognise macOS version 11.0+.
  Apple aliases 10.16 == 11.0; the `cc-rs` crate respects this env var, fixing
  the `ring` build for `aarch64-apple-darwin`.
- **Gitian Docker base image: install `sudo` before creating sudoers entry.**
  The `/etc/sudoers.d/` directory does not exist in the minimal Ubuntu image
  until the `sudo` package is installed.

### 🔄 Changed

- **Replace all `BOOST_FOREACH` / `BOOST_REVERSE_FOREACH` with range-for
  loops.** 31+ call sites across test and utility code replaced with standard
  C++11 range-based for. Adds `/DNOMINMAX` to MSVC definitions to prevent
  Windows `min`/`max` macro collisions.
- **Replace hardcoded `-fPIC` with `POSITION_INDEPENDENT_CODE`.** The CMake
  property works across all compilers (GCC, Clang, MSVC). Applied to
  `liblmdb` and `easylogging++` CMakeLists.
- **Guard/remove unguarded `#include <unistd.h>`.** POSIX header guarded
  behind `#ifndef _WIN32` in `blockchain_import.cpp`; unused include removed
  from `crypto.cpp`.
- **Replace C++20 designated initializers with C++17-compatible member
  assignment.** Rewrote 10 call sites in `cryptonote_core.cpp`,
  `blockchain.cpp`, `levin_notify.cpp`, `multisig_tx_builder_ringct.cpp`, and
  `wallet2.cpp`. GCC/Clang accepted these as extensions; MSVC rejects them.
- **Replace all `__thread` with `thread_local`.** Covers `easylogging++.cc`,
  `perf_timer.cpp`, and `threadpool.cpp`. The `__thread` qualifier is
  GCC/Clang-specific; `thread_local` (C++11) is
  portable across GCC, Clang, and MSVC.
- **Centralize `ssize_t` typedef in `src/common/compat.h`.** Replaces
  duplicate `#if defined(_MSC_VER)` guards in `util.h` and `download.h`
  with a single include.

### 🗑️ Removed

- **Classical multisig code removed from wallet2.h.** Removed all classical
  Monero-style multisig types (`multisig_info`, `multisig_sig`,
  `multisig_kLR_bundle`, `multisig_tx_set`), public/private multisig API
  methods, multisig private members, MMS (message store) integration, and
  associated Boost serialization functions. The `src/multisig/` directory and
  `src/wallet/message_store.h` are deleted; `wallet2.h` no longer depends on
  those headers. All multisig uses PQC-only authorization (`scheme_id = 2`)
  via the `pqc_auth` layer.
- **Gitian Android build.** Removed from the Gitian matrix since there is no
  Android wallet. The Android NDK r17b is also incompatible with Ubuntu Jammy.
- **Gitian Linux: drop i686-linux-gnu (32-bit x86) target.** Eliminates the
  need for `linux-libc-dev:i386`, `gcc-multilib`, `g++-multilib`, `sudo`,
  and the `dpkg --add-architecture i386` workaround. Simplifies the Docker
  base image patching to only enable the `universe` repository.

### 📚 Documentation

- **`docs/RELEASING.md`: document all release artifacts.** Updated the
  artifact table to list all 13 files produced per release (was 6),
  including cross-platform tarballs, aarch64 `.deb`/`.rpm`, and source
  archive. Updated "Future Platforms" to reflect that macOS tarballs are
  now shipping and `.dmg`/AppImage remain planned.

## [3.0.3-RC1] - 2026-03-31

### Known Limitations

- **Multisig not yet implemented.** Multisig wallets are restricted to v2
  transactions (no PQC authentication). PQC-enabled multisig is planned for
  a future release. See `docs/PQC_MULTISIG.md` for the design.

### ✨ Added

- **Rust wallet RPC server (`shekyl-wallet-rpc`)**: New Rust crate that
  replaces the C++ `wallet_rpc_server` with an axum-based JSON-RPC server.
  Calls the existing C++ `wallet2` library through a new C FFI facade
  (`wallet2_ffi.cpp/.h`). Supports all 98 RPC methods with full parity.
  Can run as a standalone binary (`shekyl-wallet-rpc`) or be embedded
  as a library in the Tauri GUI wallet. See `docs/WALLET_RPC_RUST.md`.

- **C++ wallet2 FFI facade (`wallet2_ffi.cpp/.h`)**: Opaque-handle C API
  over `wallet2` with JSON serialization at the boundary. Includes a
  generic `wallet2_ffi_json_rpc()` dispatcher that routes all RPC methods
  to the underlying wallet2 implementation. Covers lifecycle, queries,
  transfers, sweeps, proofs, accounts, address book, import/export,
  multisig, staking, mining, background sync, and daemon management.

- **GUI wallet direct FFI integration**: The Tauri GUI wallet now calls
  wallet2 directly through the Rust FFI bridge (`wallet_bridge.rs`)
  instead of spawning a child `shekyl-wallet-rpc` process and
  communicating via HTTP. Eliminates process management, port allocation,
  and HTTP overhead. Removed `wallet_process.rs` and `wallet_rpc.rs`.

### v3-First Core Test Adaptation

- **Enforced min_tx_version=3 for non-coinbase transactions**: All user
  transactions in the test suite now construct v3 with PQC authentication
  (hybrid Ed25519 + ML-DSA-65). Coinbase transactions remain v2.
- **Adapted chaingen framework for RCT-from-genesis**: Transaction
  construction helpers (`construct_tx_to_key`, `construct_tx_rct`) thread
  `hf_version=1` and `use_view_tags=true`. Coinbase outputs are indexed
  under `amount=0` for correct RCT spending. Fixed difficulty is injected
  for FAKECHAIN replay. Mixin checks are relaxed for FAKECHAIN.
- **Added RCT-aware balance verification**: Pool transaction balance checks
  in `gen_chain_switch_1` now decrypt ecdhInfo amounts using the recipient's
  view key instead of relying on the plaintext `o.amount` field (always 0
  for RCT outputs).
- **Recalibrated economic constants for Shekyl**: Test constants
  (`TESTS_DEFAULT_FEE`, `FIRST_BLOCK_REWARD`, `MK_COINS`) match Shekyl's
  `COIN = 10^9`, `EMISSION_SPEED_FACTOR = 21`, and staker/burn splits.
  `construct_miner_tx_manually` in block validation tests uses Shekyl's
  reward distribution.
- **Fixed Bulletproofs+ test suite**: Dynamically discover miner output
  amounts, set HF to 1 for all block construction, correctly flag coinbase
  outputs as RCT. All 15 BP+ tests pass.
- **Fixed txpool tests**: Adjusted key image count assertions for
  multi-input RCT transactions and corrected unlock_time handling.
- **Fixed double-spend tests**: Modified output selection to pick the
  largest decomposed output, avoiding underflow on fee subtraction.
- **Disabled legacy-incompatible tests**: `gen_block_invalid_binary_format`
  (hours-long), `gen_block_invalid_nonce`, `gen_block_late_v1_coinbase_tx`,
  `gen_uint_overflow_1`, `gen_block_reward`,
  `gen_bpp_tx_invalid_before_fork`, `gen_bpp_tx_invalid_clsag_type`,
  `gen_ring_signature_big`. These rely on pre-RCT economics, legacy
  fork transitions, or are prohibitively slow.
- **All 79 core_tests pass with 0 failures.**

### Test suite cleanup for Shekyl HF1

- **Removed 96 dead Borromean ringct tests**: All tests in
  `tests/unit_tests/ringct.cpp` that exercised legacy Borromean range
  proofs were removed. Shekyl HF1 rejects Borromean proofs at the
  `genRctSimple` level. Retained 9 non-Borromean tests (CLSAG, HPow2,
  d2h, d2b, key_ostream, zeroCommit, H, mul8).
- **Updated transaction construction helpers to Bulletproofs+**: The
  `test::make_transaction` helper (used by JSON serialization and ZMQ
  tests) now constructs transactions with
  `{ RangeProofPaddedBulletproof, 4 }` (BP+/CLSAG) instead of the
  removed Borromean or unsupported BP v2 configs. Removed the obsolete
  `bulletproof` parameter. Consolidated three JSON serialization tests
  (RegularTransaction, RingctTransaction, BulletproofTransaction) into
  one `BulletproofPlusTransaction` test. Fixes all 8 zmq_pub/zmq_server
  test failures.
- **Updated serialization round-trip test to BP+**: Changed
  `Serialization.serializes_ringct_types` from `bp_version 2` (throws
  "Unsupported BP version") to `bp_version 4` (Bulletproofs+). Updated
  assertions from MGs to CLSAGs and from `bulletproofs` to
  `bulletproofs_plus`.
- **Removed legacy Monero-era core/perf test executions**: Stopped running
  deprecated Borromean/pre-RCT/fork-transition test generators in
  `core_tests` and removed Borromean/MLSAG/range-proof performance test
  invocations and defaults, so CI validates HF1-era behavior only.
- **Hardened block-weight test contract for HF1 semantics**: `block_weight`
  comparison now enforces deterministic `H/BW/LTBW` parity and EMBW floor
  invariants instead of byte-identical legacy model output, preventing
  false failures from non-consensus median implementation details.
- **Fixed block_reward test expected values**: Updated emission curve
  expectations to match Shekyl's `EMISSION_SPEED_FACTOR = 21` (120s
  blocks) and per-block tail floor of
  `FINAL_SUBSIDY_PER_MINUTE * target_minutes`.
- **Rewrote mining_parity release multiplier test**: Replaced legacy
  pre-Shekyl-NG equality assertion (which tested a non-existent version
  0) with a test that verifies the release multiplier correctly scales
  rewards above and below the tx volume baseline.
- **Fixed Ubuntu 24.04 CI test runner**: Replaced `pip install` with
  `apt install python3-*` packages to comply with PEP 668
  (externally-managed-environment).

### 🐛 Fixed

- **macOS cross-compilation (depends CI)**: Fixed multiple build failures
  for Cross-Mac x86_64 and Cross-Mac aarch64 targets:
  - Raised macOS minimum deployment target from 10.8 (Mountain Lion, 2012)
    to 10.15 (Catalina, 2019) to enable `std::filesystem` support in the
    cross-compiled libc++.
  - Fixed Boost discovery in depends builds by setting `Boost_NO_BOOST_CMAKE`
    and forcing MODULE mode, preventing `BoostConfig.cmake` variant-check
    failures on cross-compiled Darwin libraries.
  - Made `boost_locale` a conditional dependency (Windows only), since it
    is only used within `#ifdef WIN32` blocks and was unavailable for
    Darwin cross-builds.
  - Added per-target `CC_<triple>/AR_<triple>/CFLAGS_<triple>` environment
    variables in `BuildRust.cmake` so the `ring` crate can locate the
    cross-compiler for C/assembly code.
  - Used system clang (instead of the depends-bundled Clang 9) for Rust
    crate C compilation on Darwin, since `ring` 0.17 requires clang
    features unavailable in Clang 9 (macOS 11 version strings,
    `-fno-semantic-interposition`).
  - Guarded `-fno-semantic-interposition` behind `check_c_compiler_flag()`
    so it is only added when the compiler supports it (Clang 9 does not).
  - Fixed OSX SDK cache key in `depends.yml` to include the SDK version
    and skip the cache step for non-macOS builds.

- **FreeBSD cross-compilation (depends CI)**: Fixed multiple build failures
  for the x86_64 FreeBSD target:
  - Switched Boost's b2 toolset from `gcc` to `clang` for FreeBSD, fixing
    C++ standard library header resolution (`<cstddef>` not found).
  - Embedded `-stdlib=libc++` in the FreeBSD clang++ wrapper script so all
    depends packages automatically use the correct C++ standard library,
    regardless of whether their own `$(package)_cxxflags` overrides the
    host flags (previously broke zeromq, sodium, and other packages).
  - Fixed compiler wrapper argument quoting: replaced the broken
    `echo "...$$$$""@"` pattern with `printf '..."$$$$@"'` so `"$@"`
    passes through correctly to the generated wrapper, preventing argument
    mangling for flags containing quotes (e.g. `-DPACKAGE_VERSION="1.0.20"`).
  - Added `-D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION` to both
    Boost's FreeBSD cxxflags and the CMake toolchain, restoring
    `std::unary_function` compatibility needed by Boost 1.74's
    `container_hash/hash.hpp` under FreeBSD's strict C++17 libc++.
  - Removed the unsupported `no-devcrypto` option from OpenSSL's FreeBSD
    configure flags (the devcrypto engine was removed in OpenSSL 3.0).
  - Added `threadapi=pthread runtime-link=shared` to Boost's FreeBSD
    config options for correct threading and linking behavior.

- **Linux static release build (libudev linking)**: Added `libudev-dev` to
  the `release-tagged.yml` CI package list. Static `libusb-1.0.a` and
  `libhidapi-libusb.a` depend on `libudev` for USB hotplug support;
  without the dev package installed, `find_library(udev)` failed and the
  final link produced undefined `udev_*` references, preventing the
  "Publish GitHub Release" step from running.
- **Win64 build failure (ICU generator expression)**: Replaced broken CMake
  generator expressions `$<$<BOOL:${WIN32}>:${ICU_LIBRARIES}>` with
  `if(WIN32)` blocks in `simplewallet`, `wallet_api`, and
  `libwallet_api_tests` CMakeLists. Generator expressions cannot contain
  semicolon-separated lists; the old pattern passed literal fragments like
  `$<1:icuio` to the linker on MinGW cross-compilation.
- **Linux static build (libunbound linking)**: Fixed `FindUnbound.cmake`
  scoping bug where `list(APPEND UNBOUND_LIBRARIES ...)` created a local
  variable shadowing the `find_library` cache entry. The transitive static
  deps (libevent, libnettle, libhogweed, libgmp) were silently dropped,
  causing undefined reference errors in `release-static-linux-x86_64`
  builds.
- **JSON serialization of v3 (PQC) transactions**: Added missing
  `pqc_auth` field to the RapidJSON `toJsonValue`/`fromJsonValue`
  roundtrip for `cryptonote::transaction`. V3 transactions created
  under `HF_VERSION_SHEKYL_NG` include a `pqc_authentication`
  envelope; without JSON support the field was silently dropped,
  causing `get_transaction_hash` to fail with "Inconsistent
  transaction prefix, unprunable and blob sizes" after a JSON
  roundtrip. Fixes the `JsonSerialization.BulletproofPlusTransaction`
  unit test failure.

### GUI Wallet

- New project: Shekyl GUI Wallet (`shekyl-gui-wallet`) at
  [Shekyl-Foundation/shekyl-gui-wallet](https://github.com/Shekyl-Foundation/shekyl-gui-wallet).
  Built with Tauri 2 (Rust backend) + Vite + React 19 + TypeScript + Tailwind CSS 4.
  Initial scaffold includes 6 pages (Dashboard, Send, Receive, Staking,
  Transactions, Settings), stub Tauri commands, Shekyl gold/purple design system,
  and verified production builds for Linux (.deb, .rpm, .AppImage).
  Phase 2 will add the C++ FFI bridge to `wallet2_api.h` for real wallet operations.
- Added testing infrastructure: Vitest + React Testing Library for frontend
  (20 tests across 6 suites), cargo test for Rust backend (10 tests), with
  Tauri IPC mocking for isolated component testing.
- Added CI/CD via GitHub Actions: `ci.yml` runs ESLint, TypeScript type-check,
  Vitest, Rustfmt, Clippy, and cargo test on every PR; `release.yml` builds
  multi-platform binaries (Linux x64, Windows x64, macOS ARM64 + Intel) via
  `tauri-action` and creates draft GitHub releases.

### Consensus timing alignment (HF1)

- Fixed remaining runtime paths that still derived timing from legacy `DIFFICULTY_TARGET_V1` (`60s`) so active Shekyl HF1 behavior consistently uses `DIFFICULTY_TARGET_V2` (`120s`) for difficulty target selection, block reward minute-scaling, unlock-time leeway checks, sync ETA reporting, and wallet lock-time display.
- Updated `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` to mark the 120s block-time drift item as resolved (`code_fix_required` completed).

### 📚 Documentation

- Updated `docs/V3_ROLLOUT.md` to reflect HF1 (genesis) activation instead
  of the stale HF17 references. Added v3-first test strategy section.
- Updated `docs/POST_QUANTUM_CRYPTOGRAPHY.md` scheme_id status table and
  deferred-items section from HF17 to HF1.
- Updated `docs/PQC_MULTISIG.md` V3 signature list heading from HF17 to HF1.
- Updated `docs/STAKER_REWARD_DISBURSEMENT.md` to reference HF1 activation.
- Updated `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` HF naming drift label
  from `doc_correction` to resolved.
- Added `core_tests` section to `docs/COMPILING_DEBUGGING_TESTING.md`
  documenting the v3-from-genesis test approach and how to run/filter tests.

### Genesis initialization compatibility

- Regenerated `GENESIS_TX` for mainnet, testnet, and stagenet to modern coinbase format (`tx.version = 2`) with tagged outputs.
- Removed all legacy genesis compatibility exceptions and enforced strict coinbase version checks (`tx.version > 1`) across all network types, including `FAKECHAIN`.
- Fixed genesis reward validation to accept the hardcoded `GENESIS_TX` amount at `height == 0` while leaving post-genesis reward accounting unchanged.
- Fixed startup edge case where long-term weight median calculations could evaluate with zero historical blocks during genesis initialization (`count == 0`), causing daemon boot failure on empty data dirs.
- Updated genesis-construction helper (`build_genesis_coinbase_from_destinations`) to emit `tx.version = 2` with view-tagged outputs for current HF1 expectations.
- Added canonical root build command `make genesis-builder` (using the main release build dir with `GENESIS_TOOL_SRC_DIR`) to avoid split/ambiguous genesis-builder binaries across multiple build trees.

### Testnet economy readiness checks

- Added `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` to track design-vs-code status for economy testnet rehearsal with explicit drift tags (`doc_correction`, `code_fix_required`, `needs_decision`).
- Added `scripts/check_testnet_genesis_consensus.py` to verify multi-node testnet tuple consistency (`height 0 block hash`, `miner tx hash`, `tx hex`) and optional economy field presence in `get_info`.
- Added Rust parity/invariant tests:
  - `shekyl-economics-sim`: validates `SimParams::default()` against `config/economics_params.json`.
  - `shekyl-economics`: added release monotonicity, burn bounds, and emission-share monotonicity tests.
  - `shekyl-ffi`: added direct FFI-vs-Rust consistency tests for burn pct and emission share.
- Added functional RPC test `tests/functional_tests/economy_info.py` and included it in `functional_tests_rpc.py` default test list to assert required economy fields are exposed by `get_info`.
- Corrected documentation errors without changing design intent:
  - Clarified `DESIGN_CONCEPTS.md` Section 2 as historical baseline.
  - Removed duplicate heading in `GENESIS_TRANSPARENCY.md`.
  - Linked `RELEASE_CHECKLIST.md` testnet section to the rehearsal runbook/checklist and deterministic tuple check command.

### BREAKING: Second-pass rebrand (wallet, URI, serialization)

- **URI scheme**: Wallet URI generation and parsing now use `shekyl:` only.
  The legacy `monero:` scheme is no longer accepted. QR codes and payment
  links generated by previous builds will fail to parse. Regenerate all
  payment URIs before upgrading wallets.
- **Wallet/export/cache magic strings**: All file-format magic prefixes have
  been rewritten from `Monero` to `Shekyl`:
  - `UNSIGNED_TX_PREFIX` → `"Shekyl unsigned tx set\005"`
  - `SIGNED_TX_PREFIX` → `"Shekyl signed tx set\005"`
  - `MULTISIG_UNSIGNED_TX_PREFIX` → `"Shekyl multisig unsigned tx set\001"`
  - `KEY_IMAGE_EXPORT_FILE_MAGIC` → `"Shekyl key image export\003"`
  - `MULTISIG_EXPORT_FILE_MAGIC` → `"Shekyl multisig export\001"`
  - `OUTPUT_EXPORT_FILE_MAGIC` → `"Shekyl output export\004"`
  - `ASCII_OUTPUT_MAGIC` → `"ShekylAsciiDataV1"`
  - Wallet cache magic → `"shekyl wallet cache"`
  Old wallet caches, exported key images, multisig exports, signed/unsigned
  tx sets, and output exports are **incompatible** and must be re-exported
  after upgrading.
- **Message signing domain**: `HASH_KEY_MESSAGE_SIGNING` changed from
  `"MoneroMessageSignature"` to `"ShekylMessageSignature"`. Messages signed
  with the old domain separator will fail verification.
- **i18n domain**: Translation catalogue domain changed from `"monero"` to
  `"shekyl"`.
- **Daemon stdout redirect**: Daemonized output file changed from
  `bitmonero.daemon.stdout.stderr` to `shekyl.daemon.stdout.stderr`.
- **Log file names**: All blockchain utility log files renamed from
  `monero-blockchain-*` to `shekyl-blockchain-*`.
- **DNS seed/checkpoint domains**: Replaced `moneroseeds.*` and
  `moneropulse.*` lookups with 5-domain consensus set: `shekyl.org`,
  `shekyl.net`, `shekyl.com`, `shekyl.biz`, `shekyl.io`. Majority
  threshold is 3 of 5. See `shekyl-dev/docs/DNS_CONFIG.md` for the full
  infrastructure reference.
- **Update check**: Software name comparison for macOS `.dmg` extension
  switched from `monero-gui` to `shekyl-gui`.
- **Hardware wallet**: Ledger app error message now references "Shekyl Ledger
  App" instead of "Monero Ledger App". Trezor protobuf namespaces are
  unchanged (third-party protocol dependency).
- **Intentionally preserved**: Trezor/Ledger protobuf includes and protocol
  namespaces (`hw.trezor.messages.monero.*`), Esperanto mnemonic word
  `"monero"` (means "money"), academic paper citations, copyright headers,
  `MONERO_DEFAULT_LOG_CATEGORY` build-internal macros, and `MakeCryptoOps.py`
  build artifacts.

#### Operator migration checklist

1. Delete old wallet cache files (`.keys` files are unaffected).
2. Re-export any key-image, multisig, or output export files.
3. Re-export and re-sign any unsigned/signed transaction sets.
4. Regenerate all `monero:` QR codes/payment URIs as `shekyl:` URIs.
5. Update any scripts or integrations that parse URI scheme or file magic.
6. Verify message signatures were not created with the old signing domain.
7. Update log rotation configs if they reference `monero-blockchain-*` paths.
8. Update DNS infrastructure to serve records under all 5 TLDs (`.org`,
   `.net`, `.com`, `.biz`, `.io`). See `shekyl-dev/docs/DNS_CONFIG.md`.

### Dead Monero legacy code removal

- **Dead HF branch cleanup**: Collapsed all always-true / always-false hard fork
  version branches across `blockchain.cpp` (~25 sites), `wallet2.cpp` (~22 sites),
  `cryptonote_basic_impl.cpp` (2 sites), and `cryptonote_core.cpp` (2 sites).
  Since all `HF_VERSION_*` constants are 1, every `hf_version >= HF_VERSION_*`
  was always true and every `hf_version < HF_VERSION_*` was always false.
  Collapsed fee algorithms, ring size ladders, tx version ladders, difficulty
  target selection, sync block size selection, BP/CLSAG/BP+ gating, dynamic
  fee scaling, long-term block weight calculations, and `use_fork_rules()` call
  sites. Removed ~500-800 lines of dead conditional logic.

- **Dropped v1 transaction support entirely**:
  - **Consensus**: `check_tx_outputs` now rejects `tx.version == 1` outright.
    `check_tx_inputs` sets `min_tx_version = 2` unconditionally; unmixable
    output counting and ring-size exemptions removed. v1 ring signature
    verification code and threaded v1 signature checking removed from
    `check_tx_inputs`. `expand_transaction_2` only handles CLSAG and
    BulletproofPlus; old RCTTypeFull/Simple/Bulletproof/Bulletproof2 branches
    removed.
  - **RingCT** (`rctSigs.cpp`/`.h`): Removed ~770 lines of dead crypto code:
    `genBorromean`, `verifyBorromean`, `MLSAG_Gen`, `MLSAG_Ver`, `proveRange`,
    `verRange`, `proveRctMG`, `proveRctMGSimple`, `verRctMG`, `verRctMGSimple`,
    `populateFromBlockchain`, `genRct` (both overloads), `verRct`, `decodeRct`
    (both overloads). `genRctSimple`, `verRctSemanticsSimple`,
    `verRctNonSemanticsSimple`, and `decodeRctSimple` only accept
    `RCTTypeCLSAG` and `RCTTypeBulletproofPlus`. Header reduced from 144 to
    87 lines.
  - **Transaction construction** (`cryptonote_tx_utils.cpp`): Removed v1
    ring signature generation block and non-simple RCT construction
    (`genRct`). All transactions now use `genRctSimple` (CLSAG path).
  - **Tx verification utils**: Removed `RCTTypeSimple`, `RCTTypeFull`,
    `RCTTypeBulletproof`, `RCTTypeBulletproof2` from batch semantics
    verification.
  - **Test fixups**: Updated all test files under `tests/` to match the
    removed RCT primitives. Stubbed performance benchmarks for MLSAG
    (`rct_mlsag.h`, `sig_mlsag.h`) and Borromean range proofs
    (`range_proof.h`). Replaced `verRct` with `verRctNonSemanticsSimple`
    in `check_tx_signature.h`. Removed `decodeRct` else-branches from
    `rct.cpp`, `rct2.cpp`, `bulletproofs.cpp`, `bulletproof_plus.cpp`.
    In `unit_tests/ringct.cpp`: removed Borromean, MLSAG, and
    RCTTypeFull-only tests; rewrote `make_sample_rct_sig` to use
    `genRctSimple`; replaced all `verRct` calls with `verRctSimple`.

- **Wallet v1 cleanup**: Removed unmixable sweep functions, v1 fee/amount
  paths, v1 coinbase optimization, dead non-RCT creation branches, and
  replaced `RangeProofBorromean` defaults with `RangeProofPaddedBulletproof`.
  `sweep_dust` RPC returns error; `createSweepUnmixableTransaction` API
  returns empty result with error status.

- **Trezor Shekyl rebrand**: Renamed all include guard macros from
  `MONERO_*_H` to `SHEKYL_*_H` in 8 `device_trezor/` headers. Updated
  derivation path comment and HTTP Origin URL. Protobuf message types and
  wire protocol identifiers intentionally preserved (must match Trezor
  firmware definitions).

### Epee Phase 1: Rust replacement for security-critical primitives

- **SSL certificate generation migrated to Rust (`rcgen`)**: Replaced the
  deprecated OpenSSL RSA/EC_KEY certificate generation in `net_ssl.cpp` with
  Rust's `rcgen` crate (ECDSA P-256) via FFI. Eliminates all `RSA_new`,
  `RSA_generate_key_ex`, `EC_KEY_new`, `EC_KEY_generate_key`, and other
  OpenSSL 3.0-deprecated API calls. The `create_rsa_ssl_certificate` and
  `create_ec_ssl_certificate` functions are replaced by a single
  `create_ssl_certificate` that delegates to `shekyl_generate_ssl_certificate`
  in the Rust FFI, returning PEM-encoded key+cert for loading into OpenSSL's
  SSL_CTX via non-deprecated BIO APIs.
- **Post-quantum hybrid key exchange enabled**: TLS context configuration now
  prefers `X25519MLKEM768` (FIPS 203 ML-KEM-768 hybrid) key exchange groups,
  falling back to classical `X25519:P-256:P-384` when the OpenSSL build lacks
  PQ support. Also added explicit TLS 1.3 ciphersuite configuration. Removed
  deprecated `SSL_CTX_set_ecdh_auto` call.
- **Secure memory wiping migrated to Rust (`zeroize`)**: Replaced the
  platform-specific `memwipe.c` implementation (memset_s / explicit_bzero /
  compiler-barrier fallback) with a single call to the Rust `zeroize` crate
  via `shekyl_memwipe` FFI. The `zeroize` crate uses `write_volatile` which
  is guaranteed not to be optimized away, replacing the fragile compiler
  barrier tricks.
- **Memory locking migrated to Rust (`libc`)**: Replaced the GNUC-only
  `mlock`/`munlock`/`sysconf` calls in `mlocker.cpp` with Rust FFI functions
  (`shekyl_mlock`, `shekyl_munlock`, `shekyl_page_size`) backed by the `libc`
  crate. Adds Windows `VirtualLock`/`VirtualUnlock` support that was
  previously missing (`#warning Missing implementation`). The `mlocked<T>` and
  `scrubbed<T>` C++ template wrappers are preserved unchanged.
- **New Rust FFI dependencies**: Added `rcgen = "0.14"`, `zeroize = "1"`,
  `libc = "0.2"` to `shekyl-ffi/Cargo.toml`.
- **C-compatible FFI header**: Added `src/shekyl/shekyl_secure_mem.h` with
  C-linkage declarations for the secure memory primitives, usable from both
  C (`memwipe.c`) and C++ (`mlocker.cpp`) translation units.
- **CMake wiring**: `epee` library now links `${SHEKYL_FFI_LINK_LIBS}` and
  includes `${CMAKE_SOURCE_DIR}/src` for the FFI headers.

### Build fixes

- **Boost CONFIG-mode compatibility shim**: When Boost is found via cmake
  CONFIG mode (Boost 1.85+), old-style `${Boost_XXX_LIBRARY}` variables may
  resolve to versioned `.so` paths that don't exist on rolling-release distros
  (e.g. Arch Linux with Boost 1.90). Added a shim in the root `CMakeLists.txt`
  that remaps all `Boost_*_LIBRARY` variables to `Boost::*` imported targets
  when CONFIG mode is active. Fixes linker failures on Arch.
- **Removed duplicate `parse_amount` test**: Two identical
  `TEST_pos(18446744073709551615, ...)` entries in
  `tests/unit_tests/parse_amount.cpp` caused a redefinition error on macOS
  Clang. Removed the duplicate.
- **Boost CONFIG-mode validation**: Added a cmake-configure-time check that
  verifies Boost imported-target `IMPORTED_LOCATION` files exist on disk.
  Gives a clear `FATAL_ERROR` with remediation steps instead of a cryptic
  linker failure minutes into the build.
- **Arch Linux CI**: Added `boost-libs` to the Arch pacman install to
  provide shared `.so` files alongside the `boost` headers/cmake-config
  package.
- **Ubuntu 24.04 test matrix**: Added Ubuntu 24.04 to the `test-ubuntu`
  CI matrix (previously only 22.04 was tested).

### Depends system updates

- **FreeBSD sysroot updated to 14.4-RELEASE**: The cross-compilation
  sysroot was stuck at FreeBSD 11.3 (EOL Sept 2021), whose `base.txz`
  had been removed from FreeBSD mirrors (404). Updated to 14.4-RELEASE
  (March 2026), updated SHA256 hash, and fixed clang wrapper scripts
  from clang-8 to clang-14 to match `hosts/freebsd.mk`. Added
  `-stdlib=libc++` to CXXFLAGS and LDFLAGS since FreeBSD uses libc++
  and the Ubuntu host's clang-14 defaults to libstdc++. Also added
  `libc++-14-dev` and `libc++abi-14-dev` to CI packages for the FreeBSD
  cross-build so the host compiler can find libc++ headers when
  `-stdlib=libc++` is specified.
- **Boost: skip CONFIG mode for depends builds**: The depends-built Boost
  1.74.0 installs CMake config files whose variant detection fails for
  darwin cross-builds (`boost_locale` reports "No suitable build variant").
  `find_package(Boost ... CONFIG)` is now skipped when `DEPENDS` is true
  (set by the depends toolchain), falling back to the more robust MODULE
  mode (`FindBoost.cmake`).
- **OpenSSL: disabled `devcrypto` engine for FreeBSD**: Added
  `no-devcrypto` to FreeBSD OpenSSL configure options. The `/dev/crypto`
  engine requires the `crypto/cryptodev.h` kernel header which is not
  available in a cross-compilation sysroot.
- **libsodium updated to 1.0.20**: The 1.0.18 tarball was removed from
  `download.libsodium.org` (404). Updated to 1.0.20 with new SHA256 hash.
  Removed the 1.0.18-specific patches (`fix-whitespace.patch`,
  `disable-glibc-getrandom-getentropy.patch`) which no longer apply.

### Warning cleanup and dead code removal

- **Removed dead fork helpers**: Deleted unused `get_bulletproof_fork()`,
  `get_bulletproof_plus_fork()`, and `get_clsag_fork()` from `wallet2.cpp`.
  These Monero-era version ladders had no call sites; Shekyl activates all
  features from HF1.
- **Removed dead variable**: Deleted unused `bool refreshed` in
  `wallet2::refresh()`.
- **Removed legacy `result_type` typedefs**: Deleted `using result_type = void`
  from `add_input` and `add_output` visitor structs in `json_object.cpp`. These
  were required by `boost::static_visitor` but are unused by `std::visit`.
- **Fixed uninitialized-variable warning**: Zero-initialized `local_blocks_to_unlock`
  and `local_time_to_unlock` in `wallet2::unlocked_balance_all()`.
- **Fixed aliasing cast in wallet serialization**: Replaced C-style cast of
  `m_account_tags` from `pair<serializable_map, vector>` to `pair<map, vector>&`
  with direct `.parent()` accessor, eliminating formal undefined behavior.
- **Suppressed epee warnings**: Added targeted `#pragma GCC diagnostic` guards
  for `-Wclass-memaccess` (memcpy into `mlocked<scrubbed<>>` in
  `keyvalue_serialization_overloads.h`) and `-Wstring-compare` (type_info
  comparisons in `portable_storage.h`).
- **Renamed test target**: `monero-wallet-crypto-bench` renamed to
  `shekyl-wallet-crypto-bench`.
- **Trezor Protobuf fixes**: Added `std::string()` wrapping for
  `GetDescriptor()->name()` calls in `messages_map.cpp/.hpp` to handle
  Protobuf 22+ returning `absl::string_view`/`std::string_view`. Added
  missing `<cstdint>` include to `exceptions.hpp`.

### Rust crypto infrastructure

- **New `shekyl-crypto-hash` crate**: Implements `cn_fast_hash` (Keccak-256
  with original padding, not SHA3) and `tree_hash` (Merkle tree) in Rust
  using `tiny-keccak`. Both functions produce byte-identical output to the
  C implementations in `src/crypto/hash.c` and `src/crypto/tree-hash.c`.
- **FFI exports**: `shekyl_cn_fast_hash` and `shekyl_tree_hash` exposed
  through `shekyl-ffi` with C-ABI declarations in `shekyl_ffi.h`. The C++
  side can now call Rust hashing alongside or instead of the C path.
- **Rust-preferred development rule**: Added `.cursor/rules/rust-preferred.mdc`
  establishing policy for gradual C++ to Rust migration: new modules in Rust,
  crypto primitives via RustCrypto crates, computational extraction to Rust
  behind FFI when modifying existing C++ modules.

### Hardfork reboot and testnet wallet readiness

- **Hardfork schedule rebooted**: All `HF_VERSION_*` constants collapsed to 1.
  The chain starts with all features active from genesis -- no legacy migration
  gates. Hardfork tables reduced to single-entry `{ 1, 1, 0, timestamp }` for
  all three networks (mainnet, testnet, stagenet).
- Removed all raw numeric HF version gates (`hf_version <= 3`, `>= 7`, `< 8`,
  `> 8`, etc.) from consensus and transaction construction code, replacing them
  with named `HF_VERSION_*` constants. Legacy Monero-era transition logic
  (borromean proofs, bulletproofs v1, grandfathered txs) removed.
- Coinbase transactions always v2 RCT with single output, zero dust threshold.
- **Staked outputs excluded from spendable balance**: `is_transfer_unlocked()`
  now returns false for staked outputs, preventing them from being selected
  during normal transfers. `balance_per_subaddress` and
  `unlocked_balance_per_subaddress` skip staked outputs.
- **Unstake transaction fixed**: `create_unstake_transaction` now passes matured
  staked output indices directly to `create_transactions_from`, properly using
  the actual staked UTXOs as transaction inputs with standard ring signatures.
- **Claim reward validation fixed**: `check_stake_claim_input` now looks up the
  real staked output from the blockchain DB to get the actual amount and tier,
  replacing the hardcoded `shekyl_stake_weight(0, 0)` placeholder.
- **New daemon RPC `estimate_claim_reward`**: computes per-output reward
  server-side using the accrual database, returning reward amount, tier, and
  staked amount. Wallet `estimate_claimable_reward` now calls this RPC instead
  of returning a hardcoded zero.
- **CLI improvements**: `balance` command now shows staked balance alongside
  liquid and unlocked balances. New `staking_info` command shows wallet staking
  overview (locked/matured output counts with tier and remaining lock blocks).
  `stake`, `unstake`, and `claim_rewards` commands now include daemon
  connectivity guards.
- **Wallet RPC fixes**: `unstake` response changed from single `tx_hash` to
  `tx_hash_list` array to support multi-transaction unstaking. `stake` request
  now accepts `account_index` parameter. New `get_staked_balance` RPC returns
  staked balance with locked/matured output counts.

### Post-quantum cryptography

- **Phase 4 wallet/core PQC wiring completed**: all v3 transaction construction
  paths now include hybrid Ed25519 + ML-DSA-65 signing via `pqc_auth`. Fixed
  `create_claim_transaction` (staking reward claims) which previously built v3
  transactions without PQC authentication, causing consensus rejection.
- PQC verification enforced in both mempool acceptance and block validation for
  all non-coinbase v3 transactions.
- Multisig wallets intentionally restricted to v2 transactions (no PQC); the
  PQC secret key is cleared on multisig creation with a documented design note.
- Aligned `POST_QUANTUM_CRYPTOGRAPHY.md` field naming: `hybrid_ownership_material`
  renamed to `hybrid_public_key` to match the canonical code implementation.
- Added three negative PQC test vectors (`docs/PQC_TEST_VECTOR_002–004`) covering
  tampered ownership material, wrong scheme_id, and oversized/truncated signature
  blobs. Each vector is generated and verified by integration tests in
  `rust/shekyl-crypto-pq/tests/negative_vectors.rs`.
- Reconciled `POST_QUANTUM_CRYPTOGRAPHY.md` Open Items: resolved Rust crate
  selection, `RctSigningBody` layout, ownership binding, and max tx size;
  only `scheme_id` registry extension remains open.
- Added tentative V4 PQC Privacy Roadmap to `POST_QUANTUM_CRYPTOGRAPHY.md`
  with four phases (V4-A Research, V4-B Prototype, V4-C Testnet,
  V4-D Activation) and explicit KEM composition decision milestone
  (`X25519 + ML-KEM-768` via `HKDF-SHA-512`).
- Added payload limit guidance section to `V3_ROLLOUT.md` with recommended
  minimum mempool/ZMQ/relay buffer sizes for post-PQC transactions.

### Economics and simulation

- Added `rust/shekyl-economics-sim` workspace crate: reproducible 8-scenario
  simulation harness driven from `config/economics_params.json`. Scenarios
  cover baseline, boom-bust, sustained growth, stuffing attack, stake
  concentration, mass unstaking, chain bootstrap, and late-chain tail state.
  Results archived in `docs/economics_sim_results.json`.
- Provisionally locked `tx_baseline` (50) and `FINAL_SUBSIDY_PER_MINUTE`
  (300,000,000) in `DESIGN_CONCEPTS.md` after simulation validation; pending
  final testnet confirmation.
- Wired live chain-health RPC fields in `get_info`: `release_multiplier` now
  computed from rolling `tx_volume_avg`, `burn_pct` from current chain state,
  `total_burned` persisted in LMDB and accumulated per block.
- Wired `total_staked` in `get_staking_info` via new
  `Blockchain::get_total_staked()` accessor backed by existing stake cache.
- Added `total_burned` LMDB persistence: `set_total_burned`/`get_total_burned`
  on `BlockchainDB`, with rollback support via extended `staker_accrual_record`
  (`actually_destroyed` field).

### Privacy and anonymity networks

- Updated `ANONYMITY_NETWORKS.md` with measured v3 payload impact analysis
  (cell/fragment counts for Tor and I2P), known leak vectors vs mitigations
  matrix, and recommended pre-mainnet testing checklist.
- Extended `LEVIN_PROTOCOL.md` wire inventory with per-command PQC size
  impact, anonymity sensitivity ratings, and a summary table covering all
  P2P and Cryptonote protocol commands.
- Added privacy considerations section to `STAKER_REWARD_DISBURSEMENT.md`
  covering claim timing, amount correlation, and staked output visibility.
- Added reward-driven privacy/mixing research appendix to
  `DESIGN_CONCEPTS.md` evaluating random maturation delay, claim batching,
  and reward output shaping with adversarial analysis and go/no-go criteria.

### C++17 and Boost migration

- **C++17 standard bump**: `CMAKE_CXX_STANDARD` changed from 14 to 17 in both
  the main `CMakeLists.txt` and the macOS cross-compilation toolchain
  (`contrib/depends/toolchain.cmake.in`). This unblocks `std::filesystem`,
  `std::optional`, and other modern C++ features. Upstream Monero cherry-picks
  that required C++14-to-C++17 back-ports now compile without shims.
- **`boost::optional` → `std::optional` (complete)**:
  Migrated ~486 use sites across ~93 files in `src/`, `contrib/epee/`, and
  `tests/`. Replaced `boost::optional<T>` with `std::optional<T>`,
  `boost::none` with `std::nullopt`, `boost::make_optional` with
  `std::make_optional`, and `.get()` accessor calls with `*` / `->`.
  Added a `std::optional` Boost.Serialization adapter in
  `cryptonote_boost_serialization.h` so PQC auth fields serialize correctly.
  Replaced `BOOST_STATIC_ASSERT`/`boost::is_base_of` with
  `static_assert`/`std::is_base_of` in Trezor `messages_map.hpp`.
- **`boost::filesystem` → `std::filesystem` (wallet/RPC layer)**:
  Migrated `wallet_manager.cpp`, `wallet_rpc_server.cpp`,
  `core_rpc_server.cpp`, and `wallet_args.cpp` from `boost::filesystem` to
  `std::filesystem`. Combined with the earlier utility-file migration, this
  covers all filesystem usage outside of `net_ssl.cpp` (epee, deferred due to
  permissions API coupling).
- **`boost::format` removal (wallet/RPC layer)**:
  Replaced all `boost::format` calls in `wallet2.cpp` (4), `wallet_rpc_server.cpp`
  (8), and `wallet_args.cpp` (1) with stream output or string concatenation.
  `simplewallet.cpp` (106 uses, i18n-sensitive) remains deferred.
- **`boost::chrono`/`boost::this_thread` in daemonizer**: Replaced with
  `std::chrono`/`std::this_thread` in `windows_service.cpp` (PR #9544 equivalent).
- **Medium-effort Boost removals (completed earlier)**:
  - `boost::algorithm::string` (trim, to_lower, iequals, join) replaced with
    `tools::string_util` helpers in `src/common/string_util.h`.
  - `boost::format` replaced with `snprintf`, stream output, or string
    concatenation in `util.cpp`, `message_store.cpp`, `gen_ssl_cert.cpp`,
    `gen_multisig.cpp`.
  - `boost::regex` replaced with `std::regex` in `simplewallet.cpp` and
    `wallet_manager.cpp`.
  - `boost::mutex`, `boost::lock_guard`, `boost::unique_lock`, and
    `boost::condition_variable` replaced with `std::mutex`, `std::lock_guard`,
    `std::unique_lock`, and `std::condition_variable` in `util.h`, `util.cpp`,
    `threadpool.h`, `threadpool.cpp`, and `rpc_payment.h`/`rpc_payment.cpp`.
  - `boost::thread::hardware_concurrency()` replaced with
    `std::thread::hardware_concurrency()`.
- **Filesystem migration (utility files, completed earlier)**:
  - `boost::filesystem` replaced with `std::filesystem` in
    `blockchain_export.cpp`, `blockchain_import.cpp`, `cn_deserialize.cpp`,
    `util.cpp`, `bootstrap_file.h`/`.cpp`, and `blocksdat_file.h`/`.cpp`.
  - Eliminated `BOOST_VERSION` preprocessor conditional in `copy_file()`.
- **Upstream Monero cherry-pick verification**: Confirmed PRs #9628 (ASIO
  `io_service` → `io_context`), #6690 (serialization overhaul), and #9544
  (daemonizer chrono/thread) are already absorbed in our tree.
- **`boost::variant` → `std::variant` (complete)**:
  Full migration from `boost::variant` to C++17 `std::variant` across the
  entire codebase (~100+ replacements in ~40 files):
  - **Serialization layer rewrite** (`serialization/variant.h`): Replaced
    Boost.MPL type-list iteration with C++17 `if constexpr` recursion for
    deserialization and `std::visit` lambda for serialization. Removed all
    `boost::mpl`, `boost::static_visitor`, and `boost::apply_visitor` usage.
  - **Archive headers**: Replaced `boost::mpl::bool_<B>` with
    `std::bool_constant<B>` in `binary_archive.h`, `json_archive.h`, and
    `serialization.h`. Replaced `boost::true_type`/`false_type` and
    `boost::is_integral` with `std` equivalents.
  - **Core typedefs**: Changed `txin_v`, `txout_target_v`, `tx_extra_field`,
    `transfer_view::block`, and Trezor `rsig_v` from `boost::variant` to
    `std::variant`.
  - **Boost.Serialization shim**: Added a local ~45-line `std::variant`
    serialization adapter in `cryptonote_boost_serialization.h` (save/load
    with index + payload, wire-compatible with old `boost::variant` format).
    Removed dependency on `<boost/serialization/variant.hpp>`.
  - **Mechanical replacements** across all `src/` and `tests/` files:
    `boost::get<T>(v)` → `std::get<T>(v)`,
    `boost::get<T>(&v)` → `std::get_if<T>(&v)`,
    `v.type() == typeid(T)` → `std::holds_alternative<T>(v)`,
    `v.which()` → `v.index()`,
    `boost::apply_visitor(vis, v)` → `std::visit(vis, v)`.
  - **P2P layer**: Updated `net_peerlist_boost_serialization.h` to use
    `std::false_type`/`std::true_type` instead of `boost::mpl` equivalents.
  - `tests/unit_tests/net.cpp` retains `boost::get<N>` for `boost::tuple`
    access via `boost::combine` (not variant-related).
- **Remaining deferred Boost areas**: ASIO deep plumbing,
  multi-index containers, Spirit parser, multiprecision, `net_ssl.cpp` filesystem,
  `simplewallet.cpp` format strings, `boost::thread::attributes` (stack size).
  Tagged with `TODO(shekyl-v4)` in source. See `DOCUMENTATION_TODOS_AND_PQC.md`
  section 1.11 for the full backlog.

### CI/CD and build system

- **Boost minimum bumped to 1.74**: `BOOST_MIN_VER` in `CMakeLists.txt` raised
  from 1.62 to 1.74. The `contrib/depends` system now pins Boost 1.74.0
  (previously 1.69.0) and builds with `-std=c++17`. Removed legacy Boost 1.64
  patches (`fix_aroptions.patch`, `fix_arm_arch.patch`) that do not apply to 1.74.
- **CI containers updated to Ubuntu 22.04 minimum**: Dropped Debian 11 and
  Ubuntu 20.04 build jobs from `build.yml`, `depends.yml`, and
  `release-tagged.yml`. Ubuntu 22.04 is now the lowest-common-denominator Linux
  build environment (ships Boost 1.74+ and GCC 11+). Added Ubuntu 24.04 build
  matrix entry.
- Migrated version identifiers from legacy `MONERO_*` symbols to canonical
  `SHEKYL_*` names (`SHEKYL_VERSION`, `SHEKYL_VERSION_TAG`,
  `SHEKYL_RELEASE_NAME`, `SHEKYL_VERSION_FULL`, `SHEKYL_VERSION_IS_RELEASE`)
  in `src/version.h` and `src/version.cpp.in`. The old `MONERO_*` names are
  retained as preprocessor aliases so existing call sites and future Monero
  upstream cherry-picks continue to compile unchanged. The aliases will be
  removed in a single cleanup after v4 RingPQC stabilises.
- Fixed Gitian deterministic build pipeline: replaced all hardcoded Monero
  repository URLs and internal package names with Shekyl equivalents across
  `gitian-build.py`, all 5 gitian descriptor YAMLs, `dockrun.sh`, and the
  `gitian.yml` GitHub Actions workflow. The workflow now passes `--url` to
  ensure the correct repository is cloned. Added checkout error handling with
  an actionable message when a tag/branch is missing.
- Tag-driven versioning: `GitVersion.cmake` now extracts the version string
  from git tags (e.g. `v3.0.2-RC1` → `3.0.2-RC1`). The hardcoded version in
  `version.cpp.in` is replaced with the CMake-substituted `@SHEKYL_VERSION@`;
  a default (`3.1.0`) is used for development builds not on a tag.
  `Version.cmake` centralises the fallback default in `SHEKYL_VERSION_DEFAULT`.
- Updated RPC version string validator (`rpc_version_str.cpp`) from Monero's
  four-number format to Shekyl's three-number semver with optional pre-release
  suffix (e.g. `3.0.2-RC1-release`).
- Updated gitian descriptor names from Monero's `0.18` to Shekyl `3` series.
- Added `release/tagged` GitHub Actions workflow: builds static Linux x86_64
  binaries, cross-compiles Windows x64 via MinGW, and produces `.tar.gz`,
  `.deb`, `.rpm`, `.zip`, and NSIS `.exe` installer artifacts on every `v*` tag.
- Added `BuildRust.cmake` cross-compilation support: detects `CMAKE_SYSTEM_NAME`
  and `CMAKE_SYSTEM_PROCESSOR` to derive Rust target triples for Windows, macOS,
  Android, FreeBSD, and Linux cross-targets (ARM, aarch64, i686, RISC-V);
  automatically configures the MinGW linker for Windows cross-compilation.
- Added Rust toolchain installation to all CI workflows (`build.yml`,
  `depends.yml`, `release-tagged.yml`) and all 5 Gitian deterministic build
  descriptors with appropriate cross-compilation targets; required for
  `libshekyl_ffi.a` linking.
- Fixed Gitian `gitian-build.py` to fetch tags explicitly (`--tags`) during
  repository setup, preventing checkout failures for tag-based builds.
- Enhanced `gitian-build.py` error handling: robust `lsb_release` detection,
  auto-correction of stale clone origins when `--url` changes, and detailed
  diagnostics on checkout failure (lists available remote tags and suggests
  the push command).
- Added `workflow_dispatch` trigger to `gitian.yml` with configurable `tag` and
  `repo_url` inputs, allowing manual re-runs and testing against forks without
  retagging.
- Fixed Doxygen project name from `Monero` to `Shekyl` in `cmake/Doxyfile.in`.
- Replaced bundled Google Test 1.7.0 (2013) with CMake `FetchContent` for
  GoogleTest v1.16.0. Fixes `GTEST_SKIP` compilation errors on all platforms
  without a system gtest. Removes 34k lines of vendored source.
- Upgraded all GitHub Actions workflows to Node.js 24: bumped `actions/checkout`
  to v5, `actions/cache` to v5, `actions/upload-artifact` to v6, and
  `actions/download-artifact` to v7 to resolve the Node.js 20 deprecation
  warnings.
- Trimmed `depends.yml` cross-compilation matrix: dropped i686 Win and i686
  Linux (32-bit targets are dead); deferred RISCV 64-bit and ARM v7 until
  user demand materialises. Active matrix is now ARM v8, Win64, x86_64 Linux,
  Cross-Mac x86_64, Cross-Mac aarch64, and x86_64 FreeBSD (6 targets, down
  from 10). Added Cross-Mac aarch64 to the artifact upload filter.
- Added Linux packaging files: `contrib/packaging/linux/shekyld.service`
  (systemd unit) and `contrib/packaging/windows/shekyl.nsi` (NSIS installer).

### Upstream Monero sync (March 2026)

Cherry-picked 62 upstream Monero commits (from `monero-project/monero` master)
across five risk-phased integration rounds. Key improvements absorbed:

- **Wallet**: Fee priority refactoring (`fee_priority` enum + utility functions),
  improved subaddress lookahead logic, `set_subaddress_lookahead` RPC endpoint
  (no longer requires password), incoming transfers without daemon connection,
  HTTP body size limit, fast refresh checkpoint fix, ring index sanity checks,
  `find_and_save_rings()` deprecation, pool spend identification during scan.
- **Daemon/RPC**: Dynamic `print_connections` column width, ZMQ IPv6 support,
  dynamic base fee estimates via ZMQ, `getblocks.bin` start height validation,
  CryptoNight v1 error reporting, batch key image existence check, blockchain
  prune DB version handling, removed `COMMAND_RPC_SUBMIT_RAW_TX` (light wallet
  deprecated).
- **P2P/Network**: Removed `state_idle` connection state, fixed inverted peerlist
  ternary, removed `#pragma pack` from protocol defs, connection patches for
  reliability, dynamic block sync span limits.
- **Crypto/Serialization**: Fixed invalid `constexpr` on hash functions, added
  `hash_combine.h`, aligned container pod-as-blob serialization, fixed
  `apply_permutation()` for `std::vector<bool>`.
- **Build system**: Removed iwyu/MSVC/obsolete CMake targets, added
  `MANUAL_SUBMODULES` cache option, Trezor protobuf 30 compatibility, fixed
  `FetchContent`/`ExternalProject` cmake usage.
- **Tests**: New unit tests for format utils, threadpool, varint, logging,
  serialization static asserts, cold signing functional test fixes.
- **Misc**: Boost ASIO 1.87+ compatibility, fixed Trezor temporary binding,
  fixed multisig key exchange intermediate message update, `constexpr`
  `cn_variant1_check`, extra nonce length fix, removed redundant BP consensus rule.

Skipped commits (deferred to future integration): input verification caching
(conflicts with `txin_stake_claim`/PQC), `wallet_keys_unlocker` refactoring,
`get_txids_loose` DB API (missing prerequisite), complex subaddress lookahead
fixes, and several CMake/depends version bumps that conflict with Shekyl's
build system divergences.

Cherry-picked code was initially adapted to C++14 compatibility; with the
subsequent C++17 standard bump, many of those back-ports are now unnecessary
and can use native `std::optional`, `std::string_view`, etc.

### Documentation

- Added `docs/EXECUTABLES.md`: comprehensive reference for all 17 build
  artifacts covering usage, CLI options, interactive commands, and examples
  for `shekyld`, `shekyl-wallet-cli`, `shekyl-wallet-rpc`, blockchain
  utilities, and debug tools.

### Operations

- Added `utils/systemd/shekyld.service` for Shekyl-native daemon service
  deployment (`/usr/local/bin/shekyld` + `/etc/shekyl/shekyld.conf`).
- Updated `docs/INSTALLATION_GUIDE.md` related-doc references to include seed
  operations documentation in the companion `shekyl-dev` docs set.
- Added `docs/BLOCKCHAIN_NETWORKS.md` with a deep-dive comparison of network
  models across Bitcoin, Ethereum, Monero, Solana, Polkadot, and Avalanche,
  and mapped those patterns to Shekyl's mainnet/testnet/stagenet/fakechain
  usage guidance.
- Migrated Shekyl stagenet defaults from legacy Monero ports to
  `13021` (P2P), `13029` (RPC), and `13025` (ZMQ), and aligned test/docs
  references so `--testnet` workflows use `12029` while scripts support
  overrideable network/daemon variables.
- Updated libwallet API helper scripts to call `shekyl-wallet-cli` (not
  `monero-wallet-cli`) so test tooling matches Shekyl binary names.

### Staking (end-to-end claim-based system)

- Added `txout_to_staked_key` output target type for locking coins at a chosen
  tier (short/medium/long). Outputs carry `lock_tier` field enforced at the
  consensus layer. (Note: `lock_until` was originally stored on-chain but was
  removed in a subsequent fix — see Bug 13 under Unreleased.)
- Added `txin_stake_claim` input type for claiming accrued staking rewards.
  Claims specify a height range and are validated against deterministic per-block
  accrual records.
- Extended LMDB schema with `staker_accrual` and `staker_claims` tables plus a
  `staker_pool_balance` property for on-chain reward pool accounting.
- Per-block accrual logic computes staker emission share and fee pool allocation
  at block insertion time, with full reversal on reorg (block pop).
- Consensus validation: lock period enforcement on staked outputs, claim amount
  verification against accrual records, watermark-based anti-double-claim,
  maximum claim range (10,000 blocks), pool balance sufficiency checks.
- Pure claim transactions (`txin_stake_claim`-only inputs) use `RCTTypeNull`
  signatures, cleanly separated from ring-signature transaction validation.
- Extended `tx_destination_entry` with `is_staking` and `stake_tier`
  fields. `construct_tx_with_tx_key` emits `txout_to_staked_key` outputs
  when `is_staking` is set.
- Extended `transfer_details` with `m_staked`, `m_stake_tier`, and
  `m_stake_lock_until` for wallet-side staking metadata tracking.
  (`m_stake_lock_until` is computed locally from `creation_height + tier_lock_blocks`.)
- Implemented wallet2 methods: `create_staking_transaction`,
  `create_unstake_transaction`, `create_claim_transaction`,
  `get_matured_staked_outputs`, `get_locked_staked_outputs`,
  `get_claimable_staked_outputs`, `get_staked_balance`,
  `estimate_claimable_reward`.
- Added simplewallet commands: `stake <tier> <amount>`, `unstake`,
  `claim_rewards`.
- Added wallet RPC endpoints: `stake`, `unstake`, `get_staked_outputs`,
  `claim_rewards`.
- Added daemon RPC endpoint: `get_staking_info` returning current staking
  metrics (height, stake ratio, pool balance, emission share, tier lock blocks).
- Wired `stake_ratio` and `staker_pool_balance` in `/get_info` to live
  blockchain state.
- No minimum stake amount enforced (matches design doc).
- Fixed compilation errors from `txin_stake_claim` missing in exhaustive
  `boost::static_visitor` patterns: added `operator()` overloads to the
  double-spend visitor (`blockchain.cpp`) and the JSON serialization visitor
  (`json_object.cpp`), added JSON deserialization branch for `"stake_claim"`
  inputs, added `toJsonValue`/`fromJsonValue` declarations and implementations
  for `txin_stake_claim`, and added Boost.Serialization `serialize()` free
  function for wallet binary archive support (`cryptonote_boost_serialization.h`).

### Consensus and mining economics

- Wired Four-Component economics to live chain-state inputs for miner reward
  paths:
  - block template construction now passes rolling `tx_volume_avg`,
    `circulating_supply`, and `stake_ratio` to `construct_miner_tx`
  - miner transaction validation now uses the release-multiplier reward path
    and non-placeholder fee-burn inputs
  - tx pool block template estimation now uses the same rolling
    `tx_volume_avg` reward path for consistency
- Added `Blockchain::get_tx_volume_avg(height)` and
  `Blockchain::get_stake_ratio(height)` (stubbed to `0` until staking state is
  consensus-tracked).

### Modular PoW

- Added pluggable PoW schema abstractions:
  - `IPowSchema` interface
  - `RandomX` and `Cryptonight` schema implementations
  - PoW registry-based selection preserving existing behavior by block version
- Refactored `get_block_longhash` to route through the PoW schema registry while
  keeping existing RandomX seed handling and the historical block 202612
  workaround.
- Updated miner thread preparation to call schema-level
  `prepare_miner_thread(...)` (RandomX prepares thread context; Cryptonight is
  a no-op).
