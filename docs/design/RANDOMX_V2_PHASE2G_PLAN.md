# RandomX v2 — Track A Phase 2g plan

## Front-matter

| Field | Value |
|-------|-------|
| Status | Scaffold (Round 0); Round 1 to follow on `feat/randomx-v2-phase2g-plan` |
| Parent plan | [`docs/design/RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) — Track A Phase 2g todo (`phase2g-differential-harness`, line 30) |
| Sibling plans | [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) (§5.11.5 / §5.11.8 forward-actions); [`RANDOMX_V2_PHASE2D_PLAN.md`](./RANDOMX_V2_PHASE2D_PLAN.md) (§3.4 u128 / `__int128_t` edge-case discipline); [`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md) (§1.1 frozen public API; §10.4 `compute_hash_with_trace` pre-pin; §10.5 three-leg audit posture) |
| Base commit (`dev` tip at scaffold) | `e50fdd299aca17979d30735db3fb03ee1a77ae1e` — "Merge pull request #72 from Shekyl-Foundation/feat/randomx-v2-phase2f-impl" |
| Fork pin | `external/randomx-v2` at `aaafe71` (v2.0.1); unchanged by 2g per the hard-constraint substrate |
| Scaffold branch | `chore/randomx-v2-phase2g-plan` (this PR; plan-doc only; ≤5 working days per [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) rule 2) |
| Round 1 branch (planned) | `feat/randomx-v2-phase2g-plan` (Round 1+ design rounds; opens after Round 0 lands on `dev`) |
| Implementation branch (planned) | `feat/randomx-v2-phase2g-impl` (opens after Round 1 closes per [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc) rounds discipline) |
| Round 0 scope envelope | Substrate capture only: lock the 2c/2d/2f-frozen surfaces against which 2g operates; enumerate Round 1 decision points without closing them; reserve threat-model / hand-off-contract / test-plan / commit-table sections for Round-N. No production Rust code; no harness binary; no CI step; no FOLLOWUPS reflow; no `tests/perf/per_hash_latency.rs` body change. |
| Out of scope (forward-deferred) | (a) Per-PR per-hash latency CI gate — activates at Phase 3a per [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §6 line 243; 2g produces the harness binary, 3a's FFI-shim PR wires the per-PR step. (b) Binary-level `nm`-on-`shekyld` symbol-isolation check — Phase 3c per [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) "RandomX v2 Phase 3c — `aes`-crate symbol-surface check" entry. (c) 600k-block initial-sync wall-time test — release-gate suite per parent plan §6 line 242. (d) Parallel `Cache::derive` / SuperscalarHash thread-pool — separate FOLLOWUPS item if benchmarks justify; out of 2g. (e) Side-channel timing differential beyond byte-equality + median latency — out of 2g; reopen if a future threat-model surfaces a reason to add it. (f) C-side miner state-machine scenarios (epoch transition, secondary cache, async rebuild) — explicitly out of scope per [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) line 30. |

## 0. Why this document exists (Round 0)

Round 0 captures **the inherited substrate**: what the merged 2c / 2d / 2f
code already pins so 2g cannot quietly change it, what forward-actions
the prior phases queued for 2g, and what shape the Round 1 decisions
need to take when they land. Round 0 does **not** close decisions —
that is Round 1's job. The scaffold's purpose, per
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc),
is to give a reviewer reading any future Round-N round a single
substrate-anchored document to check the round's claims against,
rather than re-derive the carry-forwards from three other plan-docs
each time.

Per [`05-system-thinking.mdc`](../../.cursor/rules/05-system-thinking.mdc)
"specification first, code second," Round 0 is the design-doc-first
step before Round 1's option-set evaluation. Per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
"reject-now-with-named-reopening-criteria," every decision Round 1
closes carries an explicit reopen-criterion clause; Round 0
pre-shapes the §3 R1-D* entries to make that discipline mechanical
rather than ad-hoc at Round 1 close.

The audit-posture framing for 2g comes from
[`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md) §10.5
post-closure-pin (three-leg posture; leg 1 spec-faithful
implementation is the load-bearing claim, leg 3 corpus testing is
the backstop). 2g implements leg 3 and depends on 2c/2d/2f having
delivered legs 1 and 2 correctly. The scaffold cites the audit
posture explicitly (§2 forward-action absorption) so a reviewer
reading 2g's plan-doc does not mistake "the differential harness
passes" for "the verifier is canonical RandomX v2." The harness is
the safety net; the leg-1 claim stands on the implementation
discipline of 2b/2c/2d/2f.

### Round-count expectation

**2g's Round 1 is expected to converge in ≤3 rounds.** The
substrate-anchored rationale: 2g introduces no new public API
surface — the type-system surface (`Seedhash` newtype,
`PreparedCache` bundle, `compute_hash` signature, `CacheStore`
API, cfg-gated `VmStatePool`) was closed by Phase 2F Rounds 2
and 3 and is frozen per §1. The substantive Round 1 decisions
are corpus shape (R1-D4 random; R1-D5 adversarial; R1-D6 u128
edge-case), CI placement (R1-D12 cadence + R1-D3 CMake wiring +
R1-D13 invariant-script extension), harness wiring (R1-D1
workspace placement + R1-D2 bindings + R1-D7 per-hash
placeholder population + R1-D9 concurrent-call test), and
test-infrastructure dispositions (R1-D8 worst-case; R1-D10
trace pre-pin; R1-D11 failure-mode format; R1-D14
cache-equivalence precondition). All fourteen are bounded by
the §1 substrate — none require reopening a frozen surface.

Calibration precedent. Round counts scale with how much
type-system reframe the sub-PR does: 2c closed in 3 rounds
(modest reframe — `Cache` + `Vm` + stub-NOP dispatch); 2d
closed across multiple rounds including R0-D5 pre-flight
(dispatch-body replacement); 2f closed in 5+ rounds (substantial
reframe — `PreparedCache` + `Seedhash` newtype + `Cache`
visibility transition + `CacheStore` API + cfg-gated pool).
2g is test-infrastructure layered atop the closed type-system
surface; the round-count budget compresses accordingly.

This is a calibration expectation, not a hard ceiling. If
Round 1's adversarial pass surfaces a substrate finding that
warrants a Round 2 architectural reframe (e.g., a corpus-shape
disposition that requires amending a §1-frozen surface), the
round-count budget reopens substrate-anchored per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).
The expectation calibrates reviewers' attention budget, not
the rigor of any individual round.

### Layer-separation discipline (Round 2 observation)

The Round 1 disposition collection operationalizes the
workspace's actor-paradigm discipline more rigorously than
Round 1's own framing credits. Every other Rust crate in the
workspace adheres to the same shape: **stateless transforms**
(`Cache::derive`, `compute_hash`, `lwma1_next`, the existing
`shekyl-pow-randomx` public surface) and **state-holders confined
to crates that explicitly own them** (`shekyl-engine-state`,
`CacheStore`'s sticky-canonical invariant). Pure transforms are
the load-bearing arithmetic; state-holders are the explicit
owners of any mutability; the boundary between the two is the
project's load-bearing layer separation.

2g's disposition collection realizes a **four-crate layering**
that maps the workspace's actor paradigm onto the
differential-harness problem:

1. **`shekyl-pow-randomx` (verifier).** Pure transforms;
   public surface frozen at Phase 2F R3; no test-infrastructure
   accretion (R1-D7 (c) moves the placeholder *out*; R1-D10 (b)
   declines to add a trace surface).
2. **`CacheStore` (state-holder, lives inside the verifier
   crate).** Explicit state owner; capacity-2 sticky-canonical
   invariant; the only crate-public mutable holder in 2g's
   substrate.
3. **`randomx-v2-sys` (C-bindings boundary).** Sole-purpose:
   the seven `extern "C"` declarations + linker directives.
   Pattern-C-exempt per R1-D13 (c); no other crate holds
   `extern "C"`.
4. **`shekyl-randomx-differential` (harness orchestrator).**
   Long-running orchestration actor; holds mode-dispatch state,
   per-mode accumulators, per-iteration results; the only crate
   in 2g's substrate where `OnceLock` / `LazyLock` / `static`
   mutable state appears (per R1-D13's per-crate scoping
   discipline).

The four crates are the concrete-template realization of the
**verifier-as-pure-transform / state-holder-explicit / FFI-boundary-isolated / orchestrator-as-actor** layering
the workspace has been converging toward. R1-D1's (a) (separate
crate for the harness), R1-D2's (c) (separate sub-crate for the
C-bindings), R1-D7's (c) (placeholder migration out of the
verifier crate), R1-D10's (b) (verifier crate stays minimal),
and R1-D13's (c) (per-crate invariant scoping with crate-level
exemption rather than file-level exemption) each individually
land at the option that respects the layering; the disposition
collection's coherence is not coincidence — it is the workspace's
actor-paradigm discipline applied to a new sub-problem and
yielding the structurally clean shape by construction.

The framing matters forward. **Future Rust extractions
(Phase 3a per-PR latency gate; Phase 3c symbol-isolation check;
release-gate suites; future signing-engine extractions) inherit
this template:** the four-crate shape is the load-bearing layout
that subsequent multi-component Rust work should target by
default, not a one-off 2g shape. The §3.15 *harness actor shape*
disposition operationalizes the orchestrator-actor crate's
internal contract; the layer separation between the four crates
is the project-discipline substrate the §3.15 disposition rests
on.

This observation is a *recognition of the disposition collection's
structural achievement*, not a correction. The discipline already
landed in Round 1; Round 2 names it explicitly so future
contributors inherit the layering as a documented template rather
than reconstructing it from the disposition collection.

---

## 1. Locked-by-2c/2d/2f substrate (frozen; 2g cannot change without reopening earlier rounds)

The following surfaces are the load-bearing substrate 2g operates
against. Reopening any of them is not a 2g operation; it requires
re-opening the earlier round (2c / 2d / 2f) that landed it, with
substrate-anchored reasoning per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).
Round 0 names them so a Round 1 disposition (or implementation-PR
review) does not accidentally re-litigate a frozen surface.

### 1.1 Public API surface (frozen by Phase 2F Round 2, sharpened by post-closure pins)

Per [`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md)
§1.1 Round 2 amendment + post-closure pin #2 + post-closure-pin
refinement #1, the verifier crate's public surface at HEAD
(`dev` tip `e50fdd299`) is:

```rust
// In rust/shekyl-pow-randomx/src/lib.rs (or re-exports therefrom):

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Seedhash(/* private [u8; 32] */);
impl Seedhash {
    pub fn from_bytes(bytes: [u8; 32]) -> Seedhash;
    pub fn as_bytes(&self) -> &[u8; 32];
}
impl core::fmt::Display for Seedhash { /* lowercase hex */ }

pub struct PreparedCache { /* private fields: { cache: Cache, seedhash: Seedhash } */ }
impl PreparedCache {
    pub fn derive(seedhash: Seedhash) -> PreparedCache;
    pub fn seedhash(&self) -> &Seedhash;
    pub(crate) fn cache_ref(&self) -> &Cache;  // crate-internal reach-through per post-closure-pin refinement #1
}

pub fn compute_hash(prepared: &PreparedCache, data: &[u8]) -> [u8; 32];

// pub(crate) since Phase 2F Round 2 (was `pub` in Phase 2c):
//   struct Cache { /* private fields */ }
//   fn Cache::derive(seedhash: &Seedhash) -> Cache
//   fn Cache::from_raw / Cache::derive_item / Cache::item_bytes (test-internal)
pub use cache_store::CacheStore;
```

**2g implications.**

- 2g's harness invokes `compute_hash(&prepared, data)` against a
  `PreparedCache` constructed via `PreparedCache::derive(seedhash)`;
  it does not construct `Cache` directly (Cache is `pub(crate)`).
- The harness's seedhash inputs are `Seedhash` values constructed
  via `Seedhash::from_bytes([u8; 32])` from corpus-generator output.
  The newtype boundary prevents accidental mixing with other
  32-byte values (block hashes, output hashes, etc.) at call sites.
- `compute_hash`'s `&PreparedCache`-shaped signature means the
  harness cannot exercise a "wrong cache for seedhash" path even
  if a future corpus-generator bug tried to — the bundling
  invariant is enforced at the type system. The byte-equality
  comparison is between the Rust-side `compute_hash` output and
  the C-reference's `randomx_calculate_hash` output for the
  *same* (seedhash, data) input pair, per the parent-plan §6 +
  §7 line 248 framing.
- Any 2g need that would amend the public surface (e.g., the
  `compute_hash_with_trace` option per R1-D10 below) lands as
  cfg-gated test infrastructure under
  `#[cfg(any(test, feature = "differential-trace"))]`, **not** as
  a default-features public-API addition. Per the
  [Phase 2F §10.4 cfg-gated-additions principle](./RANDOMX_V2_PHASE2F_PLAN.md):
  cfg-gated additions that do not appear in the default-features
  production build and cannot influence consensus are Rust-language
  affordances, not "tweaks to upstream RandomX."

### 1.2 `CacheStore` API (frozen by Phase 2F Round 2 + Round 3)

Per [`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md)
§3.1 Round 2 + §3.6 Round 3, exposed at HEAD as
`pub use cache_store::CacheStore;`:

```rust
// In rust/shekyl-pow-randomx/src/cache_store.rs (new in Phase 2F; re-exported):
pub struct CacheStore { /* private fields per the sync-shape sub-block */ }
impl CacheStore {
    pub fn new() -> CacheStore;
    pub fn lookup(&self, seedhash: &Seedhash) -> Option<Arc<PreparedCache>>;
    pub fn lookup_or_derive(&self, seedhash: &Seedhash) -> Arc<PreparedCache>;
    pub fn set_canonical(&self, prepared: Arc<PreparedCache>);
}
```

**Internal synchronization shape (load-bearing for R1-D9 concurrent-call test):**

- Two slots: `canonical` and `transient`, each
  `RwLock<Option<Arc<PreparedCache>>>`.
- In-flight derivation deduplication: `Mutex<HashMap<Seedhash,
  Arc<DerivationSlot>>>` with cleanup-on-publish and
  leader-abort cleanup (per PR #72 NF6 post-fix; published
  on `feat/randomx-v2-phase2f-impl` commit `26fc49d6c` line range).
- Lock-ordering invariant: every method acquiring both slot locks
  acquires them **canonical-then-transient**, regardless of
  read-vs-write mode (per PR #72 NF2 post-fix). Lookup
  linearizability requires both read guards acquired before the
  comparison sequence.

**2g implications.**

- 2g's concurrent-call test (R1-D9) operates against the frozen
  `CacheStore` API; no 2g amendment touches the API surface.
- The success criterion for R1-D9 is "no panic, no deadlock,
  byte-equality of each pair of hashes for the same (seedhash, data)
  input regardless of which worker computed it" — the latter
  follows from `lookup_or_derive`'s in-flight-dedup discipline
  (concurrent callers for the same seedhash all receive the same
  `Arc<PreparedCache>`).
- The eviction policy — canonical non-evictable, transient
  displace-on-insert, advance promotes-and-demotes — is frozen
  by the 11-row state-transition table in 2F §3.2 Round 2; 2g's
  concurrent test does not exercise novel eviction paths.

### 1.3 Cfg-gated `VmStatePool` (Branch A: bench-only artifact at HEAD)

Per [`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md)
§3.3 Round 3 + §3.4 R1-D4 Round 3 + `BENCH_RESULTS.md` Branch A
disposition (commit `a37aac054`), the cfg-gated pool is live
behind `#[cfg(any(test, feature = "internal-pool-bench"))]` as a
bench-only artifact:

```rust
// In rust/shekyl-pow-randomx/src/vm_pool.rs (or analogous):
#[cfg(any(test, feature = "internal-pool-bench"))]
#[doc(hidden)]
pub struct VmStatePool { /* private fields */ }

#[cfg(any(test, feature = "internal-pool-bench"))]
impl VmStatePool {
    pub fn new(capacity: usize) -> VmStatePool;
    pub fn acquire(&self) -> VmStateGuard<'_>;
    // Default::default() panics outside #[cfg(test)] to enforce explicit capacity per §3.5 R1-D5.
}

#[cfg(any(test, feature = "internal-pool-bench"))]
pub fn compute_hash_with_pool(pool: &VmStatePool, prepared: &PreparedCache, data: &[u8]) -> [u8; 32];
```

- Branch A disposition stands at HEAD: pool savings ≈ 47.75 µs
  (component-floor cap) is below the 50 µs threshold; the pool
  stays as a bench-only artifact. Phase 3a's FFI shim sees the
  unchanged production `compute_hash` body (`VmState::new()` per
  call).
- The pool's `Default::default()` panics in non-test, non-`internal-pool-bench`
  builds to enforce the §3.5 R1-D5 explicit-capacity discipline
  (per [`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md)
  Cargo.toml comment + Round 3 disposition).

**2g implications.**

- 2g's harness measures against the production `compute_hash` path
  (no pool), matching the daemon's per-call-allocation discipline
  per parent plan Decision #7. The R1-D7 per-hash latency
  population mechanism does **not** consume `compute_hash_with_pool`
  or `VmStatePool` — those are bench-only artifacts owned by 2F
  for the Branch A/B/C measurement, not by 2g.
- Branch A's reopening criterion (per `BENCH_RESULTS.md`) names
  2g's per-hash latency deliverable as one of the substrate
  changes that could re-trigger the disposition: if 2g surfaces
  an A/B-delta-relevant cost on production-target hardware that
  contradicts the i9-11950H baseline, the Branch A disposition
  reopens. 2g records the measurement; the reopen is a separate
  V3.x or pre-genesis disposition pin in `BENCH_RESULTS.md`, not
  a 2g scope expansion.

### 1.4 Crate-invariant grep gate (frozen by Phase 2F Round 3 + Round 4 post-fix)

Per [`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md)
§3.6 R1-E1 + PR #72 NF7 (multi-line bypass closure) + NF8 (scan
scope expansion), the gate `scripts/ci/check_randomx_crate_invariants.sh`
operates over `rust/shekyl-pow-randomx/{src,tests,benches}` with:

- **Pattern A** (`PATTERN_RUNTIME_STATE`): bans column-0 imports
  of `once_cell` / `lazy_static` / `OnceLock` / `LazyLock`; complemented
  by a per-file POSIX awk multi-line scanner that handles the
  rustfmt-default grouped form (`use std::sync::{\n    OnceLock,\n};`).
- **Pattern B** (`PATTERN_MODULE_STATIC`): bans column-0 `static`
  declarations.
- **Pattern C** (`PATTERN_FFI_EXPORT`): bans `#[no_mangle]` /
  `#[unsafe(no_mangle)]` / `#[export_name` / `#[unsafe(export_name`,
  plus `extern "C" fn` definition form (with optional `pub` /
  `pub(crate)` / `pub(super)` / `pub(in path)` visibility prefix and
  optional `unsafe` keyword). `extern "C" { fn foo(); }` *import*
  blocks are not matched.

The gate is wired into CI at
[`.github/workflows/build.yml`](../../.github/workflows/build.yml)
line 77–78 as a sibling of the FPU rounding-mode primitive scope
check.

**2g implications.**

- The gate covers the `shekyl-pow-randomx` crate's source surface
  (`src/` + `tests/` + `benches/`). 2g does not amend the gate;
  the gate continues to fire on any drift in the verifier crate's
  isolation invariants.
- R1-D13 is the Round 1 disposition that decides where 2g's
  C-side bindings (the `extern "C" fn` declarations needed to
  call into `shekyl_randomx_v2`) live relative to this gate. The
  three options (a/b/c) below have different relationships to
  the gate; the default expectation is option (c) (a tiny
  `randomx-v2-sys` crate that owns the `extern "C"` declarations
  and is the only crate carrying them, leaving the
  differential-harness crate Rust-side and invariant-clean).
  Round 1 closes the disposition.

### 1.5 Existing `tests/perf/per_hash_latency.rs` placeholder

Per [`rust/shekyl-pow-randomx/Cargo.toml`](../../rust/shekyl-pow-randomx/Cargo.toml)
lines 149–159 + [`rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs`](../../rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs):

```rust
#[test]
#[ignore = "Phase 2g deliverable; placeholder per 2c's F8 forward-action"]
fn per_hash_latency_ratio_within_budget() {
    unimplemented!(
        "Phase 2g lands this; see RANDOMX_V2_PHASE2C_PLAN.md §5.8 F8 \
         and §13 forward-path 2g inheritance"
    );
}
```

The placeholder is the structural-out-surviving form per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).
2g replaces the body in-place per R1-D7; the test name and the
`#[ignore]` (or its removal) is part of the R1-D7 disposition.
The `[[test]] name = "per_hash_latency"` Cargo.toml entry stays
in place — the deliverable name is grep-discoverable from the
canonical path.

### 1.6 Existing CI substrate the harness inherits unchanged

Per [`.github/workflows/build.yml`](../../.github/workflows/build.yml):

- `check_randomx_fpu_rounding.sh` — Phase 2d FPU rounding-mode
  primitive scope gate (line 75–76).
- `check_randomx_crate_invariants.sh` — Phase 2F crate-isolation
  gate (line 77–78; see §1.4 above).
- `cargo fmt --all -- --check` (line 584).
- `cargo clippy --workspace --all-targets --keep-going -- -D warnings`
  (line 596).
- `cargo test --locked --workspace` (line 602).
- "Gate 2: `shekyl-pow-randomx` debug-vs-release equivalence"
  (line 606; `cargo test --release -p shekyl-pow-randomx`).

2g inherits these unchanged. R1-D12 decides where 2g's byte-equality
differential job lands relative to this workflow (per-PR sibling
step vs. scoped separate workflow vs. split-cadence). The default
expectation (per the parent-plan 2g todo: "CI job runs the harness;
failure fails CI") is per-PR cadence for the byte-equality pass.

### 1.7 Phase 1 RandomX v2 CMake wiring (frozen by Phase 1)

Per [`external/CMakeLists.txt`](../../external/CMakeLists.txt)
lines 81–216 + [`CMakeLists.txt`](../../CMakeLists.txt) line 503:

- `BUILD_RANDOMX_V2_MINER_LIB` is a CMake option defaulting OFF
  (line 503).
- When ON, `external/CMakeLists.txt` builds the v2 fork
  out-of-tree via `ExternalProject_Add` (line 193) and exposes
  it as `IMPORTED GLOBAL` target `shekyl_randomx_v2` (line 204)
  with `INTERFACE_INCLUDE_DIRECTORIES` set to the install-dir
  include path.
- Phase 1 fail-fast disposition (line 123): combining
  `BUILD_RANDOMX_V2_MINER_LIB=ON` with a multi-config generator
  (`CMAKE_CONFIGURATION_TYPES` non-empty) refuses with
  `FATAL_ERROR`. Single-config generators (Ninja, Make) are
  required.
- FOLLOWUPS pointer: per-`CONFIG` install path + per-`CONFIG`
  `IMPORTED_LOCATION` for multi-config generators is queued at
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) line 3684 ("RandomX v2
  `ExternalProject_Add`: per-`CONFIG` install path and
  `IMPORTED_LOCATION_<CONFIG>` for multi-config generators"),
  targeted at "V3.x — RandomX v2 Phase 2."

**2g implications.**

- R1-D3 decides how 2g's harness build flips
  `BUILD_RANDOMX_V2_MINER_LIB=ON` (auto-flip when the harness
  is built; require explicit; new `BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS`
  option that implies it). Round 1 closes the disposition.
- Single-config-generator constraint per the Phase 1 fail-fast
  applies to 2g's CI runner platform (R1-D12 pins runner choice
  to single-config generators, or escalates the per-`CONFIG`
  FOLLOWUPS entry to V3.0 ahead of 2g if the CI requires
  multi-config support).
- The canonical C export list 2g's bindings (R1-D2) must cover is
  derived from [`external/randomx-v2/src/randomx.h`](../../external/randomx-v2/src/randomx.h)
  and pinned to the minimal-subset 2g consumes (per `RANDOMX_V2_RUST.md`
  §7.1's 10-symbol explicit list): `randomx_alloc_cache`,
  `randomx_init_cache`, `randomx_create_vm`, `randomx_calculate_hash`,
  `randomx_destroy_vm`, `randomx_release_cache`, `randomx_get_flags`
  (7 of 10; the dataset-side symbols `randomx_alloc_dataset` /
  `randomx_init_dataset` / `randomx_dataset_item_count` are not
  needed because 2g exercises light-mode VM only). The full
  enumeration belongs in R1-D2.
- **Fork-pin coupling (substrate-anchored maintenance pin).** Under
  R1-D2's default expectation (option (c): a Shekyl-introduced
  `randomx-v2-sys` sub-crate that owns the hand-written `extern "C"`
  declarations + `build.rs` linker directives), the sub-crate does
  not exist in upstream `tevador/RandomX` or in Monero — it is a
  Shekyl-side artifact whose `extern "C"` declarations must match
  the symbol signatures exposed by
  [`external/randomx-v2/src/randomx.h`](../../external/randomx-v2/src/randomx.h)
  at the pinned fork commit (`aaafe71`). **The sub-crate's update
  cadence is coupled to the fork pin, not to Shekyl's release
  cadence.** Any future PR that advances the `external/randomx-v2`
  fork pin (e.g., a security-patch cherry-pick from upstream, a
  v2.0.2 update) is responsible for diffing the new pin's
  `randomx.h` against the prior pin's `randomx.h`, identifying any
  signature changes on the 7-symbol minimal subset (or additions
  to the canonical export list 2g consumes), and updating the
  `randomx-v2-sys` declarations in lockstep. The PR description
  for any fork-pin-advance cites the signature-diff verification
  step explicitly so reviewers do not assume the bindings
  "just work" against the new pin. Reopen criterion for R1-D2 /
  R1-D13: if upstream RandomX v2 changes its C ABI (e.g., adding
  a parameter to `randomx_calculate_hash` or renaming a symbol),
  the fork-pin-advance PR cannot land without amending the
  sub-crate. (For comparable cross-component verification-step
  discipline see `RANDOMX_V2_PHASE2D_PLAN.md` §3.4 "audit-against-actual-code"
  framing applied to fork-derived dependencies.)

---

## 2. Forward-actions absorbed from prior phases (verbatim, with cross-references)

The following forward-actions were enumerated in prior plan-docs
with explicit "Phase 2g inherits" or "2g forward-action" framing.
Round 0 captures them verbatim so Round 1's decision-set has the
substrate without chasing through three plan-docs.

### 2.1 From `RANDOMX_V2_PHASE2C_PLAN.md` §5.11.5 — adversarial seedhash corpus + worst-case timing bound

> The Phase 2g differential harness corpus is a sampled set of
> `(seedhash, data)` inputs; sampling catches statistically-common
> bugs but misses adversarially-crafted inputs. Two forward-actions:
>
> - **Adversarial seedhash corpus**: 2g selects 5–10 seedhashes
>   specifically chosen to produce programs that exercise rare paths:
>   programs heavy in CFROUND (per-iteration rounding-mode thrash),
>   heavy in FDIV_M (per-iteration FP division with mask), heavy in
>   cache-miss-shaped scratchpad access patterns, heavy in CBRANCH
>   (branch-misprediction-shaped dispatch). The corpus runs the T1–T8
>   matrix (and 2d's T9+ per-opcode tests) plus the differential
>   harness against each adversarial seedhash. Assertions: byte-equality
>   against C reference per (seedhash, data) pair; per-hash latency
>   within budget (see worst-case bound below) for each pair.
> - **Pathological-program worst-case timing bound**: Phase 0's ≤3.0×
>   C-reference per-hash budget is an average across benign inputs.
>   2g adds a worst-case bound (parent plan §6 carries the constant;
>   Round 4 sibling commit lands the constant) tested against the
>   adversarial corpus. If the worst case exceeds the bound, the
>   verifier can be CPU-DoS'd by miners grinding seedhashes to find
>   pathological programs.
>
> The 2g plan-doc (when drafted) carries these forward-actions
> verbatim and selects the specific seedhash corpus. The criteria for
> "this seedhash is adversarial enough to include" are part of 2g's
> Round 1.

— [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) §5.11.5,
lines 1735–1762.

**Round 0 cross-link.** R1-D5 (adversarial seedhash corpus) and
R1-D8 (worst-case ratio measurement) are the Round 1 decisions
that close this forward-action. The parent-plan §6 Round 4 ≤5.0×
constant (per [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §6 line
238) is the worst-case bound 2g asserts against.

### 2.2 From `RANDOMX_V2_PHASE2C_PLAN.md` §5.11.8 — audit-against-actual-code discipline

> **Observation.** Round 3's `VmState` field-set audit (§5.1.1) caught
> one correction-from-prompt finding: the earlier `mp` row in the
> field-set table was speculative (transcribed from an expected-behavior
> prompt), and the audit against `vm_interpreted.cpp` and `common.hpp`
> revealed `mp` is a v2-only local-variable alias for `mem.ma`, not a
> struct field. The discipline that found it — **audit-against-actual-code,
> not against documentation or prompted lists** — is the
> discipline that prevents the same class of bug shipping as a
> consensus-split source.
> […]
> **Forward propagation.** 2d's §1.3 audit re-verification (per
> `RANDOMX_V2_PHASE2D_PLAN.md` §1) carries the discipline forward to
> the dispatch surface; 2g's differential harness is the eventual
> empirical check (byte-equality against the C reference for both
> sampled and adversarial inputs). The discipline applies at each
> PR's design time; 2g's harness is the safety net for cases where
> the plan-doc-time discipline missed something.
> […]
> **Enforcement: show your work.** Every audit table in the plan-doc
> […] **cites line ranges in the C reference at the pinned fork
> commit.** […] The line-range citations are the audit's
> evidence-trail.

— [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) §5.11.8,
lines 1840–1946.

**Round 0 cross-link.** 2g's C-reference cross-check (R1-D2's
bindings audit; R1-D11's bisection-divergence format) inherits the
"cite line ranges in the C reference at the pinned fork commit
(`aaafe71`)" discipline. Audit tables that 2g produces — e.g., the
enumeration of which C exports the bindings cover, or the
divergence-failure reporting format that names the C-side function
producing the reference output — cite C-side line ranges per the
§5.11.8 enforcement requirement. The discipline applies at Round
1's R1-D2 disposition write time, not at implementation-PR review
time.

### 2.3 From `RANDOMX_V2_PHASE2D_PLAN.md` §3.4 — u128 / `__int128_t` edge-case differential discipline

> **Context.** Per 2c §5.11 Objective 6 ("consensus split via
> implementation divergence"), Rust's `u128` arithmetic may diverge
> from C's `__int128_t` arithmetic at edge cases the spec does not
> mechanically pin down. Examples:
>
> - **Division by zero.** Rust panics on `u128 / 0` and `u128 % 0`
>   […]. C is undefined behavior. […]
> - **Signed division overflow** (`i128::MIN / -1`). Rust panics; C
>   is UB. Same hazard, opposite-sign register variant.
> - **Shift-by-width-or-greater.** Rust panics in debug, wraps in
>   release […]. C is UB. […]
> - **`u128 * u128` truncation.** Rust's `wrapping_mul` returns the
>   low 128 bits; the C reference uses `_umul128` intrinsic for the
>   low half and may compute the high half separately. If the
>   dispatch needs both halves (e.g., IMULH_R, IMULH_M, IMUL_RCP),
>   the high half's computation path must be byte-equality-checked
>   against the C reference.
> […]
> 3. **Generator-side test coverage.** The reference vector
>    generator (per 2c §5.6 F6) gains adversarial inputs that drive
>    each enumerated edge case at the C reference; 2d's tests
>    assert byte-equality. Belongs in 2g's adversarial corpus per
>    2c §5.11.5 for the full enumeration; 2d carries the
>    per-opcode subset that 2d's dispatch implementation needs.
>
> **Why this is 2d's problem, not 2g's.** 2g's harness is the
> empirical safety net for cases that escape design-time audit; 2d's
> audit is the design-time mitigation. […]
>
> **Out of scope for 2d.** `i128::MIN / -1` paths and div-by-zero
> paths that turn out to be reachable but the C reference's UB is
> itself the consensus rule (i.e., the network has long agreed on
> some specific compiler output as the canonical answer) — these are
> 2g findings, not 2d findings. 2d audits and pre-handles; 2g's
> harness backstops.

— [`RANDOMX_V2_PHASE2D_PLAN.md`](./RANDOMX_V2_PHASE2D_PLAN.md) §3.4,
lines 494–562.

**Round 0 cross-link.** R1-D6 (u128 edge-case corpus) is the
Round 1 decision that extends the R1-D4/R1-D5 corpus with seedhashes
that drive each of the four enumerated edge-case classes. R1-D6
inherits the methodology question (grinded vs. constructed) from
R1-D5 and the per-class targets from §3.4. The "C reference's UB
is itself the consensus rule" disposition is 2g's empirical task:
if the corpus surfaces a Rust/C divergence at one of these edge
cases, the disposition is recorded against the 2d audit table
(re-opening the relevant 2d row) rather than absorbed as a
2g-internal patch.

### 2.4 From `RANDOMX_V2_PHASE2F_PLAN.md` §10.4 — `compute_hash_with_trace` pre-pin

> Phase 2g's differential harness compares Rust-side `compute_hash`
> output against the C reference's output. When the two diverge,
> the harness sees that the final 32-byte hash differs; bisecting
> from final-hash divergence to the specific instruction / iteration
> where the divergence first appeared is expensive (manual
> spelunking of two implementations' intermediate state).
>
> Phase 2g may add a test-infrastructure entry point to the verifier
> crate:
>
> ```rust
> #[cfg(any(test, feature = "differential-trace"))]
> pub fn compute_hash_with_trace(
>     prepared: &PreparedCache,
>     data: &[u8],
>     trace_sink: &mut impl TraceSink,
> ) -> [u8; 32];
> ```
>
> `TraceSink` captures per-iteration register-file snapshots,
> program-counter values, and dataset-read indices. The C reference
> does not expose this; the Rust verifier exposes it under
> `#[cfg(...)]` so the production build pays no overhead. […]
>
> **This is test-infrastructure, not a public-API addition.** The
> production build does not include `compute_hash_with_trace`; the
> symbol does not appear in the crate's public API surface under
> default features; the FFI shim does not see it. […]
>
> **`TraceSink` trait scope (post-closure pin refinement).** […]
>
> - The trait's surface lives with the differential harness, not
>   with the verifier's public API. […]
> - 2g's plan-doc is responsible for the trait's design, scope, and
>   stability commitments. […]
> - **Do not promote `TraceSink` to a public surface.** […]
>
> Pre-pin disposition: Phase 2g's plan-doc inherits this option. If
> 2g's bisection workflow needs the trace API, 2g's plan adds it
> under the `#[cfg(...)]` shape above and designs the `TraceSink`
> trait surface with the scope discipline named here. If 2g's
> differential pass surfaces no divergence (or the divergences that
> surface are bisectable without trace infrastructure), the trace
> API is not added — the verifier crate stays minimal. Reopen
> criterion: 2g's substrate finds bisection from final-hash
> divergence is intractable without per-iteration trace visibility.

— [`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md) §10.4,
lines 2682–2785.

**Round 0 cross-link.** R1-D10 is the Round 1 decision that closes
this pre-pin. Default expectation per the §10.4 framing is "omit
until needed; explicitly carry the option to a future round with
the named reopening criterion." If R1-D10 closes as "include,"
R1-D11 (bisection-divergence failure format) inherits the
per-iteration trace as part of its output shape.

### 2.5 From `RANDOMX_V2_PHASE2F_PLAN.md` §10.5 — three-leg audit posture against the C reference

> Phase 2g's differential harness is the test backstop for the
> "Shekyl's verifier is canonical RandomX v2" claim. **The harness
> is necessary but not sufficient for the claim.** Three distinct
> legs support spec-equivalence with canonical RandomX v2:
>
> 1. **Spec-faithful implementation discipline** (Phases 2b / 2c /
>    2d / 2f): each phase implements against the canonical RandomX
>    v2 specification, with the C reference (RandomX upstream at
>    the pinned commit) consulted where the spec is silent or
>    ambiguous. […]
> 2. **C-reference audit where the spec is silent.** Some behavior
>    in canonical RandomX v2 is defined by the C reference […]
>    rather than by the spec text. Each Shekyl-side implementation
>    of these is audited against the C reference at the pinned
>    commit.
> 3. **Differential-harness corpus testing** (Phase 2g): the
>    harness compares Rust-side `compute_hash` output against the
>    C reference's output across an adversarial corpus of inputs
>    […]. Agreement on the corpus is evidence of agreement; it is
>    not proof of spec-equivalence.
>
> **The load-bearing claim is leg 1, not leg 3.** "Shekyl's verifier
> is canonical RandomX v2" is established by the spec-faithful
> implementation discipline of leg 1, audited against leg 2's
> C-reference where leg 1 is underspecified. Leg 3 is the backstop
> that catches divergences leg 1 and leg 2 missed; corpus testing
> on a finite set of inputs does not establish behavior on the
> unbounded set of all inputs, but it does increase confidence
> that the implementation discipline of leg 1 was applied
> correctly.
> […]
> Phase 2g's plan-doc inherits this audit-posture framing explicitly;
> the differential harness is built and operated under leg 3, not
> as a standalone "we tested it" claim. The plan-doc cites legs 1
> and 2 as the upstream disciplines the harness depends on. Reopen
> criterion: a substrate finding in Phase 2g surfaces that one of
> the legs is broken (e.g., a spec-silent behavior was implemented
> without C-reference audit, surfacing a corpus divergence that is
> ambiguous between "Rust-side bug" and "C-reference quirk we
> mis-mirrored").

— [`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md) §10.5,
lines 2787–2849.

**Round 0 cross-link.** The audit posture is the framing for the
entire 2g plan-doc. §10 forward path cites it for 2g's hand-off
to 3a / 3c / release-gate; §4 threat model (Round-N placeholder)
will return to it explicitly. Round 0 names the framing here so a
reviewer reading 2g's plan does not mistake "the differential
harness passes" for "the verifier is canonical RandomX v2" — the
harness is the safety net for legs 1 and 2.

**Round 0 amplification: leg 3 as catch-of-last-resort.** The
verbatim §10.5 framing names leg 3 as "the backstop that catches
divergences leg 1 and leg 2 missed." Operationally this is
catch-of-last-resort: bugs that slipped past the spec-faithful
implementation discipline (leg 1) and the C-reference audit
discipline (leg 2) — bugs caused by auditor-side errors reading
the wrong line range, transcribing the spec text but missing an
implementation detail, or applying the C-reference audit to a
surface the spec is silent on but the auditor assumed was
spec-defined — are detectable nowhere else in the audit posture.
The 2c §5.11.8 "audit-against-actual-code" recurrence record
(`mp` correction at 2c Round 3; R1-D3 frequency-decode finding
at 2d Round 1; R6-D2 frequency-completeness finding at 2d
Round 6) shows the discipline catching real findings before the
harness was in place; absent the discipline catching them at
read-time, leg 3 would have been the catch. **Corollary: corpus
coverage is itself a load-bearing property of the audit
posture, not "completeness of testing."** Thin corpus coverage
thins the catch-of-last-resort surface; the harness's coverage
profile (random per R1-D4 + adversarial per R1-D5/R1-D6 +
worst-case timing per R1-D8) is the substrate that determines
how much of leg 3's possible catch is actually delivered. The
distinction matters for Round 1's R1-D4 / R1-D5 / R1-D6 / R1-D8
dispositions: under-investment in corpus shape is not
"good-enough testing pragmatism"; it is reducing the audit
posture's residual catch capacity. The corpus-coverage-as-leg-3-completeness
framing is pinned in §4 (Round-1-close obligation) so Round 1's
threat-model close treats it as load-bearing rather than
adjacent to the F1–F7-style attack classes.

### 2.6 From `RANDOMX_V2_PLAN.md` §6 — performance targets (average ≤3.0×, worst-case ≤5.0×)

> - **Per-hash latency (average):** Rust interpreter / C light-VM-JIT
>   ≤ 3.0× on the cache mode daemons actually run in. Benchmarked in
>   Phase 2g (consumes the differential harness binary that 2g
>   produces); CI-enforced in Phase 3.
> - **Per-hash latency (worst-case; Round 4 addition).** Rust
>   interpreter / C light-VM-JIT ≤ 5.0× on adversarial inputs. […]
>   Benchmarked in Phase 2g against an adversarial seedhash corpus
>   (per 2c §5.11.5 forward-action): 5–10 seedhashes specifically
>   chosen to produce programs heavy in CFROUND, FDIV_M,
>   cache-misses, and branches. Phase 2g asserts the worst-case
>   ratio is ≤5.0× and reports the actual ratio in `BENCH_RESULTS.md`.
>   Release-gate-suite cadence (not per-PR) to match the per-hash
>   benchmark's deterministic-corpus framing without inflating
>   per-PR CI runtime.
> […]
> - **CI enforcement mechanism for the per-hash target** (per-PR
>   cadence, **activated starting at Phase 3a** when the FFI shim
>   that exposes `compute_hash` to C++ callers lands […]):
>   synthetic benchmark of N = 1024 hashes against a fixed seedhash
>   + fixed inputs, asserting the median Rust-interpreter latency
>   is ≤ 3.0× the corresponding C-reference median on the same
>   hardware. <30s of CI wall time, deterministic, and validates
>   the load-bearing ratio that drives the 4-hour figure. Pre-Phase-3a
>   (i.e., during Phase 2c/2d/2f/2g) the benchmark runs in 2g
>   without CI gating — 2g produces the harness binary that the
>   per-PR CI mechanism then consumes; the gate activates when the
>   FFI shim makes per-PR regressions reachable from C++ callers.

— [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §6 lines 236–243.

**Round 0 cross-link.** R1-D7 (per-hash latency benchmark
population) closes the average-≤3.0× population mechanism;
R1-D8 (worst-case ratio measurement) closes the worst-case-≤5.0×
mechanism. §9 below records that the per-PR per-hash latency CI
gate is **3a-land, not 2g-land** — 2g produces the harness
binary that 3a's FFI-shim PR consumes for the per-PR CI step.

### 2.7 From `RANDOMX_V2_PLAN.md` §7 — separate artifact, not a dev-dep

> 7. **Structural isolation invariants** (CI-enforced, two of them):
>    […]
>    - Differential test harness (Phase 2g) is a separate artifact,
>      not a dev-dependency of `shekyl-pow-randomx`.

— [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §7 line 248.

**Round 0 cross-link.** This is a **hard constraint**, not a
recommendation. R1-D1 (workspace placement) closes it by placing
the harness as its own workspace member; option (b) (tests folder
of an existing crate) is rejected by construction because it
would make the harness a dev-dep of whatever crate hosts it.
R1-D13 closes the companion structural question of where the
`extern "C"` declarations live; the default expectation (option c)
keeps both crates Rust-side and invariant-clean by splitting the
C-side bindings into a tiny `randomx-v2-sys` crate.

---

## 3. Round 1 decision points (open; enumerated, not closed)

The following decisions Round 1 will need to close. Each has the
**decision** named, the **option set** (with rejected-by-construction
options identified so Round 1 does not re-litigate them), the
**criteria** for choosing among options, a **default expectation**
(where the substrate strongly suggests one), and a placeholder
**Round 1 disposition: TBD** that Round 1 replaces with the closed
disposition + reversion clause per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).

Round 0 does **not** close any of these. The default expectations
below are pre-flight intuition that Round 1's adversarial pass may
overturn; they are recorded so Round 1 has a starting point, not
a binding pin.

### R1-D1 — Workspace placement

**Decision.** Where does the differential-harness binary live in
the Cargo workspace?

**Options.**

- **(a)** New workspace member `rust/shekyl-randomx-differential/`
  with a `[[bin]]` target (and possibly a `lib.rs` test-harness
  surface — see R1-D7).
- **(b)** `tests/` folder of an existing crate (rejected by
  construction — [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §7
  line 248 forbids the harness from being a dev-dep of
  `shekyl-pow-randomx`; any test under `shekyl-pow-randomx/tests/`
  *is* a dev-target of that crate by Cargo's model).
- **(c)** `tools/` directory outside `rust/` (rejected by
  construction — the Rust workspace boundary at `rust/Cargo.toml`
  is the canonical location for Rust artifacts; placing a Rust
  binary outside the workspace fragments tooling, lock-file
  reconciliation, and `cargo` invocation discipline).

**Criteria.** Hard constraint § 2.7 forces (a) or a structurally-equivalent
shape; (b) and (c) are rejected by construction. The Round 1
choice between (a) and a hypothetical (a′) (e.g., a sibling
workspace under `tests/release_gates/`) is governed by whether
the harness needs to be discoverable from the workspace `cargo`
default-member surface vs. opt-in via path.

**Default expectation.** (a) — new workspace member
`rust/shekyl-randomx-differential/` with `[[bin]]` (and possibly
`[lib]` per R1-D7).

**Reopen criterion (sketch for Round 1).** Reopen if Round 1's
discussion surfaces a structural reason the harness needs to live
outside the standard `rust/` workspace (e.g., it depends on a
build artifact that the workspace's `cargo` defaults cannot
discover); not anticipated.

#### Round 1 disposition (closes R1-D1)

**Close at default expectation.** Workspace placement is (a) — new
workspace member at `rust/shekyl-randomx-differential/` with a
`[[bin]]` target *and* a `[lib]` target so R1-D7 (c) can share
in-process bindings between the binary and the per-hash latency
integration test.

**Substrate-anchored rationale.** The §2.7 hard constraint
(harness is a separate artifact, not a dev-dependency of
`shekyl-pow-randomx`) plus the §1.4 crate-invariant grep gate
(Pattern C: no `extern "C"` in `rust/shekyl-pow-randomx/tests/`)
make (b) rejected by construction; the `rust/` workspace boundary
at `rust/Cargo.toml` makes (c) rejected by construction. The
remaining structural question — `[[bin]]`-only vs.
`[lib]` + `[[bin]]` — closes at `[lib]` + `[[bin]]` per R1-D7's
default (c) (the per-hash latency test under
`rust/shekyl-randomx-differential/tests/perf/per_hash_latency.rs`
consumes the same in-process C bindings the binary uses, which
requires the binary's binding-layer code to be reachable from an
integration test, which requires `[lib]`). The `[lib]` surface is
**not** a public-API surface intended for downstream consumers
beyond the harness's own tests; the crate's `Cargo.toml`
publish-policy stays `publish = false` per
[`25-rust-architecture.mdc`](../../.cursor/rules/25-rust-architecture.mdc)
workspace-internal artifact discipline.

**Crate-name pin.** `shekyl-randomx-differential` per parent plan
§7 line 248 framing ("differential test harness"). The
`shekyl-` prefix matches the workspace convention; the
`-randomx-` qualifier matches the `shekyl-pow-randomx` /
`randomx-v2-sys` (R1-D2) sibling-crate naming; the `-differential`
suffix names the harness's specific role (vs. the
unprefixed `shekyl-randomx-pow` which would invite confusion with
the verifier crate).

**Reversion clause.**

- *Rejection.* Single-crate placement under
  `shekyl-pow-randomx/` (§2.7-rejected) or under-`tools/`
  placement outside `rust/` (rejected by workspace-boundary
  convention).
- *Reopening criteria.* Reopen if a future workspace-wide
  crate-count budget per
  [`25-rust-architecture.mdc`](../../.cursor/rules/25-rust-architecture.mdc)
  requires consolidating
  `shekyl-randomx-differential` + `randomx-v2-sys` (R1-D2) +
  potentially other harness siblings into a single
  `shekyl-randomx-test-infra` umbrella crate; the consolidation
  preserves §1.4 invariant cleanliness per Pattern C
  exemption. Or reopen if R1-D2 disposition shifts to (a)
  bindgen-at-build-time, which structurally re-shapes the
  bindings-crate surface (bindgen-output crate vs.
  hand-written shim crate is a different scope-per-crate
  question).
- *Re-evaluation shape.* Round-2 design-round entry with
  workspace-state evidence (crate count at the time;
  consolidation candidates enumerated) per
  [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
  A4 sub-PR boundary reversion clause.

### R1-D2 — C-side bindings

**Decision.** How does the harness call into `shekyl_randomx_v2`
(the IMPORTED static-library target from
[`external/CMakeLists.txt`](../../external/CMakeLists.txt) line
204)?

**Options.**

- **(a)** Hand-written `extern "C"` declarations + `build.rs`
  linker directives.
- **(b)** `bindgen` at build-time.
- **(c)** Prebuilt `randomx-v2-sys`-shaped sub-crate that owns
  the `extern "C"` block + linker directives; the
  differential-harness crate depends on this sub-crate for the
  unsafe surface.

**Criteria.**

- Minimize `unsafe` surface (per
  [`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc),
  [`25-rust-architecture.mdc`](../../.cursor/rules/25-rust-architecture.mdc),
  and the
  [`shekyl-ffi` localization principle](./RANDOMX_V2_PHASE2F_PLAN.md)
  from Phase 2F Decision #5).
- Avoid generating bindings for symbols outside the canonical
  consumed-export list (per `RANDOMX_V2_RUST.md` §7.1 + the
  minimal subset enumerated in §1.7 above:
  `randomx_alloc_cache`, `randomx_init_cache`, `randomx_create_vm`,
  `randomx_calculate_hash`, `randomx_destroy_vm`,
  `randomx_release_cache`, `randomx_get_flags`).
- Keep bindings reviewable — a hand-written ≤50-LOC `extern "C"`
  block is auditable line-by-line against
  [`external/randomx-v2/src/randomx.h`](../../external/randomx-v2/src/randomx.h);
  a `bindgen`-generated binding emits the entire visible C surface
  unless filtered, expanding the audit and tying the harness's
  unsafe footprint to bindgen's output stability.
- Per [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc),
  introducing `bindgen` as a workspace `[build-dependencies]`
  entry requires a justification against the workspace's
  dependency-additions cost; the cited consumer is one harness
  crate, which makes (b) hard to justify against (a) and (c).

**Default expectation.** (c) — `randomx-v2-sys` sub-crate with
hand-written `extern "C"` declarations + `build.rs` linker
directives. The sub-crate has the absolute minimum unsafe surface
(7 export declarations); the harness crate depends on it via path
dependency and stays Rust-side. R1-D13 closes the relationship of
this sub-crate to the Phase 2F crate-invariant grep gate.

**Reopen criterion (sketch for Round 1).** Reopen if the canonical
C export list grows beyond ≤10 symbols (bindgen's auditability
relative advantage grows with surface size); not anticipated for
2g's scope (light-mode VM only; no dataset-side calls).

#### Round 1 disposition (closes R1-D2)

**Close at default expectation.** C-side bindings are (c) — a
Shekyl-introduced `randomx-v2-sys` sub-crate at
`rust/randomx-v2-sys/` carrying 7 hand-written `extern "C"`
declarations + `build.rs` linker directives.

**Substrate-anchored rationale.** (a) bindgen-at-build-time is
rejected on auditability — bindgen output is generated code that
varies per bindgen version, and an audit cycle would have to
re-verify the generated declarations match the C header at every
bindgen-version bump; for a 7-symbol surface, the audit cost of
hand-written declarations is one-time per fork-pin (per §1.7
maintenance pin) versus per-bindgen-version. (b) inline `extern
"C"` in the harness crate is rejected on §1.4-invariant-script
extensibility — Pattern C (no `extern "C"` in source trees) would
need a per-file exemption inside the harness crate, contradicting
the invariant's "binary 'present' or 'absent'" shape rather than
"present with per-file exemptions." (c)'s sub-crate localizes the
`extern "C"` to one source file whose sole purpose is the
declarations, audit-bounded against the C header at the pinned
fork commit.

**Canonical 7-symbol pin (matches the §1.7 enumeration).**

```rust
extern "C" {
    fn randomx_alloc_cache(flags: c_uint) -> *mut RandomxCache;
    fn randomx_init_cache(cache: *mut RandomxCache, seed: *const c_void, seed_size: usize);
    fn randomx_release_cache(cache: *mut RandomxCache);
    fn randomx_create_vm(flags: c_uint, cache: *mut RandomxCache, dataset: *mut RandomxDataset) -> *mut RandomxVm;
    fn randomx_destroy_vm(vm: *mut RandomxVm);
    fn randomx_calculate_hash(vm: *mut RandomxVm, input: *const c_void, input_size: usize, output: *mut c_void);
    fn randomx_get_flags() -> c_uint;
}
```

The signatures match
[`external/randomx-v2/src/randomx.h`](../../external/randomx-v2/src/randomx.h)
at fork-pin `aaafe71` (verified at Round-1-close; the §1.7
maintenance pin requires re-verification on fork-pin advance).
Dataset-side symbols (`randomx_alloc_dataset`,
`randomx_init_dataset`, `randomx_dataset_item_count`) are *not*
declared — 2g exercises light-mode VM only; declaring unused
symbols invites a future caller to use them without re-auditing
the scope-vs-fork-pin assumption.

**Reversion clause.**

- *Rejection.* bindgen-at-build-time (a) or inline `extern "C"`
  in the harness crate (b); both rejected per the substrate-anchored
  rationale above.
- *Reopening criteria.* Reopen toward (a) if the canonical C
  export list grows beyond ≤10 symbols (bindgen's auditability
  advantage grows with surface size); reopen toward (b) if the
  workspace consolidation reversion-clause in R1-D1 fires, in
  which case the consolidated umbrella crate absorbs the
  `extern "C"` and the invariant script's per-crate exemption
  shape needs to be re-evaluated (the (b)-shape would then be
  "harness crate carries the extern `C` declarations and is
  per-crate-exempt from Pattern C," structurally equivalent to
  today's (c)).
- *Re-evaluation shape.* Round-N design-round entry that names
  the new symbol count or the consolidation trigger; per
  [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)
  the disposition's API-existence-verification step is
  re-anchored against the new fork-pin's `randomx.h`.

**Fork-pin coupling cross-reference.** Per §1.7 fork-pin coupling
maintenance pin (Round 0 calibration item 3): any future PR
advancing the `external/randomx-v2` fork pin verifies these 7
declarations against the new pin's `randomx.h`. The verification
step is the PR-description discipline, not a Round-1-closeable
gate.

### R1-D3 — CMake wiring for `BUILD_RANDOMX_V2_MINER_LIB`

**Decision.** How does the harness build flip
`BUILD_RANDOMX_V2_MINER_LIB=ON` (currently default-OFF per
[`CMakeLists.txt`](../../CMakeLists.txt) line 503)?

**Options.**

- **(a)** Auto-flip ON when the harness binary is being built
  (CMake-side conditional).
- **(b)** Require the developer/CI to pass it explicitly
  (`-DBUILD_RANDOMX_V2_MINER_LIB=ON`).
- **(c)** Add a separate `BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS`
  option (defaulting OFF; required for the harness to build at
  all) that implies `BUILD_RANDOMX_V2_MINER_LIB=ON` when set.

**Criteria.**

- Multi-config-generator constraint: per
  [`external/CMakeLists.txt`](../../external/CMakeLists.txt)
  line 123, combining `BUILD_RANDOMX_V2_MINER_LIB=ON` with a
  multi-config generator currently `FATAL_ERROR`s. The
  per-`CONFIG` install-path follow-up is queued in
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) line 3684 (V3.x
  Phase 2 target). Either (i) single-config CI runners are
  required, or (ii) the per-`CONFIG` FOLLOWUPS entry is
  escalated to V3.0 ahead of 2g.
- The harness build cost (out-of-tree `ExternalProject_Add`
  build of `external/randomx-v2/`) is ≥30s on a clean checkout;
  auto-flipping it ON for every CMake configure that *might*
  build the harness imposes that cost on developers who
  weren't asking for it. (c) makes the cost opt-in.

**Default expectation.** (c) — separate
`BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS` option that implies
`BUILD_RANDOMX_V2_MINER_LIB=ON` when set; default OFF. Mirrors
the precedent of the Phase 1 `BUILD_RANDOMX_V2_MINER_LIB` shape
(opt-in option; default OFF; explicit consumer). Single-config CI
runner requirement (constraint (i) above) is the §9 CI default;
the per-`CONFIG` escalation is deferred to V3.x.

**Reopen criterion (sketch for Round 1).** Reopen if multi-config
CI coverage becomes a 2g requirement (e.g., the V3.0 Windows
build requires Visual Studio multi-config); the per-`CONFIG`
FOLLOWUPS entry then escalates to V3.0 ahead of 2g.

#### Round 1 disposition (closes R1-D3)

**Close at default expectation.** CMake wiring is (c) — new
top-level option `BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS`,
default OFF, which sets `BUILD_RANDOMX_V2_MINER_LIB=ON` when
enabled and triggers the harness crate build in the Rust side.

**Substrate-anchored rationale.** (a) auto-flip is rejected on
opt-in discipline grounds — the §1.7 fail-fast disposition
(combining `BUILD_RANDOMX_V2_MINER_LIB=ON` with a multi-config
generator refuses with `FATAL_ERROR`) is built around explicit
opt-in semantics; an auto-flip muddles "which CMake invocations
trigger the multi-config refusal" because the trigger becomes
implicit. (b) require-explicit is rejected on ergonomic and
contract-coupling grounds — CI scripts would need to pass both
`BUILD_RANDOMX_V2_MINER_LIB=ON` *and* a separate
"harness-is-enabled" trigger, and a developer who passes only
`BUILD_RANDOMX_V2_MINER_LIB=ON` (the Phase 1 documented option)
gets the miner lib built but no harness, which is a confusing
no-op state. (c) collapses both into one opt-in surface:
`-DBUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON` is sufficient and
unambiguous.

**Option pin.**

- Top-level CMake option in
  [`CMakeLists.txt`](../../CMakeLists.txt) (alongside the
  existing `BUILD_RANDOMX_V2_MINER_LIB` at line 503).
- Default OFF (matches Phase 1's `BUILD_RANDOMX_V2_MINER_LIB`
  default-OFF discipline; preserves daemon-build byte-equivalence
  per Phase 1 §4.1 contract).
- When ON, sets `BUILD_RANDOMX_V2_MINER_LIB=ON` via CMake's
  `option()` + `set()` pattern (Phase 1 substrate convention).
- When ON, also wires Rust-side: the harness crate's `build.rs`
  detects the option via an environment variable
  (`SHEKYL_BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=1` exported
  from CMake's `add_custom_target`) and gates the
  `randomx-v2-sys` (R1-D2) `cargo build` step accordingly.

**Single-config-generator constraint inheritance.** Per §1.7 +
[`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) line 3684, the
`ExternalProject_Add` shape does not yet support per-`CONFIG`
install paths or per-`CONFIG` `IMPORTED_LOCATION`; multi-config
generators (Visual Studio, Xcode, Ninja Multi-Config) are
refused with `FATAL_ERROR` when `BUILD_RANDOMX_V2_MINER_LIB=ON`.
The new `BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON` inherits the
refusal transitively (because it implies `BUILD_RANDOMX_V2_MINER_LIB=ON`);
single-config-generator (Ninja, Make) is the only supported CI +
local-dev configuration.

**Reversion clause.**

- *Rejection.* (a) auto-flip rejected on fail-fast-clarity;
  (b) require-explicit rejected on ergonomic-and-coupling.
- *Reopening criteria.* Reopen toward (a) if the §1.7
  fail-fast disposition is itself revisited (per the
  per-`CONFIG` FOLLOWUPS entry escalation to V3.0, which would
  re-shape the multi-config-generator refusal); reopen toward
  (b) if downstream CI moves to a two-stage configure
  pattern that benefits from the explicit decoupling.
- *Re-evaluation shape.* Per
  [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) line 3684 escalation
  event triggers a Phase 2g amendment design-round that
  re-evaluates this disposition against the new
  multi-config-generator support.

### R1-D4 — Random corpus shape

**Decision.** What is the "sampled set of `(seedhash, data)`
inputs" shape (per parent-plan 2g todo: "asserts byte equality
across a corpus of `(seedhash, data)` inputs"; per 2c §5.11.5
leg 3 framing)?

**Options.**

- **(a)** Deterministic ChaCha20-seeded PRNG over a fixed test
  seed; corpus is generated at runtime from the seed,
  reproducible across hardware.
- **(b)** Committed fixture file (e.g.,
  `tests/vectors/reference/randomx_v2/differential_corpus.bin`)
  containing the (seedhash, data) pairs verbatim.
- **(c)** Wall-clock entropy (rejected by construction — fails
  the reproducible-failure-analysis criterion; a CI failure
  cannot be reproduced locally without an entropy-snapshot
  mechanism that defeats the simplicity gain).

**Criteria.**

- Reproducible failure analysis: a CI byte-equality failure must
  be reproducible from a local `cargo` invocation with the same
  inputs; (a) achieves this via the seed; (b) achieves it via
  the committed bytes; (c) fails it.
- Storage cost: (b) commits the corpus to the repo (potentially
  KiB–MiB-scale for 1024+ pairs); (a) computes at runtime from a
  ~32-byte seed.
- Provenance: (b) makes the corpus visible in the diff; (a)
  makes it visible in the seed + the generator source.

**Pins required for Round 1.** Corpus size (parent plan §6
line 243 names N=1024 for the per-PR per-hash median benchmark,
but the byte-equality corpus has a separate sizing question);
data-length distribution (block-template-shaped — bimodal
around the 600 KiB effective cap and 76-byte header sizes — vs.
uniform over [0, 2 MiB]); deterministic-test-seed value (Round
1 names it explicitly so failures are reproducible from the
seed alone).

**Default expectation.** (a) — deterministic ChaCha20-seeded
PRNG. Corpus size, data-length distribution, and seed value
pinned by Round 1.

**Reopen criterion (sketch for Round 1).** Reopen if the
ChaCha20 dependency cost (workspace addition + audit) is judged
unjustified relative to a hand-rolled SplitMix64 or similar; the
choice of PRNG is implementation-detail to (a) but a
sub-disposition Round 1 closes for reproducibility.

#### Round 1 disposition (closes R1-D4)

**Close at default expectation.** Random corpus is (a) —
deterministic `rand_chacha::ChaCha20Rng` over a fixed 32-byte
test seed; corpus generated at runtime from the seed.

**Dependency-discipline check (per
[`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)).**
`rand_chacha = "0.3"` is already a workspace dependency
(verified at Round 1 close against `rust/shekyl-crypto-pq/Cargo.toml:13`,
`rust/shekyl-fcmp/Cargo.toml:39,50`,
`rust/shekyl-engine-core/Cargo.toml:105`). No new workspace
dependency is introduced; the harness crate's `Cargo.toml`
adds `rand_chacha = "0.3"` as a direct dep (workspace-state
reuse). Test-only use; no cryptographic property attached (the
PRF is for test-corpus determinism, not for any secret-derivation
surface).

**F2 numeric pins (corpus shape per cadence).** The R1-D12 (c)
split-cadence (per F2 finding in Round 1's adversarial pass)
makes the corpus shape cadence-stratified:

| Cadence | Seedhash count | Data values per seedhash | Total hashes | Reference-machine wall-clock |
|---------|---------------|--------------------------|--------------|------------------------------|
| Per-PR byte-equality | 16 | 8 | 128 | ~96 s hash + ~2 min cache-derive = **~3.5 min** |
| Nightly full corpus | 32 | 32 | 1024 | ~5.3 min hash + ~4 min cache-derive = **~9 min** |

The numbers are anchored against
[`rust/shekyl-pow-randomx/BENCH_RESULTS.md`](../../rust/shekyl-pow-randomx/BENCH_RESULTS.md)
Phase 2c baseline on the reference machine (Intel i9-11950H @
2.60 GHz; C reference ~12 ms/hash; Rust ~296 ms/hash;
cache-derive ~341 ms). Per F5 (R1-D12 close) the CI runner class
is `ubuntu-latest` (4 vCPU); wall-clock scales by the runner's
single-thread performance vs. reference machine — the
release-gate cadence is the ground truth for runner-vs-reference
adjustment per the parent §6 line 238 framing.

**Data-length distribution pin.** Block-template-shaped bimodal:
~50% of data values draw from `Uniform(64, 200)` bytes
(block-header-shaped; matches real `compute_hash` inputs for
PoW verification), ~50% draw from `Uniform(200, 600 * 1024)`
bytes (larger block-template-shaped; exercises the
`data_len <= RANDOMX_BLOCK_TEMPLATE_MAX_SIZE` boundary at
`parent §6 line 234`'s 2 MiB ceiling without grinding against
the ceiling itself). Uniform-over-[0, 2 MiB] is rejected
because >99% of real `compute_hash` inputs are header-shaped;
the random corpus mirroring realistic-input distribution
catches divergences in the common-input path before grinding
against the rare-path corpus (R1-D5) catches the
rare-path-specific divergences.

**Deterministic test-seed pin.** 32-byte ChaCha20Rng seed:

```
"shekyl-randomx-differential-corpus-v1\x00"  // padded to 32 bytes
```

The seed string is recorded in the harness source file as a
named constant
(`pub const RANDOM_CORPUS_SEED_V1: [u8; 32] = ...`) with the
`-v1` suffix anchoring the reversion-clause: a future R1-D4
reopen toward a different distribution lands as `RANDOM_CORPUS_SEED_V2`
in a new constant, leaving the v1 seed intact for historical
reproduction.

**Reversion clause.**

- *Rejection.* Wall-clock entropy (c) rejected by construction;
  committed-fixture-file (b) rejected on the diff-surface cost
  for 1024+ pairs at ~ (32 + 600KiB) per pair ≈ 600 MiB
  fixture-size (b) imposes on the repo, vs. (a)'s 32-byte seed
  + generator source.
- *Reopening criteria.* Reopen if (i) the ChaCha20 dependency
  is removed from the workspace (substrate-change in
  workspace-state per
  [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc));
  (ii) the per-PR or nightly wall-clock budget tightens
  (e.g., a CI runner-class change cuts the per-job budget) and
  the corpus shape needs re-sizing; (iii) the
  data-length-distribution assumption (block-template-shaped
  bimodal) is invalidated by a Shekyl-side dynamic-block-size
  change (per parent §6 line 234's 2 MiB ceiling reversion
  clause).
- *Re-evaluation shape.* Per
  [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
  A5 forward-action propagation: the re-sizing or
  distribution-change lands in the harness crate's
  `RANDOM_CORPUS_SEED_V2` constant + a Round-N design-doc
  entry naming the new pin's substrate evidence.

### R1-D5 — Adversarial seedhash corpus (per 2c §5.11.5)

**Decision.** How are the 5–10 adversarial seedhashes constructed
that produce programs heavy in CFROUND, FDIV_M, cache-miss-shaped
scratchpad access, and CBRANCH dispatch (per §2.1 above)?

**Options (per-seedhash methodology).**

- **(a)** **Grinded.** Search seedhashes whose
  generator-produced programs are pathological per the named
  classes — costly (potentially minutes-to-hours of compute per
  class) but reproducible by recording the seedhash bytes.
- **(b)** **Constructed.** Use the program-generation seed
  structure to back-derive a seedhash that produces a target
  program shape — fast but spec-coupled (the back-derivation
  depends on the AES-1R generator's structure; a future spec
  amendment that changes the generator invalidates the
  construction).

Either methodology must produce a seedhash that, when run
through the production `Cache::derive` + `compute_hash` pipeline
(not a generator shortcut), exercises the target rare path.

**Criteria.**

- Reproducibility: both (a) and (b) produce a seedhash that the
  corpus stores as 32 hex bytes; reproducibility is the same.
- Cost: (a) is one-shot at corpus-generation time, then cached;
  (b) is cheap at any time but requires maintaining the
  back-derivation code.
- Spec-coupling: (a) is generator-agnostic (any future generator
  changes find a different pathological seedhash, but the
  *methodology* of grinding stays valid); (b) couples the
  corpus-generation logic to the v2 generator's structure.

**Pins required for Round 1.** Methodology (a / b); per-class
targets (which class each of the 5–10 seedhashes targets;
weighting); storage shape (committed-bytes hex array vs.
computed-at-test-time via the grinding script). Per
[`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md)
§5.11.5: "The criteria for 'this seedhash is adversarial
enough to include' are part of 2g's Round 1."

**Default expectation.** (a) — grinded, committed as hex bytes
under `rust/shekyl-randomx-differential/src/adversarial_corpus.rs`
or analogous. Per-class breakdown (5–10 seedhashes split across
the four classes: CFROUND, FDIV_M, cache-miss, CBRANCH) is
Round 1's responsibility. Spec-coupling cost of (b) is
substrate-anchored against the V4 lattice transition: the v2
generator is stable until V4; if (b) re-derives at V4 time,
the cost is comparable to maintaining (a)'s grinding script.

**Reopen criterion (sketch for Round 1).** Reopen if grinding
cost exceeds the substrate's budget (Round 1 records the
grinding wall-time on the reference machine; if the wall-time
is >1 day for 5–10 seedhashes, the substrate-anchored disposition
reopens toward (b)).

#### Round 1 disposition (closes R1-D5)

**Close at default expectation.** Adversarial corpus is (a) —
grinded, committed as hex bytes under
`rust/shekyl-randomx-differential/src/adversarial_corpus.rs`
(seedhash hex bytes + per-class rationale comments) and the
grinding tool lives at
`rust/shekyl-randomx-differential/tools/grind_adversarial_corpus.rs`
as a separate binary (run on demand, not on every CI invocation).

**F3 grinding budget pin (Round 1's adversarial-pass
substrate-anchoring).** Round 0's reopen-criterion sketch named
"if wall-time is >1 day"; the actual substrate-anchored budget
is much smaller. Per `configuration.h:88–125`'s
`RANDOMX_FREQ_*` distribution (verified at 2d R6-D2;
substrate-anchored against `bytecode_machine.hpp:67–98`),
grinding for a class-heavy program (≥40% combined opcodes in
the targeted class) is rejection-sampling at ~1/256 per random
seedhash; 5–10 heavy seedhashes across the four classes ≈
**~1280–2560 grinds × ~300 ms = ~6–13 minutes** total grinding
wall-clock on the reference machine. The grinding-tool budget
is pinned at **4 hours wall-clock on the reference machine**
(intel-i9-11950H baseline; ~18× headroom for "heavy" being more
selective — e.g., combined CFROUND+FDIV_M+CBRANCH ≥60% rather
than single-class ≥40%); the tool aborts with a
substrate-anchored error message if it exceeds the budget.

**Per-class targets pin (5–10 seedhashes across four classes).**

| Class | Target opcode pattern | Seedhash count (min–max) |
|-------|----------------------|--------------------------|
| CFROUND-heavy | ≥40% CFROUND opcodes per program | 1–2 |
| FDIV_M-heavy | ≥40% FDIV_M opcodes per program | 1–2 |
| Cache-miss-heavy | ≥40% scratchpad-access opcodes with stride > L2 cache size | 1–2 |
| CBRANCH-heavy | ≥40% CBRANCH opcodes per program | 1–2 |
| Combined-heavy | ≥60% combined CFROUND + FDIV_M + cache-miss + CBRANCH | 1–2 |

Total: 5–10 seedhashes. Each commit-time seedhash entry records
(i) the seedhash hex bytes, (ii) the per-class opcode-frequency
statistics measured at grind time, (iii) the run-cost on the
reference machine.

**Storage shape.** Hex bytes committed as a Rust source array
(`pub const ADVERSARIAL_CORPUS_V1: &[(SeedHashBytes, &str)]`)
with per-class tagging comments. No fixture file under
`tests/vectors/reference/` (the adversarial corpus is harness-internal,
not a spec-reference vector).

**Reversion clause.**

- *Rejection.* (b) constructed rejected on spec-coupling cost —
  the back-derivation depends on the AES-1R generator's
  structure, which is V4-coupled (a V4 generator amendment
  invalidates every committed back-derivation seedhash); (a)'s
  grinding is V4-decoupled (the grinding tool re-runs at V4
  time against the V4 generator with no spec-shape coupling).
- *Reopening criteria.* Reopen toward (b) if (i) the grinding
  tool exceeds the 4-hour wall-clock budget on the reference
  machine (substrate-change in grinding-cost); (ii) the V4
  lattice transition produces a generator whose grinding-cost
  is comparable to (b)'s back-derivation cost (substrate-change
  in the spec-coupling-cost-vs-grinding-cost calculus); (iii)
  a future Shekyl-side spec amendment changes the generator
  structure (in which case (b)'s back-derivation can re-derive
  the committed seedhashes without re-running grinding).
- *Re-evaluation shape.* Per
  [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
  A4 sub-PR boundary reversion: a Round-N design-round entry
  with the substrate evidence (the grinding wall-time on the
  reference machine; the V4 substrate-change name) and the
  amended methodology (per-class regrind vs. (b)
  back-derivation).

### R1-D6 — u128 / `__int128_t` edge-case corpus (per 2d §3.4 + 2c §5.11 Objective 6)

**Decision.** How is the adversarial corpus extended with inputs
driving div-by-zero, signed-div overflow, shift-by-width, and
`u128 * u128` truncation high-half (per §2.3 above)?

**Options.** Same option set as R1-D5 (grinded vs. constructed);
same outputs (seedhash list + per-class rationale + committed-bytes
hex array vs. computed-at-test-time).

**Criteria.** Per §2.3's "C reference's UB is itself the consensus
rule" disposition: a Rust/C divergence at one of the four edge-case
classes is itself an audit finding (one of 2d's rows in the
§3.4 audit table is wrong; or the C reference's UB is non-deterministic
and the consensus rule needs to be re-anchored). The corpus must
exercise each enumerated class with reachable inputs (per 2d's
"audit every opcode handler" discipline).

**Pins required for Round 1.** Per-class methodology (grinded vs.
constructed; same shape as R1-D5); the per-class targets — at least
one seedhash per class drives at least one opcode handler that
reaches the edge case under the corpus's data-length distribution.

**Default expectation.** Same as R1-D5: (a) grinded, committed as
hex bytes. Adversarial-corpus extension lands in the same file
(`adversarial_corpus.rs` or analogous) with per-class tagging.

**Reopen criterion (sketch for Round 1).** Same as R1-D5.

#### Round 1 disposition (closes R1-D6)

**Close at default expectation.** u128 edge-case corpus is (a) —
grinded, committed as hex bytes in the same source file as the
adversarial corpus (`rust/shekyl-randomx-differential/src/adversarial_corpus.rs`),
extended with per-class tagging for the four u128 edge classes.

**Per-class targets pin (≥1 seedhash per class; 4 minimum).**

| Edge class | Target opcode handler | Reach criterion |
|------------|----------------------|-----------------|
| div-by-zero IMUL_RCP / IDIV | IMUL_RCP w/ imm32=0; IDIV w/ divisor=0 in the dispatch path | At least one program instruction reaches the edge under the corpus's data-length distribution; verified at grind time by per-iteration opcode-trace instrumentation in the grinding tool only. |
| signed-div overflow | IDIV w/ `INT_MIN / -1` | Same. |
| shift-by-width | ISHIFT_L / ISHIFT_R w/ shift count = 64 (mod 64 yields 0; UB in C for `<<` if >= width — handled per 2d §3.4) | Same. |
| `u128 * u128` truncation high-half | IMUL_HM / ISMULH_M / IMULH_R / ISMULH_R w/ inputs producing non-zero high-half | Same. |

The 4-minimum is per-class (`>=1` seedhash exercising the
class); the maximum is bounded by the R1-D5 5–10 total
adversarial-corpus budget. The R1-D5 + R1-D6 corpus
intersection: if a single grinded seedhash exercises both an
R1-D5 class (e.g., CBRANCH-heavy) and an R1-D6 class (e.g.,
ISMULH_M high-half-nonzero), it counts toward both budgets.

**Grinding-tool extension.** The R1-D5 grinding tool
(`grind_adversarial_corpus.rs`) extends with per-edge-class
criteria (the four classes above). Same wall-clock budget
(4 hours per F3 pin); per-class grind cost is bounded by the
RANDOMX_FREQ_* distribution at `configuration.h:88–125` (the
edge-reach probability per program-iteration drives the
rejection-sampling rate; per 2d's audit-against-actual-code
discipline the grinding-tool criteria cite the substrate line
at audit pin).

**Hand-crafting fallback rejection.** Hand-crafting (an
alternative R1-D6 sub-option, *not* in the R1-D5 option set)
was considered: build a synthetic seedhash whose generator
output is constructed-to-include the edge case. Rejected on
the same spec-coupling cost (b) is rejected on: the synthetic
construction depends on the generator's hashing-to-bytecode
structure, which is V4-coupled. The (a) grinding approach
catches the edge cases by exhaustive search, V4-decoupled.

**Reversion clause.**

- *Rejection.* Same as R1-D5: (b) constructed and synthetic
  hand-crafting rejected on spec-coupling cost.
- *Reopening criteria.* Same as R1-D5; additionally, reopen
  toward synthetic hand-crafting if grinding fails to find
  reachable seedhashes for a given edge class within the
  4-hour budget *and* the spec-coupling cost is judged
  acceptable for the missing class (e.g., shift-by-width
  edges are spec-rare and may justify a per-class
  hand-crafted seedhash).
- *Re-evaluation shape.* Same as R1-D5.

### R1-D7 — Per-hash latency benchmark population (per 2c §13 R3-minor-2)

**Decision.** How does 2g populate the placeholder body at
[`rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs`](../../rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs)?
The placeholder asserts the Rust/C ratio ≤ 3.0× per parent plan §6.

**Options.**

- **(a)** Populate via the differential-harness binary as an
  in-process call (test invokes harness binary as subprocess and
  reads its output).
- **(b)** Duplicate the C-side bindings inside the test file
  (couples the test to bindgen output; bypasses R1-D2's R1-E1
  invariant by introducing `extern "C"` declarations into
  `shekyl-pow-randomx/tests/`).
- **(c)** Move the test under the harness crate and have it
  consume both Rust and C in-process (cleanest, but requires
  the harness crate to expose a test-harness library target —
  `[lib]` + `[[bin]]` — and requires deleting the
  `tests/perf/per_hash_latency.rs` placeholder from
  `shekyl-pow-randomx/` once the new home is wired).

**Criteria.**

- (b) is rejected by inspection: the crate-invariant grep gate
  (§1.4 above; Pattern C) forbids `extern "C"` in
  `rust/shekyl-pow-randomx/tests/`; (b) would require either
  weakening the gate (rejected per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
  "audits-are-clean-so-compress" anti-pattern) or adding a
  per-file exemption (architectural drift).
- (a) is straightforward but introduces subprocess-overhead noise
  to the latency measurement; depending on N (1024 hashes per
  parent §6) the subprocess startup cost is ~5–10 ms, dominated
  by the ~300 ms per-hash full-pipeline cost, but the
  measurement-noise budget for a ≤3.0× ratio gate is non-trivial.
- (c) eliminates subprocess overhead; requires the harness crate
  to expose `[lib]` such that an integration test under
  `rust/shekyl-randomx-differential/tests/perf/per_hash_latency.rs`
  can consume both `shekyl_pow_randomx::compute_hash` and the
  C-side `randomx_calculate_hash` via the same in-process
  symbol resolution the harness binary uses.

**Pins required for Round 1.**

- Which side runs first to avoid CPU-cache-warmth bias (e.g.,
  interleave Rust/C calls per-iteration vs. run all N Rust then
  all N C; the latter favors whichever ran second).
- Iteration count: parent plan §6 line 243 names N=1024 hashes.
- Median vs. mean: parent plan §6 line 243 names median.

**Default expectation.** (c) — move the test under the harness
crate; delete the `shekyl-pow-randomx/tests/perf/per_hash_latency.rs`
placeholder once the new home is wired. The harness crate's
`[[bin]]` target shares code with a `[lib]` target so the test
can consume the same in-process bindings as the binary.

**Placeholder end-of-life audit-trail pin.** Phase 2c §13
R3-minor-2 created the placeholder pending 2g implementation
(see [`rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs`](../../rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs)
+ [`rust/shekyl-pow-randomx/Cargo.toml`](../../rust/shekyl-pow-randomx/Cargo.toml)
lines 149–159). 2g's R1-D7 disposition (c) is the **planned
end-of-life** for the placeholder, not architectural drift —
the placeholder's removal is the substrate change R1-D7 (c)
records. The implementation-PR commit message that performs
the deletion cites "closes Phase 2c R3-minor-2" so the audit
trail is mechanically grep-discoverable per
[`90-commits.mdc`](../../.cursor/rules/90-commits.mdc) "reference
the work the commit addresses." Per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
the placeholder's reversion-clause shape was always "delete on
2g's implementation"; 2g's R1-D7 (c) is the planned trigger
firing.

**Reopen criterion (sketch for Round 1).** Reopen if (c) requires
restructuring R1-D1 or R1-D13 in a way that re-litigates the
workspace-placement disposition.

#### Round 1 disposition (closes R1-D7)

**Close at default expectation.** Per-hash latency test
population is (c) — move under harness crate; delete the
placeholder at `rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs`
in the implementation PR. New location:
`rust/shekyl-randomx-differential/tests/perf/per_hash_latency.rs`
(integration test consuming the harness crate's `[lib]` surface
per R1-D1).

**Placeholder end-of-life audit-trail.** Per Round 0
calibration item 5, the implementation-PR commit message that
deletes the placeholder cites "closes Phase 2c §13 R3-minor-2"
so the audit trail is mechanically grep-discoverable per
[`90-commits.mdc`](../../.cursor/rules/90-commits.mdc). The
placeholder's reversion-clause shape per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
was always "delete on 2g's implementation"; this is the
planned trigger firing.

**Methodology pin (per parent §6 line 243 + Round 0
pins-required-for-Round-1).** N=1024 iterations per the parent
plan; **interleaved Rust/C per-iteration** (rather than
all-Rust-then-all-C) to amortize cache-warmth bias across the
two implementations symmetrically; median Rust / median C
asserted ≤ 3.0× per parent §6 line 237. Single fixed
seedhash + 1024 fixed deterministic data values per
R1-D4's ChaCha20Rng-seeded shape (a sub-sample of the per-PR
corpus, *not* the adversarial corpus per R1-D5 — average-case
latency, not worst-case ratio).

**Cadence pin.** Pre-Phase-3a (i.e., 2g): test runs in the
harness binary, no CI gate per parent §6 line 243 framing
("Phase 2g produces the harness binary that the per-PR CI
mechanism then consumes; the gate activates when the FFI shim
makes per-PR regressions reachable from C++ callers"). Per
R1-D12 (c) cadence: the per-hash latency test runs in the
nightly job (cadence-anchored to surface latency regressions
in the harness's own evolution before the Phase 3a gate
activates).

**Reversion clause.**

- *Rejection.* (a) populate body in current `shekyl-pow-randomx/tests/perf/`
  location rejected on §1.4 Pattern C (the test would need to
  link `randomx-v2-sys`, which carries `extern "C"`); (b)
  populate body in `shekyl-pow-randomx/benches/` rejected on
  the same Pattern C exemption issue.
- *Reopening criteria.* Reopen if R1-D1 reverts toward
  single-crate consolidation (the test relocates with the
  consolidation); or if R1-D13 reverts toward Pattern C
  per-file exemption (a (b)-shape becomes viable with the
  per-file exemption).
- *Re-evaluation shape.* Per A4 sub-PR boundary reversion: a
  Round-N design-round entry citing R1-D1 or R1-D13 reopen
  evidence.

### R1-D8 — Worst-case ratio measurement (per parent §6 Round 4)

**Decision.** Where does the worst-case ≤5.0× ratio test live?
Per parent §6 Round 4: ≤5.0× on adversarial inputs,
release-gate-suite cadence.

**Options.**

- **(a)** Same harness binary, separate subcommand
  (`--mode=worst-case`); release-gate suite invokes the
  subcommand.
- **(b)** Separate test file with `#[ignore]` opt-in (release-gate
  suite invokes `cargo test -- --ignored`).
- **(c)** Release-gate-only CI workflow (separate `.github/workflows/`
  file) invoked on release-tag PRs.

**Criteria.**

- Discoverability: developers should find the worst-case test
  by grepping the harness crate; (a) and (b) keep it in the
  harness; (c) splits to CI-only.
- Cost: worst-case measurement runs against the adversarial
  corpus (R1-D5 + R1-D6 union; size TBD by Round 1's corpus
  sizing); per-iteration cost is the full ~300 ms per-hash
  pipeline; total cost is corpus-size × 300 ms (per-side; ×2 for
  Rust + C).
- Cadence: parent §6 names release-gate cadence; per-PR is
  excluded by construction.

**Pins required for Round 1.** Which adversarial corpus this
runs against (R1-D5 + R1-D6 union vs. subset); whether the
worst-case ratio is reported as a single max-over-corpus number
or a per-class breakdown (CFROUND / FDIV_M / cache-miss /
CBRANCH plus the four u128 edge-case classes);
`BENCH_RESULTS.md` table shape for the worst-case ratio entry.

**Default expectation.** (a) — same harness binary, separate
subcommand. R1-D12's release-gate CI workflow invokes the
subcommand; per-PR CI does not.

**Reopen criterion (sketch for Round 1).** Reopen if the
worst-case wall-time exceeds the release-gate suite's budget;
(c) becomes the disposition with explicit cadence (e.g., weekly
scheduled run rather than every release-tag).

#### Round 1 disposition (closes R1-D8)

**Close at default expectation.** Worst-case ratio measurement
is (a) — same harness binary, separate subcommand
(`--mode=worst-case`); R1-D12's release-gate CI workflow
invokes the subcommand.

**Subcommand pin.** Harness binary command-line:

```
shekyl-randomx-differential --mode=byte-equality              # per-PR + nightly default
shekyl-randomx-differential --mode=byte-equality --corpus=adversarial   # nightly extension
shekyl-randomx-differential --mode=worst-case                 # release-gate only
shekyl-randomx-differential --mode=per-hash-latency           # nightly per R1-D7
shekyl-randomx-differential --mode=concurrent                 # per-PR per R1-D9
```

The mode-as-subcommand discipline shares C bindings, corpus
loading, and `PreparedCache` derivation across modes (each
mode's binary entry-point is a thin dispatcher into a
mode-specific function). Single binary; no inter-mode state
sharing (each mode initializes fresh state at entry).

**Adversarial corpus for worst-case (R1-D5 + R1-D6 union).**
The worst-case ratio runs against the R1-D5 adversarial
corpus (5–10 seedhashes, 4 R1-D5 classes + 1 combined-heavy)
+ R1-D6 u128 edge-case extensions (≥4 seedhashes, one per
class). Total: 5–10 + ≥4 ≤ 14 unique seedhashes (de-duplicated
if a seedhash exercises both R1-D5 and R1-D6 classes per
R1-D6's intersection note). Data values per seedhash: 16
(matching the F2 release-gate cadence pin).

**Per-class breakdown reporting.** Round 1 pins the
`BENCH_RESULTS.md` table shape for the worst-case ratio:

| Class | Seedhash hex (prefix) | C median (ms) | Rust median (ms) | Ratio | ≤5.0× target |
|-------|----------------------|---------------|------------------|-------|--------------|
| (per R1-D5 + R1-D6 class) | (8-char prefix) | (measured) | (measured) | (computed) | PASS / FAIL |

Plus an aggregate row: `max(ratio over all rows) ≤ 5.0×`. The
harness binary writes the table directly to a file path
specified by `--output BENCH_RESULTS_WORSTCASE.md` (the
release-gate CI workflow then commits the result as part of
the release-tag artifact pipeline).

**Reversion clause.**

- *Rejection.* (b) `#[ignore]`-gated test rejected on
  discoverability — a developer grepping for "worst-case"
  finds the test but the `#[ignore]` shape makes the
  invocation convention non-obvious; (c) separate CI workflow
  rejected on duplication — the workflow has to redeclare
  `BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON` and the
  ExternalProject build, doubling the CI surface for a
  cadence-only difference.
- *Reopening criteria.* Reopen toward (c) if the
  release-gate wall-time exceeds the release-gate suite's
  budget (substrate-anchored against the actual suite budget
  at release time; the per-class breakdown above is small
  enough that this is unlikely); reopen toward (b) if the
  shared-binary contract under R1-D9's concurrent mode proves
  error-prone (cross-mode state sharing surface bug → split
  per mode).
- *Re-evaluation shape.* Per A4 sub-PR boundary reversion: a
  Round-N design-round entry citing the budget-exceeded
  evidence or the cross-mode bug evidence.

### R1-D9 — Concurrent-call thread-safety test (per parent 2g todo)

**Decision.** What shape does the "concurrent-call test verifies
`CacheStore` thread-safety" test take (per parent plan 2g todo
on line 30)?

**Options.**

- **(a)** `std::thread::spawn` workers each calling
  `compute_hash` against a shared `CacheStore` populated with
  one canonical + transient slot.
- **(b)** `tokio` async runtime with `spawn_blocking` for the
  per-hash work.
- **(c)** `rayon` parallel iterator over the corpus.

**Criteria.**

- Dep-surface: (a) is `std`-only; (b) adds `tokio` (large dep);
  (c) adds `rayon` (smaller than tokio but still a workspace
  addition); per [`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc),
  the cited consumer is one test, which makes (b)/(c) hard to
  justify against (a).
- Realism: the daemon's parallel-verification fanout is
  threadpool-shaped per
  [`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md)
  §3.5 R1-D5 Round 1 substrate-correction — the daemon uses
  `tools::threadpool::getInstanceForCompute()` (Boost-shaped
  C++ threadpool); the closest Rust shape is `std::thread::spawn`
  in a fixed worker loop.
- Determinism: (a)/(b)/(c) all produce non-deterministic
  scheduling; success criterion is the *property* (no panic,
  no deadlock, byte-equality of each pair of hashes for the
  same input regardless of worker), not the scheduling.

**Pins required for Round 1.**

- Worker count: matches Phase 2F R1-D5's daemon parallel-verification
  fanout — `min(threadpool::getInstanceForCompute().get_max_concurrency(),
  m_max_prepare_blocks_threads) + 1` reserve (per
  [`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md)
  §3.5 R1-D5 Round 1 substrate-correction). Round 1 pins the
  numeric value (likely 4 + 1 = 5 on the reference machine).
- Iteration count per worker (per-worker hashes computed).
- **Correctness criterion:** no panic, no deadlock, byte-equality
  of each pair of hashes for the same `(seedhash, data)` input
  regardless of which worker computed it.
- **Adversarial criterion (Phase 2F F2 backstop).** Memory
  usage during concurrent execution stays bounded; no per-call
  `Arc<PreparedCache>` leak grows the resident set
  indefinitely. Measure RSS before the concurrent test and at
  steady-state during the test; assert the growth is bounded
  by `CacheStore`'s capacity-2 invariant per Phase 2F §4 F2
  disposition (≤ 2 × 256 MiB derived-cache holdings + a small
  per-worker working-set overhead for the `VmState` /
  `Scratchpad` per-call allocations, bounded by worker-count ×
  ~2 MiB scratchpad + register-file). Without the RSS-bound
  assertion the test verifies only the correctness criterion;
  with it the test backstops 2F's F2 disposition under load —
  the F2 mitigation (canonical non-eviction; transient
  displace-on-publish; `Arc` reach-through carrying live
  references) holds in single-threaded scenarios by
  construction, but a concurrent-load regression that
  accidentally retained `Arc`s beyond their derivation scope
  (e.g., a future caller-side cache or a leaked
  `lookup_or_derive` clone) would surface as RSS growth that
  the correctness criterion alone would not catch. Round 1
  pins the RSS-bound numeric ceiling against the chosen
  worker-count, the measurement methodology (`/proc/self/statm`
  vs. equivalent platform primitive), and the assertion
  tolerance band.

**Default expectation.** (a) — `std::thread::spawn` workers.
Minimizes dep surface; matches the daemon's threadpool-shaped
fanout more closely than (b)/(c); reuses the harness's
already-established `compute_hash`-against-`CacheStore` shape.

**Reopen criterion (sketch for Round 1).** Reopen if a future
daemon-side architectural change moves parallel verification to
an async (tokio) shape; the test's substrate-anchored shape
would re-anchor against the new daemon model. RSS-bound
adversarial criterion reopens if a future caller-side discipline
note (per [Phase 2F §3 caller hand-off Arc-lifetime
discipline](./RANDOMX_V2_PHASE2F_PLAN.md)) authorizes longer
`Arc` retention windows, in which case the RSS-bound ceiling
re-anchors against the new caller-discipline bound.

#### Round 1 disposition (closes R1-D9)

**Close at default expectation.** Concurrent-call thread-safety
test is (a) — `std::thread::spawn` workers; no async runtime
dep; no parallel-iterator dep.

**Substrate-anchored rationale.** Per
[`17-dependency-discipline.mdc`](../../.cursor/rules/17-dependency-discipline.mdc)
workspace-state check: `tokio` is a workspace dependency (Phase
2F + 3a infra) but adding it for one test in the harness crate
fails the single-cited-consumer test (the harness's other
modes don't use `tokio`); `rayon` is not a workspace dep and
adding it for one test surfaces dependency-discipline questions
about audit-fan-out. (a) `std::thread::spawn` is `std`-only,
zero new dep surface, and matches the daemon's
`tools::threadpool::getInstanceForCompute()` shape more closely
than the async (b) or work-stealing (c) shapes.

**Worker-count pin (F5 substrate from R1-D12 close).** Worker
count = **4 production workers + 1 reserve = 5 total**,
matching Phase 2F R1-D5's daemon parallel-verification fanout
formula `min(get_max_concurrency(), m_max_prepare_blocks_threads) + 1`
on the GitHub Actions `ubuntu-latest` runner class (4 vCPU; per
F5 R1-D12 close). The numeric pin tracks the R1-D12 runner
class; if R1-D12 reverts to a larger runner class, this pin
reopens.

**Iteration count pin.** **256 hashes per worker × 5 workers
= 1280 total hashes** computed across the test. Substrate
rationale: 1280 hashes exercises `CacheStore`'s capacity-2
invariant multiple times (assuming the corpus has more than
2 distinct seedhashes, the worker scheduling forces canonical
vs. transient slot rotation under contention); 256 per worker
is large enough that per-call hash-time variance averages out;
5 workers × 256 hashes × ~300ms = ~6.4 min total wall-clock
fits under the per-PR ~7-minute budget per F2 (the test runs
concurrently across workers, not sequentially, so the
wall-clock is closer to 256 × 300ms × (1 / parallelism) ≈ ~1.5
min on `ubuntu-latest`'s 4 vCPU).

**F4 RSS-ceiling numeric pin.** Per F4 adversarial-pass
finding: substrate-anchored against Phase 2F §4 F2 disposition:

- CacheStore capacity-2 derived-cache holdings:
  2 × 256 MiB = **512 MiB**
- Worker working-set: 5 workers × (~2 MiB scratchpad +
  ~8 KiB register-file + ~10 KiB miscellaneous) ≈
  **~10 MiB**
- OS / allocator overhead headroom: **~118 MiB**
- **Total RSS ceiling: 640 MiB** during steady-state
  concurrent execution.
- **Tolerance band: ±10% of the measured pre-test baseline
  RSS.** Assertion: `max(steady_state_samples) − baseline ≤
  640 MiB × 1.10`.
- **Measurement methodology:** Linux `/proc/self/statm` field
  2 (resident pages × page size at runtime) sampled at 100 ms
  intervals during the concurrent test; baseline taken at
  test entry (after `PreparedCache` initialization but before
  worker spawn); steady-state samples = samples taken at
  t > 5 s into the test (after worker scheduling warms up).

**macOS / Windows fallback pin.** The harness's RSS measurement
is Linux-specific (`/proc/self/statm`). On macOS, the
equivalent is `task_info(mach_task_self(), TASK_BASIC_INFO,
...)`; on Windows, `GetProcessMemoryInfo()`. **Cross-platform
disposition: the RSS-bound test runs on Linux only;** macOS /
Windows CI (if added) runs only the correctness criterion.
The cross-platform shape lands as a `#[cfg(target_os = "linux")]`
gate on the RSS-bound assertion. Substrate: `ubuntu-latest`
is the per-PR + nightly runner per F5; macOS / Windows
runners are not in the CI matrix; the cfg-gate documents the
future-portability shape without paying the cross-platform
cost now.

**Reversion clause.**

- *Rejection.* (b) tokio rejected on dep-surface; (c) rayon
  rejected on dep-surface + dependency-discipline single-cited-consumer.
- *Reopening criteria.* Reopen toward (b) if the daemon-side
  parallel-verification surface moves to async; the test's
  substrate-anchored shape re-anchors against the new daemon
  model. RSS-bound numeric ceiling reopens if (i) the R1-D12
  runner class changes (re-pin against new vCPU count + RAM);
  (ii) Phase 2F §3 caller-discipline authorizes longer `Arc`
  retention windows (re-pin against the new caller bound);
  (iii) the harness adds modes that share state across mode
  invocations (concurrent test's baseline becomes ambiguous).
- *Re-evaluation shape.* Per A4 sub-PR boundary reversion: a
  Round-N design-round entry citing daemon-architectural or
  caller-discipline substrate-change evidence; the RSS-bound
  numeric pin updates with measurement-anchored justification.

**Round 2 amendment: mode-scoping pin.** The RSS-bound assertion
is **scoped to the concurrent-call test mode only**; other
harness modes (latency per R1-D7, worst-case per R1-D8, future
trace per a R1-D10 reopen) do **not** inherit the RSS-bound
assertion. The F2 backstop's measurement is meaningful only when
the harness's own accumulator state is minimal — in the
concurrent-call mode, the harness holds the corpus iteration
state, the worker pool, and the `CacheStore`'s capacity-2
holdings, with no per-iteration accumulators large enough to
shift the steady-state RSS measurement. In other modes (e.g.,
the worst-case mode accumulates per-(seedhash, data) timing
samples; a future trace mode would accumulate per-iteration
register snapshots), the harness's own accumulator state grows
with corpus size and would push the measured RSS above the
640 MiB ceiling without the verifier-side F2 mitigation having
regressed — i.e., a false-positive RSS-bound failure.

The mode-scoping is implemented at the §3.15 mode-dispatch
boundary: the RSS-sampler thread (per
`mode_concurrent.rs` per §5.1.13) is spawned only inside the
`--mode=concurrent` dispatch branch; other modes do not spawn
it and do not assert against the 640 MiB ceiling.

The substrate cross-reference: **R1-D9 is the F2 backstop, not
a generic memory-pressure guard for the harness binary.** A
future Round-N that adds a new harness mode with a large
accumulator state (e.g., a trace-collection mode buffering
per-iteration register snapshots) does *not* inherit the R1-D9
RSS-bound; if memory pressure for that new mode becomes a
concern, the new mode's design surfaces its own
mode-scoped memory-pressure disposition. **This pin prevents
inheritance-by-default** of the RSS-bound assertion in contexts
where the measurement is structurally meaningless. Per the
§3.15 actor-shape framing, each mode is responsible for its own
load-bearing invariants; R1-D9's invariant is one such per-mode
load-bearing invariant, not a binary-wide assertion.

**Reopen criterion for the mode-scoping pin.** If a future
substrate change makes the harness's per-mode accumulator state
small enough that the RSS-bound assertion remains meaningful
across modes (e.g., a Round-N redesign that moves accumulator
state out of process and into a separate reporter), the
mode-scoping pin reopens toward binary-wide RSS-bound assertion.
Future-deferred; substrate trigger is the accumulator
relocation.

### R1-D10 — `compute_hash_with_trace` decision (per 2f §10.4 pre-pin)

**Decision.** Does 2g add the optional cfg-gated entry point
`#[cfg(any(test, feature = "differential-trace"))] pub fn
compute_hash_with_trace(prepared, data, trace_sink) -> [u8; 32]`
to `shekyl-pow-randomx`?

**Options.**

- **(a)** **Include.** Add the cfg-gated entry point + the
  `TraceSink` trait (the trait lives **harness-side**, not in
  the verifier crate's public API, per [Phase 2F §10.4
  post-closure-pin refinement](./RANDOMX_V2_PHASE2F_PLAN.md)).
  Surfaces bisection-from-final-hash-divergence capability.
- **(b)** **Omit.** Accept that bisection from final-hash
  divergence is manual (read both intermediate states in a
  debugger) until a real divergence demands it.

**Criteria.**

- Substrate-anchored need: per [Phase 2F §10.4](./RANDOMX_V2_PHASE2F_PLAN.md),
  the (a)-option is justified only if "2g's differential pass
  surfaces a divergence and bisection without per-iteration
  trace visibility is intractable." Pre-implementation, there
  is no surfaced divergence to bisect; the (a)-cost is paid for
  a hypothetical use.
- Cfg-gated discipline: per [Phase 2F §10.4 cfg-gated-additions
  principle](./RANDOMX_V2_PHASE2F_PLAN.md), the (a) cost is
  bounded by the `#[cfg(...)]` gate — production build does not
  include the entry point, the FFI shim does not see it, the
  default-features public API does not expose it. The `TraceSink`
  trait surface stays harness-side, never promoted to
  verifier-public-API.
- Reopening cost: omitting at Round 1 and re-adding later is
  cheap (small cfg-gated addition); the over-prediction cost
  is bounded.

**Default expectation.** (b) — omit until a real divergence
demands it; explicitly carry the option to a future round
with the named substrate-anchored reopening criterion.
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
"reject-now-with-named-reopening-criteria" applies.

**Reopen criterion (sketch for Round 1).** Per [Phase 2F §10.4](./RANDOMX_V2_PHASE2F_PLAN.md):
2g's differential pass surfaces a divergence and bisection
without per-iteration trace visibility is intractable.

**Reopen-criterion class (post-closure pin).** The R1-D10
reopen criterion is **future-deferred**, not substrate-anchored
at Round-1-evaluation-time. There is no Round-1-time test of
the criterion — it fires only at a future Round-N+M when an
actual divergence surfaces and bisection from final-hash output
proves intractable. This contrasts with the substrate-anchored
reopen-criterion shape of (e.g.) R1-D5 ("reopen if grinding
wall-time on the reference machine exceeds 1 day"), which is
evaluable against current-Round-1 substrate. Both classes are
legitimate per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
"reject-now-with-named-reopening-criteria" — the discipline's
load-bearing requirement is that the criterion be *named*
specifically enough that a future maintainer can determine
whether it has fired without re-deriving the original
reasoning. Future-deferred criteria satisfy this when the
trigger event itself is future-only (a divergence that has not
yet occurred at Round-1-evaluation-time). 2F §10.4's
post-closure pin used the same future-deferred class for the
pre-pin; R1-D10's reopen is the same shape inherited forward.
A future Round-N opening R1-D10's reopening does not need new
Round-1 evidence; the divergence itself is the
substrate-anchored evidence. The §11 round-history entry
opening that reopening cites the divergence's `(seedhash,
data)` pair and the bisection-attempt artefact as the reopen's
substrate trigger.

#### Round 1 disposition (closes R1-D10)

**Close at default expectation.** `compute_hash_with_trace` is
**omitted** at Round 1. No cfg-gated entry point added to
`shekyl-pow-randomx`; no `TraceSink` trait; no
`differential-trace` feature flag.

**Future-deferred reopen-criterion class (per Round 0
calibration item 7).** The reopen criterion is future-deferred
(the trigger event — divergence + intractable bisection — has
not occurred at Round-1-evaluation-time); legitimate per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).
A future Round-N opening cites the divergence's `(seedhash,
data)` pair and the bisection-attempt artefact as the reopen's
substrate trigger rather than re-deriving Round-1 evidence.

**Public-API non-impact pin.** The R1-D10 (b) close preserves
the Phase 2F R3-frozen `shekyl-pow-randomx` public API surface
verbatim — no new exports, no new feature flags, no cfg-gated
type names in `pub use` paths. The §1 substrate's public-API
freeze remains the load-bearing contract; this disposition is
the substrate that confirms it. The §1.4 crate-invariant grep
gate continues to enforce the freeze.

**Reversion clause.**

- *Rejection.* (a) Include rejected on substrate-anchored
  cost-benefit: paying the cfg-gated-entry-point cost for a
  hypothetical use; per
  [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
  "Keep it for flexibility" anti-pattern.
- *Reopening criteria.* Per [Phase 2F §10.4](./RANDOMX_V2_PHASE2F_PLAN.md):
  2g's differential pass (or any future differential pass)
  surfaces a divergence that survives bisection-without-trace.
  Future-deferred; the substrate trigger is the divergence
  itself.
- *Re-evaluation shape.* Per A1 function-body-replacement
  contract: a Round-N design-round entry adds the cfg-gated
  entry point + the harness-side `TraceSink` trait per Phase
  2F §10.4 substrate; the implementation lands in a separate
  PR per [`20-rust-vs-cpp-policy.mdc`](../../.cursor/rules/20-rust-vs-cpp-policy.mdc)
  migration discipline (the trace surface is secret-adjacent
  — intermediate VM register values are inputs to the final
  hash output — and gets its own design rounds rather than
  "while we're here" addition).

### R1-D11 — Bisection-divergence failure mode

**Decision.** When the byte-equality corpus pass fails, what does
the harness produce for a reviewer facing the CI failure?

**Options.**

- **(a)** Print Rust output, C output, and the differing bytes
  only.
- **(b)** Include input `(seedhash, data)` for reproduction (so
  the reviewer can `cargo run -- --seedhash $HEX --data $HEX`
  locally and reproduce the failure deterministically).
- **(c)** Include input + per-iteration trace if R1-D10's
  disposition is "include."

**Criteria.**

- Reproducibility: (b) is the minimum bar — a CI failure that
  cannot be reproduced locally is a debugging black hole. (a)
  alone fails this criterion.
- Bisection cost: (c) gives the reviewer the per-iteration
  intermediate state, eliminating the spelunking step.

**Pins required for Round 1.** Format (text vs. JSON; per-byte
diff vs. hex-dump); whether the failure output is gated on a
verbosity flag or always emitted; whether `Cache` derivation
state (the seedhash, the cache's first 64 bytes for sanity) is
included for additional cross-check.

**Default expectation.** (b) — include input for local
reproduction; per-iteration trace is gated on R1-D10's
disposition.

**Reopen criterion (sketch for Round 1).** Tied to R1-D10's
reopen.

#### Round 1 disposition (closes R1-D11)

**Close at default expectation.** Bisection-divergence failure
mode is (b) — include input `(seedhash, data)` for local
reproduction; per-iteration trace omitted per R1-D10 (b).

**F1 dependency: cache-sha256 fields included per R1-D14
(b)-then-(iii).** The structured failure output's content is
shaped by R1-D14's close — since the harness's R1-D14
cache-equivalence precondition asserts SHA-256 equality of
the Rust-side and C-side caches per seedhash *before* the
per-(seedhash, data) byte-equality test runs, the
post-byte-equality-failure structured output includes both
SHA-256s so a reviewer can confirm the precondition held at
test time (defense-in-depth: a non-aborted run with mismatched
cache-sha256s would itself be a harness bug, but the structured
output surfaces the discrepancy if it occurs).

**Failure output format pin.**

| Field | Type | Example |
|-------|------|---------|
| `mode` | string | `"byte-equality"` |
| `corpus_id` | string | `"random-v1-per-pr"` or `"adversarial-v1"` or `"u128-edge-v1"` |
| `seedhash` | hex string | `"a3b2c1d0…"` (64 hex chars) |
| `data_len` | int | 76 |
| `data` | hex string | `"…"` |
| `rust_hash` | hex string | 64 hex chars (32 bytes) |
| `c_hash` | hex string | 64 hex chars |
| `rust_cache_sha256` | hex string | 64 hex chars (R1-D14 precondition cross-check) |
| `c_cache_sha256` | hex string | 64 hex chars (R1-D14 precondition cross-check) |
| `differing_bytes` | array of `(offset, rust_byte, c_byte)` triples | `[[0, 0xa5, 0x5a], [17, 0xff, 0x00]]` |
| `cargo_repro_invocation` | string | `cargo run --bin shekyl-randomx-differential -- --mode=byte-equality --seedhash <hex> --data <hex>` |

**Output channel pin.** JSON-formatted to stderr (one-failure-per-line
for grep-friendliness); pretty-printed human-readable form to
stdout (formatted-block per failure). First failure aborts the
corpus pass — no continue-on-failure (a divergence at
seedhash N is high-priority; running through to seedhash N+1
under a known-buggy implementation wastes CI minutes and
muddles the failure attribution between divergent seedhashes).

**`Cache` first-64-bytes inclusion (Round 0 pin question).**
Excluded — the SHA-256 cache-sha256 fields supersede the
"first 64 bytes for sanity" Round 0 pin. The cache-sha256 is
strictly more diagnostic (covers the full cache rather than a
prefix) at the same comparison cost (32-byte hash vs. 64-byte
prefix); the first-64-bytes Round 0 sketch was substrate-anchored
against (i) full-cache-diff disposition (which is now (iii) by
R1-D14), and (iii)'s sha256 collapses the diagnostic need.

**Verbosity-flag-gating pin.** Failure output is **always
emitted** (not gated). Substrate: the failure output is
emitted only on failure (the success-path produces a single
"OK: N hashes checked, 0 divergences" log line); the cost is
zero when the test passes; the benefit (diagnostic
completeness at failure) is asymmetric to the cost.

**Reversion clause.**

- *Rejection.* (a) bytes-only rejected on reproducibility —
  fails the minimum bar (cf. criteria); (c) per-iteration
  trace rejected by R1-D10 (b) dependency.
- *Reopening criteria.* Tied to R1-D10's reopen (if R1-D10
  (a) reopens, R1-D11 (c) becomes available); reopen
  independently if the structured failure-output format
  proves insufficient for diagnosing a future divergence
  (per the future-deferred substrate trigger).
- *Re-evaluation shape.* Per A4 sub-PR boundary reversion: a
  Round-N design-round entry citing the divergence's
  failure-output artifact and the format extension needed.

### R1-D12 — CI job structure (per parent 2g todo)

**Decision.** How does the byte-equality differential job land
in CI ("CI job runs the harness; failure fails CI" per parent
plan 2g todo on line 30)?

**Options.**

- **(a)** Per-PR job in
  [`.github/workflows/build.yml`](../../.github/workflows/build.yml)
  (sibling to the FPU + crate-invariant steps at lines 75–78).
  Runs the byte-equality corpus on every PR regardless of
  diff surface.
- **(b)** Separate workflow file (`differential.yml`) that runs
  only on PRs touching `rust/shekyl-pow-randomx/`,
  `external/randomx-v2/`, or
  `rust/shekyl-randomx-differential/` (path-filtered trigger).
- **(c)** Per-PR for byte-equality + scheduled nightly for
  worst-case ratio + release-gate-only for full corpus
  (split-cadence).

**Criteria.**

- Runner platform requirements: single-config CMake constraint
  per Phase 1 wiring (§1.7 above; line 123 fail-fast). Either
  pin runner to single-config generators (Ubuntu/macOS Ninja
  or Make; Windows MSYS2 Ninja) or escalate the per-`CONFIG`
  FOLLOWUPS entry to V3.0 ahead of 2g (per R1-D3 reopen
  criterion).
- Timeout budget: must fit within current CI ceiling. The
  inherited Phase 3a synthetic per-hash benchmark target is
  "<30s of CI wall time" per parent plan §6 line 243 — but
  that is the *per-hash latency* benchmark, not the byte-equality
  corpus. Byte-equality with a ~300 ms per-hash cost over a
  corpus of N pairs and Rust+C sides is ~600 ms × N; N=64
  fits in ~40s, N=1024 is ~10 min. The corpus-size and the
  cadence are coupled via this budget.
- Diff-surface scoping: (b) avoids spending CI on PRs that
  cannot regress 2g's substrate; (a) is fail-loud-on-everything.

**Pins required for Round 1.** Cadence (per-PR / nightly /
release-gate split); runner platform (Linux Ninja default;
Windows MSYS2 conditional); timeout budget vs. corpus-size
tradeoff.

**Default expectation.** (c) — split-cadence:

- Per-PR for byte-equality on a subset of the corpus
  (size pinned by Round 1 to fit a ≤2-minute CI budget; e.g.,
  N=32 random + 5–10 adversarial pairs).
- Scheduled nightly for the full byte-equality corpus.
- Release-gate suite for worst-case ratio (R1-D8).

**Reopen criterion (sketch for Round 1).** Reopen if the
per-PR cost exceeds the budget (raise the floor on
runner-class spec, or shrink the per-PR subset further).

#### Round 1 disposition (closes R1-D12)

**Close at default expectation.** CI job structure is (c) —
split-cadence per-PR / nightly / release-gate, with the F2 +
F5 numeric pins anchored against the `ubuntu-latest` runner
class.

**F5 runner-class pin (substrate verified at Round 1 against
GitHub Actions docs).** Per [GitHub Actions runner
specifications](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners/about-github-hosted-runners#standard-github-hosted-runners-for-public-repositories)
(verified at Round 1 close, not from training-data recall):
`ubuntu-latest` runners for public repositories are **4 vCPU /
16 GB RAM / 14 GB SSD**. The per-job timeout ceiling is 6
hours (well above any 2g cadence). Substrate verified at
Round 1; if GitHub Actions changes runner specs, R1-D12 reopens
substrate-anchored.

**F2 cadence-vs-corpus pin (matches R1-D4 close).**

| Cadence | Workflow file | Corpus | Wall-clock budget |
|---------|---------------|--------|-------------------|
| Per-PR | `.github/workflows/build.yml` (new step) | R1-D4 random per-PR (16×8 = 128 hashes) + R1-D9 concurrent (~1.5 min) + R1-D14 cache-precondition (~6–8 s × 16 = ~2 min) | **~7 min** total per job |
| Nightly | `.github/workflows/differential-nightly.yml` (new file; scheduled cron `0 3 * * *`) | R1-D4 random nightly (32×32 = 1024 hashes) + R1-D5 adversarial (~5–10 × 16 = 80–160 hashes) + R1-D6 u128 edge (~4 × 16 = 64 hashes) + R1-D7 per-hash latency (N=1024) | **~25 min** total per job |
| Release-gate | `.github/workflows/differential-release-gate.yml` (new file; triggered by `release/*` branches) | R1-D8 worst-case (R1-D5 + R1-D6 union × 16 = ~14–16 seedhashes × 16 = ~224–256 hashes) | **~10 min** total per job |

All three workflows pin runner: `runs-on: ubuntu-latest`. Per
R1-D3 (c), each workflow's build step passes
`-DBUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON` to the CMake
configure step (which transitively enables
`BUILD_RANDOMX_V2_MINER_LIB=ON` per R1-D3 disposition).

**Path-filtered per-PR trigger pin.** Per-PR job runs on every
PR by default but can be skipped for PRs that touch only
`docs/`, `*.md`, or non-RandomX-related crates (per the
`paths-ignore:` GitHub Actions trigger filter). The full path
filter (Round 2 may refine):

```yaml
paths-ignore:
  - 'docs/**'
  - '**/*.md'
  - '**/CHANGELOG.md'
```

Rejecting `paths:` (positive filter on
`rust/shekyl-pow-randomx/**` etc.) because Phase 2g is
substrate-coupled to many surfaces (changes to
`rust/shekyl-pow-randomx/`, `external/randomx-v2/` submodule,
`external/CMakeLists.txt`, `rust/randomx-v2-sys/`,
`rust/shekyl-randomx-differential/`, `scripts/ci/check_randomx_crate_invariants.sh`,
the workflows themselves) can all regress 2g's substrate;
enumerating positive paths is brittle.

**Nightly failure handling pin.** Per current Shekyl
nightly-CI-failure convention: nightly failures surface via
GitHub Actions email notifications to the workflow's
configured recipients. (Pinning a "GitHub issue auto-opened
on nightly failure" surface is out-of-scope for 2g — that
would require a separate `actions/github-script` step + issue
template, which adds CI surface unrelated to the differential
harness. If the project adopts that convention later, the 2g
nightly workflow extends without 2g-specific design.)

**Reversion clause.**

- *Rejection.* (a) per-PR full-corpus rejected on per-PR
  cost (~25 min per PR run is wasteful for PRs that don't
  touch the 2g substrate); (b) separate workflow with
  diff-surface trigger rejected on path-trigger brittleness
  (per the path-filtered per-PR trigger pin above).
- *Reopening criteria.* Reopen if (i) per-PR wall-clock
  exceeds 15 minutes (tighten corpus shape vs. escalate to
  `ubuntu-latest-xl` runner class); (ii) nightly failures
  prove brittle (substrate-anchored against the failure rate
  measured over the first month post-merge); (iii) GitHub
  Actions runner-class specs change.
- *Re-evaluation shape.* Per A4 + A5: a Round-N design-round
  entry citing the per-PR-wall-clock or nightly-failure-rate
  evidence; the cadence-vs-corpus re-pin lands as a workflow
  amendment + this disposition's numeric-pin update.

### R1-D13 — Crate-invariant compatibility

**Decision.** How does the new `rust/shekyl-randomx-differential/`
crate (R1-D1) interact with the Phase 2F crate-invariant grep gate
(§1.4 above)? The new crate genuinely needs `extern "C"`
declarations to call the C reference (R1-D2).

**Options.**

- **(a)** Leave the new crate ungated and document in its
  rustdoc that it is the deliberate exception to the
  `shekyl-pow-randomx`-scoped invariants.
- **(b)** Extend
  [`scripts/ci/check_randomx_crate_invariants.sh`](../../scripts/ci/check_randomx_crate_invariants.sh)
  with a per-crate exception list (a `CRATE_SRC` filter that
  excludes the differential-harness crate from Pattern C but
  not Patterns A/B).
- **(c)** Split the C-side bindings into a tiny
  `randomx-v2-sys` crate (per R1-D2 option (c)) that is the
  only crate carrying `extern "C"`; the differential-harness
  crate itself stays Rust-side and invariant-clean. The
  invariants script extends scan-scope to *both* crates and
  enforces Patterns A/B on both; only the `randomx-v2-sys`
  crate is excluded from Pattern C.

**Criteria.**

- Per [Phase 2F §3.6 R1-E1](./RANDOMX_V2_PHASE2F_PLAN.md), the
  Pattern A/B/C invariants are anchored to `shekyl-pow-randomx`
  because that crate is the verifier — the surface the daemon
  links. (a) leaves the new crate outside the gate entirely;
  (b)/(c) bring it inside the gate with a narrow Pattern C
  exception.
- Unsafe-surface minimization: (c) constrains the `extern "C"`
  declarations to one crate with seven export declarations,
  reviewable line-by-line; (a)/(b) allow the
  differential-harness crate to grow `extern "C"` declarations
  as it pleases.
- Substrate-anchored discipline: the
  [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)
  "continuous discipline as inheritance prevention" framing
  favors (c) — extending the gate's coverage rather than
  carving an exception preserves the gate's load-bearing
  property as the project's invariant surface grows.

**Default expectation.** (c) — `randomx-v2-sys` sub-crate
owns the `extern "C"` declarations; the differential-harness
crate stays Rust-side and invariant-clean. The invariants
script extends to cover both crates; the
`randomx-v2-sys` crate is excluded from Pattern C only (its
sole purpose is to carry `extern "C"`).

**Reopen criterion (sketch for Round 1).** Reopen if R1-D2's
disposition rejects (c) for an unrelated reason; R1-D13 then
re-evaluates (a) vs. (b).

#### Round 1 disposition (closes R1-D13)

**Close at default expectation.** Crate-invariant compatibility
is (c) — `randomx-v2-sys` sub-crate is the *only* crate carrying
`extern "C"` (sole-purpose); the differential-harness crate
(`shekyl-randomx-differential`) consumes `randomx-v2-sys` as a
path-dep and stays Pattern-C-clean. Both crates are inside the
invariant-script scan-scope with a per-crate Pattern C exemption
list.

**Invariant-script extension pin.** The current
[`scripts/ci/check_randomx_crate_invariants.sh`](../../scripts/ci/check_randomx_crate_invariants.sh)
scans `rust/shekyl-pow-randomx/` and asserts the Pattern A
(`#[no_mangle]` absence), Pattern B (`extern "C"` absence in
non-FFI-shim path) and Pattern C (per-file FFI exemption)
invariants. Round 1 pins the extension shape:

1. **Scan-scope extension.** Add `rust/randomx-v2-sys/` and
   `rust/shekyl-randomx-differential/` to the script's
   `CRATE_SRC_ROOTS` array.
2. **Per-crate Pattern C exemption.** Add a `CRATE_PATTERN_C_EXEMPT`
   set: `{rust/randomx-v2-sys/}`. The script's Pattern C check
   skips files under exempt crates; the new
   `shekyl-randomx-differential` crate is **not** exempt
   (consumes `randomx-v2-sys` via Rust types; no direct
   `extern "C"`).
3. **Pattern A + B preservation.** Both new crates honor
   Pattern A (no `#[no_mangle]`) and Pattern B (no `extern "C"`
   outside the exempt `randomx-v2-sys` source files). The
   `randomx-v2-sys` crate carries `extern "C"` declarations
   in `rust/randomx-v2-sys/src/lib.rs` (or analogous); no
   `#[no_mangle]` anywhere.

**CI wiring extension pin.** The current invariant-script CI
step in `.github/workflows/build.yml` continues to run; the
extended scan-scope is exercised by the same step (no new
workflow steps needed; the script's exit code is the
gate).

**Reversion clause.**

- *Rejection.* (a) ungate-and-document rejected on the
  "continuous discipline as inheritance prevention" framing
  per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc);
  (b) inline `extern "C"` with per-file exemption rejected
  because the workspace-wide grep gate's "binary present /
  absent" property weakens when per-file exemptions
  proliferate.
- *Reopening criteria.* Reopen toward (b) if R1-D2 reopens
  toward (b) inline `extern "C"` (the per-crate exemption
  would migrate to per-file); reopen toward (a) if a future
  crate-architecture restructuring eliminates the per-crate
  exemption surface entirely.
- *Re-evaluation shape.* Per A2 audit-against-actual-code:
  any Round-N reopening cites the substrate evidence —
  R1-D2 reopening trigger, crate-restructuring evidence,
  or a script-level pattern that supersedes per-crate
  exemption.

**Round 2 amendment: harness stateful-pattern exemption pin.**
The harness crate's stateful mode-dispatch is **appropriately
outside the verifier-crate-scoped Pattern A and Pattern B
invariants**. Per §0 layer-separation discipline and §3.15
harness actor shape, `shekyl-randomx-differential` is the
workspace's orchestrator-actor for the differential-harness
problem; orchestrator actors hold accumulator state, mode-dispatch
state, and CLI argument parsing — all patterns that the
verifier-crate-scoped invariants forbid (and that the verifier
crate's pure-transform discipline requires forbidding).

The harness crate may therefore legitimately use:

- **`OnceLock<T>` / `LazyLock<T>` / `static` mutable state**
  for CLI argument parsing (e.g., a `static REGEX:
  OnceLock<Regex>` for parsing the `--debug-cache-divergence`
  flag's seedhash hex argument; a `static CORPUS:
  OnceLock<Vec<Seedhash>>` for one-time corpus-load
  initialization).
- **Module-level accumulator state** for per-mode aggregation
  (e.g., a `static RSS_SAMPLES: OnceLock<Mutex<Vec<u64>>>`
  for the R1-D9 RSS sampler; a `static TIMING_HISTOGRAM:
  OnceLock<Mutex<Histogram>>` for the R1-D8 worst-case mode).
- **Multi-mode dispatch state** via `enum Mode { ... }` +
  match-dispatch in `src/main.rs` (per §5.1.3).

The grep gate's **per-crate scoping** (R1-D13 (c) close above)
is precisely what enables this — Pattern A (`#[no_mangle]`
absence) and Pattern B (`extern "C"` absence outside FFI shim)
remain in force across all three crates in scan-scope
(`shekyl-pow-randomx`, `randomx-v2-sys`, `shekyl-randomx-differential`),
but the verifier-crate-specific patterns that forbid stateful
constructs are anchored to `rust/shekyl-pow-randomx/` only. The
harness crate's stateful patterns don't accidentally constrain
the verifier's invariants (the gate doesn't scan for these
patterns inside the verifier crate as a Round-2-side-effect),
and the verifier's invariants don't accidentally constrain the
harness's legitimate orchestrator-actor patterns (the gate's
per-crate scoping isolates them).

**The pin makes the per-crate scoping load-bearing**, not
incidental. A future Round-N that proposes to add a workspace-wide
stateful-pattern grep gate (e.g., "no `OnceLock` anywhere in
the workspace") would fail this pin's substrate check: the
harness crate's legitimate orchestrator-actor patterns are
exactly the patterns such a gate would forbid; the layer
separation per §0 is what makes the verifier-side
stateful-construct prohibition load-bearing without
requiring the same prohibition on the orchestrator-actor side.

**Substrate cross-reference.** Per §0 layer-separation
discipline observation: the four-crate layering (verifier /
state-holder / C-bindings / orchestrator-actor) is the workspace's
actor-paradigm template; each crate's invariant footprint
should be scoped to its role in the layering, not applied
binary-wide. R1-D13's per-crate scoping is the operational
form of this principle in the invariant-script substrate.

### R1-D14 — Equivalent-cache-state precondition

**Decision.** How does the harness establish cache-state
byte-equivalence between Rust and C as a **precondition** for
the per-`(seedhash, data)` byte-equality test on `compute_hash`
output?

**Substrate.** The byte-equality test compares Rust-side
`compute_hash(&prepared, data)` output against C-side
`randomx_calculate_hash(cache, vm, data, hash_out)` output. For
the comparison to be meaningful — i.e., for a divergence to
mean "the implementations disagree" rather than "the inputs
disagree" — both sides must operate against byte-identical
cache state derived from the same seedhash. The Rust side
derives via `PreparedCache::derive(seedhash)`; the C side
derives via `randomx_init_cache(cache, seedhash, seedhash_size)`.
If these two paths produce byte-different caches for the same
seedhash, the byte-equality test is testing the wrong thing —
"given divergent caches, do divergent hashes result?" rather
than "given the same cache, do the implementations agree?"

**Options.**

- **(a)** **Implicit.** Assume the spec-faithful implementation
  discipline (leg 1 per §2.5) makes the two cache-derivation
  paths byte-identical; do not test the assumption. Failure
  mode: a `compute_hash`-output divergence cannot be
  attributed to cache-derivation vs. dispatch — the failure
  is ambiguous between the two layers.
- **(b)** **Explicit upstream test.** Separate harness pass
  per seedhash derives both caches and asserts byte-equality
  before any `compute_hash` test runs against that seedhash;
  per-`(seedhash, data)` byte-equality on `compute_hash`
  output is the load-bearing test. Failure mode: cache
  divergence fails the precondition test with the seedhash
  named; dispatch divergence fails the `compute_hash` test
  with `(seedhash, data)` named. The two failure classes are
  cleanly separable.
- **(c)** **Inlined assertion.** Every per-hash test re-derives
  both caches and asserts byte-equality before computing.
  Functionally equivalent to (b) but pays the
  cache-derivation cost (~150–200 ms per seedhash for
  Argon2d-512 fill) per `compute_hash` call rather than per
  seedhash. With ~32 + 5–10 seedhashes × N (R1-D12-tunable)
  data values per seedhash, (c)'s redundant derivation
  overwhelms the per-call ~300 ms cost.

**Criteria.**

- Failure-mode separability: (b) and (c) cleanly distinguish
  cache-derivation vs. dispatch divergence; (a) cannot.
- Cost: (a) pays nothing; (b) pays one extra
  cache-derivation per seedhash (~150–200 ms × ~40 seedhashes
  ≈ 6–8 s, one-shot per harness run); (c) pays per
  `compute_hash` call (orders-of-magnitude more).
- R1-D11 interaction: the bisection-divergence failure-mode
  question (R1-D11) is bounded by R1-D14 — a (a) disposition
  means R1-D11's output cannot distinguish cache-derivation
  from dispatch divergence even when R1-D10's optional
  per-iteration trace is included; the trace surfaces the
  *symptom* (intermediate-state mismatch from instruction K
  onward) but not the *layer* (was the cache the divergence
  seed, or did instruction K's handler diverge?).

**Pins required for Round 1.** Whether the cache-byte-equality
test compares the full cache (256 MiB × 2 sides; significant
memory pressure during the test) or a deterministic subset
(e.g., first 64 KiB; sampled rows; SHA-256 of full cache);
which side runs first; whether the test runs in the harness
binary, the test-harness library surface (per R1-D7), or both;
how the test reports the divergence offset when the assertion
fails.

**Default expectation.** (b) — explicit upstream test per
seedhash. Cache-equivalence is a precondition; per-`(seedhash,
data)` byte-equality on `compute_hash` output is the
load-bearing test. The (a) cost (failure-mode ambiguity) is
substrate-anchored against §2.5's leg-3-as-catch-of-last-resort
framing: if the harness cannot distinguish a cache-derivation
divergence from a dispatch divergence, leg 3's diagnostic
value to a future maintainer chasing a corpus failure is
substantially weakened. The (b) cost (one-shot ~6–8 s per
harness run) is negligible relative to the byte-equality
corpus pass's per-PR budget.

**Reopen criterion (sketch for Round 1).** Reopen if the
full-cache comparison's memory pressure (256 MiB × 2 = 512 MiB
peak during the test, on top of the harness's running
working-set) exceeds the CI runner-class budget; the
sub-disposition (full vs. subset vs. hash) closes
substrate-anchored against the measured runner-class memory
ceiling.

#### Round 1 disposition (closes R1-D14)

**Close at default expectation.** Cache-state byte-equivalence
precondition is (b) — explicit upstream per-seedhash test that
runs before any per-`(seedhash, data)` byte-equality test
against that seedhash's `compute_hash` output.

**F1 comparison-shape pin (sub-disposition).** **SHA-256 of full
cache by default + full-cache byte-diff mode behind a
`--debug-cache-divergence` post-failure flag.**

- **Default precondition test** (every harness run): for each
  seedhash in the corpus, derive both the Rust `PreparedCache`
  (via `PreparedCache::derive(seedhash)` per the Phase 2F
  R3-frozen API surface) and the C cache (via
  `randomx_alloc_cache` + `randomx_init_cache`); compute
  SHA-256 of the full 256 MiB Rust cache and SHA-256 of the
  full 256 MiB C cache; assert byte-equality of the two
  SHA-256 outputs (32-byte comparison). Memory peak per
  seedhash: ~280 MiB (two 256 MiB derives held in memory
  concurrently while computing each side's SHA-256
  incrementally, or sequentially with ~256 MiB peak if the
  SHA-256 is computed first-side-then-second-side; the
  per-seedhash sequence in code holds at most one
  Rust + one C cache at a time → ~512 MiB peak across both
  sides only if both are held; sequentially-released keeps
  peak at ~256 MiB).
- **`--debug-cache-divergence` mode** (manual post-failure
  diagnostic): after a precondition test SHA-256 mismatch,
  the harness operator re-runs with
  `--debug-cache-divergence --seedhash <hex>`; that mode
  performs the full 256 MiB × 2 byte-by-byte diff and reports
  the first divergent offset, the surrounding window
  (e.g., 64 bytes around the offset), and the implied
  divergence-class (e.g., Argon2d-512 fill divergence vs.
  superscalar-program divergence based on the offset's
  position in the cache's structure).

**Memory pressure reasoning.** Per F5 (R1-D12 close) runner
class `ubuntu-latest` has 16 GB RAM. The default SHA-256 mode
peak (~280–512 MiB per seedhash) fits with ample headroom; the
`--debug-cache-divergence` mode peak (~512 MiB strict) still
fits but is paid only on manual invocation. Substrate
verified: even under R1-D9's concurrent test (which holds
RSS at 640 MiB per F4), the precondition tests run
sequentially per seedhash *before* the concurrent test begins,
not concurrently — so the precondition memory pressure does
not stack with R1-D9's working set.

**R1-D11 dependency cross-reference.** The R1-D11 structured
failure output includes `rust_cache_sha256` + `c_cache_sha256`
fields (per R1-D11 close); under R1-D14 (b)-then-(iii), those
fields are populated from the precondition test's SHA-256
computations. A precondition test failure aborts the corpus
pass for that seedhash before any per-`(seedhash, data)`
byte-equality test runs, so a divergent-cache-sha256 in the
R1-D11 failure output is a harness bug (the precondition
should have caught it first) and surfaces clearly.

**Comparison ordering pin.** Rust side runs first per seedhash;
C side runs second. Substrate: minor stylistic preference for
"derive new cache via the system-under-test path first,
ground-truth oracle second" — a Rust-side panic during
derivation is the more interesting failure class (the C side
is the ground truth; a C-side panic means the precondition
itself is broken, not the cache pair). The ordering is a
documented harness convention, not a load-bearing test
property.

**Reversion clause.**

- *Rejection.* (a) implicit rejected on failure-mode-separability
  per §2.5 leg-3 catch-of-last-resort framing (cf. Round-0
  amplification block); (c) inlined-per-call rejected on cost
  (re-deriving caches per `compute_hash` call ≈ 16×8 × 6–8 s
  per per-PR run > the entire per-PR wall-clock budget).
  (i) full-cache-diff default-mode rejected on memory pressure
  (peak ~512 MiB per seedhash × every-harness-run is wasteful
  when (iii)'s SHA-256 collapses the comparison cost to
  ~280 MiB per seedhash); (ii) deterministic-subset default
  rejected on diagnostic completeness (a divergence outside
  the sampled region passes silently — leg-3's catch-of-last-resort
  surface is exactly what (ii) thins).
- *Reopening criteria.* Reopen toward (i) full-cache-diff
  default-mode if a future divergence surfaces and the
  `--debug-cache-divergence` flag's manual-re-run cost proves
  unacceptable (e.g., the divergence is non-reproducible
  outside CI, so the operator cannot manually re-run; or the
  divergence-class diagnostic cost exceeds the budget for a
  release-gate review). Reopen toward (iii) sub-disposition
  alternatives (e.g., per-row hash + per-row diff) if the
  current SHA-256-of-full-cache shape proves too coarse —
  i.e., the cache structure has sub-regions whose divergence
  behavior would be diagnostically useful to separate
  (Argon2d-512 fill region vs. superscalar-program region).
- *Re-evaluation shape.* Per A1 + A4: a Round-N design-round
  entry citing the divergence's `(seedhash, …)` artifact and
  the comparison-shape extension; the harness's `--mode`
  surface extends with the new precondition variant per
  R1-D8's subcommand discipline.

**Round 2 amendment: drop discipline + CacheStore-empty-during-precondition
pin.** The SHA-256 incremental shape relies on **sequential
release** of the Rust cache before the C cache is allocated, to
keep peak per-seedhash memory at ~256 MiB rather than the
~512 MiB worst case where both sides are held concurrently. The
sequencing per the (user-pinned) pseudocode:

```rust
for seedhash in corpus {
    let rust_cache = PreparedCache::derive(seedhash);
    let rust_hash = sha256_full(rust_cache.bytes());   // ~256 MiB peak
    drop(rust_cache);                                  // explicit release

    let c_cache = unsafe {
        let p = randomx_v2_sys::randomx_alloc_cache(flags);
        randomx_v2_sys::randomx_init_cache(p, seedhash.as_bytes().as_ptr(), 32);
        p
    };
    let c_hash = sha256_full_c_cache(c_cache);         // ~256 MiB peak
    unsafe { randomx_v2_sys::randomx_release_cache(c_cache); }

    assert_eq!(rust_hash, c_hash);
}
```

The `drop(rust_cache)` is **load-bearing**: with Rust's
`Arc<PreparedCache>` shape (per Phase 2F R3 `PreparedCache`
internals — `Arc<Cache>` held inside the bundle), the explicit
`drop` releases the strong reference, and the cache's backing
allocation is freed *only if* the `drop`-side is the **last
holder**. If any other code path holds a clone of the same
`Arc<Cache>` for the same seedhash at precondition-time, the
backing allocation persists past the `drop` and the peak
memory measurement degrades to ~512 MiB before stabilizing
when the other holder releases.

**CacheStore-empty-during-precondition invariant.** The
precondition test owns the **only** `Arc<PreparedCache>` clone
for each seedhash in the corpus during the precondition phase.
Specifically:

- The `CacheStore` is **empty** when the precondition tests
  run; **no `CacheStore::get_or_derive(seedhash)` call has
  inserted any entry yet**. The precondition phase derives
  fresh via `PreparedCache::derive(seedhash)` directly (not
  via the `CacheStore`), and drops the result before the
  next iteration; the `CacheStore`'s sticky-canonical
  slot stays unpopulated.
- The byte-equality test phase (which runs *after* all
  precondition tests have passed for all seedhashes) is the
  first phase that populates the `CacheStore` per-seedhash.
- The phase boundary is enforced at the §3.15 lifecycle level
  (init → corpus-load → precondition-all-seedhashes →
  byte-equality-per-(seedhash,data) → accumulate → report);
  no `CacheStore::get_or_derive` calls leak from the
  byte-equality phase back into the precondition phase.

The invariant is **implementation-PR-side**, not just a
documented convention: the precondition test's source code
calls `PreparedCache::derive` directly (per §5.1.9 `rust_subject`
module), not `CacheStore::get_or_derive` (per Phase 2F
`CacheStore` public surface); a Pattern-D extension to the
R1-D13 invariant script could optionally enforce this at CI
time by grepping for `CacheStore::` references inside
`cache_precondition.rs` (per §5.1.7) — but Round 2 declines
to add the Pattern-D extension because the module-level
co-location of the precondition logic in a single 50-100 LoC
module makes the discipline manually verifiable at review
time without script enforcement.

**Why the invariant matters for Round 2.** The SHA-256 memory
peak (~256 MiB per seedhash) is the load-bearing memory budget
under F5's 16 GB runner ceiling; if the precondition phase's
peak silently degraded to ~512 MiB due to a `CacheStore`-leak,
the precondition tests for a large corpus would push the
process's RSS past the runner's budget headroom for the
*other* concurrent test (R1-D9's 640 MiB ceiling). Per §3.15
phase-boundary discipline, the precondition phase runs
sequentially per seedhash and completes before the concurrent
phase begins; F5's 16 GB headroom comfortably absorbs the
256 MiB-per-seedhash peak even with the worst-case 32 nightly
seedhashes processed sequentially.

**Reopen criterion for the drop-discipline pin.** If a future
substrate change shifts the `PreparedCache` internals away from
`Arc<Cache>` (e.g., a Round-N redesign that adopts a different
ownership shape), the `drop` discipline reopens against the
new ownership model. Future-deferred; substrate trigger is the
Phase 2F R3-frozen `PreparedCache` internals shifting.

### §3.15 Harness actor shape (Round 2 architectural framing)

**Scope.** This section makes explicit what the §3.1–§3.14
disposition collection determines implicitly: the
`shekyl-randomx-differential` binary is a **multi-mode
orchestration actor** with mode-dispatched state, per-cadence
invocation, and a structured lifecycle. The disposition
collection already pins the answers (R1-D1 workspace placement
+ R1-D7 latency mode + R1-D8 worst-case mode + R1-D10 trace-mode
deferral + R1-D11 failure-output schema + R1-D12 cadence
mapping + R1-D14 cache-precondition phase); §3.15 names the
actor shape explicitly so future consumers (Phase 3a per-PR
latency gate, Phase 3c symbol-isolation check, release-gate
suites) inherit a documented contract rather than reconstructing
one from the disposition collection.

**Substrate-anchored framing.** The workspace's actor paradigm
(per §0 layer-separation discipline observation) shapes the
disposition collection's coherence: the harness crate is the
sole workspace-side orchestration actor in the 2g substrate,
and its internal contract should be specified with the same
discipline as the verifier crate's pure-transform contract.
"All our other clients are Actors" — the harness is a client
of the verifier's pure transforms and an orchestration actor
in its own right; §3.15 specifies the orchestrator-actor
contract.

#### §3.15.1 Mode set

The harness binary exposes **four modes** via the top-level
`--mode={correctness,worst-case,latency,concurrent}` CLI flag,
mutually exclusive per invocation:

| Mode | Source disposition | CI cadence (per R1-D12) | Section anchor |
|---|---|---|---|
| `correctness` | R1-D4 + R1-D5 + R1-D6 + R1-D14 | per-PR (subset) + nightly (full) + release-gate (full) | §5.1.10 (`mode_correctness`) |
| `worst-case` | R1-D8 | nightly + release-gate | §5.1.11 (`mode_worst_case`) |
| `latency` | R1-D7 | nightly + release-gate | §5.1.12 (`mode_latency`) |
| `concurrent` | R1-D9 | nightly + release-gate | §5.1.13 (`mode_concurrent`) |

A **fifth mode is reserved** but not currently implemented:

| Mode | Source disposition | Status | Reopen criterion |
|---|---|---|---|
| `trace` (future) | R1-D10 (closed at (b) — omit) | Reserved, not implemented | A future divergence + intractable bisection (per R1-D10 future-deferred reopen) |

The default behavior when invoked without `--mode` is **error
with a usage message**, not implicit-default-to-correctness;
the substrate rationale per the `user-protection-defaults-in-user-absent-contexts`
anti-pattern discipline
([`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc)):
"graceful degradation under unknown input" inverts to "loud
failure" pre-genesis. The CI workflow steps (per §5.5) always
pass `--mode=...` explicitly; a missing `--mode` indicates an
operator misuse and should not silently pick a mode.

A reserved sixth orchestration surface exists for the
`--debug-cache-divergence --seedhash <hex>` post-failure
diagnostic mode (per R1-D14 sub-disposition). This is invoked
*as a flag combination on the `correctness` mode*, not as a
separate `--mode=` value; the flag triggers a different
in-mode codepath (full byte-diff instead of SHA-256
comparison). Per the §3.15.3 dispatch surface table.

#### §3.15.2 State shape per mode

Each mode initializes a distinct combination of state holders;
modes do not share state across invocations (the process exits
after one mode completes):

| Mode | `CacheStore`? | `Cache + Vm` pair (C)? | Per-mode accumulator state | RSS-bound assertion (R1-D9)? |
|---|---|---|---|---|
| `correctness` | Yes (capacity 2; populated during byte-equality phase, *not* during precondition phase per R1-D14 amendment) | Yes (allocated per-seedhash; released between seedhashes) | Per-`(seedhash, data)` byte-equality result (pass/fail bit); failure output buffer populated per R1-D11 schema | No |
| `worst-case` | Yes (capacity 2) | Yes (one per-seedhash) | Per-`(seedhash, data, class_tag)` per-hash latency sample (ring buffer; class-tagged); per-class median + max accumulator | No |
| `latency` | Yes (capacity 2; one seedhash) | Yes (one `Cache + Vm`) | N=1024 per-hash latency samples (interleaved Rust/C); two `Vec<u64>` (Rust samples, C samples); per-side median + p95 + max accumulator | No |
| `concurrent` | Yes (capacity 2; shared across 5 workers) | Yes (one per-worker `Vm`; shared `Cache` via `CacheStore` get_or_derive) | Per-worker `Vec<[u8; 32]>` of computed hashes; RSS sampler thread's `Mutex<Vec<u64>>` of RSS samples | **Yes** (per R1-D9 amendment: scoped to this mode only) |
| `trace` (reserved) | TBD (a future R1-D10 reopen specifies) | TBD | TBD: per-iteration register snapshots; trace-buffer accumulator | TBD; per the R1-D9 amendment, would not inherit the RSS-bound by default |

**Free-between-modes discipline.** Each mode is invoked in its
own process (one `cargo run` per invocation; one CI step per
mode). No state survives across modes. The orchestrator-actor
shape is **process-scoped**, not session-scoped; the lifecycle
per §3.15.4 always begins from a clean state and ends at process
exit.

This matters for the §3.15 actor framing: the harness is *not*
a long-lived daemon-style actor (like the daemon-side
`shekyl-engine-state` actor with multi-request lifetime); it
is a **per-invocation orchestration actor** whose state lives
only inside one mode's run. The simplification matters for
future consumers — Phase 3a's per-PR latency gate doesn't have
to reason about state surviving across `--mode=latency`
invocations; each invocation is independent.

#### §3.15.3 Mode-dispatch surface (CLI argument shape)

The argument shape is **mode-mutually-exclusive at the top
level, with mode-scoped sub-arguments below**:

```text
shekyl-randomx-differential
  --mode={correctness,worst-case,latency,concurrent}
  [--corpus-size={per-pr,nightly,release-gate}]    # default: per-pr; controls R1-D4 corpus size; valid on all modes
  [--seed=<hex32>]                                  # default: pinned per R1-D4; valid on correctness only
  [--debug-cache-divergence --seedhash=<hex32>]     # post-failure diagnostic; valid on correctness only
  [--workers=<u32>]                                 # default: 5; valid on concurrent only
  [--samples=<u32>]                                 # default: 1024; valid on latency only
  [--mode=test-failure]                             # synthetic failure injection for T11; not a real mode
```

The dispatch is implemented at `src/main.rs` (per §5.1.3) as
argument parsing → `enum Mode { Correctness, WorstCase, Latency,
Concurrent, TestFailure }` → `match`-dispatch to the
mode-specific module. Mode-scoped sub-arguments are rejected
at parse-time with a clear error message when used outside
their mode (e.g., `--workers=8 --mode=latency` errors with
"the --workers flag is valid only for --mode=concurrent").

**No mode composition.** A single invocation runs exactly one
mode. The substrate rationale: mode composition would require
the orchestrator to manage state-handoff across modes (e.g.,
`--mode=correctness,latency` would need to decide whether to
share the corpus state or re-derive); the per-invocation
process-scoping per §3.15.2 avoids the question by construction.
Each CI step invokes its own process per mode (per §5.5).

#### §3.15.4 Orchestration lifecycle

Every mode follows the same lifecycle skeleton; per-mode
specialization happens at the per-iteration step:

```text
[init]
  → parse_args() / argument validation
  → init_logging() (stderr + stdout sinks)
  → init_oracle() (C-side: load randomx-v2-sys symbols; ready Cache+Vm allocator)
  → init_subject() (Rust-side: ready PreparedCache::derive path; configure CacheStore capacity)

[corpus-load]
  → load_corpus(mode, corpus_size_flag)
       (mode == Correctness: random per R1-D4 + adversarial per R1-D5 + u128-edge per R1-D6)
       (mode == WorstCase: R1-D5 + R1-D6 union per R1-D8)
       (mode == Latency: single seedhash, N data samples per R1-D7)
       (mode == Concurrent: per-PR-size random corpus per R1-D9)

[mode == Correctness only: precondition-all-seedhashes]
  → for each seedhash in corpus:
       precondition_test(seedhash)  // per R1-D14 + drop-discipline pin
  → abort-on-first-failure (per R1-D14 + R1-D11 fail-fast discipline)

[per-iteration loop]
  → mode-specific per-iteration step:
       (Correctness: per-(seedhash, data) byte-equality)
       (WorstCase: per-(seedhash, data) timing measurement, class-tagged)
       (Latency: per-iteration interleaved Rust/C timing measurement)
       (Concurrent: spawn 5 workers; each worker runs 256 hashes; RSS sampler thread per R1-D9 amendment)

[accumulate]
  → per-mode aggregation (median / max / per-class breakdown)
  → write BENCH_RESULTS.md updates if perf mode (Latency, WorstCase, Concurrent)

[report]
  → success: stdout summary; exit 0
  → failure: stderr JSON per R1-D11 schema; stdout human-readable; exit 1

[exit]
  → drop all state holders (Rust drop order)
  → cleanup oracle (free C-side Cache+Vm allocations)
  → process exit
```

**Phase boundaries are load-bearing.** Per the R1-D14 amendment,
the precondition phase runs to completion before the per-iteration
phase begins; per R1-D11's fail-fast discipline, the
per-iteration phase aborts on first failure rather than
continuing to accumulate divergences. Per R1-D9's amendment,
the RSS-bound assertion is scoped to the concurrent mode's
per-iteration phase only (the sampler thread is spawned
inside that phase, not during init or corpus-load).

#### §3.15.5 Forward-template for Phase 3a / 3c / release-gate

The §3.15 actor shape is **the contract Phase 3a's per-PR
latency gate consumes**: the 3a CI step invokes
`shekyl-randomx-differential --mode=latency` (per §3.15.1
mode set) and parses the stdout summary (per §3.15.4 report
phase); the 3a wiring does not need to understand the harness's
internal state shape because the actor's per-invocation
process-scoping (per §3.15.2) means each 3a invocation is
independent.

Similarly, **Phase 3c's symbol-isolation check** can consume
the harness as a binary whose Cargo build product is queryable
via `nm` (per parent-plan line 26); the §3.15 actor shape's
process-scoped lifecycle means the symbol-isolation check
operates on the static linker output, not on a running-process
state.

**Future signing-engine extractions** (per Phase 4+ post-V3
forward path) inherit the §3.15 template: per-invocation
process-scoped orchestrator actors with mode-dispatched state,
phase-boundary-load-bearing lifecycles, and explicit-mode CLI
argument shapes. The harness is the workspace's first
multi-mode orchestrator-actor; the shape it pins is reusable.

#### §3.15.6 What §3.15 is not

- **Not a substrate reframe.** §3.15 makes explicit what the
  R1-D1/D7/D8/D9/D10/D11/D12/D14 disposition collection
  already determines. The actor shape lands by composition of
  closed dispositions; §3.15 surfaces the composition rather
  than introducing new substrate.
- **Not a runtime specification.** The mode-dispatch
  implementation details (argument-parser library, error
  message wording, exit-code mapping) are implementation-PR
  concerns; §3.15 specifies the contract surface, not the
  implementation.
- **Not a threat-model.** Round 3 (deferred per §4) closes the
  threat-model addenda for the harness surface; §3.15 is
  architectural framing, not adversarial enumeration. The
  §4 Round-3 enumeration sketch's "harness surface attack
  classes" (corpus-generation bug, R1-D14 precondition
  bypass, CMake-trigger bypass, R1-D11 failure-output
  incompleteness, CacheStore `Arc` retention regression,
  adversarial-corpus drift, reviewer-blind nightly failures)
  evaluates against the §3.15 framing as substrate, not as
  competing scope.

---

## 4. Threat model (Round-N placeholder)

Reserved for Round-N's adversarial pass against the 2g
substrate. The Round-N threat model will enumerate attack
classes against the differential-harness surface itself —
e.g., a corpus-generation bug that produces inputs the
verifier accepts but the C reference rejects (or vice versa);
a CI scheduling bug that runs the harness without
`BUILD_RANDOMX_V2_MINER_LIB=ON` and silently passes; a
binding-layer bug that calls the wrong C export and silently
returns a stale-cache hash. The framing inherits the [Phase 2F
§10.5 three-leg audit posture](./RANDOMX_V2_PHASE2F_PLAN.md):
2g implements leg 3 and depends on legs 1 and 2 having been
applied correctly; leg-3 corpus testing on a finite set of
inputs does not establish behavior on the unbounded set of all
inputs.

**Not in-scope for Round 0.** Round 0 names the placeholder
explicitly so a Round-N pass adds substance against the
substrate captured in §§1–3 rather than against a
substrate-free framing.

**Round-1-close obligation (corpus-coverage-as-leg-3-completeness
framing).** Per §2.5's Round-0-amplification block, the three
corpus-coverage classes — random per R1-D4 ("typical inputs"),
adversarial per R1-D5/R1-D6 ("rare-path inputs"), worst-case
timing per R1-D8 ("timing pathology") — are not redundant; they
catch different bug classes. A random corpus catches divergences
in opcodes that fire on common inputs; an adversarial corpus
catches divergences in opcodes that fire on rare inputs (which
would otherwise slip past a random corpus by definition);
worst-case-timing tests catch timing divergences that produce
byte-identical output but reach it through structurally different
code paths (the Rust may match the C output but take 10× as long
due to a different code-shape choice). Each is a different
coverage profile of leg 3's catch-of-last-resort surface; thin
coverage in any one class thins the residual catch capacity in
that direction. **Round 1's threat-model close must treat
corpus-coverage as load-bearing**, not adjacent to (or weaker
than) F1–F7-style attack-class enumeration. This obligation is
the substrate Round 1 closes against; the absence of explicit
corpus-coverage-class framing in the Round-1 threat-model close
is grounds for reviewer challenge per the §0 round-count
expectation calibration (Round 1's three-round expectation does
not authorize cutting corners on substrate-load-bearing
disposition). The framing is cross-referenced from §2.5's
Round-0 amplification and from R1-D4 / R1-D5 / R1-D6 / R1-D8
default-expectation rationales.

### Round 1 disposition (re-anchor §4 close to Round 2)

**Substrate-anchored deferral, not drop.** The §4 threat-model
close is **deferred from Round 1 to Round 2**, substrate-anchored
against the
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
A3 timing discipline: "Threat-model addenda is typically a **late
design-rounds** discipline (often Round 3–4): after feature
completeness, before closure. At Round 1 the design is not yet
stable enough to adversarially probe; at Round 5-only it is too
late." Round 1 closes 14 substrate-anchored dispositions plus
introduces F1–F5 substrate findings against Round 0 defaults; the
Round 1 close is the **closed-disposition substrate** that
Round 2's threat-model pass adversarially probes, not a frozen
design that the threat-model pass cannot reshape.

**Round-2-close obligation (inherits the Round-0 corpus-coverage
framing).** The Round-0 Round-1-close obligation
(corpus-coverage-as-leg-3-completeness; cf. block above)
re-anchors as the **Round-2-close obligation** with no content
change: the three corpus-coverage classes (random, adversarial,
worst-case timing) catch different bug classes; corpus coverage
is load-bearing as a property of the audit posture, not adjacent
to F1–F7-style attack-class enumeration. The deferral preserves
the obligation per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
"reject-now-with-named-reopening-criteria" — the rejection here
is "do not close §4 at Round 1"; the reopening criterion is
"Round 2 closes §4 against the Round-1-anchored substrate."

**Round-2 enumeration sketch (pre-bound; Round 2 supersedes).**
Round 2's threat-model pass enumerates 5–7 attack classes against
the differential-harness surface itself, *not* against the
verifier (the verifier's threat model is closed by 2c/2d/2f). The
pre-bound categories are:

1. **Corpus-generation bug.** The R1-D4 ChaCha20Rng-seeded
   corpus or the R1-D5/D6 grinded adversarial corpus produces
   inputs the harness's Rust + C sides both *agree* on, but
   that agreement is itself wrong (e.g., a corpus generator
   bug that produces inputs both sides reject identically,
   silently bypassing the byte-equality check).
2. **R1-D14 precondition bypass.** A future harness-side change
   accidentally disables the SHA-256 cache-precondition test
   (cf. R1-D14 disposition); per-`(seedhash, data)` tests then
   run against potentially-divergent caches and silently pass
   when the divergence happens to produce identical hash output
   for some `(seedhash, data)` pair.
3. **CMake-trigger bypass.** A future CI workflow misconfigures
   the harness build (e.g., `BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON`
   without `BUILD_RANDOMX_V2_MINER_LIB=ON`, which R1-D3's (c)
   prevents by construction — but a future R1-D3 revert could
   reintroduce); the harness builds successfully but links
   against a stale `shekyl_randomx_v2` artifact, surfacing
   stale-cache divergences as harness-bug noise.
4. **R1-D11 failure-output incompleteness.** A future divergence
   surfaces but the R1-D11 structured-failure-output format
   omits a load-bearing field; reviewer diagnosis is bounded
   by what the format includes (cross-link to R1-D10's
   future-deferred reopen and R1-D14's `--debug-cache-divergence`
   diagnostic mode).
5. **CacheStore `Arc` retention regression.** A future Phase 2F
   caller-side regression breaks the F2 capacity-2 invariant
   under R1-D9's concurrent test; the test's RSS-bound
   assertion (640 MiB per F4) catches the regression, but a
   regression that breaks the RSS-bound assertion's
   methodology (e.g., `/proc/self/statm` reading the wrong
   field) silently misses the regression.
6. **Adversarial-corpus drift.** The R1-D5 grinded seedhashes
   become stale if the C reference's `RANDOMX_FREQ_*`
   distribution (`configuration.h:88–125`) shifts (V4
   transition or a fork-pin advance per §1.7); the
   adversarial corpus's "heavy" criterion no longer matches
   the v2.x generator's output, and the worst-case ratio
   test runs against effectively-random seedhashes.
7. **Reviewer-blind nightly failures.** If R1-D12's nightly
   failure handling proves inadequate (GitHub email
   notifications missed; no automatic issue-opening), nightly
   regressions persist for days/weeks before discovery; the
   cadence-vs-discovery-latency calculus reopens.

The seven pre-bound categories above are **scaffolding for
Round 2**, not Round 2's closed enumeration. Round 2's pass
adversarially probes the Round-1-closed substrate and may
surface additional classes, collapse some into others, or
re-prioritize disposition (cf. [Phase 2c §5.11.5](./RANDOMX_V2_PHASE2C_PLAN.md)
threat-model objectives shape). Round 2 also discharges the
corpus-coverage-as-leg-3-completeness Round-2-close obligation
explicitly (the obligation is not closed by enumerating the
seven categories above; it is closed by the Round-2 framing
naming corpus coverage as substrate-load-bearing in the same
sense the seven categories are substrate-load-bearing).

### Round 2 amendment (re-anchor §4 close to Round 3)

**Substrate-anchored re-anchor, not drop.** Round 2 absorbed
five architectural tightenings (per §11 Round 2 row) and the
new §3.15 harness-actor-shape framing rather than closing §4's
threat-model addenda. The §4 close re-anchors from Round 2 to
**Round 3**; the Round-1 deferral's reopening criterion
("Round 2 closes §4 against the Round-1-anchored substrate")
re-points to "**Round 3** closes §4 against the **Round-1- +
Round-2-anchored substrate** — the §3.15 actor-shape framing
becomes part of the substrate that §4 evaluates against."

**Why Round 2 chose tightenings over §4 close.** The
architectural-tightening findings surfaced through a fresh
adversarial read of the Round-1 close (per [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
"what does this actually deliver against the threat model?"
discipline). Specifically: the harness-as-orchestration-actor
framing is itself substrate that §4's adversarial probe needs
to operate against — the seven pre-bound attack classes above
(corpus-generation bug, R1-D14 precondition bypass, etc.) each
evaluate against the actor shape's mode-boundary discipline,
phase-boundary discipline, and per-mode state shape; closing
§4 before §3.15 lands would force §4 to either (a) re-derive
the actor framing per attack class or (b) close against an
implicit-rather-than-explicit substrate. Round 2 lands §3.15
to give §4 the named substrate it adversarially probes.

The §0 round-count expectation (≤3 rounds total) accommodates
the re-anchor: Round 0 (Scaffold) + Round 0 calibration + Round
1 + Round 2 + Round 3 = 3 substantive rounds (Round 0
calibration counts as substrate-tightening against Round 0,
not a separate close-round). Round 3's scope is §4 close +
optional adversarial-pass findings against the §3.15 substrate
+ implementation-PR transition gate.

**Round-3-close obligation (inherits the corpus-coverage +
actor-shape framings).** The Round-2-close obligation
(corpus-coverage-as-leg-3-completeness) re-anchors as the
**Round-3-close obligation** with no content change. **A new
load-bearing obligation lands at Round 2 for Round 3 to absorb:**
the §3.15 harness-actor-shape framing is substrate that §4's
attack-class enumeration must explicitly probe against,
specifically:

- Mode-boundary violations (a §4 attack class would surface
  if a future contributor accidentally lets state leak across
  mode boundaries despite §3.15.2's process-scoped framing).
- Phase-boundary violations (per the R1-D14 amendment's
  CacheStore-empty-during-precondition invariant; per the
  R1-D9 amendment's RSS-sampler-spawned-in-concurrent-mode-only
  invariant).
- Per-mode-state-shape regression (a §4 attack class would
  surface if a future mode addition silently inherits an
  invariant that no longer applies, per the R1-D9 amendment's
  inheritance-by-default prevention).

The Round-3 close must enumerate these three attack classes
explicitly, alongside the seven Round-1 / Round-2 pre-bound
classes; the absence is grounds for reviewer challenge per the
same discipline that the corpus-coverage obligation enforces.

### Round 3 disposition (closes §4 against the Round-1- + Round-2-anchored substrate)

**Scope.** §4 enumerates **ten attack classes** against the
differential-harness surface itself (`shekyl-randomx-differential`,
`randomx-v2-sys`, CMake wiring, CI cadence, harness-actor
discipline). The verifier crate's threat model is closed by
Phase 2c §5.11.5–.8, Phase 2d §10, and Phase 2f §4; 2g does
not re-litigate any verifier-crate attack class. Each §4
attack class is named, framed, dispositioned, cross-linked to
its catching T# from §6, and (where applicable) carries a
reversion clause per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).

The Round-3 close also **discharges three load-bearing
obligations** inherited forward from prior rounds, named
explicitly before the attack-class enumeration so the
discharges are auditable as their own dispositions rather
than buried inside individual attack-class entries.

#### §4.1 Load-bearing-property discharge: corpus coverage as leg-3 completeness

**Inherited obligation.** Per the Round-0 calibration item (8),
re-anchored as the Round-1-close obligation (deferred at Round
1), re-anchored as the Round-2-close obligation (Round 2 chose
architectural tightenings instead), the Round-3 §4 close must
treat corpus coverage as a load-bearing property of the
audit posture, not as adjacent to attack-class enumeration.
The framing's load-bearing assertion is "**thin corpus coverage
thins the catch-of-last-resort surface**" per §2.5 leg-3 framing
+ Round-0 amplification block.

**Discharge.** The three corpus-coverage classes (cf. §2.5)
catch different bug classes and are non-redundant; thin
coverage in any one class thins the residual catch capacity
in that direction. The Round-3 disposition pins all three as
substrate-load-bearing:

1. **Random corpus** (per R1-D4) catches divergences in
   opcodes that fire on common inputs. The R1-D4 numeric pin
   (16 seedhashes × 8 data values per-PR; 32 × 32 nightly;
   bimodal block-template-shaped data-length distribution;
   32-byte ChaCha20 seed; deterministic regeneration verified
   via T9) is the load-bearing substrate for this class.
   Thinning the pin (e.g., reducing nightly to 16 × 8)
   measurably thins the catch surface; reopening requires
   substrate-anchored justification per
   [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc).
2. **Adversarial corpus** (per R1-D5 + R1-D6) catches
   divergences in opcodes that fire on rare inputs (heavy in
   CFROUND, FDIV_M, cache-miss, CBRANCH, Combined-heavy
   seedhashes; div-by-zero, signed-div overflow,
   shift-by-width, u128-truncation data). The 4-hour-per-class
   grinding budget (F3) is the load-bearing substrate;
   the SHA-256 hash-pin via T10 is the drift-detection
   substrate. Thinning the per-class corpus or relaxing the
   T10 drift-detection assertion thins the catch surface for
   the rare-path opcode bug class specifically; reopening
   requires substrate-anchored justification.
3. **Worst-case timing** (per R1-D8) catches *timing*
   divergences (Rust may produce byte-identical output but
   take pathologically long due to a different code-shape
   choice). The 5.0× ceiling (Parent §6) is the load-bearing
   substrate; T6 is the operationalization. This catch class
   is **categorically different from byte-equality** — a
   verifier that produces correct output but takes 50× the
   C reference's time is a CPU-DoS vector against validating
   nodes per parent-plan §6 framing, not a correctness bug.

The discharge is **not** "the three corpus-coverage classes
exist therefore the obligation is satisfied"; the discharge
is the explicit pinning of each class as load-bearing-against-
substrate-anchored-numeric-criteria, with reopening criteria
that catch silent thinning. A future Round-N (or
implementation-PR-side change) that reduces any of the three
classes' substrate without substrate-anchored justification
violates the discharged obligation, not the attack-class
enumeration.

#### §4.2 Load-bearing-property discharge: harness-as-actor invariants

**Inherited obligation.** Per the §3.15 Round 2 amendment and
the §4 Round 2 amendment, the Round-3 §4 close must enumerate
the three Round-2 new attack classes (mode-boundary,
phase-boundary, per-mode-state-shape regression) as load-bearing
against the §3.15 harness-actor-shape framing. The discharge
condition: each of A8, A9, A10 below must explicitly cite
§3.15 substrate, not be re-derived from the disposition
collection.

**Discharge.** A8, A9, A10 below cite §3.15.2 (mode-boundary
discipline), §3.15.4 (phase-boundary discipline + R1-D14
amendment's CacheStore-empty + R1-D9 amendment's RSS-sampler
scoping), §3.15.6 (what §3.15 is not — confirming the framing's
own self-bounded discipline) as their load-bearing substrate.
The harness-actor-shape framing is therefore not just §3.15
architectural framing; it is a §4-load-bearing audit-posture
property that the per-attack-class dispositions rest on. Per
the §0 layer-separation observation, the four-crate layering
is the structural property that makes the harness-actor
discipline auditable; the §4 dispositions for A8–A10 evaluate
the discipline's continued integrity against future regressions.

#### §4.3 Load-bearing-property discharge: three-leg audit-posture rebalance

**Inherited substrate.** Per §2.5 + Round 0 amplification block,
leg 1 (spec-faithful implementation, Phase 2c/2d/2f) is the
primary load-bearing leg; leg 2 (audit-against-C-where-spec-is-silent,
Phase 2c §5.11.8 + 2d Round-6 R6) is the supporting leg; leg 3
(corpus testing, this Phase 2g) is the catch-of-last-resort.
Round 0 amplified leg-3's role: it is not "redundant safety
net" but the only mechanism that catches discipline failures in
legs 1 + 2.

**Discharge.** The §4 attack-class enumeration is the
operationalization of leg-3's catch surface. A1, A2, A6 below
are the cases where a verifier-side bug that slipped past legs
1 + 2 would surface; A3, A4, A5, A7, A8, A9, A10 are the cases
where leg-3's catch capacity itself is the attack surface
(harness bugs, CI-cadence bugs, fork-pin-coupling bugs,
audit-posture-degradation bugs). The two attack-class kinds
are **structurally distinct** and require structurally
distinct mitigations:

- **Leg-3-catch-of-verifier-bug** (A1, A2, A6): mitigated by
  preserving the corpus-coverage classes per §4.1 + the
  per-`(seedhash, data)` byte-equality test against the C
  reference (T1, T2, T3).
- **Leg-3-catch-capacity-degradation** (A3, A4, A5, A7, A8,
  A9, A10): mitigated by preserving the harness's own
  integrity per §4.2 + the operational discipline
  (per-cadence CI placement R1-D12, fork-pin coupling §1.7,
  per-crate invariant scoping R1-D13).

The two-kind structural framing is the discharge: future
contributors evaluating §4 against a proposed change can
classify the change against the two-kind framework and reach
for the appropriate mitigation class without re-deriving the
substrate.

#### §4.4 Attack-class enumeration (A1–A10)

The ten attack classes are numbered A1–A10 (Attack class).
A1–A7 are the Round-1 pre-bound classes (per the Round-1
disposition above); A8–A10 are the Round-2 new classes (per
the Round-2 amendment above). Each carries Attack / Round 3
disposition / Test coverage / Reversion clause (where
applicable), matching the precedent shape from
[Phase 2F §4](./RANDOMX_V2_PHASE2F_PLAN.md) F1–F7.

##### A1 — Corpus-generation false-agreement bug

**Attack.** The R1-D4 ChaCha20Rng-seeded corpus or the
R1-D5/D6 grinded adversarial corpus produces inputs that the
harness's Rust + C sides both *agree* on identically, but
where the agreement is itself wrong — e.g., a corpus
generator bug that produces inputs both implementations
reject in the same way for the same wrong reason, silently
bypassing the byte-equality check (the check passes; no
divergence is recorded; the verifier-side bug remains
hidden behind the symmetric corpus bug).

**Round 3 disposition.** Two-layer structural mitigation:

1. **Determinism gate** (T9). The corpus generator's output
   is deterministic given the R1-D4 32-byte seed, and T9
   asserts byte-identical regeneration across runs. A
   corpus-generator bug that produces *random* false-agreement
   inputs (in the sense of "different across runs") fails T9
   in CI before reaching the per-`(seedhash, data)` byte-equality
   step. Mitigation surface: catches non-determinism in the
   generator, not determinism that happens to be wrong.
2. **Drift-detection pin** (T10). The R1-D5/D6 adversarial
   corpus is committed as hex byte arrays under
   `rust/shekyl-randomx-differential/src/adversarial_corpus.rs`
   (per §5.1.6); T10 asserts SHA-256 of the entire module's
   byte arrays matches a pinned constant. A corpus-generator
   bug that *silently re-grinds* and replaces the adversarial
   corpus during PR review fails T10's drift-detection
   assertion; reviewer attention is forced to the diff that
   re-grinded the corpus.

**Residual.** Neither T9 nor T10 catches a corpus that is
deterministically and stably wrong from initial commit (e.g.,
the initial PR author commits an adversarial corpus that
mistakenly fails to exercise CFROUND despite the R1-D5
specification). This residual is caught by the §5.7
drift-prevention discipline (reviewer-rejection criterion
for implementation-PR surfaces that don't match §5
specifications) + Phase 2c §5.11.8 audit-against-actual-code
discipline applied to the corpus per R1-D5 grinding criteria.
The residual is **accepted** as a discipline-failure-mode that
the audit-against-actual-code framework catches at PR-review
time, not as a runtime check.

**Test coverage.** T9 + T10.

**Reversion clause.** Reopen if a future incident surfaces a
corpus-generator bug that silently passed T9 + T10; substrate
trigger is the post-mortem analysis identifying the audit-time
gap.

##### A2 — R1-D14 precondition bypass (silent cache divergence)

**Attack.** A future harness-side change accidentally disables
the SHA-256 cache-precondition test (cf. R1-D14 disposition).
Per-`(seedhash, data)` tests then run against
potentially-divergent caches and silently pass when the
divergence happens to produce identical hash output for some
`(seedhash, data)` pair (the cache divergence may produce
*different* hashes for *most* data pairs but the same hash
for a fraction; the corpus's sampled pairs may all fall in
the latter fraction by accident).

**Round 3 disposition.** Structural enforcement via the §3.15.4
phase-boundary discipline: the precondition phase runs to
completion before the byte-equality phase begins; precondition
failure aborts the corpus pass for that seedhash. The
phase-boundary is implemented at the dispatch level (per
§5.1.10 `mode_correctness` module); a harness-side change
that disabled the precondition phase would have to reorder
or skip an explicit call site in the orchestration lifecycle.
T3 catches the precondition assertion's positive case
(precondition passes → byte-equality runs); a precondition
that was *silently disabled* (the assertion is no-op'd or
short-circuited) is caught by the §6 test suite's coverage
of T3 itself — T3 must *fail* in a synthetic-divergence test
(per T11's failure-output schema round-trip discipline, which
injects a known divergence to verify the failure path).

**Residual.** A harness-side change that disables T3
*and* the synthetic-divergence test for T3 *and* T11
(orchestrated silent-disable) bypasses the structural
discipline. This residual is caught by §5.7 + §8.3
scope-discipline pin (reviewer-rejection criterion for
implementation-PR surfaces that modify the failure path
without justification) + §3.15.4 phase-boundary
discipline auditable at implementation-PR review time.
The residual is **accepted** as a multi-component
discipline-failure-mode that requires concerted bypass to
surface; partial bypasses fail T3 or T11.

**Test coverage.** T3 + T11.

**Reversion clause.** Reopen if a future change to the
phase-boundary discipline (per §3.15.4) introduces dispatch
shapes where the precondition is conditionally skipped
(e.g., a hypothetical "fast-path" mode that bypasses
precondition for trusted seedhashes); substrate trigger is
the dispatch-shape change.

##### A3 — CMake-trigger bypass (stale linker artifact)

**Attack.** A future CI workflow misconfigures the harness
build — e.g., `BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON`
without `BUILD_RANDOMX_V2_MINER_LIB=ON` — leading the
harness to link against a stale `shekyl_randomx_v2` artifact
from a prior build. Stale-cache divergences surface as
harness-bug noise (the Rust side computes against the
current verifier code; the C side computes against the
stale C reference symbols); reviewer attention is misallocated
to investigating "real" divergences that are stale-link
artifacts.

**Round 3 disposition.** Structural prevention via R1-D3 (c):
`BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON` *implies*
`BUILD_RANDOMX_V2_MINER_LIB=ON` at CMake-configure-time, with
a warning emitted when the user explicitly sets
`BUILD_RANDOMX_V2_MINER_LIB=OFF`. T12 asserts the
implication mechanism: configure with the harness on + miner
off; verify the miner is auto-flipped on and the configure
succeeds with a warning. A future CMake change that reverts
the implication mechanism would fail T12.

**Residual.** A future CMake change that *both* reverts the
implication mechanism *and* updates T12 to assert the new
(broken) behavior bypasses the structural discipline. This
residual is caught by §5.7 + §8.3 + the §3.15-style
review discipline at implementation-PR time. The residual
is **accepted**.

**Test coverage.** T12.

**Reversion clause.** Reopen if CMake's
multi-config-generator semantics shift in a way that breaks
the implication mechanism (e.g., a future CMake version that
deprecates the implication-via-`set(...)` pattern); substrate
trigger is the CMake-version change.

##### A4 — R1-D11 failure-output incompleteness

**Attack.** A future divergence surfaces, but the R1-D11
structured-failure-output format omits a load-bearing field
that the reviewer needs to diagnose. The reviewer's diagnosis
is bounded by what the format includes; if a critical field
(e.g., `rust_cache_sha256`, `fork_pin`) is absent, the
reviewer cannot determine whether the divergence is a
verifier bug, a cache-derivation bug, or a fork-pin-coupling
bug, and the diagnosis stalls.

**Round 3 disposition.** Two-layer mitigation:

1. **R1-D11 schema pin** (T11). The R1-D11 disposition pins
   the failure-output schema as 11 required fields
   (`seedhash`, `data`, `rust_hash`, `c_hash`,
   `rust_cache_sha256`, `c_cache_sha256`, `mode`, `class_tag`,
   `timestamp`, `harness_version`, `fork_pin`); T11
   round-trips a synthetic divergence through the failure
   path and asserts all 11 fields are present and well-formed.
   A future change that drops a field fails T11.
2. **Forward-deferred extension shape** (R1-D10
   future-deferred reopen + R1-D14
   `--debug-cache-divergence` extension). When a real
   divergence surfaces and the existing 11 fields prove
   insufficient, the schema extends per R1-D10 (cfg-gated
   trace surface) and/or R1-D14 (full-cache byte-diff
   diagnostic mode) — both substrate-anchored reopening
   criteria are already on file from Round 1.

**Residual.** The 11 fields may prove insufficient for a
divergence class not anticipated at Round 1; the residual is
**accepted** as a future-deferred reopen criterion (per
R1-D10 + R1-D14 future-deferred reopen-criterion class) with
the substrate trigger being the actual divergence.

**Test coverage.** T11.

**Reversion clause.** Reopen on the first real divergence
that requires schema extension; substrate trigger is the
divergence's diagnostic-gap evidence.

##### A5 — CacheStore Arc retention regression (F2 backstop bypass)

**Attack.** A future Phase 2F caller-side regression
(implementation-PR-side change to the caller code that holds
`Arc<PreparedCache>` clones longer than the
Phase 2F F2 disposition allows) breaks the capacity-2
invariant under R1-D9's concurrent test. Memory grows
unboundedly under concurrent load; the F2 backstop fails to
catch it because the RSS-bound assertion's measurement
methodology was itself regressed in the same PR (e.g.,
`/proc/self/statm` reading the wrong field; tolerance band
widened silently).

**Round 3 disposition.** Three-layer mitigation:

1. **R1-D9 amendment mode-scoping pin** (Round 2 T3): the
   RSS-bound assertion is scoped to the concurrent-call test
   mode only; the F2 backstop's measurement is meaningful
   only when the harness's own accumulator state is minimal.
   The scoping prevents inheritance-by-default failures
   (false-positive bound failures in modes whose accumulator
   state grows with corpus size).
2. **T8 measurement methodology pin** (per R1-D9 F4): RSS
   sampled via `/proc/self/statm` field 2 at 100 ms
   intervals; baseline taken at test entry after
   `PreparedCache` initialization but before worker spawn;
   steady-state samples = t > 5 s. T8 asserts
   `max(steady_state_samples) − baseline ≤ 640 MiB × 1.10`.
3. **Phase 2F F2 caller-discipline boundary** (cross-PR
   discipline): Phase 2F F2's disposition documents
   `Arc<PreparedCache>` clone-lifetime caller discipline in
   the `CacheStore` rustdoc; a 3a-side regression that
   violates the caller discipline would surface in T7 + T8
   even before the F2 disposition's intended caller-side
   tests catch it.

**Residual.** A future regression that *both* breaks the
caller discipline *and* updates T8's methodology to mask the
RSS bound (e.g., changes the tolerance band from ±10% to
±100% silently) bypasses the structural discipline. This
residual is caught by §5.7 + §8.3 + the Phase 2F F2
disposition's audit posture at implementation-PR review time.
The residual is **accepted**.

**Test coverage.** T7 + T8 (catching at the harness level) +
Phase 2F caller-side tests (catching at the 3a level).

**Reversion clause.** Reopen if Phase 3a profiling surfaces
caller-side patterns that the existing R1-D9 F4 numeric pin
doesn't bound (e.g., a 3a-introduced async caller pattern
that extends `Arc` lifetime across an await point);
substrate trigger is the 3a profiling evidence per Phase
2F F2's reversion clause.

##### A6 — Adversarial-corpus drift

**Attack.** The R1-D5 grinded seedhashes become stale if the
C reference's `RANDOMX_FREQ_*` distribution
(`configuration.h:88–125`) shifts (V4 transition, a fork-pin
advance per §1.7, a future RandomX-version-3 reframe). The
"heavy in CFROUND" or "heavy in FDIV_M" criterion no longer
matches the generator's actual frequency distribution; the
worst-case-ratio test (T6) runs against effectively-random
seedhashes and the adversarial coverage degrades to random
coverage.

**Round 3 disposition.** Three-layer mitigation:

1. **§1.7 fork-pin coupling pin** (Round-0 calibration item
   3): any fork-pin-advance PR must diff the new pin's
   `randomx.h` + `configuration.h` against the prior pin's;
   identify signature changes on the 7-symbol minimal subset
   *and* `RANDOMX_FREQ_*` constant changes; update
   sub-crate declarations + adversarial-corpus grinding
   criteria in lockstep; cite the diff verification step in
   the PR description.
2. **T15 signature audit pin**: `randomx-v2-sys/Cargo.toml`
   `[package.metadata.shekyl]` `fork-pin-sha = "<commit>"`
   tracks `external/randomx-v2`'s HEAD SHA; T15 asserts the
   pinned SHA matches the actual HEAD. A fork-pin advance
   without metadata-pin advance fails T15; advancing the
   metadata pin without re-verifying the corpus is a §1.7
   discipline violation auditable at PR review.
3. **T10 corpus-hash pin**: SHA-256 of the adversarial
   corpus module's hex byte arrays is pinned; a re-grind
   without explicit reviewer attention fails T10. The
   corpus-update PR is forced to update the T10 constant in
   the same commit that updates the corpus bytes.

The three layers compose: a fork-pin advance that doesn't
re-grind the adversarial corpus fails T15 (metadata-pin
mismatch); a fork-pin advance that re-grinds the corpus
without updating T10 fails T10 (hash-pin mismatch); both
together force explicit reviewer attention to the corpus
re-grinding step + the §1.7 fork-pin coupling discipline.

**Residual.** A fork-pin advance that updates all three
layers (signature, metadata, corpus, T10 hash) without
actually re-verifying the corpus against the new
`RANDOMX_FREQ_*` distribution bypasses the structural
discipline. The residual is caught by the §1.7
fork-pin-advance PR's discipline at PR review time
(reviewer must verify the grinding criteria against the new
distribution, not just rubber-stamp the bytes). The
residual is **accepted** as a discipline-failure-mode that
the §1.7 audit-against-actual-code framework catches.

**Test coverage.** T10 + T15 (catching at the harness level)
+ §1.7 fork-pin advance PR's discipline (catching at
PR-review time).

**Reversion clause.** Reopen if upstream RandomX advances the
`configuration.h` distribution in a way that the §1.7
coupling discipline cannot catch by mechanical signature
diff (e.g., the upstream change is to the algorithm's
implementation behavior, not its constants); substrate
trigger is the upstream change.

##### A7 — Reviewer-blind nightly failures (cadence-vs-discovery gap)

**Attack.** R1-D12's nightly cadence catches per-PR-too-expensive
tests (T2, T5, T6, T7, T8) on a daily basis. If nightly
failure handling is inadequate (GitHub email notifications
missed; no automatic issue-opening; nightly results not
surfaced in any active reviewer's workflow), nightly
regressions persist for days or weeks before discovery; the
cadence-vs-discovery-latency calculus shifts unfavorably
(the nightly cadence's value depends on the discovery
latency being measured in days, not weeks).

**Round 3 disposition.** Two-layer mitigation:

1. **R1-D12 split-cadence-with-required-status-check pin**
   (Round 1): nightly is implemented as a separate GitHub
   Actions workflow that uses the same `required-status-check`
   shape as per-PR (each nightly run becomes a status check
   on the most-recent push to `dev`); a failed nightly turns
   the `dev` branch's status check red, surfacing the failure
   in any subsequent PR's review surface. The discovery
   latency is bounded by the next PR-open time, not by
   anyone actively monitoring the nightly results.
2. **§1.7 fork-pin coupling + R1-D12 + T10/T15 composition**:
   if the nightly catches a fork-pin-related drift (A6) or
   a worst-case-ratio regression (T6), the failure surfaces
   on the next PR's `dev`-branch status check, and the
   reviewer is forced to triage the nightly failure before
   merging the PR. This composition leverages the existing
   PR-review discipline rather than requiring active nightly
   monitoring.

**Residual.** A nightly failure that persists across a
multi-day period with no PR activity (e.g., during a slow
review cycle or a holiday) is undiscovered until the next
PR opens. The residual window is bounded by team activity
patterns, not by the harness discipline. The residual is
**accepted** for V3.0 given the small team size; a future
team-scale shift may warrant active nightly monitoring (e.g.,
on-call rotation, automated issue-opening).

**Test coverage.** R1-D12 CI workflow shape (operational
discipline, not a T# test) + T10 + T15.

**Reversion clause.** Reopen if a nightly failure persists
across more than 7 calendar days before discovery; substrate
trigger is the post-incident-review documentation of the
discovery gap. Active nightly monitoring (per-failure issue
auto-opening; per-failure Slack notification) becomes
warranted at that point.

##### A8 — Mode-boundary violation (§3.15.2 process-scoping bypass)

**Attack.** A future contributor adds a new harness mode (or
modifies an existing one) that violates the §3.15.2
process-scoped framing — e.g., a mode that depends on state
from a previous mode invocation (cached results from
`--mode=latency` consumed by `--mode=concurrent`), or a mode
that orchestrates multiple sub-modes within a single
invocation. The process-scoping discipline is foundational
to Phase 3a / 3c / release-gate consumers' ability to invoke
the harness without reasoning about session state; a
mode-boundary violation breaks that contract retroactively.

**Round 3 disposition.** Two-layer mitigation:

1. **§3.15.3 mode-mutual-exclusion pin**: the
   `--mode={correctness,worst-case,latency,concurrent}` flag
   is implemented as a mutually-exclusive enum at parse-time
   per §5.1.3; a single invocation runs exactly one mode.
   The dispatch is implemented as `match mode { ... }`
   without fall-through. A future change that introduces
   mode composition (e.g., `--mode=correctness,latency`)
   would have to revise the CLI parser, the enum, and the
   dispatch — visible in the implementation-PR diff.
2. **§3.15.2 free-between-modes pin + §3.15.6 framing**:
   the process-scoped (not session-scoped) framing is
   load-bearing per §3.15.2; the §3.15.6 "what §3.15 is not"
   block declares the framing as architectural, requiring a
   §3.15-amendment-round to revise. A mode-boundary
   violation that doesn't go through a §3.15-amendment is a
   discipline failure auditable at implementation-PR review.

**Residual.** A future contributor who *does* go through a
§3.15-amendment-round to revise the process-scoping is making
a legitimate substrate change, not a discipline failure;
this isn't an attack class but a legitimate evolution path.
The residual to accept is **only** the case where mode
composition lands without a §3.15-amendment-round; this is
caught at §3.15-frame audit time per §5.7 + §8.3 + §3.15.6
discipline.

**Test coverage.** §3.15.6 framing + §5.7 + §8.3 + §3.15.3
mode-mutual-exclusion at CLI-parse-time (mechanical
assertion via the enum match).

**Reversion clause.** Reopen if a future Phase 3a / 3c
consumer surfaces a legitimate need for mode composition
(e.g., a release-gate suite that needs all four modes' results
in a single invocation's output for atomic reporting);
substrate trigger is the consumer's named need, evaluated
through a §3.15-amendment-round.

##### A9 — Phase-boundary violation (R1-D14 + R1-D9 amendment invariants)

**Attack.** A future contributor modifies the per-mode
orchestration lifecycle (per §3.15.4) in a way that violates
the phase-boundary discipline that R1-D14 (precondition phase
runs to completion before byte-equality phase) and R1-D9
(RSS sampler thread spawned only inside `--mode=concurrent`
dispatch branch) depend on. The dependencies are encoded as
explicit call-site sequencing in the orchestration lifecycle;
a phase-boundary violation breaks the invariant that the
attack-class dispositions for A2 and A5 rest on.

**Round 3 disposition.** Two-layer mitigation:

1. **§3.15.4 phase-boundary discipline pin**: the
   orchestration lifecycle's phase boundaries are documented
   explicitly in §3.15.4 (`init → corpus-load →
   [precondition-all-seedhashes for correctness] →
   per-iteration loop → accumulate → report → exit`); a
   future change that reorders or interleaves phases would
   visible in the implementation-PR diff against §3.15.4.
2. **R1-D14 CacheStore-empty-during-precondition invariant +
   R1-D9 RSS-sampler-spawned-in-concurrent-mode-only
   invariant**: both invariants are implementation-PR-side
   discipline, enforced at code-level co-location (per the
   R1-D14 Round 2 amendment's module-scoping pin). A
   phase-boundary violation that breaks either invariant
   manifests as an immediate test failure (T8 fails for
   the R1-D9 invariant; the precondition test's memory peak
   degrades to ~512 MiB for the R1-D14 invariant), even if
   the violation itself isn't directly caught by a
   dedicated test.

**Residual.** A future contributor who introduces a new mode
with a different phase-boundary structure (e.g., a future
`--mode=trace` per R1-D10's reopen criterion) goes through a
§3.15-amendment-round to update §3.15.4 — this is a legitimate
substrate change, not an attack-class instance. The residual
to accept is **only** the case where phase-boundary
modifications land without a §3.15-amendment-round; this is
caught at §3.15-frame audit time per the same discipline as
A8.

**Test coverage.** §3.15.4 framing + the R1-D14 and R1-D9
amendments' load-bearing invariants + indirect catch via T3,
T7, T8 (failure-of-invariant manifests as test failure).

**Reversion clause.** Reopen if a future divergence requires
introducing a phase-boundary not contemplated at §3.15.4
(e.g., an inter-mode synchronization phase for cross-mode
state handoff); substrate trigger is the divergence's
evidence + a §3.15-amendment-round disposition.

##### A10 — Per-mode-state-shape regression (R1-D9 RSS-bound inheritance-by-default)

**Attack.** A future contributor adds a new harness mode (or
modifies an existing one) that silently inherits an invariant
that no longer applies to its state shape — e.g., a future
trace-collection mode (per R1-D10's reopen criterion) that
buffers per-iteration register snapshots and pushes the
process RSS past the 640 MiB ceiling, while the RSS-bound
assertion is still active in the new mode. The new mode's
per-mode accumulator state is structurally different from
the concurrent-call test mode's, but the inherited assertion
treats them as equivalent; the test fails for the wrong
reason (false-positive: the verifier-side F2 mitigation
hasn't regressed; the new mode's accumulator state is the
cause).

**Round 3 disposition.** Two-layer mitigation:

1. **R1-D9 amendment mode-scoping pin** (Round 2 T3): the
   RSS-bound assertion is scoped to the concurrent-call test
   mode only; the RSS sampler thread is spawned only inside
   the `--mode=concurrent` dispatch branch. A new mode does
   not inherit the RSS-bound assertion unless the new mode's
   author explicitly extends the dispatch to spawn the
   sampler. The inheritance-by-default failure mode is
   structurally prevented.
2. **§3.15.2 per-mode-state-shape table**: the per-mode state
   shape is documented in §3.15.2's table (CacheStore
   presence × C-side Cache+Vm pair × accumulators × RSS-bound
   applicability); a new mode's row addition forces explicit
   consideration of the per-column-load-bearing properties.
   The table is the audit substrate for new-mode-addition
   PRs; a row addition that doesn't specify RSS-bound
   applicability is a §3.15.2 discipline violation auditable
   at PR review.

**Residual.** A future contributor adds a new mode that has
genuine memory-pressure concerns of its own (e.g., the trace
mode's per-iteration register snapshot buffering needs a
different memory bound) — this is a legitimate substrate
need, not an attack-class instance. The residual to accept
is **only** the case where new-mode-addition's memory-pressure
disposition lands without a §3.15.2 + §3.15-amendment-round
disposition; this is caught at §3.15-frame audit time per
the same discipline as A8 + A9.

**Test coverage.** §3.15.2 table + §3.15.6 framing + the
R1-D9 amendment's mode-scoping pin + indirect catch via
T8's per-mode applicability assertion.

**Reversion clause.** Reopen if a future mode addition
surfaces a structural pattern not contemplated at §3.15.2
(e.g., a mode whose state shape is dynamic — varies across
invocations based on corpus content — and whose RSS-bound
applicability is run-time-dependent); substrate trigger is
the dynamic-state-shape evidence + a §3.15.2 + §3.15-amendment-round
disposition.

#### §4.5 Negative space: classes 2g does not defend against

Per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
"reject-now-with-named-reopening-criteria" + Phase 2F
F7-out-of-scope precedent, §4 explicitly enumerates the
attack classes 2g does **not** defend against, with
substrate-anchored reopening criteria for each:

##### N1 — V4 lattice-transition substrate shift (out of scope)

**Class.** V4 (lattice-only) is gated on external
standardization (NIST lattice threshold algorithms) and may
be 12–24 months away per
[`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)
V3.x-as-long-term-platform framing. V4's algorithm change
invalidates the RandomX-shaped harness; the harness's leg-3
catch capacity does not extend to V4's lattice substrate.

**Disposition.** Out of scope for V3.x. The harness is
RandomX-v2-specific; V4 introduces a new harness against the
V4 reference implementation (when standardized).

**Reopen criterion.** NIST lattice threshold algorithm
standardization completes + a V4 reference implementation
becomes available; substrate trigger is the standardization
evidence per V4 transition's parent plan.

##### N2 — Multi-platform corpus determinism (out of scope for V3.0)

**Class.** R1-D4's ChaCha20Rng-seeded corpus is
deterministic per the seed; T9 asserts determinism within
`ubuntu-latest` per F5. A future platform addition (macOS,
Windows, ARM Linux) may surface a determinism property that
the existing ChaCha20Rng pin doesn't guarantee (e.g., if
ChaCha20 implementation differs subtly across `rand_chacha`
versions or platform-specific compilation flags).

**Disposition.** Out of scope for V3.0. The R1-D9 macOS /
Windows fallback pin (per R1-D9 reversion clause) already
declares macOS/Windows runners are not in the CI matrix;
multi-platform determinism is therefore not a V3.0 catch
class.

**Reopen criterion.** macOS or Windows enters the CI matrix
per parent plan §6 platform-support roadmap; substrate
trigger is the CI-matrix expansion + the platform's actual
determinism evidence.

##### N3 — Proof-of-Work consensus attacks (out of scope)

**Class.** Attacks against the consensus protocol's
difficulty algorithm, block-template construction, or PoW
acceptance rules are out of scope for the verifier crate
and out of scope for the differential harness. The harness
verifies that the Rust verifier computes the same hash as
the C reference; the consensus-level attacks operate at the
daemon level (alt-chain submission rate, difficulty
exploitation, etc.) and are addressed by Phase 0 / LWMA-1 /
Phase 3a daemon-side disciplines.

**Disposition.** Out of scope; cross-reference to Phase 0,
[Phase 2F F7 out-of-scope precedent](./RANDOMX_V2_PHASE2F_PLAN.md)
+ [LWMA-1 plan](./DAA_LWMA1_PLAN.md).

**Reopen criterion.** Never within the harness; per the
verifier-crate scope boundary, this is permanently
upstream-of-the-verifier.

##### N4 — Side-channel attacks on the verifier crate (out of scope, cross-link to 2c §5.11.4)

**Class.** Cache-line residency, allocator-pressure timing,
per-iteration variance — all the side-channel surfaces
[Phase 2c §5.11.4](./RANDOMX_V2_PHASE2C_PLAN.md) declares
out-of-scope-for-public-input-use are out of scope for the
differential harness. The harness's leg-3 catch capacity is
*output equivalence*, not side-channel equivalence.

**Disposition.** Out of scope; cross-reference to Phase 2c
§5.11.4 + the public-input-only scope note inherited
forward.

**Reopen criterion.** Per Phase 2c §5.11.4: a future
consumer proposes using `shekyl-pow-randomx` with secret
material; the side-channel threat model would then become
load-bearing for the verifier crate and (transitively) for
the harness's catch surface.

##### N5 — Adversarial CI infrastructure (out of scope)

**Class.** Attacks where the CI infrastructure itself is
compromised (a malicious GitHub Actions runner that returns
"all green" without actually running the harness; a
compromised release-gate workflow that signs an artifact
built from a corrupted source tree). The harness's discipline
operates within trusted-CI substrate; CI-compromise is a
supply-chain attack class addressed at a different layer.

**Disposition.** Out of scope; cross-reference to the
reproducible-Guix-build discipline + the signed-release-tag
discipline per
[`06-branching.mdc`](../../.cursor/rules/06-branching.mdc)
release flow + [`docs/SIGNING.md`](../SIGNING.md).

**Reopen criterion.** A CI-compromise incident surfaces;
substrate trigger is the post-mortem documentation of the
incident's catch surface (and gap).

#### §4.6 Implementation-PR transition gate

**Gate condition.** §4 close + §5 hand-off contract + §6
test plan + §8 commit table collectively constitute the
**implementation-PR-ready substrate**. The Round 3 close
verifies the gate condition is satisfied:

| Substrate | Round closed | Verification |
|---|---|---|
| §1 substrate (frozen) | Phase 2F R3 | Verified at Round 0; unchanged since |
| §2 forward-actions absorbed | Round 0 | Verified at Round 0 scaffold |
| §3 (R1-D1 through R1-D14) | Round 1 close + Round 2 amendments | All 14 decisions closed at substrate-anchored defaults; Round 2 tightenings preserve closures |
| §3.15 harness actor shape | Round 2 | All six subsections substantive; lifecycle + mode set + state shape + dispatch + forward-template + negative space pinned |
| §4 threat model (A1–A10 + N1–N5) | Round 3 (this round) | Ten attack classes dispositioned with test coverage + reversion clauses; five negative-space classes with substrate-anchored reopen criteria |
| §5 hand-off contract | Round 1 (initial substance) | 16-row harness crate + 5-row randomx-v2-sys + 2-row verifier + 3-row CMake + 4-row CI; §5.6 negative space + §5.7 drift-prevention pins |
| §6 test plan | Round 1 (initial substance) | 15-row T# matrix; cadence summary; §6.9 negative space + §6.10 drift-prevention pins |
| §7 generator + fixtures plan | Round 0 (scaffold) | Substrate sufficient; implementation-PR finalizes generator-script details per §7 |
| §8 commit table | Round 1 (initial substance) | 10-commit implementation sequence; boundary-strengthening pins + scope-discipline + PR-opening citation |
| §9 CI gates | Round 0 (scaffold) | Substrate sufficient; R1-D12 + R1-D13 implementation pins inform §9 |
| §10 forward path | Round 0 (scaffold) | Substrate sufficient; Phase 3a / 3c consumer contracts pin from §3.15.5 |

**Substrate completeness.** All 11 substrate rows are
either closed (substantive content frozen by this round or
earlier) or scaffolded with sufficient substance to bound the
implementation-PR's scope. The implementation PR per §8 starts
at the substrate's current state; deviation requires a
plan-doc round (not an in-implementation-PR amendment per the
§8.3 scope-discipline pin).

**Transition disposition.** The Round 3 close authorizes
**implementation-PR opening** per [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc)
rule 2 (short-lived branch off `dev`, ≤10 commits per
§8 sequence, ≤5 working days per `06-branching.mdc` rule 2
ceiling). The implementation PR cites this Round 3 close
in its description per [`90-commits.mdc`](../../.cursor/rules/90-commits.mdc)
+ §8.4 PR-opening citation discipline. The plan-doc rounds
are closed; subsequent plan-doc changes are reopens against
substrate-anchored evidence per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc),
not iterative design-rounds.

**Post-implementation-PR reopen criteria** (sketch). The
substrate may reopen during implementation if:

1. Implementation-PR discovers a §1 substrate dependency
   that Round 0 missed (forces §1 re-anchor; rare; the
   Round 0 + Round 0 calibration verification was thorough);
2. Implementation surfaces a §3.15 actor-shape discipline
   gap (a new mode or phase-boundary concern that the §3.15
   substrate didn't contemplate);
3. Implementation surfaces an A1–A10 disposition gap (a
   substantive attack-class instance the §4 disposition
   doesn't cover);
4. CI surfaces an R1-D# numeric pin (corpus size, RSS
   ceiling, wall-clock budget) that proves substrate-unsound
   (the pin's substrate evidence was wrong, not the pin
   itself).

Each reopen-class is substrate-anchored; none is
preference-anchored per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
discipline.

---

## 5. Implementation hand-off contract (Round-N placeholder)

Reserved for Round-N's close: the **frozen-by-this-doc** table
that pins (i) the harness crate's surface (binary entry points;
optional `[lib]` test-harness surface per R1-D7); (ii) the
`randomx-v2-sys` crate's surface (the seven `extern "C"`
declarations + linker directives) if R1-D2's disposition is
(c); (iii) the verifier-crate-side cfg-gated additions if any
(R1-D10's `compute_hash_with_trace` if disposition is
(a)); (iv) the corpus-generation API; (v) the CI job interface
(invocation shape; output format; success/failure encoding).

The contract is the "what 2g lands and the implementation PR
cannot drift from" pin per [Phase 2c §5.1.1 function-body
replacement contract](./RANDOMX_V2_PHASE2C_PLAN.md) precedent
and [Phase 2F §5 hand-off contract](./RANDOMX_V2_PHASE2F_PLAN.md)
precedent.

**Not in-scope for Round 0.** Round 0 names the placeholder
explicitly so a Round-N close fills it against the closed
§3 R1-D* dispositions.

### Round 1 disposition (initial substance for §5, pre-Round-2 freeze)

The Round 1 hand-off contract enumerates the surfaces the 2g
implementation PR lands. Each row pins the surface, its visibility,
and the R1-D# disposition it closes against. The contract freezes
at Round-N close (current Round 1; superseded if Round 2 finds a
substrate-anchored reshape). The implementation PR cannot drift
from this table; surfaces not listed are out-of-scope-by-omission
per [Phase 2F §5](./RANDOMX_V2_PHASE2F_PLAN.md) precedent.

#### §5.1 Harness crate (`rust/shekyl-randomx-differential/`)

| # | Surface | Visibility | Anchor | Notes |
|---|---|---|---|---|
| 5.1.1 | `[[bin]]` `shekyl-randomx-differential` | binary | R1-D1, R1-D7, R1-D8, R1-D9, R1-D11 | Single binary; subcommand-dispatched via `--mode={correctness,worst-case,latency,concurrent}` |
| 5.1.2 | `[lib]` `shekyl_randomx_differential` | library (`#[doc(hidden)]`) | R1-D7 | Test-harness surface; consumed by `tests/`; not a public-API crate |
| 5.1.3 | `src/main.rs` | binary entry point | R1-D1, R1-D11 | Argparse + subcommand dispatch + JSON-to-stderr failure output per R1-D11 |
| 5.1.4 | `src/lib.rs` | library entry point | R1-D7 | Re-exports modules below for `tests/` consumption |
| 5.1.5 | `src/corpus_random.rs` | `pub(crate)` | R1-D4 | `ChaCha20Rng`-seeded random corpus generator; 32-byte seed pinned per R1-D4 |
| 5.1.6 | `src/adversarial_corpus.rs` | `pub(crate)` | R1-D5, R1-D6 | Committed hex byte arrays for adversarial seedhashes + u128 edge-case data; tagged by class (CFROUND, FDIV_M, Cache-miss, CBRANCH, Combined-heavy, div-by-zero, signed-div overflow, shift-by-width, u128-trunc-high) |
| 5.1.7 | `src/cache_precondition.rs` | `pub(crate)` | R1-D14 | SHA-256 cache-equivalence precondition test; `--debug-cache-divergence` mode performs byte-by-byte diff |
| 5.1.8 | `src/c_oracle.rs` | `pub(crate)` | R1-D2 | Thin wrapper over `randomx-v2-sys` `extern "C"` declarations; lifetime + error-translation discipline |
| 5.1.9 | `src/rust_subject.rs` | `pub(crate)` | R1-D14, Phase 2F §5 | Calls `PreparedCache::derive` + `compute_hash` per the Phase 2F R3-frozen public surface; no internals access |
| 5.1.10 | `src/mode_correctness.rs` | `pub(crate)` | R1-D4, R1-D5, R1-D6, R1-D14 | Per-seedhash: precondition (R1-D14) then per-data byte-equality (R1-D4 + R1-D5 + R1-D6) |
| 5.1.11 | `src/mode_worst_case.rs` | `pub(crate)` | R1-D8 | Per-(adversarial-seedhash, u128-edge-data) per-hash latency measurement; aggregates median and per-class breakdown |
| 5.1.12 | `src/mode_latency.rs` | `pub(crate)` | R1-D7 | Replaces deleted `rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs`; interleaved Rust/C measurement methodology pinned per R1-D7 |
| 5.1.13 | `src/mode_concurrent.rs` | `pub(crate)` | R1-D9 | `std::thread::spawn` workers; RSS-bound assertion via `/proc/self/statm`; byte-equality assertion per worker |
| 5.1.14 | `src/failure_output.rs` | `pub(crate)` | R1-D11 | Structured JSON failure schema; fields enumerated in R1-D11 disposition |
| 5.1.15 | `Cargo.toml` | manifest | R1-D1, R1-D2, R1-D4 | Workspace member; depends on `shekyl-pow-randomx` (workspace), `randomx-v2-sys` (workspace path), `rand_chacha` (workspace), `sha2` (workspace), `serde_json` (workspace, for R1-D11) |
| 5.1.16 | `README.md` | doc | R1-D11 | How to read a failure output; how to invoke `--debug-cache-divergence`; how to re-grind the adversarial corpus (R1-D5/R1-D6 grinding budget per F3) |

#### §5.2 `randomx-v2-sys` sub-crate (`rust/randomx-v2-sys/`)

| # | Surface | Visibility | Anchor | Notes |
|---|---|---|---|---|
| 5.2.1 | `src/lib.rs` | `pub` | R1-D2 | Seven hand-written `extern "C"` declarations per R1-D2 disposition table |
| 5.2.2 | `build.rs` | build | R1-D2, R1-D3 | Emits `cargo:rustc-link-lib=static=shekyl_randomx_v2` + `cargo:rustc-link-search=…`; the search path is configured from `BUILD_RANDOMX_V2_MINER_LIB`'s output directory per R1-D3's CMake wiring |
| 5.2.3 | `Cargo.toml` | manifest | R1-D2 | Workspace member; build-dep none beyond stdlib; consumers list = `shekyl-randomx-differential` only |
| 5.2.4 | `Cargo.toml` `[package.metadata.shekyl]` | metadata | R1-D2 | `fork-pin-coupled = true` marker per R1-D2 future-maintenance hardening; advances to `external/randomx-v2` require re-verifying signatures |
| 5.2.5 | `README.md` | doc | R1-D2, R1-D13 | "This crate's only consumer is `shekyl-randomx-differential`. Pattern C invariant exempt per R1-D13. Fork-pin coupling per §1.7." |

#### §5.3 Verifier-crate-side additions (`rust/shekyl-pow-randomx/`)

| # | Surface | Visibility | Anchor | Notes |
|---|---|---|---|---|
| 5.3.1 | (none) | — | R1-D10 | R1-D10 closes at (b) — no `compute_hash_with_trace` cfg-gated entry point. The verifier crate gains zero new surfaces in 2g. |
| 5.3.2 | **Deletion**: `tests/perf/per_hash_latency.rs` | — | R1-D7 | Placeholder deletion; the 2g implementation PR commit closing R1-D7 marks "closes Phase 2c R3-minor-2" per R1-D7's audit-trail discipline |

#### §5.4 CMake wiring (`external/CMakeLists.txt`)

| # | Surface | Visibility | Anchor | Notes |
|---|---|---|---|---|
| 5.4.1 | `option(BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS "Build the Phase 2g Rust/C differential harness" OFF)` | CMake | R1-D3 | Default OFF; implies `BUILD_RANDOMX_V2_MINER_LIB=ON` when set |
| 5.4.2 | `if(BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS AND NOT BUILD_RANDOMX_V2_MINER_LIB)` `set(BUILD_RANDOMX_V2_MINER_LIB ON …)` | CMake | R1-D3 | Implication mechanism; warning emitted on auto-flip per R1-D3 |
| 5.4.3 | No new CMake targets | — | R1-D3 | The harness's Cargo build runs out-of-band from CMake; CMake's role is exclusively building the C reference's static lib for `randomx-v2-sys` to link |

#### §5.5 CI surface (`.github/workflows/`)

| # | Surface | Visibility | Anchor | Notes |
|---|---|---|---|---|
| 5.5.1 | New job in `build.yml` (or new workflow file): per-PR differential-harness job | CI | R1-D12 | Cadence: per-PR; runner: `ubuntu-latest`; budget: ~7 min wall-clock per F5 |
| 5.5.2 | New scheduled workflow: nightly differential-harness job | CI | R1-D12 | Cadence: nightly (cron); runner: `ubuntu-latest`; budget: ~25 min wall-clock per F5 |
| 5.5.3 | Release-gate workflow entry | CI | R1-D12 | Cadence: tag-triggered; runner: `ubuntu-latest`; budget: ~10 min wall-clock per F5 |
| 5.5.4 | Crate-invariant script extension (`scripts/check-crate-invariants.sh` or equivalent) | tooling | R1-D13 | Pattern coverage extends to `randomx-v2-sys` + `shekyl-randomx-differential`; `randomx-v2-sys` exempt from Pattern C |

#### §5.6 What 2g does **not** land

The implementation PR does **not** introduce:

- Any new verifier-crate-side API surface (per R1-D10 (b) close)
- Any new committed reference vectors (per §7 disposition; the C reference is runtime ground truth)
- Any consumption of the harness's `randomx-v2-sys` from other workspace members (per R1-D13 (c) close; `randomx-v2-sys` is sole-consumer-locked to `shekyl-randomx-differential`)
- Any cfg flag or feature gate on `shekyl-pow-randomx` for harness-only behavior (per R1-D10 (b) close; no `harness-trace` feature)
- Any modification to the existing Phase 2F R3-frozen public surface (`PreparedCache`, `Seedhash`, `compute_hash`, `CacheStore`); the harness consumes the surface as-is

#### §5.7 Drift-prevention discipline

Per [Phase 2c §5.1.1](./RANDOMX_V2_PHASE2C_PLAN.md) and [Phase 2F §5](./RANDOMX_V2_PHASE2F_PLAN.md)
precedent, the §5.1–§5.5 tables are the **only** new surfaces the
2g implementation PR may introduce. Reviewer rejection criterion
for the implementation PR: any file, module, function, or surface
added by the PR that is not listed in §5.1–§5.5 (or that is listed
in §5.6) is grounds for scope-creep rejection per
[`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)
"while we're here is the enemy" discipline. The implementation PR
commit message cites the contract entry it closes against (e.g.,
"closes §5.1.7 R1-D14 cache-precondition module").

**Round 2 may reshape this contract.** Per
[`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
A1 + A3, the threat-model pass in Round 2 may surface findings
requiring contract reshape (e.g., a Round-2 finding that the
R1-D11 failure output needs additional fields would extend §5.1.14;
a Round-2 finding that the §5.5.4 crate-invariant script needs an
additional pattern would extend §5.5.4). Round 2's close folds any
contract reshape into this table; the contract freezes at Round-N
close.

---

## 6. Test plan (Round-N placeholder)

Reserved for Round-N's close: the test matrix the implementation
PR's CI gates assert against. Will mirror [Phase 2F §6](./RANDOMX_V2_PHASE2F_PLAN.md)
and [Phase 2c §9](./RANDOMX_V2_PHASE2C_PLAN.md) shapes — a
table per test category (corpus-correctness; thread-safety;
per-hash-latency-population; reproducibility) naming the test
function, the input shape, the assertion, the cadence, and the
substrate it's defending.

**Not in-scope for Round 0.** Round 0 names the placeholder
explicitly.

### Round 1 disposition (initial substance for §6, pre-Round-2 freeze)

The test plan is the table the implementation PR's CI gates assert
against. Each row is anchored to a closed R1-D# disposition and the
§5 hand-off contract surface it exercises. The plan freezes at
Round-N close (current Round 1; Round 2 may extend or reshape based
on threat-model findings).

#### §6.1 Category A: Correctness (per-`(seedhash, data)` byte-equality)

| # | Test | Surface | Input | Assertion | Cadence | Anchor |
|---|---|---|---|---|---|---|
| T1 | `random_corpus_byte_equality` | `mode_correctness` (§5.1.10) | R1-D4 random corpus: 16 seedhashes × 8 data values (per-PR); 32 × 32 (nightly) | For each `(seedhash, data)` pair: Rust `compute_hash(prepared, data)` == C `randomx_calculate_hash(cache, vm, data)` (byte-equality of 32-byte output) | per-PR + nightly | R1-D4 |
| T2 | `adversarial_corpus_byte_equality` | `mode_correctness` (§5.1.10) | R1-D5 adversarial-seedhash corpus × R1-D6 u128-edge-case data; union per F6 sequencing | Same per-pair byte-equality; PER-CLASS reporting in failure output (R1-D11) | nightly + release-gate | R1-D5, R1-D6 |
| T3 | `cache_precondition_sha256` | `cache_precondition` (§5.1.7) | Every seedhash in T1/T2/T4/T5/T6 corpus | SHA-256(Rust `Cache`) == SHA-256(C `randomx_cache`); failure aborts the corpus pass for that seedhash before T1/T2 per-data tests run | per-PR + nightly + release-gate | R1-D14 |
| T4 | `cache_precondition_byte_diff` | `cache_precondition` (§5.1.7) with `--debug-cache-divergence` | Manual: operator invokes post-T3-failure with `--seedhash <hex>` | First divergent offset + ±64-byte window logged; non-zero exit | manual post-failure | R1-D14 |

#### §6.2 Category B: Performance (per-hash latency + worst-case ratio)

| # | Test | Surface | Input | Assertion | Cadence | Anchor |
|---|---|---|---|---|---|---|
| T5 | `per_hash_latency_median` | `mode_latency` (§5.1.12) | N=1024 hashes per side, interleaved Rust/C | median(Rust per-hash wall-clock) / median(C per-hash wall-clock) ≤ 3.0× per R1-D7; report median, p95, max in `BENCH_RESULTS.md` | nightly + release-gate | R1-D7, Parent §6 |
| T6 | `worst_case_ratio` | `mode_worst_case` (§5.1.11) | R1-D5+R1-D6 union corpus; 16 data values per seedhash | max(Rust per-hash wall-clock / C per-hash wall-clock) ≤ 5.0× per R1-D8 / Parent §6; report per-class breakdown in `BENCH_RESULTS.md` | nightly + release-gate | R1-D8, Parent §6 |

#### §6.3 Category C: Thread-safety (concurrent-call correctness + RSS-bound)

| # | Test | Surface | Input | Assertion | Cadence | Anchor |
|---|---|---|---|---|---|---|
| T7 | `concurrent_byte_equality` | `mode_concurrent` (§5.1.13) | 4 production + 1 reserve workers; 256 hashes per worker; shared `CacheStore` (capacity 2 per Phase 2F R3-D4) | (i) no panic; (ii) no deadlock (test completes within wall-clock bound = 4× single-thread bound); (iii) for each per-worker `(seedhash, data)` pair: byte-equality of Rust hash output across all workers and against C `randomx_calculate_hash` | nightly + release-gate | R1-D9, Phase 2F F2 |
| T8 | `concurrent_rss_bound` | `mode_concurrent` (§5.1.13) | Same as T7 | RSS during concurrent execution ≤ 640 MiB (±10% tolerance) per F4; measured via `/proc/self/statm` (Linux); RSS sampled at 100 ms intervals; max sample reported in `BENCH_RESULTS.md` | nightly + release-gate | R1-D9, Phase 2F F2 |

#### §6.4 Category D: Reproducibility / determinism

| # | Test | Surface | Input | Assertion | Cadence | Anchor |
|---|---|---|---|---|---|---|
| T9 | `random_corpus_seed_determinism` | `corpus_random` (§5.1.5) | Two independent invocations with the same 32-byte seed (R1-D4 pin) | Byte-identical corpus output across invocations; assert in unit test (no external dependency) | per-PR | R1-D4 |
| T10 | `adversarial_corpus_hash_pin` | `adversarial_corpus` (§5.1.6) | SHA-256 of the entire adversarial-corpus module's hex byte arrays | SHA-256 matches a pinned constant; failure indicates accidental drift in the committed corpus, surfaces in code review | per-PR | R1-D5, R1-D6 |

#### §6.5 Category E: Failure-output contract

| # | Test | Surface | Input | Assertion | Cadence | Anchor |
|---|---|---|---|---|---|---|
| T11 | `failure_output_schema_round_trip` | `failure_output` (§5.1.14) | Injected synthetic divergence in a test-only mode (separate `--mode=test-failure` subcommand) | Stderr emits valid JSON; required fields per R1-D11 schema present (`seedhash`, `data`, `rust_hash`, `c_hash`, `rust_cache_sha256`, `c_cache_sha256`, `mode`, `class_tag`, `timestamp`, `harness_version`, `fork_pin`); stdout emits human-readable log | per-PR | R1-D11 |

#### §6.6 Category F: Build-system + crate-invariant

| # | Test | Surface | Input | Assertion | Cadence | Anchor |
|---|---|---|---|---|---|---|
| T12 | `cmake_implication_auto_flip` | §5.4.2 | Configure with `BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON` + `BUILD_RANDOMX_V2_MINER_LIB=OFF` (explicit) | CMake auto-flips `BUILD_RANDOMX_V2_MINER_LIB=ON`; warning emitted; configure succeeds | per-PR | R1-D3 |
| T13 | `crate_invariant_script_coverage` | §5.5.4 | Run `check-crate-invariants.sh` against the workspace | Patterns A/B/D/E enforced against `shekyl-randomx-differential` + `randomx-v2-sys`; Pattern C exempted for `randomx-v2-sys` only; script exits 0 | per-PR | R1-D13 |
| T14 | `randomx_v2_sys_sole_consumer` | §5.2.5 README invariant | `cargo metadata` query: which workspace members depend on `randomx-v2-sys`? | Exactly one consumer: `shekyl-randomx-differential`; any additional consumer is a Pattern-C-violation-by-precedent and fails the invariant check | per-PR | R1-D13 |

#### §6.7 Category G: Fork-pin coupling

| # | Test | Surface | Input | Assertion | Cadence | Anchor |
|---|---|---|---|---|---|---|
| T15 | `randomx_v2_sys_signature_audit_pin` | §5.2.4 metadata | `external/randomx-v2` HEAD commit + `randomx-v2-sys/Cargo.toml` `[package.metadata.shekyl]` `fork-pin-sha = "…"` | Metadata's pinned SHA matches `external/randomx-v2`'s HEAD SHA; a mismatch indicates the fork pin advanced without re-verifying the `extern "C"` declarations per R1-D2 hardening | per-PR | R1-D2, §1.7 |

#### §6.8 Cadence summary

| Cadence | Tests | Wall-clock budget (per F5) |
|---|---|---|
| per-PR | T1, T3, T9, T10, T11, T12, T13, T14, T15 | ~7 min (per R1-D12 F5 pin) |
| nightly | T1 (larger corpus), T2, T3, T5, T6, T7, T8 | ~25 min (per R1-D12 F5 pin) |
| release-gate | T2, T3, T5, T6, T7, T8 | ~10 min (per R1-D12 F5 pin) |
| manual post-failure | T4 | bounded by operator |

#### §6.9 What 2g does **not** test

The test plan does **not** include:

- Property-based testing (e.g., `proptest`) — corpus shape is closed at R1-D4/D5/D6 as deterministic + grinded, not generated per-test-run
- Fuzzing (e.g., `cargo fuzz`) — out-of-scope-by-omission; corpus discipline is leg-3 backstop, not adversarial-input discovery
- Mutation testing — out-of-scope; the harness exists to test the verifier, not the harness itself
- Cross-platform consistency (e.g., macOS, Windows, ARM64) — out-of-scope-by-omission; the per-F5 runner pin is `ubuntu-latest` x86_64 exclusively; cross-platform divergence is a future-deferred FOLLOWUPS item per R1-D12 reopen criterion

#### §6.10 Drift-prevention discipline

Per [Phase 2F §6](./RANDOMX_V2_PHASE2F_PLAN.md) precedent, the
§6.1–§6.7 tables are the **only** new test surfaces the 2g
implementation PR introduces. Tests added during implementation
that do not map to a T# row require a Round-2 design-round entry
extending the table; the implementation PR commit message cites
the T# row each new test closes against.

**Round 2 may extend this matrix.** Threat-model findings in
Round 2 may surface new test categories (e.g., a Round-2 finding
that an additional corpus-coverage class is required adds tests
in §6.1 or §6.2; a Round-2 finding that an additional concurrent
race condition is suspected adds tests in §6.3). Round 2's close
folds any extensions into this matrix; the matrix freezes at
Round-N close.

---

## 7. Generator / fixtures plan

**Disposition: 2g introduces no new committed reference vectors.**

The differential harness consumes the C reference
(`shekyl_randomx_v2`'s `randomx_calculate_hash`) as **ground
truth at runtime**: for each `(seedhash, data)` pair, the harness
invokes both `compute_hash` (Rust) and `randomx_calculate_hash`
(C) in the same process against the same input bytes and asserts
byte-equality of the two outputs. The C output is the reference;
no pre-computed reference bytes need to be committed to the repo.

This confirms against [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md)
§5.11.5 leg 3 framing: the corpus is a **sampled set of inputs**
plus an **adversarial set of inputs**; the assertion shape is
**byte-equality against the C reference per (seedhash, data)
pair**. There is no fixture-side artifact analogous to the
T1–T8 spec vectors (per 2c §6) or the T9–T15 per-opcode vectors
(per 2d §6) — those are *spec-derived* reference bytes that
encode the expected canonical RandomX v2 output; the harness's
inputs are *substrate-derived* (per R1-D4 corpus generation;
per R1-D5 / R1-D6 adversarial seedhashes) and the expected
output is *the C reference's runtime output*, not a committed
bytestring.

**Forward-action.** If a Round-N substrate finding surfaces a
reason to commit reference bytes (e.g., a specific seedhash
that has produced a Rust/C divergence and the divergence's
disposition is "2d audit table row is wrong; commit the C
reference's bytes as a regression fixture"), the fixture lands
under `tests/vectors/reference/randomx_v2/` per the existing
spec-vector home, with `.meta.txt` provenance per the Phase 2d
generator-CLI shape. This is a hypothetical addition gated on a
substrate finding; it is not a 2g-Round-0 deliverable and not
a 2g-Round-1 deliverable absent the trigger.

**Adversarial-corpus storage.** R1-D5 / R1-D6 may commit
*seedhash bytes* (not reference output) under
`rust/shekyl-randomx-differential/src/adversarial_corpus.rs` or
analogous (per the R1-D5 default expectation). Seedhashes are
~10–20 32-byte arrays (≈320–640 bytes) — well below the
storage-cost threshold that would justify a fixture-file shape.
The Round 1 disposition pins the format.

---

## 8. Commit table (Round-N placeholder)

Reserved for Round-N's close: the implementation-PR commit
sequence. Will mirror [Phase 2F §8](./RANDOMX_V2_PHASE2F_PLAN.md)
and [Phase 2c §8](./RANDOMX_V2_PHASE2C_PLAN.md) shapes —
ordered commits with per-commit bisection invariants ("every
commit passes `cargo build` and `cargo clippy -D warnings` per
[`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) rule
and [Phase 2c §14 Round 0 R0-D8](./RANDOMX_V2_PHASE2C_PLAN.md)).
Expected commit count per [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc)
rule 2 (≤10 commits, ≤5 working days).

**Not in-scope for Round 0.** Round 0 names the placeholder
explicitly.

### Round 1 disposition (initial substance for §8, pre-Round-2 freeze)

The 2g implementation PR lands as 10 commits on a short-lived
branch off `dev` per
[`06-branching.mdc`](../../.cursor/rules/06-branching.mdc)
rule 2 (≤10 commits, ≤5 working days). Each commit closes against
a §5 hand-off contract surface or a §6 T# test row. Per
[`90-commits.mdc`](../../.cursor/rules/90-commits.mdc) scope
discipline, no commit aggregates unrelated changes; per-commit
bisection invariant is "every commit passes `cargo build
--workspace --all-targets`, `cargo clippy --workspace
--all-targets --keep-going -- -D warnings`, and `cargo fmt --all
-- --check`" (the harness binary's runtime correctness is
asserted only at C10 when CI wires the harness into the pipeline;
intermediate commits assert build cleanliness against the
workspace, not behavioral correctness against the C reference).

#### §8.1 Commit sequence

| # | Subject (≤72 chars, imperative, prefix `randomx-v2-diff:`) | §5/§6 surface closed | Bisection invariant |
|---|---|---|---|
| C1 | `randomx-v2-diff: introduce randomx-v2-sys crate skeleton` | §5.2.1, §5.2.3, §5.2.4 | Builds; clippy clean; `randomx-v2-sys` is in `members =` list; `extern "C"` declarations present per R1-D2 table |
| C2 | `randomx-v2-diff: wire CMake BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS option` | §5.4.1, §5.4.2, §5.4.3 | Configure with the new option succeeds; `BUILD_RANDOMX_V2_MINER_LIB` auto-flips with warning per T12; existing CMake builds unchanged when option is OFF |
| C3 | `randomx-v2-diff: implement randomx-v2-sys build.rs linker directives` | §5.2.2 | `cargo build -p randomx-v2-sys` succeeds when `BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON` was configured; otherwise emits a clear build-time error pointing to the CMake option |
| C4 | `randomx-v2-diff: introduce shekyl-randomx-differential crate skeleton` | §5.1.1, §5.1.2, §5.1.3, §5.1.4, §5.1.15, §5.1.16 | Builds; clippy clean; `[[bin]]` + `[lib]` targets present; `main.rs` argparse + subcommand-dispatch skeleton in place; runs with `--help` |
| C5 | `randomx-v2-diff: implement random + adversarial corpora` | §5.1.5, §5.1.6, T9, T10 | Builds; clippy clean; T9 + T10 unit tests pass; R1-D4 32-byte seed pinned; R1-D5/R1-D6 adversarial hex byte arrays committed with per-class tags per R1-D5 / R1-D6 |
| C6 | `randomx-v2-diff: implement cache-precondition + Rust/C oracle wrappers` | §5.1.7, §5.1.8, §5.1.9, T3, T4 | Builds; clippy clean; `--debug-cache-divergence` flag wired per T4; SHA-256 default path wired per R1-D14 + T3 |
| C7 | `randomx-v2-diff: implement correctness + worst-case + latency modes` | §5.1.10, §5.1.11, §5.1.12, T1, T2, T5, T6 | Builds; clippy clean; subcommand dispatch routes `--mode={correctness,worst-case,latency}` to the right module; smoke-test against a 1-seedhash, 1-data corpus passes byte-equality |
| C8 | `randomx-v2-diff: implement concurrent mode + RSS-bound assertion` | §5.1.13, T7, T8 | Builds; clippy clean; T7 + T8 pass on a 4+1-worker × 256-hash run; `/proc/self/statm` RSS-sampling methodology in place per F4 |
| C9 | `randomx-v2-diff: implement failure-output JSON schema + delete placeholder` | §5.1.14, §5.3.2, T11 | Builds; clippy clean; T11 passes against the synthetic `--mode=test-failure` injection; `rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs` deletion commits with message "closes Phase 2c R3-minor-2" per R1-D7 audit-trail discipline |
| C10 | `randomx-v2-diff: wire CI gates + extend crate-invariant script` | §5.5.1, §5.5.2, §5.5.3, §5.5.4, T13, T14, T15 | Per-PR + nightly + release-gate workflows configured per R1-D12 cadence; crate-invariant script extended per R1-D13; T13/T14/T15 pass in CI |

#### §8.2 Bisection-invariant strengthening at the boundaries

Two boundary points carry stricter invariants than the per-commit
build-cleanliness baseline:

- **C4 → C5 boundary.** After C4 (skeleton lands) and before C5
  (corpora land), the harness binary builds and accepts `--help`
  but cannot produce hash output. A reviewer bisecting a future
  regression to C4 ↔ C5 sees the boundary as "before harness
  was functional" vs. "after harness was functional"; the
  intermediate state (C4 lands, C5 doesn't yet) is a legitimate
  bisection-target with bounded behavior (`--help` works;
  `--mode=*` returns a clear "corpus modules not yet wired"
  error rather than silently producing empty output).
- **C9 → C10 boundary.** After C9 (full harness landed; placeholder
  deleted) and before C10 (CI wired), the harness is locally
  runnable end-to-end but does not run in CI. A reviewer
  bisecting a future CI regression to C9 ↔ C10 sees the
  boundary as "harness existed but didn't run in CI" vs.
  "harness existed and ran in CI"; the intermediate state is a
  legitimate bisection-target with no behavioral impact on the
  verifier (the harness is a separate workspace member; its
  pre-CI-wiring presence doesn't affect `cargo test --workspace`
  beyond `cargo build` cleanliness).

#### §8.3 What §8.1 enforces (scope discipline)

Per [`90-commits.mdc`](../../.cursor/rules/90-commits.mdc) and
[`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)
"while we're here is the enemy":

- No commit modifies the verifier crate's public API surface
  (`shekyl-pow-randomx`'s post-2F surface is frozen per §5.3);
  C9's deletion is the only verifier-crate-touching commit, and
  it deletes a placeholder, not a surface
- No commit re-implements anything 2c/2d/2f already landed
- No commit introduces dependencies beyond those listed in
  §5.1.15 + §5.2.3
- No commit re-shapes the Round 1 dispositions; any
  implementation-time discovery that requires a R1-D# reshape
  triggers a Round-2 design-round entry, not a commit-table
  amendment-in-place

#### §8.4 PR opening discipline

The 2g implementation PR's description cites this commit table by
§8.1 row. Each commit's subject prefix `randomx-v2-diff:` and
contract-row citation (in the commit body) lets reviewers
mechanically verify that every commit closes against a planned
contract row and that no commit aggregates beyond its row.

**Round 2 may extend this sequence.** Threat-model findings in
Round 2 may add commits (e.g., a Round-2 finding requiring an
additional test category §6.C extension adds a commit between
C8 and C9). Round 2's close folds any new commits into this
table; the sequence freezes at Round-N close.

---

## 9. CI gates

2g's CI footprint is the **incremental** addition over the
existing gates inherited from 2c/2d/2f. The split between
"2g adds" and "2g inherits unchanged" is load-bearing because
two distinct per-hash performance gates exist at different
cadences and 2g is responsible for only one (the production of
the harness binary; not the per-PR gate that consumes it).

### 9.1 2g adds

| Gate | Cadence | Source | Description |
|------|---------|--------|-------------|
| Byte-equality differential pass (sampled + adversarial corpus) | Per-PR (default per R1-D12 (c) first arm) | New: `rust/shekyl-randomx-differential/` harness binary + `.github/workflows/build.yml` or sibling `differential.yml` step (R1-D12) | Runs the harness binary against the per-PR corpus subset (R1-D4 + R1-D5 + R1-D6 subset per R1-D12 pin); fails CI on any byte-equality divergence. Matches parent-plan 2g todo: "CI job runs the harness; failure fails CI." |
| Byte-equality differential pass (full corpus) | Scheduled nightly (default per R1-D12 (c) second arm) | New: scheduled workflow trigger | Runs the harness binary against the full corpus (R1-D4 full + R1-D5 + R1-D6 full); fails the scheduled run on divergence. Catches regressions invisible to the per-PR subset. |
| Worst-case Rust/C ratio ≤ 5.0× (adversarial corpus) | Release-gate suite (default per R1-D12 (c) third arm; matches parent §6 Round 4 cadence) | New: release-gate workflow (R1-D8 `--mode=worst-case` subcommand on the harness binary) | Asserts the worst-case per-hash ratio across the adversarial corpus is ≤ 5.0× per parent §6 line 238. Release-gate-suite cadence, not per-PR; reports the actual ratio to `BENCH_RESULTS.md`. |
| `per_hash_latency_ratio_within_budget` test body | Inherited workflow trigger; **not a CI gate at 2g** | Existing placeholder at `rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs`; R1-D7 replaces the body (default: move to harness crate) | 2g populates the body per R1-D7; the body asserts the median Rust/C ratio is ≤ 3.0× per parent §6 line 237. **The per-PR CI gate activates at Phase 3a per parent §6 line 243 — not at 2g.** 2g produces the harness binary the 3a per-PR step consumes. |
| Concurrent-call `CacheStore` thread-safety test | Inherited `cargo test` workflow trigger | New test in the harness crate per R1-D9 | The success criterion (no panic, no deadlock, byte-equality of pairs) per R1-D9 disposition; fails CI on any of the three. |

### 9.2 2g inherits unchanged

- [`check_randomx_fpu_rounding.sh`](../../scripts/ci/check_randomx_fpu_rounding.sh)
  per Phase 2d §3.5 R5-D1 + §3.7 R6-D1 — FPU rounding-mode
  primitive scope gate.
- [`check_randomx_crate_invariants.sh`](../../scripts/ci/check_randomx_crate_invariants.sh)
  per Phase 2F §3.6 R1-E1 + PR #72 NF7/NF8 — crate-isolation
  grep gate over `rust/shekyl-pow-randomx/{src,tests,benches}`.
  Per R1-D13, the gate may be extended in scan-scope to cover
  the new `randomx-v2-sys` crate (Patterns A/B) and the new
  differential-harness crate (Patterns A/B/C) under option
  (c); the existing `shekyl-pow-randomx`-scoped coverage is
  unchanged.
- `cargo fmt --all -- --check`
  ([`.github/workflows/build.yml`](../../.github/workflows/build.yml)
  line 584).
- `cargo clippy --workspace --all-targets --keep-going -- -D warnings`
  (line 596).
- `cargo test --locked --workspace` (line 602).
- "Gate 2: `shekyl-pow-randomx` debug-vs-release equivalence"
  (line 606).

### 9.3 Cadence rationale (load-bearing distinction)

Per [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §6:

- **Per-hash latency average ≤ 3.0×** — per-PR cadence;
  **activated at Phase 3a, not 2g** (line 243). The 2g
  deliverable is the *harness binary*; the 3a deliverable is
  the *per-PR CI wiring that consumes the harness binary*.
  Pre-3a (during 2g) the benchmark runs in 2g without CI
  gating per the parent-plan disposition.
- **Worst-case Rust/C ratio ≤ 5.0×** — release-gate-suite
  cadence (line 238 Round 4 addition). Per-PR is excluded
  because the corpus-size × per-hash-cost product exceeds the
  per-PR budget; release-gate is the right cadence for the
  deterministic-corpus framing.
- **Byte-equality differential pass** — per-PR cadence on a
  corpus subset (R1-D12 (c) default); scheduled nightly on the
  full corpus. Per parent-plan 2g todo: "CI job runs the
  harness; failure fails CI."

The three cadences are independent: 2g's per-PR byte-equality
gate is a correctness gate; the per-hash-latency average gate
(3a-land) is a performance gate; the worst-case-ratio gate is
a DoS-resistance gate. None subsumes another; all three are
required for genesis release.

---

## 10. Forward path

What 2g hands off to subsequent phases:

- **3a** consumes the harness binary (or its `[lib]` test-harness
  surface per R1-D7) to populate the per-PR per-hash latency CI
  gate per parent §6 line 243. The 3a plan-doc cites this hand-off
  as the activation trigger for the per-PR CI step.
- **3a** also consumes the
  [Phase 2F §10.3 FFI-shim discipline](./RANDOMX_V2_PHASE2F_PLAN.md)
  (already pinned at 2F; 2g does not amend). The `shekyl-ffi`
  shim's per-PR CI step asserts the same byte-equality property
  2g's harness asserts at the verifier-crate boundary, now at
  the FFI boundary. 2g's harness validates the verifier crate's
  output; 3a's per-PR step validates that the FFI shim does
  not introduce a divergence on the C++/Rust boundary.
- **3c** absorbs the binary-level `nm`-on-`shekyld` symbol-isolation
  check per [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) "RandomX v2
  Phase 3c — `aes`-crate symbol-surface check" entry (line 1557ff).
  2g's source-level invariants (per R1-D13) are the Rust-side
  companion to 3c's binary-level check; 2g does not duplicate
  the post-link `nm` shape.
- **Release-gate suite** absorbs the worst-case Rust/C ratio
  ≤ 5.0× gate per R1-D8 + parent §6 Round 4. 2g produces the
  release-gate subcommand; the release-gate workflow is
  invoked on release-tag PRs.
- **Release-gate suite** also absorbs the 600k-block initial-sync
  wall-time test per parent §6 line 242 — not a 2g deliverable;
  the 600k-block test is hand-off from Phase 0 / 3a via the
  synthetic chain harness per [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md)
  §8 lines 449–462.
- **Documentation closure** per [`91-documentation-after-plans.mdc`](../../.cursor/rules/91-documentation-after-plans.mdc):
  the implementation-PR (Round-N close) updates
  [`docs/CHANGELOG.md`](../CHANGELOG.md), flips the parent plan
  [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) `phase2g-differential-harness`
  todo from `pending` to `completed`, updates
  [`rust/shekyl-pow-randomx/BENCH_RESULTS.md`](../../rust/shekyl-pow-randomx/BENCH_RESULTS.md)
  with the Rust-vs-C ratio table for the production-target
  hardware-class baseline, and adds a 2g cross-link to any
  affected FOLLOWUPS items (RandomX v2 V3.x Guix obligation
  pickup; per-`CONFIG` install-path FOLLOWUPS entry if R1-D3's
  disposition triggered escalation).

---

## 11. Round history

**Round-count expectation (per §0 calibration block).** 2g's
Round 1 is expected to converge in ≤3 rounds because there is
no new public API surface; the substantive decisions are
corpus shape, CI placement, and harness wiring, all bounded by
the §1 substrate. The expectation calibrates reviewer attention
budget; it is not a hard ceiling per
[`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc)
reversion-clause discipline, and substrate findings that
warrant a Round-2 architectural reframe legitimately reopen
the round-count budget.

| Round | Date | Outcome |
|-------|------|---------|
| Round 0 (Scaffold) | 2026-05-24 | This document. Pins the substrate carry-forwards from [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §6 + §7 line 248 + Phase 2 sub-PR 2g todo, [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) §5.11.5 + §5.11.8, [`RANDOMX_V2_PHASE2D_PLAN.md`](./RANDOMX_V2_PHASE2D_PLAN.md) §3.4, and [`RANDOMX_V2_PHASE2F_PLAN.md`](./RANDOMX_V2_PHASE2F_PLAN.md) §1.1 (current public API) + §10.1 (precursor PR) + §10.4 (`compute_hash_with_trace` pre-pin) + §10.5 (three-leg audit posture). Enumerates §3 Round 1 decision points R1-D1 (workspace placement) through R1-D14 (cache-state byte-equivalence precondition) with named option sets, criteria, default expectations, and reopen-criterion sketches. Out-of-scope items pinned in front-matter (no per-PR per-hash latency CI gate at 2g — Phase 3a-land; no binary-level `nm` check — Phase 3c-land; no 600k-block sync test — release-gate-suite-land; no parallel `Cache::derive` — FOLLOWUPS-land; no side-channel timing differential — out-of-2g; no C-side miner state-machine — parent-plan line 30 explicit). §4 threat model, §5 implementation hand-off contract, §6 test plan, §8 commit table are placeholders reserved for Round-N close. §7 generator/fixtures plan confirms 2g introduces no new committed reference vectors (the harness consumes the C reference at runtime as ground truth per 2c §5.11.5 leg 3 framing); adversarial seedhash bytes (R1-D5 + R1-D6) commit under the harness crate per the R1-D5 default expectation. §9 CI gates split between "2g adds" (per-PR byte-equality differential pass; nightly full corpus; release-gate worst-case ratio; per-hash latency placeholder body via R1-D7; concurrent-call thread-safety test via R1-D9) and "2g inherits unchanged" (`check_randomx_fpu_rounding.sh`, `check_randomx_crate_invariants.sh`, fmt/clippy/test, debug-vs-release equivalence). §10 forward path names the 3a / 3c / release-gate / documentation-closure hand-offs. Round 1 supersedes this scaffold's §3 / §4 / §5 / §6 / §8 with closed-decision content; the scaffold remains the substrate-capture provenance per [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc) plan-doc Round-0 framing. |
| Round 0 calibration corrections | 2026-05-24 | Post-scaffold calibration pass against the Round 0 doc, applied as substrate-tightening additions (no decision-reopening; Round 0 closed no decisions). Eight observations incorporated. **(1)** §3 new decision point **R1-D14 (cache-state byte-equivalence precondition)** added after R1-D13: how the harness establishes Rust/C cache byte-equivalence as a precondition for the per-`(seedhash, data)` byte-equality test on `compute_hash` output; options (a) implicit / (b) explicit upstream test / (c) inlined assertion; default (b); reopen criterion against full-cache memory pressure vs. CI runner-class budget. The R1-D11 bisection-failure-mode question is bounded by R1-D14: a (a)-disposition makes R1-D11's output unable to distinguish cache-derivation from dispatch divergence even when R1-D10's optional per-iteration trace is included. **(2)** §0 **round-count expectation calibration block** added: 2g's Round 1 expected to converge in ≤3 rounds (substrate-anchored against no-new-public-API; type-system surface closed by Phase 2F Rounds 2–3); calibration precedent traced through 2c (3 rounds) / 2d (multi-round with R0-D5 pre-flight) / 2f (5+ rounds for new public API surface); expectation is reviewer-attention budget, not hard ceiling (per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc) round-count budget reopens substrate-anchored). **(3)** §1.7 **fork-pin coupling maintenance pin** added: `randomx-v2-sys`'s `extern "C"` declarations are coupled to the `external/randomx-v2` fork pin (commit `aaafe71`); any future fork-pin-advance PR diffs the new pin's `randomx.h` against the prior pin's, identifies signature changes on the 7-symbol minimal subset, updates sub-crate declarations in lockstep, and cites the signature-diff verification step in the PR description. Reopen criterion for R1-D2 / R1-D13 if upstream changes RandomX v2's C ABI. **(4)** §2.5 **Round 0 amplification: leg 3 as catch-of-last-resort** added: reframes leg 3 from "redundant safety net" to "catch-of-last-resort for leg-1/leg-2 discipline failures" (auditor-side read errors, transcription misses on details the C reference defines but the spec is silent on); 2c §5.11.8 audit-against-actual-code recurrence record cited as evidence that the discipline catches real findings before the harness is in place, but absent the catch, leg 3 would have been the catch. Corollary: corpus coverage is itself a load-bearing property of the audit posture; thin corpus coverage thins the catch-of-last-resort surface. **(5)** §3.7 R1-D7 **placeholder end-of-life audit-trail pin** added: 2c §13 R3-minor-2's `tests/perf/per_hash_latency.rs` placeholder reaches planned end-of-life under R1-D7 (c); implementation-PR commit message cites "closes Phase 2c R3-minor-2" so the audit trail is grep-discoverable per [`90-commits.mdc`](../../.cursor/rules/90-commits.mdc). Per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc) the placeholder's reversion-clause shape was always "delete on 2g's implementation"; R1-D7 (c) is the planned trigger firing, not architectural drift. **(6)** §3.9 R1-D9 **RSS-bound adversarial criterion + Phase 2F F2 backstop framing** added: success criterion bifurcated into correctness criterion (no panic, no deadlock, byte-equality of each pair of hashes for the same `(seedhash, data)` input regardless of worker) and adversarial criterion (RSS growth during concurrent execution bounded by `CacheStore`'s capacity-2 invariant per Phase 2F §4 F2 disposition: ≤ 2 × 256 MiB derived-cache holdings + worker-count × ~2 MiB scratchpad + register-file). Without the RSS-bound assertion the test verifies correctness only; with it the test backstops 2F's F2 disposition under load (catches a regression that accidentally retained `Arc`s beyond derivation scope). Round 1 pins numeric ceiling, measurement methodology (`/proc/self/statm` vs. platform equivalent), and tolerance band. **(7)** §3.10 R1-D10 **future-deferred reopen-criterion class** made explicit: R1-D10's reopen criterion is future-deferred (the trigger event — divergence + intractable bisection — has not occurred at Round-1-evaluation-time), legitimate per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc); future Round-N opening R1-D10 cites the divergence's `(seedhash, data)` pair as the reopen's substrate trigger rather than re-deriving Round-1 evidence. **(8)** §4 **Round-1-close obligation: corpus-coverage-as-leg-3-completeness framing** pinned: the three corpus-coverage classes (random per R1-D4 / adversarial per R1-D5 + R1-D6 / worst-case timing per R1-D8) catch different bug classes; thin coverage in any one class thins the residual catch capacity in that direction. Round 1's threat-model close must treat corpus-coverage as load-bearing, not adjacent to F1–F7-style attack-class enumeration; absence of explicit corpus-coverage-class framing in Round-1 close is grounds for reviewer challenge. None of (1)–(8) reopens a frozen surface from §1; all eight are substrate-tightening additions to the scaffold per [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc) plan-doc-Round-0 framing. |
| Round 1 (Decisions close + §4 deferral + §5/§6/§8 substance) | 2026-05-24 | Closes all 14 §3 decision points (R1-D1 through R1-D14) at their Round-0-named default expectations, each with substrate-anchored rationale, named sub-disposition pins where the option set carried multiple branches (e.g., R1-D5 + R1-D6 corpus-storage formats, R1-D11 failure-output schema, R1-D14 SHA-256-vs-byte-diff comparison shape), and full reversion-clause shape per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc) (rejection / reopening criteria / re-evaluation shape). **Five Round-0-defaults-supporting substrate findings surfaced and pinned:** **F1** R1-D14 comparison-shape (SHA-256 of full cache by default; `--debug-cache-divergence` flag for byte-by-byte diff on post-failure manual re-run; memory pressure within 16 GB runner budget); **F2** R1-D4 numeric pins (16 seedhashes × 8 data values for per-PR cadence; 32 × 32 for nightly; bimodal block-template-shaped data-length distribution; 32-byte ChaCha20 seed; deterministic regeneration verified via T9); **F3** R1-D5 + R1-D6 grinding budget (4 hours wall-clock per class on a 16-core baseline; per-class targets enumerated for CFROUND, FDIV_M, Cache-miss, CBRANCH, Combined-heavy seedhashes + div-by-zero, signed-div overflow, shift-by-width, u128-truncation data); **F4** R1-D9 RSS-bound pin (640 MiB ceiling with ±10% tolerance, measured via `/proc/self/statm` field 2; sampled at 100 ms intervals during concurrent execution); **F5** R1-D12 runner-class pin (`ubuntu-latest` per GitHub Actions specs: 4 vCPU / 16 GB RAM / x86_64; wall-clock budgets ~7 min per-PR / ~25 min nightly / ~10 min release-gate, all within the 6 h runner ceiling). **R1-D11 ↔ R1-D14 dependency edge surfaced and absorbed (F6):** R1-D11's structured-failure-output schema includes `rust_cache_sha256` + `c_cache_sha256` fields populated from R1-D14's precondition test; a precondition test failure aborts the corpus pass for that seedhash before per-`(seedhash, data)` tests run, so a divergent-cache-sha256 in the R1-D11 failure output is a harness bug (the precondition should have caught it first). **§4 threat-model close deferred to Round 2** per [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc) A3 timing discipline ("threat-model addenda is typically late-design-rounds: after feature completeness, before closure"); the Round-0 Round-1-close obligation (corpus-coverage-as-leg-3-completeness framing) re-anchors as the Round-2-close obligation with no content change, and the Round-2 enumeration sketch pre-binds 7 attack classes against the differential-harness surface (corpus-generation bug, R1-D14 precondition bypass, CMake-trigger bypass, R1-D11 failure-output incompleteness, CacheStore `Arc` retention regression, adversarial-corpus drift, reviewer-blind nightly failures). **§5 implementation hand-off contract initial substance** lands: 16-row table for the harness crate (`shekyl-randomx-differential` `[[bin]]` + `[lib]` + 14 module surfaces), 5-row table for `randomx-v2-sys` sub-crate (`lib.rs` extern declarations + `build.rs` + manifests + README), 2-row verifier-crate side (no new surfaces per R1-D10 (b); placeholder deletion per R1-D7 (c)), 3-row CMake wiring (R1-D3 option + implication mechanism + zero new targets), 4-row CI surface (per-PR + nightly + release-gate workflows + crate-invariant script extension), explicit §5.6 negative-space pin (no new verifier API; no committed reference vectors; no additional `randomx-v2-sys` consumers; no `harness-trace` feature; no Phase 2F surface modification), and §5.7 drift-prevention discipline (reviewer rejection criterion for implementation-PR surfaces outside the table per [`15-deletion-and-debt.mdc`](../../.cursor/rules/15-deletion-and-debt.mdc)). **§6 test plan initial substance** lands: 15-row test matrix across 7 categories (T1–T2 correctness; T3–T4 cache precondition; T5–T6 performance; T7–T8 thread-safety + RSS-bound; T9–T10 reproducibility; T11 failure-output schema; T12–T14 build-system + crate-invariant; T15 fork-pin coupling), cadence summary (9 per-PR / 7 nightly / 6 release-gate / 1 manual-post-failure), explicit §6.9 negative-space pin (no proptest, no fuzz, no mutation testing, no cross-platform — all out-of-scope-by-omission with future-deferred FOLLOWUPS pickup criteria), and §6.10 drift-prevention discipline. **§8 commit table initial substance** lands: 10-commit implementation-PR sequence within the [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) rule-2 ceiling (≤10 commits, ≤5 working days), each commit anchored to §5 surfaces and §6 T# rows, with per-commit bisection invariants ("every commit passes `cargo build` + `cargo clippy -D warnings` + `cargo fmt --check`"), §8.2 boundary-strengthening pins at C4→C5 (skeleton-without-corpora) and C9→C10 (harness-without-CI) for bisection legibility, §8.3 scope-discipline pin (no verifier-API modification; no re-implementation of 2c/2d/2f; no out-of-table dependencies; no in-place R1-D# reshape), and §8.4 PR-opening citation discipline. None of Round 1's closures reshapes the §1 substrate; all closures fall within the option sets enumerated at Round 0. Round 2 follows per the §0 round-count expectation (target ≤3 rounds total) and the §4 deferral pin (Round 2 closes §4 against the Round-1-anchored substrate). |
| Round 2 (Architectural tightenings + §3.15 harness actor shape + §4 re-anchor to Round 3) | 2026-05-24 | Adversarial pass against the Round-1 close through the **workspace actor-paradigm lens** ("all our other clients are Actors") surfaces five substrate-tightening findings — none reopens a Round-1 disposition; each names a discipline the disposition collection already determines but did not surface explicitly. **(T1) §3.15 new section — harness actor shape (load-bearing architectural framing).** The `shekyl-randomx-differential` binary is the workspace's first multi-mode orchestration-actor consumer of the verifier's pure-transform surface; the R1-D1/D7/D8/D10/D11/D12/D14 disposition collection collectively determines its mode set (4 modes — correctness / worst-case / latency / concurrent — plus reserved trace), per-mode state shape (CacheStore presence + C-side Cache+Vm pair + accumulators + RSS-bound applicability), mode-dispatch surface (`--mode=` mutually exclusive top-level flag with mode-scoped sub-args; default behavior is loud-failure per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc) `user-protection-defaults-in-user-absent-contexts` inversion), and orchestration lifecycle (init → corpus-load → [precondition-all-seedhashes for correctness] → per-iteration loop → accumulate → report → exit, with §3.15.4 phase-boundary discipline load-bearing for the R1-D9 + R1-D14 amendment pins). Process-scoped (not session-scoped) so each invocation is independent — the contract Phase 3a / 3c / release-gate consumers inherit. **(T2) §0 layer-separation positive observation.** The disposition collection operationalizes a **four-crate layering** (`shekyl-pow-randomx` verifier as pure-transforms + `CacheStore` state-holder + `randomx-v2-sys` C-bindings boundary + `shekyl-randomx-differential` orchestrator-actor) that is the concrete-template realization of the workspace's actor-paradigm discipline. R1-D1 (a) / R1-D2 (c) / R1-D7 (c) / R1-D10 (b) / R1-D13 (c) each individually land at the option that respects this layering; the disposition collection's coherence is the discipline applied to a new sub-problem yielding the structurally-clean shape by construction. The four-crate template is the load-bearing layout future Rust extractions (Phase 3a / 3c; signing-engine extractions) target by default. **(T3) R1-D9 amendment — RSS-bound mode-scoping pin.** The RSS-bound assertion (640 MiB ceiling per F4) is scoped to the concurrent-call test mode only; other modes (latency, worst-case, future trace) do not inherit it. The F2 backstop's measurement is meaningful only when the harness's own accumulator state is minimal — in modes whose per-mode accumulator state grows with corpus size, the measured RSS would shift without the verifier-side F2 mitigation having regressed (false-positive bound failure). Implementation: RSS sampler thread spawned only inside the `--mode=concurrent` dispatch branch (per §3.15 actor shape). Prevents inheritance-by-default for new mode additions. **(T4) R1-D13 amendment — harness stateful-pattern exemption pin.** The harness crate's stateful mode-dispatch (`OnceLock` / `LazyLock` / `static` for CLI arg parsing, accumulator state, mode-dispatch enum) is appropriately outside the verifier-crate-scoped Pattern A and Pattern B invariants. Per-crate scoping of the invariant grep gate (R1-D13 (c) close) is what enables this — Pattern A and Pattern B remain workspace-wide in scan-scope (all three crates), but the verifier-crate-specific stateful-construct-forbidding patterns anchor to `rust/shekyl-pow-randomx/` only. The per-crate scoping is now load-bearing, not incidental; a future workspace-wide stateful-pattern grep gate would fail this pin's substrate check (the layer separation per T2 is what makes the verifier-side prohibition load-bearing without requiring the same prohibition orchestrator-actor-side). **(T5) R1-D14 amendment — drop discipline + CacheStore-empty-during-precondition pin.** The SHA-256 incremental shape's ~256 MiB per-seedhash memory peak depends on `drop(rust_cache)` being load-bearing — the explicit drop releases the `Arc<Cache>` strong reference and the backing allocation is freed only if the drop-side is the last holder. The precondition test owns the only `Arc<PreparedCache>` clone for each seedhash; the `CacheStore` is empty during the precondition phase (precondition test calls `PreparedCache::derive` directly, not `CacheStore::get_or_derive`; the sticky-canonical slot stays unpopulated until the byte-equality phase begins). Phase-boundary enforcement at the §3.15.4 lifecycle level. **§4 threat-model close re-anchored from Round 2 to Round 3.** Round 2 absorbed the five architectural tightenings instead of closing §4; the §4 close re-anchors against the Round-1 + Round-2 substrate, with the §3.15 actor-shape framing becoming load-bearing for §4's adversarial probe. Three new Round-3-close obligations land at Round 2 for §4 to absorb: mode-boundary violations, phase-boundary violations, and per-mode-state-shape regression — alongside the seven Round-1 pre-bound attack classes and the corpus-coverage-as-leg-3-completeness obligation inherited forward. **Round-count budget unchanged:** Round 0 + Round 0 calibration + Round 1 + Round 2 + Round 3 = 3 substantive close-rounds within the §0 ≤3-round expectation (calibration counts as substrate-tightening, not a separate close-round). **Project-posture observation (broader project record).** 2g is the **fourth substantive sub-PR of the RandomX v2 migration to close Round 1 cleanly without an adversarial reframe** (2c closed in 3 rounds; 2d closed via R0-D5 pre-flight; 2f closed in 5+ rounds with substantial type-system reframe; 2g closes Round 1 at defaults with Round 2 handling tightenings rather than reframes). The pattern suggests the project's design discipline has matured to the point where Round 1's "default expectation" entries are usually right; converged-state-of-project-posture per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc) discovery-cadence-compounding-substrate framing. None of T1–T5 reopens a frozen surface from §1 or reshapes a closed Round-1 disposition; all five are substrate-tightening additions per [`26-sub-pr-design-discipline.mdc`](../../.cursor/rules/26-sub-pr-design-discipline.mdc). Round 3 follows per the §4 Round-2 amendment re-anchor (Round 3 closes §4 against the Round-1- + Round-2-anchored substrate; transitions to implementation-PR after close). |
| Round 3 (§4 threat-model close + implementation-PR transition gate) | 2026-05-24 | Closes §4 against the Round-1- + Round-2-anchored substrate with **ten attack classes (A1–A10) + five negative-space classes (N1–N5) + three load-bearing-property discharges + an implementation-PR transition gate**. **Three load-bearing-property discharges land before the attack-class enumeration**, each named explicitly so the discharges are auditable as their own dispositions rather than buried inside individual attack-class entries: **§4.1 corpus-coverage-as-leg-3-completeness discharge** (closes the inherited Round-0 → Round-1 → Round-2 obligation; pins all three corpus-coverage classes — random per R1-D4, adversarial per R1-D5+R1-D6, worst-case timing per R1-D8 — as substrate-load-bearing with substrate-anchored reopening criteria that catch silent thinning; the discharge is the explicit pinning of each class as load-bearing-against-substrate-anchored-numeric-criteria, not "the three classes exist therefore the obligation is satisfied"); **§4.2 harness-as-actor-invariants discharge** (closes the inherited Round-2 obligation; A8/A9/A10 dispositions explicitly cite §3.15.2 mode-boundary, §3.15.4 phase-boundary + R1-D14 amendment + R1-D9 amendment, §3.15.6 framing as load-bearing substrate); **§4.3 three-leg audit-posture rebalance discharge** (operationalizes the leg-3 catch surface as two structurally-distinct mitigation classes — leg-3-catch-of-verifier-bug for A1/A2/A6 and leg-3-catch-capacity-degradation for A3/A4/A5/A7/A8/A9/A10 — so future contributors can classify changes against the two-kind framework without re-deriving substrate). **§4.4 attack-class enumeration (A1–A10)** uses the [Phase 2F §4](./RANDOMX_V2_PHASE2F_PLAN.md) F1–F7 precedent shape (Attack / Round 3 disposition / Test coverage / Reversion clause where applicable). **A1 corpus-generation false-agreement bug** mitigated by T9 (determinism gate) + T10 (drift-detection pin); residual accepted as audit-against-actual-code-discipline catch at PR-review time. **A2 R1-D14 precondition bypass** mitigated by §3.15.4 phase-boundary discipline + T3 + T11 (synthetic-divergence round-trip); residual accepted as multi-component discipline-failure-mode requiring concerted bypass. **A3 CMake-trigger bypass** mitigated by R1-D3 (c) implication mechanism + T12; residual accepted at §3.15-style review discipline. **A4 R1-D11 failure-output incompleteness** mitigated by T11 (11-required-fields schema round-trip) + forward-deferred extension shape (R1-D10 + R1-D14 future-deferred reopens); residual accepted as future-deferred reopen criterion. **A5 CacheStore Arc retention regression (F2 backstop bypass)** mitigated by R1-D9 amendment mode-scoping + T8 measurement methodology + Phase 2F F2 caller-discipline boundary; residual accepted at PR-review discipline. **A6 adversarial-corpus drift** mitigated by §1.7 fork-pin coupling + T15 signature audit + T10 corpus-hash; residual accepted at §1.7 fork-pin-advance PR discipline. **A7 reviewer-blind nightly failures** mitigated by R1-D12 split-cadence-with-required-status-check + §1.7 + R1-D12 + T10/T15 composition; residual accepted for V3.0 small-team substrate (reversion criterion: >7-day discovery gap triggers active monitoring). **A8 mode-boundary violation (§3.15.2 process-scoping bypass)** mitigated by §3.15.3 mode-mutual-exclusion pin + §3.15.2 free-between-modes pin + §3.15.6 framing; residual accepted at §3.15-frame audit time. **A9 phase-boundary violation (R1-D14 + R1-D9 amendment invariants)** mitigated by §3.15.4 phase-boundary discipline pin + R1-D14 CacheStore-empty + R1-D9 RSS-sampler-scoping invariants + indirect catch via T3/T7/T8; residual accepted at §3.15-frame audit time. **A10 per-mode-state-shape regression (R1-D9 RSS-bound inheritance-by-default)** mitigated by R1-D9 amendment mode-scoping + §3.15.2 per-mode-state-shape table + indirect catch via T8 per-mode applicability; residual accepted at §3.15-frame audit time. **§4.5 negative space (N1–N5)** explicitly enumerates classes 2g does NOT defend against with substrate-anchored reopening criteria: **N1** V4 lattice-transition substrate shift (out of scope for V3.x; reopen on NIST lattice standardization); **N2** multi-platform corpus determinism (out of scope for V3.0; reopen on macOS/Windows CI matrix expansion); **N3** PoW consensus attacks (out of scope permanently — operates upstream of verifier; cross-link to Phase 0 / [Phase 2F F7](./RANDOMX_V2_PHASE2F_PLAN.md) / [LWMA-1](./DAA_LWMA1_PLAN.md)); **N4** side-channel attacks (out of scope; cross-link to [Phase 2c §5.11.4](./RANDOMX_V2_PHASE2C_PLAN.md) public-input-only scope note); **N5** adversarial CI infrastructure (out of scope; cross-link to reproducible-Guix-build + signed-release-tag disciplines per [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) + [`docs/SIGNING.md`](../SIGNING.md)). **§4.6 implementation-PR transition gate** verifies all 11 substrate rows are either closed or scaffolded with sufficient substance: §1 (frozen at Phase 2F R3) + §2 (absorbed Round 0) + §3 R1-D1–R1-D14 (closed Round 1 + tightened Round 2) + §3.15 (substantive Round 2 — six subsections covering modes/state/dispatch/lifecycle/forward-template/negative-space) + §4 A1–A10+N1–N5 (this round) + §5 (Round 1 initial substance: 16+5+2+3+4 = 30 rows) + §6 (Round 1 initial substance: 15-row T# matrix) + §7 (Round 0 scaffold sufficient) + §8 (Round 1 initial substance: 10-commit sequence) + §9 (Round 0 scaffold sufficient) + §10 (Round 0 scaffold sufficient). Implementation-PR opening is **authorized** per [`06-branching.mdc`](../../.cursor/rules/06-branching.mdc) rule 2 (short-lived branch, ≤10 commits, ≤5 working days) with §8.4 PR-opening citation discipline + [`90-commits.mdc`](../../.cursor/rules/90-commits.mdc); subsequent plan-doc changes are substrate-anchored reopens per [`21-reversion-clause-discipline.mdc`](../../.cursor/rules/21-reversion-clause-discipline.mdc), not iterative design-rounds. **Four post-implementation-PR reopen-criterion classes named** (substrate-anchored, not preference-anchored): §1 substrate gap, §3.15 actor-shape discipline gap, A1–A10 disposition gap, R1-D# numeric pin substrate-unsoundness. **Project-posture observation (broader project record).** Round 3 closes the design-phase substrate; 2g transitions to implementation-PR with **3 substantive close-rounds within the §0 ≤3-round target** (Round 0 + Round 0 calibration + Round 1 + Round 2 + Round 3, where Round 0 calibration is substrate-tightening rather than a separate close-round). The pattern reaffirms the §11 Round 2 fourth-clean-Round-1 project-posture observation — converged-state-of-project-posture per [`16-architectural-inheritance.mdc`](../../.cursor/rules/16-architectural-inheritance.mdc) discovery-cadence-compounding-substrate framing. Round 3's adversarial pass against the Round-1+Round-2 substrate surfaces no new attack-class reframe; the §4.4 enumeration absorbs the seven Round-1 pre-bound classes + three Round-2 obligations + five negative-space classes without restructuring. None of the Round 3 close reopens a §1-frozen surface, reshapes a Round-1 disposition, reshapes a Round-2 amendment, or reshapes the §3.15 actor-shape framing; all Round 3 additions are substrate-anchored attack-class dispositions or substrate-anchored discharge of inherited obligations. **The plan-doc design rounds are closed.** The implementation PR per §8 starts at the current substrate state; the next plan-doc activity is reactive (post-implementation-PR reopen against substrate-anchored evidence) not iterative (no Round 4 expected; if one arrives, it is substrate-reopen-driven per the four post-implementation reopen classes). |
