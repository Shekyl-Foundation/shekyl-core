# RandomX v2 — Track A Phase 2f plan

**Status.** Scaffold landed 2026-05-23 on branch
`chore/randomx-v2-phase2f-plan` post Phase 2d merge (PR #70 → `dev`
merge commit `fb21909ff`). This document is the Round-0 substrate
capture: it pins the carry-forwards from `RANDOMX_V2_PLAN.md` Decisions
#6 / #7, from `RANDOMX_V2_PHASE2C_PLAN.md` §5.11.7, and from
`RANDOMX_V2_PHASE2D_PLAN.md` §10; names the locked-by-2c/2d surface that
2f inherits; and enumerates the Round 1 decision points without
prematurely closing them. Round 1 (post-scaffold-merge) closes the
decision points and lands the implementation hand-off contract on
`feat/randomx-v2-phase2f-impl`.

**Parent plan.** [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md)
§"Track A — Phase 2" sub-PR 2f scope (line 27):

> "Implement `CacheStore` utility type (`LruCache<Seedhash, Arc<Cache>>`
> behind a `Mutex`; default capacity 2). The crate exports it as a
> generic helper for any Rust caller; `shekyl-pow-randomx` instantiates
> none. PR includes TWO crate-level invariant tests on
> `shekyl-pow-randomx`: (1) no module-level static/OnceCell/lazy_static
> other than const data; (2) no `#[no_mangle]` or `extern "C"` exports.
> Both CI-enforced via grep on the crate source tree. Benchmark
> per-call `VmState` allocation cost inside `compute_hash` (extending
> the Phase 2c `BENCH_RESULTS.md` baseline); if it dominates per-hash
> time, internalize a `VmState` pool inside `compute_hash` (private to
> `vm.rs`, invisible to consumers — same shape as Phase 2c R2-D1's
> dispatch-function-body-replacement discipline; no public `VmPool`
> type). Per Decision #7 (Round 2 substrate-shift form): per-call
> allocation is the default; pooling, if needed, is internal to
> `compute_hash`."

**2c precedent.**
[`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) §5.11.7
"Forward-actions to Phase 2f" pins two substrate carries (canonical-
slot eviction-protection; pool capacity sized against daemon parallel-
verification fanout). Reproduced verbatim in §2 below so Phase 2f's
review does not require chasing the 2c plan.

**2d precedent.**
[`RANDOMX_V2_PHASE2D_PLAN.md`](./RANDOMX_V2_PHASE2D_PLAN.md) §10
"Forward path" pins the inherited surface:

> "2f inherits unchanged `compute_hash` surface; pooling wraps the
> same `VmState` allocation path 2c landed."

The 2d implementation (PR #70) realized this: `compute_hash`'s
signature is `pub fn compute_hash(&Cache, &[u8; 32], &[u8]) -> [u8;
32]`, `VmState` is private to `vm.rs`, `dispatch_instruction` is
private. 2f's CacheStore lives alongside this surface; the pool (if
benchmarks justify it) lives *inside* `compute_hash`. No 2c or 2d
public surface changes in 2f.

**Base commit.** `dev` at `fb21909ff` (PR #70 merge tip,
2026-05-23). This doc's branch (`chore/randomx-v2-phase2f-plan`)
cuts from there; the Phase 2f implementation branch
(`feat/randomx-v2-phase2f-impl`) cuts later from post-this-doc `dev`.

**Branches.**

- `chore/randomx-v2-phase2f-plan` (this doc; short-lived per
  `06-branching.mdc` rule 2; lands on `dev` via its own PR).
- `feat/randomx-v2-phase2f-impl` (implementation; cut from
  post-this-doc `dev`; not yet cut as of Scaffold close).

**Scope envelope.** Single implementation PR. Target ≤600 lines of
net-new Rust (CacheStore type + tests + benchmark harness + crate-
invariant grep tests + optional VmState pool body if the bench result
warrants it) + one new CI script (`scripts/ci/check_randomx_crate_invariants.sh`
or equivalent — final name pinned at Round 1) + updates to
`rust/shekyl-pow-randomx/BENCH_RESULTS.md`. **No consensus-affecting
changes; no new reference vectors; no fork-pin advance.** 2f is
pure-utility + benchmark; the consensus surface was exhausted by 2d's
T9–T16 + bench delta entries.

**Out of scope (deferred to subsequent phases).**

- **Differential test harness against C reference** — deferred to 2g
  per `RANDOMX_V2_PLAN.md` line 30. 2f's benchmark uses the existing
  `compute_hash` against a fixed seedhash/data pair (not a corpus and
  not differentially against the C reference).
- **Per-PR per-hash latency CI gate** — activates at Phase 3a per
  `RANDOMX_V2_PLAN.md` line 243. 2f reports the bench delta in
  `BENCH_RESULTS.md`; CI gating is 3a's responsibility.
- **Binary-level `nm`-on-`shekyld` symbol-isolation check** — deferred
  per the FOLLOWUPS V3.1+ entry (line 3633ff), which names Phase 3c
  as the natural landing site sharing the link-job with the
  CryptoNote DAA `nm` check. 2f's symbol-isolation is grep-based at
  the Rust source tree level (Decision-#1 form per the parent-plan
  line 27 scope text), not binary-level.
- **`Cache::derive` parallelism / SuperscalarHash thread-pool** — out
  of scope; 2c shipped serial derivation. Parallel derivation is a
  separate FOLLOWUPS item if benchmarks justify.

---

## 1. Locked-by-2c-and-2d substrate

The following are frozen by the post-PR-#70 `dev` tip. 2f does not
amend any of them.

### 1.1 Public API surface (unchanged)

```rust
// In rust/shekyl-pow-randomx/src/lib.rs (or re-exports therefrom):
pub struct Cache { /* private fields */ }
impl Cache {
    pub fn derive(seedhash: &[u8; 32]) -> Cache;
}
pub fn compute_hash(cache: &Cache, seedhash: &[u8; 32], data: &[u8]) -> [u8; 32];

// pub(crate) items consumed by tests / internal callers:
//   Cache::from_raw, Cache::derive_item, Cache::item_bytes
// (no public exposure; pinned by Phase 2c R1)
```

2f **adds** `pub struct CacheStore` (shape TBD per R1-D1) and
**possibly amends** `compute_hash`'s body to consult an internal
`VmStatePool` (per R1-D4 / bench result). It does **not** change
`compute_hash`'s signature.

### 1.2 Private substrate (unchanged)

- `VmState` is `pub(crate)` in `src/vm.rs`; constructed by
  `compute_hash` per call; scratchpad via `Box::new_zeroed_slice`.
- `dispatch_instruction(&Instruction, &mut VmState)` is `pub(crate)`
  in `src/vm.rs`.
- `fpu_rounding` module is `pub(crate)` per the 2d Round 1 R1-D1 + R6-D1
  decision.

### 1.3 Crate-invariant posture (active discipline carried forward)

Both new invariant greps that 2f lands have an empirical baseline at
PR-#70 tip:

- **No module-level `static` / `OnceCell` / `lazy_static`** other
  than `const` data. Empirically the crate has zero such items at
  HEAD (per `RANDOMX_V2_PLAN.md` §7.7's design intent absorbed by
  Phase 2c's implementation). 2f's grep makes this CI-enforced rather
  than discipline-as-reviewer-attention.
- **No `#[no_mangle]` / `extern "C"`** exports. Empirically zero at
  HEAD per the parent-plan `RANDOMX_V2_PLAN.md` §7.7 framing. 2f's
  grep makes it CI-enforced.

Both greps must be zero-hit on HEAD-prior-to-2f and remain zero-hit
post-2f. The grep set is pinned at Round 1 R1-E1 (CI grep patterns +
permitted exceptions).

---

## 2. Forward-actions absorbed from 2c §5.11.7 + 2d §10

### F1 — CacheStore canonical-slot eviction-protection (from 2c §5.11.7 #1)

> The capacity-2 LRU `CacheStore` is small enough that an attacker who
> can submit alt-chain block headers with novel seedhashes can flush
> the canonical-seedhash slot with a 3-seedhash interleave, forcing
> ~150-200 ms of cache re-derivation per attack block. The forward-
> action: the canonical-seedhash slot (the seedhash for the current
> chain tip's epoch) is **sticky** — it is not subject to LRU
> eviction; only the secondary slot churns under attacker-induced
> pressure.

**2f Round 1 disposition:** R1-D2 picks the eviction-policy shape
(capacity-2 LRU with sticky canonical via a `pin(seedhash)` API the
caller invokes when learning a new canonical seedhash; or explicit
"pinned slot + transient slot" two-slot type that needs no LRU). Both
satisfy F1; the trade-off is API surface vs. implementation
simplicity. Round 1 closes the choice.

### F2 — VmState pool capacity sized against daemon parallel-verification fanout (from 2c §5.11.7 #2)

> If 2f's benchmarks show pooling is needed, the pool's capacity must
> be sized against the daemon's actual parallel-verification fanout
> (alt-chain branch validation runs in parallel; mempool tx
> verification runs in parallel). An arbitrarily-chosen capacity
> either under-provisions (pool exhaustion forces per-call allocation,
> defeating the pool) or over-provisions (memory waste).

**2f Round 1 disposition:** R1-D5 enumerates the daemon's actual
parallel-verification fanout. Two sources of concurrent
`compute_hash` callers exist at Phase 3a+: alt-chain branch
validation worker pool + mempool tx verification worker pool. Round 1
surveys the daemon-side code (worker-pool thread-count settings) or
runs a single instrumented startup to determine the maximum-concurrent
fanout, and sizes the pool to that maximum + a small reserve. **F2
only fires if R1-D4's bench result triggers the pool path; otherwise
F2 is deferred unchanged to whatever future PR re-opens the
pool decision.**

### F3 — `compute_hash` surface unchanged (from 2d §10)

> 2f inherits unchanged `compute_hash` surface; pooling wraps the
> same `VmState` allocation path 2c landed.

**2f Round 1 disposition:** No-op carry. The §1.1 freeze enforces
this. If R1-D4 selects the pool path, the pool is internal to
`compute_hash`'s body — the function signature is untouched.

### F4 — Audit-against-actual-code discipline (from 2c §5.11.8, 2d Round 6 R6 posture cite)

> An audit that reads the actual C reference at the pinned commit
> catches consensus-split bugs that an audit that reads the plan-doc
> tables does not.

**2f Round 1 disposition:** No-op for the CacheStore surface (the
type has no C reference counterpart — it's a Rust-only utility, per
`RANDOMX_V2_PLAN.md` Decision #1). Applies forward to 2g's
differential harness. Recorded here only to acknowledge the carry-
forward exists.

### F5 — Pre-genesis posture (from `15-deletion-and-debt.mdc` + `16-architectural-inheritance.mdc`)

2f is pre-genesis. Per `15-deletion-and-debt.mdc`'s pre-V3-launch
discount, no migration code is justified; if the CacheStore shape
chosen at R1-D2 turns out to be wrong, the disposition is to redesign
in a follow-up rather than maintain a versioning surface.

---

## 3. Round 1 decision points

Round 1 (post-scaffold-merge) closes these. Scaffold names the
options without picking; user-facing review chooses.

### 3.1 R1-D1 — `CacheStore` API surface shape

Options:

- **(a) Transparent memo with explicit `pin(seedhash)` / `unpin()`**
  — `CacheStore::new(capacity)` returns a `CacheStore`; the consumer
  calls `store.pin(canonical_seedhash)` when learning a new
  canonical seedhash; the store maintains a `LruCache<Seedhash,
  Arc<Cache>>` internally, where the pinned slot is treated as
  ineligible-for-eviction. Pros: API matches the parent-plan
  `RANDOMX_V2_PLAN.md` line 27 framing (LruCache behind Mutex).
  Cons: caller-driven pinning is a footgun (forget to `pin`, lose
  the sticky property).
- **(b) Explicit two-slot type with `set_canonical` + `lookup`** —
  `CacheStore::new()` returns a fixed two-slot type (one canonical
  pinned slot, one transient LRU slot); the consumer calls
  `store.set_canonical(seedhash)` to advance the canonical, which
  evicts the previous canonical (if any) into the transient slot
  (preserving the previous canonical for the duration of the
  rollback window). Pros: structurally enforces the sticky property
  (no caller-error path leaves canonical evictable). Cons: harder to
  generalize beyond capacity-2 if a future caller wants capacity-N.
- **(c) Type-stratified shape** — separate `PinnedSlot` and
  `TransientSlot` types, composed by the consumer. Pros: maximal
  type-system enforcement. Cons: API surface bloat for a capacity-2
  utility.

**Round 1 task.** Pick one. Pin the public surface (constructor
signatures, lookup signature, pin/canonical signature). Round 1
output is a code-block-shaped API spec mirroring §1.1's style. The
discipline question per `21-reversion-clause-discipline.mdc`: which
optionality is rejected, under what substrate-change does the
rejection reopen?

### 3.2 R1-D2 — Eviction policy under attacker interleave

Given R1-D1's API choice, fix the eviction policy:

- For option (a): the LRU treats the pinned slot as ineligible
  regardless of access recency. Concrete behavior: if pinned ==
  seedhash-A and the LRU is full with pinned-A + transient-B, a
  lookup miss for seedhash-C evicts B (not A); a lookup miss for
  seedhash-D evicts C (not A); etc.
- For option (b): canonical-slot is non-evictable by construction.
  Transient slot holds at-most-one cache; arrivals replace it.
- For option (c): pin/transient ownership is type-level; no eviction
  policy exists at the composition layer.

Round 1 picks the option-specific concrete behavior + the test
matrix (§6.1 below) that asserts the canonical slot survives a
worst-case interleave.

### 3.3 R1-D3 — Benchmark methodology (per-call VmState allocation)

Phase 2c's `BENCH_RESULTS.md` baseline is `compute_hash` median per-
call timing (303.60 ms post-2d; 295.91 ms post-2c). The per-call
`VmState` allocation cost is currently *included* in that figure but
not isolated.

Options for isolation:

- **(a) Diff method** — measure `compute_hash` with the current
  per-call allocation (baseline), then with allocation hoisted
  outside (e.g., a one-time `VmState` instance reused across N hash
  calls, instrumented for the bench); the delta is the per-call
  allocation cost amortized over N. Pros: directly measures what the
  pool decision optimizes. Cons: requires a temporary internal API
  to hoist `VmState` for the bench, which leaks into the bench
  harness.
- **(b) Component method** — separately benchmark
  `Box::<[u8]>::new_zeroed_slice(2 << 20)` (the 2 MB scratchpad
  zero-init) and the register-file `VmState` field init. Pros: no
  internal API exposure. Cons: doesn't account for any allocator-
  amortization effect a steady-state pool would capture.
- **(c) Population method** — benchmark a pool-mode `compute_hash`
  body against the current per-call body across N iterations. Pros:
  measures the actual A/B the pool decision depends on. Cons:
  requires implementing the pool body before the bench, which makes
  the "decide whether to pool based on the bench" sequencing
  circular.

Round 1 picks one. Disposition rules out the cycle (i.e., option (c)
without the pool already implemented). Likely (a) or (b).

### 3.4 R1-D4 — Pool decision threshold

Phase 0 budget is **≤100 µs** per `RANDOMX_V2_PLAN.md` line 240. R1-D4
fixes the bench-result-to-pool-decision rule:

- If R1-D3's bench shows per-call allocation < 100 µs → no pool;
  document the bench result in `BENCH_RESULTS.md`; F2 stays deferred.
- If per-call allocation ≥ 100 µs → pool lands inside `compute_hash`
  (private to `vm.rs`, no public `VmPool` type) with capacity from
  R1-D5; bench delta in `BENCH_RESULTS.md`.

Round 1 task is to confirm the threshold without re-litigating
Decision #7. The threshold is the Phase-0-budget number; Round 1's
work is naming what *response* the implementation PR takes given the
empirical input. The reversion clause per
`21-reversion-clause-discipline.mdc`: the no-pool disposition reopens
only if a substrate change (e.g., allocator regression, scratchpad
size change at consensus-rule level, runtime architecture mismatch)
moves the bench above 100 µs.

### 3.5 R1-D5 — Daemon parallel-verification fanout survey (conditional)

Fires only if R1-D4 triggers the pool path. Two sources of
concurrent `compute_hash` callers in the daemon today:

1. **Alt-chain branch validation.** `src/cryptonote_core/blockchain.cpp`
   — worker pool count from `--max-validation-threads` or
   `boost::thread::hardware_concurrency()` default.
2. **Mempool tx verification.** `src/cryptonote_core/cryptonote_tx_utils.cpp`
   + `src/cryptonote_core/tx_pool.cpp` — separate worker pool, count
   from a different setting.

Round 1's survey reads both code paths at HEAD, records the worker-
pool count derivation, sums them (+ small reserve), and pins the
pool capacity at the implementation PR. Methodology pinned at Round
1; actual capacity number lands in the implementation PR (since the
survey can read different settings between Round 1 close and the
implementation PR — but pinning the *methodology* freezes how the
number is derived).

### 3.6 R1-E1 — CI grep pattern set for the two new crate invariants

Modeled on Phase 2d's `scripts/ci/check_randomx_fpu_rounding.sh` shape.
Two greps:

- **No module-level `static` / `OnceCell` / `lazy_static`** — pattern
  draft: search `rust/shekyl-pow-randomx/src/**/*.rs` for `^static `
  / `OnceCell` / `lazy_static!` / `LazyLock` at item level (not in
  `fn` bodies, where local statics are allowed). Permitted
  exception: `const` items (`const FOO: T = ...`) are unaffected.
  Round 1 pins the exact regex + permitted-exception list.
- **No `#[no_mangle]` / `extern "C"`** — pattern draft: search for
  `#[no_mangle]`, `#[export_name`, `extern "C" fn` at item level.
  Permitted exception: none (an `extern "C"` block consuming an FFI
  surface is *callee*, not exporter; pattern matches *exporters*).
  Round 1 pins.

R1-E1 also pins the CI workflow integration site (add a step to
`build.yml` modeled on Phase 2d's `check_randomx_fpu_rounding.sh`
step) and the failure mode (CI step fails with the matched
line numbers, mirroring the FPU grep's UX).

---

## 4. Threat-model addenda (Round 4 placeholder)

Round 4 reviews Phase 2f's design against Shekyl's
`00-mission.mdc` priority hierarchy. Substrate-anchored items
expected to surface, based on prior phases' Round 4 patterns:

- **Cache-derivation DoS amplification.** F1's sticky canonical
  defends against the 3-seedhash interleave. Does it defend against
  a 2-seedhash interleave (where the attacker controls both slots —
  e.g., the daemon hasn't yet learned a new canonical, so no slot is
  pinned, and both LRU slots churn)? Round 4 addresses.
- **Pool exhaustion attack (conditional on R1-D4 pool path).** If
  the pool capacity from R1-D5 is sized to N and an attacker submits
  > N concurrent verification requests, the (N+1)th request hits
  the slow per-call-allocation path. Is this a DoS? Round 4
  evaluates against the parent-plan's worst-case latency budget.
- **Mutex contention.** A `Mutex<LruCache<...>>` serializes all
  CacheStore lookups across the daemon. At Phase 3a fanout, is this
  a throughput bottleneck? Round 4 evaluates against the per-hash
  latency budget.

Round 4 may identify in-2f-implementation work or 2f→2g/3a forward-
action carries. The placeholder is a discipline anchor only; actual
items land at Round 4 close.

---

## 5. Implementation hand-off contract

Round 1 close lands this section. Mirrors Phase 2c §5.1.1 / Phase 2d
§5 — the contract names what 2f's implementation PR can change vs.
what is frozen.

Frozen-by-this-doc-at-Round-1 (placeholder; Round 1 lands content):

- `compute_hash` signature (per §1.1).
- `Cache` public API (per §1.1).
- `CacheStore` API surface chosen at R1-D1.
- Eviction policy chosen at R1-D2.
- Bench methodology chosen at R1-D3.
- Pool decision rule chosen at R1-D4.
- Pool capacity sizing methodology chosen at R1-D5.
- Grep pattern set chosen at R1-E1.

In-scope for the implementation PR (placeholder):

- `CacheStore` struct + impl block (~150–250 lines).
- Crate-invariant grep script (~30–80 lines bash).
- Bench harness extension to `BENCH_RESULTS.md` workflow.
- Pool body inside `compute_hash` (conditional on R1-D4; ~50–150
  lines).
- Tests: CacheStore unit tests (§6.1); crate-invariant grep tests
  (§6.2); bench harness regression (§6.3).

---

## 6. Test plan (Round 1 placeholder)

### 6.1 CacheStore unit tests

(Round 1 pins exact list once R1-D1/R1-D2 are picked.)

Sketch:

- `cachestore_pin_survives_interleave` — canonical slot pinned;
  worst-case 3-seedhash interleave; assert canonical still resident
  after attack sequence.
- `cachestore_lru_evicts_least_recently_used_transient` — capacity-
  2; lookup pattern A, B, C with no canonical pinned; assert A
  evicted (LRU semantics on transient slots).
- `cachestore_lookup_returns_arc_clone` — `Arc<Cache>` reference
  count increments on lookup; cache dropped only when all `Arc`
  clones go out of scope.
- `cachestore_pin_advances_canonical` — pin(A) then pin(B); A
  becomes transient and is subject to eviction; B is the new sticky
  canonical.

### 6.2 Crate-invariant grep tests

- `randomx_crate_has_no_module_level_static` — grep fails on the
  source tree pre-2f and post-2f.
- `randomx_crate_has_no_no_mangle_or_extern_c` — same.

Both run as part of `cargo test -p shekyl-pow-randomx` or as a CI
step; final shape pinned at R1-E1.

### 6.3 Bench harness

- `compute_hash` median latency under per-call allocation
  (baseline; matches 2d's 303.60 ms median).
- `compute_hash` median latency under pool path (if R1-D4 triggers
  pool); delta in `BENCH_RESULTS.md`.

---

## 7. Generator / fixtures plan

**None.** 2f is pure utility + benchmark; no consensus-affecting
surface; no fork-pin advance. The `tests/vectors/reference/`
directory is untouched. `_generator/phase2c/` and
`_generator/phase2d/` remain as-is.

---

## 8. Commit table (Round 1 placeholder)

Round 1 lands the per-commit breakdown. Sketch (5-commit target,
matching 2d's actual landed count):

| # | Subject | Scope |
|---|---------|-------|
| 1 | `randomx: add CacheStore utility type` | New `src/cache_store.rs` (per R1-D1/D2 shape); re-export from `lib.rs`. |
| 2 | `randomx: add crate-invariant grep tests` | New CI script + `build.yml` step; per R1-E1 patterns. |
| 3 | `randomx: extend bench harness for per-call VmState allocation isolation` | Per R1-D3 methodology; update `BENCH_RESULTS.md`. |
| 4 | (conditional, per R1-D4) `randomx: internalize VmState pool inside compute_hash` | Pool body in `vm.rs`; per R1-D5 capacity. |
| 5 | `randomx: document Phase 2f close-out` | CHANGELOG + Round-history entry. |

---

## 9. CI gates

Inherits Phase 2d's gates. Adds two new ones:

- **Format**: `cargo fmt --check -p shekyl-pow-randomx` ✓ (unchanged).
- **Lint**: `cargo clippy --all-targets -D warnings` ✓ (unchanged).
- **Test**: `cargo test -p shekyl-pow-randomx --release -- --test-threads=1` ✓
  (now includes §6.1 CacheStore tests).
- **Doc**: `cargo doc -p shekyl-pow-randomx --no-deps` ✓ (unchanged).
- **FPU unsafe grep**: `scripts/ci/check_randomx_fpu_rounding.sh` ✓
  (unchanged; inherited from 2d).
- **NEW** Crate-invariant greps: `scripts/ci/check_randomx_crate_invariants.sh`
  (per R1-E1 — final name pinned at Round 1). Catches module-level
  static / `#[no_mangle]` / `extern "C"` exports.
- **Bench delta (informational)**: ±10% threshold per the Phase 2c +
  Phase 2d cadence. If R1-D4 triggers pool, the post-pool median is
  the new baseline; the delta is reported but not gated.

---

## 10. Forward path

- **2g** inherits the post-2f `compute_hash` body (with or without
  pool per R1-D4). The differential harness operates on the same
  public surface as today; no harness-side changes from 2f are
  visible.
- **3a** sees only `Cache::derive`, `compute_hash`, and the new
  `CacheStore` (which `shekyl-ffi` will instantiate as the
  transparent memo per `RANDOMX_V2_PHASE2C_PLAN.md` Decision #6).
  Dispatch and pool stay private.
- **3c** absorbs the binary-level `nm`-on-`shekyld` symbol-isolation
  check from FOLLOWUPS line 3633ff; 2f's source-level greps are the
  Rust-side companion.

---

## 11. Round history

| Round | Date | Outcome |
|-------|------|---------|
| Scaffold | 2026-05-23 | This document. Pins the substrate carry-forwards from `RANDOMX_V2_PLAN.md` Decisions #6/#7, `RANDOMX_V2_PHASE2C_PLAN.md` §5.11.7, and `RANDOMX_V2_PHASE2D_PLAN.md` §10. Enumerates §3 Round 1 decision points (R1-D1 API shape; R1-D2 eviction policy; R1-D3 bench methodology; R1-D4 pool threshold; R1-D5 fanout survey; R1-E1 grep patterns). Out-of-scope items pinned (no differential harness; no CI per-hash latency gate; no binary-level `nm` check; no parallel `Cache::derive`). Round 1 supersedes this scaffold's §3 / §5 / §6 / §8 with closed-decision content; the scaffold remains the substrate-capture provenance. |
