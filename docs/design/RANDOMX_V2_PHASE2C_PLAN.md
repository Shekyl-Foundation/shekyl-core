# RandomX v2 — Track A Phase 2c plan

**Status.** Round 1 closed via interactive walk on 2026-05-21 (this
conversation; F1–F9 dispositions + ShekylU128 audit). Round 2 closed
2026-05-21: substrate-finding pass surfaced the mock-X anti-pattern
recurring under the `BytecodeDispatch` trait / `StubNopDispatch` impl
naming (same shape F4 dissolved for `DatasetReader` / `MockDatasetReader`).
Three structural restructurings landed within Round 1's bounds:
(R2-D1) trait → free function for dispatch; (R2-D2) `Vm<'a>` private →
`compute_hash` public transform; (R2-D3) `Cache::from_raw` visibility
correction. **Round 3 closed 2026-05-21:** substrate-completeness pass
before implementation cuts. (R3-D1) §5.1.1 function-body replacement
contract pins the 2c→2d hand-off (frozen signature; frozen
`Instruction` field set; `VmState` field set populated empirically
against `bytecode_machine.hpp`'s 29 opcode handlers and corrected one
prompted-list speculation — `mp` is a v2-only local alias, not a
struct field). (R3-minor-1) §13 3a inheritance FFI layering note.
(R3-minor-2) §9/§12/§15 `tests/perf/per_hash_latency.rs` placeholder.
(R3-D3) Sibling commit lands `RANDOMX_V2_PHASE2D_PLAN.md` skeleton
scaffold. **Round 4 closed 2026-05-21:** threat-model addenda pass
against the priority-1 surface (per `00-mission.mdc`'s
security-and-quantum-resilience commitment). New §5.11 enumerates
six attack-objective findings + the audit-against-source discipline
note that produced the R3-D1 `mp` correction. In-scope 2c-implementation
additions: T1'/T2' determinism property tests (~60 LoC across
commits 2 and 3); `debug_assert!` discipline on the two unsafe
allocation sites (~10 LoC across commits 2 and 4); debug-vs-release
equivalence as a per-PR gate (1 CI-workflow line). Forward-actions
accumulated for 2g (adversarial seedhash corpus; pathological-program
worst-case timing bound), 3a (FFI null-check + length-validation +
seedhash-as-array-pointer + ERR_NULL_PTR taxonomy), and 2f (CacheStore
canonical-slot eviction-protection; `VmState` pool capacity sized
against daemon parallel-verification fanout). Parent-plan alignment
ships as a sibling commit on this branch (Decision #6, Decision #7,
Phase 0 §5/§6 carry-forwards). **Round 5 closed 2026-05-21:**
closure-only refinement pass tightening four discipline-enforcement
edges without surfacing new findings (substantive review surface
closed at Round 4). (R5-D1) §5.11.8 framing amendment — "reading-the-
source vs. producing-a-table-from-intuition" named as the load-
bearing audit step; "show your work" enforcement via line-range
citations in every audit table. (R5-D2) Parent plan §5 FFI hardening
refinements (sibling commit) — C-side `const uint8_t (*seedhash)[32]`
header form, C++ call-site declaration discipline, and
`RANDOMX_BLOCK_TEMPLATE_MAX_SIZE` rationale-sentence cross-check.
(R5-D3) 2d skeleton §3.1 CI grep mechanical enforcement addendum
(sibling commit) — matches the `no #[no_mangle]` invariant shape;
the prose-as-discipline is necessary but not sufficient. (R5-D4)
`docs/FOLLOWUPS.md` V3.0 entry (sibling commit) — post-2c-implementation
forward-action to promote 2c-emergent disciplines to project-level
documentation. Posture-shift note: Round 4's threat-model framing
converted "design closure" into "design closure plus active defense
against named attacker objectives" — named so 2d/2f/2g/LWMA-1 Phase 4
inherit the shape. Target ≤1 round met; implementation cut authorized
post-PR-#65 merge.

**Parent plan.** [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §"Track A
— Phase 2" sub-PR 2c is the binding one-line scope ("Implement Cache
(with public `derive(seedhash)` + pub(crate) `from_raw`/`derive_item`
accessors) AND `compute_hash(&Cache, &[u8; 32], &[u8]) -> [u8; 32]`
public transform [...]"); this doc expands it into a reviewable
change list, dependency-discipline dispositions, a test plan, and
the nine findings (plus the ShekylU128 audit) that closed during
Round 1, as tightened by Round 2's three structural restructurings.
The parent plan was revised in the precursor commit to absorb the
originally-scoped Phase 2e Cache::derive deliverable into 2c;
rationale in §5 F4 below. Round 2's parent-plan alignment is a
separate commit on this branch (terminology rewires for 2c/2d/2f
sub-PR text plus Decision #7 substrate-shift per
`21-reversion-clause-discipline.mdc`).

**Base commit.** `dev` at the post-PR-#64 merge tip (PR #64 — Phase
2b — landed via merge commit `fe7bc97d5` on 2026-05-21). This doc's
branch (`chore/randomx-v2-phase2c-plan`) cuts from there; the
Phase 2c implementation branch cuts later from post-this-doc `dev`.

**Branches.**

- `chore/randomx-v2-phase2c-plan` (this doc + the parent-plan
  precursor patch + Round 2 plan-doc revisions + Round 2 parent-plan
  alignment + Round 3 plan-doc revisions + Round 3 2d skeleton scaffold,
  plus Round 4 plan-doc threat-model addenda + Round 4 2d skeleton
  threat-model addenda + Round 4 parent-plan alignment, plus Round 5
  plan-doc closure refinements + Round 5 2d skeleton CI grep addendum,
  plus Round 5 parent-plan FFI-hardening refinements + Round 5
  `docs/FOLLOWUPS.md` V3.0 entry; short-lived per `06-branching.mdc`
  rule 2; thirteen commits; lands on `dev` via PR #65).
- `feat/randomx-v2-phase2c` (implementation; cut from post-this-doc
  `dev`; not yet cut as of this doc's commit).

**Scope envelope.** Single implementation PR. Target ≤1800 lines of
net-new Rust (implementation + tests + rustdoc) + ~50 KB of committed
reference vector bytes + ~200 LoC of C++ generator glue + ~200-250
LoC of CMake plumbing. ≤8 commits per §9 below. Slightly above 2b's
≤1500 envelope because of the F4-absorbed Cache::derive scope (which
in 2b's accounting would have been a separate 2e PR of ~500 LoC).
No FFI surface, no C++ caller rewire, no deletion of existing
`src/crypto/rx-slow-hash.c` etc. — those are Phase 3a/3b/3c/4.

**Cross-references.**

- **Parent plan.** [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md)
  §"Track A — Phase 2" enumerates the sub-PR split (now 6 sub-PRs:
  2a, 2b, 2c, 2d, 2f, 2g — 2e absorbed into 2c); §"Permanent
  architectural decisions" 1-8 are the locked decisions Phase 2c
  respects.
- **Design substrate.** [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md)
  §4 (Derived-First Design — Cache is the canonical transform-shaped
  example, built end-to-end in 2c; `compute_hash` is the
  per-hash transform), §7 (Isolation Invariants — `compute_hash`
  borrows `&Cache` and owns its transient `VmState` internally), §8
  (Performance Targets — ≤200 ms cache derive, ≤100 µs `VmState`
  allocation inside `compute_hash`, both PR-gated here; ≤3.0×
  per-hash deferred to 2g), §17 (Error taxonomy: `ERR_CACHE_DERIVE_FAILED`
  and `ERR_INTERNAL` plus the allocation-aborts-not-errors disposition).
- **Phase 2a precedent.** PR #62 (commit stack `7655310e2..f0d648fb2`
  on `feat/randomx-v2-phase2a`) is the workspace-member + first-
  primitive landing pattern. Provides `argon2d::fill_cache`
  consumed by `Cache::derive`.
- **Phase 2b precedent.** PR #64 (commit stack on
  `feat/randomx-v2-phase2b`, merged via `fe7bc97d5`) is the multi-
  primitive landing pattern this PR mirrors. Provides
  `aes::fill_aes_1r_x4`, `aes::fill_aes_4r_x4`, `aes::hash_aes_1r_x4`,
  `blake2_generator::Blake2Generator`, `superscalar::generate_superscalar`,
  `superscalar::execute_superscalar`, `superscalar::randomx_reciprocal`
  — all consumed by `Cache::derive` and `compute_hash` (via
  `VmState`'s internal execution loop).
- **Fork pin.** `external/randomx-v2/` submodule at `aaafe71`
  (v2.0.1). Line citations in this doc are stable against that pin.
- **Spec.** `external/randomx-v2/doc/specs.md` §4 (VM execution),
  §4.5 (program execution), §5 (instruction set), §7 (Cache
  derivation — Argon2d fill + 8 SuperscalarHash programs), §7.3
  (Dataset item derivation).
- **C reference.** `external/randomx-v2/src/dataset.cpp`
  (`initCache` + `initDatasetItem`),
  `external/randomx-v2/src/virtual_machine.cpp` (`initialize`),
  `external/randomx-v2/src/vm_interpreted.cpp` (interpreted VM
  execution loop), `external/randomx-v2/src/vm_interpreted_light.cpp`
  (`LightInterpretedVm::datasetRead`),
  `external/randomx-v2/src/bytecode_machine.{cpp,hpp}` (program
  parsing + bytecode dispatch, the latter stubbed in 2c).

## 1. Permanent architectural decisions binding Phase 2c

Per `RANDOMX_V2_PLAN.md` §"Permanent architectural decisions" 1-8.
Each is satisfied at Phase 2c open.

| # | Decision | Phase 2c compliance |
|---|----------|---------------------|
| 1 | C JIT stays miner-only | Zero JIT code in this PR; pure interpreter `compute_hash` transform. |
| 2 | Spec wins over C reference | `Cache` follows spec §7 (Argon2d fill + 8 SuperscalarHash); `compute_hash` follows spec §4 (initialization + execution loop). Spec-silent details dispositioned per `superscalar.rs`'s Phase 2b audit table; any 2c-new spec-silence entries go in `vm.rs` or `cache.rs` rustdoc. |
| 3 | Transform-shaped types | Both new public surfaces are transform-shaped per `18-type-placement.mdc`: `Cache::derive(seedhash) -> Cache` produces the long-lived derived state; `compute_hash(&Cache, &[u8; 32], &[u8]) -> [u8; 32]` produces a single hash from inputs. `VmState` exists only as a private implementation detail of `compute_hash` (transient per-hash scratchpad + register state, never observable to callers). No persisted intermediate state at any public boundary. |
| 4 | No prewarm / no async cache rebuild | Phase 2c adds no scheduling. `Cache::derive` is synchronous; `compute_hash` is synchronous. |
| 5 | No `#[no_mangle]` / `extern "C" fn` / `#[export_name]` | Phase 2f greps continue to zero-hit. |
| 6 | No module-level runtime-mutable state | Constants are `const`-only (cache memory size, scratchpad size, program size, program iterations, register counts). |
| 7 | Isolation invariants | `#![deny(unsafe_code)]` preserved at crate level. Two `unsafe` blocks needed (per §3 below): `Box::new_zeroed_slice` for cache + scratchpad allocation. Both gated behind `#[allow(unsafe_code)]` at the call site with `// SAFETY:` documentation per `45-rust-lint-checks.mdc`. |
| 8 | No env vars / build-flag dispatch | All constants inline; no runtime configuration. |

**F4-absorbed cross-cut: Cache lives in 2c, not 2e.** Per §5 F4 below,
absorbing `Cache::derive` into 2c eliminates the `DatasetReader` trait
abstraction the 2c-without-Cache shape would have required.
`compute_hash` takes `&Cache` directly — the eventual production
shape. Round 2's F1 restructuring (§5.1) generalizes this pattern:
the stub-NOP dispatch is a free function whose body is replaced in
2d, not a trait whose impl is swapped — eliminating the same mock-X
attack surface a second time.

## 2. Scope (the in-scope work)

One new public type + one new public free function. `VmState` and
`dispatch_instruction` are private implementation details of
`vm.rs`:

| # | Surface | Visibility | Spec section | C reference | Downstream caller |
|---|---------|-----------|--------------|-------------|--------------------|
| 1 | `Cache` (with `pub fn derive(seedhash)`; `pub(crate)` `from_raw`, `derive_item`, `item_bytes`) | `pub struct` + mixed-visibility methods | §7, §7.3 | `dataset.cpp::initCache` + `initDatasetItem` | 2c `compute_hash` (via `pub(crate)` `derive_item`); eventual 2f `CacheStore` (via `pub` `derive`); eventual 3a FFI surface |
| 2 | `compute_hash(cache: &Cache, seedhash: &[u8; 32], data: &[u8]) -> [u8; 32]` | `pub fn` | §4 (full per-hash flow) | `randomx::calculate_hash` orchestrating `virtual_machine.cpp::initialize` + `vm_interpreted.cpp::run` | eventual 2f `VmState`-pooling decision (internal to `compute_hash`); eventual 3a FFI surface (the FFI shim calls `compute_hash` directly) |
| 3 | `VmState` (private struct; internal scratchpad + register file + helpers) | `pub(crate) struct` (visible to `cache.rs` for tests, **not** re-exported via `lib.rs`) | §4 (initialization + execution loop) | `virtual_machine.hpp::RandomXVm` | internal to `vm.rs` only |
| 4 | `dispatch_instruction(instr: &Instruction, state: &mut VmState)` | private `fn` (not `pub(crate)`) | §5 (bytecode) | `bytecode_machine.cpp::execute` | internal to `vm.rs`'s execution loop only; Phase 2d replaces the body, no signature change |

Plus T1–T8 spec-vector tests (§6) + cache-derive bench +
compute-hash bench + BENCH_RESULTS.md baseline artifact + reference
vector generator (one binary with CLI flag per §7).

**Public surface delta from upstream framing.** The C reference and
the original Round-1 plan modeled the VM as a long-lived
`RandomXVm` / `Vm<'a>` value with `new` + `run` methods. Round 2
collapses this to a single `compute_hash` transform function: VM
state for a single hash has no identity across hashes (program is
re-derived from each seedhash per spec §4.1, scratchpad is
re-initialized per spec §4.3), the `new` then `run` two-call
ceremony is one operation, and exposing `VmState` would constrain
the 2f pooling-shape decision to a public-type pattern that
contradicts Decision #6 (`CacheStore` as transparent memo). Hiding
`VmState` keeps the 2f decision free to internalize pooling inside
`compute_hash` without an API-break. Exposing `VmState` later is
non-breaking; hiding it later isn't — so the conservative
disposition is to hide it from the start. See §5.1 F1 for the
matching dispatch-shape decision.

### 2.1 Explicitly out of scope

- Real bytecode dispatch (2d). The `dispatch_instruction` free
  function lands in 2c with a NOP body (`// Phase 2c stub: NOP all
  opcodes. Phase 2d replaces this body with table-driven per-opcode
  dispatch.`); 2d replaces the body in place. No trait, no impl
  swap, no generic parameter to thread through `compute_hash`'s
  signature.
- FPU rounding-mode plumbing for `fprc` (2d, per F2c). 2c uses host-
  default rounding mode; stub-NOP dispatch ensures this is unobservable
  in test outputs (per F7's rounding-mode-insensitive invariant).
- `F128([f64; 2])` newtype extraction (2d, per F3a). 2c uses raw
  `[f64; 2]` for FP registers; newtype extraction is 2d's call once
  bytecode dispatch reveals the API surface needed.
- `CacheStore` (2f), `VmState` pooling decision (2f — internalized
  inside `compute_hash`, not a public type), FFI surface, C++ rewire
  (3a-3c).
- Per-hash latency benchmark (2g). The ≤3.0× ratio check needs the
  differential harness 2g produces. 2c only runs cache-derive and
  compute-hash-allocation benches.

"While we're here" cleanup of unrelated files is forbidden per
`15-deletion-and-debt.mdc`. The in-file-discipline exception is the
2c-internal restructuring of `src/lib.rs` (adding `mod cache;` and
`mod vm;` declarations + re-exports), which is allowed because the
file is edited for substantive Phase 2c reasons.

## 3. Module layout

Forward from Phase 2a / 2b's one-file-per-primitive precedent:

```text
rust/shekyl-pow-randomx/src/
├── lib.rs                # adds `mod cache; mod vm;` + re-exports `Cache` (pub) + `compute_hash` (pub)
├── argon2d.rs            # (2a, unchanged)
├── aes.rs                # (2b, unchanged)
├── blake2_generator.rs   # (2b, unchanged)
├── superscalar.rs        # (2b, unchanged)
├── cache.rs              # NEW: `pub struct Cache` + `pub fn Cache::derive` + `pub(crate)` `Cache::{from_raw, derive_item, item_bytes}`
└── vm.rs                 # NEW: `pub fn compute_hash` + `pub(crate) struct VmState` + private `fn dispatch_instruction` (NOP stub body, replaced in 2d)
```

**Why two new files, not five.** Round 1's first-draft layout split
`vm/` into four sub-files (`mod.rs`, `dispatch.rs`, `scratchpad.rs`,
`registers.rs`). Round 2 collapses this: once `BytecodeDispatch` is
a free function (§5.1 F1), `dispatch.rs` is ~20 LoC and folds in;
the scratchpad helpers and register-file helpers are ~50 LoC and
~80 LoC respectively. Total `vm.rs` ≈ 250 LoC — under any file-size
threshold worth splitting on, and well-aligned with the one-file-per-primitive
precedent (`argon2d.rs`, `aes.rs`, `blake2_generator.rs`,
`superscalar.rs`) and the C reference's one-file-per-VM organization
(`vm_interpreted.cpp`). Splitting `vm.rs` later if it grows beyond
~500 LoC is non-breaking; collapsing it now matches the precedent.

Reference vectors land at:

```text
rust/shekyl-pow-randomx/tests/vectors/reference/
├── argon2d/              # (2a, unchanged)
├── aes/                  # (2b, unchanged)
├── superscalar/          # (2b, unchanged)
├── cache/                # NEW: T1 (cache derive) + T2 (derive_item) + .meta.txt + _generator/
└── vm/                   # NEW: T3-T8 (scratchpad/registers/program/spAddr/aes-mix/end-to-end) + .meta.txt + _generator/
```

Both new `_generator/` directories use **C++** (`gen.cpp` +
`g++ -std=c++17`) because `dataset.cpp` and `virtual_machine.cpp` are
C++ classes. Phase 2c uses a **single binary with CLI flag** per
§7 (one CMakeLists.txt, one binary, multiple test modes selected at
runtime via `--test=tN`).

## 4. Dependency dispositions

### 4.1 No new workspace dependencies

`Cache` and `compute_hash` (via `VmState`) consume only types
already exported (or `pub(crate)`) from 2a and 2b modules:

| Phase 2c consumer | Phase 2a/2b provider | Provider's current visibility | 2c disposition |
|-------------------|---------------------|------------------------|----------------|
| `Cache::derive` | `argon2d::fill_cache(key: &[u8], blocks: &mut [Block])` | `pub(crate) fn` | reuse as-is |
| `Cache::derive` | `blake2_generator::Blake2Generator::new` + `.get_byte`/`.get_uint32` | `pub(crate) struct` + `pub(crate) fn` methods | reuse as-is |
| `Cache::derive` | `superscalar::generate_superscalar(gen: &mut Blake2Generator) -> SuperscalarProgram` | `pub(crate) fn` | reuse as-is |
| `Cache::derive_item` | `superscalar::execute_superscalar(program: &SuperscalarProgram, registers: &mut [u64; 8])` | `pub(crate) fn` | reuse as-is |
| `Cache::derive_item` | `superscalar::randomx_reciprocal(divisor: u32) -> u64` | currently private `fn` (module-internal helper for `SuperscalarInstructionState::create`) | **2c promotes to `pub(crate) fn`** so `cache.rs` can call it during dataset-item derivation; the C reference computes the reciprocal on-the-fly per `dataset.cpp::initDatasetItem`, so no Rust-side `reciprocalCache` is introduced |
| `VmState::new` (scratchpad init) | `aes::fill_aes_1r_x4(state: &mut [u8; 64], output: &mut [u8])` | `pub(crate) fn` | reuse as-is |
| `VmState::new` (program parse) | `aes::fill_aes_4r_x4(state: &[u8; 64], output: &mut [u8])` | `pub(crate) fn` | reuse as-is |
| `compute_hash` / `VmState::run` (F/E AES mix) | `aes::fill_aes_4r_x4` (per spec §4) | `pub(crate) fn` | reuse as-is |
| `compute_hash` / `VmState::finalize` | `aes::hash_aes_1r_x4(input: &[u8], hash: &mut [u8; 64])` | `pub(crate) fn` | reuse as-is |

**Audit provenance (Round 5 amendment — §5.11.8 discipline).** Every
row in this table was verified by reading the named function's
declaration in the pinned `shekyl-pow-randomx` source. Per-row line
references at the time of the Round-5 audit pass (post-Phase-2b
merge SHA, recorded for reviewer spot-check):

- `argon2d::fill_cache` — `rust/shekyl-pow-randomx/src/argon2d.rs:165`
- `Blake2Generator::get_byte` / `get_uint32` — `rust/shekyl-pow-randomx/src/blake2_generator.rs:128, 145`
- `superscalar::generate_superscalar` — `rust/shekyl-pow-randomx/src/superscalar.rs:1227`
- `superscalar::execute_superscalar` — `rust/shekyl-pow-randomx/src/superscalar.rs:1427`
- `superscalar::randomx_reciprocal` — `rust/shekyl-pow-randomx/src/superscalar.rs:1520`
- `aes::fill_aes_1r_x4` / `fill_aes_4r_x4` / `hash_aes_1r_x4` — `rust/shekyl-pow-randomx/src/aes.rs:253, 312, 392`

The earlier draft (Rounds 1–4) had three audit-drift entries: the
`Blake2Generator` method names (`.next_byte`/`.next_u32` are not
the actual names — the actual methods are `.get_byte`/`.get_uint32`);
the `generate_superscalar` signature shape (the actual signature
takes only `gen: &mut Blake2Generator` and returns a
`SuperscalarProgram` by value, not the out-parameter form);
`randomx_reciprocal`'s divisor type (`u32`, not `u64`) and
visibility (currently private; Phase 2c promotes to `pub(crate)`).
The AES helper rows had a visibility-drift error (`pub fn`,
actually `pub(crate) fn`). All five corrections landed in the
Copilot-review absorption commit per the §5.11.8 audit-against-source
precedent (`mp` correction at R3-D1 — same shape, different surface;
audit-tables that don't cite line ranges are a prompted-list failure
mode regardless of how plausible the table looks).

**Verification gate (carried forward to Phase 2c implementation PR).**
Re-run the audit at PR-implementation time against the then-current
`shekyl-pow-randomx` source — visibilities, signatures, and method
names must match the implementation PR's actual call sites. Any
drift between this table and the implementation PR's source is the
same class of finding as `mp`; the implementation PR's plan-doc
audit row updates the citations to the implementation-PR pin and
the file/line numbers above adjust accordingly.

### 4.2 `criterion = "0.5"` (added by 2c implementation PR as DEV-only)

Used for `benches/cache_derive.rs` and `benches/compute_hash_alloc.rs`.
The implementation PR's commit 8 (per §9 commit granularity) adds the
dev-dep entry to `rust/shekyl-pow-randomx/Cargo.toml`:

```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
```

mirroring the pattern in `shekyl-scanner`, `shekyl-engine-state`, and
`shekyl-engine-file` (all of which declare `criterion = { version = "0.5",
features = ["html_reports"] }` directly in their crate `Cargo.toml`).
The version `0.5` is established by those crates; no version bump and no
workspace-dependencies-table addition needed. **R0-audit correction
(R0-D3):** earlier drafts framed criterion as "already in workspace via
Phase 2b's bench setup"; Phase 2b did not establish a bench setup in
`shekyl-pow-randomx`, and `rust/shekyl-pow-randomx/Cargo.toml` has no
`[dev-dependencies]` section at audit-pin `5df8bd2c2`. See
`RANDOMX_V2_PHASE2C_AUDIT.md` §5 F1 for the audit trail.

### 4.3 `bytemuck` — REJECTED

The dataset-item derivation path needs byte-level access to
`Cache.blocks: Box<[argon2d::Block]>` where `Block` is
`#[repr(align(64))] struct Block([u64; 128])`. The straightforward
approach is a `bytemuck::cast_slice::<Block, u8>(&cache.blocks)`,
but this requires adding `bytemuck` as a workspace dependency and
deriving `Pod` for `Block` — both broader changes than 2c needs.

**Disposition:** Add a `pub(crate) fn item_bytes(&self, item_number: u64)
-> [u8; 64]` accessor method on `Cache` that does the index math
inline (item_number → cache-line offset → block index + within-block
offset → 8 × 8-byte loads via `Block::word(idx) -> u64` accessor on
the Block type). No `unsafe`, no new dependency, no `Pod` derivation,
no broader API surface. This is F4-detail-A from the Round 1 walk;
F4-detail-B (bytemuck addition) is the reopening criterion if 2c's
test runtime shows the per-load overhead is significant.

## 5. Findings (Round 1)

Round 1 closed via interactive design walk on 2026-05-21. Each
finding has a one-paragraph problem statement + a disposition + (where
applicable) a reversion-clause-shaped reopening criterion per
`21-reversion-clause-discipline.mdc`.

### 5.1 F1 — 2c/2d boundary: stub-NOP bytecode dispatch as a free function

**Problem.** The parent plan's 2c scope ("`Vm<'a>` ... spec-vector
parity tests") is incoherent without the 2d bytecode dispatch — a
`Vm` without instruction dispatch can't produce a hash, and spec
vectors test hashes. The naive 2c shape produces a `Vm` whose `run`
method is unimplemented or panics, which makes the spec-vector tests
unable to land.

**Disposition (F1a + F4-absorbed strengthening + R2-D1
function-body-replacement).** 2c lands `compute_hash` with the
following internal execution loop:

```rust
// vm.rs (private to the module)
fn dispatch_instruction(_instr: &Instruction, _state: &mut VmState) {
    // Phase 2c stub: NOP all opcodes.
    // Phase 2d replaces this body with table-driven per-opcode dispatch.
    // See docs/design/RANDOMX_V2_PHASE2D_PLAN.md (forward-action).
}
```

`VmState::run` calls `dispatch_instruction(instr, self)` directly
inside the per-iteration loop. The spec-vector tests validate the
structural pieces of the VM loop (scratchpad init, register init,
program parse, spAddr derivation, F/E AES mix, end-to-end finalize)
using a synthetic 2048-NOP program over a **real cache** (per the
F4-absorbed scope expansion below). This corpus exercises everything
except per-instruction semantics — a much wider test surface than
the original F1a stub-NOP-with-mock-cache shape would have allowed.

**Why a free function, not a trait + stub impl (Round 2 substrate
finding).** Round 1's first-draft F1 introduced a `BytecodeDispatch`
trait with a `StubNopDispatch` impl, intended to be replaced by a
`TableDispatch` impl in 2d. Round 2 caught this as a recurrence of
the same mock-X anti-pattern Round 1 F4 dissolved for `DatasetReader`
/ `MockDatasetReader`. The recurrence is structurally identical:

- **The trait exists only to support a temporary stub.** Once 2d
  lands, there is exactly one implementation. A trait with one
  implementation is debt per `21-reversion-clause-discipline.mdc`
  (optionality without a named caller).
- **The stub is consensus-relevant code shipped in test builds.**
  Same reviewer-attention and audit-surface cost as the dissolved
  `MockDatasetReader`.
- **The trait surface persists past 2d.** Removing the trait in 2d
  is itself a follow-up PR (with its own review surface, breakage
  risk, and migration cost). Free-function-body-replacement requires
  no follow-up removal.
- **2d's wire-in cost is non-trivial under the trait shape.** Either
  (a) `compute_hash` takes `impl BytecodeDispatch` (signature change,
  every caller updates); (b) `compute_hash` is generic over `D:
  BytecodeDispatch` (every caller specifies the type parameter); or
  (c) `compute_hash` holds a `Box<dyn BytecodeDispatch>` (heap
  allocation in the hot path, dynamic-dispatch overhead per
  instruction × 8 chains × 2048 iterations per hash). All three are
  downstream costs the free-function shape avoids entirely.

The case for the trait was "dependency injection for testing." The
case against: 2c's spec-vector tests don't need to inject a different
dispatch — they verify the stub-NOP behavior directly against
generator output. 2d's test corpus verifies the real dispatch. There
is no test scenario where 2c's tests need to inject anything other
than the stub. The trait would exist solely to enable a degree of
freedom no caller exercises.

**Reopening criterion (reversion-clause shape).** Reject the trait
shape now. Reopen only if 2d's design surfaces a concrete consumer
that needs to inject an alternative dispatch implementation — e.g.,
an instrumented dispatch for profiling, or a constant-time-checked
dispatch for an audit. "If we ever need it" is not a criterion;
"if Phase 2d's design rounds enumerate a specific second
implementation with a named caller" is. The re-evaluation shape:
2d's plan-doc-time design round, not implementation-time
reactive scope expansion.

**Cross-reference.** This is the same shape as F4's elimination
of `DatasetReader`; the F4 dissolution rationale (§5.4 "Why the
absorption is the right shape") applies here verbatim. The two
findings together establish the discipline: trait + stub-impl =
mock-X anti-pattern; transform-function + body-replacement = the
shape Shekyl uses for this pattern.

### 5.1.1 Function-body replacement contract (2c → 2d hand-off)

**Why this section exists (R3-D1).** R2-D1 replaced the
`BytecodeDispatch` trait + `StubNopDispatch` impl with a
`dispatch_instruction` free function whose body is NOP in 2c and is
replaced in 2d. "Replaces the body" is one of the most failure-prone
refactor patterns in code review — the signature can change silently;
the new body can implicitly require different state initialization;
the stub's assumptions about `VmState`'s shape can fail to carry
forward. This section pins the contract explicitly so 2d's review
surface is mechanical ("does the contract hold?") rather than
diff-archaeology of what the trait used to encapsulate.

The contract has three frozen surfaces. Each freezing locks one
degree of freedom that the trait + stub-impl shape would have exposed.

#### Frozen surface 1: `dispatch_instruction` signature

```rust
fn dispatch_instruction(instr: &Instruction, state: &mut VmState)
```

2d **cannot**:

- Add parameters. (E.g., a `&Cache` parameter for "memory-mode reads"
  — empirically wrong: per `bytecode_machine.hpp:145-270`, no
  per-instruction handler reads the cache. M-opcodes read the
  scratchpad; the cache is only read by the per-iteration dataset
  read inside `VmState::run`, not by `dispatch_instruction`.)
- Add a return value. (CBRANCH's PC mutation is via `state` — see
  VmState field set below.)
- Change the lifetime/borrow shape. (No `&'a Cache` field on
  `VmState`; no `'_` elision shift; `VmState` carries owned data
  only with no lifetime parameter.)
- Restructure as an IBC-style 2-pass design. (See the reopening
  criterion at the bottom of this sub-section.)

**Single-pass design choice.** The contract locks the single-pass
shape (`dispatch_instruction` reads `opcode`/`dst`/`src`/`mod_`/`imm32`
from `&Instruction` per call). The C reference uses a 2-pass design
that pre-resolves register pointers into an `InstructionByteCode`
form at compile-time (`bytecode_machine.hpp:46-65, 117-124`). The
Rust port adopts the single-pass shape on the prior that Rust+LLVM
optimize the per-call decode trivially (`Instruction` is an 8-byte
packed struct read). If 2d's benchmarks invalidate this prior, the
reopening criterion below applies.

#### Frozen surface 2: `Instruction` field set

Per RandomX spec §5.1 and verified against the v2 fork's
`instruction.hpp`:

```rust
struct Instruction {
    opcode: u8,
    dst: u8,
    src: u8,
    mod_: u8,
    imm32: u32,
}
```

2d cannot add fields. Spec §5.1's 8-byte instruction layout is
wire-format-stable (program-init produces these byte-for-byte from
the entropy buffer). Instruction-derived state (resolved register
pointers, memMask, shift amount, branch target) is computed per-call
inside `dispatch_instruction`'s body, not stored on `Instruction`.

#### Frozen surface 3: `VmState` field set

The most failure-prone hand-off. If `VmState` ships in 2c missing a
field 2d's dispatch needs (e.g., FDIV_M's `eMask`), 2d either extends
`VmState` (violating this contract) or hacks around it. Either is
bad. The audit (below) enumerates each field empirically against the
C reference's 29 opcode handlers + iteration loop.

**Audit command (Round 3 deliverable; re-verified at implementation-PR
time):**

```bash
grep -nE 'static void exe_' external/randomx-v2/src/bytecode_machine.hpp
```

28 hits — one per spec opcode **except** IMUL_RCP, which has no
dedicated `exe_` handler. IMUL_RCP dispatches through `exe_IMUL_R`:
`bytecode_machine.cpp:75` reads `case InstructionType::IMUL_RCP: //executed as IMUL_R`,
and `compileInstruction` sets `ibc.type = IMUL_R` for IMUL_RCP with
`ibc.isrc` pointing at the precomputed reciprocal in `reciprocalCache`
instead of a real register. The 28 handlers cover all 29 dispatchable
ibc.type values because IMUL_RCP collapses to IMUL_R at compile time.
**R0-audit correction (R0-D1):** earlier drafts read "29 hits"; the
actual grep count at audit-pin `aaafe71` is 28. Field-set derivation
unaffected (IMUL_RCP's register reads/writes are a subset of IMUL_R's;
the reciprocal lives behind `ibc.isrc` which resolves through the same
`int_reg_t*` typedef regardless of whether the source is a real
register or `reciprocalCache[i]`). See `RANDOMX_V2_PHASE2C_AUDIT.md`
§5 F2 for the audit trail.

Each handler's body reads/writes through
`*ibc.{idst,isrc,fdst,fsrc}`, `ibc.{imm,shift,target,memMask}`,
`scratchpad`, and `config` (FDIV_M only). The pointer indirections
(`ibc.idst` etc.) resolve to fields on `RegisterFile`/
`NativeRegisterFile` (`common.hpp:189-195`, `bytecode_machine.hpp:38-44`)
plus `ProgramConfiguration` (`program.hpp:39-42`) plus
`MemoryRegisters` (`common.hpp:184-187`) plus per-VM state in
`randomx_vm` (`virtual_machine.hpp:69-85`). Cross-referenced against
`vm_interpreted.cpp::execute()` (the iteration loop) for fields read
outside `dispatch_instruction`.

**Required for `dispatch_instruction`:**

| Field | Type | C reference source | Used by opcode(s) |
|-------|------|-------------------|-------------------|
| `r` | `[u64; 8]` | `NativeRegisterFile.r[RegistersCount]` | All integer R-form opcodes (IADD_RS, ISUB_R, IMUL_R, IMULH_R, ISMULH_R, IMUL_RCP, INEG_R, IXOR_R, IROR_R, IROL_R, ISWAP_R) + integer M-opcodes (IADD_M, ISUB_M, IMUL_M, IMULH_M, ISMULH_M, IXOR_M) + ISTORE + CBRANCH |
| `f` | `[F128; 4]` (Phase 2c: `type F128 = [f64; 2];` alias) | `NativeRegisterFile.f[RegisterCountFlt]` | FADD_R, FADD_M, FSUB_R, FSUB_M, FSCAL_R, FSWAP_R |
| `e` | `[F128; 4]` (Phase 2c: `type F128 = [f64; 2];` alias) | `NativeRegisterFile.e[RegisterCountFlt]` | FMUL_R, FDIV_M, FSQRT_R |
| `a` | `[F128; 4]` (Phase 2c: `type F128 = [f64; 2];` alias) | `NativeRegisterFile.a[RegisterCountFlt]` | Read-only operand (FADD_R, FSUB_R, FMUL_R `fsrc`); never mutated after init |
| `fprc` | `u32` | not in `NativeRegisterFile`/`MemoryRegisters` — separate VM state (per spec §5.2.5) | CFROUND |
| `scratchpad` | `Box<[u8; SCRATCHPAD_L3]>` | `uint8_t* scratchpad` (VmBase) | All M-opcodes (IADD_M, ISUB_M, IMUL_M, IMULH_M, ISMULH_M, IXOR_M, FADD_M, FSUB_M, FDIV_M) + ISTORE |
| `e_mask` | `[u64; 2]` | `ProgramConfiguration.eMask[2]` | FDIV_M (via `maskRegisterExponentMantissa`, `bytecode_machine.hpp:272-278`) |

**`F128` shorthand discipline.** The `[F128; 4]` spelling in the
table above is editorial shorthand for `[[f64; 2]; 4]` — Phase 2c
introduces `F128` only as a `type F128 = [f64; 2];` alias (per §5.3
F3a). Phase 2c's `VmState` field types compile against the raw
`[f64; 2]` representation; the alias is a single-line `type`
declaration with no methods and no `struct` wrapper. The newtype
extraction decision (`struct F128([f64; 2])` with method API,
distinct type identity, potential `Copy`/`Default`/`Debug` derives)
is deferred to Phase 2d's §3.2 design-decision point per F3a's
explicit deferral. Implementers reading this table should **not**
infer that 2c must define an `F128` newtype — the frozen field set
locks the *element shape* (`[f64; 2]`), not the *type identity*.
2d Round 1 makes the newtype-or-keep-alias call against real
dispatch surfaces; until then, "F128" is a typographic convenience
for "the two-f64 pair the FP registers carry."

**Required for `VmState::run` iteration loop only (`dispatch_instruction` does NOT read these):**

| Field | Type | C reference source | Iteration-loop role |
|-------|------|-------------------|---------------------|
| `ma` | `u32` | `MemoryRegisters.ma` | `datasetRead` address; per F5 v2-only collapse, also written by `mp ^= readReg2 ^ readReg3` (`vm_interpreted.cpp:90` under V2 alias). Init source for `sp_addr1` (`vm_interpreted.cpp:67`). |
| `mx` | `u32` | `MemoryRegisters.mx` | `datasetPrefetch` address; `std::swap(mem.mx, mem.ma)` swap target each iteration (`vm_interpreted.cpp:94`). Init source for `sp_addr0` (`vm_interpreted.cpp:66`). |
| `read_reg` | `[u32; 4]` | `ProgramConfiguration.readReg0..3` | sp_addr derivation + mp-XOR each iteration (`vm_interpreted.cpp:70, 90`). |
| `dataset_offset` | `u64` | `randomx_vm::datasetOffset` | `datasetRead`/`datasetPrefetch` base offset (per-VM, set during `initialize`). |
| `program` | `Box<Program>` | `randomx_vm::program` | 2048 parsed instructions feeding the dispatch loop. |
| `temp_hash` | `[u64; 8]` | `randomx_vm::tempHash` | Blake2b intermediate buffer for program-init and finalize. |

**Explicitly NOT in `VmState` (with Round 3 audit rationale):**

| Field | Disposition | Source / why |
|-------|-------------|--------------|
| `mp` | **NOT a separate field** | `vm_interpreted.cpp:89` is `auto& mp = (flags & V2) ? mem.ma : mem.mx;` — a v2-only **local-variable alias** for `mem.ma`. The C reference's `MemoryRegisters` struct (`common.hpp:184-187`) carries only `mx` and `ma`. F5 v2-only simplification collapses the assignment site to `state.ma` directly, eliminating the alias. **Round 3 audit correction (R3-D1):** the earlier prompted field list speculated `mp: u32` as a separate field; the audit verified no such field exists in the C reference, and the v2-only Rust port introduces none. See §5.5 F5 corrected entry. |
| `vm_flags` | NOT in `VmState` | F5 v2-only: no version branching at runtime; v2 is structural. |
| `cache_key` | NOT in `VmState` | `randomx_vm::cacheKey: std::string` (`virtual_machine.hpp:83`) is metadata not read by execution; only used for diagnostic prints in the C reference. |
| `register_usage` | NOT in `VmState` (under single-pass) | `BytecodeMachine::registerUsage[RegistersCount]` (`bytecode_machine.hpp:282`) is compile-pass state for CBRANCH-time register-availability tracking. Single-pass dispatch (per Frozen surface 1) has no compile pass; the tracking is unneeded. |
| `sp_addr0`, `sp_addr1` | NOT in `VmState` (locals) | `vm_interpreted.cpp:66-67` are local variables in `execute()`. The Rust port keeps them as local variables in `VmState::run`'s iteration loop. `dispatch_instruction` never reads them; M-opcode addresses come from `r[src] + imm32` masked by memMask (`bytecode_machine.hpp:285-288`), NOT from spAddr. |
| `&Cache` borrow | NOT a `VmState` field | Passed to `VmState::run` as a parameter; `compute_hash` owns the borrow. `VmState` carries owned data only — no lifetime parameter, no `&'a Cache` field. The cache is read once per iteration (the dataset read between dispatch loop and AES mix) inside `VmState::run`, not by `dispatch_instruction`. |

#### Reopening criterion (reversion-clause shape)

Per `21-reversion-clause-discipline.mdc`, the signature freeze is
conditional, not absolute. The reopening criterion:

**Reopen iff** 2d's per-opcode dispatch benchmark (per F8
forward-action consumed by 2g) demonstrates that single-pass dispatch
cannot meet Phase 0's ≤3.0× C-reference budget — **and** the
demonstrated shortfall is attributable to per-call decode cost rather
than per-opcode body work (i.e., profiling shows the
`opcode`/`dst`/`src`/`mod_` field reads from `&Instruction` are a
non-trivial fraction of per-instruction cost).

**Re-evaluation shape** (if the criterion triggers): 2d Round 1
surfaces the benchmark evidence and re-specs the signature to
`fn dispatch_instruction(ibc: &InstructionByteCode, state: &mut
VmState)`, where `InstructionByteCode` is the pre-resolved-pointer
form mirroring the C reference's `bytecode_machine.hpp:46-65`. The
2c amendment (adding `InstructionByteCode` to `vm.rs` + adding an
`Instruction → InstructionByteCode` compile pass to
`VmState::initialize`) is a documented 2d-Round-1 amendment to 2c,
not implementation-time reactive scope expansion. The cost of the
reopening is bounded by 2c's structural pre-work: the audit table
above already enumerates everything `VmState` needs; the only
addition is the `InstructionByteCode` type and the compile pass.

**Reopen NOT iff** 2d's author prefers the IBC form for style
reasons, wants pre-emptive performance margin without benchmark
evidence, or cites "alignment with C reference shape" as the
justification. Per `21-reversion-clause-discipline.mdc`'s
anti-pattern enumeration ("Keep it for flexibility" is debt;
"Reopen on request" is no discipline at all), preference-based
reopening is rejected.

**Cross-references.** Phase 2d's plan doc
(`docs/design/RANDOMX_V2_PHASE2D_PLAN.md`, the Round 3 R3-D3 skeleton
shipped alongside this plan doc) carries the contract forward
verbatim and references this section. Implementation-PR-time review
of 2d's diff checks against this contract mechanically: signature
unchanged; `Instruction` field set unchanged; `VmState` field
additions justified by audit-grep evidence against
`bytecode_machine.hpp` opcode handlers; reversion criterion either
satisfied (with named benchmark evidence) or not invoked.

### 5.2 F2 — FPU rounding mode: deferred to 2d

**Problem.** RandomX's `fprc` register selects one of four IEEE 754
rounding modes (RN/RD/RU/RZ) per program iteration. Stable Rust has
no direct `set_rounding_mode` API (it's nightly-only via
`std::arch::asm!` or third-party crates with `unsafe`). The crate's
`#[deny(unsafe_code)]` policy forecloses naive plumbing.

**Disposition (F2c — defer to 2d).** 2c's `compute_hash` (via
`VmState::run`) uses the host's default FP rounding mode (RN on
every standard platform). This is unobservable in 2c's spec-vector
tests because stub-NOP dispatch means no FP arithmetic executes,
so the rounding mode never affects any operation. The `fprc` field
exists in `VmState` but is never read in 2c (no instruction reads
it).

**Reopening criterion.** 2d's bytecode dispatch wires FADD_R, FSUB_R,
FMUL_R, FDIV_M, FSQRT_R, CFROUND — all of which depend on `fprc`.
2d's design rounds revisit the rounding-mode plumbing question: either
(a) opt-in `unsafe` block with a `// SAFETY:` doc-comment, (b)
third-party crate (e.g., `rug` or a minimal x86_64+aarch64-targeted
helper), or (c) a Rust language change (unlikely; track upstream).
Each option has its own dependency-discipline and isolation-invariant
implications evaluated at 2d's design time, not 2c's.

### 5.3 F3 — `f128` representation: `[f64; 2]` raw; `F128` newtype deferred

**Problem.** RandomX's FP registers are 128-bit values (two 64-bit
doubles). Stable Rust has no `f128` type. The Rust representation
must be chosen.

**Disposition (F3a — `[f64; 2]` raw).** Phase 2c uses `[f64; 2]` raw
for FP register fields in `NativeRegisterFile`. No newtype, no traits,
no encapsulation beyond the array.

**Why `ShekylU128` was rejected.** Round 1 considered using the
existing `ShekylU128 { lo: u64, hi: u64 }` ABI type from
`shekyl-ffi/src/difficulty_ffi.rs`. Three independently-sufficient
disqualifiers surfaced; the load-bearing one is workspace-dependency
direction:

1. **Semantic mismatch.** `ShekylU128` is a 128-bit *integer* ABI
   shim; FP registers are *two floats*. Reinterpreting bits via
   `f64::from_bits(u128.lo) + f64::from_bits(u128.hi)` ceremony at
   every use site obscures the actual operation.
2. **Workspace-dependency direction (load-bearing disqualifier).**
   Today `shekyl-ffi` depends on `shekyl-pow-randomx` (consumes the
   verifier crate). Importing `ShekylU128` into `shekyl-pow-randomx`
   reverses the direction and creates a dependency cycle in the
   workspace topology. Even if the bit-pattern matched and the
   ceremony were ergonomic, the structural disqualifier stands.
3. **`#[repr(C)]` constraints.** `ShekylU128`'s ABI layout is
   load-bearing for the FFI surface it's designed for; adopting it
   for FP registers would constrain its layout against an additional
   consumer (compounding maintenance risk).

The closest pure-Rust alternative — a `struct F128([f64; 2])`
newtype with method API for FP operations — is the right encapsulation
when API beyond raw `[f64; 2]` is needed. Per the parent-plan
discipline of "don't pre-extract," 2c uses `[f64; 2]` raw; 2d's
bytecode dispatch reveals the actual method needs (e.g.,
`add_unrestricted`, `sub_unrestricted`, `mul_unrestricted` per spec
§5.2.5); 2d extracts the newtype at that point.

**Reopening criterion.** 2d's design rounds. If 2d's bytecode
dispatch requires method-shaped API on FP registers (likely yes,
given spec §5.2.5's unrestricted-arithmetic semantics), extract
`F128([f64; 2])` as a newtype with `pub fn` methods. If 2d's dispatch
keeps everything as inline `[f64; 2]` operations, no newtype is
needed.

### 5.4 F4 — Cache::derive absorption (eliminates DatasetReader trait)

**Problem.** Phase 2c's per-hash execution needs to read dataset
items (spec §4.5.4 — every iteration reads one 64-byte dataset item
into the scratchpad). The parent plan's original split had
`Cache::derive` in 2e, so 2c had no `Cache` type to borrow from.
The naive 2c shape introduces a `DatasetReader` trait that abstracts
over the absent `Cache::derive`, with a `MockDatasetReader` impl for
2c's tests and a real `CacheDatasetReader` impl that 2e wires up.

**Disposition (absorption — eliminate the trait).** 2c absorbs the
`Cache::derive` deliverable from 2e. `compute_hash` takes `&Cache`
directly; the dataset-item read inside `VmState::run` is
`cache.derive_item(item_number)` — a `pub(crate) fn` on `Cache`,
not a trait method on an abstract reader. No trait, no mock, no
light-vs-full abstraction split. The same dissolution rationale
applies recursively to the dispatch shape (F1 R2-D1): trait + stub
impl is the mock-X anti-pattern; function-body-replacement is the
shape Shekyl uses.

**Why the absorption is the right shape.**

- **Eliminates trait + mock attack surface.** A trait exists to
  abstract over multiple implementations. With the absorption, there
  is exactly one implementation (`Cache::derive_item`). A trait with
  one implementation is debt per `21-reversion-clause-discipline.mdc`
  (optionality without a named caller).
- **`compute_hash`'s production shape lands in 2c.** Eventually
  2f's `CacheStore` produces `Arc<Cache>` and the FFI shim runs
  `compute_hash(&cache, seedhash, data)`. The 2c borrow signature
  is the eventual production signature — no API churn between 2c
  and 3a.
- **Test corpus widens dramatically.** Stub-NOP dispatch + mock
  cache (the original F1a + 2c-without-Cache shape) tests the VM
  loop's structural correctness in isolation. Stub-NOP dispatch +
  **real** cache (this absorption) tests the cache-derived data
  flowing through real entropy buffers, real register initialization,
  real spAddr derivation, real F/E AES mix, real Blake2b finalization
  — everything except per-instruction semantics. The bisect-friendly
  surface is the same (T1–T8 cover each component); the validation
  surface is roughly an order of magnitude wider.
- **The work is small.** `Cache::derive` composes existing 2a+2b
  primitives (`argon2d::fill_cache` + 8× `superscalar::generate_superscalar`
  per spec §7). The C reference's `dataset.cpp::initCache` is ~30
  meaningful lines of orchestration. The Rust port is similar,
  plus an additional ~30 lines for `derive_item` (per spec §7.3 —
  8 SuperscalarHash executions chained with cache reads). Net new
  code ≈ 100 LoC including rustdoc.
- **The Rust port is simpler than C.** The C reference maintains a
  `reciprocalCache` (`dataset.cpp::initCache` ~line 100) that
  precomputes reciprocals for IMUL_RCP instructions in the
  SuperscalarHash programs. Phase 2b's `randomx_reciprocal` is
  already on-the-fly (computed at execution time, not cache time);
  the Rust port omits the reciprocal cache entirely. ~20 LoC saving
  vs. C, with no semantic change.

**Reopening criterion.** Not applicable as a 2c-time deferral — the
absorption is the implementation shape, not a deferral. As a
forward-action: if 2f's `CacheStore` or 3a's FFI surface reveals a
need for trait-based abstraction (e.g., to mock cache reads in
high-level integration tests), revisit at that point. As of 2c's
landing, no caller needs a trait.

**Parent-plan revision artifact.** The precursor commit (preceding
this doc's commit on the same branch) revised
[`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) to:

- expand `phase2c-vm-and-cache` content;
- expand `phase2d-bytecode-v2` content (FPU + F128 forward-pointers);
- delete `phase2e-cache-derive` entirely;
- update §"Track A — Phase 2" sub-PR bullet enumeration (now 6 bullets
  instead of 7);
- update §"Performance targets" benchmark-phase references (Phase 2e
  → Phase 2c for cache derive; Phase 2e → Phase 2g for per-hash);
- flip `phase2a` and `phase2b` YAML status to `completed` (PRs #62
  and #64 merged respectively).

### 5.5 F5 — v2-only simplifications from C reference

**Problem.** The C reference is dual-version (v1 + v2). Per
`60-no-monero-legacy.mdc`, Shekyl is v2-from-genesis; the Rust port
must delete v1 branches, not preserve them under flags.

**Disposition.** Enumerate the v1/v2 branches in the C reference
that the Rust port deletes (interpreter path only; the JIT path is
not ported per `RANDOMX_V2_PLAN.md` Decision #1).

**Audit grep command (run at plan-doc-time + implementation-PR-time):**

```bash
grep -rn -E "(RANDOMX_PROGRAM_SIZE_V1|RANDOMX_PROGRAM_SIZE_V2|RANDOMX_FLAG_V2|isV2\(|flags\s*&\s*RANDOMX_FLAG)" external/randomx-v2/src/
```

Round 1 ran this against the `aaafe71` fork pin. Interpreter-path
hits (the Rust port deletes these; JIT-path hits are out of scope per
Decision #1):

| C reference site | v2 form (Rust port adopts) | Rust port shape |
|------------------|----------------------------|-----------------|
| `vm_interpreted.cpp:89` — `auto& mp = (flags & V2) ? mem.ma : mem.mx;` | `mp` is a v2-only **local-variable alias** for `mem.ma` | No `mp` field in `VmState`. The v2 simplification collapses the assignment site (`vm_interpreted.cpp:90`, `mp ^= ...`) to `state.ma ^= ...` directly, eliminating the alias. The C reference's `MemoryRegisters` struct (`common.hpp:184-187`) carries only `mx` and `ma`; `mp` exists only as the function-local reference inside `execute()`. **Round 3 audit correction (R3-D1):** earlier drafts read this entry as `mp` being a `Vm` field that "exists unconditionally"; the C reference does not carry it as a struct field, and the v2-only Rust port has no reason to introduce one. See §5.1.1's "Explicitly NOT in `VmState`" row for the verified disposition. |
| `vm_interpreted.cpp:99` — `if (flags & V2)` F/E AES mix over FP registers | take v2 branch unconditionally | `VmState::run`'s F/E AES mix is the v2 form (per spec §4.5.4) with no conditional. |
| `bytecode_machine.hpp:261-266` — `exe_CFROUND` body: `if (((flags & V2) == 0) \|\| ((isrc & 60) == 0)) rx_set_rounding_mode(isrc % 4);` | take v2 branch (CFROUND is throttled) | The v2-only condition gates CFROUND on `(isrc & 60) == 0` — bits 2–5 of the rotated source register must be clear, so CFROUND fires on ~1/64 of evaluations rather than every iteration. Phase 0 §6 names this as the structural protection against adversarial seedhashes that produce programs which re-set the FPU rounding mode every iteration (worst-case-timing exposure). The v2-only Rust port encodes the throttle unconditionally in 2d's `exe_CFROUND` equivalent — no `cfg(v1)` branch, no fall-through to the v1-form "fire every time" path. 2c's stub-NOP `dispatch_instruction` body executes no CFROUND, but the F5 forward-pointer ensures 2d's body replacement inherits the throttle exactly. **R0-audit correction (R0-D1):** earlier drafts mis-labeled this row as an "IADD_M/ISUB_M/IMUL_M imm32 cap"; the cited line is CFROUND, not a memory-instruction handler. Memory-form integer instructions in `bytecode_machine.cpp` (`compileInstruction` sites for IADD_M/ISUB_M/IMUL_M) full-sign-extend the 32-bit imm via `signExtend2sCompl(instr.getImm32())` with no v1/v2 differential cap. The "caps to first 6 bits" framing was a mis-summary of CFROUND's `isrc & 60` mask. See `RANDOMX_V2_PHASE2C_AUDIT.md` §5 F3 for the audit trail. |
| `virtual_machine.hpp:63-66` — `setFlagV2()` / `clearFlagV2()` mutators | no flag mutation | `Vm` has no `set_flag_v2` method; v2 is hardcoded by construction. |
| `program.hpp:56-58` — `Program::getSize(flags)` returning `_V1=256` or `_V2=2048` | `PROGRAM_SIZE = 2048` | Rust constant `pub(crate) const PROGRAM_SIZE: usize = 2048;` (no flags param). **R0-audit correction (R0-D2):** earlier drafts cited `program.hpp:46-48`; the correct location at audit-pin `aaafe71` is `program.hpp:56-58`. Lines 46-48 are `operator()(int pc)`, the instruction accessor. Semantic claim unchanged. |
| `common.hpp:51-54, 98-102` — V1+V2 static_asserts | V2 only | Rust port retains only V2-form assertions in `Cache`/`Vm` const blocks. |
| `configuration.h:56` — `#define RANDOMX_PROGRAM_SIZE_V1 256` | not defined | Rust has no `PROGRAM_SIZE_V1` constant. |
| `randomx.h:52` — `RANDOMX_FLAG_V2 = 128` enum value | no flags enum | Rust has no flags enum; v2 is structural. |

**JIT-path hits (out of scope per Decision #1, not deleted from C
reference because the C reference is the upstream-tracking source):**

`jit_compiler_x86.cpp`, `jit_compiler_rv64.cpp`, `jit_compiler_rv64_vector.cpp`
— ~18 total `flags & RANDOMX_FLAG_V2` branches across these files.
The Rust port doesn't link these compilation units; their v1/v2
branches are irrelevant to the Rust port.

**CFROUND forward-pointer (2d discipline note).** CFROUND (spec
§5.2.5) is the per-program-iteration rounding-mode-setter instruction.
Spec v1 had a per-iteration form; v2 has a per-program-iteration
counter form. The C reference's CFROUND handler in
`bytecode_machine.{cpp,hpp}` does not branch on `RANDOMX_FLAG_V2`
(the v2 form is structural in the v2 fork), so the F5 grep doesn't
surface a CFROUND v1/v2 branch to delete. However, when 2d
implements CFROUND, the implementer must inherit this discipline:
no `cfg(v1)` shim is permitted, no version-gated CFROUND handler
is permitted. The v2 form is the only form. **This note is the
discipline carry-forward; 2d's plan doc cites it explicitly.**

### 5.6 F6 — Reference vector generator

**Problem.** 2c's spec-vector tests (T1–T8) require a C++ generator
linking a non-trivial subset of the `randomx-v2` source plus
Argon2d and Blake2 substrate, totaling ~17-19 implementation files
(`.cpp`/`.c`) + ~15 transitive headers. Plus custom C++ glue that
constructs the test artifacts.

**Disposition: single binary with CLI flag.**

One CMake link target (`phase2c_gen`) with multiple entry-point
functions in `gen.cpp`; `main()` dispatches via flag:

```bash
./phase2c_gen --test=t1 > t1.bin   # cache-derive fingerprint
./phase2c_gen --test=t2 > t2.bin   # cache.derive_item per item_number
# ... etc ...
./phase2c_gen --test=t8 > t8.bin   # end-to-end stub-NOP hash
```

Trade-off: slightly larger source per binary but eliminates duplicated
link recipes. Mirrors Phase 2b's generator shape (one binary per
phase, multiple test modes inside). Two binaries was the alternative;
single binary chosen for CMake-surface minimization.

**Linked source files (full enumeration, ~17 impl + ~15 headers,
verified against `aaafe71` fork pin):**

| Subsystem | Implementation files | Headers |
|-----------|----------------------|---------|
| Argon2d | `argon2_ref.c`, `argon2_ssse3.c`, `argon2_avx2.c`, `argon2_core.c` | `argon2.h`, `argon2_core.h`, `blamka-round-*.h` |
| Blake2b | `blake2/blake2b.c` | `blake2/blake2.h`, `blake2/blake2-impl.h`, `blake2/endian.h` |
| Blake2Generator | `blake2_generator.cpp` | `blake2_generator.hpp` |
| Superscalar | `superscalar.cpp` | `superscalar.hpp`, `superscalar_program.hpp`, `program.hpp`, `instruction_weights.hpp` |
| Cache + dataset | `dataset.cpp`, `allocator.cpp` | `dataset.hpp`, `allocator.hpp`, `virtual_memory.h` |
| AES | `aes_hash.cpp` | `aes_hash.hpp`, `soft_aes.h` |
| VM substrate | `virtual_machine.cpp`, `vm_interpreted.cpp`, `vm_interpreted_light.cpp`, `bytecode_machine.cpp` | `virtual_machine.hpp`, `vm_interpreted.hpp`, `vm_interpreted_light.hpp`, `bytecode_machine.hpp` |
| Instructions | `instruction.cpp`, `instructions_portable.cpp` | `instruction.hpp` |
| Reciprocal | `reciprocal.c` | `reciprocal.h` |
| Common | (header-only) | `common.hpp`, `configuration.h`, `intrin_portable.h` |

Generator-side glue (~200 LoC C++ + ~200-250 LoC CMake): orchestrates
T1–T8 generation. For T5 (program parse from entropy) uses the real
program-init path (`fillAes4Rx4` from entropy → 2048-instruction
Program). For T8 (end-to-end stub-NOP hash) constructs a literal-NOP
Program directly (2048 `randomx::Instruction` slots with `opcode =
InstructionType::NOP`, all other fields = 0) — no upstream patch to
`bytecode_machine.cpp::compileProgram`.

**Reviewer calibration note (lands in `_generator/README.md`):**
"Generator's build is a one-time `make` invocation per this
README; reviewers do not need to read the linked `.cpp` files —
those are unchanged fork reference at pin `aaafe71`. Review surface
is the ~200 LoC of glue (`gen.cpp`) + ~200-250 LoC of CMake
(`CMakeLists.txt`) + the `.meta.txt` provenance file documenting
the link recipe. The fork files are linked-against, not modified."

**Scope budget.** ~1-1.5 days of plumbing work. Bounded; not a
blocker.

### 5.7 F7 — Sub-test surface: T1–T8 matrix with FP rounding-mode invariant

**Problem.** Without enumeration, 2c's test surface is "single
end-to-end hash" — too coarse to bisect failures. The plan doc needs
a per-component test matrix.

**Disposition.** Eight named tests (one per `tests/cache/*.rs` or
`tests/vm/*.rs` file). Each test compares a Rust-produced fingerprint
to a generator-produced reference vector (`tests/vectors/reference/{cache,vm}/tN.bin`).

| ID | Tests | Input | Output fingerprint | FP rounding-mode invariant |
|----|-------|-------|--------------------|----------------------------|
| T1 | Cache derivation | seedhash (32 bytes) | SHA256(Cache.blocks bytes ‖ serialized 8 SuperscalarHash programs) | N/A — no FP arithmetic in cache derivation |
| T2 | `cache.derive_item` | seedhash, item_number (8 inputs: 0, 1, 1023, 1024, 524287, 524288, 2097150, 2097151) | concatenated 8 × 64-byte dataset items | N/A — derive_item is integer-only arithmetic + cache reads |
| T3 | Scratchpad init via `fillAes1Rx4` | entropy buffer (256 bytes from synthetic seedhash) | SHA256(scratchpad bytes after `fillAes1Rx4` init) | N/A — integer AES |
| T4 | Register init from entropy | entropy buffer (256 bytes) | NativeRegisterFile snapshot (8 × u64 integers + 4 × `[f64; 2]` FP + 4 × `[f64; 2]` E + 4 × `[f64; 2]` A) | **Invariant: FP values are bit-exact reinterpretations via `getSmallPositiveFloatBits` (purely bitwise, no FPU). Rounding-mode-insensitive by construction.** |
| T5 | Program parse from entropy | entropy buffer (16 KB from `fillAes4Rx4`) | Parsed `Program` structure (2048 `Instruction { opcode, dst, src, mod_, imm32 }` records, serialized canonically) | N/A — program parse is integer-only |
| T6 | spAddr0/1 derivation per iteration | per-iteration register state (4 iterations chosen to cover the four `readReg0`/`readReg1` combinations) | `(spAddr0, spAddr1)` pairs for first 4 iterations | N/A — integer arithmetic |
| T7 | F/E AES mix per iteration | per-iteration register state (4 iterations) | Post-mix register snapshot (integer registers updated, FP registers untouched in stub-NOP land) | **Invariant: FP register values stay at their bit-deterministic init values throughout because no FP arithmetic executes under stub-NOP dispatch. The F/E AES mix is integer AES on scratchpad data. Rounding-mode-insensitive by construction.** |
| T8 | End-to-end stub-NOP hash | seedhash + data buffer | Final 256-bit Blake2b hash | **Invariant: FP register values flow through register init (bit-exact) → never modified (stub-NOP) → serialized into `hashAes1Rx4` finalization. Final hash bytes are insensitive to host rounding mode.** |

**T4/T7/T8 FP rounding-mode invariant (carried forward to 2d).** The
invariant survives into 2d as a forward-pointer: when 2d's bytecode
dispatch lands and FADD_R/FSUB_R/FMUL_R/FDIV_M/FSQRT_R execute, the
2d author must either (a) re-verify the invariant under each test's
specific input space, or (b) constrain T4/T7/T8 inputs to IEEE 754
exact-integer-representation range (integers ≤ 2^53) so all FP
operations produce identical results regardless of rounding mode.
The 2d plan doc must address this when it lands.

**Test placement.** T1, T2 live in `tests/cache/*.rs` files (one file
per test ID). T3–T8 live in `tests/vm/*.rs` files. Mirrors Phase 2b's
per-primitive test-file convention.

### 5.8 F8 — Benchmark strategy

**Problem.** Phase 0 budgets are `≤200 ms` cache-derive and `≤100 µs`
Vm-alloc. 2c needs measurement infrastructure to validate the
budgets and record a baseline for downstream phases.

**Disposition.**

1. **PR gate (absolute threshold).** Two criterion benches:
   - `benches/cache_derive.rs` — measures `Cache::derive(&KEY)`
     median latency over N=100 iterations on a fixed seedhash.
     **PR fails if median > 200 ms.**
   - `benches/compute_hash_alloc.rs` — measures `compute_hash(
     &cache, &SEEDHASH, &DATA)` median latency over N=10000
     iterations with a pre-derived `Cache`. Under stub-NOP dispatch
     (Phase 2c), the per-call cost is dominated by `VmState`
     allocation + scratchpad zeroing + program init + the
     iteration-loop overhead (no per-instruction work). **PR fails
     if median > 100 µs.** Once Phase 2d's real dispatch lands, this
     bench's per-call cost grows by the per-iteration dispatch cost;
     the 100 µs budget continues to bound the allocation portion
     specifically — Phase 2d's plan doc may split the bench into
     allocation-only vs. execution-only sub-benches if precision
     becomes load-bearing. Mechanism for measuring just the
     allocation portion (e.g., `#[doc(hidden)] pub fn _bench_vm_state_alloc()`
     bench hook vs. end-to-end `compute_hash` measurement) is an
     implementation-PR-time decision; the plan-doc-time disposition
     is "measure end-to-end under stub-NOP; budget binds the
     allocation portion."

2. **Baseline artifact.** Commit `rust/shekyl-pow-randomx/BENCH_RESULTS.md`
   at PR-merge with measured medians + run conditions (CPU model,
   OS, libc allocator, kernel version, wall-clock date, criterion
   version). Downstream phases (2d, 2f, 2g) compare against this
   baseline; regression > 10% triggers investigation, not auto-
   failure (which is Phase 0's absolute-threshold check above).

3. **Per-hash benchmark deferred to 2g.** The ≤3.0× ratio against
   C reference needs the differential harness 2g produces. Per-hash
   benchmark placement: `rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs`
   (or equivalent under 2g's test-only artifact). Cadence:
   release-gate suite (not per-PR), per parent plan's release-gate-
   vs-per-PR-CI split. The 2c plan doc records this deferral
   explicitly so a 2c reviewer doesn't ask "why no 3.0× check?"

**Bench environment.** Both 2c benches run on the PR author's
local hardware first (developer-loop), then in CI on the
`Rust: audit, test, determinism` job (shared with 2b's bench
infrastructure). CI threshold check is informational at this
phase; absolute-threshold check is the PR gate.

### 5.9 F9 — Cache lands in 2c (covered by §5.4) + R2-D3 visibility correction

Per the F4-absorbed disposition above, `Cache` lands in 2c with the
following visibilities:

| Method | Visibility | Purpose |
|--------|-----------|---------|
| `Cache::derive(seedhash: &[u8; 32]) -> Cache` | `pub fn` | Production constructor for FFI consumers (called via `compute_hash`'s callers; eventually wrapped by 2f's `CacheStore`). |
| `Cache::from_raw(bytes: Vec<u8>) -> Cache` | **`pub(crate) fn`** | **Test-time construction only.** Spec-vector tests hand-roll `Cache` values from generator-produced byte arrays to bypass derivation overhead in `derive_item` tests. **Not** an FFI surface — FFI consumers call `compute_hash` which calls `Cache::derive` internally. |
| `Cache::derive_item(item_number: u64) -> [u8; 64]` | `pub(crate) fn` | Internal helper consumed by `VmState::run` (the per-iteration dataset-item read). Not part of the public crate surface; if a future caller needs it, the visibility-promotion is a documented 2-line change. |
| `Cache::item_bytes(item_number: u64) -> [u8; 64]` | `pub(crate) fn` | Helper accessor for the byte-level indexing into `Cache.blocks` (F4-detail-A). Internal to `cache.rs`. |

**Round 2 visibility correction (R2-D3).** Round 1's first-draft
plan described `from_raw` as "the public byte-array constructor for
FFI consumers." This phrasing was a holdover from F9's original
framing before F4-absorbed dissolved the dataset-reader abstraction.
The actual consumer of `from_raw` is the test corpus, not the FFI
surface. The correction tightens the surface area: one fewer `pub`
on the crate's public boundary; one fewer thing a reviewer has to
audit as "is this safe for FFI consumers?" The visibility-promotion
escape hatch (pub(crate) → pub) remains a documented future-action
if a real FFI consumer demands it; until then, the default is the
tighter visibility.

### 5.10 ShekylU128 audit (mechanical action item from F3)

**Audit task.** Per F3's framing, audit 2c's surface for any
`u128` occurrences that should translate to `ShekylU128`.

**Audit result.** The only `u128` occurrence in 2c-adjacent code is
the `mulh()` helper in `rust/shekyl-pow-randomx/src/superscalar.rs:1486`:

```rust
fn mulh(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) >> 64) as u64
}
```

This is a **Rust-language intermediate** for computing the high 64
bits of a 64×64 multiply (IMULH_R semantics). The function takes
`u64` and returns `u64`; `u128` is purely the widening type for
`>> 64`. It is **not** a data type crossing any interface.

**Translation disposition: no.** Translating to `ShekylU128` would:

1. Force ABI machinery into an internal arithmetic helper (no
   call-site benefit).
2. Break the autovectorization story by foreclosing the
   64×64-with-128-bit-intermediate pattern LLVM recognizes.
3. Reverse the workspace dependency direction (per F3's structural
   disqualifier #2).

**Test corpus gap analysis.** The path from RandomX hash → difficulty
comparison uses `u64::from_le_bytes(hash[24..32])` × `difficulty`
→ `u128` check `<= 2^64`. That check lives in `shekyl-difficulty`'s
hash-below-difficulty function or in C++ glue, **not** in
`shekyl-pow-randomx`. The RandomX side produces bytes (`[u8; 32]`),
not integers; the integer interpretation happens at the consumer.
**No 2c-surface test corpus gap.** Phase 3's FFI integration tests
exercise the hash → difficulty path via `shekyl-difficulty`'s test
suite; 2c is not the right place to add a test for that path.

**Audit closure.** Recorded here; no action.

## 5.11 Threat-model findings (Round 4)

Round 4 closed 2026-05-21. A priority-1 (per `00-mission.mdc`)
adversarial review of the Round 3 plan-doc enumerated six attack
objectives against the Phase 2c surface; each objective surfaced
findings whose disposition is recorded below. The framing names
each finding as either **(a) 2c-implementation-PR scope expansion**
(work that the Phase 2c implementation PR absorbs), **(b) plan-doc
discipline note** (no implementation impact; a scope-or-discipline
boundary recorded for future maintainers), or **(c) forward-action
to a downstream phase** (work that 2d, 2f, 2g, or 3a inherits).

The six attack objectives, with the findings and their dispositions,
follow. Cross-cutting recommendations are §5.11.1 through §5.11.8.

| Objective | Attack surface | Dispositions in §5.11 |
|-----------|---------------|------------------------|
| 1. Mine valid blocks faster than honest miners | Differential between Rust verifier and C miner | §5.11.5 (2g adversarial corpus); §5.11.8 (audit-against-source discipline) |
| 2. Poison the cache | `Cache::derive` / `derive_item` determinism | §5.11.1 (T1' / T2' determinism property tests, in-scope) |
| 3. Exploit the FFI boundary | `compute_hash` → `shekyl_pow_randomx_v2_hash` | §5.11.6 (3a forward-actions: null-check + length-validation + seedhash-as-`[u8; 32]` ptr + ERR_NULL_PTR taxonomy) |
| 4. Cause the verifier to consume excessive resources | Cache-derivation DoS; scratchpad allocation pressure; pathological programs | §5.11.5 (2g pathological-program timing); §5.11.7 (2f CacheStore eviction-protection + VmState pool capacity sizing) |
| 5. Exploit Rust safety boundary gaps | `Box::new_zeroed_slice` size correctness; 2d's FPU rounding-mode unsafe carve-out | §5.11.2 (`debug_assert!` discipline, in-scope); §5.11.4 (public-input-only scope note); 2d skeleton §3.1 augmentation |
| 6. Cause consensus split via implementation divergence | Rust-vs-C edge-case behaviors (u128 / FP NaN / debug-vs-release / `mp`-style transcription errors) | §5.11.3 (debug-vs-release equivalence, in-scope); §5.11.8 (discipline note); 2d skeleton §4.1 (u128 vs `__int128`) |

### 5.11.1 Determinism property tests (T1' + T2')

**Problem.** T1 (cache derivation) and T2 (`cache.derive_item`) in
the F7 matrix each compare a single Rust output to a single
generator-produced reference vector. A single-comparison test
catches deterministic bugs in `Cache::derive` / `derive_item`, but
misses non-determinism bugs (race conditions in the 8-program
SuperscalarHash generation, allocator-dependent ordering effects,
hidden state inside the `Cache` struct that leaks across `derive_item`
calls). Non-determinism in cache derivation is a **consensus-split
attack surface**: validators producing different caches from the
same seedhash reach different acceptance decisions on the same
block.

**Disposition.** Add two property-shaped sibling tests to commits 2
and 3 respectively:

- **T1' — `Cache::derive` determinism property** (commit 2; ~30 LoC):
  - **T1'a (single-thread loop)**: Run `Cache::derive(SAME_SEEDHASH)`
    100 times sequentially; assert every output is byte-identical to
    every other output (and to T1's reference vector). Catches hidden
    state inside the `Cache` struct, allocator-dependent layout, and
    any state-mutating shortcut that affects byte output.
  - **T1'b (concurrent threads)**: Spawn 4 threads, each running
    `Cache::derive(SAME_SEEDHASH)` 25 times; collect 100 outputs;
    assert all byte-identical. Catches races in the 8-program
    SuperscalarHash generation or in Argon2d block initialization
    if any per-call mutable state slipped in.
  - **T1'c (interleaved seedhash pattern)**: Run
    `derive(A), derive(B), derive(C), derive(A), derive(D), derive(A)`;
    assert all three `derive(A)` outputs are byte-identical and
    match T1's reference. Catches cross-call state pollution (e.g.,
    a thread-local buffer that doesn't get reset between calls).
- **T2' — `Cache::derive_item` invariance property** (commit 3; ~30 LoC):
  - **T2'a (same item_number, varied call order)**: For each of T2's
    8 item_numbers, call `derive_item(N)` 10 times in varying
    intervening-call patterns (e.g., `derive_item(N), derive_item(N+1),
    derive_item(N), derive_item(N+2), derive_item(N)`); assert every
    return for `N` is byte-identical to T2's reference vector. Catches
    any cross-call state pollution inside `derive_item` (e.g., a
    `&mut [u64; 8]` register buffer reused without reset).

**Test placement.** T1' lives in `tests/cache/t1_prime_determinism.rs`
(sibling to `tests/cache/t1_cache_derive.rs`); T2' lives in
`tests/cache/t2_prime_invariance.rs`. Both are CI-gated; failure
fails the PR.

**Cost.** ~60 LoC of test code total. No new dependencies (uses
`std::thread::scope` for T1'b). Negligible CI time (≤2 s wall;
single-thread `Cache::derive` is the cost dominator and runs
serially in T1'a regardless).

**Reopening criterion (reversion-clause shape).** If T1' or T2' ever
fails, the disposition is **NOT** "remove the property test as
flaky" — that's the failure mode `16-architectural-inheritance.mdc`'s
"audits-are-clean-so-compress" anti-pattern warns against. The
disposition is "find the non-determinism source and remove it." The
property test stays.

### 5.11.2 `debug_assert!` discipline for unsafe allocation sites

**Problem.** Phase 2c's two carve-outs from `#![deny(unsafe_code)]`
are `Box::new_zeroed_slice` calls (one in `Cache::derive` for the
~256 MB cache buffer; one in `VmState::new` for the 2 MB scratchpad).
Each call is followed by `assume_init_slice` (or equivalent) that
trusts the allocation size matches `CACHE_SIZE` / `SCRATCHPAD_L3`.
If a future refactor drifts the size constant in one place without
updating the unsafe site (e.g., `RANDOMX_CACHE_SIZE` changes but the
`Box::new_zeroed_slice(2 * 1024 * 1024)` literal stays the same),
the allocated buffer's actual length disagrees with downstream code's
indexing expectations. Downstream indexing reads past the actual
allocation. Subtle, not caught by `cargo test` if the indexing
happens to stay in-bounds of the wrong-but-still-allocated region.

**Disposition.** Each `Box::new_zeroed_slice` site gains a
`debug_assert_eq!(allocation.len(), EXPECTED_SIZE)` immediately after
`assume_init_slice` (or the equivalent `MaybeUninit::assume_init`
shape that 2c's implementation actually uses), before any indexing.
`EXPECTED_SIZE` is the same constant the `Box::new_zeroed_slice` call
used (so the assertion fires only if the constant is drifted in one
place without the other). In debug builds this catches size-constant
drift in CI; in release builds (production) the assertion compiles
out, so there is no per-call overhead.

The `// SAFETY:` doc-comment template for both sites carries the
discipline as a required item:

```rust
// SAFETY:
// - <reason the allocation+assume_init pair is sound>
// - Size invariant: `allocation.len() == EXPECTED_SIZE` per the
//   `debug_assert_eq!` immediately below; in release builds this
//   assertion compiles out, leaving the wrap zero-overhead, but in
//   debug builds (CI) it catches size-constant drift before any
//   indexing reads past the actual allocation.
let allocation = unsafe { ... };
debug_assert_eq!(allocation.len(), EXPECTED_SIZE);
```

**Cost.** ~5 LoC per site × 2 sites = ~10 LoC; absorbed into commit 2
(cache site) and commit 4 (scratchpad site).

**Reopening criterion.** If a future contributor argues for removing
the `debug_assert!` because "we have other tests that would catch
the bug," the reopening criterion is whether those other tests
actually exercise the size-drift path (typically they don't — the
T1–T8 corpus uses the same constants the allocation does, so a
drift that affects both equally is invisible). Per
`16-architectural-inheritance.mdc`'s "audits-are-clean-so-compress"
anti-pattern, the discipline doesn't get to coast.

### 5.11.3 Debug-vs-release equivalence as PR gate

**Problem.** Rust's integer-overflow behavior differs between debug
(panic) and release (two's-complement wrap). The verifier ships
release. If a future maintainer runs `cargo test` in debug mode and
sees green, but the release build of the same code produces a
different hash for some input, the maintainer's local validation
disagrees with what ships. This is a class of consensus-split bug
that's invisible to default `cargo test`.

The mechanism is mechanical: 2c contains integer arithmetic in
`Cache::derive_item`'s superscalar-hash chain (8 × 8-register
`u64` programs) and in the `dispatch_instruction` body's eventual
2d integer opcodes. Any wrapping arithmetic that uses Rust's
`wrapping_*` methods is consistent across profiles; any arithmetic
that uses `+` / `*` directly will panic in debug and wrap in
release on the same overflow input. If 2c's code accidentally uses
`+` where it should use `wrapping_add`, the bug is invisible until
the release build hits a real-world overflow input.

**Disposition.** The 2c implementation PR's `cargo test` invocation
in CI runs both `cargo test -p shekyl-pow-randomx --all-features`
(debug) **and** `cargo test -p shekyl-pow-randomx --all-features
--release` (release). The release run asserts identical T1–T8
outputs to the debug run (they share the same reference vectors;
both must pass byte-equality against the generator output). Any
divergence between profiles fails the PR.

CI workflow line addition (~1 line in the existing
`Rust: audit, test, determinism` workflow). The release build
takes longer than debug, but compilation is already incremental
across the workflow steps, so the cost is bounded by ~30 s additional
wall time per CI run. Acceptable for the security property gained.

**Cost.** 1 line in the CI workflow file. The 2c implementation PR
adds it as part of the in-file-discipline exception (the workflow
file is already edited for Phase 2c reasons; the additional line
fits the exception).

**Reopening criterion.** If CI infrastructure ever moves to a
release-only test pipeline (e.g., a future "all tests run release
by default" workflow change), the debug-vs-release gate becomes
redundant in that pipeline. At that point the disposition is to
either (a) keep the explicit dual run for the security property
(debug catches integer-overflow panics that release silently
wraps), or (b) document the change in the plan doc and accept the
reduction. Don't silently drop the gate.

### 5.11.4 Public-input-only scope note

**Problem.** RandomX `compute_hash` operates on public inputs
(seedhash + block-header bytes). Allocator-pressure patterns (e.g.,
the cache-line residency of the scratchpad after a given execution
path) could in principle leak information about input distributions
through cache-line timing. For public-input use, this is not a
threat — the inputs are already public. For hypothetical future
secret-input use (e.g., a wallet hashing private material with a
RandomX-shaped construction), it would be a threat.

**Disposition.** Add a scope-bounding note to `cache.rs` and `vm.rs`
crate-level doc-comments stating:

> This crate is designed for public-input verification (block PoW).
> Secret-input use would require a separate threat model addressing
> allocator-pressure side channels, scratchpad cache-line residency,
> and per-iteration timing variance. No current or planned consumer
> uses this crate with secret material.

**Cost.** ~6 lines of doc-comment. No code change.

**Reopening criterion.** If a future consumer proposes using
`shekyl-pow-randomx` with secret material (a wallet KDF, a
ProofOfWork-shaped commitment scheme over private inputs, etc.),
the reopening criterion is "draft a separate threat model addressing
the side-channel surfaces this crate's design did not consider."
Per `21-reversion-clause-discipline.mdc`, this is a substrate-shift
trigger (consumer class changes), not a preference-trigger.

### 5.11.5 Forward-actions to Phase 2g (adversarial corpus + worst-case timing)

The Phase 2g differential harness corpus is a sampled set of
`(seedhash, data)` inputs; sampling catches statistically-common
bugs but misses adversarially-crafted inputs. Two forward-actions:

- **Adversarial seedhash corpus**: 2g selects 5–10 seedhashes
  specifically chosen to produce programs that exercise rare paths:
  programs heavy in CFROUND (per-iteration rounding-mode thrash),
  heavy in FDIV_M (per-iteration FP division with mask), heavy in
  cache-miss-shaped scratchpad access patterns, heavy in CBRANCH
  (branch-misprediction-shaped dispatch). The corpus runs the T1–T8
  matrix (and 2d's T9+ per-opcode tests) plus the differential
  harness against each adversarial seedhash. Assertions: byte-equality
  against C reference per (seedhash, data) pair; per-hash latency
  within budget (see worst-case bound below) for each pair.
- **Pathological-program worst-case timing bound**: Phase 0's ≤3.0×
  C-reference per-hash budget is an average across benign inputs.
  2g adds a worst-case bound (parent plan §6 carries the constant;
  Round 4 sibling commit lands the constant) tested against the
  adversarial corpus. If the worst case exceeds the bound, the
  verifier can be CPU-DoS'd by miners grinding seedhashes to find
  pathological programs.

The 2g plan-doc (when drafted) carries these forward-actions
verbatim and selects the specific seedhash corpus. The criteria for
"this seedhash is adversarial enough to include" are part of 2g's
Round 1.

### 5.11.6 Forward-actions to Phase 3a (FFI boundary hardening)

Phase 3a wires `shekyl-ffi::shekyl_pow_randomx_v2_hash` over
`shekyl-pow-randomx::compute_hash` per the §13 R3-minor-1 FFI
layering note. Round 4 expands that note with three FFI-boundary
hardening forward-actions:

- **Null-pointer validation**: the FFI shim explicitly checks
  `seedhash`, `data`, and `out` for null before constructing slices
  or dereferencing. Even `slice::from_raw_parts(ptr::null(), 0)` is
  UB in Rust, so the check is mandatory regardless of length. Null
  on any of the three pointers translates to **`ERR_NULL_PTR
  (-1)`** per the parent plan's FFI error taxonomy (`RANDOMX_V2_PLAN.md`
  Phase 0 §5 + `RANDOMX_V2_RUST.md` §7's
  `SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR` constant). The LWMA-1 FFI
  precedent has the same shape and is the template.
- **Length validation against a published maximum**: `data_len` is
  validated against `RANDOMX_BLOCK_TEMPLATE_MAX_SIZE` (parent plan
  §5 Round 4 + Round 5 cross-check pins the constant at 2 MiB). If
  `data_len > MAX`, the FFI shim returns **`ERR_DATA_TOO_LARGE
  (-2)`** per the parent plan's FFI error taxonomy
  (`RANDOMX_V2_PLAN.md` Phase 0 §5 + `RANDOMX_V2_RUST.md` §7's
  `SHEKYL_POW_RANDOMX_V2_ERR_DATA_TOO_LARGE` constant) without
  constructing the slice. The check defends against a hostile C++
  caller passing `data_len` that overruns the actual buffer; even
  though the C++ side is the trust boundary in principle, defense-in-depth
  at the FFI shim is the discipline.
- **`seedhash` as typed-array pointer**: the FFI signature is
  `seedhash: *const [u8; 32]` (a pointer to a typed array) rather
  than `seedhash: *const u8` (an untyped pointer relying on
  documentation to claim 32-byte length). The type system enforces
  the length at the shim's compile time, eliminating the class of
  bugs where a caller passes a shorter buffer and Rust reads past
  the end.

All three are 3a-implementation-time discipline notes; the parent
plan §5 Round 4 amendment pins the `RANDOMX_BLOCK_TEMPLATE_MAX_SIZE`
constant value and the full `ERR_NULL_PTR (-1)` / `ERR_DATA_TOO_LARGE
(-2)` taxonomy (per `RANDOMX_V2_RUST.md` §7's C-header
`SHEKYL_POW_RANDOMX_V2_*` constants) so 3a doesn't re-litigate them.
This plan-doc's references to those constants use the parent-plan
spelling and numeric values verbatim (no alternative spellings,
no placeholder values) so Phase 3a's enum doesn't have to reconcile
two competing taxonomies at implementation time.

### 5.11.7 Forward-actions to Phase 2f (CacheStore + VmState pool)

Two forward-actions sized for the 2f plan doc:

- **CacheStore canonical-slot eviction-protection**: Decision #6's
  capacity-2 LRU `CacheStore` is small enough that an attacker who
  can submit alt-chain block headers with novel seedhashes can flush
  the canonical-seedhash slot with a 3-seedhash interleave, forcing
  ~150-200 ms of cache re-derivation per attack block. The forward-
  action: the canonical-seedhash slot (the seedhash for the current
  chain tip's epoch) is **sticky** — it is not subject to LRU
  eviction; only the secondary slot churns under attacker-induced
  pressure. The 2f plan doc Round 1 enumerates the mechanism
  (explicit "pinned slot" + "transient slot" rather than
  capacity-2 LRU; or capacity-2 LRU with a `pin(seedhash)` API the
  daemon calls when it learns a new canonical seedhash). Parent
  plan Decision #6 Round 4 carries the disposition note.
- **`VmState` pool capacity sized against daemon parallel-verification
  fanout**: Decision #7 (Round 2 substrate-shift form) makes
  `VmState` pooling internal to `compute_hash`. If 2f's benchmarks
  show pooling is needed, the pool's capacity must be sized against
  the daemon's actual parallel-verification fanout (alt-chain branch
  validation runs in parallel; mempool tx verification runs in
  parallel). An arbitrarily-chosen capacity either under-provisions
  (pool exhaustion forces per-call allocation, defeating the pool)
  or over-provisions (memory waste). The 2f plan doc Round 1
  enumerates the daemon's actual parallel-verification fanout (via
  a daemon-side code survey or runtime measurement) and sizes the
  pool accordingly. Parent plan Decision #7 Round 4 carries the
  discipline note.

### 5.11.8 Audit-against-actual-code discipline (mp-correction validation)

**Observation.** Round 3's `VmState` field-set audit (§5.1.1) caught
one correction-from-prompt finding: the earlier `mp` row in the
field-set table was speculative (transcribed from an expected-behavior
prompt), and the audit against `vm_interpreted.cpp` and `common.hpp`
revealed `mp` is a v2-only local-variable alias for `mem.ma`, not a
struct field. The discipline that found it — **audit-against-actual-
code, not against documentation or prompted lists** — is the
discipline that prevents the same class of bug shipping as a
consensus-split source.

Had the Rust port shipped `state.mp: u32` synced to `state.ma`, the
verifier might have produced subtly different behavior in some
opcode path that read `mp` directly vs. reading `ma` — exactly the
shape of Objective 6 (consensus split via implementation divergence).
The bug would have been invisible to T1–T8 (which test structural
correctness against generator output; the generator would have used
`mem.ma` everywhere, matching the C reference, and the Rust port's
`state.mp` divergence would have flowed through the F/E AES mix
silently). It would have surfaced only as a chain split between
Rust verifiers and C miners on inputs where the divergent code path
fired.

**Disposition (discipline note, not in-scope).** The audit-against-
source discipline is the operational form of Round 4 against
Objective 6. For every `VmState` field, `Instruction` field,
`Cache` accessor, and `compute_hash` operation in 2c's
implementation PR, the reviewer's check is:

> Is this field/operation present in the C reference at the pinned
> commit? Does its semantic match the C reference's? Or is it a
> prompted-list speculation that drifted from the reference?

The §5.1.1 audit-grep command (`grep -nE 'static void exe_'
external/randomx-v2/src/bytecode_machine.hpp`) is the operational
form for the bytecode dispatch surface; the Round 4 expansion is to
apply the same discipline at every other 2c surface (Cache
construction, scratchpad init, register init, F/E AES mix,
finalization). The discipline is not "trust the plan doc's tables"
— the plan doc's tables are the audit's output; the audit's input
is the C reference source.

**Forward propagation.** 2d's §1.3 audit re-verification (per
`RANDOMX_V2_PHASE2D_PLAN.md` §1) carries the discipline forward to
the dispatch surface; 2g's differential harness is the eventual
empirical check (byte-equality against the C reference for both
sampled and adversarial inputs). The discipline applies at each
PR's design time; 2g's harness is the safety net for cases where
the plan-doc-time discipline missed something.

**Round 5 framing amendment — "the audit's value is in the
reading-the-source step, not the producing-a-table step."** The mp
correction is the precedent that proves the discipline. The lesson
is *not* "we caught one bug." The lesson is that **an audit that
just confirms a prompted-list table is the failure mode
`16-architectural-inheritance.mdc`'s "audits-are-clean-so-compress"
anti-pattern names** — the table is the audit's output; the audit's
substance is in the line-by-line reading of the C reference that
*produces* the table. A contributor who skips the reading-the-source
step and generates a table from prompted intuition reintroduces the
consensus-split-via-divergence failure mode (Objective 6) exactly
as the pre-correction Rounds 1–2 tables had `mp` wrong: the table
existed, it looked plausible, it was wrong, and no audit happened
because "audit" meant "look at the prompted summary," not "open
`vm_interpreted.cpp` and read."

**Enforcement: show your work.** Every audit table in the plan-doc
(`§5.1.1` `VmState` field set; `§5.5 F5` v2-only simplification
table; the eventual `§3.4` `u128`/`__int128_t` edge-case audit in
the 2d skeleton; the eventual `§7.1` opcode-handler audit in 2d's
Round 1 plan-doc) **cites line ranges in the C reference at the
pinned fork commit.** Format:

| Subject | C reference cite | Disposition |
|---------|------------------|-------------|
| (field/opcode/path) | (file `path/to/source.{cpp,hpp,h}:N–M`) | (audit-derived disposition) |

The line-range citations are the audit's evidence-trail. A reviewer
spot-checks by opening the cited file at the pinned commit and
reading the named lines; if the citation matches the disposition,
the row is confirmed. If the cited lines don't contain what the
disposition claims, the row fails and the audit is rejected
regardless of how plausible the rest of the table looks. This is
the same shape as `30-cryptography.mdc`'s constant-time-or-explicit-
rejection rule: absence of the citation is a claim that no
citation is needed, and the burden of that claim is the audit
table's author's, not the reviewer's.

The discipline's recurrence-pattern protection is the same as the
`mp` precedent: future contributors who attempt to land an audit
table without line-range citations are asking for the "table looks
plausible, audit didn't happen" failure mode. Catching this at
PR-review-time prevents the consensus-split-source bug from
shipping. The §5.1.1 audit-grep command is the operational form
that pre-fills the cite column; the reviewer's spot-check is the
operational form of confirming the auditor read what the citation
claims.

**No new code; no plan-doc change beyond this section.** The
discipline already exists; this section names it explicitly so 2d/2g
PRs inherit it as a discipline note rather than as a precedent the
authors have to re-derive. The Round 5 amendment names the
*reading-the-source* step as load-bearing — distinct from the
table-existing step — so future audit-table authors don't optimize
toward the visible artifact at the expense of the invisible
discipline.

## 6. Test strategy

Eight named spec-vector tests per the F7 matrix above. Each test:

1. Reads its reference vector from `tests/vectors/reference/{cache,vm}/tN.bin`.
2. Runs the Rust path (cache derive, derive_item, scratchpad init,
   register init, program parse, spAddr derivation, AES mix, or
   end-to-end stub-NOP hash).
3. Asserts byte equality.

The reference vectors are produced by the F6 generator (single binary
with CLI flag). Generator output is checked in at
`tests/vectors/reference/{cache,vm}/tN.bin` with a `.meta.txt`
companion documenting the seedhash, parameters, and link recipe.

Plus per-component unit tests inside `cache.rs` and `vm.rs` for
internal invariants (cache memory size, scratchpad size, program
size, register count, dataset-item byte offset arithmetic). These
are coarse functional tests, not spec-vector parity — they catch
implementation-side bugs that the spec-vectors would only catch via
the full T1–T8 run.

**Round 4 additions — determinism property tests (§5.11.1).** Two
sibling tests extend the T1/T2 spec-vector coverage with
non-determinism-detecting properties:

- **T1' (`tests/cache/t1_prime_determinism.rs`)**: three sub-tests
  exercising single-thread loop (100 iterations), concurrent
  threads (4 × 25), and interleaved seedhash patterns; all assert
  byte-identity across runs and against T1's reference vector.
- **T2' (`tests/cache/t2_prime_invariance.rs`)**: one sub-test per
  item_number in T2's 8-input set; each runs 10 interleaved
  `derive_item` calls per item_number with varying intervening
  calls; asserts byte-identity across runs and against T2's
  reference vector.

T1' and T2' are CI-gated. Failure fails the PR. They sit alongside
T1/T2 in `tests/cache/`; both file naming and `cargo test` discovery
respect the per-test-file convention from Phase 2b.

**Round 4 additions — debug-vs-release equivalence (§5.11.3).** The
CI workflow runs both debug (`cargo test`) and release
(`cargo test --release`) profiles of the T1–T8 corpus (plus T1'/T2')
and asserts byte-identity between profiles. Any divergence fails the
PR. This catches integer-overflow-semantics drift between profiles
(Rust panics in debug, wraps in release) that default `cargo test`
would silently let ship in release builds.

## 7. Reference-vector generator (F6 details)

Per F6's disposition: single binary with CLI flag, linked against
~17 implementation files + ~15 transitive headers (see F5 table).
Lives at:

```text
rust/shekyl-pow-randomx/tests/vectors/reference/_generator/phase2c/
├── CMakeLists.txt        # ~200-250 LoC; links the randomx-v2 substrate
├── gen.cpp               # ~200 LoC; T1–T8 entry points + main() dispatch
├── README.md             # build instructions + reviewer calibration note
└── .meta.txt             # fork pin (aaafe71) + linked-file enumeration
```

The phase2c subdirectory mirrors Phase 2b's `phase2b/` convention.
Generator output drops into `tests/vectors/reference/cache/tN.bin`
and `tests/vectors/reference/vm/tN.bin`.

**Provenance discipline.** `.meta.txt` records the fork pin commit,
each linked file path, the build command (`cmake .. && make` or
similar), and the SHA256 of each `.bin` file. Implementation-PR-time
CI grep validates that `.meta.txt`'s fork pin matches
`external/randomx-v2/`'s actual pin.

## 8. Benchmark strategy

Per F8's disposition: two PR-gated benches plus a BENCH_RESULTS.md
baseline; per-hash latency benchmark deferred to 2g.

```text
rust/shekyl-pow-randomx/benches/
├── cache_derive.rs            # criterion bench; ≤200 ms median assertion (Cache::derive)
└── compute_hash_alloc.rs      # criterion bench; ≤100 µs median assertion (per-call compute_hash under stub-NOP dispatch; budget binds the VmState allocation portion)

rust/shekyl-pow-randomx/BENCH_RESULTS.md   # measured medians at PR-merge
```

CHANGELOG entry records the BENCH_RESULTS.md commit so downstream
PRs know to compare against it.

**Per-hash latency placeholder (R3-minor-2).** Phase 2c also lands
a placeholder file at the canonical 2g path:

```text
rust/shekyl-pow-randomx/tests/perf/per_hash_latency.rs   # #[ignore]'d; populated in 2g
```

The placeholder's body:

```rust
//! Phase 2g deliverable: per-hash latency benchmark against the
//! v2 C reference, asserting Rust/C ratio ≤ 3.0× per Phase 0 §8
//! budget. Requires 2g's differential harness binary; landed
//! alongside 2g's other harness infrastructure.
//!
//! Cadence: release-gate suite, not per-PR CI, per parent plan's
//! release-gate vs per-PR split.

#[test]
#[ignore = "Phase 2g deliverable; placeholder per 2c's F8 forward-action"]
fn per_hash_latency_ratio_within_budget() {
    unimplemented!(
        "Phase 2g lands this; see RANDOMX_V2_PHASE2C_PLAN.md §5.8 F8 \
         and §13 forward-path 2g inheritance"
    );
}
```

`#[ignore]` makes `cargo test` skip it (no PR-gate failure);
`unimplemented!()` makes "running it" produce a clear pointer to
where the real work lands. 2g's author finds the placeholder by
grep against its own deliverable name and replaces the body
in-place — same shape as 2c's stub-NOP `dispatch_instruction`
body-replacement, applied to a different cross-phase hand-off.
Per `21-reversion-clause-discipline.mdc`, structural code
out-survives prose discipline; the placeholder is the
out-surviving form.

## 9. Commit granularity

Eight commits, each respecting `06-branching.mdc` and
`90-commits.mdc` (imperative mood, ≤72 chars subject, subsystem
prefix `randomx:`, references the relevant plan-doc section or
finding):

| # | Commit | LoC budget | Section reference |
|---|--------|-----------|-------------------|
| 1 | `randomx: Cache type skeleton + size constants + Drop` | ~80 LoC | §3 module layout, §2 surface 1 |
| 2 | `randomx: Cache::derive + pub(crate) Cache::from_raw + T1 + T1' determinism + cache-site debug_assert!` | ~290 LoC | §5.4, §5.9, §6 T1, §5.11.1 T1', §5.11.2 |
| 3 | `randomx: Cache::derive_item + item_bytes accessor + T2 + T2' invariance` | ~180 LoC | §4.3, §5.4, §6 T2, §5.11.1 T2' |
| 4 | `randomx: VmState skeleton + scratchpad/register-file alloc + scratchpad debug_assert! + Drop` | ~125 LoC | §3, §2 surface 3, §5.11.2 |
| 5 | `randomx: VmState::initialize with register/program init (T3-T5)` | ~180 LoC | §6 T3-T5 |
| 6 | `randomx: compute_hash with dispatch_instruction NOP body + spec vectors (T6-T8)` | ~200 LoC | §5.1, §5.7, §6 T6-T8 |
| 7 | `randomx: Phase 2c reference vector generator (T1-T8)` | ~400 LoC | §5.6, §7 |
| 8 | `randomx: Phase 2c benchmarks + per_hash_latency placeholder + debug-vs-release CI gate + scope-bounding doc-comments + BENCH_RESULTS.md + CHANGELOG` | ~180 LoC | §5.8, §8, §13 forward-path 2g, §5.11.3, §5.11.4 |

Total ≈ 1635 LoC, comfortably below the §"Scope envelope" 1800 LoC
target. The Round 2 collapse (5 vm-side files → 1 vm.rs) shaved
~150 LoC of module-boundary boilerplate vs. Round 1's first-draft
estimate. Commit 8 carries a ~20 LoC bump vs. Round 2's first-draft
to land the R3-minor-2 `tests/perf/per_hash_latency.rs` placeholder
(`#[ignore]` + `unimplemented!()` cross-referencing F8 / §13 2g
inheritance; the deferred-action becomes structural code rather
than plan-doc prose 2g's author has to remember to consult).
Round 4 absorbs ~85 LoC additional across commits 2 (T1' + cache
`debug_assert!`), 3 (T2'), 4 (scratchpad `debug_assert!`), and 8
(debug-vs-release CI line + public-input-only doc-comments).
Generator C++ + CMake (~450 LoC) is separate from the Rust LoC
count.

## 10. Gates

PR-merge gates (CI-enforced):

- `cargo fmt --check` (all Rust passes; rustfmt regression-free per
  Phase 2b's commit 28d9a336f precedent).
- `cargo clippy --workspace --all-targets -- -D warnings`.
- `cargo test -p shekyl-pow-randomx --all-features` (T1–T8 plus
  T1' / T2' plus unit tests all pass under debug profile).
- **`cargo test -p shekyl-pow-randomx --all-features --release`**
  (Round 4 §5.11.3 addition: same T1–T8 / T1' / T2' corpus runs
  under release profile; byte-equality assertions in those tests
  fail the PR if release output diverges from debug output. Catches
  integer-overflow-semantics drift between profiles.)
- `cargo doc -p shekyl-pow-randomx --no-deps` (rustdoc clean).
- `Lint: no debug macros in production Rust` (workflow already in
  CI; zero hits expected).
- **Phase 2c bench thresholds:** `cache_derive` median ≤200 ms;
  `compute_hash_alloc` median ≤100 µs (under stub-NOP dispatch;
  budget binds the `VmState` allocation portion). **Fail → PR blocked.**
- **No new dependencies grep:** `git diff dev rust/Cargo.toml`
  shows no `[workspace.dependencies]` additions.
- **F5 audit grep rerun:** confirm every hit from the F5 audit
  command (§5.5) is either in the F5 table or in a file not linked
  by the Rust port.

## 11. MSRV gate (1.85)

Rust APIs Phase 2c depends on:

- `Box::new_zeroed_slice` — stable since 1.82 ✓
- `std::array::from_fn` — stable since 1.63 ✓
- `u64::from_le_bytes`, `f64::from_bits` — stable since 1.0 ✓
- `core::mem::MaybeUninit::assume_init` — stable since 1.0 ✓

No nightly-only APIs. MSRV stays at 1.85 (no bump).

## 12. Forecast envelope

| Artifact | LoC budget | Notes |
|----------|-----------|-------|
| `src/cache.rs` | ~300 | `pub Cache` + `pub derive` + `pub(crate)` `from_raw`/`derive_item`/`item_bytes` |
| `src/vm.rs` | ~250 | `pub compute_hash` + `pub(crate) VmState` + private `dispatch_instruction` (NOP body) + scratchpad/register helpers all in one file |
| `src/lib.rs` | ~10 (delta) | `mod cache; mod vm;` + re-exports `Cache` and `compute_hash` |
| `tests/cache/t1_cache_derive.rs` | ~80 | T1 spec-vector test |
| `tests/cache/t1_prime_determinism.rs` | ~40 | R4 §5.11.1: T1' determinism property (3 sub-tests) |
| `tests/cache/t2_derive_item.rs` | ~100 | T2 spec-vector test |
| `tests/cache/t2_prime_invariance.rs` | ~30 | R4 §5.11.1: T2' invariance property (per-item interleaved-call) |
| `tests/vm/t3_scratchpad_init.rs` | ~60 | T3 spec-vector test |
| `tests/vm/t4_register_init.rs` | ~60 | T4 spec-vector test |
| `tests/vm/t5_program_parse.rs` | ~60 | T5 spec-vector test |
| `tests/vm/t6_spaddr_derive.rs` | ~60 | T6 spec-vector test |
| `tests/vm/t7_aes_mix.rs` | ~80 | T7 spec-vector test |
| `tests/vm/t8_end_to_end.rs` | ~80 | T8 spec-vector test |
| `benches/cache_derive.rs` | ~80 | criterion bench |
| `benches/compute_hash_alloc.rs` | ~80 | criterion bench (under stub-NOP dispatch) |
| `tests/perf/per_hash_latency.rs` | ~20 | R3-minor-2 placeholder (`#[ignore]` + `unimplemented!()`); populated in 2g |
| `BENCH_RESULTS.md` | ~30 | baseline numbers |
| `CHANGELOG.md` delta | ~15 | one entry |
| `.github/workflows/...` delta | ~1 | R4 §5.11.3: `cargo test --release` line in existing Rust workflow |
| **Rust total** | ~1444 | inside ≤1800 envelope; ~140 LoC under Round 1 first-draft estimate (vm/ module-boundary boilerplate eliminated); +20 LoC for R3-minor-2 placeholder; +80 LoC for R4 §5.11.1 + §5.11.2 + §5.11.3 + §5.11.4 (`debug_assert!` discipline absorbed into cache.rs and vm.rs LoC budgets above) |
| `_generator/phase2c/gen.cpp` | ~200 | C++ generator |
| `_generator/phase2c/CMakeLists.txt` | ~250 | CMake plumbing |
| `_generator/phase2c/README.md` | ~40 | build + reviewer notes |
| `_generator/phase2c/.meta.txt` | ~30 | provenance |
| **Generator total** | ~520 | separate from Rust budget |
| Reference vectors (binary) | ~50 KB | committed `.bin` files |

## 13. Forward path

Phase 2c lands the cache + VM substrate; downstream phases inherit:

- **2d** inherits:
  - F1's `dispatch_instruction` NOP stub body → replace the body
    in place with table-driven per-opcode dispatch. **No trait
    wiring, no impl swap, no signature change to `compute_hash`.**
    The wire-in is a function-body diff inside `vm.rs`, scoped to
    `dispatch_instruction`'s implementation.
  - F2c's FPU rounding-mode plumbing TODO → real `fprc` setter
    alongside CFROUND.
  - F3a's `F128` newtype extraction decision → extract when
    bytecode dispatch reveals the API surface.
  - F5's CFROUND throttling forward-pointer → no v1 per-iteration
    rounding-mode shim is constructed.
  - F7's FP rounding-mode invariant carry-forward → constrain T4/T7/T8
    inputs to IEEE 754 exact-integer-representation range, or
    re-verify invariant under each test's specific input space.
  - F8's bench may split into allocation-only vs. execution-only
    sub-benches if precision becomes load-bearing once real dispatch
    lands (per §5.8).

- **2f** inherits:
  - `Cache` type ready for `CacheStore` (`LruCache<Seedhash,
    Arc<Cache>>` wrapping it). `CacheStore` remains a `pub`
    utility type exported by `shekyl-pow-randomx` and instantiated
    by `shekyl-ffi` (per parent plan §"What irreducibly stays
    state" entry on `shekyl-ffi`'s internal `CacheStore` entries).
  - F8's BENCH_RESULTS.md baseline drives the `VmState` pooling
    decision: if `compute_hash_alloc.rs` median is close to the
    100 µs budget, 2f internalizes a `VmState` pool inside
    `compute_hash` (private to `vm.rs`, invisible to consumers —
    same shape as the dispatch-function-body-replacement
    discipline, not a public `VmPool` type). If comfortably under,
    2f records the decision as "`VmState` pooling deferred —
    per-call allocation cost is within budget." Per parent plan
    Decision #7 (Round 2 substrate-shift form): per-call allocation
    is the default; pooling, if needed, is internal to
    `compute_hash`.
  - **R4 §5.11.7: CacheStore canonical-slot eviction-protection.**
    The capacity-2 LRU `CacheStore` is small enough that an
    attacker can flush the canonical-seedhash slot with a
    3-seedhash interleave (alt-chain block headers with novel
    seedhashes), forcing ~150-200 ms cache re-derivation per
    attack block. 2f's Round 1 decision point: implement the
    canonical-seedhash slot as **sticky** (not subject to LRU
    eviction); only the secondary slot churns under attacker-induced
    pressure. Mechanism is 2f's call (explicit
    pinned-slot + transient-slot, or `pin(seedhash)` API on the
    capacity-2 LRU). Parent plan Decision #6 R4 carries the
    discipline note.
  - **R4 §5.11.7: `VmState` pool capacity sized against daemon
    parallel-verification fanout.** If 2f's benchmarks show pooling
    is needed, the pool capacity must be sized against the daemon's
    actual parallel-verification fanout (alt-chain branch validation
    plus mempool tx verification), not chosen arbitrarily. 2f
    Round 1 enumerates the fanout via daemon-side code survey or
    runtime measurement and sizes the pool accordingly. Parent
    plan Decision #7 R4 carries the discipline note.

- **2g** inherits:
  - Differential-harness test corpus uses real cache + real
    dispatch (2g lands after 2d).
  - Per-hash latency benchmark placement
    (`tests/perf/per_hash_latency.rs`) + release-gate cadence.
  - **R4 §5.11.5: adversarial seedhash corpus.** 2g selects 5–10
    seedhashes specifically chosen to produce programs heavy in
    CFROUND, FDIV_M, cache-miss-shaped scratchpad access, and
    CBRANCH. The corpus runs T1–T8 (and 2d's T9+ per-opcode tests)
    plus the differential harness against each adversarial
    seedhash. Selection criteria are part of 2g's Round 1.
  - **R4 §5.11.5: pathological-program worst-case timing bound.**
    Phase 0's ≤3.0× C-reference budget is the average across
    benign inputs. 2g asserts a worst-case bound (parent plan §6
    R4 carries the constant) against the adversarial corpus. If
    the worst case exceeds the bound, the verifier is exposed to
    CPU-DoS by miners grinding seedhashes for pathological
    programs.

- **3a** inherits:
  - `Cache` (the `pub fn derive` constructor) + `compute_hash` (the
    `pub fn` transform) are the FFI-exposed surfaces. The FFI shim
    in `shekyl-ffi` constructs `Cache` via `CacheStore` (transparent
    memo per parent plan Decision #6) and invokes `compute_hash`
    per request. `VmState` and `dispatch_instruction` remain
    invisible to the FFI consumer.
  - **FFI layering discipline (R3-minor-1).**
    `shekyl_ffi::shekyl_pow_randomx_v2_hash` is a **thin
    error-translation shim** over
    `shekyl_pow_randomx::compute_hash`; no semantic logic lives in
    the shim. The shim's body consists of: (a) `*const u8` /
    `*const [u8; 32]` / `*mut u8` → `&[u8]` / `&[u8; 32]` /
    `&mut [u8; 32]` slice construction with null-pointer + length
    validation, (b) a single `compute_hash(&cache, seedhash, data)`
    call, and (c) `i32` error-code translation (slice validation
    failures → negative error codes per `shekyl_ffi`'s existing
    convention; success → 0). Verification, dispatch, cache
    derivation, scratchpad allocation, register init, AES mix,
    finalization — **none** of these live in the FFI boundary.
    Implementation-PR-time review of 3a checks that the shim body
    is ≤30 LoC and that the only `compute_hash` call site lives
    inside the shim (no per-request `Cache::derive` in the FFI
    layer; cache construction routes through `CacheStore` per
    Decision #6). This discipline note prevents 3a from accidentally
    pulling verification logic into the FFI boundary — a
    failure-mode for `shekyl-ffi` cutovers per
    `36-secret-locality.mdc` (Rust owns secrets; FFI owns ABI
    translation only).
  - **R4 §5.11.6: FFI boundary hardening** (three forward-actions,
    each landed in 3a's implementation):
    - **Null-pointer validation.** Each of `seedhash`, `data`,
      `out` is checked for null before any dereference or slice
      construction. `slice::from_raw_parts(ptr::null(), 0)` is UB
      in Rust regardless of length; the check is mandatory.
      Translates to **`ERR_NULL_PTR (-1)`** per the parent plan's
      FFI error taxonomy (`RANDOMX_V2_PLAN.md` Phase 0 §5 +
      `RANDOMX_V2_RUST.md` §7).
    - **Length validation against `RANDOMX_BLOCK_TEMPLATE_MAX_SIZE`.**
      `data_len` is validated against the max before slice
      construction; oversize returns **`ERR_DATA_TOO_LARGE (-2)`**
      per the parent plan's FFI error taxonomy. Parent plan §5 R4
      pins the constant value (2 MiB; cross-checked in R5).
    - **`seedhash` as typed-array pointer.** FFI signature uses
      `seedhash: *const [u8; 32]` (typed-array pointer) rather
      than `seedhash: *const u8` (untyped pointer relying on
      documentation for length). The type system enforces the
      32-byte length at the shim's compile time. Same shape applies
      to `out: *mut [u8; 32]`.

## 14. Round history

| Round | Date | Outcome |
|-------|------|---------|
| Round 1 | 2026-05-21 | F1–F9 dispositions closed via interactive walk + ShekylU128 audit. F4 absorption surfaced as round-1 structural change requiring parent-plan revision (the first precursor commit on this branch). |
| Round 2 | 2026-05-21 | Substrate-finding pass against the Round 1 plan-doc. Three structural restructurings landed within Round 1's locked dispositions: **(R2-D1)** `BytecodeDispatch` trait + `StubNopDispatch` impl → `dispatch_instruction` free function with NOP body replaced in 2d, eliminating the mock-X anti-pattern recurrence (§5.1 F1, §1 cross-cut). **(R2-D2)** `Vm<'a>` public type → `compute_hash` public transform with `VmState` private (§2 type table, §3 module layout collapse 5 files → 2 files, §13 forward-path updates for 2d/2f/3a). **(R2-D3)** `Cache::from_raw` visibility correction (`pub` → `pub(crate)`; test-time only, not FFI surface — §5.9 F9). Parent-plan alignment commit follows (Decision #7 substrate-shift per `21-reversion-clause-discipline.mdc`: `VmState` pooling becomes internal to `compute_hash`, not a public `VmPool` type). All three deliverables tighten the type-and-module shape inside the bounds Round 1's dispositions already established; no Round 1 disposition reopened. |
| Round 3 | 2026-05-21 | Substrate-completeness pass against Round 2 plan-doc; close-out before implementation. **(R3-D1)** §5.1.1 "Function-body replacement contract" pins the 2c → 2d hand-off: frozen `dispatch_instruction` signature, frozen `Instruction` field set, and `VmState` field set populated empirically from an audit against `bytecode_machine.hpp`'s 29 opcode handlers + `vm_interpreted.cpp::execute()`. Audit produced one correction-from-prompted-list finding: `mp` is a v2-only local-variable alias for `mem.ma` per `vm_interpreted.cpp:89`, not a `MemoryRegisters` struct field; §5.5 F5 entry updated to match (existence disposition was wrong in Rounds 1–2; the v2-only Rust port introduces no `mp` field). Single-pass dispatch shape locked; IBC 2-pass form rejected with named reversion-clause criterion (reopen iff 2d benchmarks show single-pass cannot hit ≤3.0× Phase 0 budget AND profiling attributes shortfall to per-call decode cost). **(R3-minor-1)** §13 3a inheritance gains an FFI layering discipline note: `shekyl_pow_randomx_v2_hash` is a thin error-translation shim over `compute_hash`; no semantic logic in the FFI boundary; shim body ≤30 LoC. **(R3-minor-2)** §9 commit 8 + §15 PR template + §12 forecast envelope add the `tests/perf/per_hash_latency.rs` placeholder (`#[ignore]` + `unimplemented!()` cross-referencing F8 / §13 2g inheritance); structural code out-survives prose deferral. **(R3-D3)** Sibling commit lands `docs/design/RANDOMX_V2_PHASE2D_PLAN.md` skeleton scaffold: §5.1.1 contract carry-forward, VmState field-set reference, forward-actions accumulated from F1/F2/F3/F5/F7, decision points for 2d Round 1 (FPU rounding-mode mechanism; F128 newtype shape; per-opcode dispatch shape). All Round 3 deliverables remain within Round 2's locked dispositions; no Round 2 or Round 1 disposition reopened. Target ≤1 round met. |
| Round 4 | 2026-05-21 | Threat-model addenda pass against the Round 3 plan-doc; priority-1 (per `00-mission.mdc`) adversarial review enumerating six attack objectives (mining-faster differential; cache poisoning; FFI exploitation; resource DoS; Rust safety boundary gaps; consensus split via implementation divergence). New §5.11 records eight findings + dispositions. **In-scope 2c-implementation additions:** §5.11.1 T1' (`Cache::derive` determinism property — single-thread loop, concurrent threads, interleaved seedhash) + T2' (`derive_item` invariance property), ~60 LoC in commits 2 and 3; §5.11.2 `debug_assert!` discipline at the two unsafe `Box::new_zeroed_slice` sites, ~10 LoC across commits 2 and 4; §5.11.3 debug-vs-release equivalence as PR gate (1 line in CI workflow + §10 gate entry); §5.11.4 public-input-only scope note in crate-level doc-comments. **Forward-actions to downstream phases:** §5.11.5 2g adversarial seedhash corpus + pathological-program worst-case timing bound; §5.11.6 3a FFI null-pointer + length-validation + `seedhash: *const [u8; 32]` typed-array pointer + `ERR_NULL_PTR` taxonomy; §5.11.7 2f CacheStore canonical-seedhash slot eviction-protection + `VmState` pool capacity sized against daemon parallel-verification fanout. **Discipline note:** §5.11.8 audit-against-actual-code validation (the discipline that produced R3-D1's `mp` correction is the discipline 2d/2g inherit for their own surfaces). Parent plan alignment ships as a sibling commit on this branch (Decision #6 R4 carries CacheStore eviction-protection note; Decision #7 R4 carries VmState pool sizing note; Phase 0 §5 R4 pins `RANDOMX_BLOCK_TEMPLATE_MAX_SIZE` and `ERR_NULL_PTR` taxonomy + `*const [u8; 32]` signature; Phase 0 §6 R4 adds worst-case ≤5.0× timing bound; Risk acknowledgments R4 adds a Rust-vs-C edge-case differential bullet). The 2d skeleton scaffold gets a sibling commit adding §2 F7 per-rounding-mode coverage forward-action, §3.1 unsafe-block scope-check discipline, and §4.1 u128/`__int128` edge-case differential discipline. All Round 4 additions remain within Round 1–3's locked dispositions; no prior disposition reopened. Target ≤1 round met. |
| Round 5 | 2026-05-21 | Closure-only refinement pass against the Round 4 plan-doc. Substantive review surface is closed at Round 4; Round 5 tightens four discipline-enforcement edges without surfacing new findings. **(R5-D1)** §5.11.8 framing amendment: "reading-the-source vs. producing-a-table-from-intuition" named as the load-bearing audit step (the table is the audit's output; the audit's substance is the line-by-line reading that *produces* the table); "show your work" enforcement formalized — every audit table cites line ranges at the pinned fork commit, reviewer spot-checks by opening the cited file and reading the named lines. The `mp` correction is reframed from "we caught one bug" to "the prompted-list table that didn't reflect a reading-the-source pass was the failure mode `16-architectural-inheritance.mdc`'s 'audits-are-clean-so-compress' anti-pattern names." **(R5-D2)** Parent plan Phase 0 §5 FFI hardening refinements (sibling commit): C-side header form `const uint8_t (*seedhash)[32]` (not decayed `const uint8_t *`); C++ call-site declaration discipline (`uint8_t seedhash_buffer[32]` + `&seedhash_buffer`), documented at each call site not just at the signature; `RANDOMX_BLOCK_TEMPLATE_MAX_SIZE` rationale-sentence ("generous ceiling well above any realistic Shekyl block template; the 2 MiB == scratchpad-size coincidence is not load-bearing coupling"). **(R5-D3)** 2d skeleton §3.1 CI grep mechanical enforcement addendum (sibling commit): the unsafe-block scope-check discipline gets the same shape as the `no #[no_mangle] in shekyl-pow-randomx` invariant — a CI-time grep asserts the rounding-mode-setter function body contains exactly one of the chosen intrinsic / asm form and nothing else (no other intrinsic calls, no pointer dereferences, no allocator calls). Prose-as-discipline is necessary but not sufficient; the grep is the enforcement that survives "a future contributor stashing the previous mode for restoration" style additive drift. **(R5-D4)** New `docs/FOLLOWUPS.md` V3.0 entry (sibling commit): post-2c-implementation forward-action to promote 2c-emergent disciplines (function-body replacement contract, audit-against-actual-code, threat-model addenda framing, reversion-clause for sub-PR boundary changes, forward-action propagation convention) to project-level documentation (likely `.cursor/rules/26-sub-pr-design-discipline.mdc` or `docs/conventions/`). **Posture-shift note (recorded for downstream sub-PRs).** Round 4's threat-model framing converted "design closure" into **design closure plus active defense against named attacker objectives**. The shift is worth naming so 2d Round 1, 2f Round 1, 2g Round 1, and LWMA-1 Phase 4's design rounds get the same shape rather than reverting to per-finding review — the threat-model-objective framing surfaces findings (`mp`, eviction interleave, FPU rounding-mode escape, u128 edge cases) that per-finding review wouldn't have caught because no individual finding *suggests* the next one; the attacker-objective frame does. All Round 5 additions remain within Round 1–4's locked dispositions; no prior disposition reopened. Target ≤1 round met. |

## 15. References to commit (Phase 2c PR description shape)

The implementation PR's description carries the following structure
(template-style, populated per actual landing):

```markdown
## Summary

Phase 2c of the RandomX v2 Rust port. Lands `Cache` (`pub derive`
constructor + `pub(crate)` `from_raw`/`derive_item`/`item_bytes`
accessors) and `compute_hash(&Cache, &[u8; 32], &[u8]) -> [u8; 32]`
public transform. `VmState` and `dispatch_instruction` are private
implementation details of `vm.rs`; `dispatch_instruction`'s NOP body
is replaced in Phase 2d. T1–T8 spec-vector parity tests.
Cache-derive + compute-hash-allocation benchmarks within Phase 0
budgets (≤200 ms / ≤100 µs).

Scope per [`RANDOMX_V2_PHASE2C_PLAN.md`](docs/design/RANDOMX_V2_PHASE2C_PLAN.md);
F4 absorption rationale at §5.4 (Cache::derive absorbed from
originally-scoped 2e). Round 2 substrate-finding pass tightened the
public surface (`compute_hash` as transform, `VmState` private,
`dispatch_instruction` as free function with body replacement)
within Round 1's locked dispositions.

## Gates

- [x] `cargo fmt --check`
- [x] `cargo clippy -- -D warnings`
- [x] `cargo test -p shekyl-pow-randomx --all-features` (T1–T8 + T1' + T2' pass under debug)
- [x] `cargo test -p shekyl-pow-randomx --all-features --release` (same corpus passes under release; byte-identity vs. debug per §5.11.3)
- [x] `cargo doc -p shekyl-pow-randomx --no-deps`
- [x] `cache_derive` bench median ≤200 ms (see BENCH_RESULTS.md)
- [x] `compute_hash_alloc` bench median ≤100 µs under stub-NOP dispatch (see BENCH_RESULTS.md)
- [x] No new workspace dependencies
- [x] F5 audit grep clean against fork pin

## Test plan

T1–T8 spec-vector parity (byte-equality against generator output)
plus T1' / T2' determinism + invariance property tests
(`tests/cache/t1_prime_determinism.rs`,
`tests/cache/t2_prime_invariance.rs` — see §5.11.1). Plus
per-component unit tests in `cache.rs` and `vm.rs`. Plus
`tests/perf/per_hash_latency.rs` placeholder (`#[ignore]`'d; landed
for 2g's per-hash latency benchmark — see RANDOMX_V2_PHASE2C_PLAN.md
§8 placeholder sub-section). Debug-vs-release equivalence verified
by running the full test suite under both profiles in CI
(`cargo test` + `cargo test --release`; see §5.11.3).

## Forward path verification

- `dispatch_instruction` body is the only `vm.rs` site mutated by
  Phase 2d (see RANDOMX_V2_PHASE2C_PLAN.md §5.1.1 contract).
- `VmState` field additions in 2d require audit-grep evidence per
  §5.1.1 reopening criterion.
- `tests/perf/per_hash_latency.rs` body is replaced by 2g, not by 2d.
- `debug_assert!` lines at the two `Box::new_zeroed_slice` sites are
  preserved across 2d/2f refactors (see §5.11.2 discipline note).
- Public-input-only scope notes in `cache.rs` and `vm.rs` crate-level
  doc-comments are preserved across downstream phases (see §5.11.4).
```
