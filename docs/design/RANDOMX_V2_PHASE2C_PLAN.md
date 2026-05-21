# RandomX v2 — Track A Phase 2c plan

**Status.** Round 1 closed via interactive walk on 2026-05-21 (this
conversation; F1–F9 dispositions + ShekylU128 audit). Implementation
is gated on Round 2+ design closure (target: 2-3 rounds before
implementation per Phase 2b precedent) and on workspace MSRV
verification (≥ 1.85, unchanged from 2b).

**Parent plan.** [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §"Track A
— Phase 2" sub-PR 2c is the binding one-line scope ("Implement Cache
(with derive(key) + from_raw + derive_item methods, 256 MB cache
memory + 8 SuperscalarHash programs) AND Vm<'a> [...]"); this doc
expands it into a reviewable change list, dependency-discipline
dispositions, a test plan, and the nine findings (plus the
ShekylU128 audit) that closed during Round 1. The parent plan was
revised in the precursor commit to absorb the originally-scoped
Phase 2e Cache::derive deliverable into 2c; rationale in §5 F4 below.

**Base commit.** `dev` at the post-PR-#64 merge tip (PR #64 — Phase
2b — landed via merge commit `fe7bc97d5` on 2026-05-21). This doc's
branch (`chore/randomx-v2-phase2c-plan`) cuts from there; the
Phase 2c implementation branch cuts later from post-this-doc `dev`.

**Branches.**

- `chore/randomx-v2-phase2c-plan` (this doc only + the parent-plan
  precursor patch; short-lived per `06-branching.mdc` rule 2; two
  commits; lands on `dev` via its own PR).
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
  §4 (Derived-First Design — Cache is the canonical example, now
  built end-to-end in 2c), §7 (Isolation Invariants — `Vm<'a>`
  borrow vs. `Cache` ownership), §8 (Performance Targets — ≤200 ms
  cache derive, ≤100 µs Vm allocation, both PR-gated here; ≤3.0×
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
  — all consumed by `Cache::derive` and `Vm::run`.
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
| 1 | C JIT stays miner-only | Zero JIT code in this PR; pure interpreter `Vm<'a>`. |
| 2 | Spec wins over C reference | `Cache` follows spec §7 (Argon2d fill + 8 SuperscalarHash); `Vm` follows spec §4 (initialization + execution loop). Spec-silent details dispositioned per `superscalar.rs`'s Phase 2b audit table; any 2c-new spec-silence entries go in `vm.rs` or `cache.rs` rustdoc. |
| 3 | Transform-shaped types | `Cache::derive(key) -> Cache` is the canonical transform-shaped example per `18-type-placement.mdc`. `Vm<'a>` is execution-shaped (per-hash transient state); its `run` method is the transform. No persisted intermediate state. |
| 4 | No prewarm / no async cache rebuild | Phase 2c adds no scheduling. `Cache::derive` is synchronous; `Vm::run` is synchronous. |
| 5 | No `#[no_mangle]` / `extern "C" fn` / `#[export_name]` | Phase 2f greps continue to zero-hit. |
| 6 | No module-level runtime-mutable state | Constants are `const`-only (cache memory size, scratchpad size, program size, program iterations, register counts). |
| 7 | Isolation invariants | `#![deny(unsafe_code)]` preserved at crate level. Two `unsafe` blocks needed (per §3 below): `Box::new_zeroed_slice` for cache + scratchpad allocation. Both gated behind `#[allow(unsafe_code)]` at the call site with `// SAFETY:` documentation per `45-rust-lint-checks.mdc`. |
| 8 | No env vars / build-flag dispatch | All constants inline; no runtime configuration. |

**F4-absorbed cross-cut: Cache lives in 2c, not 2e.** Per §5 F4 below,
absorbing `Cache::derive` into 2c eliminates the `DatasetReader` trait
abstraction the 2c-without-Cache shape would have required. `Vm::run`
takes `&'a Cache` directly — the eventual production shape.

## 2. Scope (the in-scope work)

Two new types land:

| # | Type | Spec section | C reference | Downstream caller |
|---|------|--------------|-------------|--------------------|
| 1 | `Cache` (with `derive` + `from_raw` + `derive_item` methods) | §7, §7.3 | `dataset.cpp::initCache` + `initDatasetItem` | 2c `Vm::run`; eventual 2f `CacheStore`; eventual 3a FFI surface |
| 2 | `Vm<'a>` (with `new` + `run` methods) | §4 | `virtual_machine.cpp::initialize` + `vm_interpreted.cpp::run` | eventual 2f `VmPool`; eventual 3a FFI surface |

Plus one new internal trait:

| # | Trait | Phase 2c impl | 2d disposition |
|---|-------|---------------|----------------|
| 3 | `BytecodeDispatch` | `StubNopDispatch` (all 29 opcodes are NOP) | Real `TableDispatch` lands in 2d alongside FPU plumbing |

Plus T1–T8 spec-vector tests (§6) + cache-derive bench + Vm-alloc
bench + BENCH_RESULTS.md baseline artifact + reference vector
generator (one binary with CLI flag per §7).

### 2.1 Explicitly out of scope

- Real bytecode dispatch (2d). The `BytecodeDispatch` trait lands in
  2c with the stub impl; 2d adds the real table-driven impl.
- FPU rounding-mode plumbing for `fprc` (2d, per F2c). 2c uses host-
  default rounding mode; stub-NOP dispatch ensures this is unobservable
  in test outputs (per F7's rounding-mode-insensitive invariant).
- `F128([f64; 2])` newtype extraction (2d, per F3a). 2c uses raw
  `[f64; 2]` for FP registers; newtype extraction is 2d's call once
  bytecode dispatch reveals the API surface needed.
- `CacheStore`, `VmPool`, FFI surface, C++ rewire (2f, 3a-3c).
- Per-hash latency benchmark (2g). The ≤3.0× ratio check needs the
  differential harness 2g produces. 2c only runs cache-derive and
  Vm-alloc benches.

"While we're here" cleanup of unrelated files is forbidden per
`15-deletion-and-debt.mdc`. The in-file-discipline exception is the
2c-internal restructuring of `src/lib.rs` (adding `mod cache;` and
`mod vm;` declarations + re-exports), which is allowed because the
file is edited for substantive Phase 2c reasons.

## 3. Module layout

Forward from Phase 2b's pattern:

```text
rust/shekyl-pow-randomx/src/
├── lib.rs                # adds mod cache; mod vm; re-exports
├── argon2d.rs            # (2a, unchanged)
├── aes.rs                # (2b, unchanged)
├── blake2_generator.rs   # (2b, unchanged)
├── superscalar.rs        # (2b, unchanged)
├── cache.rs              # NEW: Cache type, derive, from_raw, derive_item
└── vm/
    ├── mod.rs            # NEW: Vm<'a>, new, run; dispatch trait re-export
    ├── dispatch.rs       # NEW: BytecodeDispatch trait + StubNopDispatch impl
    ├── scratchpad.rs     # NEW: Scratchpad alloc + init (fillAes1Rx4 wiring)
    └── registers.rs      # NEW: NativeRegisterFile + init from entropy
```

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

`Cache` and `Vm` consume only types already exported (or `pub(crate)`)
from 2a and 2b modules:

| Phase 2c consumer | Phase 2a/2b provider | Provider's visibility |
|-------------------|---------------------|------------------------|
| `Cache::derive` | `argon2d::fill_cache(key: &[u8], blocks: &mut [Block])` | `pub(crate) fn` |
| `Cache::derive` | `blake2_generator::Blake2Generator::new` + `.next_byte`/`.next_u32` | `pub(crate) struct` |
| `Cache::derive` | `superscalar::generate_superscalar(prog: &mut SuperscalarProgram, gen: &mut Blake2Generator)` | `pub(crate) fn` |
| `Cache::derive_item` | `superscalar::execute_superscalar(prog: &SuperscalarProgram, regs: &mut [u64; 8])` | `pub(crate) fn` |
| `Cache::derive_item` | `superscalar::randomx_reciprocal(divisor: u64) -> u64` | `pub(crate) fn` (already on-the-fly per C reference's `reciprocalCache`; no Rust-side cache needed) |
| `Vm::new` (scratchpad init) | `aes::fill_aes_1r_x4(state: &mut [u8; 64], scratchpad: &mut [u8])` | `pub fn` |
| `Vm::new` (program parse) | `aes::fill_aes_4r_x4(entropy: &[u8; 64], buf: &mut [u8])` | `pub fn` |
| `Vm::run` (F/E AES mix) | `aes::fill_aes_4r_x4` (per spec §4) | `pub fn` |
| `Vm::run` (finalize) | `aes::hash_aes_1r_x4(scratchpad: &[u8], hash: &mut [u8; 64])` | `pub fn` |

**Verification step (Round 2 deliverable):** confirm each
`pub(crate)` visibility is sufficient for 2c's consumption (i.e.,
the same crate). If any needs to be `pub`, it's a documented
visibility-promotion in 2c; if any needs no change, the 2c PR is a
pure consumer of the existing 2a+2b surface.

### 4.2 `criterion = "0.5"` (already DEV-only)

Already in workspace via Phase 2b's bench setup. Used for
`benches/cache_derive.rs` and `benches/vm_allocation.rs`. No
version bump needed.

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

### 5.1 F1 — 2c/2d boundary: stub-NOP bytecode dispatch

**Problem.** The parent plan's 2c scope ("`Vm<'a>` ... spec-vector
parity tests") is incoherent without the 2d bytecode dispatch — a
`Vm` without instruction dispatch can't produce a hash, and spec
vectors test hashes. The naive 2c shape produces a `Vm` whose `run`
method is unimplemented or panics, which makes the spec-vector tests
unable to land.

**Disposition (F1a + F4-absorbed strengthening).** 2c lands `Vm<'a>`
with a `BytecodeDispatch` trait whose all-NOP impl (`StubNopDispatch`)
runs all 29 opcodes as no-ops. The spec-vector tests validate the
structural pieces of the VM loop (scratchpad init, register init,
program parse, spAddr derivation, F/E AES mix, end-to-end finalize)
using a synthetic 384-NOP program over a **real cache** (per the
F4-absorbed scope expansion below). This corpus exercises everything
except per-instruction semantics — a much wider test surface than the
original F1a stub-NOP-with-mock-cache shape would have allowed.

**Reopening criterion.** Not applicable: F1a is the implementation
shape, not a deferral. 2d replaces `StubNopDispatch` with `TableDispatch`
(the real per-opcode dispatch) as a planned subsequent landing.

### 5.2 F2 — FPU rounding mode: deferred to 2d

**Problem.** RandomX's `fprc` register selects one of four IEEE 754
rounding modes (RN/RD/RU/RZ) per program iteration. Stable Rust has
no direct `set_rounding_mode` API (it's nightly-only via
`std::arch::asm!` or third-party crates with `unsafe`). The crate's
`#[deny(unsafe_code)]` policy forecloses naive plumbing.

**Disposition (F2c — defer to 2d).** 2c's `Vm::run` uses the host's
default FP rounding mode (RN on every standard platform). This is
unobservable in 2c's spec-vector tests because stub-NOP dispatch
means no FP arithmetic executes, so the rounding mode never affects
any operation. The `fprc` register exists in `Vm`'s state but is
never read in 2c (no instruction reads it).

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

**Problem.** Phase 2c's `Vm::run` needs to read dataset items
(spec §4.5.4 — every iteration reads one 64-byte dataset item
into the scratchpad). The parent plan's original split had
`Cache::derive` in 2e, so 2c had no `Cache` type to borrow from.
The naive 2c shape introduces a `DatasetReader` trait that abstracts
over the absent `Cache::derive`, with a `MockDatasetReader` impl for
2c's tests and a real `CacheDatasetReader` impl that 2e wires up.

**Disposition (absorption — eliminate the trait).** 2c absorbs the
`Cache::derive` deliverable from 2e. `Vm::run` takes `&'a Cache`
directly; the dataset-item read is `cache.derive_item(item_number)`
— a method on `Cache`, not a trait method on an abstract reader.
No trait, no mock, no light-vs-full abstraction split.

**Why the absorption is the right shape.**

- **Eliminates trait + mock attack surface.** A trait exists to
  abstract over multiple implementations. With the absorption, there
  is exactly one implementation (`Cache::derive_item`). A trait with
  one implementation is debt per `21-reversion-clause-discipline.mdc`
  (optionality without a named caller).
- **`Vm::run`'s production shape lands in 2c.** Eventually 2f's
  `CacheStore` produces `Arc<Cache>` and the FFI shim runs
  `Vm::run(scratchpad, &cache, ...)`. The 2c borrow signature is the
  eventual production signature — no API churn between 2c and 3a.
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
| `vm_interpreted.cpp:89` — `auto& mp = (flags & V2) ? mem.ma : mem.mx;` | `mp = ma` | `mp = ma` assignment is unconditional (no version gate). `mp` register exists unconditionally as a `Vm` field. **Distinction:** existence is the data-flow disposition; assignment is the control-flow disposition. |
| `vm_interpreted.cpp:99` — `if (flags & V2)` F/E AES mix over FP registers | take v2 branch unconditionally | `Vm::run`'s F/E AES mix is the v2 form (per spec §4.5.4) with no conditional. |
| `bytecode_machine.hpp:263` — `if ((flags & V2) == 0 \|\| (isrc & 60) == 0)` IADD_M/ISUB_M/IMUL_M imm32 cap | take v2 branch (the cap applies) | `Vm::run`'s memory-instruction imm32 handling caps to first 6 bits unconditionally (relevant to 2d's bytecode dispatch; 2c carries the discipline forward as a forward-pointer). |
| `virtual_machine.hpp:63-66` — `setFlagV2()` / `clearFlagV2()` mutators | no flag mutation | `Vm` has no `set_flag_v2` method; v2 is hardcoded by construction. |
| `program.hpp:46-48` — `Program::getSize(flags)` returning `_V1=256` or `_V2=2048` | `PROGRAM_SIZE = 2048` | Rust constant `pub(crate) const PROGRAM_SIZE: usize = 2048;` (no flags param). |
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
   - `benches/vm_allocation.rs` — measures `Vm::new(&cache,
     &SEEDHASH, &DATA)` median latency over N=10000 iterations.
     **PR fails if median > 100 µs.**

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

### 5.9 F9 — Cache lands in 2c (covered by §5.4)

Per the F4-absorbed disposition above, `Cache` lands in 2c with
both `from_raw` (the public byte-array constructor for FFI
consumers) and `derive` (the seedhash → Cache derivation function
that absorbs the originally-scoped 2e deliverable). Plus
`derive_item(item_number)` per spec §7.3. No separate 2e PR.

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

Plus per-component unit tests inside `cache.rs` and `vm/*.rs` for
internal invariants (cache memory size, scratchpad size, program
size, register count, dataset-item byte offset arithmetic). These
are coarse functional tests, not spec-vector parity — they catch
implementation-side bugs that the spec-vectors would only catch via
the full T1–T8 run.

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
├── cache_derive.rs       # criterion bench; ≤200 ms median assertion
└── vm_allocation.rs      # criterion bench; ≤100 µs median assertion

rust/shekyl-pow-randomx/BENCH_RESULTS.md   # measured medians at PR-merge
```

CHANGELOG entry records the BENCH_RESULTS.md commit so downstream
PRs know to compare against it.

## 9. Commit granularity

Eight commits, each respecting `06-branching.mdc` and
`90-commits.mdc` (imperative mood, ≤72 chars subject, subsystem
prefix `randomx:`, references the relevant plan-doc section or
finding):

| # | Commit | LoC budget | Section reference |
|---|--------|-----------|-------------------|
| 1 | `randomx: Cache type skeleton + size constants + Drop` | ~80 LoC | §3 module layout, §2 type 1 |
| 2 | `randomx: Cache::derive + Cache::from_raw + cache.rs tests` | ~250 LoC | §5.4, §6 T1 |
| 3 | `randomx: Cache::derive_item + item_bytes accessor + T2 tests` | ~150 LoC | §4.3, §5.4, §6 T2 |
| 4 | `randomx: Vm<'a> skeleton + Scratchpad alloc + Drop` | ~100 LoC | §3, §2 type 2 |
| 5 | `randomx: Vm::new with register init + program init (T3-T5)` | ~250 LoC | §6 T3-T5 |
| 6 | `randomx: Vm::run with stub-NOP dispatch + spec vectors (T6-T8)` | ~300 LoC | §5.1, §5.7, §6 T6-T8 |
| 7 | `randomx: Phase 2c reference vector generator (T1-T8)` | ~400 LoC | §5.6, §7 |
| 8 | `randomx: Phase 2c benchmarks + BENCH_RESULTS.md + CHANGELOG` | ~150 LoC | §5.8, §8 |

Total ≈ 1680 LoC, slightly below the §"Scope envelope" 1800 LoC
target. Generator C++ + CMake (~450 LoC) is separate from the Rust
LoC count.

## 10. Gates

PR-merge gates (CI-enforced):

- `cargo fmt --check` (all Rust passes; rustfmt regression-free per
  Phase 2b's commit 28d9a336f precedent).
- `cargo clippy --workspace --all-targets -- -D warnings`.
- `cargo test -p shekyl-pow-randomx --all-features` (T1–T8 + unit
  tests all pass).
- `cargo doc -p shekyl-pow-randomx --no-deps` (rustdoc clean).
- `Lint: no debug macros in production Rust` (workflow already in
  CI; zero hits expected).
- **Phase 2c bench thresholds:** `cache_derive` median ≤200 ms;
  `vm_allocation` median ≤100 µs. **Fail → PR blocked.**
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
| `src/cache.rs` | ~300 | Cache type + derive + from_raw + derive_item + item_bytes |
| `src/vm/mod.rs` | ~200 | Vm<'a> + new + run + state plumbing |
| `src/vm/dispatch.rs` | ~80 | BytecodeDispatch trait + StubNopDispatch |
| `src/vm/scratchpad.rs` | ~100 | Scratchpad alloc + init |
| `src/vm/registers.rs` | ~80 | NativeRegisterFile + init from entropy |
| `src/lib.rs` | ~20 (delta) | `mod cache; mod vm;` + re-exports |
| `tests/cache/t1_cache_derive.rs` | ~80 | T1 spec-vector test |
| `tests/cache/t2_derive_item.rs` | ~100 | T2 spec-vector test |
| `tests/vm/t3_scratchpad_init.rs` | ~60 | T3 spec-vector test |
| `tests/vm/t4_register_init.rs` | ~60 | T4 spec-vector test |
| `tests/vm/t5_program_parse.rs` | ~60 | T5 spec-vector test |
| `tests/vm/t6_spaddr_derive.rs` | ~60 | T6 spec-vector test |
| `tests/vm/t7_aes_mix.rs` | ~80 | T7 spec-vector test |
| `tests/vm/t8_end_to_end.rs` | ~80 | T8 spec-vector test |
| `benches/cache_derive.rs` | ~80 | criterion bench |
| `benches/vm_allocation.rs` | ~80 | criterion bench |
| `BENCH_RESULTS.md` | ~30 | baseline numbers |
| `CHANGELOG.md` delta | ~15 | one entry |
| **Rust total** | ~1483 | inside ≤1800 envelope |
| `_generator/phase2c/gen.cpp` | ~200 | C++ generator |
| `_generator/phase2c/CMakeLists.txt` | ~250 | CMake plumbing |
| `_generator/phase2c/README.md` | ~40 | build + reviewer notes |
| `_generator/phase2c/.meta.txt` | ~30 | provenance |
| **Generator total** | ~520 | separate from Rust budget |
| Reference vectors (binary) | ~50 KB | committed `.bin` files |

## 13. Forward path

Phase 2c lands the cache + VM substrate; downstream phases inherit:

- **2d** inherits:
  - F1's `BytecodeDispatch` trait → `TableDispatch` impl with real
    per-opcode dispatch.
  - F2c's FPU rounding-mode plumbing TODO → real `fprc` setter
    alongside CFROUND.
  - F3a's `F128` newtype extraction decision → extract when
    bytecode dispatch reveals the API surface.
  - F5's CFROUND throttling forward-pointer → no v1 per-iteration
    rounding-mode shim is constructed.
  - F7's FP rounding-mode invariant carry-forward → constrain T4/T7/T8
    inputs to IEEE 754 exact-integer-representation range, or
    re-verify invariant under each test's specific input space.

- **2f** inherits:
  - `Cache` type ready for `CacheStore` (`LruCache<Seedhash,
    Arc<Cache>>` wrapping it).
  - F8's BENCH_RESULTS.md baseline drives the `VmPool` decision:
    if `vm_allocation.rs` median is close to the 100 µs budget,
    2f adds `VmPool`; if comfortably under, 2f records the
    decision as "VmPool deferred — current Vm::new cost is within
    budget."

- **2g** inherits:
  - Differential-harness test corpus uses real cache + real
    dispatch (2g lands after 2d).
  - Per-hash latency benchmark placement
    (`tests/perf/per_hash_latency.rs`) + release-gate cadence.

- **3a** inherits:
  - `Cache` + `Vm<'a>` are the FFI-exposed types (via shekyl-ffi
    shim with `CacheStore` as transparent memo per parent plan
    Decision #6).

## 14. Round history

| Round | Date | Outcome |
|-------|------|---------|
| Round 1 | 2026-05-21 | F1–F9 dispositions closed via interactive walk + ShekylU128 audit. F4 absorption surfaced as round-1 structural change requiring parent-plan revision (the precursor commit on this branch). |
| Round 2+ | pending | Substrate-completeness pass + implementation-detail refinement. Target ≤2 rounds before implementation cut. |

## 15. References to commit (Phase 2c PR description shape)

The implementation PR's description carries the following structure
(template-style, populated per actual landing):

```markdown
## Summary

Phase 2c of the RandomX v2 Rust port. Lands `Cache` (with `derive` +
`from_raw` + `derive_item` methods) and `Vm<'a>` (with stub-NOP
bytecode dispatch trait — real dispatch lands in 2d). T1–T8
spec-vector parity tests. Cache-derive + Vm-alloc benchmarks within
Phase 0 budgets (≤200 ms / ≤100 µs).

Scope per [`RANDOMX_V2_PHASE2C_PLAN.md`](docs/design/RANDOMX_V2_PHASE2C_PLAN.md);
F4 absorption rationale at §5.4 (Cache::derive absorbed from
originally-scoped 2e).

## Gates

- [x] `cargo fmt --check`
- [x] `cargo clippy -- -D warnings`
- [x] `cargo test -p shekyl-pow-randomx --all-features` (T1–T8 pass)
- [x] `cargo doc -p shekyl-pow-randomx --no-deps`
- [x] `cache_derive` bench median ≤200 ms (see BENCH_RESULTS.md)
- [x] `vm_allocation` bench median ≤100 µs (see BENCH_RESULTS.md)
- [x] No new workspace dependencies
- [x] F5 audit grep clean against fork pin

## Test plan

T1–T8 spec-vector parity (byte-equality against generator output).
Plus per-component unit tests in `cache.rs` and `vm/*.rs`.
```
