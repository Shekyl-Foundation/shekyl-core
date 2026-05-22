# RandomX v2 — Phase 2c implementation pre-flight audit

**Status.** Audit executed 2026-05-21 on `feat/randomx-v2-phase2c-impl`,
branched from `dev` at `5df8bd2c2` (the PR #65 merge commit). The audit
satisfies the §4.1 verification gate ("re-run the audit at
PR-implementation time against the then-current `shekyl-pow-randomx`
source") and the §5.11.8 audit-against-actual-code discipline.
Four findings surfaced (one clarity item; three plan-doc errata —
one substantive, two factual citation drifts). All four are addressed
by short-lived sibling commits on this branch before any implementation
code lands.

**Audit pin.**

- `shekyl-core` `dev` at `5df8bd2c2` (PR #65 plan-doc merge commit).
- `external/randomx-v2` submodule at `aaafe71322df6602c21a5c72937ac284724ae561`,
  unchanged since PR #64 (Phase 2b) merged.

**Audited document.** [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md)
as merged via PR #65.

**Out of scope.** This audit is a pre-implementation re-verification
of the plan-doc's claims against the substrate at branch-cut time.
Implementation-time audits (per `91-documentation-after-plans.mdc`
and `cargo test` byte-equality against generator vectors) are downstream
gates on the implementation PR itself, not this audit's responsibility.

## 1. Audit purpose

Per Phase 2c plan-doc §5.11.8:

> The discipline that found [the `mp` correction] — **audit-against-
> actual-code, not against documentation or prompted lists** — is the
> discipline that prevents the same class of bug shipping as a
> consensus-split source.

And §4.1's verification gate:

> Re-run the audit at PR-implementation time against the then-current
> `shekyl-pow-randomx` source — visibilities, signatures, and method
> names must match the implementation PR's actual call sites.

This audit is the operational form of both. The plan-doc's tables are
the audit's output from PR #65's Round 5 close; this audit's tables are
the audit's output from the pre-implementation re-verification pass.
Per §5.11.8's "show your work" amendment, every audited row carries a
line-range citation at the audit pin, and the audit is rejected
regardless of how plausible a row looks if the cited lines don't
contain what the disposition claims.

## 2. Methodology

For each of the eight audit surfaces below, the auditor:

1. **Read the cited file at the audit pin** (not the plan-doc's
   summary; not a search-engine excerpt).
2. **Confirmed each line-range citation against the file's actual
   contents** — both the line numbers and the semantic claim.
3. **Recorded the disposition** as either:
   - **Confirmed** (the citation and claim hold byte-perfect);
   - **Errata — citation drift** (the semantic claim is correct but the
     line numbers shifted, e.g., a v2 fork edit moved a function);
   - **Errata — substantive** (the line numbers may be correct but the
     semantic claim doesn't match what's at those lines);
   - **Clarity** (the claim is technically correct but understates
     what the implementation must do).

The §5.11.8 anti-pattern protection is "the table is the audit's
output, not the audit's substance." A reader who skips this audit and
reads only the plan-doc's tables receives a clean substrate; a reader
who skips the implementation work and reads both this audit and the
plan-doc receives both the original tables and the corrections.

## 3. Substrate-drift check

The plan-doc branch (`chore/randomx-v2-phase2c-plan`, 22 commits) was
forked from `dev` at `fe7bc97d5` (the PR #64 Phase 2b merge commit).
The pre-merge `dev` tip when PR #65 merged was also `fe7bc97d5`. Zero
commits landed on `dev` between fork and merge. The merge commit is
`5df8bd2c2`; reachable-from-`dev` but not-from-`fe7bc97d5` is exactly
the 22 plan-doc commits plus the merge commit itself.

```text
$ git log --oneline fe7bc97d5..fe7bc97d5
(empty)

$ git diff --name-only fe7bc97d5..5df8bd2c2 -- \
    rust/shekyl-pow-randomx/ \
    rust/shekyl-ffi/ \
    external/randomx-v2/ \
    rust/Cargo.toml
(empty)
```

**Verdict.** No RandomX-relevant substrate moved between the plan-doc's
write-time pin and this audit's execution pin. Per
`16-architectural-inheritance.mdc`'s continuous-discipline corollary,
this is the expected outcome: continuous application of the
discipline produces the same outcome as retroactive migration at
substantially lower total cost; the substrate drift check confirms the
continuity held across PR #65's review window.

## 4. Surface-by-surface results

| # | Surface | Plan-doc location | Verdict |
|---|---------|-------------------|---------|
| 1 | Dependency table (Phase 2a/2b providers consumed by 2c) | §4.1 (9 rows) | 8 rows verify byte-perfect; 1 row (criterion dev-dep claim) needs clarification — **F1** |
| 2 | `randomx_reciprocal` visibility | §4.1 row 6 + §4.3 | Confirmed: currently private `fn` at `superscalar.rs:1520`; 2c promotes to `pub(crate) fn` as planned |
| 3 | Frozen `dispatch_instruction` signature | §5.1.1 surface 1 | Confirmed against `bytecode_machine.hpp:46-65` IBC pattern + `bytecode_machine.hpp:145-268` handler bodies |
| 4 | Frozen `Instruction` field set | §5.1.1 surface 2 | Confirmed against v2 fork's `instruction.hpp` (Round-5 plan-doc table reads the spec §5.1 layout correctly) |
| 5 | Frozen `VmState` field set | §5.1.1 surface 3 | Field-set rows confirmed against `bytecode_machine.hpp` opcode handlers + `virtual_machine.hpp:69-85` per-VM state; **opcode-count statement off-by-one** — **F2** |
| 6 | `mp` correction precedent | §5.5 F5 row 1, §5.11.8 | Confirmed: `vm_interpreted.cpp:89` is `auto& mp = (randomx_vm::getFlags() & RANDOMX_FLAG_V2) ? mem.ma : mem.mx;`; `common.hpp:184-187`'s `MemoryRegisters` has only `mx, ma, memory` |
| 7 | V2-only simplification table rows 1, 2, 4, 6, 7, 8 | §5.5 F5 | Verified clean (six of eight rows) |
| 8 | V2-only simplification row 3 (`bytecode_machine.hpp:263`) | §5.5 F5 | **Substantive miscategorization** — **F3** |
| 9 | V2-only simplification row 5 (`program.hpp:46-48`) | §5.5 F5 | **Line citation off by ~10 lines** — **F4** |
| 10 | `ShekylU128` audit (only `u128` site in `shekyl-pow-randomx`) | §5.10 | Confirmed: `mulh()` at `superscalar.rs:1486` is the only production `u128` site (plus its `mulh_*` test and its rustdoc) |
| 11 | Cross-plan-doc consistency (2d skeleton §1 frozen field set) | 2d skeleton §1 vs 2c §5.1.1 | Confirmed: 2d's table mirrors 2c's exactly; the "2c wins" tie-break is documented |
| 12 | Threat-model substrate (six attack objectives) | §5.11 | No substrate shift; the disciplines (T1'/T2' determinism, `debug_assert!`, debug-vs-release equivalence, audit-against-source) are encoded in plan-doc and will encode into implementation |
| 13 | Scope-discipline pre-flight (out-of-scope §2.1) | §2.1 | All six "while we're here" temptations (reciprocal cache, F128 newtype, real dispatch, CFROUND throttling, FPU unsafe block, VmState pool) are pre-named by the plan-doc |
| 14 | Module layout precondition | §3 | Confirmed: `rust/shekyl-pow-randomx/src/` contains `argon2d.rs`, `aes.rs`, `blake2_generator.rs`, `superscalar.rs`, `lib.rs`; `cache.rs` and `vm.rs` do not yet exist |
| 15 | Fork pin | "Fork pin" line in header | Confirmed: submodule `aaafe71322df6602c21a5c72937ac284724ae561` matches `aaafe71` in plan-doc header |
| 16 | Substrate drift since plan-branch fork | — | **Zero** drift (per §3 above) |

## 5. Findings

### F1 — `criterion` is implementation-PR work, not pre-existing dev-dep *(clarity)*

**Plan-doc claim** (§4.2):

> ### 4.2 `criterion = "0.5"` (already DEV-only)
>
> Already in workspace via Phase 2b's bench setup. Used for
> `benches/cache_derive.rs` and `benches/compute_hash_alloc.rs`. No
> version bump needed.

**Verification.**

- `rust/shekyl-pow-randomx/Cargo.toml` contains no `[dev-dependencies]`
  section and no `criterion` entry. It currently declares only
  `aes`, `blake2`, and `argon2`.
- `rust/Cargo.toml`'s `[workspace.dependencies]` does not list
  `criterion`.
- Other crates using `criterion` declare it directly:
  - `rust/shekyl-scanner/Cargo.toml:54`: `criterion = { version = "0.5", features = ["html_reports"] }`
  - `rust/shekyl-engine-state/Cargo.toml:49`: same form
  - `rust/shekyl-engine-file/Cargo.toml:39`: same form
- `rust/shekyl-pow-randomx/` has no `benches/` directory (Phase 2b
  shipped `tests/` + reference vectors + generators, but no
  criterion-driven benches).

**Disposition.** The plan-doc's "No version bump needed" claim is
accurate (the version `0.5` is established by other workspace
crates). The "Already in workspace via Phase 2b's bench setup"
framing is wrong — Phase 2b did not establish a bench setup in
`shekyl-pow-randomx`. The implementation PR's commit 8 (per §9 commit
granularity) must add the dev-dep entry to
`rust/shekyl-pow-randomx/Cargo.toml`:

```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
```

mirroring the pattern in `shekyl-scanner`, `shekyl-engine-state`, and
`shekyl-engine-file`.

**Plan-doc errata applied.** §4.2 rephrased to name the addition
explicitly. See sibling commit on this branch.

### F2 — §5.1.1 audit-grep count off-by-one *(factual; field-set unaffected)*

**Plan-doc claim** (§5.1.1):

> **Audit command (Round 3 deliverable; re-verified at
> implementation-PR time):**
>
> ```bash
> grep -nE 'static void exe_' external/randomx-v2/src/bytecode_machine.hpp
> ```
>
> 29 hits (one per opcode).

**Verification.** Re-running the same command at the audit pin
produces **28 hits**, not 29:

```text
$ grep -nE 'static void exe_' external/randomx-v2/src/bytecode_machine.hpp | wc -l
28
```

The 28 handlers are: `exe_{IADD_RS, IADD_M, ISUB_R, ISUB_M, IMUL_R,
IMUL_M, IMULH_R, IMULH_M, ISMULH_R, ISMULH_M, INEG_R, IXOR_R, IXOR_M,
IROR_R, IROL_R, ISWAP_R, FSWAP_R, FADD_R, FADD_M, FSUB_R, FSUB_M,
FSCAL_R, FMUL_R, FDIV_M, FSQRT_R, CBRANCH, CFROUND, ISTORE}` at lines
145–268.

The 29th spec opcode (IMUL_RCP) has **no** dedicated handler in the
header. It dispatches through `exe_IMUL_R` via the compile pass at
`bytecode_machine.cpp:75`:

```cpp
case InstructionType::IMUL_RCP: //executed as IMUL_R
default:
    UNREACHABLE;
```

`BytecodeMachine::compileInstruction` (`bytecode_machine.cpp` ~lines
245–260) sets `ibc.type = IMUL_R` when the opcode falls into the
IMUL_RCP range and points `ibc.isrc` at the precomputed reciprocal
in `reciprocalCache`. The execute pass dispatches on `ibc.type`,
which is IMUL_R, which fires `exe_IMUL_R`.

**Field-set impact.** None. IMUL_RCP's `VmState` field requirements
are a subset of IMUL_R's (same `r[]` reads and writes; the `isrc`
pointer indirection inside the handler resolves through the same
`int_reg_t*` typedef regardless of whether the source operand is a
real register or the precomputed reciprocal stored in the IBC).

**Disposition.** Cosmetic factual correction. The §5.1.1 audit-grep
count statement is amended; the field-set table is unchanged.

**Plan-doc errata applied.** §5.1.1 count statement corrected. See
sibling commit on this branch.

### F3 — §5.5 F5 row 3 conflates CFROUND throttling with non-existent imm32 cap *(substantive; misdirects 2d implementation)*

**Plan-doc claim** (§5.5 F5 row 3):

> `bytecode_machine.hpp:263` — `if ((flags & V2) == 0 || (isrc & 60) == 0)`
> **IADD_M/ISUB_M/IMUL_M imm32 cap** | take v2 branch (the cap applies)
> | `dispatch_instruction`'s memory-instruction imm32 handling caps to
> first 6 bits unconditionally (relevant to 2d's bytecode dispatch;
> 2c's stub-NOP `dispatch_instruction` body carries no integer ops,
> but the F5 discipline forward-pointer ensures 2d's body replacement
> inherits the v2-only cap).

**Verification.** Reading `bytecode_machine.hpp:261-266`:

```cpp
static void exe_CFROUND(RANDOMX_EXE_ARGS) {
    uint64_t isrc = rotr(*ibc.isrc, ibc.imm);
    if (((flags & RANDOMX_FLAG_V2) == 0) || ((isrc & 60) == 0)) {
        rx_set_rounding_mode(isrc % 4);
    }
}
```

The conditional at line 263 belongs to **`exe_CFROUND`** (line 261).
The semantics:

- In v1 (`(flags & V2) == 0`), CFROUND fires unconditionally on
  every CFROUND instruction.
- In v2 (`(isrc & 60) == 0` — bits 2 through 5 of the rotated source
  must be clear), CFROUND fires only on a ~1/64 fraction of
  instructions. This is the **v2-only CFROUND throttling**: it
  prevents adversarial seedhashes from producing programs that
  re-set the FPU rounding mode every iteration, which would
  pessimize miner performance and create a Phase 0 §6 worst-case
  timing exposure.

The plan-doc's "IADD_M/ISUB_M/IMUL_M imm32 cap" claim describes a
feature that **does not exist** in the C reference. A spot-check of
the `compileInstruction` site for memory-form integer instructions
in `bytecode_machine.cpp` (lines 92–142, 164–204, 232–250) shows
all M-form `imm32` fields are full 32-bit sign-extended via
`signExtend2sCompl(instr.getImm32())`; there is no
v1/v2 differential cap. The "caps to first 6 bits" framing is a
mis-summary of CFROUND's `isrc & 60` mask (which tests bits 2–5 of
the rotated source register, not "first 6 bits of imm32 in memory
instructions").

The forward-pointer carries through to a different 2d obligation
than what the plan-doc stated:

- **Wrong** (per plan-doc): 2d's memory-instruction handlers (IADD_M,
  ISUB_M, IMUL_M) inherit a v2-only imm32 cap.
- **Right**: 2d's CFROUND handler inherits the v2-only `(isrc & 60) == 0`
  throttling — only fires when bits 2–5 of the rotated source are
  clear, structurally throttling rounding-mode changes to ~1/64
  iterations. No `cfg(v1)` shim; the throttle applies unconditionally
  in the v2-only Rust port.

**Implementation impact at Phase 2c.** None directly (2c is stub-NOP
dispatch; neither CFROUND nor IADD_M execute). The miscategorization
matters because the forward-pointer to 2d is wrong: 2d's author
following the uncorrected plan-doc might (a) implement a non-existent
memory-instruction imm32 cap and produce code divergent from the
C reference (consensus-split surface — exactly the Objective 6 the
mp-correction precedent guards against), or (b) miss the CFROUND
throttling entirely.

This finding is the same class as the mp correction recorded in
§5.5 F5 row 1 / §5.11.8: a prompted-list table entry that looks
plausible until the cited source is read. The R5 §5.11.8 enforcement
("the audit's value is in the reading-the-source step") is the
operational defense; this audit is its application.

**Plan-doc errata applied.** §5.5 F5 row 3 rewritten to describe
CFROUND's v2-only throttling correctly, with the corrected forward-
pointer to 2d's CFROUND handler. See sibling commit on this branch.

### F4 — §5.5 F5 row 5 line citation off *(factual; semantic claim correct)*

**Plan-doc claim** (§5.5 F5 row 5):

> `program.hpp:46-48` — `Program::getSize(flags)` returning `_V1=256`
> or `_V2=2048` | `PROGRAM_SIZE = 2048` | Rust constant
> `pub(crate) const PROGRAM_SIZE: usize = 2048;` (no flags param).

**Verification.** Reading `program.hpp:44-58`:

```cpp
class Program {
public:
    Instruction& operator()(int pc) {
        return programBuffer[pc];
    }
    // ...
    static uint32_t getSize(randomx_flags flags) {
        return (flags & RANDOMX_FLAG_V2) ? RANDOMX_PROGRAM_SIZE_V2 : RANDOMX_PROGRAM_SIZE_V1;
    }
```

Lines 46–48 are `operator()` (the instruction accessor by program
counter), not `getSize`. The actual `Program::getSize` is at lines
**56–58**. The semantic claim is correct (`getSize` returns V1=256
or V2=2048 based on the flag bit; v2-only Rust port hardcodes 2048
via `pub(crate) const PROGRAM_SIZE: usize = 2048;`); only the line
citation drifted.

**Disposition.** Cosmetic factual correction.

**Plan-doc errata applied.** §5.5 F5 row 5 citation updated to
`program.hpp:56-58`. See sibling commit on this branch.

## 6. Confirmed surfaces (no errata)

The following surfaces verify cleanly against the audit pin. Each
is recorded here so a future audit cycle can spot-check the
audit-against-source discipline against the confirmed surface, not
only against the errata surfaces.

### 6.1 §4.1 dependency table — confirmed rows

| Phase 2c consumer | Provider | Cite verified |
|-------------------|----------|---------------|
| `Cache::derive` | `argon2d::fill_cache(key: &[u8], blocks: &mut [Block])` | `argon2d.rs:165` `pub(crate) fn fill_cache(key: &[u8], blocks: &mut [Block])` |
| `Cache::derive` | `blake2_generator::Blake2Generator::{new, get_byte, get_uint32}` | `blake2_generator.rs:107` (`new`), `:128` (`get_byte`), `:145` (`get_uint32`) — all `pub(crate)` |
| `Cache::derive` | `superscalar::generate_superscalar(gen: &mut Blake2Generator) -> SuperscalarProgram` | `superscalar.rs:1227` `pub(crate) fn generate_superscalar(gen: &mut Blake2Generator) -> SuperscalarProgram` |
| `Cache::derive_item` | `superscalar::execute_superscalar(program: &SuperscalarProgram, registers: &mut [u64; REGISTERS_COUNT])` | `superscalar.rs:1427` (note: actual signature uses `REGISTERS_COUNT = 8` const at `superscalar.rs:151`, semantically identical to `[u64; 8]`) |
| `Cache::derive_item` | `superscalar::randomx_reciprocal(divisor: u32) -> u64` | `superscalar.rs:1520` `fn randomx_reciprocal(divisor: u32) -> u64` (currently private; 2c promotes to `pub(crate)`) |
| `VmState::new` (scratchpad init) | `aes::fill_aes_1r_x4(state: &mut [u8; 64], output: &mut [u8])` | `aes.rs:253` `pub(crate) fn fill_aes_1r_x4(state: &mut [u8; 64], output: &mut [u8])` |
| `VmState::new` (program parse) + `compute_hash` (F/E mix) | `aes::fill_aes_4r_x4(state: &[u8; 64], output: &mut [u8])` | `aes.rs:312` `pub(crate) fn fill_aes_4r_x4(state: &[u8; 64], output: &mut [u8])` |
| `compute_hash::finalize` | `aes::hash_aes_1r_x4(input: &[u8], hash: &mut [u8; 64])` | `aes.rs:392` `pub(crate) fn hash_aes_1r_x4(input: &[u8], hash: &mut [u8; 64])` |

**Implementation note.** `execute_superscalar`'s parameter type is
`&mut [u64; REGISTERS_COUNT]` where `REGISTERS_COUNT = 8` is a
`pub(crate) const` at `superscalar.rs:151`. The plan-doc's
`[u64; 8]` spelling is semantically identical (the same monomorphized
type); the implementation in `cache.rs::derive_item` should prefer the
named constant for consistency with the source pattern.

### 6.2 §5.1.1 `VmState` field set — confirmed rows

The field-set audit reads cleanly against the audit pin. Each
"Required for `dispatch_instruction`" row's C-reference cite is
verified:

| Field | Cite verified |
|-------|---------------|
| `r: [u64; 8]` | `bytecode_machine.hpp:40` `int_reg_t r[RegistersCount] = { 0 };` inside `NativeRegisterFile` (lines 39–44) |
| `f: [F128; 4]` | `bytecode_machine.hpp:41` `rx_vec_f128 f[RegisterCountFlt];` |
| `e: [F128; 4]` | `bytecode_machine.hpp:42` `rx_vec_f128 e[RegisterCountFlt];` |
| `a: [F128; 4]` | `bytecode_machine.hpp:43` `rx_vec_f128 a[RegisterCountFlt];` |
| `fprc: u32` | Not present in `NativeRegisterFile`/`MemoryRegisters`; C reference uses thread-global FPU state via `rx_set_rounding_mode` (`intrin_portable.h:174`, called from `bytecode_machine.hpp:264` inside `exe_CFROUND`). The Rust port adds the field to `VmState` because `#![deny(unsafe_code)]` makes thread-global FPU state hard to plumb portably; the actual FPU mode is set in 2d per F2c. |
| `scratchpad: Box<[u8; SCRATCHPAD_L3]>` | `virtual_machine.hpp:75` `uint8_t* scratchpad = nullptr;` (per-VM heap allocation) |
| `e_mask: [u64; 2]` | `program.hpp:40` `uint64_t eMask[2];` inside `ProgramConfiguration` (lines 39–42) |

The "Required for `VmState::run` iteration loop only" rows verify
analogously against `virtual_machine.hpp:69-85`:

| Field | Cite verified |
|-------|---------------|
| `ma: u32`, `mx: u32` | `common.hpp:184-187` `struct MemoryRegisters { addr_t mx, ma; uint8_t* memory = nullptr; };` |
| `read_reg: [u32; 4]` | `program.hpp:41` `uint32_t readReg0, readReg1, readReg2, readReg3;` inside `ProgramConfiguration` |
| `dataset_offset: u64` | `virtual_machine.hpp:80` `uint64_t datasetOffset;` |
| `program: Box<Program>` | `virtual_machine.hpp:71` `alignas(64) randomx::Program program;` |
| `temp_hash: [u64; 8]` | `virtual_machine.hpp:84` `alignas(16) uint64_t tempHash[8];` |

The "Explicitly NOT in `VmState`" rows (`mp`, `vm_flags`, `cache_key`,
`register_usage`, `sp_addr0/sp_addr1`, `&Cache` borrow) verify
analogously; the mp row in particular is the §5.11.8 precedent and is
re-verified above.

### 6.3 §5.5 F5 v2-only simplification table — confirmed rows

| Row | Cite verified |
|-----|---------------|
| 1 (`vm_interpreted.cpp:89` mp alias) | `auto& mp = (randomx_vm::getFlags() & RANDOMX_FLAG_V2) ? mem.ma : mem.mx;` |
| 2 (`vm_interpreted.cpp:99` F/E AES mix V2 branch) | `if (randomx_vm::getFlags() & RANDOMX_FLAG_V2) {` |
| 4 (`virtual_machine.hpp:63-66` setFlagV2/clearFlagV2) | `virtual void setFlagV2() { vmFlags |= RANDOMX_FLAG_V2; }` and the corresponding clearer |
| 6 (`common.hpp:51-54, 98-102` V1+V2 static_asserts) | Lines 51–54 are the four `static_assert(RANDOMX_PROGRAM_SIZE_V{1,2} {>, <=} N, "...");` assertions; lines 98–102 are the four `static_assert(... RANDOMX_PROGRAM_SIZE_V{1,2} ...);` unsafe-configuration assertions |
| 7 (`configuration.h:56` `#define RANDOMX_PROGRAM_SIZE_V1 256`) | Exact match |
| 8 (`randomx.h:52` `RANDOMX_FLAG_V2 = 128` enum value) | Exact match |

### 6.4 §5.10 ShekylU128 audit

Re-running the equivalent `rg u128 rust/shekyl-pow-randomx/src/` at
the audit pin produces:

```text
superscalar.rs:1481  /// `u64 -> u128` widening is lossless; the `>>` produces a value in
superscalar.rs:1483  /// `const fn` because `u128::From` is not yet stable as a const
superscalar.rs:1487      ((u128::from(a) * u128::from(b)) >> 64) as u64
superscalar.rs:1569              assert_eq!(mulh(a, b), ((u128::from(a) * u128::from(b)) >> 64) as u64);
```

The only production `u128` site is `mulh()` (lines 1481–1487 inclusive
of rustdoc); the test cite (1569) is `mulh_and_smulh_agree_with_widening_multiplication`.
Plan-doc disposition (no `ShekylU128` translation) stands.

### 6.5 Threat-model substrate

The six attack objectives (§5.11):

1. **Mining-faster differential.** Substrate is 2g (differential
   harness) + 3a (FFI shim) work. No 2c-time substrate; no audit
   surface change.
2. **Cache poisoning.** 2c-time substrate via `Cache::derive`. The
   underlying primitives (argon2d, blake2_generator, superscalar)
   are 2a/2b work, audited at their respective pins. T1' / T2'
   determinism property tests are the in-scope defense. Substrate
   unchanged.
3. **FFI exploit.** Substrate is 3a work. No 2c substrate.
4. **Resource DoS.** 2c-time substrate via the 256 MB cache and 2 MB
   scratchpad allocations; their sizes are constant per spec, so
   the substrate is fixed by spec, not by 2c-implementation choice.
   `CacheStore` / `VmState` pool decisions are 2f work.
5. **Rust safety boundary gaps.** 2c-time substrate via the two
   `Box::new_zeroed_slice` carve-outs; `debug_assert!` discipline
   per §5.11.2 is the in-scope defense.
6. **Consensus split via implementation divergence.** 2c-time
   substrate via `Cache::derive_item`'s superscalar-hash chain and
   the eventual 2d integer-opcode dispatch. Debug-vs-release
   equivalence (§5.11.3) and audit-against-source (§5.11.8) are
   the in-scope defenses. **F3 above is itself a §5.11.8 catch —
   a plan-doc table entry that would have misdirected 2d's CFROUND
   implementation toward a non-existent v2 feature.**

**Verdict.** No threat-model substrate has shifted. The four findings
in §5 of this audit reinforce the §5.11.8 discipline rather than
expand the threat surface.

### 6.6 Scope-discipline pre-flight

The six "while we're here" temptations the plan-doc pre-names in §2.1
(reciprocal cache; F128 newtype; real opcode dispatch; CFROUND
throttling; FPU rounding-mode `unsafe`; `VmState` pool) all remain
out of 2c scope. F3's correction (CFROUND throttling is the actual
v2-only feature at line 263, not memory-instruction imm32 capping)
**does not** expand 2c's scope — CFROUND implementation is still 2d's
work; the correction only fixes the plan-doc's forward-pointer to
2d's CFROUND handler.

## 7. Disposition for the Phase 2c implementation PR

Per the §4.1 verification gate, the implementation PR can proceed
after the audit-surfaced corrections land. The disposition for each
finding:

| Finding | Sibling commit | Implementation impact |
|---------|----------------|------------------------|
| F1 (criterion dev-dep) | Plan-doc §4.2 rephrased | Implementation commit 8 adds `criterion` to `shekyl-pow-randomx/Cargo.toml` `[dev-dependencies]` (per the same pattern as `shekyl-scanner` et al.) |
| F2 (29 vs 28 hits) | Plan-doc §5.1.1 count corrected | None — field-set table unchanged |
| F3 (CFROUND vs imm32 cap) | Plan-doc §5.5 F5 row 3 rewritten | None at 2c (stub-NOP dispatch executes neither CFROUND nor IADD_M); 2d inherits the corrected CFROUND throttling forward-pointer |
| F4 (program.hpp citation) | Plan-doc §5.5 F5 row 5 citation updated | None — semantic disposition unchanged |

The implementation PR thus proceeds against a corrected plan-doc.
The audit doc (this file) is the evidence trail per §5.11.8's "show
your work" amendment: every disposition is backed by a line-range
citation at the audit pin; a future reviewer can spot-check by opening
the cited file at `aaafe71` and reading the named lines.

## 8. Round history

| Round | Date | Outcome |
|-------|------|---------|
| Round 0 (audit) | 2026-05-21 | Pre-implementation re-verification of plan-doc claims against substrate at branch-cut pin. Substrate-drift check confirmed zero RandomX-relevant movement between plan-branch fork (`fe7bc97d5`) and PR #65 merge (`5df8bd2c2`). Four findings surfaced: F1 (clarity — criterion dev-dep), F2 (factual — 29 vs 28 grep hits), F3 (substantive — CFROUND throttling vs non-existent imm32 cap), F4 (factual — program.hpp citation off ~10 lines). All four addressed via sibling plan-doc errata commits on `feat/randomx-v2-phase2c-impl` before any implementation code lands. F3 is the second instance (after the `mp` correction at Round 3 D1) of the §5.11.8 audit-against-actual-code discipline catching a prompted-list table entry that would have misdirected downstream implementation. Posture-shift note: §5.11.8's "audits-are-clean-so-compress" anti-pattern protection held — the audit produced findings precisely because it did the reading-the-source work rather than re-summarizing the plan-doc tables. |

## 9. Cross-references

- **Parent plan.** [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §"Track A — Phase 2" sub-PR 2c.
- **Audited document.** [`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) post-PR-#65 merge state at `5df8bd2c2`.
- **Downstream substrate.** [`RANDOMX_V2_PHASE2D_PLAN.md`](./RANDOMX_V2_PHASE2D_PLAN.md) §1 (frozen field set carries 2c's; F3's CFROUND correction reaches 2d via the §5.5 F5 row 3 errata).
- **Discipline anchors.** §5.11.8 of the audited plan-doc (audit-against-actual-code); `.cursor/rules/16-architectural-inheritance.mdc` (continuous-discipline corollary; audits-are-clean-so-compress anti-pattern); `.cursor/rules/91-documentation-after-plans.mdc` (stale-doc detection — the doc update is not optional when the doc references behavior that doesn't exist).
- **Pin.** `external/randomx-v2` submodule at `aaafe71322df6602c21a5c72937ac284724ae561`. Every line-range citation in this audit is stable against that pin.
