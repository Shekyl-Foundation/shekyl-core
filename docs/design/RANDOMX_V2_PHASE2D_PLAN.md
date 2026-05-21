# RandomX v2 — Track A Phase 2d plan (skeleton scaffold)

**Status.** Skeleton scaffold landed 2026-05-21 as a deliverable of
Phase 2c Round 3 (R3-D3) — _not_ a Round 1 design. This document
records the 2c → 2d hand-off contract, the locked-by-2c surfaces, the
forward-actions 2c accumulated for 2d, and the decision points 2d's
Round 1 must address. Round 1 of Phase 2d populates this scaffold;
this commit only puts the scaffold in place so 2d's author does not
have to reconstruct the 2c-locked items from plan-doc prose.

**Parent plan.** [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md)
§"Track A — Phase 2" sub-PR 2d is the binding one-line scope
("Implement v2 bytecode dispatch — real per-opcode dispatch
replacing 2c's `dispatch_instruction` NOP stub body in place; FPU
rounding-mode plumbing; `F128` newtype extraction if needed").

**2c precedent.**
[`RANDOMX_V2_PHASE2C_PLAN.md`](./RANDOMX_V2_PHASE2C_PLAN.md) §5.1.1
"Function-body replacement contract" pins the hand-off. The contract
is reproduced verbatim in §1 below so Phase 2d's review does not
require chasing the 2c diff to find what was frozen.

**Base commit.** `dev` at the post-PR-2c-merge tip (TBD). Phase 2d's
branch (`feat/randomx-v2-phase2d`) cuts from there.

**Branches.**

- `chore/randomx-v2-phase2d-plan` (Phase 2d Round 1 design doc; cut
  after 2c lands; expands this skeleton into a reviewable Round 1
  document per the 2b/2c precedent).
- `feat/randomx-v2-phase2d` (implementation; cut from
  post-Round-1-design-doc `dev`).

**Cross-references.**

- **Contract source.** `RANDOMX_V2_PHASE2C_PLAN.md` §5.1.1.
- **Field-set audit source.** `RANDOMX_V2_PHASE2C_PLAN.md` §5.1.1
  (audit table populated against `bytecode_machine.hpp` opcode
  handlers; correction-from-prompt finding for `mp` documented).
- **Spec.** `external/randomx-v2/doc/specs.md` §5 (instruction set),
  §5.1 (instruction encoding), §5.2 (FPU semantics), §5.2.5
  (CFROUND), §5.3 (memory addressing).
- **C reference.** `external/randomx-v2/src/bytecode_machine.{cpp,hpp}`
  (29 opcode handlers), `external/randomx-v2/src/vm_interpreted.cpp`
  (iteration loop integration), `external/randomx-v2/src/intrin_portable.h`
  (FPU rounding-mode primitives + `rx_vec_f128` operations).
- **Cursor rules.** `30-cryptography.mdc` (constant-time discipline
  for any unsafe code), `35-secure-memory.mdc` (no secret material
  in dispatch), `21-reversion-clause-discipline.mdc` (decision-point
  framing).

---

## 1. Function-body replacement contract (carry-forward from 2c §5.1.1)

The contract has three frozen surfaces. Each is reproduced here
verbatim from `RANDOMX_V2_PHASE2C_PLAN.md` §5.1.1; the authoritative
form lives in 2c's plan doc. If the two diverge in future edits, 2c's
plan doc wins (2c's review fixed the contract; 2d's review fixes the
implementation against the contract).

### Frozen surface 1: `dispatch_instruction` signature

```rust
fn dispatch_instruction(instr: &Instruction, state: &mut VmState)
```

2d cannot:

- Add parameters.
- Add a return value.
- Change the lifetime/borrow shape.
- Restructure as an IBC-style 2-pass design (see Reopening criterion
  in 2c §5.1.1; reopening requires benchmark evidence per
  `21-reversion-clause-discipline.mdc`, not preference).

### Frozen surface 2: `Instruction` field set

```rust
struct Instruction {
    opcode: u8,
    dst: u8,
    src: u8,
    mod_: u8,
    imm32: u32,
}
```

2d cannot add fields. Per RandomX spec §5.1.

### Frozen surface 3: `VmState` field set (locked by 2c)

Required for `dispatch_instruction` (audit source:
`bytecode_machine.hpp:145-270`):

| Field | Type | Used by opcode(s) |
|-------|------|-------------------|
| `r` | `[u64; 8]` | All integer R-form, integer M-form, ISTORE, CBRANCH |
| `f` | `[F128; 4]` | FADD_R, FADD_M, FSUB_R, FSUB_M, FSCAL_R, FSWAP_R |
| `e` | `[F128; 4]` | FMUL_R, FDIV_M, FSQRT_R |
| `a` | `[F128; 4]` | Read-only operand (FADD_R, FSUB_R, FMUL_R `fsrc`) |
| `fprc` | `u32` | CFROUND |
| `scratchpad` | `Box<[u8; SCRATCHPAD_L3]>` | All M-opcodes + ISTORE |
| `e_mask` | `[u64; 2]` | FDIV_M |

Required for `VmState::run` iteration loop only
(`dispatch_instruction` does NOT read these):

| Field | Type |
|-------|------|
| `ma` | `u32` |
| `mx` | `u32` |
| `read_reg` | `[u32; 4]` |
| `dataset_offset` | `u64` |
| `program` | `Box<Program>` |
| `temp_hash` | `[u64; 8]` |

Explicitly NOT in `VmState` (per 2c §5.1.1 audit): `mp` (v2-only
local alias for `mem.ma`); `vm_flags` (v2 is structural); `cache_key`
(metadata); `register_usage` (single-pass dispatch has no compile
pass); `sp_addr0`/`sp_addr1` (per-iteration locals); `&Cache` borrow
(passed to `VmState::run` as parameter; `compute_hash` owns it).

**2d-side audit re-verification.** When 2d Round 1 lands, re-run the
2c §5.1.1 audit-grep command and confirm no opcode handler in the v2
fork at the then-current pin requires a `VmState` field absent from
the table above. If any field is needed beyond the table, the
addition is a documented 2d Round 1 amendment to 2c's §5.1.1 — not
silent extension.

---

## 2. Forward-actions accumulated from 2c

Each Phase 2c finding (F1, F2, F3, F5, F7) generated a 2d-bound
forward-action. These are the items 2d Round 1 must address; they
are not 2d-time decisions to be re-litigated (2c locked them) but
are the obligations 2d takes on by virtue of being the dispatch PR.

### F1 forward-action: replace `dispatch_instruction` NOP body

Per 2c §5.1.1: the function-body diff is scoped to
`dispatch_instruction`'s implementation. `compute_hash`'s signature
is unchanged; `VmState`'s field set is unchanged (modulo any
re-audit additions). 2d's PR is the body diff plus tests; nothing
else.

### F2 forward-action: FPU rounding-mode plumbing

Per 2c §5.2 F2c: 2c uses the host's default FP rounding mode (RN on
every standard platform) because stub-NOP dispatch executes no FP
arithmetic. 2d wires CFROUND, FADD_*, FSUB_*, FMUL_R, FDIV_M,
FSQRT_R — each of which either reads `fprc` or executes under it.
The plumbing decision is a 2d Round 1 decision point (see §3 below).

### F3 forward-action: `F128` newtype extraction

Per 2c §5.3 F3a: 2c uses `[f64; 2]` raw for FP register fields. 2d
extracts an `F128([f64; 2])` newtype if bytecode dispatch reveals a
sufficient API surface (e.g., `add_unrestricted`, `sub_unrestricted`,
`mul_unrestricted`, `div_masked`, `sqrt_unrestricted` per spec §5.2's
arithmetic semantics). If 2d's dispatch can be written cleanly with
raw `[f64; 2]` and inline helpers, no newtype is needed. Newtype
shape is a 2d Round 1 decision point (see §3 below).

### F5 forward-action: CFROUND v2-only discipline carry-forward

Per 2c §5.5 F5 ("CFROUND forward-pointer"): the C reference's
`exe_CFROUND` handler (`bytecode_machine.hpp:261-266`) carries a
v2-form gate (`if (((flags & RANDOMX_FLAG_V2) == 0) || ((isrc & 60)
== 0))`) that throttles the rounding-mode setter under v1. The Rust
port deletes the v1 form: no `cfg(v1)` shim, no version-gated CFROUND
handler. The v2 form (rounding-mode set iff the high 6 bits of the
rotated source are zero) is structural. **2d implements this as the
sole CFROUND body.** No flag check, no version branch.

### F7 forward-action: FP rounding-mode invariant under real arithmetic

Per 2c §5.7 F7 (T7/T8 entries): 2c's test inputs are constrained to
IEEE 754 exact-integer-representation range so test outputs are
rounding-mode-insensitive. **Once 2d wires real FP arithmetic, the
constraint becomes load-bearing.** Tests that exercise FADD_*/FSUB_*/
FMUL_R/FDIV_M/FSQRT_R with rounding-mode-sensitive inputs must
establish their rounding mode explicitly (via CFROUND's plumbing
once F2 lands) and compare against generator output produced under
the same mode. **2d's test corpus extends 2c's T1–T8 matrix with
T9+ tests for per-opcode arithmetic correctness, each carrying an
explicit rounding-mode disposition in its `.meta.txt`.**

---

## 3. Decision points for 2d Round 1

The items below are **not** pre-decided by 2c. They are the
substantive design choices Phase 2d's Round 1 (the to-be-drafted
`RANDOMX_V2_PHASE2D_PLAN.md` Round 1 design doc, expanding this
scaffold) must close. Each is framed as a question + an option
enumeration; 2d Round 1 selects with reasoning.

### 3.1 FPU rounding-mode mechanism

**Question.** How does Rust set the host's IEEE 754 rounding mode
under `#[deny(unsafe_code)]`?

Options (none pre-selected):

- **(a) Quarantined-`unsafe` block** wrapping
  `core::arch::x86_64::_MM_SET_ROUNDING_MODE` (x86_64) and
  `aarch64::__set_fpcr` (aarch64) intrinsics. Smallest dependency
  footprint; satisfies `30-cryptography.mdc` constant-time
  discipline (the intrinsic is a single MXCSR/FPCR write).
  Requires per-arch dispatch + a `#[allow(unsafe_code)]` carve-out
  with `// SAFETY:` doc-comment per `35-secure-memory.mdc`.
- **(b) Inline assembly** via `core::arch::asm!`. Stable since
  1.59. Strictly more dependency-free than (a) (no intrinsic
  wrapper crate). Same per-arch dispatch. Same `unsafe` carve-out.
- **(c) Third-party crate** (e.g., a hypothetical
  `fenv-stable` or maintained-fork-of-`float-rounding-mode`).
  Pushes the `unsafe` into a vendored audit surface. Adds workspace
  dependency per `17-dependency-discipline.mdc`'s verification
  protocol. Decision burden: prove the crate's audit posture
  meets `30-cryptography.mdc`.
- **(d) Pure-software rounding** (manual round-to-nearest /
  round-down / round-up / round-zero implementations in safe Rust,
  bypassing the FPU's rounding hardware). No `unsafe`; significant
  per-operation overhead; risks correctness drift from the C
  reference's exact bit patterns. Likely rejected on
  performance-and-correctness grounds but enumerated for completeness.

2d Round 1 evaluates each against `17-dependency-discipline.mdc`,
`30-cryptography.mdc`, and Phase 0's ≤3.0× performance budget.

### 3.2 `F128` newtype shape

**Question.** Does Phase 2d extract an `F128` newtype, and if so
with what surface?

Options:

- **(a) No newtype.** Continue with raw `[f64; 2]` in `VmState`'s
  `f`/`e`/`a` fields. Dispatch body inlines the per-opcode FP math
  directly. Lowest abstraction cost; highest risk of per-call-site
  drift.
- **(b) Minimal newtype.** `struct F128([f64; 2])` with `Copy`,
  `Debug`, plus only the methods bytecode dispatch directly needs
  (FADD_R: `add_unrestricted`; FSUB_R: `sub_unrestricted`; FMUL_R:
  `mul_unrestricted`; FDIV_M: `div_masked`; FSQRT_R:
  `sqrt_unrestricted`; FSWAP_R: `swap_lanes`; FSCAL_R:
  `xor_with_scale_mask`). Methods are 1-3 lines each, mapping
  directly to spec §5.2 semantics.
- **(c) Full newtype.** As (b) plus integer-encoding/decoding
  helpers (`from_raw_bits`, `to_raw_bits`), conversion from
  scratchpad-packed-int form (per spec §4.5.4 — the F/E AES mix
  input conversion), and arithmetic-mode-aware operations. Larger
  surface; better encapsulation; risks
  `21-reversion-clause-discipline.mdc` "Keep it for flexibility"
  anti-pattern if methods land without callers.

The 2c §5.3 disposition pre-tilts toward (b): "extract `F128` when
bytecode dispatch reveals the API surface needed." 2d Round 1
confirms (b) is the right shape after enumerating the actual
per-opcode mutations, or surfaces (a)/(c) with named justification.

### 3.3 Per-opcode dispatch shape

**Question.** How does `dispatch_instruction`'s body decode the
opcode and reach the per-opcode handler?

Options:

- **(a) `match` on opcode.** Idiomatic Rust; rustfmt-clean; LLVM
  optimizes well-formed dense matches to jump tables. Highest
  reviewability.
- **(b) Function-pointer table.** `static DISPATCH_TABLE: [fn(&Instruction,
  &mut VmState); 256] = [...]` indexed by `instr.opcode`. Closer
  to the C reference's `genTable` / `compileInstruction` shape.
  Per-instruction overhead is one indirect call; may foreclose
  some LLVM inlining vs. (a).
- **(c) Computed-goto via LLVM tail-call.** `become` (RFC 2945,
  unstable as of 2026) or `#[inline(never) fn`-per-opcode + LLVM
  musttail. Theoretically lowest dispatch overhead. Requires
  nightly Rust (MSRV bump foreclosed by Phase 0 stance) or
  fragile stable-Rust emulation; likely rejected on availability
  grounds.

2d Round 1 chooses one with named benchmark or reasoning evidence.
Per the reversion-clause in 2c §5.1.1, the IBC 2-pass form is a
fallback if (a)/(b) cannot meet the ≤3.0× budget.

---

## 4. Scope discipline

Per `15-deletion-and-debt.mdc`, "while we're here" expansions into
2c territory (Cache, scratchpad/register-file allocation,
`compute_hash` orchestration, T1–T8 spec vectors) are forbidden.
2d's deliverables are:

- `dispatch_instruction` body replacement (real per-opcode dispatch).
- FPU rounding-mode plumbing (the §3.1 decision-point outcome).
- `F128` newtype extraction (if §3.2 selects (b) or (c)).
- Per-opcode test corpus extending T1–T8 with T9+ tests for
  arithmetic correctness (per F7 forward-action's rounding-mode
  invariant carry-forward).
- `BENCH_RESULTS.md` update with post-2d `compute_hash_alloc.rs`
  baseline + (if 2d sees fit) a per-opcode bench distinguishing
  dispatch overhead from per-opcode body work (input to 2g's
  per-hash latency benchmark).

Out of scope (regardless of how convenient it would be):

- Cache re-derivation (2c).
- Scratchpad/register-file re-allocation (2c).
- `compute_hash` signature changes (2c §5.1.1 contract).
- `VmState` field additions without audit-grep evidence (2c §5.1.1
  contract).
- `CacheStore` / `VmState` pooling (2f).
- Per-hash latency benchmark / differential harness (2g).
- FFI surface / C++ rewire (3a/3b/3c).

---

## 5. Round 1 readiness gate

This skeleton scaffold satisfies the 2c → 2d hand-off discipline
(per `91-documentation-after-plans.mdc` and the 2b/2c precedent that
each phase's plan doc carries forward-actions for the next).
Implementation of Phase 2d is **gated** on:

1. PR #65 (Phase 2c plan-doc PR) merged.
2. PR for Phase 2c implementation (`feat/randomx-v2-phase2c`)
   merged.
3. A `chore/randomx-v2-phase2d-plan` branch cut, expanding this
   scaffold into a Round 1 design doc that closes the §3 decision
   points and re-runs the §1 §1.3 audit-re-verification.
4. Round 1 design rounds closed (target 4-6 rounds per
   `20-rust-vs-cpp-policy.mdc`), at which point this file is
   replaced by the post-Round-1 plan doc.

Items 1-2 are gating events outside this branch's scope; items 3-4
are Phase 2d's own pre-flight work.

---

## 6. Round history

| Round | Date | Outcome |
|-------|------|---------|
| Scaffold | 2026-05-21 | Skeleton scaffold landed as deliverable of Phase 2c Round 3 (R3-D3). Records the 2c → 2d hand-off contract verbatim, the locked-by-2c `VmState` field set, the F1/F2/F3/F5/F7 forward-actions, the three Round 1 decision points (FPU rounding-mode mechanism; `F128` newtype shape; per-opcode dispatch shape), and the scope discipline. Round 1 design doc supersedes this file when it lands. |
| Round 1 | pending | Phase 2d's first design round. Cuts after Phase 2c implementation lands. |
