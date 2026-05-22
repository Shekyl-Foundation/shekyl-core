# RandomX v2 — Track A Phase 2d plan (skeleton scaffold)

**Status.** Skeleton scaffold landed 2026-05-21 as a deliverable of
Phase 2c Round 3 (R3-D3) — _not_ a Round 1 design. This document
records the 2c → 2d hand-off contract, the locked-by-2c surfaces, the
forward-actions 2c accumulated for 2d, and the decision points 2d's
Round 1 must address. Round 1 of Phase 2d populates this scaffold;
this commit only puts the scaffold in place so 2d's author does not
have to reconstruct the 2c-locked items from plan-doc prose.

**Round 4 addenda (2026-05-21).** Phase 2c Round 4's threat-model
review (`RANDOMX_V2_PHASE2C_PLAN.md` §5.11) accumulated three
2d-bound items on top of the original Round 3 contract: §2's F7
forward-action gains a per-rounding-mode coverage requirement (carry
from 2c §5.11 Objective 1 "FPU rounding-mode escape"); §3.1's FPU
rounding-mode decision-point gains an unsafe-block scope-check
discipline addendum (carry from 2c §5.11 Objective 5
"`unsafe`-block discipline at the FPU intrinsic"); §3.4 is new and
records the `u128`-vs-`__int128_t` edge-case differential discipline
(carry from 2c §5.11 Objective 6 "consensus split via implementation
divergence"). All three are forward-actions that 2d Round 1 absorbs
at design time; none reopen the Round 3 contract.

**Round 5 addendum (2026-05-21).** Phase 2c Round 5's closure
refinements (`RANDOMX_V2_PHASE2C_PLAN.md` §14 Round 5 entry) added
a single 2d-bound item: §3.1's unsafe-block scope-check discipline
(prose-form from Scaffold-R4) is promoted to a CI-time grep
mechanical-enforcement gate modeled on the **`shekyl-pow-randomx`
never uses `#[no_mangle]`** invariant pattern from `RANDOMX_V2_PLAN.md`
§7.7. The grep is a §10 hard gate in the 2d implementation PR;
reviewer-attention enforcement (prose) is necessary but not
sufficient against the failure mode where a future contributor
expands the unsafe surface with a reasonable-seeming addition
("stash the previous mode for restoration," "check a feature flag
before writing") that slips past a reviewer reading the unsafe
block but not the diff context. 2d Round 1 fixes the primitive
choice; the implementation PR adds the option-specific permitted
and forbidden grep pattern set. No Scaffold or Scaffold-R4
disposition reopened.

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
| `f` | `[F128; 4]` (alias in 2c; see note) | FADD_R, FADD_M, FSUB_R, FSUB_M, FSCAL_R, FSWAP_R |
| `e` | `[F128; 4]` (alias in 2c; see note) | FMUL_R, FDIV_M, FSQRT_R |
| `a` | `[F128; 4]` (alias in 2c; see note) | Read-only operand (FADD_R, FSUB_R, FMUL_R `fsrc`) |
| `fprc` | `u32` | CFROUND |
| `scratchpad` | `Box<[u8; SCRATCHPAD_L3]>` | All M-opcodes + ISTORE |
| `e_mask` | `[u64; 2]` | FDIV_M |

**`F128` shape note.** Per Phase 2c §5.1.1 + §5.3 F3a, the
`[F128; 4]` spelling above is shorthand for `[[f64; 2]; 4]`. Phase
2c locks the _element shape_ (`[f64; 2]` — two `f64`s per FP
register) via `type F128 = [f64; 2];` alias only — no newtype, no
methods, no `struct` wrapper. **Phase 2d Round 1 §3.2 decision
point** is whether the alias stays as-is or is promoted to a
`struct F128([f64; 2])` newtype with method API for FP
operations. If §3.2 keeps the alias, the field types in this table
compile against `[[f64; 2]; 4]` as written; if §3.2 promotes to
newtype, the field types compile against `[F128; 4]` where `F128`
is a `struct` with method API. The _frozen_ property is the
element shape (`[f64; 2]`); the type identity is 2d Round 1's
call.

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

**Round 4 addition: per-rounding-mode coverage.** Per 2c §5.11
Objective 1 ("FPU rounding-mode escape" — an attacker who reverse-
engineers the verifier's actual rounding behavior can craft inputs
that exploit divergence from spec-required rounding), the F7
forward-action's "explicit rounding-mode disposition per test" is
insufficient on its own. 2d Round 1 commits to a stronger discipline:
**every FP opcode (FADD_R, FADD_M, FSUB_R, FSUB_M, FMUL_R, FDIV_M,
FSQRT_R, FSCAL_R, FSWAP_R) must have at least one test under each of
the four IEEE 754 rounding modes (RN/RD/RU/RZ), with byte-equality
asserted against the C reference under the matching mode.** That is
9 FP opcodes × 4 modes = 36 mode-coverage tests at minimum, beyond
whatever T9+ tests the F7 forward-action otherwise produces.

The coverage matrix lives in 2d Round 1's test plan (the to-be-
expanded version of this skeleton's §4); the generator binary (per
2c §5.6 F6 single-binary CLI dispatch) gains a per-mode reference
output mode that sets the host rounding mode before generating
reference register state. The C reference's `setRoundingMode` (per
`intrin_portable.h`) is the source of truth for what "set rounding
mode" means at the generator level; the Rust verifier's
mode-plumbing (per §3.1's outcome) is the equivalent at the
verifier level. Test byte-equality holds iff both implementations
agree at every IEEE 754 corner case under each of the four modes.

This is the test-side mitigation for 2c §5.11 Objective 1's
attacker-controlled-divergence concern. The dispatch-side
implementation is §3.1's decision-point outcome; the test-side
coverage is this F7 addition.

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

**Round 4 addition: unsafe-block scope-check discipline.** Per 2c
§5.11 Objective 5 ("`unsafe`-block discipline at the FPU intrinsic"),
whichever option from (a)–(d) 2d Round 1 selects, the resulting
`unsafe` block (if any — option (d) avoids `unsafe` entirely) is
audited at 2d-implementation time to verify it does **only** the
rounding-mode write and nothing else:

- **No surrounding state mutation.** The `unsafe` block contains
  exactly one operation: the MXCSR (x86_64) or FPCR (aarch64) write.
  Adjacent register-file reads, scratchpad writes, or VmState field
  updates live in the surrounding safe code, not inside the
  `unsafe` carve-out.
- **No pointer dereferences.** The rounding-mode write does not
  read or write memory through a raw pointer; it operates only on
  the CPU's FPU control word via the intrinsic / asm primitive.
- **No allocation.** No `Box::new_*`, no slice constructor, no
  `assume_init` call inside the `unsafe` block.
- **No call-site fan-out.** The `unsafe` block contains no function
  call other than the single intrinsic (option (a)) or no `call`
  instruction beyond the inline-asm body (option (b)). If option
  (c) is selected, the third-party crate's `unsafe` discipline is
  audited per `17-dependency-discipline.mdc`'s property-existence
  verification, not assumed.

The audit produces a `// SAFETY:` doc-comment per
`35-secure-memory.mdc` that enumerates exactly what the block does
and why it cannot violate UB. The comment is part of the 2d
implementation-PR review surface; a reviewer who finds the block
doing more than the rounding-mode write rejects the PR.

This is the discipline that prevents the FPU rounding-mode carve-
out from becoming the entry point for unrelated `unsafe` work
("while I have the carve-out open, let me also..."), which would
violate both `15-deletion-and-debt.mdc` and `35-secure-memory.mdc`.
The two existing 2c carve-outs (`Box::new_zeroed_slice` for cache
and scratchpad) are governed by the same discipline; 2c §5.11.2's
`debug_assert!` pattern is the implementation-PR-side check that
the carve-out body produces the size it claims.

**Round 5 addition: CI-time grep mechanical enforcement.** The
prose-as-discipline above is necessary but not sufficient.
Reviewer-attention enforcement is the failure mode where an
auditor reads the `unsafe` block, sees a small body, and confirms
the discipline without re-reading every line — exactly the shape
that lets a future contributor land a "reasonable-seeming addition"
that silently expands the unsafe surface (e.g., stashing the
previous rounding mode for restoration; checking a feature flag
before writing; mutating a sibling field "while the carve-out is
already open"). The grep catches these; prose doesn't.

The 2d implementation PR adds a CI-time grep against the rounding-
mode-setter function body, modeled on the **`shekyl-pow-randomx`
never uses `#[no_mangle]`** invariant pattern from
`RANDOMX_V2_PLAN.md` §7.7 (the "Phase 2 structural isolation
invariants" surface). The grep asserts that the function body
contains exactly one of the option (a)/(b)/(c) primitives and
nothing else — no other intrinsic calls, no pointer dereferences,
no allocator calls, no function calls beyond the chosen primitive.

**Discipline note for 2d Round 1 design closure.** The grep's
exact source-form depends on which of options (a)–(d) Round 1
selects in §3.1; the discipline is the same in all cases. Round 1's
disposition fixes the primitive choice, and the implementation-PR's
CI script greps for _that_ primitive's presence and the absence of
every other intrinsic / allocator / pointer-dereference pattern in
the function body. The Round 1 doc-comment names the primitive and
the grep's exact pattern set; the implementation PR adds the grep.

**Expected shape of the grep set** (filled per Round 1 disposition):

- **Permitted (exactly one expected in the function body):** one
  of `_mm_setcsr` / `_MM_SET_ROUNDING_MODE` (option (a), x86_64
  intrinsic), `__set_fpcr` (option (a), aarch64 intrinsic),
  `asm!` (option (b), inline asm form), or `<chosen-crate>::<fn>`
  (option (c), third-party-crate form).
- **Forbidden (zero hits expected in the function body):** any
  other `_mm_*` / `__*` intrinsic; any `asm!` other than the one
  intended primitive (option (b) only); any `Box::*`,
  `Vec::with_capacity`, `slice::from_raw_parts*`,
  `assume_init`, `MaybeUninit::*` allocator/init pattern; any
  unary `*` dereference of a `*const _` / `*mut _` pointer; any
  function call other than the single primitive.

The implementation-PR's CI script scopes the grep to the
rounding-mode-setter function body (e.g., `fn set_rounding_mode`
or `fn apply_fprc`) — _not_ the whole crate — by matching on the
function declaration's line range. A reviewer who notes the
function name changed (e.g., a contributor renames it to
`fn maybe_restore_and_set_rounding_mode`) is the human-side check
that the grep scope still matches the intended target; the grep
fails closed (assertion-style: zero forbidden-hits OR fail) so a
function-body that drifted outside the scope-match is caught at
PR-CI-time, not at audit-time.

This grep is the same shape as the §7.7 `no #[no_mangle]`
invariant: a future contributor who adds an "improvement" that
expands the unsafe surface ("let me also stash the previous mode"
or "let me also check a feature flag") fails CI immediately rather
than slipping past a reviewer who reads the `unsafe` block
contents but not the diff context that motivated the change. The
discipline doesn't depend on the reviewer's careful reading; it
depends on the grep's mechanical execution.

The 2d implementation-PR description names this grep explicitly
under §10 Gates (cargo fmt / cargo clippy / cargo test / **FPU
unsafe-block scope-check grep** / cargo doc). A failing grep is
a hard gate; the PR cannot land until the function body matches
the discipline.

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

### 3.4 `u128` / `__int128_t` edge-case differential discipline (Round 4)

**Context.** Per 2c §5.11 Objective 6 ("consensus split via
implementation divergence"), Rust's `u128` arithmetic may diverge
from C's `__int128_t` arithmetic at edge cases the spec does not
mechanically pin down. Examples:

- **Division by zero.** Rust panics on `u128 / 0` and `u128 % 0`
  (in debug and release alike — the panic is a defined behavior,
  not a profile-dependent one). C is undefined behavior. If a
  RandomX opcode's input can ever drive a divisor to zero, the
  Rust verifier panics where the C miner produces an arbitrary
  bit pattern, and the chain forks.
- **Signed division overflow** (`i128::MIN / -1`). Rust panics; C
  is UB. Same hazard, opposite-sign register variant.
- **Shift-by-width-or-greater.** Rust panics in debug, wraps in
  release (profile-dependent). C is UB. The debug-vs-release
  equivalence test from 2c §5.11.3 catches the
  profile-dependence; the bigger hazard is the Rust-vs-C
  divergence at the boundary.
- **`u128 * u128` truncation.** Rust's `wrapping_mul` returns the
  low 128 bits; the C reference uses `_umul128` intrinsic for the
  low half and may compute the high half separately. If the
  dispatch needs both halves (e.g., IMULH_R, IMULH_M, IMUL_RCP),
  the high half's computation path must be byte-equality-checked
  against the C reference.

**Discipline.** 2d Round 1 commits to:

1. **Audit every opcode handler that uses `u128` or `i128`** for
   the four edge-case classes above. The audit produces a table
   like 2c §5.1.1's VmState audit: opcode → arithmetic path →
   edge-case disposition (cannot occur per spec / saturated
   explicitly / checked path with explicit Rust panic prevented
   by guard).
2. **Match the C reference's behavior at every reachable edge
   case.** Where the C reference exhibits UB, the Rust dispatch
   either:
   - Proves the edge case is unreachable (spec excludes it; e.g.,
     IMUL_RCP divisor is always non-zero by spec construction),
     and documents the proof in a comment that names the spec
     section.
   - Pre-handles the edge case with an explicit branch that
     produces the same observable result as the C reference's
     dominant compiler output (or the spec's intended behavior,
     where the spec specifies and the C implementation deviates
     — in which case the deviation is itself an upstream-fork
     finding and routes to a follow-up).
3. **Generator-side test coverage.** The reference vector
   generator (per 2c §5.6 F6) gains adversarial inputs that drive
   each enumerated edge case at the C reference; 2d's tests
   assert byte-equality. Belongs in 2g's adversarial corpus per
   2c §5.11.5 for the full enumeration; 2d carries the
   per-opcode subset that 2d's dispatch implementation needs.

**Why this is 2d's problem, not 2g's.** 2g's harness is the
empirical safety net for cases that escape design-time audit; 2d's
audit is the design-time mitigation. The audit prevents the bug
from shipping in the first place; the harness catches what the
audit missed. Per `16-architectural-inheritance.mdc`'s "continuous
discipline as inheritance prevention," design-time discipline is
cheaper and more durable than empirical sampling.

**Out of scope for 2d.** `i128::MIN / -1` paths and div-by-zero
paths that turn out to be reachable but the C reference's UB is
itself the consensus rule (i.e., the network has long agreed on
some specific compiler output as the canonical answer) — these are
2g findings, not 2d findings. 2d audits and pre-handles; 2g's
harness backstops.

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
| Scaffold-R4 | 2026-05-21 | Round 4 addenda landed as a sibling commit of Phase 2c Round 4's threat-model addenda (per `RANDOMX_V2_PHASE2C_PLAN.md` §5.11). Three additions: (i) §2 F7 forward-action extended with per-rounding-mode coverage requirement (9 FP opcodes × 4 IEEE 754 modes ≥ 36 mode-coverage tests, byte-equality-asserted against C reference under matching mode); carry from 2c §5.11 Objective 1 "FPU rounding-mode escape." (ii) §3.1 FPU rounding-mode decision-point gains an "unsafe-block scope-check discipline" addendum: whichever option (a)–(d) 2d Round 1 selects, the resulting `unsafe` block is audited to do only the rounding-mode write (no state mutation, no pointer dereferences, no allocation, no call-site fan-out); carry from 2c §5.11 Objective 5 "`unsafe`-block discipline at the FPU intrinsic." (iii) New §3.4 "`u128` / `__int128_t` edge-case differential discipline" enumerates four edge-case classes (div by zero, signed-div overflow, shift-by-width, `u128 * u128` truncation) and requires 2d Round 1 to audit every `u128`/`i128`-using opcode handler against the C reference, pre-handling reachable edge cases; carry from 2c §5.11 Objective 6 "consensus split via implementation divergence." None of the three additions reopen the Round 3 contract; all are forward-actions absorbed at 2d Round 1 design time. |
| Scaffold-R5 | 2026-05-21 | Round 5 addendum landed as a sibling commit of Phase 2c Round 5's closure refinements (per `RANDOMX_V2_PHASE2C_PLAN.md` §14 Round 5 entry). One addition: §3.1 "CI-time grep mechanical enforcement" subsection promotes the Scaffold-R4 prose-as-discipline (unsafe-block scope-check) to a mechanically-enforced gate. The grep is modeled on the **`shekyl-pow-randomx` never uses `#[no_mangle]`** invariant pattern from `RANDOMX_V2_PLAN.md` §7.7 — asserts the rounding-mode-setter function body contains exactly one of the option (a)/(b)/(c) primitives and nothing else (no other intrinsic calls, no pointer dereferences, no allocator calls, no function calls beyond the chosen primitive). 2d Round 1 fixes the primitive choice; the implementation-PR adds the grep with the option-specific permitted/forbidden pattern set. Catches the "future contributor adds a reasonable-seeming improvement that silently expands the unsafe surface" failure mode (e.g., stashing previous mode for restoration, checking a feature flag, mutating a sibling field) that prose-as-discipline depends on reviewer attention to catch. CI-fail-closed: a function body that drifts outside the discipline fails PR CI rather than passing audit. Named as a §10 hard gate in the 2d implementation PR. No prior Scaffold or Scaffold-R4 disposition reopened. |
| Round 1 | pending | Phase 2d's first design round. Cuts after Phase 2c implementation lands. |
