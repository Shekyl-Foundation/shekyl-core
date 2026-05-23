# RandomX v2 — Track A Phase 2d plan

**Status.** Rounds 1–6 closed 2026-05-22 on branch
`chore/randomx-v2-phase2d-plan`. This document began as the skeleton
scaffold landed 2026-05-21 (Phase 2c Round 3, R3-D3) and was expanded
into a Round 1 design doc after PR #66 (Phase 2c implementation) merged
to `dev` at `e9917097f`. Round 1 closes the §3 decision points (FPU
rounding-mode mechanism; `F128` newtype shape; per-opcode dispatch
shape; `u128`/`__int128_t` edge-case audit), re-verifies the §1.3
`VmState` field-set audit against pin `aaafe71`, and lands the test
plan / commit table / gate checklist. Rounds 2–5 close the CBRANCH
substrate gap (R2-D1–R2-D5), threat-model addenda, generator CLI, and
closure. Round 6 closes two findings against the Round 5 state that
were Round-6-blocking before implementation cuts: the aarch64 FPU-
primitive inconsistency between R1-D1 (hardware FPCR) and R5-D1 (libc
`fesetround`), and the debug-vs-release divergence in R1-D3's out-of-
range opcode disposition (`debug_assert!` vs no-op). Three plan-doc
edits ride along: R1-D4 IMUL_RCP unreachability citation; R2-D5
`exec_pc` invariant-documentation note for the implementation PR; §8
commit-5 split into 5a (T9–T16 additions) + 5b (T8 expectation flip).
See §3.7 and §11. Implementation cut on `feat/randomx-v2-phase2d` is
authorized post this doc landing on `dev`.

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
§7.7. The grep is a §9 hard gate in the 2d implementation PR;
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

**Base commit.** `dev` at the post-PR-#66 merge tip (merge commit
`e9917097f` on 2026-05-22). This doc's branch
(`chore/randomx-v2-phase2d-plan`) cuts from there; the Phase 2d
implementation branch cuts later from post-this-doc `dev`.

**Branches.**

- `chore/randomx-v2-phase2d-plan` (this doc; short-lived per
  `06-branching.mdc` rule 2; lands on `dev` via its own PR).
- `feat/randomx-v2-phase2d` (implementation; cut from post-this-doc
  `dev`; not yet cut as of Round 1 close).

**Scope envelope.** Single implementation PR. Target ≤1200 lines of
net-new Rust (dispatch body + `F128` newtype + integer helpers +
tests + rustdoc) + ~150 KB of committed reference vector bytes (T9+
per-opcode corpus + rounding-mode matrix) + ~400 LoC of C++ generator
glue extending the Phase 2c `phase2c/` generator pattern. ≤7 commits
per §8 below. No FFI surface, no C++ caller rewire, no changes to
`Cache::derive` / `compute_hash` signatures.

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
under §9 Gates (cargo fmt / cargo clippy / cargo test / **FPU
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

### 3.5 Round 1 dispositions (2026-05-22)

Round 1 closes the four §3 items below. Each disposition cites the
audit-pin substrate (`external/randomx-v2/` at `aaafe71`) and the
post-PR-#66 Rust port at `e9917097f`.

#### R1-D1 — FPU rounding-mode mechanism: option (a)

**Disposition.** Quarantined-`unsafe` per-arch intrinsic writes in a
dedicated `set_rounding_mode(mode: u32)` function inside
`src/fpu_rounding.rs` (new module), matching the C reference's
semantics at the MXCSR/FPCR level rather than libc `fesetround` alone.

| Target | Primitive | C substrate |
|--------|-----------|-------------|
| `x86_64` | `core::arch::x86_64::_mm_setcsr(rx_mxcsr_default \| (mode << 13))` with `rx_mxcsr_default = 0x9FC0` | `intrin_portable.h:168-176` |
| `aarch64` | Stable inline asm read/modify/write of `FPCR` rounding field (`mrs {0}, fpcr` + `msr fpcr, {0}`), with IEEE 754 mode 0..3 remapped to FPCR `RMode` encoding (RN/RU/RD/RZ at bits 22–23) — see R6-D1 substrate finding | C reference on aarch64 calls the same hardware path through SoftFloat/intrinsics; libc `fesetround` is the portable fallback in `instructions_portable.cpp:141-158`, **not** the path Shekyl selects |
| other | `compile_error!` at module compile time | Shekyl verifier CI targets `x86_64` + `aarch64` only (same posture as Phase 2b AES generator README) |

**Rejected options.**

- **(b) Inline asm** — rejected for `x86_64` per worse audit readability
  with no substrate advantage over `_mm_setcsr`. **Reopened for
  `aarch64` only at Round 6 (R6-D1)**: stable `core::arch::aarch64`
  does not expose an FPCR-write intrinsic, so the "no substrate
  advantage" rationale applies only to `x86_64`. Inline asm via the
  stable `core::arch::asm!` macro is the only path that satisfies R1-D1's
  "MXCSR/FPCR level rather than libc `fesetround` alone" design intent
  on aarch64. Per `21-reversion-clause-discipline.mdc`'s reopening-
  criteria principle, the reopening is substrate-anchored (different
  intrinsic landscape on aarch64 vs x86_64), not preference-anchored.
- **(c) Third-party crate** — no workspace dependency verified under
  `17-dependency-discipline.mdc` that exposes a narrower `unsafe`
  surface than (a); adds supply-chain fan-out without property gain.
- **(d) Pure-software rounding** — forecloses hardware FPU semantics;
  byte-equality against the C reference's `rx_*_vec_f128` paths is the
  load-bearing property; software emulation risks drift at subnormal /
  NaN corners the T9+ corpus will exercise.

**CFROUND integration.** Handler body matches v2-only form from
`bytecode_machine.hpp:261-266` with the v1 gate deleted (per §2 F5):

```text
isrc = rotr(r[src_reg], imm32 & 63)   // imm from compileInstruction: getImm32() & 63
if (isrc & 60) == 0:
    set_rounding_mode(isrc % 4)
    state.fprc = isrc % 4
```

The host rounding mode is set **before** subsequent FP opcodes in the
same program execute, mirroring C's `rx_set_rounding_mode` side effect.
`state.fprc` mirrors the C `randomx_vm::fprc` field for test introspection.

**CI grep (Scaffold-R5 carry-forward).** Implementation PR adds a
scoped grep on `set_rounding_mode`'s function body asserting exactly one
of `_mm_setcsr` (x86_64 cfg branch) or the aarch64 FPCR write primitive,
and zero forbidden patterns (other intrinsics, pointer dereferences,
allocators, extra function calls). Permitted/forbidden sets are pinned in
§9 (Gates table) and §3.7 R6-D1.

#### R1-D2 — `F128` newtype shape: option (b)

**Disposition.** Promote `type F128 = [f64; 2]` to `struct F128([f64; 2])`
with `Copy`, `Debug`, and the minimal method surface the 28 opcode handlers
need:

| Method | Opcode(s) | Spec / C substrate |
|--------|-----------|-------------------|
| `add_unrestricted` | FADD_R, FADD_M | `rx_add_vec_f128` |
| `sub_unrestricted` | FSUB_R, FSUB_M | `rx_sub_vec_f128` |
| `mul_unrestricted` | FMUL_R | `rx_mul_vec_f128` |
| `div_masked` | FDIV_M | `rx_div_vec_f128` after `mask_register_exponent_mantissa` |
| `sqrt_unrestricted` | FSQRT_R | `rx_sqrt_vec_f128` |
| `swap_lanes` | FSWAP_R | `rx_swap_vec_f128` |
| `xor_with_scale_mask` | FSCAL_R | XOR with `0x80F0000000000000` per lane |

Existing Phase 2c helpers (`cvt_packed_int_to_f128`,
`mask_register_exponent_mantissa`, AES mix conversions) move to
`impl F128` or remain free functions taking/returning `F128` — no
second parallel API. **Rejected (a):** per-opcode inline `[f64; 2]`
arithmetic duplicates the C `rx_*_vec_f128` call sites and forecloses
centralized rounding-mode-sensitive test hooks. **Rejected (c):** full
integer-encoding surface has no caller beyond what Phase 2c already
lands; optionality without named caller per `21-reversion-clause-discipline.mdc`.

**Frozen element shape.** The `[f64; 2]` lane layout is unchanged; only
the type identity promotes from alias to newtype. `VmState` field types
become `[F128; 4]` without adding fields.

#### R1-D3 — Per-opcode dispatch shape: option (a), with frequency decode

**Substrate finding (audit-against-actual-code).** The wire-format
`Instruction.opcode` byte is **not** equal to `InstructionType`'s
numeric enum (`instruction.hpp:42-72`). The C reference maps opcode
bytes to handler types via cumulative frequency ceilings
(`bytecode_machine.hpp:67-98`, `configuration.h:88-125
RANDOMX_FREQ_*`). T5's byte-equality test proves the Rust port stores
these frequency-encoded opcode bytes verbatim. Matching on
`instr.opcode` as if it were `0..=28` would mis-dispatch.

**Disposition.** Two-layer dispatch inside `dispatch_instruction`:

1. **`decode_instruction_type(opcode: u8) -> InstructionType`** — a
   `const fn` (or `match` chain) mirroring the `ceil_*` ladder at
   `bytecode_machine.hpp:68-98` using the same `RANDOMX_FREQ_*`
   constants ported to Rust `const` items in `vm.rs`.
2. **`match decode_instruction_type(instr.opcode)`** with one arm per
   `InstructionType`, each arm replicating **both** the
   `compileInstruction` operand decode **and** the corresponding
   `exe_*` body from `bytecode_machine.hpp:145-270`.

Special cases preserved from C:

- `IMUL_RCP` (`InstructionType` via its frequency bucket) executes
  the `IMUL_R` body (`bytecode_machine.cpp:75-77`).
- `NOP` bucket is a no-op.
- Out-of-range opcode bytes hit the `UNREACHABLE` posture: `panic!`
  in both profiles (R6-D2 supersedes the Round 1 draft of
  `debug_assert!` in debug / no-op in release).

Operand decode replicates `bytecode_machine.cpp:81-477` rules:
`dst/src % RegistersCount`, `signExtend2sCompl(imm32)` for M-form and
self-src R-form variants, `getModMem` / `getModShift` / `getModCond`
splits from `instruction.hpp:90-98`, and scratchpad mask selection
(`ScratchpadL1Mask` / `L2` / `L3` constants already in `vm.rs`).

**Rejected (b)/(c):** unchanged from the scaffold — indirect tables
and nightly tail-call add cost without substrate fidelity gain.

**Register decode helpers** land as private `fn` in `vm.rs`:
`decode_int_reg`, `decode_fp_reg`, `scratchpad_addr`, `load64`/`store64`
(little-endian), `rotr`/`rotl` (portable definitions matching
`instructions_portable.cpp:92-103`), `sign_extend_i32_to_i64`.
**`mulh` / `smulh_u64`** reuse Phase 2b widening helpers via
`pub(crate)` promotion — do not re-derive semantics.

#### R1-D4 — `u128` / `__int128_t` edge-case audit table

Audit performed 2026-05-22 against `bytecode_machine.hpp:145-270` and
`instructions_portable.cpp` at pin `aaafe71`. Disposition classes per
§3.4: **U** = unreachable under spec-constrained inputs; **M** = matches
C widening path already verified in Phase 2b; **G** = guarded to match C
portable helper (shift mask).

| Opcode | Arithmetic path | Div-by-zero | Signed-div overflow | Shift ≥ width | u128 high-half |
|--------|-----------------|-------------|---------------------|---------------|----------------|
| IADD_RS | `wrapping_add` + shift ≤3 | U | U | G (`shift = mod>>2 % 4`) | — |
| IADD_M | `load64` + `wrapping_add` | U | U | — | — |
| ISUB_R/M | `wrapping_sub` | U | U | — | — |
| IMUL_R/M | `wrapping_mul` low 64 | U | U | — | M (low half only) |
| IMULH_R/M | `mulh` | U | U | — | M (`superscalar.rs:1495-1497`) |
| ISMULH_R/M | `smulh_u64` | U | U | — | M (`superscalar.rs:1506-1519`) |
| IMUL_RCP | same as IMUL_R | U (see footnote) | U | — | M |
| INEG_R | `(!x).wrapping_add(1)` | U | U | — | — |
| IXOR_R/M | `^` | U | U | — | — |
| IROR_R | `rotr(x, src & 63)` | U | U | G | — |
| IROL_R | `rotl(x, src & 63)` | U | U | G | — |
| ISWAP_R | register swap | U | U | — | — |
| F* / CFROUND | hardware FPU | U | U | G (CFROUND `rotr` uses compile-time imm) | — |
| CBRANCH | `wrapping_add` + mask test | U | U | — | — |
| ISTORE | `store64` | U | U | — | — |

No opcode handler performs division; `i128::MIN / -1` is **U**. Full
adversarial corpus remains a 2g forward-action (§2 F7 + §5.11.5); 2d
ships the design-time audit above plus T9+ vectors that exercise IMULH
and shift-boundary inputs.

**IMUL_RCP unreachability footnote (R1-D4 / Round 6 cite).** The
"U" cell for IMUL_RCP div-by-zero is established by the C reference's
compile-time gate: `bytecode_machine.cpp:246-258` rewrites the
instruction type to NOP when `isZeroOrPowerOf2(divisor)` is true,
where `divisor = imm32`. The reciprocal-table lookup at runtime is
therefore never reached with a zero or power-of-2 divisor — both are
filtered out at program-compile time. RandomX v2 spec §5.2.10
(IMUL_RCP) names the same precondition normatively
(`imm32 != 0 && !isPowerOf2(imm32)`). The Rust port's Phase 2c
`compile_instruction` already mirrors this gate
(`superscalar.rs` `randomx_reciprocal` callers); 2d's dispatch
inherits the same precondition without re-checking it. If a future
refactor moves the gate, the IMUL_RCP "U" disposition reverts to
**G** with a runtime check matching the spec wording.

#### R1-D5 — §1.3 `VmState` audit re-verification

Re-run 2026-05-22: all 28 executable handlers in
`bytecode_machine.hpp:145-270` read only fields present in §1 frozen
surface 3. No amendment required. `mp` remains absent (v2-only alias
collapsed to `ma` per 2c). `dataset_offset` is read by the iteration
loop in `execute_iteration`, not by `dispatch_instruction` — unchanged
from 2c audit.

### 3.6 Rounds 2–5 dispositions (2026-05-22)

#### R2-D1 — PC-driven iteration loop (substrate gap closure)

**Substrate.** The C reference executes parsed instructions via a
PC-driven loop with backward branches (`bytecode_machine.hpp:126-130`,
`exe_CBRANCH` at `:254-258`). Phase 2c's linear `for instr_idx in
0..PROGRAM_SIZE` scan cannot reproduce CBRANCH control flow.

**Disposition.** Replace the §4.6.4 linear scan in
`VmState::execute_iteration` with a PC-driven loop mirroring C's
`executeBytecode` post-increment semantics:

```text
pc = 0
while pc < PROGRAM_SIZE:
    dispatch_instruction(&program.instructions[pc], self)
    if branch_pc is Some(t):
        pc = t + 1          // C sets pc = target, then for-loop ++pc
        clear branch_pc
    else:
        pc += 1
```

The frozen `dispatch_instruction` signature is unchanged; PC mutation
is iteration-loop responsibility per 2c §5.1.1 (loop fields are not
part of the frozen dispatch surface).

**Rejected:** keeping the linear scan (byte-equality failure on any
program containing a taken CBRANCH); reopening the IBC 2-pass signature
(no benchmark evidence per §1 reopening criterion).

#### R2-D2 — CBRANCH static metadata on `Program` (not `VmState`)

**Substrate.** CBRANCH branch targets come from the compile-time
`registerUsage[creg]` table (`bytecode_machine.cpp:435-450`), updated
during `compileInstruction` as a side effect of parsing the static
384-instruction program. The table depends only on `(instructions,
index)` — not on runtime register values.

**Disposition.** Extend [`Program`] with a parallel
`cbranch_table: [CBranchMeta; PROGRAM_SIZE]` populated once at the end
of `VmState::init_program` by simulating C's `registerUsage` updates
across all 384 slots (same rules as `compileInstruction` dst-write
sites + CBRANCH's "mark all registers used at i"). Each `CBranchMeta`
holds `{ creg, target, imm, mem_mask }` for slots whose frequency-decode
type is `CBRANCH`; non-CBRANCH slots remain `CBranchMeta::INACTIVE`.

At dispatch time the CBRANCH arm reads
`program.cbranch_table[state.exec_pc]` — see **R2-D5** for how `exec_pc`
is supplied without changing the frozen `dispatch_instruction` signature.

**Rejected:** storing `register_usage: [i32; 8]` on `VmState` (explicitly
forbidden in 2c §5.1.1); per-iteration registerUsage pre-pass (redundant
once static metadata exists).

#### R2-D5 — `VmState.exec_pc` iteration index (pairs with R2-D2)

**Substrate.** `cbranch_table` is indexed by instruction position `i`,
but `dispatch_instruction` cannot gain a `pc` parameter (frozen surface
1). The CBRANCH arm must know which table slot to read.

**Disposition.** Add `exec_pc: u16` to `VmState` as iteration-loop
scratch (same class as R2-D3's `branch_pc`):

- Set by `execute_iteration` immediately before each
  `dispatch_instruction` call.
- Read **only** by the CBRANCH arm (to index `cbranch_table`) and by
  test introspection if needed.
- Reset is implicit (overwritten each dispatch step).

Together, R2-D3 + R2-D5 are two iteration-coordination fields replacing
C's `int& pc` split across "current index" (`exec_pc`) and "branch
target pending" (`branch_pc`). Neither field is read by non-CBRANCH
opcode handlers.

#### R2-D3 — `VmState.branch_pc` iteration-coordination field (R1-D5 amendment)

**Substrate.** C passes `int& pc` into `exe_CBRANCH`; the frozen Rust
signature cannot add parameters or return values.

**Disposition.** Add `branch_pc: Option<u16>` to `VmState`:

- Reset to `None` at the start of each `execute_iteration`.
- Written **only** by the CBRANCH arm inside `dispatch_instruction`
  when the branch condition fires.
- Read **only** by `execute_iteration`'s PC loop (then cleared).

This field is iteration-coordination scratch — not read by any other
opcode handler. Documented as a Round 2 amendment to §1.3 (one field;
does not reopen `register_usage` / `mp` / cache-key prohibitions).

**Reopening criterion.** Reopens to the IBC 2-pass design only if
Phase 2d per-opcode benchmarks demonstrate the single-pass decode cost
fails the ≤3.0× C-reference budget with evidence attributable to
per-call decode (unchanged from §1 reopening criterion).

#### R2-D4 — IMUL_RCP reciprocal access

**Disposition.** Promote `superscalar::randomx_reciprocal` to
`pub(crate)` for the `IMUL_RCP` → `IMUL_R` dispatch arm (same
semantics as `bytecode_machine.cpp:245-258`). No new crate surface.

#### R3-D1 — Threat-model addenda (Round 3)

Carry-forward from 2c §5.11, scoped to 2d surfaces:

| Objective | 2d disposition |
|-----------|----------------|
| FPU rounding-mode escape | T11–T14 matrix (§6.2) + CFROUND throttle T15; host mode set only inside `set_rounding_mode` |
| Timing side-channels at dispatch | Explicit rejection: verifier-only path; no constant-time claim for PoW VM dispatch (`30-cryptography.mdc` explicit rejection) |
| `unsafe` FPU surface expansion | §9 CI grep on `set_rounding_mode` body (Scaffold-R5) |
| Integer widening divergence | R1-D4 audit + T9 IMULH/ISMULH smoke |
| Malformed opcode bytes | Frequency decode out-of-range → `panic!` in both profiles (R6-D2; supersedes Round 3 draft of `debug_assert!`/no-op) |

Property-test analogs T9'–T16' remain **deferred to 2g** unless a
future substrate finding surfaces a gap (unchanged from §6.2).

#### R4-D1 — Phase 2d generator CLI (`tests/vectors/reference/_generator/phase2d/`)

Sibling directory to `phase2c/`, same Makefile/link posture (x86_64
Linux, fork pin `aaafe71`, soft-Aes-only). Subcommands:

| Flag | Output | Rust test |
|------|--------|-----------|
| `--t9-integer-smoke` | `t9_*.bin` + `.meta.txt` | `t9_*` in `vm.rs#mod tests` |
| `--t10-fp-smoke --mode=rn` | `t10_*.bin` | `t10_*` |
| `--fp-matrix --mode={rn,rd,ru,rz}` | `t11_*` … `t14_*` (9 opcodes × 4 modes) | `t11_*` … `t14_*` |
| `--cfround-throttle` | `t15_*.bin` | `t15_*` |
| `--hash-e2e` | `t16_*.bin` (replaces T8 NOP fixture) | `t8_*` updated + `t16_*` |

Wire formats follow phase2c README conventions (little-endian,
`.meta.txt` names pin + mode + opcode). Generator sets host rounding
mode before FP captures to match Rust `set_rounding_mode` semantics.

#### R5-D1 — Design closure (Round 5)

- §5 readiness gate items 3–4 satisfied as of Round 5 close; Round 6
  re-opens the readiness gate for two design-disposition findings
  (§3.7 R6-D1, R6-D2) plus three plan-doc edits (R1-D4 cite, R2-D5
  invariant note, §8 commit-5 split). Implementation cut remains
  authorized only after Round 6 closes.
- §1.3 amendment recorded: `branch_pc`, `exec_pc`, `Program.cbranch_table` only.
- §9 FPU grep permitted patterns pinned (superseded by R6-D1 — see
  §3.7 for the post-Round-6 grep targets; preserved here as the Round-5
  closure record).

---

### 3.7 Round 6 dispositions

Round 6 closes two findings against the Round-5 state that were
Round-6-blocking (R6-D1, R6-D2) and absorbs three plan-doc edits that
ride along with the implementation PR (R6-D3 R1-D4 cite already landed
in §3.4; R6-D4 §8 commit-5 split already landed in §8; R6-D5 R2-D5
invariant-documentation note for implementation-PR rustdoc). Dispositions
are recorded here so the implementation PR inherits an unambiguous
design state.

#### R6-D1 — Aarch64 FPU primitive: hardware FPCR via stable inline asm

**Finding.** R1-D1's design table specified the aarch64 primitive as
"Read/modify/write FPCR rounding field … via `core::arch::aarch64`
helpers" — an intrinsic-level hardware write matching the "MXCSR/FPCR
level rather than libc `fesetround` alone" design intent. R5-D1's grep
target, however, pinned `fesetround(` as the aarch64 permitted pattern.
The two specifications are different primitives (intrinsic vs libc) and
selecting `fesetround` silently routes the aarch64 verifier through
glibc/musl/Bionic's libc implementations, whose semantics can vary
across libc vendors. Byte-equality against the C reference's hardware-
FPCR path may not hold on aarch64 under libc-mediated mode setting —
exactly the consensus-split-via-divergence threat R1-D4 was structured
to catch.

**Substrate finding (audit-against-actual-substrate).** Stable Rust's
`core::arch::aarch64` does not expose an FPCR-write intrinsic. The
substrate options for aarch64 FPCR access in stable Rust are:

- Stable inline asm via `core::arch::asm!` macro (`mrs {0}, fpcr` +
  `msr fpcr, {0}` register read/modify/write).
- Libc `fesetround` (the R5-D1 target).
- Third-party crate exposing the hardware path.

R1-D1's blanket rejection of inline asm (option b) was anchored in "no
substrate advantage over the intrinsics the C reference already uses on
x86_64." That rationale is correct for x86_64 — `_mm_setcsr` exists in
`core::arch::x86_64`, intrinsic-level. On aarch64 there is no
equivalent stable intrinsic, so the "no substrate advantage" rationale
does not apply; rejecting (b) for aarch64 forces (libc) or (third-party
crate), neither of which delivers the hardware-FPCR property R1-D1's
design intent requires.

**Disposition (Round 6).** Aarch64 uses stable inline asm to write
FPCR, reopening R1-D1 option (b) for aarch64 only per
`21-reversion-clause-discipline.mdc`'s reopening-criteria principle
(substrate-anchored re-evaluation: the intrinsic landscape differs
between x86_64 and aarch64; R1-D1's rejection rationale applied only to
x86_64).

| Target | Primitive | C substrate parity |
|--------|-----------|--------------------|
| `x86_64` | `core::arch::x86_64::_mm_setcsr(rx_mxcsr_default \| (mode << 13))` (unchanged from R1-D1) | `intrin_portable.h:168-176` `_mm_setcsr` |
| `aarch64` | `asm!("mrs {0}, fpcr", out(reg) old); let new = (old & !FPCR_RM_MASK) \| remap(mode); asm!("msr fpcr, {0}", in(reg) new)` | C reference's hardware path; libc `fesetround` is the portable fallback path Shekyl explicitly does not select |
| other | `compile_error!` (unchanged from R1-D1) | — |

The IEEE 754 mode index 0..3 (the bit pattern stored in `VmState.fprc`
and exposed by CFROUND) maps to FPCR `RMode` field (bits 22–23)
differently from MXCSR — aarch64 FPCR's encoding is (00=RN, 01=RU,
10=RD, 11=RZ) while spec/MXCSR is (00=RN, 01=RD, 10=RU, 11=RZ). The
aarch64 implementation contains a small remap table; the implementation
PR's grep allows the remap table's static contents but no other
intrinsic calls or function calls in the `set_rounding_mode` function
body.

**§9 FPU unsafe grep targets (Round 6 supersedes Round 5).** Permitted
and forbidden patterns are specified in §3.7 R6-D1; the §9 Gates table
names the CI script as a hard gate.

- **x86_64:** exactly one `_mm_setcsr(` in `set_rounding_mode` body.
- **aarch64:** exactly two `asm!(` invocations in body (the `mrs` read
  and `msr` write), zero `fesetround(` calls, zero other function
  calls (the remap-table lookup is a `static` array index, not a
  function call).
- **Forbidden (all targets):** any function call beyond the
  arch-specific permitted set, pointer deref, allocator, second
  rounding primitive, or `unsafe { … }` block that does anything other
  than the rounding-mode write.

**`unsafe_code` discipline.** The arch-cfg'd inline asm sits inside the
single `#[deny(unsafe_code)]` carve-out promised by §7; no additional
carve-outs are introduced relative to Round 1's accounting.

**Reversion criteria (`21-reversion-clause-discipline.mdc`).** R6-D1
reverts to libc `fesetround` on aarch64 if any of: (a) the asm-based
primitive fails byte-equality against the C reference's hardware path
under T11–T14's per-mode corpus on aarch64 CI hosts; (b) stable Rust
exposes a `core::arch::aarch64` FPCR write intrinsic (substrate change
making asm unnecessary). Criterion (b) is the documented re-evaluation
shape; the disposition revisits at that point, not by author preference.

#### R6-D2 — Out-of-range opcode disposition: `panic!` in both profiles

**Finding.** R1-D3's "out-of-range opcode bytes hit the UNREACHABLE
posture (`debug_assert!` in debug; no-op in release)" produces
observable behavior divergence across profiles. The §9 Gates table
**Debug ≡ release** row (inherited from Phase 2c
`RANDOMX_V2_PHASE2C_PLAN.md` §5.11.3) runs the test corpus under both
profiles and asserts identical output. A
malformed (out-of-range) opcode byte in debug panics; in release it
no-ops silently. Two failure modes follow:

- A future generator change accidentally produces a malformed opcode
  byte: debug CI panics, release silently passes — and release is the
  shipped artifact. The CI failure is visible; the underlying
  divergence in observable behavior is exactly the
  consensus-split-via-divergence threat the equivalence gate catches.
- An adversarial input (Phase 2g's adversarial corpus) crafts a
  malformed opcode byte deliberately. Debug rejects; release silently
  accepts. Two correctly-implementing verifiers disagree on validity.

**Substrate finding.** R1-D3's frequency decode (the cumulative ceiling
ladder per `bytecode_machine.hpp:67-98`) covers all 256 u8 values
(0..=255) exhaustively — `RANDOMX_FREQ_*` sums to 256 by spec
construction. The
"out-of-range" branch in `decode_instruction_type` is therefore
unreachable in well-formed RandomX v2 programs. If the branch ever
fires, the decode logic itself has drifted upstream of dispatch — not
that an attacker crafted bad input.

**Disposition (Round 6).** Replace R1-D3's `debug_assert!` / no-op pair
with `panic!("RandomX v2 opcode decode produced out-of-range value {opcode}; decode ladder is inconsistent with bytecode_machine.hpp:67-98")`
in both profiles. The panic is the "this should never happen"
assertion that fails closed: if it ever fires, the decode logic has
drifted and the verifier correctly halts rather than silently producing
arbitrary output. The C reference's `UNREACHABLE` (`__builtin_unreachable()`)
admits undefined behavior the optimizer may eliminate; `panic!` in both
profiles is the safer consensus posture — observable, identical across
debug and release, and matches the unreachability claim normatively
rather than relying on profile-conditional checks.

**Equivalence gate.** Under R6-D2, the §9 **Debug ≡ release** gate
(Phase 2c §5.11.3) no longer has a divergence-of-behavior-on-malformed-opcode escape
hatch. T9–T16 cannot exercise the panic path (all use frequency-encoded
well-formed programs); the panic is a defensive assertion against
decode-logic drift, not a runtime case the corpus exercises.

**Test coverage.** No T-vector exercises the panic (by R6-D2's
construction). The implementation PR adds a `#[should_panic]` unit
test that constructs a `decode_instruction_type` call on a synthetic
out-of-range u8 with a deliberately broken decode-ladder mock, asserting
the panic message text. This sits in the same posture as Phase 2c's
allocation-failure tests: the test exists to prove the failure-closed
posture is wired, not to exercise it in production paths.

**Reversion criteria.** R6-D2 reverts to a profile-conditional posture
only if a substrate change makes the decode ladder genuinely incomplete
(e.g., a future spec amendment introducing reserved opcode bytes whose
dispatch is undefined). No such substrate change is anticipated under
RandomX v2 spec at pin `aaafe71`.

#### R6-D3 — R1-D4 IMUL_RCP unreachability citation (light edit)

Landed in §3.4 as the IMUL_RCP unreachability footnote (post-table).
Cites RandomX v2 spec §5.2.10 and C reference `bytecode_machine.cpp:246-258`
(`isZeroOrPowerOf2(divisor)` gate at compile time). Aligns the R1-D4
"U" disposition with the rules-26 A2 discipline that audit-table
cells cite pinned line ranges; the load-bearing step is reading source
at those lines.

#### R6-D4 — Commit table split: T9–T16 vs T8 expectation flip

Landed in §8. Commit 5 splits into:

- **5a:** add T9–T16 vectors and tests (all new tests; ~350 LoC + fixtures).
- **5b:** flip T8 expectation from NOP-hash to real-hash byte-equality
  (one existing test; expected output changes; ~20 LoC).

The split keeps the consensus-affecting flip independently bisectable.
Bisection against the original combined commit 5 produced "either a
new test failed or T8 flipped incorrectly" without distinguishing. The
split makes 5b independently reviewable as "this commit changes
consensus-affecting test expectations because dispatch now produces
real hashes" — the same shape as the `mp` correction discipline from
Phase 2c Round 3 (audit-against-actual-code surfacing a consensus-
affecting change as an atomic event).

#### R6-D5 — `exec_pc` invariant-documentation note (implementation PR)

R2-D5 added `exec_pc: u16` to `VmState` as iteration-loop scratch for
CBRANCH-table indexing under the frozen `dispatch_instruction`
signature. A future reader of `VmState` may not see why `exec_pc` is a
field (which conceptually persists across dispatch calls) versus a
parameter or a scratch local — and silent mis-reads of stale `exec_pc`
outside the intended window are exactly the kind of subtle bug rust-
type-system discipline is supposed to prevent.

**Note for implementation PR (R6-D5).** Two refinements ride along
with the implementation PR's `VmState` rustdoc:

1. **Field-rustdoc invariant.** The `exec_pc` field's rustdoc records
   the invariant verbatim: *"`exec_pc` is iteration-loop scratch; it is
   set by `execute_iteration` immediately before each
   `dispatch_instruction` call and is read only by the CBRANCH
   dispatch arm. The field is not part of the VM's persistent state
   between dispatch calls; it exists on `VmState` because the frozen
   `dispatch_instruction` signature precludes passing it as a
   parameter. Any read of `exec_pc` outside the CBRANCH dispatch arm
   is a discipline violation; any write outside `execute_iteration`'s
   pre-dispatch step is a discipline violation."*
2. **Sentinel reset.** `execute_iteration` writes `exec_pc =
   u16::MAX` at the end of each iteration (after the final dispatch
   returns). A future code path that reads `exec_pc` outside the
   intended window will trip the `cbranch_table[u16::MAX]` index-out-
   of-bounds check (`Program.cbranch_table` is length `PROGRAM_SIZE`
   (384); `u16::MAX`
   is out of range), failing closed with a panic rather than silently
   reading stale data. The sentinel-reset cost is one `u16` store per
   iteration; the discipline payoff is index-out-of-bounds-rather-
   than-silent-stale-read on every out-of-window read.

Both refinements land in the implementation PR (per R6-D5's
"plan-doc edits ride along" disposition); they do not require a Round
7 amendment to the plan doc.
- Implementation PR cites §8 commit table + §9 gate checklist.
- `docs/CHANGELOG.md` updated when plan doc merges.

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

Items 1–2 are **satisfied** as of 2026-05-22 (PR #65 plan-doc merge;
PR #66 implementation merge at `e9917097f`). Implementation of Phase
2d remains **gated** on:

1. ~~PR #65 (Phase 2c plan-doc PR) merged.~~ **Done.**
2. ~~PR for Phase 2c implementation merged.~~ **Done** (`e9917097f`).
3. This `chore/randomx-v2-phase2d-plan` branch expanding the skeleton
   into a Round 1 design doc — **Done** (Rounds 1–6 closed 2026-05-22).
4. Rounds 1–6 design rounds closed (target 4–6 rounds per
   `20-rust-vs-cpp-policy.mdc`; Round 6 added one Round-6-blocking
   amendment plus three plan-doc edits — see §3.7). **Done 2026-05-22**
   (§3.6 + §3.7). `feat/randomx-v2-phase2d` implementation cut
   authorized.

---

## 6. Test plan

### 6.1 Inherited vectors (must stay green)

T1–T8 from Phase 2c remain mandatory. T8 (`t8_vm_compute_hash_nop.bin`)
**must flip** to real-hash byte-equality once dispatch lands — the NOP
stub expectation is replaced by end-to-end hash parity under real
bytecode semantics. T6/T7 unchanged (iteration snapshots precede full
dispatch semantics).

### 6.2 New spec vectors (T9+)

Extend the Phase 2c generator (`tests/vectors/reference/_generator/phase2c/`)
into a `phase2d/` sibling (or subcommand) producing:

| ID | Coverage | Generator mode |
|----|----------|----------------|
| T9 | Single-instruction integer smoke (IADD_RS, IMULH_R, IROR_R, ISTORE) | `--t9-integer-smoke` |
| T10 | FP smoke under RN (FADD_R, FMUL_R, FDIV_M, FSQRT_R) | `--fp-smoke --mode=rn` |
| T11–T14 | Rounding-mode matrix: 9 FP opcodes × 4 IEEE modes (36 tests minimum per §2 F7 Round 4 addition) | `--fp-matrix --mode={rn,rd,ru,rz}` |
| T15 | CFROUND throttle (`isrc & 60 != 0` → no mode change) | `--cfround-throttle` |
| T16 | End-to-end `compute_hash` with real dispatch (replaces T8 NOP expectation) | `--hash-e2e` |

Each vector ships `.bin` + `.meta.txt` naming the rounding mode, opcode
under test, and fork pin. Property-test analogs T9'–T16' are **deferred
to Phase 2g** unless a future substrate finding surfaces a gap (per
R3-D1).

### 6.3 Test placement

Per Phase 2c R0-D6: spec-vector tests live in `src/vm.rs#mod tests`
via `include_bytes!("../tests/vectors/reference/vm/...")`. No new
`pub` accessors for test convenience.

---

## 7. Module layout

```
rust/shekyl-pow-randomx/src/
├── lib.rs           # add `mod fpu_rounding;`
├── fpu_rounding.rs  # NEW: `set_rounding_mode` + CI-grep target
├── vm.rs            # dispatch body, F128 newtype, integer helpers / re-exports
└── superscalar.rs   # `pub(crate)` mulh / smulh_u64 (if not extracted)
```

No new workspace dependencies. Third `#![deny(unsafe_code)]` exception:
only `fpu_rounding::set_rounding_mode` (after the two allocation carve-
outs from 2c).

---

## 8. Commit table (implementation PR)

| # | Subject (imperative, ≤72 chars) | ~LoC | Plan anchor |
|---|----------------------------------|------|-------------|
| 1 | `randomx: F128 newtype + integer rotate/load helpers` | ~180 | §3.5 R1-D2, R1-D3 |
| 2 | `randomx: fpu_rounding module + CFROUND handler wiring` | ~120 | §3.5 R1-D1, §3.7 R6-D1, §2 F5 |
| 3 | `randomx: dispatch_instruction match arms (integer opcodes)` | ~350 | §3.5 R1-D3, §3.7 R6-D2, R1-D4 |
| 4 | `randomx: dispatch_instruction FP opcode arms` | ~280 | §3.5 R1-D2, §2 F2 |
| 5a | `randomx: T9-T16 spec vectors (additions)` | ~350 + fixtures | §6, §3.7 R6-D4 |
| 5b | `randomx: flip T8 expectation to real-hash byte-equality` | ~20 | §6.2, §3.7 R6-D4 |
| 6 | `randomx: FPU rounding-mode CI grep + BENCH_RESULTS update` | ~80 | §3.7 R6-D1, §9 |

≤7 commits; bisect-friendly ordering (integer dispatch before FP arms so
commit 3 keeps `cargo test` green with stub FP arms if needed — prefer
single commit 4 landing all FP arms atomically to avoid half-real hash
semantics). Per R6-D4, commit 5 splits into 5a (T9–T16 additions, all
new tests green) and 5b (T8 NOP-hash → real-hash expectation flip, one
existing test's expected output changes); the split keeps the
consensus-affecting flip independently bisectable from the new-vector
additions.

---

## 9. Gates (implementation PR)

| Gate | Command / check |
|------|-----------------|
| Format | `cargo fmt --check` (workspace) |
| Lint | `cargo clippy --all-targets -- -D warnings` on `shekyl-pow-randomx` |
| Test | `cargo test -p shekyl-pow-randomx` (includes T1–T16 unit tests) |
| Debug ≡ release | Existing `.github/workflows/build.yml` Gate 2 (inherited from 2c) |
| Doc | `cargo doc -p shekyl-pow-randomx --no-deps` |
| FPU unsafe grep | Script scoped to `fn set_rounding_mode` per §3.7 R6-D1 (supersedes R5-D1's `fesetround` aarch64 target) |
| Bench (informational) | `cargo bench -p shekyl-pow-randomx --bench compute_hash_alloc` — record in `BENCH_RESULTS.md`; not a PR hard gate per R0-D12 |

---

## 10. Forward path

- **2f** inherits unchanged `compute_hash` surface; pooling wraps the
  same `VmState` allocation path 2c landed.
- **2g** inherits T11–T14 mode matrix as seed corpus for differential
  harness expansion per §2 F7.
- **3a** still sees only `Cache::derive` + `compute_hash`; dispatch
  remains private.

---

## 11. Round history

| Round | Date | Outcome |
|-------|------|---------|
| Scaffold | 2026-05-21 | Skeleton scaffold landed as deliverable of Phase 2c Round 3 (R3-D3). Records the 2c → 2d hand-off contract verbatim, the locked-by-2c `VmState` field set, the F1/F2/F3/F5/F7 forward-actions, the three Round 1 decision points (FPU rounding-mode mechanism; `F128` newtype shape; per-opcode dispatch shape), and the scope discipline. Round 1 design doc supersedes this file when it lands. |
| Scaffold-R4 | 2026-05-21 | Round 4 addenda landed as a sibling commit of Phase 2c Round 4's threat-model addenda (per `RANDOMX_V2_PHASE2C_PLAN.md` §5.11). Three additions: (i) §2 F7 forward-action extended with per-rounding-mode coverage requirement (9 FP opcodes × 4 IEEE 754 modes ≥ 36 mode-coverage tests, byte-equality-asserted against C reference under matching mode); carry from 2c §5.11 Objective 1 "FPU rounding-mode escape." (ii) §3.1 FPU rounding-mode decision-point gains an "unsafe-block scope-check discipline" addendum: whichever option (a)–(d) 2d Round 1 selects, the resulting `unsafe` block is audited to do only the rounding-mode write (no state mutation, no pointer dereferences, no allocation, no call-site fan-out); carry from 2c §5.11 Objective 5 "`unsafe`-block discipline at the FPU intrinsic." (iii) New §3.4 "`u128` / `__int128_t` edge-case differential discipline" enumerates four edge-case classes (div by zero, signed-div overflow, shift-by-width, `u128 * u128` truncation) and requires 2d Round 1 to audit every `u128`/`i128`-using opcode handler against the C reference, pre-handling reachable edge cases; carry from 2c §5.11 Objective 6 "consensus split via implementation divergence." None of the three additions reopen the Round 3 contract; all are forward-actions absorbed at 2d Round 1 design time. |
| Scaffold-R5 | 2026-05-21 | Round 5 addendum landed as a sibling commit of Phase 2c Round 5's closure refinements (per `RANDOMX_V2_PHASE2C_PLAN.md` §14 Round 5 entry). One addition: §3.1 "CI-time grep mechanical enforcement" subsection promotes the Scaffold-R4 prose-as-discipline (unsafe-block scope-check) to a mechanically-enforced gate. The grep is modeled on the **`shekyl-pow-randomx` never uses `#[no_mangle]`** invariant pattern from `RANDOMX_V2_PLAN.md` §7.7 — asserts the rounding-mode-setter function body contains exactly one of the option (a)/(b)/(c) primitives and nothing else (no other intrinsic calls, no pointer dereferences, no allocator calls, no function calls beyond the chosen primitive). 2d Round 1 fixes the primitive choice; the implementation-PR adds the grep with the option-specific permitted/forbidden pattern set. Catches the "future contributor adds a reasonable-seeming improvement that silently expands the unsafe surface" failure mode (e.g., stashing previous mode for restoration, checking a feature flag, mutating a sibling field) that prose-as-discipline depends on reviewer attention to catch. CI-fail-closed: a function body that drifts outside the discipline fails PR CI rather than passing audit. Named as a §9 hard gate in the 2d implementation PR. No prior Scaffold or Scaffold-R4 disposition reopened. |
| Round 1 | 2026-05-22 | Post-PR-#66 design round on `chore/randomx-v2-phase2d-plan`. Closes §3 decision points: **(R1-D1)** FPU rounding via quarantined `unsafe` intrinsics in `fpu_rounding.rs` (option a); **(R1-D2)** minimal `F128` newtype (option b); **(R1-D3)** dense `match` on `decode_instruction_type(opcode)` (option a) — substrate finding: wire opcode bytes are frequency-encoded (`bytecode_machine.hpp:67-98`), not `InstructionType` enum values; dispatch replicates `compileInstruction` operand decode plus `exe_*` bodies; **(R1-D4)** u128/i128 edge-case audit table; **(R1-D5)** §1.3 VmState re-audit (no field amendments). Lands §6–§10. |
| Round 2 | 2026-05-22 | CBRANCH / PC substrate gap closure: **(R2-D1)** PC-driven `execute_iteration` loop; **(R2-D2)** `Program.cbranch_table` static metadata from simulated `registerUsage`; **(R2-D3)** `VmState.branch_pc` iteration-coordination field; **(R2-D5)** `VmState.exec_pc` for CBRANCH table indexing; **(R2-D4)** `pub(crate) randomx_reciprocal` for IMUL_RCP. Frozen `dispatch_instruction` signature preserved. |
| Round 3 | 2026-05-22 | Threat-model addenda **(R3-D1)**: FPU escape → T11–T15 + grep; timing side-channels explicitly rejected for verifier dispatch; integer widening → R1-D4 + T9; malformed opcodes → UNREACHABLE posture. T9'–T16' deferred to 2g. |
| Round 4 | 2026-05-22 | Generator CLI spec **(R4-D1)**: `phase2d/` sibling to `phase2c/` with subcommands for T9–T16 + T8 real-hash fixture. |
| Round 5 | 2026-05-22 | Closure **(R5-D1)**: §5 gate satisfied as of round close; §9 FPU grep patterns pinned (x86_64 `_mm_setcsr`, aarch64 `fesetround` matching C portable path). Note: R5-D1's aarch64 `fesetround` target was found inconsistent with R1-D1's "MXCSR/FPCR level rather than libc `fesetround` alone" design intent during Round 6 review; superseded by R6-D1. |
| Round 6 | 2026-05-22 | Round-6-blocking findings closed against the Round-5 state: **(R6-D1)** aarch64 FPU primitive resolves the R1-D1/R5-D1 inconsistency by reopening R1-D1 option (b) for aarch64 only — stable inline asm `mrs/msr fpcr` write — with substrate justification (no stable `core::arch::aarch64` FPCR-write intrinsic exists; R1-D1's "no substrate advantage" rejection rationale applied to x86_64, not aarch64). §9 FPU unsafe grep targets updated (§3.7 R6-D1). **(R6-D2)** Out-of-range opcode disposition changes from R1-D3's `debug_assert!`/no-op pair to `panic!` in both profiles, removing the debug-vs-release behavior divergence the §9 **Debug ≡ release** gate (Phase 2c §5.11.3) would surface and asserting unreachability normatively rather than via profile-conditional checks. Plan-doc edits ride along: **(R6-D3)** R1-D4 IMUL_RCP unreachability citation (spec §5.2.10 + C `bytecode_machine.cpp:246-258`); **(R6-D4)** §8 commit-5 split into 5a (T9–T16 additions) + 5b (T8 expectation flip) keeping the consensus-affecting flip independently bisectable; **(R6-D5)** `exec_pc` invariant-documentation note for implementation-PR rustdoc + sentinel-reset to `u16::MAX` for fail-closed out-of-window reads. Implementation cut authorized. **Posture cite (audit-against-actual-code recurrence).** R1-D3's frequency-decode finding (wire opcode bytes are frequency-encoded per `bytecode_machine.hpp:67-98`, not `InstructionType` enum values) is the **second instance** of the audit-against-actual-code discipline catching a real consensus-split bug pre-implementation. First instance: Phase 2c Round 3 `mp` correction (audit reading the actual C reference rather than working from prompted summaries). Two instances now confirm the pattern; the discipline applies forward to 2f/2g per `16-architectural-inheritance.mdc`'s discovery-cadence framing. |
