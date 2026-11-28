# RandomX directed rounding: each instruction in its own block

**Status:** LIVING CONTRACT — last verified 2026-11-28. RULED 2026-11-28 (Rick): option (b), built in `rust/shekyl-pow-randomx/src/fpu_rounding.rs`. This record supersedes the setter design of `RANDOMX_V2_PHASE2D_PLAN.md` R1-D1 and R6-D1 (in `docs/completed/`).

**Scope:** how the Rust verifier rounds RandomX's floating-point instructions, what each `asm!` block promises the compiler, why the software-corrected candidate is a test oracle and not the implementation, and the subnormal statement the design rests on. The measured comparison's raw logs stay in the Foundation's private operations records; the numbers it decided on are in §6.

## 1. The decision

RandomX rounds every floating-point instruction by the mode the last CFROUND chose: `0` nearest, `1` down, `2` up, `3` toward zero. Until this change, CFROUND wrote that mode into MXCSR (x86_64) or FPCR (aarch64), and ordinary Rust code then ran under it. The compiler assumes the opposite: Rust floating-point code runs under the thread's control word, at round-to-nearest. On x86 the end of a hash also wrote `0x9FC0`, leaving flush-to-zero and denormals-are-zero on for whatever the thread ran next. A panic mid-hash skipped the closing reset on both architectures and left the directed mode set.

**Ruled (Rick, 2026-11-28): build (b).** Every RandomX floating-point instruction runs in one `asm!` block that:

1. writes a fixed control word: the IEEE defaults plus the mode, with flush-to-zero and denormals-are-zero off and every exception masked;
2. computes both lanes;
3. writes back the caller's word before the block ends.

The caller's word is read once per program run (`FpEnv::capture`, from `VmState::execute_program`: eight reads per hash), not per instruction. When the mode is nearest and the caller's control bits already equal the fixed nearest word, the instruction is plain Rust. Otherwise it goes through a block too, so a caller with flush-to-zero on still gets IEEE results. Whether the caller's word allows plain Rust is decided once per iteration, by which of two instruction loops runs, not in each instruction (§6).

Two things follow by construction:

- **No leak.** Nothing else in the crate writes the register, and no block can unwind (`asm.rules.unwind`). So a hash, or a panic out of one, leaves the caller's control bits as it found them. MXCSR's status flags are not control bits: each block restores the word read at the start of the run, flags included.
- **IEEE results everywhere.** No flush-to-zero on any architecture, whatever the caller's word.

The alternative measured against it, (c), computes at round-to-nearest in plain Rust and then corrects by at most one step from the exact sign of the rounding error. It ties (b) on the floor device and is 9–12 % slower on x86. Its failures are quiet: a wrong answer for a narrow input class that the whole-hash pins do not reach. A (b) bug breaks every directed-mode instruction at once, and directed mode is 71 % of the work (§3). (c) stays as a test-only oracle (§4), cross-checked against the blocks per operation and mode. It is not in shipped binaries.

## 2. What each block promises the compiler

One line per promise, and only promises that are true. An undeclared clobber or a false option does not reliably fail the hash pins, so `scripts/ci/check_randomx_fpu_rounding.sh` holds the shape by count. It requires exactly eight `asm!(` in `fpu_rounding.rs` and none elsewhere in the crate. It refuses `pure` and `preserves_flags`, and refuses `_mm_setcsr(`, `_mm_getcsr(` and `fesetround(` anywhere in the crate.

| block | promise or declaration | why it is true |
|---|---|---|
| x86_64 add/sub/mul/div, sqrt | `readonly` | the two `ldmxcsr` read the fixed and the caller's word through their pointers; nothing is written to memory |
| x86_64 add/sub/mul/div, sqrt | `nostack` | nothing is pushed and the red zone is not touched |
| x86_64 add/sub/mul/div, sqrt | operands `a0`, `a1` `inout(xmm_reg)`, `b0`, `b1` `in(xmm_reg)`, the two pointers `in(reg)` | the arithmetic writes only `a0` and `a1`; no other register is touched, so there is nothing else to clobber |
| aarch64 add/sub/mul/div, sqrt | `nomem` | `msr fpcr` and the arithmetic read and write no memory; the words arrive in general registers |
| aarch64 add/sub/mul/div, sqrt | `nostack` | as on x86_64 |
| aarch64 add/sub/mul/div, sqrt | operands as on x86_64, in `vreg`; the two words `in(reg)` | the arithmetic writes only `a0` and `a1` |
| all arithmetic blocks | the control register written back before the block ends | the rule for registers that cannot be an operand is target-specific (`asm.rules.reg-not-output`); compiled code runs under the caller's word, so the block leaves that word in place |
| all arithmetic blocks | **not** `pure` | the arithmetic raises exception flags (MXCSR status bits, FPSR): a side effect, which `pure` forbids (`asm.rules.pure`) |
| all arithmetic blocks | **not** `preserves_flags` | on x86 that option covers MXCSR's exception flags and on aarch64 FPSR (`asm.rules.preserved-registers`); the arithmetic sets both |
| the once-per-run read (`stmxcsr`, `mrs fpcr`) | no options | it runs eight times per hash; a promise would buy nothing |
| the test-only write (`ldmxcsr`, `msr fpcr`) | no options | test code; it stands in for a caller with another word |

A write to FPCR applies to the instructions after it with no barrier; glibc's `fesetround` relies on the same.

## 3. How much of the work runs in a directed mode

Census of the measured comparison: 2,048 hashes (32 seedhashes × 64 inputs),
4.24 billion packed floating-point operations:

| op | nearest | down | up | toward zero | directed share |
|---|---|---|---|---|---|
| add | 304,435,107 | 253,105,768 | 251,798,411 | 249,941,450 | 71.26 % |
| sub | 303,649,927 | 252,861,471 | 251,473,587 | 249,265,518 | 71.28 % |
| mul | 463,190,500 | 386,248,078 | 384,387,459 | 380,234,924 | 71.30 % |
| div | 58,311,281 | 48,358,853 | 48,305,935 | 47,762,684 | 71.24 % |
| sqrt | 87,097,324 | 72,439,523 | 72,014,863 | 71,437,186 | 71.25 % |

**71.3 % of all FP ops run in a directed mode.** The mode resets only at the
start of a hash, so once a CFROUND fires it holds for the rest of the hash.
The plain-Rust nearest path saves less than a third of the work. Every op × mode cell is populated, so the whole-hash
differential does exercise all twenty.

Also from the census: 0 subnormal inputs or results, 0 NaN, 145 exact-zero
results (so the zero-sign rule is live), 1,005,428 infinite results (so the
overflow rule is live: (c) applied it 688,471 times), and the integer slow
path of (c) never ran with FMA available.

## 4. The oracles' edge cases, and why each is right

(c) lives on as the test-only oracle `fpu_rounding::oracle` (`Impl::C`,
and `Impl::CInt` for the integer path). Every case below is in the per-op
cross-check's edge set, which compares both oracles with the blocks per
operation and mode.

| case | what IEEE 754 requires | what (c) does | why it is right |
|---|---|---|---|
| inexact, in range | round to the neighbour in the mode's direction | RN result `s`, then one step if `true − s` points that way | RN is within half an ulp, so the directed result is `s` or its neighbour; the exact sign of the error picks which. At a binade boundary (`s = 2^k`, error negative) the true value lies in `(next_down(s), s)`, so `next_down` is still the answer. |
| exact result | unchanged | error is exactly zero, no step | TwoSum and the FMA residual are exact, so zero error means exact. |
| overflow, RN gives ±inf from finite operands | down/zero give `MAX` for positive, up/zero give `−MAX` for negative, else ±inf | `overflow(s, mode)` before any error is computed | RN only overflows when the true value is beyond `MAX + ulp/2`, so every directed mode's answer is fixed by sign alone. The residual would be NaN here, which is why this check comes first. |
| true value just above `MAX`, RN gives `MAX` | up gives +inf | error positive, `next_up(MAX) = inf` | falls out of the general rule. |
| infinite operand | result exact (inf) | returned unchanged | no rounding happens; E-group infinities (6.85 % of programs) take this path. |
| exact zero from add/sub of opposite values | `+0` in every mode except down, which gives `−0`; `(−0) + (−0) = −0` always | RN gives the right sign except in mode down, which is patched: `−0` unless both operands are `+0` | addition never underflows inexactly, so `s == 0` is exact; only the sign is mode-dependent. 145 such zeros in the census. |
| zero operand in mul/div | exact, sign by XOR | returned unchanged | exact. |
| results near or below `2^−1022` | (cannot occur in RandomX, §5) | FMA path refuses (exponent guard); the integer comparison is exact for subnormals too | the FMA residual is not representable below the guard, the integer comparison does not depend on representability. |
| spurious overflow inside TwoSum next to `MAX` | n/a | halve both operands and take the error's sign from the halves | halving is exact for operands that large; only the sign is needed. Never seen in RandomX ranges (F stays below about 2^49). |
| NaN | n/a | propagated | cannot occur (§5). |

During the comparison the per-op fuzz found two bugs in the first integer
comparison (a shift-direction error and an overflow guard sized wrong), on
`sqrt(2^−1074)` and a quotient just above half the smallest subnormal. Both
are inputs no hash reaches, so the whole-hash pins would have passed with
them in. That is why the per-op cross-check, not the pins, is the oracles'
gate.

## 5. Subnormals: the spec's statement and its proof

**The statement.** RandomX `doc/specs.md:618`: "Due to restrictions on the
values of the floating point registers, no operation results in `NaN` or a
denormal number." Range notes at `doc/design.md:180-194`. The C reference
relies on it too: x86 sets FTZ+DAZ (`intrin_portable.h:168`, 0x9FC0), the
portable path used on aarch64 sets only the rounding mode
(`instructions_portable.cpp`, `fesetround`). The two agree only if no
subnormal ever occurs.

**F group (add, sub, FSCAL): never, for any program.**
- Loads are int32 values converted exactly: 0 or `1 ≤ |x| ≤ 2^31`. A
  registers are `1.fraction × 2^(0..31)`, so `1 ≤ a < 2^32`. FADD/FSUB add
  one of those (`|y| ≥ 1`, or a memory zero, which leaves `f` unchanged).
- If `|f|` is tiny next to `|y|` the result is about `y`, so at least 1/2.
  Otherwise the result is 0 or a multiple of the smaller ulp of the two
  operands, which is at least `2^−112` for any `|f| ≥ 2^−60`. So every
  nonzero F result is above about `2^−127` after an FSCAL.
- FSCAL is a XOR of `0x80F0000000000000`: it flips the sign and the low four
  exponent bits, a scale by `2^x`, `x` odd in −15..15. Applied twice it is
  the identity. FSCAL of `+0` gives `−2^−1008` (normal, mantissa 0); FSCAL of
  that gives `±0`, not a subnormal, because the mantissa is zero. A field-15
  value with a nonzero mantissa (whose FSCAL would be subnormal) can only
  come from FSCAL of a subnormal, which never exists.
- Census: smallest nonzero F result 1.42e−14 (2^−46), largest 5.63e14.

**E group (mul, div, sqrt): only in a program with at least 256 FDIV_M on one
E register; probability about 2^−1698.6 per program.**
- E registers are reloaded every iteration with exponent bits forced to
  0x300..0x3FF (`get_float_mask` and `mask_register_exponent_mantissa`), so
  the start value is in `[2^−255, 2)`. FDIV_M's divisor gets the same mask, so
  it is in `[2^−255, 2)` too.
- FMUL_R multiplies by `a ≥ 1`, so it never lowers a value. FSQRT_R never
  takes a value below `min(x, 1)` (it lowers values above 1, but never past
  1). Rounding down cannot undo either, because the bound in each case is
  representable. So neither lowers the running lower bound, which stays
  below 1. Only FDIV_M lowers it, by less than a factor of 2 each time, and
  at worst by another `(1 − 2^−52)` from rounding down.
- So after `k` divisions in one iteration the value is at least
  `2^−255 · 2^−k · (1 − 2^−52)^k`, normal for `k ≤ 766`.
- CBRANCH counts as modifying every integer register, so no jump target lies
  before an earlier CBRANCH: jump blocks never nest, and each instruction sits
  in at most one. A block re-runs at most twice in a row: a second jump needs
  a carry into bit `b`, a third needs a second carry in a row, and the
  construction (`cimm` bit `b−1` clear) makes two consecutive carries
  impossible. So **each instruction runs at most 3 times per iteration**.
- Hence a subnormal needs `3 × (FDIV_M instructions on one E register) ≥ 767`,
  that is at least 256 of the 384 instructions. FDIV_M is opcode 204..207
  (4/256) with a uniform destination, so 1/256 per instruction per register:
  the binomial tail is 2^−1700.6 per register, 2^−1698.6 for any of the four.
- Census: 3 runs per instruction per iteration at most (as proved), at most 11
  FDIV_M runs on one E register in an iteration, at most 9 FDIV_M
  instructions on one register in a program, smallest E result 2^−254.7.

**What follows.** The spec's sentence is true for F unconditionally and
for E only with overwhelming probability. Nobody can grind for the E case
(2^−1698.6 per program is far past any work an attacker can do), so it is not
an attack; it is a gap between the sentence and the proof. Shekyl closes it by
construction: the blocks give IEEE results with no flush-to-zero on every
architecture (§2), so x86_64 and aarch64 Shekyl nodes agree even on such a
program. Only a disagreement with the C reference's x86 flush-to-zero path
would remain, and the C reference is never part of a shipped binary. The
statement is a spec anchor:
[`RANDOMX_V2_SPEC_ANCHORS.md`](RANDOMX_V2_SPEC_ANCHORS.md) §2 Tier 4.

**The test that holds it:** `vm::subnormal_tests` in `shekyl-pow-randomx`,
a census over whole hashes (`fpu_rounding::fp_census`, test-only) that
asserts:

- no subnormal operand or result, and no NaN;
- every operation × mode cell populated;
- at most three runs of any instruction in one iteration, counted in the
  dispatch loop;
- fewer than 256 FDIV_M on any E register in any program run.

The quick tier hashes two inputs per PR. The long tier,
`no_subnormal_reaches_or_leaves_an_instruction_long` (8 seedhashes × 64
inputs by default), runs nightly.

## 6. What was measured

**The comparison (2026-11-28), hash time against the code before this change**, on the production verification path (`compute_hash` over a prepared cache, light mode). Every timing is the median of three interleaved rounds:

| | floor device, 1 thread | floor device, 4 cores | x86 build VM, 1 thread | x86 build VM, 8 threads |
|---|---|---|---|---|
| (b) | +9.4 % | −9.6 % | within noise | within noise |
| (c), FMA | +9.1 % | −9.6 % | +9 to +12 % | −8 to −12 % |
| (c), integer path | +13.4 % | −13.2 % | +16 % | −14 % |

Both candidates were byte-identical to the C reference in every differential leg on both architectures: T2, all 1,024 canonical pins, and correctness mode. (c) matched the hardware instruction in every operation × mode cell of the per-op fuzz: 350,006,561 cases per cell on x86_64 and 70,006,561 on aarch64, with 0 mismatches. (c)'s x86 figure is an upper bound from a scalar, per-lane prototype. Compiling the FMA in, so that no run-time check remains, did not lower it.

**Reading the caller's word once per run, against once per instruction (ruled: measure in this change).** On the floor device, one thread, the production path, four interleaved rounds of three passes over eight inputs; every variant built from the same tree, a bench-only edit of `fpu_rounding.rs` that is not committed:

| variant | median ms per hash |
|---|---|
| the code before this change | 1,474.7 |
| read once per run, fixed word from a table (the first build) | 1,637.5 |
| read once per run, fixed word computed in a register | 1,635.5 |
| read in every block (`mrs` before the write), fixed word in a register | 1,638.1 |

Reading once per run and reading in every block differ by 0.04 %, inside the rounds' spread: on this core an `mrs` of FPCR costs nothing measurable beside the two `msr` writes. The read stays once per run. In that build the table load cost 0.1 %, also noise; once the instruction loop was split it cost far more (below).

The same rounds put that build 2.5 % behind the comparison's per-instruction prototype (1,598 ms). Two things in it cost time, and they had to go together:

- **The per-instruction test of whether nearest may run as plain Rust** (`mode == NEAREST && plain_nearest`). That fact is fixed for the run, so the VM now picks one of two instruction loops per iteration (`run_instructions::<PLAIN>`), and an instruction tests only its mode.
- **The table of fixed words on aarch64.** With two loops in one function, the table's address spilled to the stack, and every directed-mode instruction then loaded it and the word before its `msr`. With the loops split and the table kept, the hash measured 1,643 ms, no faster. On aarch64 the fixed word is now computed from the mode in a register (two instructions, no load). x86_64 keeps a table, one promoted array, because `ldmxcsr` takes only a memory operand: a block's operand is the table's address plus four times the mode.

Three more interleaved rounds on the floor device, one thread:

| build | median ms per hash | against the code before |
|---|---|---|
| the code before this change | 1,477.5 | |
| loops split, table kept (`a09ef87e16`) | 1,643.2 | +11.2 % |
| loops split, fixed word in a register (`2d5f7e1367`, as built) | 1,531.8 | +3.7 % |

As built, the change costs 3.7 % of a single-thread hash on the floor device, against the comparison's 9.4 % for the per-instruction prototype. On four cores the floor device's rate goes from 2.80 to 2.67 hashes per second.

The raw logs of these rounds are in the Foundation's private operations records, beside the comparison's.

## 7. Measured with this change, for the record

Every number here is from the second floor device (a Raspberry Pi 4 Model B with 4 GB, 1.5 GHz), as built at `2d5f7e1367`; the commit after it changes only x86_64 code.

**`HASH_CPU_NANOS`** is now 1,526,655,460 ns, RT-W10's header series at the thread-CPU 99th percentile ([`rt_w10_hash_series_20261128.md`](../benchmarks/rt_w10_hash_series_20261128.md)). The same device measured 1,480,596,442 ns before the change, so the fix adds 3.1 % at the 99th percentile. The rest of the move from 1,290,885,199 ns is the device: that figure came from the first floor device at 1.8 GHz, and rule 176 provisions at the slower one. One hash is now earned every 6,107 ms of the budget's quarter-core share, up from 5,164 ms.

**The cache derivation (BA-T14)** runs no floating-point instruction, and this change does not touch it. Re-measured for the record: 2.30 s median over three criterion runs ([`cache_derive_pi4_20261128.txt`](../benchmarks/cache_derive_pi4_20261128.txt)).

**`RANDOMX_V2_RUST.md` §8's targets are drift.** None of them was restated anywhere:

- The 36 ms ceiling was "3.0x the C light-VM-JIT median" (12 ms), measured against a C path that no longer exists (§8 cites `src/crypto/rx-slow-hash.c`, deleted). The CI gate kept the ratio (`LATENCY_RATIO_BUDGET = 3.0`, `shekyl-randomx-differential/src/mode_latency.rs`), but against the C reference interpreted, not JIT. The absolute ceiling and the "about four hours" of sync it implies were never restated; `RANDOMX_V2_PLAN.md` still repeats them. A single-thread hash measures 0.74 s on the x86 build VM and 1.53 s on the floor device, 20 and 42 times the ceiling.
- The 200 ms cache-derivation target: the floor device measures 2.09 s (2026-11-10, 1.8 GHz) and 2.30 s (this run), eleven times the target. The ledger row stays stale until the target is restated.

Restating them is a decision this record does not make.

**The floor in `RANDOMX_V2_MINING_ASYMMETRY.md`** is Appendix B.1: this device's single-thread latency and four-core aggregate rate, before and after the change, with the §2 provenance.

**x86_64 on the shared build VM, a sanity figure only:** at the head, 723.3 ms per single-thread hash against 716.0 ms before the change (about +1 %), three interleaved rounds under a load of 7 to 10 from other work on the VM. The x86_64 block's operand is the table's address plus four times the mode, with no load in front (checked in the disassembly).

**Other platforms.** `FpEnv::DEFAULT` assumes a new thread starts at the fixed nearest word; `a_new_thread_starts_at_the_fixed_nearest_word` holds it. The crate's tests, that one included, pass on Linux x86_64 and aarch64, macOS aarch64 and Windows x86_64 (MSVC). At the head, the long oracle fuzz (20M cases per cell) passes on Linux x86_64, macOS aarch64 and Windows x86_64, and the long census (8 × 64 hashes) on Linux x86_64 and macOS aarch64.

**Owed: x86_64 on bare metal.** These re-measurements are to be repeated for x86_64 on bare metal, not on the shared build VM. No bare-metal x86_64 host is free for it yet.

## 8. Open

- **Batching one iteration's floating-point instructions into one block per mode** is a measured round after this change: `docs/FOLLOWUPS.md`. Its first step is to confirm, from the v2 loop, that no integer instruction reads a float register mid-iteration.
