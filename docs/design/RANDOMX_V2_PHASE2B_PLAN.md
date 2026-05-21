# RandomX v2 — Track A Phase 2b plan

**Status.** Design-phase closed at Round 3 on 2026-05-21. Implementation
is gated on PR #62 (Phase 2a) merging to `dev` and on workspace MSRV
verification (≥ 1.85). The implementation-open commit is the
post-#62-merge `dev` tip; the branch cuts from there per the F1 in-file-
discipline ordering rationale (§5.1 below).

**Parent plan.** [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §"Track A
— Phase 2" sub-PR 2b is the binding one-line scope ("AES round /
SuperscalarHash primitives from the v2 spec; spec-vector parity"); this
doc expands it into a reviewable change list, dependency-discipline
dispositions, a test plan, and the seven findings that surfaced during
Rounds 2 and 3.

**Base commit.** `dev` at `e63fd2105` (this doc's cut point on
`docs/randomx-v2-phase2b-plan`). The Phase 2b implementation branch
cuts later from post-PR-#62 `dev`.

**Branches.**
- `docs/randomx-v2-phase2b-plan` (this doc only; short-lived per
  `06-branching.mdc` rule 2; one commit; lands on `dev` via its own PR).
- `feat/randomx-v2-phase2b` (implementation; cut from post-PR-#62 `dev`
  per §5.1's F1 ordering rationale; not yet cut as of this doc's commit).

**Scope envelope.** Single PR. Target ≤1500 lines of net-new Rust
(implementation + tests + rustdoc) + ~10 KB of committed reference
vector bytes. ≤6 commits per §7 below. No FFI surface, no C++ caller
rewire, no deletion of existing `src/crypto/rx-slow-hash.c` etc. — those
are Phase 3a/3b/3c/4.

**Cross-references.**
- **Parent plan.** [`RANDOMX_V2_PLAN.md`](./RANDOMX_V2_PLAN.md) §"Track A
  — Phase 2" enumerates the sub-PR split; §"Permanent architectural
  decisions" 1-8 are the locked decisions Phase 2b respects.
- **Design substrate.** [`RANDOMX_V2_RUST.md`](./RANDOMX_V2_RUST.md) §3
  (Spec Is the Source of Truth), §4 (Derived-First Design), §7
  (Isolation Invariants), §8 (Performance Targets), §1.3 (the v1→v2
  delta — SuperscalarHash is **not** in the delta; v2 changes are
  CFROUND throttling, AES tweak, program-size 256→384, prefetch
  lookahead).
- **Phase 1 precedent.** [`RANDOMX_V2_PHASE1_PLAN.md`](./RANDOMX_V2_PHASE1_PLAN.md)
  is the doc-shape template for per-phase plans.
- **Phase 2a precedent.** PR #62 (commit stack
  `7655310e2..f0d648fb2` on `feat/randomx-v2-phase2a`) is the
  workspace-member + Argon2d primitive landing pattern this PR mirrors.
- **Fork pin.** `external/randomx-v2/` submodule at `aaafe71` (v2.0.1).
  Line citations in this doc are stable against that pin.
- **Spec.** `external/randomx-v2/doc/specs.md` §§3.2-3.5 (AES generators
  + BlakeGenerator), §6 (SuperscalarHash + reference CPU + CPU
  simulation), §7.2 (SuperscalarHash initialization).
- **C reference.** `external/randomx-v2/src/aes_hash.{cpp,hpp}` (379 +
  44 lines), `soft_aes.{cpp,h}` (365 + 52 lines), `blake2_generator.{cpp,hpp}`
  (61 + 46 lines), `superscalar.{cpp,hpp}` (903 + 60 lines),
  `superscalar_program.hpp` (83 lines), `common.hpp:84` (the
  `SuperscalarMaxSize` derivation), `configuration.h:47` (the
  `RANDOMX_SUPERSCALAR_LATENCY` value), `instruction.hpp:147` (the
  `sizeof(Instruction) == 8` static_assert).

## 1. Permanent architectural decisions binding Phase 2b

Per `RANDOMX_V2_PLAN.md` §"Permanent architectural decisions" 1-8. Each
is satisfied at Phase 2b open. **The CI greps from Phase 2f are not yet
in place; Phase 2b is written as if they were, so 2f's CI install is a
zero-finding integration rather than a refactor.**

| # | Decision | Phase 2b compliance |
|---|----------|---------------------|
| 1 | C JIT stays miner-only | Zero JIT code in this PR; pure interpreter primitives. |
| 2 | Spec wins over C reference | All six primitives have spec sections (§3.2-3.4 AES round + composites, §3.5 BlakeGenerator, §6 SuperscalarHash). Spec-silent fine-grain details (§3 in `RANDOMX_V2_RUST.md`) are dispositioned via the spec-silence audit table in `superscalar.rs` rustdoc (§5.5 below); the Rust port matches the C iteration order verbatim and files fork-side clarification issues. |
| 3 | Transform-shaped types | Five of the six primitive call surfaces are pure functions; `Blake2Generator` is the one stateful type because §3.5 *defines* it as stateful (get_byte / get_uint32 advance state); the constructor is `Blake2Generator::new(seed, nonce)` and the state is `&mut self` per-call. No module-level state. |
| 4 | No prewarm / no async cache rebuild | Phase 2b adds no scheduling. |
| 5 | No `#[no_mangle]` / `extern "C" fn` / `#[export_name]` | Phase 2f greps continue to zero-hit. |
| 6 | No module-level runtime-mutable state | Spec constants are `const`-only (AES round keys per §3.2-3.4, AesHash1R initial state + extra keys per §3.4, BlakeGenerator's lack of seed-state defaults). |
| 7 | Isolation invariants | `#![deny(unsafe_code)]` preserved at crate level. `aes::hazmat::cipher_round` and `aes::hazmat::equiv_inv_cipher_round` are safe at the public API per §5.6 verification at source. |
| 8 | No env vars / build-flag dispatch | All constants inline; no runtime configuration. |

## 2. Scope (the in-scope work)

Six primitives land:

| # | Primitive | Spec section | C reference | Downstream caller |
|---|-----------|--------------|-------------|--------------------|
| 1 | AES single round (enc + equiv-inv-dec) | building block of §3.2-3.4 | `soft_aes.cpp` + `intrin_portable.h` | basis for #2-#4 |
| 2 | AesGenerator1R | §3.2 | `aes_hash.cpp::fillAes1Rx4` | 2c VM init (per §4.6.1) |
| 3 | AesGenerator4R | §3.3 | `aes_hash.cpp::fillAes4Rx4` | 2c scratchpad init |
| 4 | AesHash1R | §3.4 | `aes_hash.cpp::hashAes1Rx4` | 2c VM finalize (scratchpad fingerprint) |
| 5 | BlakeGenerator | §3.5 | `blake2_generator.cpp` | #6 + 2c program generation |
| 6 | SuperscalarHash (generator + executor) | §6 + §7.2 | `superscalar.cpp` + `superscalar_program.hpp` | 2e `Cache::derive` dataset construction |

### 2.1 Explicitly out of scope

- `Vm<'a>` scratchpad + execution loop (2c).
- v2 bytecode opcode dispatch (2d).
- `Cache::derive` itself wrapping #5+#6 (2e).
- `hashAndFillAes1Rx4` combined-AES-pass optimization (2e; it's a
  callsite optimization on top of #3+#4).
- `CacheStore`, FFI surface, C++ rewire (2f, 3a-3c).

"While we're here" cleanup of unrelated files is forbidden per
`15-deletion-and-debt.mdc`. The single in-file-discipline exception is
§5.1's F1 convergence (Phase 2a's `argon2d` module-level allow → function-
level allow on `fill_cache`), which is allowed because `src/lib.rs` is
edited for substantive Phase 2b reasons.

## 3. Module layout

Forward from Phase 2a's pattern:

```
rust/shekyl-pow-randomx/src/
├── lib.rs                # adds three mod declarations; tightens 2a's mod argon2d allow per F1
├── argon2d.rs            # (unchanged structurally; one allow attribute moves from above to fn)
├── aes.rs                # AES round wrappers + Gen1R + Gen4R + Hash1R
├── blake2_generator.rs   # Blake2Generator PRNG
└── superscalar.rs        # SuperscalarHash generator + executor + spec-silence audit table
```

Reference vectors land at:

```
rust/shekyl-pow-randomx/tests/vectors/reference/
├── argon2d/              # (unchanged from 2a)
├── aes/                  # Gen1R, Gen4R, Hash1R derived vectors + .meta.txt + _generator/
└── superscalar/          # Layer A program serialization + Layer B execution tuples + combined + _generator/
```

Both new `_generator/` directories use **C++** (`gen.cpp` + `g++ -std=c++17`)
because `aes_hash.cpp` and `superscalar.cpp` are C++ templates / classes.
Phase 2a's `_generator/` stays C (no churn).

## 4. Dependency dispositions

Per `17-dependency-discipline.mdc` §"The verification protocol." Two new
workspace dependencies; both verified at source before this doc closes
(see §5.6 for the `aes` verification record).

### 4.1 `aes = "0.9"` (NEW)

```toml
aes = { version = "0.9", default-features = false, features = ["hazmat"] }
```

- **Workspace state.** Not currently a workspace dep. Added at the
  `[workspace.dependencies]` level + at `shekyl-pow-randomx`'s
  `[dependencies]`.
- **API surface needed.** `aes::hazmat::cipher_round(block: &mut Block,
  round_key: &Block)` (single AES encryption round, matching
  `_mm_aesenc_si128` and `soft_aesenc`); `aes::hazmat::equiv_inv_cipher_round`
  (single AES decryption round, equivalent-inverse cipher form matching
  `_mm_aesdec_si128` and `soft_aesdec`). The crate exposes **only** the
  equivalent-inverse form (no separate `inv_cipher_round`), so the wrong-
  form selection failure mode is structurally precluded.
- **Feature plumbing.** `hazmat` is the gating feature
  (`aes-0.9.0/Cargo.toml:43-44`, in the `aes` crate's own manifest —
  not the workspace `rust/Cargo.toml`). Without it the single-round
  API is unreachable.
- **Safety posture.** Both `hazmat` round functions are safe at the public
  API; the `unsafe { $body }` is internal to an `if_intrinsics_available!`
  macro gated by runtime CPUID detection. `#![deny(unsafe_code)]`
  discipline at the crate level survives unchanged.
- **Edition / MSRV.** `aes-0.9.0` is edition 2024 / MSRV 1.85; workspace
  MSRV must be ≥ 1.85 (§9 below).
- **Why not port `soft_aes.cpp`'s LUTs in-tree?** Porting 365 lines of
  LUT data + AES-round logic when an audited RustCrypto crate exists
  contradicts `20-rust-vs-cpp-policy.mdc` "when in doubt, Rust" and
  `17-dependency-discipline.mdc`'s "prefer reuse" guidance. RandomX's
  AES use is not secret-key encryption (the "keys" are public spec
  constants or public block-header-derived bytes); constant-timeness is
  not load-bearing here, but the `aes` crate's soft fallback is constant-
  time fixslicing regardless (`aes-0.9.0/src/lib.rs:20-22`), which is
  strictly better than `soft_aes.cpp`'s LUT path on the constant-time
  axis even though we don't need it.

### 4.2 `blake2 = "0.10"` (NEW direct)

```toml
blake2 = { version = "0.10", default-features = false }
```

- **Workspace state.** Currently a transitive via `argon2 → blake2`.
  Promoted to a direct dep at `[workspace.dependencies]` + at
  `shekyl-pow-randomx`'s `[dependencies]`. Cargo unifies; no additional
  build cost.
- **API surface needed.** `blake2::Blake2b512::new() + update(&[u8]) +
  finalize() -> [u8; 64]` for the §3.5 BlakeGenerator's "S = Hash512(S)"
  rebuild step.
- **Why direct.** Phase 2b is the first crate to need Blake2b *directly*
  (rather than through Argon2's internal use). Per dep-discipline, a
  direct dep is honest about the consumption surface; relying on a
  transitive that may disappear if `argon2` drops its `blake2` dep is
  fragile.

### 4.3 No other new deps

Constants live as `const` items per `25-rust-architecture.mdc`. The
existing `argon2 = "0.5"` dep is unchanged. The existing `zeroize`
transitive (via argon2's `zeroize` feature) is unchanged.

## 5. Findings (Rounds 2 and 3)

### 5.1 F1 — `#[allow(dead_code)]` strategy: targeted per-item with named-dissolution comments

The pattern is to gate the smallest possible surface (each top-level
entry point individually) rather than module-wide or crate-wide. The
crate-wide alternative silences real wiring bugs in 2c/2d/2e; the
module-wide alternative is more granular than crate-wide but still
forecloses the dead-code-as-signal use of the lint within a module.

**Phase 2b's annotated entry points:**

| Module | Entry point | Dissolution sub-PR |
|--------|-------------|---------------------|
| `argon2d.rs` | `fill_cache` (converted from 2a's module-level allow) | 2e (Cache::derive) |
| `aes.rs` | `fill_aes_1r_x4` | 2c (Vm scratchpad init) |
| `aes.rs` | `fill_aes_4r_x4` | 2c (Vm program init) |
| `aes.rs` | `hash_aes_1r_x4` | 2c (Vm scratchpad fingerprint) |
| `blake2_generator.rs` | `Blake2Generator::new` | 2c (program-gen seed) + 2e (SS-hash gen seed) |
| `blake2_generator.rs` | `get_uint32` (+ `get_byte` if not unit-test-only) | as above |
| `superscalar.rs` | `generate_superscalar` | 2e (Cache::derive) |
| `superscalar.rs` | `execute_superscalar` | 2e (Cache::derive) |

Each annotation carries a `// REMOVE WHEN PHASE 2x WIRES THIS:` comment
per `21-reversion-clause-discipline.mdc`. Internals of each module
(helper fns, unit tests, etc.) get exercised by unit tests inside the
same module and don't need the allow.

**In-file-discipline convergence (Phase 2a's `argon2d.rs`).** Phase 2b's
`src/lib.rs` edit (adding three new module declarations) is "the file I'm
editing for substantive reasons" per `15-deletion-and-debt.mdc`'s in-file-
discipline clause. The 2a→2b convergence (move 2a's module-level
`#[allow(dead_code)] mod argon2d;` to a function-level
`#[allow(dead_code)] pub(crate) fn fill_cache(...)`) lands in the **same
commit** as the three new module declarations, not a separate commit.
The commit message body records the convergence rationale:

> incidental: tighten Phase 2a's argon2d module-level allow to function-
> level on fill_cache per the same discipline applied to the new modules.

### 5.2 F2 — `SuperscalarProgram` representation: fixed-size 512-instruction array

**At-source derivation:**
- `RANDOMX_SUPERSCALAR_LATENCY = 170` per `external/randomx-v2/src/configuration.h:47`.
- `SuperscalarMaxSize = 3 * RANDOMX_SUPERSCALAR_LATENCY + 2 = 512` per
  `external/randomx-v2/src/common.hpp:84`.
- `sizeof(Instruction) = 8` per `external/randomx-v2/src/instruction.hpp:147`
  static_assert.

**The value is identical in v1 and v2.** `external/randomx/doc/specs.md:64`
(v1) and `external/randomx-v2/doc/specs.md:64` (v2) both list `170`.
`RANDOMX_V2_RUST.md` §1.3 confirms the v2 delta does not touch
SuperscalarHash. The `superscalar.rs` rustdoc cites
`configuration.h:47` without invoking v1-vs-v2 distinctions.

**Rust port:**

```rust
pub(crate) const RANDOMX_SUPERSCALAR_LATENCY: usize = 170;
pub(crate) const SUPERSCALAR_MAX_SIZE: usize = 3 * RANDOMX_SUPERSCALAR_LATENCY + 2; // = 512

#[repr(C)]
pub(crate) struct SuperscalarInstruction {
    opcode: u8, dst: u8, src: u8, mod_: u8,
    imm32: u32,
} // sizeof = 8

pub(crate) struct SuperscalarProgram {
    instructions: [SuperscalarInstruction; SUPERSCALAR_MAX_SIZE], // 4096 bytes
    size: u32,
    addr_reg: u32,
} // total ≈ 4104 bytes
```

**C-side diagnostic fields deleted in Rust port** per `15-deletion-and-
debt.mdc` default. `ipc`, `codeSize`, `macroOps`, `decodeCycles`,
`cpuLatency`, `asicLatency`, `mulCount`, `cpuLatencies[8]`,
`asicLatencies[8]` are not load-bearing for the execution path (only
for the C `print()` method, which has no Rust equivalent). The
deletion is recorded in the module rustdoc with rationale.

**Cache::derive stack budget.** 8 programs × ~4 KB = ~32 KB total —
well within default Linux 2 MiB thread stacks; no heap allocation
needed.

### 5.3 F3 — C++ generators for reference vectors

Both `aes/_generator/` and `superscalar/_generator/` use `gen.cpp` +
`g++ -std=c++17` (matching the fork's `CMakeLists.txt` C++ standard).
The build approach is documented in each `_generator/README.md` so
reviewers can reproduce vectors with the same toolchain.

Phase 2a's `_generator/` (Argon2d, C) is unchanged.

### 5.4 F4 — SuperscalarHash vectors: structured 3-vector seed/nonce decomposition

Three Layer A vectors, structured to isolate failure modes:

| Vector | seed | nonce | What it tests |
|--------|------|-------|---------------|
| 1 | `0x00` (baseline) | 0 | Baseline determinism |
| 2 | `0x00` | 1 | Blake2Generator nonce-mixing without seed change |
| 3 | `b"shekyl-ss-test"` | 0 | Full RNG re-seeding path |

**Failure-mode attribution.** Vectors 2 and 3 both diverge → bug is
downstream of RNG (port-assign / instruction-selection). Only vector 2
diverges → nonce-handling bug. Only vector 3 diverges → seed-init bug.
Test names encode the attribution
(`vector_2_tests_nonce_mixing_only`, etc.).

Layer B (execution): 1 fixed `input_r[8] = [0, 1, 2, 3, 4, 5, 6, 7]`
threaded through each of the 3 programs → 3 `output_r[8]` vectors of 64
bytes each.

Combined end-to-end: 1 vector
`(seed=b"shekyl-ss-test", nonce=0, input_r=[0..8]) → output_r=[...]` as
the spec-attestation tuple a downstream consumer can verify against
their own SS-hash implementation.

**Total Phase 2b SS-hash vector footprint.** ~2.3 KB committed (3 Layer
A programs at ~600 B + 3 Layer B 64-byte tuples + 1 combined 64-byte
tuple). The AES generator vectors add ~6 KB total (~2 KB per generator
× 3). Combined Phase 2b reference-vector footprint: ~9 KB, comfortable
against git-sensible thresholds.

### 5.5 F5 — Spec-silence audit table in `superscalar.rs` module rustdoc

Per `RANDOMX_V2_RUST.md` §3 "Spec is normative; disagreements file
against the C fork." Fine-grain details where the spec is silent
(e.g., exact Blake2Generator byte-stream consumption order for
register-index selection, exact bit-extraction for §6.3.1 decoder-group
random selection) get an audit-table row.

**Table shape:**

| Spec section silent on | C reference disposition | Rust port disposition | Fork issue filed |
|------------------------|-------------------------|------------------------|------------------|
| (one row per known spec gap) | (line citation into `superscalar.cpp`) | (verbatim) | (issue # at fork) |

**Closing policy.** The audit table's `fork issue filed` column is
populated **before the Phase 2b PR moves out of Draft status**, not as
a post-merge action. Phase 2b is a ~5-day PR; filing fork issues is a
few-minute task per row. Honor-system would be brittle; the PR-lifecycle
gate makes it auditable.

**Long-tail acknowledgement.** A rustdoc paragraph alongside the audit
table acknowledges that filed-but-unresolved fork issues are a known
long-tail item. The Shekyl-Foundation fork's responsiveness to spec-
silence issues is not under Phase 2b's control. The Rust port's
verbatim-port-of-C disposition is the right one regardless of fork-side
resolution status. The audit table records that this is happening
intentionally, not by oversight. The discipline says "spec wins on
disagreement" but in practice spec silence means C wins by default; the
audit table documents that.

### 5.6 F6 — `aes = "0.9.0"` verified at source

Verification performed against `aes-0.9.0` crate source downloaded from
crates.io on 2026-05-21:

| Property | Verified result | Source line |
|----------|-----------------|-------------|
| `pub mod hazmat` exists, feature-gated | Yes, gated by `#[cfg(feature = "hazmat")]` | `aes-0.9.0/src/lib.rs:128-129` |
| `[features] hazmat = []` declared | Yes | `aes-0.9.0/Cargo.toml:43-44` |
| `pub fn cipher_round(block: &mut Block, round_key: &Block)` exists | Yes, safe API | `aes-0.9.0/src/hazmat.rs:65` |
| `cipher_round` semantic = `_mm_aesenc_si128` (RandomX's `soft_aesenc`) | Yes, doc explicit | `aes-0.9.0/src/hazmat.rs:59` |
| `pub fn equiv_inv_cipher_round(...)` exists | Yes, safe API | `aes-0.9.0/src/hazmat.rs:105` |
| `equiv_inv_cipher_round` semantic = `_mm_aesdec_si128` (equivalent-inverse cipher form) | Yes, doc explicit + operation list (`is_box → is_row → im_col → ik_sch`) confirms equivalent-inverse, not FIPS-197 standard inverse | `aes-0.9.0/src/hazmat.rs:90-99` |
| No alternative `inv_cipher_round` (FIPS-197 form) exposed | Confirmed; only `equiv_inv_cipher_round` exists | `aes-0.9.0/src/hazmat.rs` (full file inspected) |
| `Block` type is 16-byte array | `pub type Block = cipher::array::Array<u8, U16>` | `aes-0.9.0/src/lib.rs:153,156` |
| Crate `#![no_std]` | Yes | `aes-0.9.0/src/lib.rs:120` |
| Soft fallback is constant-time | Constant-time fixslicing (no LUTs, no data-dependent branches) | `aes-0.9.0/src/lib.rs:20-22` |
| Edition / MSRV | edition = "2024", rust-version = "1.85" | `aes-0.9.0/Cargo.toml:13-14` |

**Implication for `#![deny(unsafe_code)]`.** Both round functions are
safe at the public API; the runtime-CPUID-gated `unsafe { intrinsics::... }`
is internal to the crate. Phase 2b consumers call only the safe
public surface; crate-level deny survives.

**Implementation-time chained-pair runtime parity test (still required).**
The API-name + doc-string check above confirms the structural semantic
match. The runtime byte-level parity is a separate check that lands in
the implementation PR: take a known `(in, key)` pair, chain through
`equiv_inv_cipher_round` three times, assert each intermediate state
matches what `soft_aesdec` from the C reference produces over the same
chain. Multi-round (not single-round) chaining catches the case where
the equivalent-inverse and FIPS-197 forms happen to agree on degenerate
inputs (e.g., zero key + zero state) but diverge by round 2.

### 5.7 F7 — AES symbol-surface check: §7.1 forward-action via FOLLOWUPS.md

`RANDOMX_V2_RUST.md` §7.1 uses an **explicit list grep** of 10 specific
`randomx_*` symbols, not a `randomx_*` or `aes*` glob. The `aes` crate's
Rust-mangled symbols (`_ZN3aes...`) and AES-NI intrinsics
(`_mm_aesenc_si128`, which lowers to a bare `aesenc` CPU instruction
without an external symbol) **never match any of the 10 banned `randomx_*`
names**. The structural concern about symbol collision is precluded by
§7.1's explicit-list shape.

The `cargo build --release && nm shekyld | grep -iE '(aes|randomx)'`
sanity check is still useful as a **Phase 3c one-shot** confirming
nothing leaks into the daemon by surprise.

**Forward-action placement.** Not in Phase 2b's PR description (which
is brittle to "rely on the 3c author re-reading the 2b PR description
months later" failure). Instead: add a `docs/FOLLOWUPS.md` entry under
the V3.0 pre-genesis queue with target "V3.0 / Phase 3c" naming the
runnable command, expected disposition (no `randomx_*` matches per §7.1;
aes-crate Rust-mangled symbols expected and benign), and §7.1 cross-
reference. Phase 3c PR closes the FOLLOWUPS item. Phase 2b's PR
description mentions it for connection auditability; the load-bearing
record lives in FOLLOWUPS.md.

**No `docs/handoff/` convention exists** in shekyl-core; `docs/FOLLOWUPS.md`
is the workspace's primary cross-PR forward-actions mechanism per
`15-deletion-and-debt.mdc`'s "FOLLOWUPS.md... Items have a target
version" discipline.

## 6. Test strategy

Two layers everywhere, both spec-vector parity per `RANDOMX_V2_RUST.md`
§3.

### 6.1 AES module
- **Round primitive smoke tests.** Three byte-for-byte tuples per
  round operation (`cipher_round`, `equiv_inv_cipher_round`) sourced
  from `tests/vectors/reference/aes/_generator/gen.cpp` using
  `soft_aesenc` / `soft_aesdec`. Validates the `aes` crate's behavior
  matches the C reference at the round level before composing into
  generators.
- **Chained-pair multi-round parity test** (F6 supplement). Three
  rounds chained for both `cipher_round` and `equiv_inv_cipher_round`;
  intermediate state asserted at each round. Catches the case where
  equivalent-inverse and FIPS-197 forms happen to agree on degenerate
  inputs.
- **AesGenerator1R / 4R parity.** Tuples of `(initial_state[64],
  iterations, output[64 * iterations])`. C generator uses
  `fillAes1Rx4<softAes=true>` / `fillAes4Rx4<softAes=true>` for
  architecture-independence.
- **AesHash1R parity.** Tuples of `(input_data, hash[64])`. C
  generator uses `hashAes1Rx4<softAes=true>`.

### 6.2 Blake2Generator module
- **PRNG parity.** Tuples of `(seed, nonce, first N get_byte() outputs,
  first M get_uint32() outputs)`. C generator calls
  `Blake2Generator::getByte()` / `getUInt32()` in a known sequence.

### 6.3 SuperscalarHash module
- **Generator parity (dual layer per F4).**
  - Layer A — *Program structure.* 3 `(seed, nonce, SuperscalarProgram
    serialization)` tuples per the F4 decomposition (baseline /
    nonce-mixing / seed-derivation).
  - Layer B — *Execution.* 1 fixed `input_r[8]` threaded through each
    of the 3 Layer A programs → 3 `output_r[8]` tuples.
- **Combined end-to-end vector.** 1 spec-attestation tuple.

### 6.4 Reference-vector generator extensions

- `tests/vectors/reference/aes/_generator/gen.cpp` — links
  `soft_aes.cpp` + `aes_hash.cpp`; emits `(state, output)` pairs.
- `tests/vectors/reference/superscalar/_generator/gen.cpp` — links
  `superscalar.cpp` + `blake2_generator.cpp` + `blake2/blake2b.c`;
  emits Program structures + execution results.

Both reviewer-runnable per `_generator/README.md`. `cargo test` consumes
pre-committed bytes via `include_bytes!`; no `cargo test` dev-dep on
the C library (that's Phase 2g's differential harness).

## 7. Commit granularity

Per `90-commits.mdc`; targeting ≤6 commits. Imperative subjects ≤72
chars; bodies reference the spec section or design-doc anchor.

1. **`randomx: add aes + blake2 deps; land AES round + Blake2Generator primitives (Phase 2b)`**

   Adds `aes = "0.9"` + `blake2 = "0.10"` to workspace; lands `aes.rs`
   with the round-primitive wrappers and `blake2_generator.rs`. Smoke
   tests only (no vectors yet). Includes the F1 convergence (Phase 2a's
   module-level allow → function-level allow on `fill_cache`) per §5.1.

2. **`randomx: land AesGenerator1R/4R + AesHash1R composites (Phase 2b)`**

   Lands the three AES composites in `aes.rs`. Per-iteration unit tests.

3. **`randomx: land SuperscalarHash program + executor (Phase 2b)`**

   Lands `superscalar.rs` with `SuperscalarProgram` type,
   `generate_superscalar`, `execute_superscalar`. Smoke tests on a
   single fixed seed. **Spec-silence audit table per §5.5 lands in this
   commit as rustdoc, not as a separate deliverable.**

4. **`randomx: add aes_hash.cpp spec-vector parity tests for AES primitives (Phase 2b)`**

   Adds `tests/vectors/reference/aes/` derived vectors + `_generator/`
   + `.meta.txt` provenance + Rust-side `include_bytes!` tests.
   Includes the chained-pair multi-round F6 supplement test.

5. **`randomx: add superscalar.cpp spec-vector parity tests for SuperscalarHash (Phase 2b)`**

   Adds `tests/vectors/reference/superscalar/` derived vectors (Layer A
   + Layer B + combined per F4) + `_generator/` + `.meta.txt` + Rust-
   side tests. Spec-silence audit table's `fork issue filed` column is
   populated by this commit (per §5.5's closing policy).

6. **`docs: changelog entry for RandomX v2 Phase 2b (AES + SuperscalarHash primitives)`**

   Plus the F7 FOLLOWUPS.md entry under V3.0 / Phase 3c.

## 8. Gates

Before any commit lands on `feat/randomx-v2-phase2b`:

- `cargo fmt --check -p shekyl-pow-randomx`
- `cargo clippy -p shekyl-pow-randomx --all-targets -- -D warnings`
- `cargo test -p shekyl-pow-randomx` (smoke + vector parity; no
  `#[ignore]`)
- `cargo doc -p shekyl-pow-randomx --no-deps` (rustdoc clean; intra-
  doc links valid)
- Repo-wide `cargo build --workspace` and `cargo test --workspace`
  green to confirm no incidental break (PR #62's pre-existing
  `shekyl-cli` link issue is tracked outside Phase 2b scope; gate uses
  `cargo check --workspace --lib --tests` for the wide sweep, matching
  Phase 2a's discipline).
- Phase 2f forward-compat isolation greps (each zero-hit):
  - `rg '#\[(?:unsafe\(\s*)?no_mangle' rust/shekyl-pow-randomx/`
  - `rg '\bextern\s+"C"\s+fn\b' rust/shekyl-pow-randomx/`
  - `rg '#\[(?:unsafe\(\s*)?export_name\b' rust/shekyl-pow-randomx/`
  - `rg 'static\s+mut\s+\w+|static\s+\w+\s*:\s*.*(?:Mutex|RwLock|Lazy|OnceCell|OnceLock|AtomicU|AtomicI|AtomicBool|AtomicPtr)' rust/shekyl-pow-randomx/`

## 9. MSRV gate

`aes-0.9.0` requires rustc ≥ 1.85 (edition 2024). Phase 2a's workspace
substrate is "stable, not pinned." Two implementation-PR-time actions:

1. **Workspace `rust/Cargo.toml`** adds explicit `rust-version = "1.85"`
   at the `[workspace.package]` level. Without an explicit pin, a future
   contributor's older toolchain hits cryptic compile errors deep in
   the dependency graph rather than a clean "your rustc is too old"
   message from cargo.

2. **Guix manifest verification.** Per `RANDOMX_V2_RUST.md` §22 (Guix
   discipline), the Guix-built daemon needs rustc ≥ 1.85. If Guix's
   current Rust packaging is older, this triggers either a Guix update
   or a Guix-rustc-version bump in the manifest. **Phase 2b
   implementation-PR sub-task: verify the Guix substrate can supply
   rustc 1.85** before locking the MSRV pin. Locking the pin without
   confirming Guix can supply it creates a Guix-side surprise later.

## 10. Forecast envelope (unchanged from Round 1)

- **Lines of Rust:** ~1500 incl. tests + module rustdoc (C reference
  is 1791 lines; Rust idiom + the `aes` dep removes ~500 lines of LUTs
  and intrinsics dispatch; plus net-new test code).
- **Branch lifetime:** ≤5 working days per `06-branching.mdc`.
- **Commits:** 6 per §7.
- **PR risk classes:** AES is mechanical; Blake2Generator is trivial;
  SuperscalarHash *generator* is the high-risk surface (port-assignment
  algorithm must match C iteration order byte-for-byte). The dual-layer
  vector strategy (§5.4) is the mitigation.

Round 2 / Round 3 refinements are net-zero against this envelope:
structured vectors (F4) are the same vector count as Round 1; spec-
silence audit table (F5) is rustdoc prose; targeted allows (F1) are one-
line-per-item; deletion-with-rationale (F2 diagnostic fields) is one
rustdoc paragraph.

## 11. Forward path

Implementation gated on two preconditions:

1. **PR #62 (Phase 2a) merges to `dev`.** Phase 2b's branch cuts from
   post-merge `dev`. The F1 convergence (§5.1) edits `rust/shekyl-pow-randomx/src/lib.rs`
   in lines that Phase 2a creates; cutting Phase 2b before #62 merges
   creates a merge-time edit conflict on the same lines. Cleaner to
   wait.

2. **Workspace MSRV verified ≥ 1.85.** Per §9. The implementation PR's
   first commit can add the `rust-version = "1.85"` pin; the Guix
   verification can run in parallel with the rest of the
   implementation.

Once both preconditions clear, the Phase 2b branch cuts from `dev` as
`feat/randomx-v2-phase2b` and the 6-commit stack from §7 lands. PR
opens against `dev` with this doc cited in the PR description as the
authoritative design substrate.

## 12. Round history

| Round | Closed | Substrate change |
|-------|--------|------------------|
| 1 | 2026-05-21 | Per-question approvals: `aes = "0.9"` hazmat, `blake2 = "0.10"` direct, dual-layer + combined SS-hash vectors, BlakeGenerator in 2b. |
| 2 | 2026-05-21 | F1 (per-item allows, not module-level), F2 (`SuperscalarMaxSize` derivation), F3 (C++ generators), F4 (structured 3-vector decomposition), F5 (spec-silence audit table), F6 (chained-pair multi-round parity), F7 (new adversarial finding: aes symbol-surface). |
| 3 | 2026-05-21 | F2 at-source disambiguation (170 not 56; identical in v1 and v2); F6 at-source `aes-0.9.0` verification (only equivalent-inverse form exposed; structural FIPS-197 collision precluded); F7 placement (FOLLOWUPS.md V3.0/Phase 3c, not PR description); 8 implementation-PR-time refinement notes captured. |

Round 4 is not anticipated; the substrate is settled.

## 13. References to commit (Phase 2b PR description shape)

The Phase 2b implementation PR description references this doc as the
authoritative substrate. The PR description's structure mirrors PR #62's
shape:

- **Scope** (one-line-per-primitive table matching §2).
- **Out of scope** matching §2.1.
- **Architectural decision compliance** matching §1.
- **Gates (all green)** matching §8.
- **Commit stack** matching §7.
- **Reviewer map** identifying which files carry load-bearing changes
  (`superscalar.rs` is the high-risk file; `aes.rs` and
  `blake2_generator.rs` are mechanical; vector binaries verify via
  `.meta.txt` + `_generator/README.md`).
- **FOLLOWUPS** entries created (the F7 V3.0/Phase 3c handoff).
- **Phase 3c handoff notes** section (mentions the FOLLOWUPS entry).
