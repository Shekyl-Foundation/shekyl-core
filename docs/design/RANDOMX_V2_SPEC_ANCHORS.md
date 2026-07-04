# RandomX v2 — spec-anchor plan (F4: break the C-fork circularity)

## Front-matter

| Field | Value |
|-------|-------|
| Status | **Reviewed 2026-07-04.** Landing shape ratified: **F4a first** (Tiers 1+2 — derivable-constant + primitive KATs — alone, then F4b/F4c as separate PRs). Argon2d KAT: **both** the Argon2 reference Argon2d vector (precise) and an RFC 9106 Argon2id vector (standards-body cross-check). F4a in progress. |
| Origin | RandomX v2 test-regime audit finding **F4**: every pinned expected value in the verifier's test corpus is derived from the C fork `@ aaafe71`, so the theorem proved is `Rust ≡ C@aaafe71`, never `Rust ≡ spec`. The spec is not in the loop. |
| Parent | Test-regime hardening program (PR-1 #236 parity wiring, PR-2 #239 native-arm, PR-3 #241 runtime-mode wiring — all merged). F4 is the fourth PR; F6/F7 follow. |
| Spec authority | `external/randomx-v2/doc/specs.md` (the pinned fork's own spec text); published primitive standards (RFC 7693 Blake2b, FIPS-197 AES, the Argon2 reference); tevador's v1 test suite in the `external/randomx` (v1) submodule as an independent-provenance oracle. |
| Non-goal | Re-deriving the whole of RandomX from first principles. The goal is to add **independent** anchors alongside the existing fork-derived corpus so a fork substitution or a shared fork/port bug cannot pass unnoticed — not to delete the fork corpus (it remains the exhaustive byte-equality oracle). |

## 0. Why this document exists

Per `05-system-thinking` (specification first) and `26-sub-pr-design-discipline`
(design round before multi-part consensus/crypto code), this doc is the
spec-and-decomposition step before any F4 code. The change touches the
genesis-critical PoW verifier's test substrate; the audit's whole thesis is
that this substrate is currently self-referential, so the fix must be
reviewed for *what it actually anchors against* before it lands.

## 1. The circularity, stated precisely

The verifier's reference corpus is `rust/shekyl-pow-randomx/tests/vectors/reference/`
(T1–T16). Every `.meta.txt` in it names the same provenance:

> ```
> fork = external/randomx-v2/
> pin  = aaafe71322df6602c21a5c72937ac284724ae561 (v2.0.1)
> generator = ./_generator/phase2c/gen.cpp
> ```

So the corpus proves **Rust port ≡ C fork at one pinned commit**. That is
exactly the right thing for a port-fidelity gate and must stay. What it
cannot catch:

1. **A shared bug.** If the spec says X and the fork does Y and the Rust port
   faithfully reproduces Y, the corpus is green and both are wrong.
2. **A substrate substitution.** `fork-pin-sha` (CI-enforced) binds the
   corpus to `aaafe71`, but it binds to *that fork's behavior*, not to the
   spec that fork claims to implement.

F4 adds oracles that are **not** the fork, in three tiers of decreasing
independence and increasing cost.

## 2. Independent anchor inventory (all verified at source before this doc)

### Tier 1 — Self-anchoring derivable constants (strongest break, cheapest)

`specs.md` does not merely *state* the verifier's magic constants — it
**derives** them from a published primitive over a published string:

| Rust constant (`src/aes.rs`) | specs.md derivation | §  |
|------------------------------|---------------------|-----|
| `AES_GEN_1R_KEY0..3` | `Hash512("RandomX AesGenerator1R keys")` | 3.2 |
| `AES_GEN_4R_KEY0..3` | `Hash512("RandomX AesGenerator4R keys 0-3")` | 3.3 |
| `AES_GEN_4R_KEY4..7` | `Hash512("RandomX AesGenerator4R keys 4-7")` | 3.3 |
| `AES_HASH_1R_STATE0..3` | `Hash512("RandomX AesHash1R state")` | 3.4 |
| `AES_HASH_1R_XKEY0..1` | `Hash256("RandomX AesHash1R xkeys")` | 3.4 |
| `RANDOMX_ARGON_SALT` | literal `"RandomX\x03"` | 1.2 |

`Hash512`/`Hash256` **are** Blake2b-512/256 (`specs.md` §1.1). So each
constant can be recomputed by the workspace's own `blake2` crate — itself
anchored in Tier 2 against RFC 7693 — and asserted equal to the hardcoded
Rust value. This converts *"trust the fork's copy of this constant"* into
*"this constant IS Blake2b(published string)"* with the fork nowhere in the
chain.

**Proof of concept (run at design time, not assumed):**

```
Blake2b512("RandomX AesGenerator1R keys")[0:16]  = 53a5ac6d096671622b55b5db1749f4b4
Rust AES_GEN_1R_KEY0                              = 53a5ac6d096671622b55b5db1749f4b4  ✓
[16:32],[32:48],[48:64] all match KEY1/2/3        ✓
```

which also matches specs.md's own printed `key0 = 53 a5 ac 6d …`. The Rust
source even *documents* these derivations in comments (`aes.rs:162-166`) but
never executes them as a test — Tier 1 is turning that comment into an
independent, executed assertion.

### Tier 2 — Primitive KATs against published standards

The verifier rests on three RustCrypto primitives. Anchor each against its
own published test vector, independent of RandomX entirely:

- **Blake2b** (`blake2::Blake2b512/256`, used by `blake2_generator.rs` and
  Tier 1): RFC 7693 §Appendix A test vector.
- **AES round** (`aes::hazmat::cipher_round` /
  `equiv_inv_cipher_round`, used by `aes.rs`): FIPS-197 Appendix B worked
  single-round example — the exact hazmat primitive RandomX composes.
- **Argon2d** (`argon2` crate, `Argon2d`/`V0x13`, used by `argon2d.rs`): the
  Argon2 reference (`draft-irtf-cfrg-argon2` / RFC 9106) Argon2d test vector
  at published params. (RFC 9106's headline KAT is Argon2**id**; the Argon2d
  vector comes from the reference `test.c`. Both are published and non-fork.)

These prove the primitives the whole chain rests on are the standard
functions, not a look-alike.

### Tier 3 — Independent-provenance transfers (tevador v1, v2-delta-audited)

tevador's original v1 suite (`external/randomx/src/tests/tests.cpp`) is
**separate provenance** from the fork's `_generator/phase2c/gen.cpp` — a
different author, a different codebase, written years earlier. Its KATs
transfer to the Rust verifier **only where v2 left the tested semantics
unchanged**, each transfer carrying a **v2 delta audit** citation.

Confirmed-transferable at source:

- **Cache-memory KAT.** `tests.cpp:84-86`: at key `"test key 000"`,
  `cacheMemory[0]==0x191e0e1d23c02186`, `[1568413]==0xf1b62fe6210bf8b1`,
  `[33554431]==0x1f47f056d05cd99b`. *v2 delta audit:* cache init is Argon2d
  over `(key, RANDOMX_ARGON_SALT)` with `ARGON_MEMORY/ITERATIONS/LANES`;
  **all four constants are byte-identical between `external/randomx/src/configuration.h`
  and `external/randomx-v2/src/configuration.h`** (verified: MEMORY 262144,
  ITERATIONS 3, LANES 1, SALT `"RandomX\x03"`), and the v2 changes (AES
  FE-mix, prefetch) live in the VM loop, not cache init. Transfer is sound.
- **SuperscalarHash generator KATs.** `tests.cpp:89-106`: 8 program hashes
  gated on `RANDOMX_SUPERSCALAR_LATENCY==170` (identical v1↔v2). *v2 delta
  audit* to complete during implementation: confirm the superscalar
  generation rules (`specs.md` §6) are v2-unchanged before transferring; if
  any rule moved, the affected hashes stay out with a recorded reason.

### Tier 4 — Hand-derived v2 deltas + FP corners (specs-only; documented as such)

The genuine v2 deltas — the **AES f/e mix** in the VM loop (the `RANDOMX_FLAG_V2`
branch) and the **prefetch tweak** — have **no** independent oracle: specs.md
+ the fork are the only descriptions. Honesty requires stating this rather
than manufacturing false independence:

- The FP register conversion (`specs.md` §4.3.1/§4.3.2) has corner cases
  (subnormals, the exponent/mantissa mask, sign handling) that **can** be
  hand-derived from IEEE-754 semantics independently — a handful of targeted
  `vm.rs` tests with hand-computed expected bits.
- The v2 AES FE-mix itself **stays fork-anchored** (T7 already covers it
  byte-for-byte). F4 does not fake an independent anchor here; it records the
  boundary: *this delta's oracle is specs.md §3.4 + the pinned fork, and that
  is the strongest available until an independent v2 implementation exists.*

## 3. Decomposition by validation surface (`19-validation-surface-discipline`)

These tiers do not share a validation surface, so they should not be one
undifferentiated commit. Recommended split:

- **F4a — primitive-and-constant anchors (Tiers 1+2).** Pure Rust unit tests
  in `shekyl-pow-randomx` (`blake2`/`aes`/`argon2` already deps; **no new
  dependencies**, no fork, no C build). Self-contained, fast, per-PR. This is
  the bulk of the circularity break and the cheapest to review. **Recommended
  first and, if you prefer, sufficient on its own for a first landing.**
- **F4b — tevador transfers + v2-delta audit (Tier 3).** Adds the v1
  submodule as a *documented* independent-provenance source; each KAT carries
  its "v2 delta audit: unchanged per …" citation. Needs the superscalar-rules
  audit finished. Slightly higher review load (the audit judgments).
- **F4c — FP corner-case derivations (Tier 4).** Small; can ride F4a or F4b,
  or defer. Records the fork-anchored-delta boundary explicitly.

Rule 19 says bundle by surface: F4a is one surface (*do our primitives +
constants match published standards*), F4b another (*does the RandomX-specific
machinery match an independent implementation, where v2 didn't change it*).

## 4. What this deliberately does NOT do

- **Does not delete or weaken the fork corpus (T1–T16) or `fork-pin-sha`.**
  Those remain the exhaustive byte-equality oracle; F4 adds a second,
  independent perspective, it does not replace the first.
- **Does not claim independence for the v2 FE-mix.** That delta stays
  fork-anchored with the boundary documented (§2 Tier 4).
- **Does not add runtime dependencies.** Tiers 1+2 use crates already in the
  verifier's tree; Tier 3 uses the already-checked-out v1 submodule as test
  data only.

## 5. Review-round resolutions (2026-07-04)

1. **Landing shape — RESOLVED: F4a first.** Tiers 1+2 (derivable-constant +
   primitive KATs) land alone, on their own branch off `dev`; F4b (tevador
   transfers) and F4c (FP corners) follow as separate PRs. Rationale: highest
   independence, lowest review cost, zero new substrate.
2. **Argon2d KAT source — RESOLVED: both.** The Argon2 reference Argon2d
   vector (the precise anchor for the variant RandomX runs) *and* an RFC 9106
   Argon2id vector (a standards-body cross-check of the `argon2` crate).
3. **Superscalar transfer scope — for F4b.** Transfer the subset whose §6
   rules audit clean as v2-unchanged; record any that don't with the reason.
4. **Doc home — RESOLVED.** This doc commits directly to `dev` (design-branch
   policy); F4a code on its own branch.
