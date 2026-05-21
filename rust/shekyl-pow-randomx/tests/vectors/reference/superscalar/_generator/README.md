<!-- Copyright (c) 2025-2026, The Shekyl Foundation -->
<!-- All rights reserved. BSD-3-Clause -->

# SuperscalarHash reference-vector generator

Reproducer for the committed test vectors at
`rust/shekyl-pow-randomx/tests/vectors/reference/superscalar/*.bin`.
Built against the v2 RandomX fork's reference SuperscalarHash
implementation (`external/randomx-v2/src/superscalar.cpp` +
`blake2_generator.cpp` + `reciprocal.c` + `blake2/blake2b.c`) at pin
`aaafe71` (v2.0.1). The generator is **not** built by `cargo test`;
the Rust test suite consumes the pre-committed `.bin` files via
`include_bytes!`. The generator exists for audit reproducibility per
`docs/design/RANDOMX_V2_RUST.md` §3 "Spec Is the Source of Truth"
and per the design plan `docs/design/RANDOMX_V2_PHASE2B_PLAN.md` §5.3
("F3 — C++ generators for reference vectors") and §5.4 ("F4 —
SuperscalarHash vectors: structured 3-vector seed/nonce decomposition").

## Why a generator and not `cargo build`'s `build.rs`?

Same rationale as the sibling `../aes/_generator/README.md` and Phase
2a's `../argon2d/_generator/README.md`: the test runner is a `cargo
test` integration test with no dev-dep on the C library (the live
differential harness is Phase 2g's separate artifact). The portability
property protected is that `shekyl-pow-randomx`'s own `cargo test`
succeeds without `external/randomx-v2/` initialized and without a C++
toolchain — needed for downstream Rust consumers, cross-compilation
contexts, and fast inner-development loops.

Until Phase 2g lands, the committed `.bin` bytes function as bootstrap
vectors and this `_generator/` directory functions as the reviewer-
runnable reproducer for verifying the bytes match the named pin's
`superscalar.cpp` + `blake2_generator.cpp`.

## Building

Requires a C++17 toolchain (`c++`), GNU `make`, and the
`external/randomx-v2/` submodule initialized at pin `aaafe71`:

```sh
git submodule update --init external/randomx-v2
cd rust/shekyl-pow-randomx/tests/vectors/reference/superscalar/_generator
make           # builds ./gen
make vectors   # regenerates the .bin files in the parent dir
make clean     # removes ./gen
```

`make check-fork-pin` prints the submodule HEAD; verify it equals
`aaafe71322df6602c21a5c72937ac284724ae561`.

## Usage

```
./gen <mode> > vector.bin
```

| Mode       | Layer | Size      | Description                                                               |
|------------|-------|-----------|---------------------------------------------------------------------------|
| `prog_v1`  | A     | ~3.6 KB   | `generateSuperscalar(Blake2Generator(seed=&[], nonce=0))` serialized      |
| `prog_v2`  | A     | ~3.6 KB   | `generateSuperscalar(Blake2Generator(seed=&[], nonce=1))` serialized      |
| `prog_v3`  | A     | ~3.6 KB   | `generateSuperscalar(Blake2Generator(seed=b"shekyl-ss-test", nonce=0))`   |
| `exec_v1`  | B     | 64 B      | `executeSuperscalar(prog_v1, r=[0..8])` → `r[8]` as little-endian `u64`   |
| `exec_v2`  | B     | 64 B      | `executeSuperscalar(prog_v2, r=[0..8])` → `r[8]` as little-endian `u64`   |
| `exec_v3`  | B     | 64 B      | `executeSuperscalar(prog_v3, r=[0..8])` → `r[8]` as little-endian `u64`   |
| `combined` | A+B   | 64 B      | End-to-end: generate `prog_v3`, execute on `r=[0..8]`, emit `r[8]`        |

`combined` produces the same bytes as `exec_v3`; the duplication is
intentional. `exec_v3` is consumed by a Rust test that first loads
the serialized program from `prog_v3`'s `.bin`, then executes; this
attributes a failure to Layer A vs. Layer B. `combined` is consumed
by a Rust test that runs the full generate→execute pipeline with no
intermediate serialization; this is the spec-attestation tuple a
downstream consumer can use to verify their own SS-hash port.

## Why these specific vectors?

Per `RANDOMX_V2_PHASE2B_PLAN.md` §5.4 (F4):

- **Three Layer A vectors structured for failure-mode attribution.**
  - Vector 1: `seed=&[]`, `nonce=0` — baseline determinism. A
    divergence here means the SS-RNG → port-assign → instruction-
    selection pipeline is broken end-to-end on the simplest possible
    inputs.
  - Vector 2: `seed=&[]`, `nonce=1` — same seed as vector 1, differs
    only in nonce. Vectors 1 and 2 diverging from baseline while
    vector 3 doesn't would indicate a Blake2Generator nonce-mixing
    bug specifically.
  - Vector 3: `seed=b"shekyl-ss-test"`, `nonce=0` — different seed,
    same nonce as vector 1. Vector 3 diverging while vector 1
    doesn't would indicate a seed-initialization or seed-byte-
    consumption bug.

  The cross-product gives mechanical attribution: a test name like
  `vector_2_tests_nonce_mixing_only` documents the failure mode the
  vector isolates.

- **Three Layer B vectors threading the same input through each
  program.** Fixed `r=[0, 1, 2, 3, 4, 5, 6, 7]` minimizes Layer B
  vector entropy — the input is the simplest non-degenerate
  permutation of the 8 register slots, so any byte-diff between
  expected and actual is attributable to the execution path, not to
  a complex input shape. Layer B tests decouple "did we generate
  the right program?" (Layer A) from "did we execute the program
  correctly?" (Layer B).

- **One combined end-to-end attestation tuple.** The spec-
  attestation tuple `(seed=b"shekyl-ss-test", nonce=0,
  input=[0..8]) → output[8]` is the canonical "this is what a
  correct SuperscalarHash port produces" reference. Downstream
  consumers (other Shekyl repos; alternative ports) can verify
  against this single vector without needing the wire-format-
  specific Layer A serialization.

## Wire format

### Layer A — Serialized `SuperscalarProgram`

```
+0:  bytes [0..4)        = ASCII magic "SSP1"
+4:  bytes [4..6)        = size: u16 LE (instruction count,
                            0..=SUPERSCALAR_MAX_SIZE = 0..=512;
                            ~448 in practice)
+6:  byte  [6..7)        = address_register: u8 (0..7)
+7:  byte  [7..8)        = reserved (must be 0x00)
+8:  bytes [8..8 + 8*size) = instructions (8 bytes each):
        +0: opcode u8        — SuperscalarInstructionType discriminant (0..13)
        +1: dst    u8        — destination register (0..7)
        +2: src    u8        — source register (0..7)
        +3: mod    u8        — packed mod field
        +4..+8: imm32 u32 LE — instruction immediate
```

The per-instruction layout mirrors `randomx::Instruction`'s declared
layout (`opcode, dst, src, mod, imm32`) so a byte diff between C and
Rust serializations attributes to a predictable offset. `imm32` is
stored explicitly little-endian rather than as host-order memory bytes
so the format is portable to a hypothetical big-endian audit host.

Total bytes per Layer A vector: `8 + 8 * size`. In practice
`generateSuperscalar` produces ~448 instructions, yielding ~3.6 KB
per program. The plan's §5.4 footprint estimate (~600 B per program)
was an overestimate-by-conciseness; the 8-byte-per-instruction format
trades footprint for byte-diff debuggability and reviewer auditability,
and ~11 KB total committed across the 3 Layer A files remains well
within the plan's "comfortable against git-sensible thresholds"
threshold.

`SuperscalarMaxSize = 3 * RANDOMX_SUPERSCALAR_LATENCY + 2 = 512` per
`common.hpp:84` with `RANDOMX_SUPERSCALAR_LATENCY = 170` (per
`configuration.h:47`). The Rust port pins the same value via
`SUPERSCALAR_MAX_SIZE` in `src/superscalar.rs`. The `size` field's
`u16` width is well above the upper bound; the generator additionally
exits non-zero if a program ever exceeds the bound, so a silent
upstream drift would surface at vector-regeneration time.

### Layer B / Combined — Register output

```
+0:  bytes [0..64) = r[8] as 8 × u64 LE
```

64 bytes total. The little-endian per-register encoding matches the
v1 RandomX spec §7.3 step 5's `SuperscalarHash[i](r0..r7)` register
output convention.

## Reviewing the vectors

To verify a `.bin` matches the named pin:

```sh
git -C external/randomx-v2 rev-parse HEAD            # expect aaafe71...
cd rust/shekyl-pow-randomx/tests/vectors/reference/superscalar/_generator
make clean && make vectors
git diff --stat -- ../*.bin                          # expect no output
```

`make vectors` regenerates the `.bin` files in the parent directory,
overwriting the committed bytes. `git diff --stat -- ../*.bin` then
asks git whether the working tree has drifted from `HEAD` on those
specific paths — a clean exit (no output) is the affirmative
attestation that the committed bytes match the named fork pin.

The `.meta.txt` files alongside each `.bin` record the input
parameters, the output size, the fork pin, and the spec section the
vector attests to; those headers are the audit attestation per
`RANDOMX_V2_RUST.md` §3.

## Endianness caveat

All multi-byte fields (size, imm32, register outputs) are emitted
explicitly little-endian in `gen.cpp`. The generator is portable to
big-endian hosts; the resulting bytes are identical regardless of
host endianness. (The AES `_generator/` README notes a little-endian
assumption for `rx_vec_i128` bytes — that does not apply here
because SuperscalarHash has no SIMD types in its wire format.)
