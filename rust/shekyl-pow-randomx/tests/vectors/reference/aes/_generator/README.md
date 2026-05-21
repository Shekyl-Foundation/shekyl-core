<!-- Copyright (c) 2025-2026, The Shekyl Foundation -->
<!-- All rights reserved. BSD-3-Clause -->

# AES reference-vector generator

Reproducer for the committed test vectors at
`rust/shekyl-pow-randomx/tests/vectors/reference/aes/*.bin`. Built
against the v2 RandomX fork's reference AES implementation
(`external/randomx-v2/src/soft_aes.cpp` +
`external/randomx-v2/src/aes_hash.cpp`) at pin `aaafe71` (v2.0.1).
The generator is **not** built by `cargo test`; the Rust test suite
consumes the pre-committed `.bin` files via `include_bytes!`. The
generator exists for audit reproducibility per
`docs/design/RANDOMX_V2_RUST.md` §3 "Spec Is the Source of Truth"
and per the design plan `docs/design/RANDOMX_V2_PHASE2B_PLAN.md`
§5.3 ("F3 — C++ generators for reference vectors").

## Why a generator and not `cargo build`'s `build.rs`?

Same rationale as Phase 2a's
`tests/vectors/reference/argon2d/_generator/README.md`: the test
runner is a `cargo test` integration test with no dev-dep on the C
library (the live differential harness is Phase 2g's separate
artifact). The portability property protected is that
`shekyl-pow-randomx`'s own `cargo test` succeeds without
`external/randomx-v2/` initialized and without a C++ toolchain —
needed for downstream Rust consumers, cross-compilation contexts,
and fast inner-development loops.

Until Phase 2g lands, the committed `.bin` bytes function as
bootstrap vectors and this `_generator/` directory functions as the
reviewer-runnable reproducer for verifying the bytes match the
named pin's `soft_aes.cpp` + `aes_hash.cpp`.

## Building

Requires a C++17 toolchain (`c++`), GNU `make`, and the
`external/randomx-v2/` submodule initialized at pin `aaafe71`:

```sh
git submodule update --init external/randomx-v2
cd rust/shekyl-pow-randomx/tests/vectors/reference/aes/_generator
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

| Mode                    | Size  | Description                                                       |
|-------------------------|-------|-------------------------------------------------------------------|
| `round_enc`             | 48 B  | 3 × `soft_aesenc` 16-byte outputs (inputs hardcoded in `gen.cpp`) |
| `round_dec`             | 48 B  | 3 × `soft_aesdec` 16-byte outputs (inputs hardcoded in `gen.cpp`) |
| `chained_enc`           | 48 B  | 3 successive `soft_aesenc` intermediate states (round 1/2/3)      |
| `chained_dec`           | 48 B  | 3 successive `soft_aesdec` intermediate states (round 1/2/3)      |
| `gen_1r_state42_iters4` | 320 B | `fillAes1Rx4<true>` iters=4: `output[256]` ‖ `final_state[64]`    |
| `gen_4r_state33_iters4` | 256 B | `fillAes4Rx4<true>` iters=4: `output[256]` (no state writeback)   |
| `hash_1r_uniform128`    | 64 B  | `hashAes1Rx4<true>(input=[0x11; 128])` digest                     |
| `hash_1r_empty`         | 64 B  | `hashAes1Rx4<true>(input=&[], 0)` digest (finalization-only)      |

All composite functions are instantiated at `<softAes=true>` so the
emitted bytes are SIMD-codegen-independent; `soft_aesenc` /
`soft_aesdec` themselves are pure LUT implementations with no
conditional codegen.

The inputs that drive each mode (round-primitive states/keys,
chained-pair initial state/key, AesGenerator initial states, hash
inputs) are hardcoded in `gen.cpp` so both the C and Rust sides
share a single source of truth. The Rust test side (`src/aes.rs`'s
`#[cfg(test)] mod tests`) reproduces the same inputs literally so
`include_bytes!` comparison reduces to "output bytes equal".

## Why these specific vectors?

Per `RANDOMX_V2_PHASE2B_PLAN.md` §6.1:

- **Round primitive smoke tests** (`round_enc` / `round_dec`).
  Three byte-for-byte tuples per round operation chosen to cover (a)
  uniform-byte state + uniform-byte key, (b) sequential state + zero
  key (catches a ShiftRows regression), and (c) sequential state +
  offset-sequential key (every byte distinct, maximising mix).
  Validates the `aes` crate's behavior matches the C reference at
  the round level before composing into generators.

- **Chained-pair multi-round F6 supplement** (`chained_enc` /
  `chained_dec`). Three rounds chained for both round operations,
  with intermediate state pinned at each round. Catches the case
  where equivalent-inverse-cipher and FIPS-197 standard inverse
  forms happen to agree on degenerate inputs (e.g., zero key + zero
  state) but diverge by round 2 — per the F6 finding in
  `RANDOMX_V2_PHASE2B_PLAN.md` §5.6.

- **AesGenerator1R / 4R parity**. One vector for each, at iters=4
  (the smallest non-trivial count that produces multi-block output).
  `fillAes1Rx4` writes back state, so the .bin commits both
  `output[256]` and the post-loop `final_state[64]`; `fillAes4Rx4`
  does not write back state, so only `output[256]` is committed.
  Pinning both surfaces guards against a regression in the
  state-writeback contract that the Rust signature (`&mut [u8; 64]`
  vs. `&[u8; 64]`) currently enforces structurally.

- **AesHash1R parity**. Two vectors: a uniform-input case
  (`[0x11; 128]`) and the empty-input case (`&[]`, length 0). The
  empty-input vector pins the finalization-only path's output —
  downstream consumers reproduce it from the published spec
  constants alone.

## Reviewing the vectors

To verify a `.bin` matches the named pin:

```sh
git -C external/randomx-v2 rev-parse HEAD            # expect aaafe71...
cd rust/shekyl-pow-randomx/tests/vectors/reference/aes/_generator
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

The `.bin` files are the raw little-endian-host memory layout of
`rx_vec_i128` (`__m128i` on x86_64, `uint8x16_t` on aarch64),
which is the canonical FIPS-197 byte order for AES state. All
maintainer and CI hosts are little-endian; regenerating on a
big-endian host would require an explicit per-block byteswap step
in `gen.cpp` that is not implemented. The Rust test side compares
to plain `[u8; 16]` / `[u8; 64]` arrays — `aes-0.9.0::Block` is
`Array<u8, U16>`, which is already the canonical FIPS-197 byte
order architecturally portably.

## Pinning soft AES (not hardware AES-NI / RVV / zvkned) for vectors

`aes_hash.hpp` exposes `template<bool softAes>` for each composite;
this generator instantiates `<true>` exclusively. The hardware
paths (`_mm_aesenc_si128` on x86, `vaeseq_u8`+`vaesmcq_u8` on
ARMv8, `aes32esi`/`aes64es` on RISC-V) produce the same byte
output by construction — that's what makes RandomX
implementation-portable — but pinning to soft AES at vector-
generation time isolates "the AES round primitive itself" from
"the platform AES-NI codegen" as a failure-mode attribution
boundary. A future divergence between a hardware path's bytes and
this generator's bytes is a bug in the hardware path, not in the
committed vector.
