<!-- Copyright (c) 2025-2026, The Shekyl Foundation -->
<!-- All rights reserved. BSD-3-Clause -->

# Phase 2c reference-vector generator (T1–T8)

Reproducer for the eight Phase 2c committed test vectors:

- `rust/shekyl-pow-randomx/tests/vectors/reference/cache/t1_cache_derive_fingerprint.bin`
- `rust/shekyl-pow-randomx/tests/vectors/reference/cache/t2_cache_derive_item_batch.bin`
- `rust/shekyl-pow-randomx/tests/vectors/reference/vm/t3_vm_scratchpad_init.bin`
- `rust/shekyl-pow-randomx/tests/vectors/reference/vm/t4_vm_register_init.bin`
- `rust/shekyl-pow-randomx/tests/vectors/reference/vm/t5_vm_program_parse.bin`
- `rust/shekyl-pow-randomx/tests/vectors/reference/vm/t6_vm_spaddr_4iter.bin`
- `rust/shekyl-pow-randomx/tests/vectors/reference/vm/t7_vm_aesmix_4iter.bin`
- `rust/shekyl-pow-randomx/tests/vectors/reference/vm/t8_vm_compute_hash_nop.bin`

Built against the v2 RandomX fork's full reference substrate
(`external/randomx-v2/src/*`) at pin `aaafe71` (v2.0.1). The
generator is **not** built by `cargo test`; the Rust test suite
consumes the pre-committed `.bin` files via `include_bytes!`. The
generator exists for audit reproducibility per
`docs/design/RANDOMX_V2_RUST.md` §3 ("Spec Is the Source of Truth")
and per the design plan
`docs/design/RANDOMX_V2_PHASE2C_PLAN.md` §5.7 ("F7 — T1-T8 spec-
vector matrix") and §9 commit 7.

## Why this generator lives one directory up from its peers

Phase 2a's `argon2d/_generator/` and Phase 2b's `aes/_generator/`
+ `superscalar/_generator/` each scope a single subsystem. Phase 2c's
eight vectors span two subsystems — T1+T2 land under `cache/`, T3-T8
land under `vm/` — so a single `_generator/phase2c/` directory sits
at the shared parent. The `.meta.txt` files alongside each `.bin`
record the per-vector provenance + per-vector wire format; this
README records the cross-vector provenance shared by all eight.

## Why a generator and not `cargo build`'s `build.rs`?

Same rationale as the sibling
`../argon2d/_generator/README.md` and `../aes/_generator/README.md`:
the test runner is a `cargo test` integration test with no dev-dep
on the C library. The portability property protected is that
`shekyl-pow-randomx`'s own `cargo test` succeeds without
`external/randomx-v2/` initialized and without a C++ toolchain
— needed for downstream Rust consumers, cross-compilation
contexts, and fast inner-development loops.

Until Phase 2g lands the live differential harness, the committed
`.bin` bytes function as bootstrap vectors and this `phase2c/`
directory functions as the reviewer-runnable reproducer for
verifying the bytes match the named pin's `randomx.cpp` +
`virtual_machine.cpp` + `vm_interpreted.cpp` + `dataset.cpp` +
`aes_hash.cpp` substrate.

## Building

Requires a C++17 toolchain (`c++`), GNU `make`, the v2 RandomX
fork submodule initialized at pin `aaafe71`, and `~30 s` to
allocate + Argon2d-derive a fresh 256 MiB cache per vector
(the slow path; the cache is rebuilt per-vector since each `./gen
<mode>` is a single-shot process):

```sh
git submodule update --init external/randomx-v2
cd rust/shekyl-pow-randomx/tests/vectors/reference/_generator/phase2c
make           # builds ./gen (~30 s)
make vectors   # regenerates all 8 .bin files (~4 min total)
make clean     # removes ./gen
```

`make check-fork-pin` prints the submodule HEAD; verify it equals
`aaafe71322df6602c21a5c72937ac284724ae561`.

## Usage

```
./gen <mode> > vector.bin
```

| Mode | Size      | Output `.bin`                                      |
|------|-----------|----------------------------------------------------|
| `t1` | 32 B      | `../../cache/t1_cache_derive_fingerprint.bin`      |
| `t2` | 512 B     | `../../cache/t2_cache_derive_item_batch.bin`       |
| `t3` | 32 B      | `../../vm/t3_vm_scratchpad_init.bin`               |
| `t4` | 256 B     | `../../vm/t4_vm_register_init.bin`                 |
| `t5` | 3072 B    | `../../vm/t5_vm_program_parse.bin`                 |
| `t6` | 32 B      | `../../vm/t6_vm_spaddr_4iter.bin`                  |
| `t7` | 1024 B    | `../../vm/t7_vm_aesmix_4iter.bin`                  |
| `t8` | 32 B      | `../../vm/t8_vm_compute_hash_nop.bin`              |

## Canonical inputs

The generator pins three canonical inputs shared by the Rust
spec-vector tests (`src/cache.rs` for T1, T2; `src/vm.rs` for
T3-T8); each is documented inline in `gen.cpp` and mirrored on
the Rust side:

| Constant                  | Value                                                                                                | Used by         |
|---------------------------|------------------------------------------------------------------------------------------------------|-----------------|
| `CANONICAL_SEEDHASH`      | 32 bytes `[0x01, 0x02, …, 0x20]` (sequential)                                                        | T1, T2, T8      |
| `CANONICAL_TEMP_HASH`     | 64 bytes = `Blake2b-512(b"shekyl-randomx-v2-phase2c-canonical-input")` derived at startup            | T3, T4, T5, T6, T7 |
| `T2_ITEM_NUMBERS`         | `[0, 1, 1023, 1024, 524287, 524288, 2097150, 2097151]` (boundary + edge dataset item indices)        | T2              |
| `T8_DATA_INPUT`           | 192-byte ASCII string (preimage label + padding)                                                      | T8              |

The `CANONICAL_TEMP_HASH` placeholder zeros in `gen.cpp` are
documentation only; the actual value is re-derived at runtime
via `derive_canonical_temp_hash()` so the generator is self-
contained (no manual transcription of 64 hex bytes into source).
The Rust side pins the derived bytes explicitly per
`src/vm.rs#mod tests` so reviewers can cross-check by running
the one-line Python equivalent.

## What the stub-NOP VM tests

T6, T7, and T8 use a `StubNopInterpretedLightVm` subclass that
mirrors the Rust port's NOP-stubbed `dispatch_instruction` per
`RANDOMX_V2_PHASE2C_PLAN.md` §5.6: each per-iteration loop body
runs the spAddr derivation, register loads, AES f/e mix,
dataset read, and scratchpad writes — but `executeBytecode` is
skipped. This isolates the iteration-loop substrate (the part
the Rust port implements in Phase 2c) from the per-opcode
bytecode dispatch (the part Phase 2d will implement). A vector
divergence under stub-NOP is attributable to a loop-body bug,
not to a per-opcode semantic mismatch.

Inheritance is from `InterpretedLightVm`, not `InterpretedVm`,
so on-demand dataset item derivation from cache replaces the
2 GiB allocated-dataset path. This matches the Rust port's
`compute_hash`, which is also light-VM-only.

## Two implementation-time divergences worth flagging

Both surfaced as Round 0 findings during commit 7's debug-build
test run; both are documented in
`docs/design/RANDOMX_V2_PHASE2C_PLAN.md` §14 Round 0 R0-D10 and
R0-D11, and re-cited in the per-vector `.meta.txt` for the
affected vector.

- **T1 (`emit_t1`) bypasses `cache->programs`.** The C reference
  `initCache` (`dataset.cpp:131-138`) post-processes its 8
  freshly-generated SuperscalarPrograms by REPLACING each
  `IMUL_RCP` instruction's `imm32` in-place with an index into a
  reciprocal-cache side table. The Rust port keeps the original
  `imm32` and computes the reciprocal on-the-fly during
  superscalar execution (RESULT-equivalent, BYTE-divergent). To
  produce a cache-fingerprint vector that hashes the
  pre-replacement programs (the byte shape the Rust port has by
  construction), `emit_t1` re-runs
  `Blake2Generator(seedhash, 32)` + `generateSuperscalar` 8 times
  on its own SuperscalarProgram array and serializes that array,
  rather than reading `cache->programs[i]` from the initialized
  cache.

- **T8 multi-chain integer-register reset.** The C reference
  constructs a fresh `NativeRegisterFile nreg;` per chain at
  `vm_interpreted.cpp:59`; the struct definition at
  `bytecode_machine.hpp:40` declares `int_reg_t r[RegistersCount]
  = { 0 };`, so each chain begins with the integer registers
  zeroed. The Rust port fuses C's `reg` + `nreg` into a single
  `VmState.r` and re-asserts the per-chain reset explicitly as
  `self.r = [0; 8];` at the top of `execute_program`. T6/T7
  single-chain vectors don't expose this since `VmState::new`
  produces zeroed `r` already; T8 is the first multi-chain
  vector and pinned the discipline. The generator does not need
  any analogous change — it inherits the C reset implicitly via
  the per-chain stack allocation.

## Wire formats

Per-vector wire formats are documented in the sibling `.meta.txt`
files (one per `.bin`). All multi-byte fields are little-endian;
the generator pins `softAes=true` for fillAes / hashAes /
aesenc / aesdec, so the bytes are reproducible on any little-
endian host with a C++17 compiler regardless of AES-NI / NEON /
RVV codegen variance.

## Reviewing the vectors

To verify the eight committed `.bin` files match the named pin:

```sh
git -C external/randomx-v2 rev-parse HEAD            # expect aaafe71...
cd rust/shekyl-pow-randomx/tests/vectors/reference/_generator/phase2c
make clean && make vectors
git diff --stat -- ../../cache/*.bin ../../vm/*.bin  # expect no output
```

`make vectors` regenerates each `.bin` in `../../cache/` or
`../../vm/`, overwriting the committed bytes. `git diff --stat`
then asks git whether the working tree has drifted from `HEAD` on
those specific paths — a clean exit (no output) is the
affirmative attestation that the committed bytes match the named
fork pin.

## Endianness caveat

All multi-byte fields (sizes, imm32 values, u64 register words,
f64 bit patterns) are emitted explicitly little-endian via
`emit_le_u32` / `emit_le_u64` / `emit_le_f64`. The generator is
portable to big-endian hosts; the resulting bytes are identical
regardless of host endianness. The `softAes=true` pin closes off
the AES-NI / NEON / RVV codegen variance that would otherwise
make the scratchpad-fill and AES-mix snapshots host-dependent.
