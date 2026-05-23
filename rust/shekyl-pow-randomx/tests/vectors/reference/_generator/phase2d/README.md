# Phase 2d single-opcode reference-vector generator

This directory rebuilds the seven Phase 2d single-opcode reference
vectors (`T9` through `T15`) consumed by `shekyl-pow-randomx`'s Rust
test suite. The Rust suite consumes the pre-committed `.bin` outputs
in `../../vm/` via `include_bytes!`; this directory is provided for
audit reproducibility per
`docs/design/RANDOMX_V2_PHASE2D_PLAN.md` §6.

## What this generator does

Each vector drives the pinned v2 RandomX fork's
`randomx::BytecodeMachine::compileInstruction` +
`randomx::BytecodeMachine::executeInstruction` against a single
fabricated `randomx::Instruction` per emission. The post-execution
`NativeRegisterFile` is snapshotted in the T4 256-byte layout
(`r[8]` u64 LE || `f[4]` `[f64; 2]` LE || `e[4]` `[f64; 2]` LE ||
`a[4]` `[f64; 2]` LE) so each vector is a stable byte-equality
fixture against the Rust port's `dispatch_instruction` body.

This is intentionally narrower than the Phase 2c generator, which
runs full programs through `randomx_calculate_hash` and snapshots
multi-iteration / multi-chain state. Phase 2d isolates per-opcode
parity so a dispatch-arm divergence surfaces as a single 256-byte
diff against a known input register file rather than as an avalanche
through every downstream iteration.

## Vector matrix

| Vector | Mode | Output                            | Bytes |
|--------|------|-----------------------------------|-------|
| T9     | t9   | `../../vm/t9_vm_single_int_smoke.bin`   | 1024  |
| T10    | t10  | `../../vm/t10_vm_single_fp_smoke_rn.bin`| 1024  |
| T11    | t11  | `../../vm/t11_vm_fp_matrix_rn.bin`      | 2304  |
| T12    | t12  | `../../vm/t12_vm_fp_matrix_rd.bin`      | 2304  |
| T13    | t13  | `../../vm/t13_vm_fp_matrix_ru.bin`      | 2304  |
| T14    | t14  | `../../vm/t14_vm_fp_matrix_rz.bin`      | 2304  |
| T15    | t15  | `../../vm/t15_vm_cfround_throttle.bin`  |  780  |

Each vector's accompanying `.meta.txt` documents the per-probe input
record (opcode, dst, src, mod, imm32, FP mode) and the snapshot
layout.

## How to rebuild

```
make            # builds `gen`
make vectors    # regenerates T9-T15 in ../../vm/
make check-fork-pin   # prints the v2 fork's pinned SHA
```

`gen` links against the v2 RandomX fork at the pin recorded in each
`.meta.txt` and in `phase2c/`'s sibling Makefile. The same fork SHA
must be used for both phase2c/ and phase2d/ — Phase 2d's vectors are
not bit-comparable across fork pins.

## Fork-link surface

Phase 2d's link list is strictly narrower than phase2c/'s because
the single-opcode harness doesn't touch the dataset / cache /
Argon2 / AES / JIT substrate. The minimal v2 substrate required is:

- `bytecode_machine.cpp` — compile and execute the single
  instruction
- `instruction.cpp` — `Instruction::setMod` / `setImm32` getters
- `instructions_portable.cpp` — `mulh` / `smulh` /
  `signExtend2sCompl`
- `reciprocal.c` — linked for the `IMUL_RCP` compile branch (T9
  doesn't exercise it but the link must resolve)
- `allocator.cpp` — `AlignedAllocator::allocMemory` for the 2 MiB
  scratchpad
- `virtual_memory.c` — linked transitively from `allocator.cpp`

No JIT sources, no AES, no Argon2, no Blake2 — Phase 2d is purely
about the `BytecodeMachine` dispatch surface.
