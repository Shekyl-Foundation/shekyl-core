<!-- Copyright (c) 2025-2026, The Shekyl Foundation -->
<!-- All rights reserved. BSD-3-Clause -->

# Argon2d reference-vector generator

Reproducer for the committed test vectors at
`rust/shekyl-pow-randomx/tests/vectors/reference/argon2d/*.bin`.
Built against the v2 RandomX fork's reference Argon2 implementation
(`external/randomx-v2/src/argon2_{ref,core}.c` + `blake2/blake2b.c`)
at pin `aaafe71` (v2.0.1). The generator is **not** built by
`cargo test`; the Rust test suite consumes the pre-committed `.bin`
files via `include_bytes!`. The generator exists for audit
reproducibility per `docs/design/RANDOMX_V2_RUST.md` §3 "Spec Is the
Source of Truth".

## Why a generator and not `cargo build`'s `build.rs`?

Per Phase 2a's scope in `docs/design/RANDOMX_V2_PLAN.md`
§"Track A — Phase 2": *Test runner at
`rust/shekyl-pow-randomx/tests/argon2d.rs` is a `cargo test`
integration test; no dev-dep on the C library (that's Phase 2g's
differential harness, explicitly separate).* The portability
property protected is that `shekyl-pow-randomx`'s own `cargo test`
succeeds without `external/randomx-v2/` initialized and without a
C toolchain — needed for downstream Rust consumers,
cross-compilation contexts, and fast inner-development loops.

Phase 2g lands the live differential cross-check as a separate
test-only artifact; until then, the committed `.bin` bytes
function as bootstrap vectors and this `_generator/` directory
functions as the reviewer-runnable reproducer for verifying the
bytes match `argon2_ref.c` at the named pin.

## Building

Requires a C toolchain (`cc`), GNU `make`, and the
`external/randomx-v2/` submodule initialized at pin `aaafe71`:

```sh
git submodule update --init external/randomx-v2
cd rust/shekyl-pow-randomx/tests/vectors/reference/argon2d/_generator
make           # builds ./gen
make vectors   # regenerates the .bin files in the parent dir
make clean     # removes ./gen
```

`make check-fork-pin` prints the submodule HEAD; verify it equals
`aaafe71322df6602c21a5c72937ac284724ae561`.

## Usage

```
./gen raw   <m_cost> <t_cost> <p_cost> <key> > vector.bin
./gen blake <m_cost> <t_cost> <p_cost> <key> > fingerprint.bin
```

- `raw` mode writes the `m_cost * 1024` bytes of filled Argon2 memory
  to stdout after the omit-finalizer fill from `specs.md` §7.1. This
  is what the Phase 2a committed vectors use.
- `blake` mode writes the 64-byte Blake2b-512 of those memory bytes
  to stdout. Provided for Phase 2g's differential harness; no
  committed Phase 2a vector uses it. (The full-RandomX-parameter
  `blake` run at m=262144 takes substantially longer than the
  small-parameter `raw` runs and is not part of `cargo test`'s
  default loop in Phase 2a.)

The salt is hardcoded to `RANDOMX_ARGON_SALT = "RandomX\x03"` per
`configuration.md`; only the algorithm parameters and key vary.
This matches the production
`shekyl-pow-randomx::argon2d::fill_cache` surface, which also
fixes the salt.

## Why small-parameter vectors?

The Argon2 inner loop (`fill_block` + `blamka_round` per RFC 9106)
is identical regardless of `m_cost`. Byte-for-byte agreement at
`m=8` (the boundary case with `MIN_M_COST = 2*SYNC_POINTS = 8`)
and `m=64` (exercising the cross-segment reference-block
dependency at non-trivial scale) is sufficient evidence that the
Rust `argon2 = "0.5"` crate's `fill_memory` agrees with
`argon2_ref.c` at the production `m=262144`. Phase 2g closes the
loop by asserting parity at the runtime parameters via the live
C reference.

## Reviewing the vectors

To verify a `.bin` matches the named pin:

```sh
git -C external/randomx-v2 rev-parse HEAD            # expect aaafe71...
cd rust/shekyl-pow-randomx/tests/vectors/reference/argon2d/_generator
make clean && make vectors
git diff --stat -- ../*.bin                          # expect no output
```

`make vectors` regenerates the `.bin` files in the parent directory,
overwriting the committed bytes. `git diff --stat -- ../*.bin` then
asks git whether the working tree has drifted from `HEAD` on those
specific paths — a clean exit (no output) is the affirmative
attestation that the committed bytes match the named fork pin.

(The earlier suggestion to run `diff -r . ..` did not work: it compared
the `_generator/` directory's file set — `gen.c`, `Makefile`, this
`README.md` — against the parent's file set — `*.bin` and `*.meta.txt`
— so `diff` always reported "only in" entries instead of the
content-drift check the workflow needs.)

The `.meta.txt` files alongside each `.bin` record the exact command
line, the fork pin, and the spec section the vector attests to;
those headers are the audit attestation per
`RANDOMX_V2_RUST.md` §3.
