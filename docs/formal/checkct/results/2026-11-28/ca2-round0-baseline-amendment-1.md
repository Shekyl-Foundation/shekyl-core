# `CA-2` Round 0 baseline: amendment 1, before any run (2026-11-28)

**Amends** [the registration](ca2-round0-baseline-registration.md), whose
text stays as written. Nothing has been timed: the codegen check stopped
the run before the shake-down.

## What the gate found

The laptop's build is `ct-dynamic.exe`, SHA-256
`3a0c4384bb65f3085618aaddffcb64d9e00a412f4b100419da4c62c1fd4f8646`, from
a fresh clone of `36f31e3998`: `cargo build --release`, rustc 1.94.0,
`x86_64-pc-windows-msvc`, dynamic CRT (the crate sets no MSVC flags).
Disassembled with `dumpbin` and its PDB, it showed:

| Timed loop | Span between the clock reads | Calls in the span | `red512` |
| --- | --- | --- | --- |
| `helio square (direct)` | 173 instructions | `U256::square_wide` (101, out of line), `to_repr` (the sink) | inlined |
| `helio mul (direct)` | 182 instructions | `U256::mul_wide` (157, out of line), `to_repr` | inlined |
| `fe25519 square (direct)` | 13-instruction body | `FieldElement::square`, `to_repr` | — |
| `fe25519 mul (direct)` | 14-instruction body | `FieldElement::mul`, `to_repr` | — |

The wrapped helpers in the same binary: `op_helio_square` is 156
instructions with one call (`square_wide`), and `op_helio_mul` is 166 with
one call (`mul_wide`). Each is reached from its row's loop through a call.

The registration said the run is not made "if `HelioseleneField` square
or mul is not inlined into its direct loop", and it listed `square_wide`
and `mul_wide` among the calls to look for. Read that way, the out-of-line
wide multiply stops the run, and the run was stopped.

## Why the criterion was mis-stated, and what it is

`CA-2`'s direct path never had the wide multiply inlined:
- **2026-10-24 disassembly** (`CRYPTO_AUDIT.md` §2, "Disassembly"). Both
  fields' `square` "call the same `crypto_bigint::Uint::square_wide` (106
  instructions)". `red512` follows it, inlined.
- **2026-10-25 code-path record.** `(direct)` is "the operator called in
  the timed loop": `HelioseleneField`'s operator, `red512` and the call to
  the wide multiply, is inlined into the loop, at 167 instructions (mul)
  and 177 (square). The wrapped path puts the operator behind the
  non-inlined `op_*` call.
- **Linux at this commit.** `cargo build --release` of the same
  `36f31e3998` on a build VM (`x86_64-unknown-linux-gnu`, rustc 1.94.0,
  SHA-256 `9e505e57…`) reads, between the clock reads:
  - the direct square loop: 176 instructions, with an out-of-line call to
    `square_wide`;
  - the direct mul loop: 183, with an out-of-line call to `mul_wide`;
  - `red512` inlined in both;
  - the wrapped rows: 25 and 26 instructions, each calling `op_helio_*`.

So the direct path is **`red512` inlined into the timed loop, and the
operator not behind the `op_*` wrapper**, whether the wide multiply is a
call or not. The laptop's MSVC binary has that shape. Its spans (173 and
182) are within a few instructions of the Linux build of the same commit
(176 and 183).

## The amendment

1. **The codegen criterion** reads: in each `HelioseleneField` direct
   loop, `red512` is inlined (its constants and multiply-carry chain are
   in the span), and the loop does not call `op_helio_square`,
   `op_helio_mul` or the field operator. The wide multiply may be an
   out-of-line call, as it was in every `CA-2` record. The laptop's binary
   `3a0c4384…` meets it.
2. **The registered binary** is that one, unchanged: `3a0c4384…`, dynamic
   CRT. The 2026-11-25 desktop record used the static CRT. That changes
   library linkage, not the timed loops.

   The after-port acceptance is built the same way, and the same check
   is run on it.
3. **A flat result on this host** reads as **inconclusive for this
   host**, not flat. The codegen matches the Linux build of this commit,
   but this host has never run a `CA-2` field row, and the silicon or the
   OS could still separate it from the 2026-10-25 records. The registration's
   other outcomes stand: nothing else runs, and the next host is the
   maintainer's ruling.
4. **The fat-LTO check** the seat offered was requested before this was
   understood. It is a data point for the record and does not pick the
   binary.

Everything else in the registration stands as written: the shake-down,
the registered run, its command lines and seed, the lines, the
definition of a crossing, the quiet gate and the captures.
