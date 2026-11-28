# `CA-2` Round 0 baseline: the registered run (2026-11-28)

**The record of** [the registration](ca2-round0-baseline-registration.md),
as amended by [amendment 1](ca2-round0-baseline-amendment-1.md). Both
programs completed on their first launch under the quiet gate, with no
stop.

**Results:**
- **`CA-2`: the baseline crosses.** Every operand-evidence row of the
  current `HelioseleneField` crosses on the direct path. `Field25519`, the
  Montgomery-form reference under the identical protocol, is flat on every
  row. This is the before-figure a port's acceptance is read against.
- **`CA-4`: RT-P4 passes its own lines.** Its `valid-vs-invalid`
  comparison reads 75.51, 39.2 ns, beyond the accepted 45.41, 35.6 ns.
  That meets `CA-4`'s second reopen criterion, which goes to the
  maintainer.

## The run

- **Host.** The maintainer's Tiger Lake laptop (Core i9-11950H), Windows,
  through the Windows seat.
- **Binaries.** Unrebuilt from the codegen check
  ([`ca2-round0-baseline-binaries.txt`](ca2-round0-baseline-binaries.txt)),
  built from a fresh clone of `36f31e3998`, rustc 1.94.0. The gate script
  checked each hash before its launch:
  - `ct-dynamic.exe` `3a0c4384…` (dynamic CRT);
  - `rt_p4_decaps_timing.exe` `2f70d07b…` (`+crt-static`).
- **The session.** As registered, with nothing between the two programs
  but the gate's samples:
  1. `ct-dynamic 1000000 "helio square (direct)+helio mul (direct)+fe25519 square (direct)+fe25519 mul (direct)+null: helio+null: fe25519+control:"`
     ran 13:28:44Z to 14:04:37Z (2,152 s). Exit 0, empty stderr.
  2. `rt_p4_decaps_timing 1000000 20261128` ran 14:06:53Z to 14:21:54Z
     (901 s). Exit 0, empty stderr.

## Conditions

- **The gate before each launch.** Four quiet 30-second samples, with:
  - Defender at most 0.1 % of one logical processor;
  - total CPU 0.1 to 1.7 %;
  - logical processor 5 at 0.0 to 1.9 %;
  - no browser process, and the laptop on mains power.
- **Affinity** was set at creation and read back as 0x10 (logical
  processor 4), at Normal priority.
- **Logical processor 5**, the sibling, sampled every 10 seconds:
  - ct-dynamic: 214 samples, maximum 1.38 %, mean 0.13 %;
  - RT-P4: 89 samples, maximum 0.41 %.
  - No sample reached 5 %.
- **The laptop was left alone.** The age of its last keyboard or mouse
  input never reset: 23 s at the first gate sample, 2,271 s at
  ct-dynamic's end and 3,308 s at RT-P4's end.
- **Platform.** Mains, battery 100 %, the Balanced plan with its AC
  overlay at best performance, turbo as the platform sets it. The query
  performance counter runs at 10 MHz.
- **Private captures.** The process snapshots, sibling samples, counters
  and gate script are in shekyl-dev,
  `infrastructure/captures/ca2-round0-laptop/2026-11-28/registered/`.

## `ct-dynamic`

The output, byte for byte:
[`ca2-round0-baseline-ct-dynamic.txt`](ca2-round0-baseline-ct-dynamic.txt).
A row's score is the larger of `|t|` raw and `|t|` cropped. The means are
nanoseconds per batch of 32 operations, fixed class first.

**Void checks: clean.**
- Controls: the byte branch reads 2276.04 and the data-dependent loop
  8519.38. Both are detected.
- Nulls: the largest of the eight is `null: helio mul (direct)` at 2.91.
  Every one is under 4.5.

**The operand-evidence rows all cross:**

| Row | `t` | `t` (crop 1 %) | Mean ns, fixed / random |
| --- | ---: | ---: | --- |
| `constant: helio square (direct)` | −16.75 | −51.16 | 566 / 576 |
| `constant: helio mul (direct)` | −14.61 | −27.06 | 765 / 773 |
| `property: helio square (direct) sparse` | −10.81 | −38.26 | 565 / 571 |
| `property: helio square (direct) small` | −14.17 | −50.32 | 563 / 572 |
| `property: helio square (direct) dense` | −18.50 | −45.01 | 570 / 578 |

**The fixed-set rows and their companions.**
- `helio square (direct)` reads 63.09 and `helio mul (direct)` 29.85.
- Their `[fixed-pair]` companions are flat, at 0.37 and 1.25.
- By the harness's reading, that is familiarity with the fixed set. The
  registration does not count it toward a crossing, and the crossing
  stands on the rows above.

**`Field25519`: flat on every row.** The largest is `property: fe25519
square (direct) small`, at 2.73.

In every crossing row the structured or constant class is the faster one,
by 6 to 11 ns per batch of 32.

## RT-P4

The output, byte for byte:
[`ca2-round0-baseline-rt-p4.txt`](ca2-round0-baseline-rt-p4.txt). The
header reads `inputs=NOT-REGISTERED`. The registration chose the seed
`20261128`, outside RT-P4's own registration, and the program labels it.

**RT-P4's own lines: PASS.**
- The reference check: 256 cases, 0 mismatches.
- The message classes: 2,020,000 entries, none decrypting wrongly and
  none not rejected.
- The control: a planted leak of 307 ns (0.5 %) is detected at 533.90.
- The nulls: `invalid-vs-invalid` 1.46 and `valid-vs-valid` 3.28.
- The pass line (message only): 2.22.

**The information comparisons**, against the accepted run of `d4917e9f79`
on this laptop
([record](../../../../benchmarks/rt_p4_mlkem_decaps_timing_20261121_message.md)).
Both runs' ns figures are at the cut-off that maximises `|t|`:

| Comparison | This run | Accepted (`d4917e9f79`) |
| --- | --- | --- |
| `valid-vs-invalid` | **75.51**, 39.2 ns (crop 38); raw 6.59, 36.9 ns | 45.41, 35.6 ns |
| `fixed-vs-invalid` | 30.01, 35.8 ns (crop 0); raw 4.48, 36.2 ns | 29.55, 27.0 ns |
| `fixed-vs-bitflip` | 20.45, 12.1 ns (crop 39); raw 1.01, 6.3 ns | 10.98, 10.3 ns |
| `fixed-vs-valid` | 2.27 | 1.52 |

In each crossing comparison the invalid class is the slower one, as
before.

**`CA-4`'s second reopen criterion** asks whether `valid-vs-invalid` grew
past about 36 ns at `|t|` 45.41 on this laptop. At the maximising
cut-off it reads 39.2 ns at 75.51, so the criterion is met. It goes to
the maintainer.

Context for that reading, without settling it:
- **The raw differences are not the measure.** The `valid-vs-valid` null
  differs by 41.6 ns raw, at `|t|` 3.28, with no class difference to find.
  The accepted figure and this one are both cropped ones.
- **The decapsulation closure is unchanged** from `d4917e9f79` to
  `36f31e3998`: `rust/Cargo.lock` moves none of its crates. The harness
  did change. Its planted control moved onto the pass line's classes,
  which changes the binary (`2f70d07b…` against the accepted
  `2ec40efc…`).
- **A changed build has moved this gap before.** `CA-4` records 13 to
  14 ns at `6b89c4862e` and 35.6 ns at `d4917e9f79`, with identical
  decapsulation instruction counts.

## The codegen check and the shake-down

- **The codegen check:**
  [`ca2-round0-codegen-timed-loops.txt`](ca2-round0-codegen-timed-loops.txt),
  the timed spans of every row's loop in `ct-dynamic.exe`, read with
  its PDB.
  - The capture's file is CRLF, SHA-256 `1fc408c6…`. The file here is
    the same text normalised to LF, as this tree's `.gitattributes`
    requires.
  - The full disassembly (5 MB) is in shekyl-dev,
    `infrastructure/captures/ca2-round0-laptop/2026-11-28/codegen-release/`.
  - Amendment 1 reads it.
- **The shake-down:**
  [`ca2-round0-shakedown-ct-dynamic.txt`](ca2-round0-shakedown-ct-dynamic.txt)
  and [`ca2-round0-shakedown-rt-p4.txt`](ca2-round0-shakedown-rt-p4.txt).
  It was run at 20,000 batches and samples, RT-P4 with seed `777`. Its
  figures are read for no line.

## SHA-256

```text
b5ecbcdf5d4f50480645e7f0818da40b3d6556571dfca8c61e228a08a0097646  ca2-round0-baseline-ct-dynamic.txt
57fe8d12f96d8aac3090db0fb97bf54545074475c868d0c0fc10956c59684ec5  ca2-round0-baseline-rt-p4.txt
b42fb8f6b3a5322a98370d95a7ea52d3bf60023c81131178339d147588adfac4  ca2-round0-baseline-binaries.txt
a7df19945f693a07f2c3bfac28c9478d410095f7dc918b1780316029d50ed7b6  ca2-round0-codegen-timed-loops.txt
d9405c9770a0b9053954c0cf718c033ed6358206aeb6ac3e7bdde5f1a2790056  ca2-round0-shakedown-ct-dynamic.txt
a88e663e17ef99d3608d37b877fd4f843762436e5e504af68f2a47f7ca1a19e1  ca2-round0-shakedown-rt-p4.txt
```

## What follows

The registration's outcome for a crossing baseline:
- the prototypes' direct rows are registered against this run, on this
  host;
- a port's acceptance is read here.

The field and one-proof costs on the floor device and x86_64 were waiting
on this baseline, and are now owed. `CA-4`'s reading is the maintainer's.
