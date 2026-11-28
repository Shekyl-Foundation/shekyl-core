# `CA-2` Round 0: the before-measurement on Tiger Lake, registered 2026-11-28

**State: registered; no registered run has been made.** This document is
not edited after the first run. Results go beside it as dated record
files, and into [`CRYPTO_AUDIT.md`](../../../../design/CRYPTO_AUDIT.md)
§2 (`CA-2`) and §4 (`CA-4`).

## Why this run, and why first

`CA-2` closes on the code side: a representation of `HelioseleneField`
re-measured flat on the direct path (`CRYPTO_AUDIT.md` §2, "Reopen /
close"). Proving a change flat needs a host where the current code
crosses, in the same harness and on the same rows. The desktop
localisation run (2026-11-25) timed the halves and the sparse Montgomery
`Field25519` rows, all flat. It did not time the direct
`HelioseleneField` rows, only their nulls, so it shows nothing about where
the effect sits. Nothing else in the Round 0 runs until this baseline
exists.

## The questions

1. **Does the current `HelioseleneField` cross on the direct path on this
   host?** Use the rows registered for `CA-2` on 2026-10-24 and 2026-10-25:
   fixed sets with their `[fixed-pair]` companions, a constant operand, and
   the sparse, small and dense operand shapes.
2. **What does `CA-4` read in the same session?** That means RT-P4's
   `valid-vs-invalid` and `fixed-vs-bitflip`, on the host where the gap
   was accepted.

## The host

Rick's Tiger Lake laptop (Core i9-11950H, Windows, MSVC), through the
Windows seat, under the quiet gate below. The seat prints the CPU model
first. The run is not made if the model is not the i9-11950H, because the
seat was last used on the i9-13900K desktop.

**`CA-2`'s Tiger Lake Linux workstation is not used.** It is the
maintainer's development machine, which the amendment of 2026-11-21
called suspect for a reported failing core. The current boot's kernel log
backs that report:
- 17 corrected machine-check errors in bank 0 over 2.6 days;
- every error on logical CPUs 1 and 9, the two threads of one physical
  core.

That machine also carries shared editing load from several lanes, and the
estate's standing rule keeps test runs off it. The runs of 2026-10-24 and
2026-10-25 that pinned a core used logical CPU 3. The earlier unpinned
runs could have been scheduled anywhere.

**This host has never run a `CA-2` field row.** The crossings so far were
Linux builds: the workstation's (`x86_64-unknown-linux-gnu`, static) and
a fleet VM's. This build is `x86_64-pc-windows-msvc`. A flat result here
could mean the silicon or the codegen, so the codegen check below comes
first.

## The build

- `docs/formal/checkct/dynamic`, from a fresh clone of the commit that
  carries this registration. Rust 1.94.0, from the crate's
  `rust-toolchain.toml`. `cargo build --release`.
- RT-P4: `rust/shekyl-rpc-channel/examples/rt_p4_decaps_timing.rs`, from
  the same clone, built as RT-P4's registration builds it. That is
  `cargo build --release -p shekyl-rpc-channel --example
  rt_p4_decaps_timing`, with the workspace's `+crt-static` for the MSVC
  target from `rust/.cargo/config.toml`.
- The record states each executable's SHA-256.

## Before the registered run (not results)

1. **The codegen check.** Disassemble the `ct-dynamic` executable with
   its PDB's symbols (`dumpbin /disasm`, or the 1.94.0 `llvm-tools`).
   For each direct row's timed loop (`helio square (direct)`, `helio mul
   (direct)`, `fe25519 square (direct)`, `fe25519 mul (direct)`), report:
   - whether the loop body calls the field operator, `square_wide`,
     `mul_wide` or `red512`, or has them inlined;
   - the inlined operator's instruction count, beside the 167 (mul) and
     177 (square) of the Linux binary of 2026-10-25.

   **If `HelioseleneField` square or mul is not inlined into its direct
   loop, the registered run is not made.** The direct path would not be
   what is measured, and the registration is amended first.
2. **A shake-down** of both programs with the registered command lines
   at 20,000 batches per class for `ct-dynamic`, and for RT-P4 at 20,000
   samples with the unregistered seed `777`. It shows that both run and
   gives the run length. Its figures are not read for any line.

## The registered run

In one session, in this order, with nothing between them but the gate's
samples:

1. `ct-dynamic 1000000 "helio square (direct)+helio mul (direct)+fe25519 square (direct)+fe25519 mul (direct)+null: helio+null: fe25519+control:"`
   - The filter admits, for each field and each direct operation: the
     fixed-set row, its `[fixed-pair]` companion, and the constant row.
     For square only it also admits the sparse, small and dense shape
     rows, since mul has no shape rows in the suite.
   - It also admits all eight null rows (both fields, both operations,
     direct and behind the wrapper) and both positive controls.
   - The `Field25519` rows are the reference: a Montgomery-form field
     under the identical protocol.
2. `rt_p4_decaps_timing 1000000 20261128`.
   - The seed is this registration's choice. The program labels a seed
     outside its own registration.
   - The record states its two validity comparisons, its message-only
     line, its nulls, its planted control and its functional checks.

## The lines

### `ct-dynamic`

A row's `|t|` is the larger of the raw and the cropped figure:
- **above 10** is a crossing;
- **below 4.5** is flat;
- **between the two** is inconclusive, and the row is reported as such.

These are the lines of the 2026-11-21 registration. The run is **void**
if either positive control is not detected or any null reads 4.5 or more.

**The baseline crosses** if the run is not void and at least one of
these operand-evidence rows crosses:
- `constant: helio square (direct)`;
- `constant: helio mul (direct)`;
- `property: helio square (direct) sparse`, `small` or `dense`;
- `helio square (direct) [fixed-pair]` or `helio mul (direct) [fixed-pair]`.

A fixed-set row that crosses while its `[fixed-pair]` companion is flat
is familiarity by the harness's own reading. It is reported, but on its
own it does not make a crossing baseline.

**These same rows are the acceptance after a port:** with the same
filter, flat on this host and on a second x86_64 host, and the floor
device flat as well. The Round 0 document states the full bar.

### RT-P4

RT-P4's own void rules (its nulls and planted control) decide whether the
run counts. The two validity comparisons are `CA-4`'s observation. They
are read against the accepted figure of `d4917e9f79` on this laptop:
`valid-vs-invalid` 45.41, 35.6 ns; `fixed-vs-bitflip` 10.98. A
`valid-vs-invalid` difference above about 36 ns meets `CA-4`'s second
reopen criterion, and goes to the maintainer.

## What follows each outcome

- **The baseline crosses.** It is the before-figure. The prototypes'
  direct rows are registered against it on this host, and a port's
  acceptance is read here.
- **Every operand-evidence row is flat, and the run is not void.** That
  is recorded as this host's result, whatever the codegen check showed.
  Nothing else runs. The only other Tiger Lake host named is the
  workstation above. Using it means an exception to the standing rule on
  a machine with a faulty core, so that goes to the maintainer to rule.
  This registration does not choose it.
- **Void.** As for any `CA-2` row, a void may be made once more after its
  cause is named and fixed. Every attempt's record is committed.

A run that completes is never made again for a better figure.

## Run conditions: the quiet gate

These are the conditions of CA-3's revision-2 attempt-2 laptop gate:
- **Before the launch:**
  - four quiet 30-second samples: Defender under 10 % of one logical
    processor, total under 15 %, and logical processor 5 under 5 %;
  - no browser process running;
  - the process list snapshotted.
- **During the run:**
  - affinity is logical processor 4, at Normal priority;
  - its sibling, logical processor 5, is sampled every 10 seconds;
  - any sample at 5 % or more is recorded with a process snapshot.
- **The stop rule:** three consecutive 10-second samples at 5 % or more
  stop the run.
  - A stopped run is not an attempt, and its partial output is kept
    privately, unread.
  - After a third stop, nothing further runs.
- **Platform:** mains power, the Balanced plan, turbo left as the
  platform sets it. The pinned-clock run of 2026-10-24 eliminated the
  P-state controller as `CA-2`'s mechanism.
- **The maintainer** leaves the laptop alone from the gate to the end. The
  shake-down gives the expected length.

## Captures

The outputs of the codegen check, the shake-down and the registered run go
beside this file, byte for byte, with their SHA-256 sums. The conditions
(process snapshots, sibling samples) go to the private captures, with a
summary in the record.
