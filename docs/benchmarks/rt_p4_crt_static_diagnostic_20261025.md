# `RT-P4`: the laptop fail, a registered diagnostic set (2026-10-25)

**State of this record: registered, not yet run.** Results are added below
"Registered before the run", and that section is not edited afterwards.

**What this is not.** These are diagnostics. None of them is an attempt
at RT-P4, and none of them changes the laptop's FAIL
([`rt_p4_mlkem_decaps_timing_20261023.md`](rt_p4_mlkem_decaps_timing_20261023.md)).
That verdict, the laptop's entry in
[`rt_p4_attestation.toml`](rt_p4_attestation.toml) and the red standing
check stay as they are whatever these show. The maintainer rules on what
`RPC_CHANNEL.md` §4.3 says once the results are in (ruled 2026-10-25).

## Why

The registered re-run with the shipped flags failed: `valid-vs-invalid`
`|t|` 25.43 and `fixed-vs-invalid` 21.72, about 16 to 18 ns at the
fastest decapsulations. The x86 code of the decapsulation path is the code
the 2026-10-11 run measured and passed. So the cause is one of three
things: the C runtime's `memcpy`/`memset`, now linked statically by
`+crt-static`; the machine or its state; or leakage that depends on the
clock frequency, a property of the platform. Each run below is chosen to
separate them.

## Registered before the run

**The harness, the inputs, the method and the lines** are those of the
2026-10-11 registration, unchanged, each run read on its own: the control
not detected (`|t|` ≤ 10) is void; a null at `|t|` ≥ 4.5 is void; any
comparison above 10 fails; any between 4.5 and 10 is inconclusive; all
four below 4.5 pass. The registered seed (`inputs=registered`).

**The machine:** the maintainer's Windows laptop (Intel Core i9-11950H),
the same machine as the 2026-10-11 run and the 2026-10-25 fail.

**One session, in this order, each run labelled `diagnostic` in its
capture's name, each pinned to logical processor 4 (`start /affinity 10`)
with its sibling, logical 5, left idle:**

| Run | Build | Machine setting |
|---|---|---|
| **A** | The harness at the commit carrying this record, built **without** `+crt-static` | as found (turbo on) |
| **B** | The harness at the commit carrying this record, built **with** `+crt-static`, as it ships | as found (turbo on) |
| **C** | B's binary, unchanged | turbo off: processor maximum state 99 % on mains, or a fixed frequency if the machine offers one; restored after the run |
| **D** | The 2026-10-11 build, rebuilt from a fresh clone of `7b7046579`, no rustflags (that commit has no `rust/.cargo/config.toml`) | as found (turbo on) |

**How each binary is built, and what shows it.** From `rust/`,
unelevated, with no compiler wrapper or cache:
`cargo build --release --locked -p shekyl-rpc-channel --example rt_p4_decaps_timing -vv`,
the full log kept.

- **A** is built from the same clone as B with the configuration's flag
  suppressed for that build. `RUSTFLAGS` set to a single space takes
  precedence over `rust/.cargo/config.toml` and adds no flag (an empty
  value would unset the variable on Windows). What counts is the evidence,
  not the method: no rustc invocation in A's log carries `+crt-static`,
  and the binary's DLL dependencies include the dynamic C runtime
  (`VCRUNTIME140.dll`).
- **B** is built with `RUSTFLAGS` unset. Every rustc invocation carries
  `+crt-static`, and the binary imports no `VCRUNTIME140.dll`. Its
  SHA-256 is compared with the failing run's binary (`f9492887…`); the
  commits differ only in documentation.
- **D** is built the same way as B, from its own fresh clone, with
  `RUSTFLAGS` unset. No invocation carries `+crt-static`, and the binary
  imports `VCRUNTIME140.dll`. Its SHA-256 is compared with the
  2026-10-11 binary's (`1077f646…`).

For each binary: `rustc -vV`, its SHA-256, its DLL dependencies, and the
disassembly of the decapsulation path compared with the 2026-10-11
excerpts in the same way as the 2026-10-25 record (excerpt lines, the
abbreviated claims, and the per-function counts).

**Conditions, for every run, at its start and end.** As the 2026-10-25
record kept them (power, the processor performance counter sampled through
the run, `QueryPerformanceFrequency`, Defender, what else is running with
its CPU time, the sibling's load), and in addition:

- the power plan and its processor maximum and minimum state on mains;
- the clock: the base frequency and the processor performance counter;
- the OS build, with its update revision;
- the microcode revision the processor is running.

For C, the setting is read back before the run starts and again after it
is restored.

**The same four for the 2026-10-11 run.** Its private conditions file
records the power plan (Balanced) and the base clock (2,611 MHz), and the
processor performance counter through the run. It does not record the OS
build's update revision or the microcode. Both are reconstructed from the
machine's own history: the Windows, driver and firmware updates installed
since 2026-10-11, with their dates, including any BIOS or microcode update
the vendor's support agent applied. What cannot be reconstructed is
recorded as not known.

**The reading, registered in advance (the maintainer's, 2026-10-25):**

- **A passes and B fails:** the flag. The static `memcpy`/`memset` are
  where to look.
- **A, B and D all fail:** the machine or its state, not the flag and not
  the build.
- **C is clean while B fails:** frequency-dependent leakage, a property of
  the platform.

Any other combination goes to the maintainer as it stands, with no reading
attached here.

**Attempts.** Each run is made once. A void run may be made again once,
only after its cause is named and fixed. A fail or an inconclusive is not
re-run. Every attempt is recorded, in order, with its full output.

**Where the captures go.** The harness outputs, the excerpt comparisons and
the rustc lines are public, under
`rt_p4_crt_static_diagnostic_20261025_captures/`. The condition files name
the host and list the machine's processes, so they go to the Foundation's
private repository (rule 37), with their hashes here.
