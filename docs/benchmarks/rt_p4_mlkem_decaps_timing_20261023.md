# `RT-P4`: the laptop re-run with the shipped flags, registered 2026-10-23

**State of this record: registered, not yet run.** Results are added below
"Registered before the run", and that section is not edited afterwards.

## Why this run

RT-P4 was met on 2026-10-11 on two machines
([`rt_p4_mlkem_decaps_timing_20261011.md`](rt_p4_mlkem_decaps_timing_20261011.md)).
The laptop's binary was built from `7b7046579` for `x86_64-pc-windows-msvc`
with no rustflags. On 2026-10-19 `rust/.cargo/config.toml` gave the MSVC
targets `-C target-feature=+crt-static`, so what ships for that target is
no longer what was measured. RT-P4's standing check
(`scripts/ci/check_rt_p4_standing.py`, RT-W9 step 6) reports exactly that
and fails until this run is recorded (`RPC_CHANNEL.md` §9 RT-P4; the
close-out's D4, ruled 2026-10-22).

The floor device is not re-run: nothing it ships with differs from its
attested run.

## Registered before the run

**The question, the harness, the method, the control and the lines are
the 2026-10-11 registration's, unchanged.** That record's "Registered
before the run" section is this run's registration, with one difference,
the build. In short:

- the harness is `rust/shekyl-rpc-channel/examples/rt_p4_decaps_timing.rs`
  at the commit that carries this record;
- the control is planted at 0.5 % of one decapsulation, and a pass
  excludes a leak of that size or more, and nothing smaller;
- the lines, read in order: the control not detected (`|t|` ≤ 10) is
  **void**; a null comparison at `|t|` ≥ 4.5 is **void**; any of the four
  comparisons above 10 is **fail**; any between 4.5 and 10 is
  **inconclusive**; all four below 4.5 is **pass**.

**The build: what changed.** A release build for `x86_64-pc-windows-msvc`
with `--locked`, from a fresh clone of the commit that carries this
record, so that the clone carries `rust/.cargo/config.toml` and the build
takes `+crt-static` from it as every MSVC build does. No `RUSTFLAGS` in
the environment. The run records evidence that the flag took effect: the
rustc invocation for the harness from a verbose build, showing
`target-feature=+crt-static`, and the binary's DLL dependencies, which
must not include the dynamic C runtime (`VCRUNTIME140.dll`).

**The inputs.** The registered seed, as before (the harness prints
`inputs=registered`). The 2026-10-11 runs have used it. That does not
weaken this run: the harness, the inputs and the lines are fixed in the
tree, and nothing in this run can be chosen after seeing them. Asking the
same question of the rebuilt binary is the point.

**One registered run.** On the laptop, pinned to logical processor 4
(`start /affinity 10`) with its sibling, logical 5, left idle, as on
2026-10-11. A fail or an inconclusive is not re-run. A void may be made
again once, only after its cause is named and fixed. Every attempt is
recorded, in order, with its full output.

**Conditions, recorded as on 2026-10-11, none of them a line.** A drive
holding no synced folder; mains power; a session that is not elevated.
Recorded at the start and the end: the power plan, the processor
performance counter (sampled through the run), `QueryPerformanceFrequency`,
Defender's real-time state, what else is running and its CPU time, and the
sibling's load. CPU temperature is not readable on this machine. The
maintainer's rulings of 2026-10-11 carry over unless the maintainer says
otherwise at the machine: this is the machine, and Defender stays on.

**Also recorded:** the binary's SHA-256; `rustc -vV`; and the x86
disassembly of the same decapsulation path the 2026-10-11 record read
(`laptop_x86_disasm_excerpts.txt`), so the two builds' code can be
compared. `+crt-static` changes which C runtime is linked, and the
expectation is that `fips203`'s code is unchanged. That is checked, not
assumed.

**What closes it.** A pass, under these lines, on this build. The commit
that records the result also replaces the laptop's entry in
[`rt_p4_attestation.toml`](rt_p4_attestation.toml) with this run's commit
and `rustflags = ["-C", "target-feature=+crt-static"]`, and the standing
check passes. A void, a fail or an inconclusive goes to the maintainer
with its output, and the entry is not changed.
