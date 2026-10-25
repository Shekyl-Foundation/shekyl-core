# `RT-P4`: the laptop re-run with the shipped flags, registered 2026-10-23

**State of this record: the one registered run is in, and it FAILS.**
`valid-vs-invalid` (`|t|` = 25.43) and `fixed-vs-invalid` (21.72) are over
the fail line of 10, and `fixed-vs-bitflip` (5.46) is inconclusive. The
control was detected and both nulls are clean, so the run is not void. A
fail is not re-run. By the closing rule below, it goes to the maintainer
with its output, and the laptop's attestation entry is not changed.
Results are added below "Registered before the run", and that section is
not edited afterwards.

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

## Results

### The laptop — FAIL

One attempt, 2026-10-25 00:49:53Z to 00:59:00Z, on the maintainer's
Windows laptop (Intel Core i9-11950H), made by the agent on that machine
from a fresh recursive clone of `caca14a3f`, the head of the pull request
carrying this record, on a local drive holding no synced folder. The
binary was not executed before this run. It was started with
`start /affinity 10`, and its affinity was read back from the running
process as `0x10`, normal priority. Its exit code was 1, the harness's
failing exit. The output is
`rt_p4_mlkem_decaps_timing_20261023_captures/laptop_registered_attempt1.txt`
(5,025 bytes), as relayed by that agent. Its SHA-256 matches the one the
agent took on the machine.

```text
RT-P4 ML-KEM-768 decapsulation timing (fips203), inputs prepared before the loop
arch=x86_64 os=windows samples_per_comparison=1000000 calibration=10000 crops=100 inputs=registered
pass: |t| < 4.5 on every real comparison; null comparisons: |t| < 4.5; control: |t| > 10
comparison=fixed-vs-valid max_abs_t=2.21 median_ns=62900 n0=499545 n1=500455 verdict=no-evidence
comparison=fixed-vs-invalid max_abs_t=21.72 median_ns=61600 n0=499434 n1=500566 verdict=LEAK
comparison=fixed-vs-bitflip max_abs_t=5.46 median_ns=60600 n0=498225 n1=501775 verdict=INCONCLUSIVE
comparison=valid-vs-invalid max_abs_t=25.43 median_ns=60700 n0=500011 n1=499989 verdict=LEAK
null=invalid-vs-invalid max_abs_t=2.10 median_ns=60800 n0=500041 n1=499959 verdict=no-evidence
null=valid-vs-valid max_abs_t=1.85 median_ns=60700 n0=499595 n1=500405 verdict=no-evidence
control=planted-leak fraction=0.005 planted_ns=304 max_abs_t=410.42 verdict=detected
result=FAIL worst_real_abs_t=25.43 worst_null_abs_t=2.10 control_abs_t=410.42
```

(The per-quantile and per-crop lines are in the capture.)

**Read against the lines, in order.** The control is detected (410.42 >
10), and neither null reaches 4.5 (2.10, 1.85), so the run is not void.
Two comparisons are over 10, so the run **fails** (line 3).
`valid-vs-invalid` and `fixed-vs-bitflip` are the two comparisons an
attacker's choice of ciphertext corresponds to; the first fails and the
second is inconclusive.

**What the output shows, stated as observations.**

- *The size.* At the crops where `|t|` peaks, the failing comparisons
  differ by 17.9 ns (`fixed-vs-invalid`, below 61,200 ns) and 16.0 ns
  (`valid-vs-invalid`, below 61,000 ns), on a decapsulation of about
  61 µs: about 0.03 % of one decapsulation. The planted control is 304 ns,
  the registered 0.5 %. So the harness resolved a difference about twenty
  times smaller than the size a pass is registered to exclude. The lines
  are `|t|` lines and do not scale with the control's size, so this is a
  fail as registered.
- *Where.* Every comparison that is over 4.5 compares an invalid
  ciphertext with something else. `fixed-vs-valid`, which never sees an
  invalid ciphertext, and `invalid-vs-invalid` are clean. The difference
  sits at the low cut-offs, near the fastest decapsulations.
- *The code.* The x86 code of the decapsulation path is the code the
  2026-10-11 run measured (below). That run passed with a worst `|t|` of
  3.00.

None of that is a diagnosis. The cause is for the next registration.

**The build.** `cargo build --release --locked -p shekyl-rpc-channel
--example rt_p4_decaps_timing -vv`, unelevated, with `RUSTFLAGS` and
`CARGO_ENCODED_RUSTFLAGS` unset (read before the build), no compiler
wrapper or cache, 111 crates compiled fresh. Every one of the 132 rustc
invocations carries `-C target-feature=+crt-static`, the example's
included. The full build log is kept on the machine (975,412 bytes,
SHA-256 `98b12972…`). `rustc 1.94.0 (4a4ef493e 2026-03-02)`, host
`x86_64-pc-windows-msvc`, LLVM 21.1.8; `fips203` 0.4.3 from the lock
file. The binary is 346,112 bytes, SHA-256 `f9492887…`. Its DLL
dependencies (`dumpbin /dependents`) are `api-ms-win-core-synch-l1-2-0.dll`,
`KERNEL32.dll` and `ntdll.dll`: no `VCRUNTIME140.dll`, no `ucrtbase`, no
`api-ms-win-crt-*`. The flag took effect.

**The code, compared with the 2026-10-11 build.** The new binary's full
disassembly (68,810 lines, larger than before because the C runtime is
now inside the image) was compared with
`rt_p4_mlkem_decaps_timing_20261011_captures/laptop_x86_disasm_excerpts.txt`:

- of the 69 full instruction lines that file quotes, 67 are identical at
  the same address. The other two differ only in RIP-relative
  displacements: an error string's address that moved, and the call to
  `memcpy`, which now comes from the static C runtime;
- all 65 of its abbreviated claims hold (the seven jumps, `ntt` and
  `ntt_inv`'s division blocks, the inlined range checks), with the same
  address, jump, target and preceding instruction;
- over the same 30 functions: 325 conditional jumps, 78 `cmov`/`set` and
  2 divisions, as in the 2026-10-11 table. The bodies match; the
  instruction totals differ by one trailing padding line per function.

The one code the path reaches that changed with `+crt-static` is the C
runtime's `memcpy` (472 call sites) and `memset` (29), now linked in
instead of imported. Both branch on length, and the lengths here do not
depend on the ciphertext. That is a reading of the code, not a
measurement.

**Conditions** (start 00:48:44Z, end 01:00:05Z), recorded as registered:

| | |
|---|---|
| Logical processor | 4, pinned from launch; read back `0x10`; normal priority |
| Its sibling, logical 5 | 0.11 % to 1.09 % in every one-minute sample but one. At 00:57:49Z one sample read 25.32 % together with a processor-performance reading of 0, a bad sample. By elapsed time that falls about 8 minutes in, during the nulls or the control, not the failing comparisons; the harness does not timestamp its comparisons, so that placement is an estimate |
| Logical 4 | 92.4 % in the first, partial minute, then 99.97 % to 100 % |
| `QueryPerformanceFrequency` | 10,000,000 at the start and the end |
| Power | mains, battery 94 %, plan Balanced, no overlay; the same at the end |
| Processor performance, % of base | 160 to 169 through the run (83 before, 106 after); no downward drift apart from the bad sample |
| CPU temperature | not measurable |
| Defender | real-time protection, Tamper Protection, behaviour monitoring and on-access scanning on; no scan running at the start or the end |
| Total CPU load | 4.7 % at the start, 1.5 % at the end |
| CPU time over the run | the kernel 19.84 s; WMI provider host 10.17 s, mostly the agent's own snapshot queries; Defender 4.78 s (3.77 s on 2026-10-11); the vendor's support agents 2.20 s over six processes, none running a diagnostic; the editor 2.78 s; the file-sync clients 0.28 s together; the search indexer 0.00 s |

Before starting, the agent waited for a vendor diagnostic run (about
eight logical processors busy) and Defender's scan of the fresh build to
finish. The attempt started only after four 30-second samples with
Defender under 10 % and total load under 15 %. The full condition files
name the host and list every process on the maintainer's machine, so they
are kept in the Foundation's private repository (rule 37), with these
hashes: start `27ac5724…`, end `3b6e548c…`, samples `fb52e897…`.

**Disclosed.**

- *A stopped start, not counted as an attempt.* Before this run, the agent
  had begun a run from `c6d3df894`, the commit that first carried this
  registration, following an earlier copy of the request. A corrected
  request pinned the run to the pull request's later head, and the agent
  stopped that start on the corrected request, not on anything it showed:
  2026-10-25 00:42:54Z to 00:43:21Z, 27 s of CPU, killed (`exit=-1`).
  Its binary was built the same way (132 of 132 invocations with
  `+crt-static`; SHA-256 `15e45ec6…`), and its disassembly matched the
  2026-10-11 excerpts the same way. Its output is the three header lines
  and nothing after them: no comparison, null, control or result had been
  computed. It is not counted as an attempt. That reading is put to the
  maintainer for a ruling.
- *A scratch folder emptied on the machine.* While the agent waited before
  the stopped start, the contents of its scratch folder were deleted,
  between about 20:13 and 20:17 local time. That took the stopped start's
  build log; its rustc line and flag counts had already been read. Nothing
  was quarantined, no event names what deleted them, and a vendor support
  agent was active at the time. The registered run's work was kept on the
  local drive beside its clone.

**Not done.** No re-run, and no analysis of the cause. The laptop's entry
in [`rt_p4_attestation.toml`](rt_p4_attestation.toml) stays at the
2026-10-11 run, the only passing laptop build, and the standing check
stays red. What comes next is the maintainer's.
