# `RT-P4`: both devices re-run on fips203 0.5.0, registered 2026-11-21

**State of this record: superseded, and not a verdict on RT-P4** (the
maintainer, 2026-11-21; see "Correction" under the results). This
registration took the 2026-10-11 lines unchanged, but the ruling of
2026-10-25 had already changed the pass line for this run. The laptop's run
under it is kept, with its captures, as information. The run that decides
RT-P4 is registered in
[`rt_p4_mlkem_decaps_timing_20261121_message.md`](rt_p4_mlkem_decaps_timing_20261121_message.md).
Results are added below "Registered before the run", and that section is
not edited afterwards.

## Why this run

RT-P4 is attested by
[`rt_p4_attestation.toml`](rt_p4_attestation.toml): a timing run on the
floor device (2026-10-11) and a disassembly entry for the laptop
(2026-10-23, against its 2026-10-11 timing run). The decapsulation image
those runs measured has changed. Pull request #1494 moves six crates of
its closure, and RT-P4's standing check
(`scripts/ci/check_rt_p4_standing.py`) fails on each:

| Crate | Attested | Now |
|---|---|---|
| `fips203` | 0.4.3 | 0.5.0 |
| `crypto-common` | 0.1.6 | 0.1.7 |
| `generic-array` | 0.14.9 | 0.14.7 |
| `typenum` | 1.20.0 | 1.20.1 |
| `zeroize` | 1.8.2 | 1.9.2 |
| `zeroize_derive` | 1.4.3 | 1.5.0 |

`fips203` 0.5.0 changes the decapsulation path itself: Decompress rounds
to the nearest integer, as FIPS 203 requires, where 0.4.3 rounded up, and
both the decryption and the re-encryption inside decapsulation run through
it (`k_pke.rs`). `zeroize` 1.9
wipes with an ordinary fill and an optimisation barrier instead of
volatile writes, and decapsulation holds its intermediates in
`Zeroizing` (`ml_kem.rs`). Neither
build's decapsulation code is expected to be identical to its attested
run's, so both devices are timed again rather than compared by
disassembly.

## Registered before the run

**The question, the harness, the method, the control and the lines are
the 2026-10-11 registration's, unchanged**
([`rt_p4_mlkem_decaps_timing_20261011.md`](rt_p4_mlkem_decaps_timing_20261011.md),
"Registered before the run"). In short:

- the harness is `rust/shekyl-rpc-channel/examples/rt_p4_decaps_timing.rs`
  at the commit that carries this record, 1,000,000 timed decapsulations
  per comparison;
- the four comparisons are `fixed-vs-valid`, `fixed-vs-invalid`,
  `fixed-vs-bitflip` and `valid-vs-invalid`; the two nulls are
  `invalid-vs-invalid` and `valid-vs-valid`;
- the control is planted at 0.5 % of one decapsulation, and a pass
  excludes a leak of that size or more, and nothing smaller;
- the lines, read in order: the control not detected (`|t|` ≤ 10) is
  **void**; a null comparison at `|t|` ≥ 4.5 is **void**; any of the four
  comparisons above 10 is **fail**; any between 4.5 and 10 is
  **inconclusive**; all four below 4.5 is **pass**. Each comparison is
  read on its own figure.

**The subject.** `fips203` 0.5.0, `ml_kem_768`, `try_decaps`, with the
rest of the closure at the versions above, built in release profile from
this workspace's lock file (`--locked`), from a fresh clone of the commit
that carries this record, in a new directory.

**The inputs.** The registered seed (the harness prints
`inputs=registered`). Earlier runs have used it; the harness, the inputs
and the lines are fixed in the tree, and nothing in these runs can be
chosen after seeing them.

**Two registered runs**, each with its own verdict:

- **The floor device** (Raspberry Pi 4, Cortex-A72, rule 76), target
  `aarch64-unknown-linux-gnu`, no rustflags, under a quiet claim in the
  estate's usage ledger. Recorded at the start and the end, as on
  2026-10-11 and none of them a line: the CPU governor, `vcgencmd
  get_throttled` (attempted; it needs root on that device), the
  under-voltage alarm, `cpufreq/stats/time_in_state` and `total_trans`,
  the SoC temperature, and what else is running.
- **The maintainer's Windows laptop** (Intel Core i9-11950H, Tiger Lake),
  target `x86_64-pc-windows-msvc`, taking `+crt-static` from
  `rust/.cargo/config.toml` as every MSVC build does, with no `RUSTFLAGS`
  in the environment. Pinned to logical processor 4 (`start /affinity
  10`), its sibling, logical 5, left idle, the affinity read back from
  the running process. Conditions recorded as on 2026-10-23: a drive
  holding no synced folder, mains power, a session that is not elevated;
  at the start and the end, the power plan, the processor performance
  counter (sampled through the run), `QueryPerformanceFrequency`,
  Defender's real-time state, what else is running and its CPU time, and
  the sibling's load. The maintainer's rulings of 2026-10-11 carry over
  unless the maintainer says otherwise at the machine: this is the
  machine, and Defender stays on. Evidence that the flag took effect: the
  harness's rustc invocation from a verbose build, showing
  `target-feature=+crt-static`, and the binary's DLL dependencies, which
  must not include `VCRUNTIME140.dll`.

**Also recorded for each run:** the binary's SHA-256, `rustc -vV`, and
the time of the run. For the laptop, the x86 disassembly of the
decapsulation path the 2026-10-11 and 2026-10-23 records read, so this
build's code can be compared with theirs.

**Attempts.** A fail or an inconclusive is not re-run. A void may be made
again once, only after its cause is named and fixed. Every attempt is
recorded, in order, with its full output, under
`rt_p4_mlkem_decaps_timing_20261121_captures/` with a `SHA256SUMS`.

**What closes it.** A pass on a device: the commit that records it
replaces that device's entry in `rt_p4_attestation.toml` with a `timing`
entry naming this record and the commit the binary was built from, and
moves `[crates]` to the versions above with their lock checksums; RT-P4's
standing check then passes on that device. A void, a fail or an
inconclusive goes to the maintainer with its output, and the entry is not
changed. The maintainer's ruling of 2026-10-25 on the laptop (a 0.03 %
difference on its `+crt-static` build, accepted as a platform property)
was made on that build's run; a fail here goes to the maintainer again.

## Results

### Correction, 2026-11-21 (the maintainer): this run is information, not a verdict

This registration said its lines were "the 2026-10-11 registration's,
unchanged". They were not the lines in force. The maintainer's ruling of
2026-10-25, the last bullet of "The ruling" in
[`rt_p4_mlkem_decaps_timing_20261023.md`](rt_p4_mlkem_decaps_timing_20261023.md),
reads: "At RT-P4's next required run, the pass line becomes
invalid-vs-invalid differing only in the decrypted message, with
valid-vs-invalid reported as information." This was that next required
run, and the registration cited the 2026-10-25 ruling only for its
platform-property point. So the comparison that decides the verdict was
never run, and the comparison over the old fail line, `fixed-vs-invalid`,
is the valid-against-invalid kind that ruling made information.

The maintainer ruled the run **neither a fail nor a platform property**:
it is information under superseded lines. Its captures and `SHA256SUMS`
stay as committed, and the run's own section below stays as written. Read
as information:

- `fixed-vs-bitflip`, 2.97: clean.
- `fixed-vs-invalid`, 20.38: a difference of 13 to 14 ns, the invalid
  class slower, at the low cut-offs. The 0.4.3 build's run on 2026-10-23
  showed the same comparisons with the same sign, by 16 to 18 ns, so 0.5.0
  did not introduce it.
- `valid-vs-invalid`, 9.64.

A source read of `fips203` 0.5.0's decapsulation, recorded with the
correction:

- K̄ = J(z ‖ c) is computed unconditionally (`ml_kem.rs:128`), before
  re-encryption, whether or not the ciphertext is valid.
- The ciphertext comparison is `subtle`'s `ct_ne`, and the key is selected
  with `conditional_assign` (`ml_kem.rs:144`). Nothing branches on
  validity.
- `compress_vector` multiplies by a precomputed reciprocal of q and shifts
  (`helpers.rs:254`); there is no division by q, so no division whose
  timing depends on the operand (the KyberSlash class).
- `decompress_vector` is a multiply and a shift (`helpers.rs:274`).

### The laptop — FAIL

One attempt, 2026-11-21 15:14:06.91Z to 15:23:22.60Z (556 s), on the
maintainer's Windows laptop, made by the agent on that machine. The
machine enumerated as an Intel Core i9-11950H, 8 cores and 16 logical
processors, before anything ran. A fresh recursive clone of `6b89c4862e`,
the commit that carries this registration (`git status` clean), on a local
fixed NTFS drive holding no synced folder; mains power; an unelevated
session; `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`,
`RUSTC_WRAPPER` and `CARGO_TARGET_DIR` empty and no user cargo config. The
binary was not executed before this run. It was started with `start
/affinity 10`, its affinity read back from the running process as `0x10`,
normal priority, with no arguments. Its exit code was 1, the harness's
failing exit. The output is
`rt_p4_mlkem_decaps_timing_20261121_captures/laptop_registered_attempt1.txt`
(5,025 bytes); its SHA-256 matches the one taken on the machine.

```text
RT-P4 ML-KEM-768 decapsulation timing (fips203), inputs prepared before the loop
arch=x86_64 os=windows samples_per_comparison=1000000 calibration=10000 crops=100 inputs=registered
pass: |t| < 4.5 on every real comparison; null comparisons: |t| < 4.5; control: |t| > 10
comparison=fixed-vs-valid max_abs_t=1.40 median_ns=63100 n0=499545 n1=500455 verdict=no-evidence
comparison=fixed-vs-invalid max_abs_t=20.38 median_ns=61900 n0=499434 n1=500566 verdict=LEAK
comparison=fixed-vs-bitflip max_abs_t=2.97 median_ns=64400 n0=498225 n1=501775 verdict=no-evidence
comparison=valid-vs-invalid max_abs_t=9.64 median_ns=63200 n0=500011 n1=499989 verdict=INCONCLUSIVE
null=invalid-vs-invalid max_abs_t=1.75 median_ns=61700 n0=500041 n1=499959 verdict=no-evidence
null=valid-vs-valid max_abs_t=1.43 median_ns=64300 n0=499595 n1=500405 verdict=no-evidence
control=planted-leak fraction=0.005 planted_ns=322 max_abs_t=374.55 verdict=detected
result=FAIL worst_real_abs_t=20.38 worst_null_abs_t=1.75 control_abs_t=374.55
```

(The per-quantile and per-crop lines are in the capture.)

**Read against the lines, in order.** The control is detected (374.55 >
10), and neither null reaches 4.5 (1.75, 1.43), so the run is not void.
`fixed-vs-invalid` is over 10, so the run **fails** (line 3).
`valid-vs-invalid`, one of the two comparisons an attacker's choice of
ciphertext corresponds to, is inconclusive (line 4); the other,
`fixed-vs-bitflip`, is below 4.5.

**What the output shows, stated as observations.**

- *The size.* Where `|t|` peaks, `fixed-vs-invalid` differs by 12.7 ns
  (below 62,000 ns) and `valid-vs-invalid` by 14.0 ns (below 62,700 ns), on
  a decapsulation of about 62 µs: about 0.02 % of one decapsulation. In
  both the invalid class is the slower. The planted control is 322 ns, the
  registered 0.5 %.
- *Where.* Both comparisons over 4.5 compare an invalid ciphertext with a
  valid one, and both peak at low cut-offs, near the fastest
  decapsulations. `fixed-vs-valid` and the null `invalid-vs-invalid` are
  clean. `fixed-vs-bitflip`, whose class 1 is also invalid, is below 4.5
  here (it was 5.46 on 2026-10-23).
- *Beside 2026-10-23.* That build's run failed on the same two
  comparisons, by 17.9 ns and 16.0 ns, with the same sign and at the same
  low cut-offs.

**The build** (`laptop_rustc_vV.txt`, `example_rustc_line.txt`). rustc
1.94.0 (`4a4ef493e`, LLVM 21.1.8), `fips203` 0.5.0 from the lock.
`cargo build --release --locked -p shekyl-rpc-channel --example
rt_p4_decaps_timing -v` exited 0; all 136 rustc invocations carry
`-C target-feature=+crt-static`, the harness's included (its line is
committed with the toolchain's path under the user profile replaced by
`<rustup home>`, nothing else changed). The binary is 345,088 bytes, SHA-256
`009df043067fd669db2e084ab2775b8be0d56ae6889c5ea54f3b0d0d2d9dc1ef`; `dumpbin
/dependents` lists `api-ms-win-core-synch-l1-2-0.dll`, `KERNEL32.dll` and
`ntdll.dll`, and no `VCRUNTIME140.dll`.

**The code** (`laptop_x86_disasm_excerpts_crt_static.txt`, from this
binary's `dumpbin /disasm`, in the 2026-10-23 file's sections). fips203
changed, so addresses are this build's own and no same-address comparison
is made. `ml_kem_decaps_internal`'s ciphertext comparison is a `sete`
accumulated through `subtle::black_box` into the choice, as before, and the
function has 9 conditional jumps. Over the 29 functions whose symbols name
fips203, `subtle::black_box`, keccak or sha3: 7,793 instructions, 371
conditional jumps, 78 cmov/set, 2 div. The agent made the excerpts with a
PowerShell script, as that machine has no Python, not with the
2026-10-23 script; per-function instruction counts may differ from that
record's by padding lines.

**Conditions**, none of them a line (the full records, which list every
process on the machine, are kept in the estate's private captures):

| Condition | At the run |
|---|---|
| Power | mains, battery 98 % charging, start and end; plan Balanced. The AC power overlay was set (`ded574b5-…`) at the start and the end; on 2026-10-23 there was none |
| `QueryPerformanceFrequency` | 10,000,000, start and end |
| Defender | real-time, tamper, behaviour and on-access protection on, start and end (left on, the maintainer's standing ruling); no scan running |
| Quiet before the start | four 30-second samples, Defender 0.3 to 1.0 % of one logical processor, total load 1.4 to 2.9 % |
| Logical processor 4 | 100 % busy in each of the nine one-minute samples through the run; performance counter 175.7 to 182.8 % of base |
| Its sibling, logical 5 | 0.6 to 3.6 % busy over the run |
| Total load | 7.5 to 10.7 % over the run |
| Other work | two browser renderer processes used 186.7 s and 12.1 s of CPU over the 556 s, about a third of one logical processor; everything else under 3.2 s. The kernel, Defender, the search indexer and the WMI hosts are not readable from an unelevated session and are not measured |

**Captures**, in `rt_p4_mlkem_decaps_timing_20261121_captures/`, each
committed byte for byte as it left the machine, with `SHA256SUMS`:
`laptop_registered_attempt1.txt`, `laptop_x86_disasm_excerpts_crt_static.txt`,
`example_rustc_line.txt` and `laptop_rustc_vV.txt`.

**Not done.** No re-run, and no analysis of the cause. The laptop's entry
in `rt_p4_attestation.toml` is unchanged, so RT-P4's standing check stays
red for the laptop until the maintainer rules.

### The floor device — not made

Not run under this registration. The floor device's run is registered,
with the 2026-10-25 lines, in
[`rt_p4_mlkem_decaps_timing_20261121_message.md`](rt_p4_mlkem_decaps_timing_20261121_message.md),
on a second Raspberry Pi 4.
