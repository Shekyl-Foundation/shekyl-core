# `RT-P4`: both devices re-run on fips203 0.5.0, registered 2026-11-21

**State of this record: registered; no run has been made.** Results are
added below "Registered before the run", and that section is not edited
afterwards.

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

*None yet.*
