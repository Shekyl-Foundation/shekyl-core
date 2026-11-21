# `RT-P4`: the message-only pass line, registered 2026-11-21

**State of this record: the laptop's registered run is in, and it PASSES;
the floor device's is not yet made.** The attestation moves when the floor
device's run is in (see "The attestation" below). Results are added below
"Registered before the run", and that section is not edited afterwards.

## Why this run

The maintainer's ruling of 2026-10-25 (the last bullet of "The ruling" in
[`rt_p4_mlkem_decaps_timing_20261023.md`](rt_p4_mlkem_decaps_timing_20261023.md))
set the lines for RT-P4's next required run: "the pass line becomes
invalid-vs-invalid differing only in the decrypted message, with
valid-vs-invalid reported as information." Pull request #1494 makes that run
required: it moves six crates of the decapsulation closure (`fips203` 0.4.3
to 0.5.0, `crypto-common`, `generic-array`, `typenum`, `zeroize` and
`zeroize_derive`), and RT-P4's standing check fails on each.

The first registration for it
([`rt_p4_mlkem_decaps_timing_20261121.md`](rt_p4_mlkem_decaps_timing_20261121.md))
used the 2026-10-11 lines unchanged. The maintainer ruled its laptop run
information under superseded lines (that record's "Correction"). This is
the run under the lines the 2026-10-25 ruling set, and the first under
them on each device.

## Registered before the run

**The question.** Unchanged (`RPC_CHANNEL.md` §4.3): does the time ML-KEM-768
decapsulation takes depend on the ciphertext, on the implicit-rejection
path included, in the build that ships?

**The subject.** `fips203` 0.5.0, `ml_kem_768`, `try_decaps`, with its
closure at #1494's versions, built in release profile from this workspace's
lock file (`--locked`), from a fresh clone of the commit that carries this
record, in a new directory.

**The harness.** `rust/shekyl-rpc-channel/examples/rt_p4_decaps_timing.rs`,
with `rt_p4_support/kpke.rs`, at the commit that carries this record. The
method is the 2026-10-11 registration's: inputs prepared before each loop,
two classes interleaved by a coin drawn then, each decapsulation timed
alone, Welch's t on the raw samples and below each of 100 cut-offs placed
from a discarded calibration batch of 10,000, the largest `|t|` reported;
1,000,000 timed decapsulations per comparison.

**The pass line: `invalid-message-fixed-vs-invalid-message-random`.** Two
classes of invalid ciphertext whose decryptions differ only in the message.

- *Construction.* Every entry is a K-PKE encryption (FIPS 203 Algorithm
  14) under the subject's encapsulation key, with fresh 32-byte coins `r`
  drawn from the input stream for that entry. Class 0 encrypts one fixed
  message `M0`, drawn once from the input stream when the subject is made.
  Class 1 encrypts a fresh 32-byte message drawn for that entry, its coins
  drawn after it. The coins, and so the noise vectors and every other part
  of the ciphertext's distribution, are drawn the same way in both classes;
  the decrypted message is the only difference.
- *Why every entry is invalid.* Decapsulation re-encrypts the decrypted
  message with the coins G(m ‖ H(ek)) derives, not with `r`, so the
  re-encrypted ciphertext differs from the input and decapsulation returns
  the implicit-rejection key J(z ‖ c).
- *The encryption.* `fips203` encrypts only with the coins it derives, and
  does not expose decryption, so the harness carries a reference K-PKE
  (`kpke.rs`, FIPS 203 Algorithms 4 to 15). It builds and checks inputs
  before each loop and is never timed; the decapsulation timed is
  `fips203`'s.

**The checks. Each can fail, and a failure voids the run before any line
is read.**

1. *The reference against `fips203`*, before anything is timed: for 256
   messages from the input stream, K-PKE encryption with ML-KEM's own
   coins must equal `encaps_from_seed(m)`'s ciphertext byte for byte, the
   key half of G must equal its shared secret, and the reference decryption
   of it must give `m`. The harness prints
   `selfcheck=reference-kpke cases=256 mismatches=N` and stops with VOID if
   N is not 0.
2. *Each class decrypts as intended*, for every entry of the pass line's
   1,010,000: the reference decryption gives the entry's own message
   (`M0` for class 0), and `fips203`'s decapsulation returns J(z ‖ c),
   so it took the rejection path. The harness prints
   `check=message-classes entries=… decrypt_mismatch=… not_rejected=…`, and
   any count other than all entries, 0 and 0 voids the run.

Both were seen to fail before this registration, on the development
machine, with a seed that is not the registered one and 20,000 samples: a
reference decryption that flips one message bit gave `mismatches=256` and
VOID; message classes built with ML-KEM's own coins (valid ciphertexts)
gave `not_rejected=30000` and VOID. The unmodified harness, on the same
seed, gave `mismatches=0` and every entry as intended. No run has drawn the
registered inputs.

**Information, not lines.** The four 2026-10-11 comparisons are run and
reported as `information=`: `fixed-vs-valid`, `fixed-vs-invalid`,
`fixed-vs-bitflip` and `valid-vs-invalid`. None keeps a fail line. The
ruling names one pass line, the message-only comparison; these four each
compare valid with valid or valid with invalid, the kind the ruling made
information.

**The control and the nulls, unchanged.** The control plants extra work
of 0.5 % of one decapsulation's median time inside the timed region for
one class of a `fixed-vs-invalid` comparison; a pass excludes a leak of
that size or more, and nothing smaller. The nulls are `invalid-vs-invalid`
and `valid-vs-valid`.

**The lines, read in this order.**

1. A check fails: **void**.
2. The control is not detected (`|t|` ≤ 10): **void**.
3. A null reports `|t|` ≥ 4.5: **void**.
4. The pass line reports `|t|` > 10: **fail**.
5. The pass line is between 4.5 and 10: **inconclusive**.
6. The pass line is below 4.5: **pass**.

The information comparisons enter no line.

**The inputs.** The registered seed; the harness prints `inputs=registered`.
The classes and the comparisons' order differ from the earlier runs', so
the inputs each comparison draws differ from theirs. Both devices draw the
same inputs.

**Two registered runs**, each with its own verdict, from fresh clones of
the commit that carries this record:

- **The maintainer's Windows laptop** (Intel Core i9-11950H, Tiger Lake),
  target `x86_64-pc-windows-msvc`, taking `+crt-static` from
  `rust/.cargo/config.toml`, no `RUSTFLAGS` in the environment. Pinned to
  logical processor 4 (`start /affinity 10`), its sibling, logical 5, left
  idle, the affinity read back from the running process. Its processor
  enumerated before anything runs. Conditions recorded at the start and
  the end as in the first 2026-11-21 registration: the drive (local, no
  synced folder), mains power, an unelevated session, the power plan and
  its overlays, the processor performance counter sampled through the run,
  `QueryPerformanceFrequency`, Defender's state (left on, the maintainer's
  standing ruling), what else is running and its CPU time, and the
  sibling's load. Evidence the flag took effect: the harness's rustc line
  showing `target-feature=+crt-static`, and the binary's dependencies
  without `VCRUNTIME140.dll`.
- **The floor device: a second Raspberry Pi 4 the maintainer provides**
  (Cortex-A72, rule 76), not the Pi under the cover-traffic lane's claim.
  Target `aarch64-unknown-linux-gnu`, no rustflags, under a quiet claim in
  the estate's usage ledger. Its identity is recorded before the run: the
  model (`/proc/device-tree/model`), the board revision (`/proc/cpuinfo`),
  the OS (`/etc/os-release`), the kernel, and the CPU governor. At the
  start and the end of the run, as the 2026-10-11 floor run recorded them:
  the load, the governor, the clock, the SoC temperature, `vcgencmd
  get_throttled` (attempted), the under-voltage alarm,
  `cpufreq/stats/time_in_state` and `total_trans`, and what else is
  running.

**Also recorded for each run:** the binary's SHA-256, `rustc -vV`, and the
times. For the laptop, the x86 disassembly of the decapsulation path, in
the earlier records' sections.

**Attempts.** A fail or an inconclusive is not re-run. A void may be made
again once, only after its cause is named and fixed. Every attempt is
recorded, in order, with its full output, under
`rt_p4_mlkem_decaps_timing_20261121_message_captures/` with a `SHA256SUMS`.

**What closes it.** A pass on a device: the commit that records it replaces
that device's entry in [`rt_p4_attestation.toml`](rt_p4_attestation.toml)
with a `timing` entry naming this record and the commit its binary was
built from, and moves `[crates]` to #1494's versions with their lock
checksums. A pass on both devices makes RT-P4's standing check pass on
#1494's head, the maintainer's condition for that pull request to merge. A
void, a fail or an inconclusive goes to the maintainer with its output, and
the entry is not changed.

## Results

### The laptop — PASS

One attempt, 2026-11-21 16:00:21.27Z to 16:13:27.02Z (786 s), on the
maintainer's Windows laptop, made by the agent on that machine. The
processor enumerated as an Intel Core i9-11950H, 8 cores and 16 logical
processors, before anything ran. A fresh recursive clone of `7297b5cfbc`,
the commit that carries this registration (`git status` clean), on a local
fixed NTFS drive holding no synced folder; mains power; an unelevated
session; `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`,
`RUSTC_WRAPPER` and `CARGO_TARGET_DIR` empty. The binary was not executed
before this run. It was started with `start /affinity 10`, its affinity
read back from the running process as `0x10`, normal priority, with no
arguments. Its exit code was 0. The output is
`rt_p4_mlkem_decaps_timing_20261121_message_captures/laptop_registered_attempt1.txt`
(5,923 bytes); its SHA-256 matches the one taken on the machine.

```text
RT-P4 ML-KEM-768 decapsulation timing (fips203), inputs prepared before the loop
arch=x86_64 os=windows samples_per_comparison=1000000 calibration=10000 crops=100 inputs=registered
pass: |t| < 4.5 on the message-only comparison (ruled 2026-10-25); null comparisons: |t| < 4.5; control: |t| > 10; the four other comparisons are information
selfcheck=reference-kpke cases=256 mismatches=0
pass-line=invalid-message-fixed-vs-invalid-message-random max_abs_t=1.36 median_ns=63000 n0=499801 n1=500199 verdict=no-evidence
check=message-classes entries=1010000 decrypt_mismatch=0 not_rejected=0 verdict=as-intended
information=fixed-vs-valid max_abs_t=1.52 median_ns=62900 n0=501276 n1=498724 verdict=information
information=fixed-vs-invalid max_abs_t=29.55 median_ns=63000 n0=499396 n1=500604 verdict=information
information=fixed-vs-bitflip max_abs_t=10.98 median_ns=62700 n0=500353 n1=499647 verdict=information
information=valid-vs-invalid max_abs_t=45.41 median_ns=62900 n0=500235 n1=499765 verdict=information
null=invalid-vs-invalid max_abs_t=1.74 median_ns=62900 n0=500220 n1=499780 verdict=no-evidence
null=valid-vs-valid max_abs_t=1.97 median_ns=61800 n0=499773 n1=500227 verdict=no-evidence
control=planted-leak fraction=0.005 planted_ns=314 max_abs_t=428.23 verdict=detected
result=PASS pass_line_abs_t=1.36 worst_null_abs_t=1.97 control_abs_t=428.23
```

(The per-quantile and per-crop lines are in the capture.)

**Read against the lines, in order.**

| Line | Registered | Observed | |
| --- | --- | --- | --- |
| 1 | a check fails: void | self-check 0 mismatches of 256; 1,010,000 entries, every one decrypting to its message and rejected | holds |
| 2 | control `\|t\|` ≤ 10: void | 428.23 (planted 314 ns, 0.5 %) | detected |
| 3 | a null ≥ 4.5: void | 1.74, 1.97 | clean |
| 4–6 | the pass line | 1.36 | **pass** |

The run is not void, and the pass line is below 4.5: **PASS**. A pass
excludes a dependence on the decrypted message of 0.5 % of a
decapsulation or more, and nothing smaller.

**Information.** `fixed-vs-valid` 1.52. `fixed-vs-invalid` 29.55 (27.0 ns
below 62,100 ns), `valid-vs-invalid` 45.41 (35.6 ns below 62,300 ns) and
`fixed-vs-bitflip` 10.98 (10.3 ns below 62,200 ns): the valid-against-invalid
difference again, the invalid class slower, at the lowest cut-offs, larger
than on the 6b89c4862e build's run and still under 0.06 % of a
decapsulation. Within invalid ciphertexts, the message makes no measured
difference.

**The build** (`laptop_rustc_vV.txt`, `example_rustc_line.txt`,
`laptop_dumpbin_dependents.txt`). rustc 1.94.0 (`4a4ef493e`, LLVM 21.1.8),
`fips203` 0.5.0 from the lock. All 136 rustc invocations carry
`-C target-feature=+crt-static`; the binary is 370,688 bytes, SHA-256
`2ec40efcc2e5c55818dc5bd7a7c8b91cd92f93d2a552565afee330519435108c`, and
imports `api-ms-win-core-synch-l1-2-0.dll`, `KERNEL32.dll` and `ntdll.dll`,
not `VCRUNTIME140.dll`. The committed rustc line and dependents list have
the clone's directory written `<clone>` and the toolchain's home
`<rustup home>`.

**The code** (`laptop_x86_disasm_excerpts_crt_static.txt`, in the earlier
records' sections, with per-function counts beside the `6b89c4862e`
build's). Every function on the decapsulation path the sections cover has
identical counts to that build's (instructions / conditional jumps /
cmov-set / div): `ml_kem_decaps_internal` 318/9/1/0, `k_pke_decrypt`
494/37/3/0, `ntt` 131/14/1/1, `ntt_inv` 155/17/1/1, `byte_decode`
93/15/1/0, `subtle::black_box` 33/1/0/0, as are `try_decaps`, the NTT
multiply and keccak. What differs is encapsulation's inlining
(`ml_kem_encaps`, `sample_ntt`, a second `k_pke_encrypt` body): the
harness now also calls `encaps_from_seed` in its self-check.

**Conditions**, none of them a line (the full records, which list every
process on the machine, are kept in the estate's private captures):

| Condition | At the run |
| --- | --- |
| Power | mains, battery 98 % charging; plan Balanced; the same AC overlay as the 6b89c4862e run |
| `QueryPerformanceFrequency` | 10,000,000, start and end |
| Defender | real-time, tamper, behaviour and on-access protection on (the maintainer's standing ruling); no scan running |
| Quiet before the start | four 30-second samples, Defender 0.1 to 0.8 % of one logical processor, total load 0.4 to 1.0 % |
| Logical processor 4 | 100 % busy in each of the thirteen one-minute samples; performance counter 176.8 to 180.8 % of base |
| Its sibling, logical 5 | 0.1 to 2.5 % busy over the run |
| Total load | 9.3 to 12.9 %; one total performance-counter sample read 0, a bad sample, with logical 4 at 180.8 % in the same sample |
| Other work | the browser was closed by the maintainer before the run (none at either end). A desktop chat-assistant application used 553.6 s of CPU over the 786 s, about 0.7 of one logical processor (which processors it ran on was not recorded); everything else under 7.1 s. The kernel, Defender, the indexer and the WMI hosts are not readable from an unelevated session and are not measured |

**Captures**, in `rt_p4_mlkem_decaps_timing_20261121_message_captures/`,
each committed byte for byte as it left the machine, with `SHA256SUMS`:
`laptop_registered_attempt1.txt`, `laptop_x86_disasm_excerpts_crt_static.txt`,
`example_rustc_line.txt`, `laptop_dumpbin_dependents.txt` and
`laptop_rustc_vV.txt`.

### The floor device — not yet made

The second Raspberry Pi 4 the maintainer is providing; its identity is
recorded here before its run.

### The attestation

"What closes it" has a pass on a device replace that device's entry and
move `[crates]`. `[crates]` is one table for both devices: the standing
check compares the shipped closure with it, not per run. Moving it on the
laptop's pass alone would make the check accept the floor device's entry,
which measured `fips203` 0.4.3, as if it covered 0.5.0. So both entries
and `[crates]` move together, in the commit that records the floor
device's pass, and the standing check stays red until then.
