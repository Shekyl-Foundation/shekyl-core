# `RT-P4`: the message-only pass line, registered 2026-11-21

**State of this record: registered; no run has been made.** Results are
added below "Registered before the run", and that section is not edited
afterwards.

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

*None yet.*
