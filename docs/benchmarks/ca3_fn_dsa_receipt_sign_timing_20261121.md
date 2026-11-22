# `CA-3`, FN-DSA: the receipt countersignature's signing time, registered 2026-11-21

**State of this record: all three registered runs are in, and all three
PASS: the floor device, and the laptop on the AVX2 and on the SSE2 path.
FN-DSA's row of `CA-3` closes.** Results
are added below "Registered before the run", and that section is not edited
afterwards.

## Why this run

`CA-3` ([`CRYPTO_AUDIT.md`](../design/CRYPTO_AUDIT.md) §3) found that no
measurement covers the time Shekyl's post-quantum signers take. FN-DSA is
the most exposed of the three. A persona countersigns every pass it serves
with its long-lived receipt key, and anyone who fetches a shard from its
onion can ask for a countersignature. This is the FN-DSA signer's
registered run. Its threat model and source read are in `CRYPTO_AUDIT.md`
§3.1. A pass on both devices closes the FN-DSA row of `CA-3`.

## Registered before the run

**The question.** Does the time the receipt countersignature takes depend
on the persona's receipt key, in the build that ships?

**The subject.** `fn-dsa` 0.4.0 (`fn-dsa-sign` 0.4.0) inside the hybrid
Ed25519 + FN-DSA-1024 scheme, signed through the held signer the serve
path uses (`FnDsaHybridSigner`, which `HeldReceiptKey` builds once and
`sign_receipt_transcript` signs through), over pass transcripts
(`PassTranscript::message`) under `SCHEME_DOMAIN_RECEIPT`. It is built in
the release profile from this workspace's lock file (`--locked`), from a
fresh clone of the commit that carries this record, in a new directory.

**The one difference from the serve path.** The serve path draws FN-DSA's
40-byte seed from the OS (`HedgedOsRng`). The harness draws it from the
held signer's seeded stream (`sign_with_rng_seed`, a ChaCha20 stream over a
32-byte seed). That makes each signature's seed known, so its restart count
can be recovered. The crate hedges the drawn seed with the hashed signing
key and the message representative before using it (`fn-dsa-sign`
`lib.rs:289-296`), and everything from there on is the same code. On x86,
the run's record lists the instruction counts of the signing path's
functions in the harness binary beside those in `shekyl-wallet-rpc` built
from the same commit (`sign_inner`, `sign_avx2_inner`, `ffsamp_fft_inner`,
`poly_LDL_fft`).

**The harness.** `rust/shekyl-p-serve/examples/ca3_receipt_sign_timing.rs`,
at the commit that carries this record. It uses RT-P4's method:
- every input is prepared before each loop;
- two classes are interleaved by a coin drawn then;
- each signature is timed alone;
- Welch's t is taken on the raw samples and below each of 100 cut-offs, placed from a discarded calibration batch of 10,000. A cut-off counts only when both classes keep more than 10,000 samples below it;
- the largest `|t|` is reported.

**The classes.** A class is a set of keys: one key for a fixed class, and
256 for the varied class, where each entry takes one uniformly. Every entry
draws a fresh pass transcript (every field drawn, the stream byte economy
or support) and a fresh 32-byte RNG seed, the same way in both classes.

**One working slot.** Each entry's key is decoded, untimed, into one
working slot just before it signs (`FnDsaHybridSigner::new`, as the serve
path builds its held key), and dropped after. The allocator hands the freed
block to the next decode, so every entry of both classes signs from the
same memory with its key freshly written into it. The classes own no memory
of their own. Three earlier designs gave each class 256 slots of its own,
and each crossed a null on placement alone in the shake-downs:
- **Decoded one class after the other** (development machine, AVX2): the
  second class was slower by about 0.15 % of a signature at every quantile
  (`|t|` 11.94 at 200,000 samples).
- **Decoded alternately:** each class took a fixed alignment (a slot is 128
  bytes short of 29 pages), and the second class was slower by about 0.3 %
  (`|t|` 37.69).
- **Decoded in a shuffled order:** clean on x86. On the floor device the
  nulls read 8.54 and 10.17 at 50,000 samples, in opposite directions, all
  in the fast tail: the slots one class drew were not like the slots the
  other drew.

The message and the seed are drawn, not held. The crate hedges the seed
with the hashed signing key and binds the hashed verifying key into the
message representative, so the computation is the key's whatever is passed
in. Holding them fixed would not equalise the classes. It would only make a
fixed class one computation repeated against a varied one.

**Restarts.** The signing loop restarts when a candidate is too long or
does not encode (`fn-dsa-sign` `lib.rs:729`, `:737`). A restart repeats
almost the whole signature. After the loop, each entry's restart count is
recovered from its signature: the nonce the signature carries is the first
40 bytes of the sampler's stream for `seed ‖ counter`. Only entries that
signed at the first attempt enter the timing statistics. A key-dependent
restart rate would be a timing difference an observer sees, and dropping
those entries would hide it. So the classes' restart rates are compared
with a pooled two-proportion `z`, and each comparison's figure is the larger
of its `|t|` and its `|z|`.

**The pass line, and one information line** (the maintainer's ruling of
2026-11-21, made before any run):

- **Pass line, `fixed-a-vs-fixed-b`:** key A against key B. With two fixed keys there is no difference in familiarity
  between the classes. So a time that depends on the key's value shows here
  even where `fixed-vs-varied` could not tell it from familiarity (the
  lesson of `CA-2`).
- **Information, `fixed-vs-varied`:** key A against the 256 keys. A difference here shows that the time depends on a key being
  repeated, not on its value. The receipt key is repeated in production, so
  the fixed class is the production condition. Its figure, the larger of
  `|t|` and the restart `|z|`, is printed beside the verdict and recorded
  with it, and is never read against the lines.

**The checks. Each can fail, and a failure voids the run before any line
is read.**

1. *The keys.* Each key's FN-DSA half is regenerated the way the scheme
   generates it, from the same seed through the same stream. The
   regenerated public key must equal the scheme's. This is what lets the
   harness compute the crate's hashed signing and verifying keys. Printed as
   `check=keys replicated=…`.
2. *The signatures.* For every entry of every comparison:
   - the timed call returned a signature;
   - it verifies under its key;
   - its nonce is the one its key, transcript and seed derive for one of
     the loop's 27 counters.

   Printed per comparison as `check entries=… failed=… not_verified=…
   nonce_unmatched=…`. Anything other than 0, 0 and 0 voids the run.

**Shake-down.** Before this registration the harness ran on the
development machine (the maintainer's x86_64 Linux workstation, shared,
load average 1 to 3). It used seeds that are not the registered one and
200,000 samples per comparison. These runs are not results, and their
pass-line figures are not reported as one.
- **Three placements.** The first two crossed a null on placement alone
  (above, *The classes*). With the shuffled placement this registration
  fixes, both builds pass every check, and every null is flat:

  | Build | Nulls | Control (planted ≈ 2.05 µs) | Restart-rate z, absolute, across comparisons |
  | --- | --- | --- | --- |
  | AVX2 | 2.26, 1.76 | 33.83, detected | 0.39 to 2.92 |
  | SSE2 (`fn-dsa-sign/no_avx2`) | 2.34, 1.73 | 49.32, detected | 0.39 to 2.92 |

  The restart-rate figures agree between the two builds: the two
  paths sign the same bytes, and the nonce check recovers the same counts.
- **The SSE2 binary has no AVX2 signing code.** It carries no
  `fn_dsa_sign::sign_avx2` symbol; the AVX2 build carries 17.
- **The development machine's x86 figures above are for the shuffled-slot
  harness.** The one-working-slot harness this registration fixes replaced
  it after the floor device's first shake-down. The laptop's own shake-down
  covers that harness on x86 before its runs.
- **The floor device** (the 4 GB Pi 4; unregistered seeds, 50,000 samples
  per comparison):
  - *Shake-down 1* (2026-11-22 01:57 to 02:14Z), the shuffled-slot harness
    at `80c4a62e19`. Every check held and the control read 56.08, but the
    nulls read 8.54 and 10.17, in opposite directions and all in the fast
    tail. **Void.** That is the reason for the one working slot.
  - *Shake-down 2* (02:21 to 02:41Z), the one-working-slot harness at
    `2e4cffa0c1`. Every check held. The nulls read 1.57 and 1.25, and the
    control (planted 10.26 µs) read 63.43, about 200 at 500,000 samples.
    The fixed pair read 2.29 and the information line 1.07. The board held
    1.5 GHz at 50 to 55 °C, throttled `0x0`, with no under-voltage.
- **Not yet shaken down:** the Windows (MSVC) build, on the laptop before
  its runs.

**The control and the nulls.**
- The nulls:
  - `fixed-a-vs-fixed-a-again`: key A in both classes;
  - `varied-vs-varied-again`: the varied class's own 256 keys in both
    classes. The keys are the same on both sides. Two
    different key sets would not be a null: under the key dependence being
    tested they would differ too, and the run would read void where it
    should read fail.
- The control plants extra work of 0.5 % of one signature's median time
  inside the timed region, for one class of the first null. It sits on a
  null so that no real key dependence adds to or cancels it. A pass
  excludes a key dependence of that size or more, and nothing smaller.

**The lines, read in this order.**

1. A check fails: **void**.
2. The control is not detected (`|t|` ≤ 10): **void**.
3. A null's figure is ≥ 4.5: **void**.
4. The fixed pair's figure is > 10: **fail**.
5. The fixed pair's figure is between 4.5 and 10: **inconclusive**.
6. The fixed pair's figure is below 4.5: **pass**.

**The inputs.** The harness's registered seed, with no seed argument. It
prints `inputs=registered`. No run before this registration drew from it.
- Every key (key A, key B and the varied class's 256) is drawn from the
  seed before any comparison, and key generation is integer-only, so every
  device signs with the same keys.
- The per-entry transcripts and RNG seeds follow in the same stream. So
  they are the same on the laptop's two runs, and differ on the floor
  device, which runs fewer samples.

**Three registered runs**, each with its own verdict, from fresh clones of
the commit that carries this record:

- **The maintainer's Windows laptop (Intel Core i9-11950H, Tiger Lake),
  AVX2 path.**
  - Target `x86_64-pc-windows-msvc`, taking `+crt-static` from
    `rust/.cargo/config.toml`, with no `RUSTFLAGS` in the environment.
  - `cargo build --release --locked -p shekyl-p-serve --example
    ca3_receipt_sign_timing`, run with no arguments (1,000,000 samples per
    comparison).
  - The harness prints `cpu_avx2=yes`. The crate takes its AVX2 path when
    the CPU has AVX2 (`fn-dsa-sign` `lib.rs:298`).
- **The same laptop, baseline (SSE2) path.**
  - The same, built with `--features fn-dsa-sign/no_avx2`, which compiles
    the AVX2 code out. This is the path an x86_64 CPU without AVX2 runs, and
    the one the CI step "FN-DSA vectors with the AVX2 paths compiled out"
    runs the vectors on.
  - Evidence that the feature took effect: `fn-dsa-sign`'s rustc line from
    `cargo build -v` carrying `--cfg 'feature="no_avx2"'`. The AVX2 build's
    line must not carry it.
- **The floor device: the second Raspberry Pi 4 the maintainer provides**
  (Cortex-A72, rule 76), not the Pi under the cover-traffic lane's claim.
  It is the 4 GB board, the floor rule 76 names (the other Pi 4 has 8 GB),
  running from its SD card with no SSD. The run's 0.8 GB fits it.
  - Target `aarch64-unknown-linux-gnu`, with no rustflags (NEON path).
  - Built on the device from the fresh clone with `-j 2`, as RT-P4's floor
    run builds, so a 4 GB build does not exhaust memory. The build is not
    timed. The binary's SHA-256 is recorded.
  - Run as `ca3_receipt_sign_timing 500000`: 500,000 samples per
    comparison. One signature takes about five times as long there (2.24 ms
    against 0.46 ms, [`FN_DSA_HYBRID.md`](../design/FN_DSA_HYBRID.md) §3.1), and the control shows the
    sensitivity reached at that count.
  - Under a quiet claim in the estate's usage ledger, on the schedule it
    shares with RT-P4.

**Conditions recorded for each run**, as RT-P4's 2026-11-21 registration
records them
([`rt_p4_mlkem_decaps_timing_20261121_message.md`](rt_p4_mlkem_decaps_timing_20261121_message.md),
"Two registered runs"):
- **The laptop:**
  - its processor, enumerated before anything runs;
  - pinned to logical processor 4 (`start /affinity 10`), with its sibling,
    logical 5, left idle, and the affinity read back from the running
    process;
  - the drive, the power state and plan, an unelevated session, Defender's
    state, what else is running and its CPU time, the sibling's load, and
    the processor performance counter through the run.
- **The Pi:**
  - the model, the board revision, the OS, the kernel and the CPU governor,
    recorded before the run;
  - the clock synchronised before the run starts (`timedatectl`: "System
    clock synchronized: yes"). These boards boot on a stale clock and step
    it a few seconds after boot, so the run starts only after the step;
  - at the start and the end: the load, the clock, the SoC temperature,
    `vcgencmd get_throttled`, the under-voltage alarm,
    `cpufreq/stats/time_in_state` and `total_trans`, and what else is
    running.
- **Every run:** the binary's SHA-256, `rustc -vV`, the start and end times,
  and the exit code.

**Time and memory.**
- **Each laptop run:** about an hour and 1.4 GB, most of it the signatures
  kept for verification after each loop. Each entry's untimed decode adds
  to the loop. The two laptop runs take about 2 hours together.
- **The Pi run:** about 3 hours 10 minutes and 0.7 GB, scaled from
  shake-down 2's 19.7 minutes at 50,000 samples.

**A shake-down on each device first.** Before each registered run, its
own binary runs once on its own device:
- with a seed that is not the registered one and 50,000 samples per
  comparison;
- to show that it builds, runs, holds its checks and detects its control
  there.

A shake-down is not an attempt. Its output is kept with the captures,
marked as a shake-down. On the floor device, it also shows whether the
0.5 % control is within reach at 500,000 samples. If it is not, the floor
run is not made: the gap goes to the maintainer before an attempt is spent.

**Attempts.**
- A fail or an inconclusive is not re-run.
- A void may be made again once, and only after its cause is named and
  fixed.
- Every attempt is recorded, in order, with its full output, under
  `ca3_fn_dsa_receipt_sign_timing_20261121_captures/` with a `SHA256SUMS`.

**What closes it.** FN-DSA's row of `CA-3` closes when the laptop's two
runs and the Pi's run all pass. The source read is already recorded in
`CRYPTO_AUDIT.md` §3.1. The commit that records the last pass moves the
row. A void, a fail or an inconclusive goes to the maintainer with its
output, the threat model in §3.1 and the options there. No fix is chosen
before that.

## Results

### The floor device: PASS

**The attempt.** One attempt, on the second Raspberry Pi 4 (the 4 GB board,
rule 76's floor), under a quiet claim, made by the crypto-audit lane.
- **Source:** a fresh recursive clone of `d0dfabb5a4`, the commit that
  carries this registration, with `git status` clean.
- **Build:** on the device at `-j 2`, 02:50:19 to 03:08:12Z, untimed.
  rustc 1.94.0 (`4a4ef493e`). The binary's SHA-256 is
  `e68db30df1372a7a0dbe914bd5004e4c4e4ded25808e1bbb6795775c7391fa16`.
- **Run:** started once the clock reported synchronised, 03:08:12 to
  05:40:03Z (2 h 32 min), as `ca3_receipt_sign_timing 500000` with no seed.
  Exit code 0.
- **Output:** `ca3_fn_dsa_receipt_sign_timing_20261121_captures/floor_registered_attempt1.txt`.

```text
arch=aarch64 os=linux cpu_avx2=n/a samples_per_comparison=500000 calibration=10000 crops=100 varied_keys=256 inputs=registered
information=fixed-vs-varied max_abs_t=5.52 restart_abs_z=0.81 median_ns=2090681 n0=249677 n1=249207 verdict=information
pass-line=fixed-a-vs-fixed-b max_abs_t=2.90 restart_abs_z=2.07 median_ns=2036367 n0=249780 n1=249209 verdict=no-evidence
null=fixed-a-vs-fixed-a-again max_abs_t=2.77 restart_abs_z=0.46 median_ns=2037293 n0=249089 n1=249775 verdict=no-evidence
null=varied-vs-varied-again max_abs_t=1.77 restart_abs_z=0.97 median_ns=2091995 n0=249281 n1=249614 verdict=no-evidence
control=planted-leak fraction=0.005 planted_ns=10186 max_abs_t=200.07 verdict=detected
check=keys replicated=true verdict=as-intended
result=PASS fixed_pair=2.90 worst_null=2.77 control_abs_t=200.07 information_fixed_vs_varied=5.52
```

(The per-quantile and per-crop lines, and each comparison's check line,
are in the capture.)

**Read against the lines, in order.**

| Line | Registered | Observed | |
| --- | --- | --- | --- |
| 1 | a check fails: void | keys replicated; in each of the five comparisons, 510,000 entries signed, all verified, every nonce matched (restarts 472 to 596 per class) | holds |
| 2 | control `\|t\|` ≤ 10: void | 200.07 (planted 10.19 µs, 0.5 %) | detected |
| 3 | a null's figure ≥ 4.5: void | 2.77 and 1.77 (restart `\|z\|` 0.46 and 0.97) | clean |
| 4–6 | the fixed pair's figure | 2.90 (`\|t\|`; restart `\|z\|` 2.07) | **pass** |

The run is not void, and the fixed pair's figure is below 4.5: **PASS**.
On the floor device, a pass excludes a dependence of the receipt
countersignature's time on the key's value of 0.5 % of a signature
(10.19 µs) or more, and nothing smaller.

**Information, not a line.** `fixed-vs-varied` read 5.52: the fixed key
was slower by about 0.26 µs (0.013 % of a signature) at every quantile up
to the 95th. Its restart `|z|` was 0.81. By the ruling it is information:
it shows how the time depends on a key being repeated, not on its value.

**Conditions** (`floor_conditions_start.txt`, `floor_conditions_end.txt`):

| Condition | Start (03:08:12Z) | End (05:40:03Z) |
| --- | --- | --- |
| Clock synchronised | yes | yes |
| Load | 1.83 (the build had just ended) | 1.00 |
| CPU clock | 1.5 GHz | 1.5 GHz |
| SoC temperature | 58.9 °C | 54.0 °C |
| `vcgencmd get_throttled` | `0x0` | `0x0` |
| Under-voltage alarm | 0 | 0 |
| Frequency transitions | 88,959 | 91,469 |

- The board identifies as Raspberry Pi 4 Model B Rev 1.2, revision
  `c03112`, Ubuntu 26.04.1 LTS, kernel 7.0.0-1023-raspi, governor
  `ondemand`.
- Nothing else of note ran: the process lists are in the captures.

**Captures**, in `ca3_fn_dsa_receipt_sign_timing_20261121_captures/` with
`SHA256SUMS`:
- the attempt's output;
- its conditions;
- the clone's head and clean status;
- the build's times, log and `rustc -vV`;
- the binary's SHA-256;
- the two floor shake-downs with their conditions (`floor_shakedown1_*`,
  void on its nulls; `floor_shakedown2_*`, clean), each marked as a
  shake-down.

The committed files write the device's clone directory `<clone>`, its home
directory `<home>` and its login `<agent>`. The unredacted files, whose own
SHA256SUMS verified after the copy, are in the estate's private captures.

### The laptop: AVX2 PASS, SSE2 PASS

**The setup.** Both runs were made on the maintainer's Windows laptop (Intel
Core i9-11950H, 8 cores, 16 logical processors) by the agent on that
machine.
- **Source and build.** Each binary came from its own fresh recursive clone
  of `3b4fd5dc2c` (the head that carries this record; the harness is
  unchanged since the registration), `git status` clean, in a new directory
  on a local drive with no synced folder. Each was built
  `cargo build --release --locked -v`, with all 224 rustc invocations
  carrying `+crt-static` and no `VCRUNTIME140.dll` among the dependents.
- **The two paths.**
  - The AVX2 binary's `fn-dsa-sign` line carries only `feature="default"`.
  - The SSE2 binary was built with `--features fn-dsa-sign/no_avx2`, and its
    line carries `feature="no_avx2"`.
  - Both print `cpu_avx2=yes`: that names the processor, not the path.
- **Pinning and quiet.** Each ran pinned to logical processor 4, with the
  affinity read back as `0x10`. Each started only after a quiet gate: four
  consecutive 30-second samples with Defender under 10 % of one logical
  processor, total load under 15 %, and the sibling, logical 5, under 5 %.
- **Shake-downs.** The registered runs were preceded by their shake-downs
  on seed `20261126`:
  - AVX2: fixed pair 1.62, nulls 2.02 and 1.08, control 24.48.
  - SSE2: fixed pair 1.05, nulls 1.18 and 2.50, control 38.17.

| | AVX2 | SSE2 |
| --- | --- | --- |
| Binary SHA-256 | `809e06bf1682d8745688dbe657dbb5289e1388e990f004e5e7b3f61e7cfc9f21` | `10dd021b5d9b6ecc336a042551a4e5889a55b4800b26e290c6c4f3650ed21383` |
| Run (UTC) | 19:38:32 to 20:24:33 | 20:33:37 to 21:22:59 |
| Checks (each comparison) | 1,010,000 entries signed, verified, nonce-matched; keys replicated | the same |
| Control (planted 0.5 %) | 159.34 (2.07 µs) | 162.04 (2.00 µs) |
| Nulls | 2.28, 2.49 | 2.25, 1.99 |
| **Fixed pair** | **1.71** (restart `\|z\|` 0.67) | **1.85** (restart `\|z\|` 0.67) |
| Information: fixed-vs-varied | 2.09 | 2.21 |
| Sibling (logical 5) over the run | 1.15 to 6.09 %, mean 2.86 % | 0.79 to 4.05 %, mean 2.52 % |
| Verdict | **PASS** | **PASS** |

Each run is not void, and its fixed pair is below 4.5. On each path, a
pass excludes a dependence of the receipt countersignature's time on the
key's value of 0.5 % of a signature, about 2 µs, or more.

**Conditions.** Both runs held the same conditions at the start and the
end:
- mains power, battery 98 % and charging, the Balanced plan with its AC
  overlay;
- `QueryPerformanceFrequency` 10,000,000;
- Defender's real-time, tamper, behaviour, on-access and IOAV protection
  all on;
- no browser, cloud-drive client or chat application running.

An AI desktop client the maintainer kept open stayed running.
- In the AVX2 run its busiest process used 564 s of CPU over 2,760 s, not
  pinned, while the sibling stayed idle.
- In the SSE2 run it was nearly idle (7 s).

One one-minute sample in the AVX2 run (20:05:33Z) read zero on both
performance counters while logical 4 read 100 %. It stays in the samples
file and is left out of the ranges. The full condition records, which list
every process on the machine, are in the estate's private captures.

**The one difference from the serve path, measured.** As this record
registers, the signing path's functions were compared, instruction by
instruction, between the two harness binaries and `shekyl-wallet-rpc` built
from the same commit. Function boundaries come from the x64 function table,
and code and data addresses are masked (`laptop_instruction_counts.txt`).
- **On the AVX2 path,** every function on the signing path is the same
  instruction sequence in the harness and in the wallet: `sign_avx2_inner`
  (767), `ffsamp_fft_inner` (493), `poly_avx2::poly_LDL_fft` (187) and
  `compute_basis_avx2_inner` (345). The AVX2 run measured the code the
  wallet runs on an AVX2 processor.
- **On the SSE2 path,** `ffsamp_fft_inner` (498) and `poly::poly_LDL_fft`
  (80) are identical. `sign_inner` is not.
  - The wallet inlines it into `SigningKey1024::sign`, instantiated with the
    OS-randomness adapter.
  - The harness, instantiated with the seeded stream, keeps it as its own
    775-instruction function.
  - Masked, the two share a longest common subsequence of 327 instructions.
    Both call the same, identical `ffsamp_fft_inner`.
  - So the SSE2 run measured the same sampler and LDL decomposition, which
    are the work that touches the key's floating-point values (the source
    read, §3.1 of `CRYPTO_AUDIT.md`), inside a differently compiled
    `sign_inner`.
  - This applies only on an x86_64 processor without AVX2. It is recorded
    with the SSE2 result rather than hidden.

**Captures** (`laptop_*`, with `SHA256SUMS`):
- each run's output and shake-down output;
- the run's one-minute counter samples;
- `rustc -vV`;
- `fn-dsa-sign`'s rustc line;
- the dependents;
- the instruction-count summary.

The full records, including the build logs, the process lists and the
disassembly, are in the estate's private captures, hashed there.
