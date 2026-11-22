# `CA-3`, FN-DSA: the receipt countersignature's signing time, registered 2026-11-21

**State of this record: registered; no run has been made.** Results are
added below "Registered before the run", and that section is not edited
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

No run has been made.
