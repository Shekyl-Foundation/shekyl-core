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

**The classes.** A class is a set of 256 decoded keys, each held in its own
slot (118,640 bytes each, 30 MB a class), and each entry signs from a slot
drawn uniformly. In a fixed class every slot holds the same key; in the
varied class each slot holds its own key. Both classes touch the same amount
of memory in the same pattern, so neither has its key warmer in the cache
than the other. The 512 slots are decoded in a shuffled order, drawn
from a stream of its own, so which addresses each class gets is random, as
which class each entry belongs to is random in time. On the development
machine's AVX2 path, placement alone moved a null:
- decoded one class after the other, the second class was slower by about
  0.15 % of a signature at every quantile (`|t|` 11.94 at 200,000
  samples);
- decoded alternately, each class took a fixed alignment (a slot is 128
  bytes short of 29 pages), and the second class was slower by about 0.3 %
  (`|t|` 37.69). Every entry draws a fresh pass transcript (every field
drawn, the stream byte economy or support) and a fresh 32-byte RNG seed, the
same way in both classes.

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

**The pass lines.** Two comparisons, both pass lines:

- `fixed-vs-varied`: key A in every slot against a key per slot.
- `fixed-a-vs-fixed-b`: key A in every slot against key B in every slot.
  With two fixed keys there is no difference in familiarity between the
  classes. So a key-dependent time shows here even where `fixed-vs-varied`
  could not tell it from familiarity (the lesson of `CA-2`).

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

  | Build | Nulls | Control (planted ≈ 2.05 µs) | Restart-rate `|z|` across comparisons |
  | --- | --- | --- | --- |
  | AVX2 | 2.26, 1.76 | 33.83, detected | 0.39 to 2.92 |
  | SSE2 (`fn-dsa-sign/no_avx2`) | 2.34, 1.73 | 49.32, detected | 0.39 to 2.92 |

  The restart-rate figures agree between the two builds: the two
  paths sign the same bytes, and the nonce check recovers the same counts.
- **The SSE2 binary has no AVX2 signing code.** It carries no
  `fn_dsa_sign::sign_avx2` symbol; the AVX2 build carries 17.
- **Not yet shaken down:** the Windows (MSVC) build and the aarch64 build.
  Each is shaken down on its own device before its registered run (below).

**The control and the nulls.**
- The nulls:
  - `fixed-a-vs-fixed-a-other-slots`: key A in two disjoint sets of slots,
    which tests whether slot placement alone crosses;
  - `varied-vs-varied-other-slots`: the varied class's own 256 keys in two
    disjoint sets of slots. The keys are the same on both sides. Two
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
4. Either pass line's figure is > 10: **fail**.
5. Either pass line's figure is between 4.5 and 10: **inconclusive**.
6. Both pass lines' figures are below 4.5: **pass**.

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
  - Target `aarch64-unknown-linux-gnu`, with no rustflags (NEON path).
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
- **Each laptop run:** about 45 minutes and 1.6 GB, most of it the signatures
  kept for verification after each loop. The two laptop runs take about
  1.5 hours together.
- **The Pi run:** about 2 hours (five comparisons of 510,000 signatures at
  2.24 ms, plus verification at 0.57 ms each) and 0.8 GB.

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
