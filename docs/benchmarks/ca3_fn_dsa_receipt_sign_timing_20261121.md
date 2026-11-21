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
than the other. Every entry draws a fresh pass transcript (every field
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
development machine, with a seed that is not the registered one and
200,000 samples per comparison, on a shared and loaded machine (load
average 2.5 at the start). Every check held, with `nonce_unmatched=0`
against 203 to 252 restarts per class. The nulls read 2.16 and 2.47. The
control's planted 2.09 µs read `|t|` 16.01, detected. This shows that the
harness can see a planted 0.5 % leak at 200,000 samples on a noisy x86
machine. It is not a result, and its pass-line figures are not reported
as one.

**The control and the nulls.**
- The control plants extra work of 0.5 % of one signature's median time
  inside the timed region, for one class of a `fixed-vs-varied` comparison.
  A pass excludes a key dependence of that size or more, and nothing
  smaller.
- The nulls:
  - `fixed-a-vs-fixed-a-other-slots`: key A in two disjoint sets of slots,
    which tests whether slot placement alone crosses;
  - `varied-vs-other-varied`: two disjoint sets of 256 keys.

**The lines, read in this order.**

1. A check fails: **void**.
2. The control is not detected (`|t|` ≤ 10): **void**.
3. A null's figure is ≥ 4.5: **void**.
4. Either pass line's figure is > 10: **fail**.
5. Either pass line's figure is between 4.5 and 10: **inconclusive**.
6. Both pass lines' figures are below 4.5: **pass**.

**The inputs.** The harness's registered seed, with no seed argument. It
prints `inputs=registered`. No run before this registration drew from it.
Every device draws the same inputs, and the key generation is integer-only,
so every device signs with the same keys.

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
