# `CA-3`, ML-DSA-65: the transaction authorisation's signing time, registered 2026-11-22

**State of this record: registered; no run has been made.** Results are
added below "Registered before the run", and that section is not edited
afterwards.

## Why this run

[`CRYPTO_AUDIT.md`](../design/CRYPTO_AUDIT.md) §3.2 holds this signer's
threat model and source read. Its exposure is very low: each output's key
signs about once. `CA-3` is still closed only by measurement. This run
follows the maintainer's rulings of 2026-11-21:
- the pass line is a fixed pair, matched on the work key generation does by
  design;
- `fixed-vs-varied` is information.

A pass on both devices closes ML-DSA's row.

## Registered before the run

**The question.** Does the time the transaction authorisation takes depend
on the value of the output's key, in the build that ships, beyond what key
generation does by design?

**The subject.** `fips204` 0.5.0 (ML-DSA-65) inside the hybrid Ed25519 +
ML-DSA-65 scheme, through `sign_pqc_auth_for_output`
(`rust/shekyl-crypto-pq/src/output.rs`). That call derives the output's
key from the transaction's combined shared secret at output index 0,
generates the key, signs the 32-byte payload hash under
`SCHEME_DOMAIN_PQC_AUTH_TX`, and wipes the key. It is built in the release
profile from this workspace's lock file (`--locked`), from a fresh clone of
the commit that carries this record, in a new directory.

**The one difference from the wallet's call.** The wallet draws ML-DSA's
32-byte signing nonce from the OS. The harness calls the seeded twin
(`sign_pqc_auth_for_output_with_ml_dsa_seed`), so every entry's nonce is
drawn the same way in both classes. Everything else is the same code.

**The harness.** `rust/shekyl-crypto-pq/examples/ca3_pq_sign_timing.rs`,
mode `ml-dsa`, at the commit that carries this record. It uses RT-P4's
method:
- inputs prepared before each loop;
- two classes interleaved by a coin drawn then;
- each signature timed alone;
- Welch's t on the raw samples and below each of 100 cut-offs, placed from
  a discarded calibration batch of 1 % of the samples. A cut-off counts
  only when both classes keep more than 1 % below it.

The largest `|t|` is reported.

**The classes.**
- A *fixed* class signs every entry under one combined shared secret.
- A *varied* class draws a fresh one per entry.

Every entry draws a fresh payload hash and a fresh nonce seed, the same way
in both classes. The call generates the key on every signature, so both
classes write the same amount of key material to the same places.

**Matching the fixed pair.** Key generation runs inside the timed
operation, and its rejection samplers do different amounts of work for
different keys by design:
- ExpandS, `fips204` `hashing.rs:313-335` through RejBoundedPoly,
  `:205-262`, on the secret ρ′;
- ExpandA, `hashing.rs:286-300` through RejNTTPoly, `:153-190`, on the
  public ρ.

The work ExpandS does carries no information about the coefficients kept,
since rejected nibbles are discarded. It is still a constant per key, and a
fixed pair reads a constant more sharply the more samples it has. Key A and
key B are therefore matched:
- Candidate secrets are drawn from the input stream before anything else.
- For each candidate, untimed, the harness replicates `fips204`'s own
  derivation:
  - ξ is the first 32 bytes of the ChaCha20 stream over the output's
    ML-DSA seed (`ml_dsa.rs:51-52`; `derivation.rs:44-45`);
  - ρ, ρ′ and K come from H(ξ ‖ k ‖ ℓ) (`ml_dsa.rs:79-83`).

  From these it counts the bytes ExpandS consumes over s1's and s2's 11
  polynomials, and the triples ExpandA rejects over Â's 30 entries.
- Key A and key B are the first pair in draw order with both counts
  equal.
- The harness prints each key's counts and the number of candidates drawn
  (`matched-pair`).
- The output's ML-DSA seed is reached through
  `output_ml_dsa_seed_for_tests` (`output.rs`), test-only behind the
  `seeded-rng` feature like the seeded twin. Production is unchanged.

**The checks. Each can fail, and a failure voids the run before any line
is read.**

1. *The replica,* for key A and key B, against `fips204`'s own key
   generated from the same seed:
   - its ρ is the public key's;
   - its K is the secret key's;
   - the s1 and s2 it samples are the secret key's encoded ones, nibble
     for nibble;
   - the t1 it recomputes is the public key's, byte for byte (Â ∘ NTT(s1),
     inverse NTT, plus s2, Power2Round, 10-bit packing).

   The last check exercises the ExpandA replica: a wrong Â gives a wrong
   t1. Printed as `check=replica replicated=…`.
2. *The signatures,* for every comparison:
   - every timed call returned a signature;
   - one in 64 of them, kept, verifies under its key.

   Printed as `check entries=… returned=… kept=… verified=…`.

**The comparisons.**
- **Pass line, `fixed-a-vs-fixed-b`:** the matched pair.
- **Information, `fixed-a-vs-varied`:**
  - printed and recorded, never read against the lines;
  - its difference shows dependence on a key being repeated, and the
    development run's 8.16 (the fixed key 4.1 µs faster) is the size the
    branch predictor learning one key's ExpandS rejection pattern gives;
  - production signs once per output key, so this line describes no
    production condition.
- **Nulls, each voiding the run:** `fixed-a-vs-fixed-a` and
  `varied-vs-other-varied`.
- **Control:** 0.5 % of one signature's median time, planted inside the
  timed region for one class of the first null. It is on a null so no real
  effect adds to or cancels it. A pass excludes a dependence of that size or
  more, and nothing smaller.

**The lines, read in this order.**

1. A check fails: **void**.
2. The control is not detected (`|t|` ≤ 10): **void**.
3. A null's `|t|` is ≥ 4.5: **void**.
4. The fixed pair's `|t|` is > 10: **fail**. It goes to the maintainer.
   The first suspect named is the predictor learning the two keys'
   rejection patterns to different degrees.
5. The fixed pair's `|t|` is between 4.5 and 10: **inconclusive**.
6. The fixed pair's `|t|` is below 4.5: **pass**.

**The inputs.** The harness's registered seed, with no seed argument. It
prints `inputs=registered`. No run before this registration drew from it.
- The candidates, and so key A and key B, come first in the stream, and
  every device draws the same ones.
- The per-entry inputs follow, so they differ on a device that runs a
  different sample count.

**Two registered runs**, each with its own verdict, from fresh clones of
the commit that carries this record. `fips204` has no run-time dispatch, so
one build covers each architecture.
- **The maintainer's Windows laptop (Intel Core i9-11950H, Tiger Lake).**
  - Target `x86_64-pc-windows-msvc`, taking `+crt-static` from
    `rust/.cargo/config.toml`, with no `RUSTFLAGS`.
  - `ca3_pq_sign_timing ml-dsa`: 1,000,000 samples per comparison.
- **The floor device: the second Raspberry Pi 4, the 4 GB board** (rule
  76's floor; Cortex-A72; no SSD).
  - Target `aarch64-unknown-linux-gnu`, built on the device at `-j 2` and
    not timed.
  - `ca3_pq_sign_timing ml-dsa 500000`, unless its shake-down says
    otherwise (below). At an estimated 5 ms a signature there (the x86
    figure scaled by FN-DSA's measured five-fold floor ratio), that is about
    3.5 hours.
  - Under a quiet claim, queued after `CA-3`'s FN-DSA run.

**Conditions recorded for each run** are as the FN-DSA registration records
them:
- [`ca3_fn_dsa_receipt_sign_timing_20261121.md`](ca3_fn_dsa_receipt_sign_timing_20261121.md),
  "Conditions recorded for each run": the processor, the affinity and the
  sibling's load, power, Defender and other work on the laptop; the
  identity, governor, clock sync, temperature, throttling and frequency
  statistics on the Pi;
- the binary's SHA-256, `rustc -vV`, the times and the exit code.

**A shake-down on each device first.** Before each registered run, its own
binary runs once on its device:
- a seed that is not the registered one;
- 50,000 samples per comparison.

It shows that the binary builds, runs, holds its checks and detects its
control there. It is not an attempt, and it is kept with the captures. On
the floor device it also sets the sample count:
- If the control reads well above 10 at 50,000, then 500,000 stands.
- If it does not, a count is derived from the shake-down's figures, which
  grow with √n, and is committed into this record before the run.
- If no count within a day's run reaches the control, the gap goes to the
  maintainer before an attempt is spent.

**Attempts.**
- A fail or an inconclusive is not re-run.
- A void may be made again once, and only after its cause is named and
  fixed.
- Every attempt is recorded, in order, with its full output, under
  `ca3_ml_dsa_tx_auth_timing_20261122_captures/` with a `SHA256SUMS`.

**What closes it.** ML-DSA's row of `CA-3` closes when both runs pass. The
commit that records the second pass moves the row. A void, a fail or an
inconclusive goes to the maintainer with its output and the threat model
in §3.2. No fix is chosen before that.

**Development trials (not results).** On the maintainer's x86_64 Linux
workstation, shared, with seeds that are not the registered one:
- At 20,000 samples, before the matching: `fixed-a-vs-varied` 8.16;
  `fixed-a-vs-fixed-b` 1.67, an unmatched pair; nulls 1.76 and 1.83;
  control 22.49.
- At 2,000 samples with the matching (load average about 0.3):
  - the pair matched after 7 candidates, at 2,496 ExpandS bytes and 7
    rejected ExpandA triples each;
  - every replica check and signature check held;
  - the control was not reached at that size.

## Results

No registered run has been made.

### The floor device's shake-down (2026-11-22): the matched pair crossed; held for the maintainer

The run:
- a fresh recursive clone of `43ac1dff98`, built on the 4 GB Pi 4 at
  `-j 2`;
- `ml-dsa 50000 20261124`, a seed that is not the registered one;
- 06:05:25 to 06:26:33Z;
- 1.5 GHz, 56 to 58 °C, throttled `0x0`.

It is a shake-down, not an attempt.

```text
matched-pair candidates_drawn=27 fixed-a expand_s_bytes=2488 expand_a_rejected=10 replicates=true fixed-b expand_s_bytes=2488 expand_a_rejected=10 replicates=true
check=replica replicated=true verdict=as-intended
information=fixed-a-vs-varied max_abs_t=2.78
pass-line=fixed-a-vs-fixed-b max_abs_t=10.44 verdict=LEAK
null=fixed-a-vs-fixed-a max_abs_t=2.09 verdict=no-evidence
null=varied-vs-other-varied max_abs_t=2.01 verdict=no-evidence
control=planted-leak planted_ns=22156 max_abs_t=127.03 verdict=detected
result=FAIL fixed_pair=10.44 worst_null=2.09 control=127.03 information_fixed_vs_varied=2.78
```

- **The checks held:** the replica against fips204's own key, and every
  signature returned (790 of 790 kept signatures verified per comparison).
  The nulls are flat and the control is detected.
- **The matched pair crossed.** Key A was about 0.9 to 1.3 µs (about
  0.04 %) slower, and only among single-attempt signatures: the fast mode,
  the 1st to 10th percentiles at about 2.98 ms. The raw means did not
  differ (`t` 0.56). At the registered 500,000 that reads about 33.
- **Not started.** The registered run is held, and the result is with the
  maintainer with these options:
  - run as registered, which almost certainly fails;
  - localise first, with key generation alone and signing alone on the
    same matched pair;
  - move the pass line to signing alone.
- **The suspects:**
  - the one the ruling names: the predictor learning the two keys'
    rejection patterns to different degrees, since matching the counts
    does not match the patterns;
  - `infinity_norm`'s data-dependent `max`;
  - the hint check's work on t0.
- **Localisation** (2026-11-22, 19:28 to about 20:10Z, the maintainer's
  go; diagnostic, no registered line). The harness's `ml-dsa-keygen` and
  `ml-dsa-sign` modes (#1504's commit `a3909ffa6d`) ran on the same
  matched pair (seed `20261124`), at 50,000 samples each, on the same
  device. Every call returned.

  | Half timed alone | Fixed pair | Null | Control | What differs |
  | --- | --- | --- | --- | --- |
  | Key generation (seed derivation + `keygen_from_seed`) | 9.96 | 1.69 | 154.27 | key A about 0.33 µs faster at almost every quantile: a constant per key (0.035 % of 0.95 ms) |
  | Signing (`try_sign_with_seed`, keys made before the loop) | 16.39 | 2.24 | 163.85 | key A 0.74 to 1.06 µs faster among single-attempt signatures (about 1.01 ms) |

  Read with the second localisation below: this run's footing could not
  separate the keys from where each class's key object sat in memory.
- **Captures:** `ca3_ml_dsa_tx_auth_timing_20261122_captures/floor_ml_*`,
  with `SHA256SUMS`. The device's paths and login are redacted; the raw
  files are in the estate's private captures.
- **That localisation does not stand.** Two faults:
  - Signing alone signed from a resident key object per class, the
    per-class memory that FN-DSA retired after placement alone crossed its
    nulls on this device. Its null reused one object, so it could not see
    placement.
  - Both halves read key A faster, while the composed call reads it slower.

### Second localisation: method, fixed before the run (2026-11-22)

This is a diagnostic, not an attempt. It has no registered line and makes
no proposal on the pass line.

- **Device and inputs:**
  - the floor device under a quiet claim;
  - seed `20261124`, so the same matched pair;
  - 50,000 samples per comparison;
  - modes `ml-dsa-sign`, `ml-dsa-keygen` and `ml-dsa` (the composed call).
- **One working slot.** Each diagnostic mode prepares every entry's key
  material, untimed, into one slot. The slot is allocated once and reused
  for every entry of both classes.
  - `ml-dsa-sign`: the keys are held as encoded bytes, and each entry
    decodes into the slot (`PrivateKey::try_from_bytes`) before
    `try_sign_with_seed` is timed.
  - `ml-dsa-keygen`: each entry copies the shared secret into the slot
    before the seed derivation and `keygen_from_seed` are timed.
- **Nulls.** `fixed-a-vs-fixed-a-again` holds key A as two separate
  copies, one per class, through the same slot. The planted control sits
  on that null.
- **Hint counts** (`ml-dsa-sign` and `ml-dsa`), read untimed after each
  call. fips204 0.5.0 writes the hint section last (`encodings.rs:280`).
  `hint_bit_pack` (`conversion.rs:277`) stores the running index after row
  `i` at `ω + i` (`:322`), so the last byte is the total.
- **A check, voiding the comparison on failure.** Every hint section is
  well formed by `hint_bit_unpack`'s rules (`conversion.rs:340-400`):
  - each row's count at least the previous and at most ω (step 4);
  - the positions within a row strictly increasing (step 9);
  - the unused bytes zero (step 17).
- **Reported per comparison:**
  - the overall figure, as in the registered statistic;
  - each class's mean hint count, and the two distributions compared by a
    chi-square test of homogeneity on a 2 × m table. Adjacent counts are
    pooled until every expected cell is at least 5. The test reports its
    degrees of freedom and the Wilson–Hilferty normal equivalent `z`.
  - the stratified comparison within equal hint counts: Welch's `t` per
    hint count, combined as the size-weighted difference of means over its
    pooled standard error. It is read as the main figure is, on the raw
    samples and below each of the same 100 cut-offs. The largest `|t|` is
    reported, with where it sits. **Minimum:** a hint count enters only
    when each class holds at least 100 entries of it below the cut-off
    being read.


### Second localisation: results (2026-11-22, 22:21 to 22:53Z)

The run:
- the floor device under a quiet claim;
- the existing clone checked out clean at `0619324b93` (status 0 lines)
  and built there, 22:07 to 22:20Z;
- `ml-dsa-sign`, `ml-dsa-keygen` and `ml-dsa`, each at 50,000 samples with
  seed `20261124`, one after another;
- 1.5 GHz, about 53 to 56 °C, throttled `0x0`, load about 1 (the run itself);
- the apt timers enabled; none fired in the window.

These are diagnostics, not attempts. The composed mode's capture prints
`result=PASS`, but it ran on diagnostic inputs (`inputs=NOT-REGISTERED`,
seed `20261124`), so it is not an attempt and closes nothing.

Every check held:
- every call returned;
- 790 of 790 kept composed signatures verified per comparison;
- no hint section was malformed;
- the replica matched fips204's own key.

The matched pair is the shake-down's: 27 candidates drawn, ExpandS bytes
2488/2488, ExpandA rejections 10/10.

| Comparison | Signing alone | Key generation alone | Composed call (`ml-dsa`) |
| --- | --- | --- | --- |
| Fixed pair, largest absolute t | 3.66 | 2.62 | 3.52 |
| Where, and the difference (A − B) | crop 1, below 1.027 ms: −0.49 µs | crop 10, below 0.956 ms: +0.08 µs | crop 2, below 3.455 ms: −9.3 µs |
| Fixed pair, raw `t` | −2.27 (means −45 µs) | 0.52 | −0.57 |
| Null `fixed-a-vs-fixed-a-again` | 2.12 | 1.21 | 2.20 (`fixed-a-vs-fixed-a`) |
| Second null `varied-vs-other-varied` | — | — | 1.85 |
| Control (planted 0.5 %) | 210.97 | 164.61 | 141.68 |
| `fixed-vs-varied` (information) | — | — | 3.32 |
| Hint means, A and B | 37.53 and 38.76 | — | 37.52 and 38.70 |
| Hint distributions, chi-square | 536.85, df 37, `z` 18.65 | — | 503.20, df 36, `z` 18.01 |
| Within equal hint counts, largest absolute t | 3.56 (crop 1) | — | 3.76 (crop 2) |
| Null within equal hint counts | 2.30 | — | 2.22 and 2.00 |
| Null hint chi-square `z` | 3.11 | — | 0.33 and 1.51 |
| Control within equal hint counts | 40.93 | — | 128.78 |

The pair's difference is A − B, from the line that sets the maximum.

**Read by the maintainer's three cases (2026-11-22):**
- **Signing alone is flat with the working slot.** 3.66, under 4.5, with
  its null at 2.12 and its control at 210.97. The first localisation's
  16.39 was placement: the per-class key objects.
- **Key generation alone is flat too.** 2.62 against the first
  localisation's 9.96. That figure was mostly placement as well, so it is
  not a by-design constant. What remains is a shift of about +0.04 to
  +0.11 µs (key A slower) from the 1st to the 90th percentile, against
  −0.09 to +0.04 µs in its null. It does not cross.
- **The composed call does not cross here.** 3.52, against the
  shake-down's 10.44 on the same mode, pair, seed and device. Neither key
  generation's residue nor the hint counts carry a crossing, because
  there is none to carry. Stratifying by hint count does not lower the
  figure (3.52 overall, 3.76 within equal counts).
- **What changed since the shake-down:**
  - Not the timed path. `shekyl-crypto-pq/src` is unchanged between
    `43ac1dff98` and `0619324b93`, fips204 is the same 0.5.0, and the
    lockfile's only change is `multiexp`, which ML-DSA signing does not
    reach.
  - The `ml-dsa` mode gained only untimed work after each call: the hint
    read, into a vector allocated before the loop.
  - Its keys were never per class: each entry carries its own copy of the
    shared secret.
  - What differs is the binary (a different tree, so a different code
    layout) and the time of the run (06:05Z, 56 to 58 °C, against 22:32Z,
    54 °C).
  - The shake-down's 10.44 is not attributed. Its binary is kept on the
    device (`sha256` `3ff1a1b5…`, the shake-down's capture), so running it
    again would separate the build from the conditions.
- **The hint counts are per key, and public.** The two keys' distributions
  differ (means 37.5 and 38.8, `z` about 18.7), as ML-DSA's design implies:
  the hints depend on the key. Within equal hint counts, the pair reads as
  it does overall, so the hint count carries none of its timing.

**Not settled by this run:**
- **Every pair figure sits above its null:** 3.66 against 2.12, 2.62
  against 1.21, and 3.52 against 2.20. A real effect of the size behind
  them would read about √10 times larger at the registered 500,000:
  about 11.6, 8.3 and 11.1. At 50,000 this run cannot tell such an effect
  from the spread of a maximum taken over 101 cut-offs.
- **The pair is not matched on signing's rejection rate.** ML-DSA's
  signing loop restarts at a rate that depends on the key. Signing alone's
  raw means differ by 45 µs (t −2.27), and its quartiles by 4.6 to
  10.0 µs. That alone would read about 7 raw at 500,000. FN-DSA's
  harness reads its restart count from the signature's nonce. ML-DSA's
  signature does not carry its attempt count.
- **The signing null's hint chi-square reads `z` 3.11** on one key held
  as two copies, where the two distributions are the same by construction.
  The composed call's two nulls read 0.33 and 1.51. It is reported as
  measured: either chance, about one in a thousand, or the
  approximation's edge with many sparse cells.
- **The stratified figure has less reach at the lowest cut-offs.** The
  minimum of 100 per class drops strata there, so the control reads 40.93
  within equal hint counts, against 210.97 overall.
- **About 1 ms of the composed call is in neither half.** The fastest
  signatures take about 2.97 ms composed, 1.01 ms signing alone and
  0.94 ms key generation alone. The rest is in `sign_derived_output_auth`
  (`output.rs:1247`): the Ed25519 key's derivation and its signature in
  the nested combiner, the ML-DSA key's encoding, and its decode on every
  call (`signature.rs:354`). The signing-alone mode decodes untimed. Its
  timed call is the shipped one: `try_sign_with_seed` on the combiner's
  64-byte inner message with an empty context (`signature.rs:439`, the
  seeded twin of the production `try_sign` at `:458`).

**Captures:** `ca3_ml_dsa_tx_auth_timing_20261122_captures/floor_loc2_*`
with `SHA256SUMS`, redacted as before. The raw files are in the estate's
private captures.

### The old-binary diagnostic (2026-11-23): the crossing reproduces with its own build

This is a diagnostic, not an attempt (the maintainer's ruling of
2026-11-22: run it before anything is registered, and let its result pick
the pass line).

The run:
- the shake-down's own binary, still on the floor device, its SHA-256
  checked first:
  `3ff1a1b523037b0de2f3350333482b44d23d5708cc53c80d4404e05b63de4939`, the
  shake-down's;
- `ml-dsa 50000 20261124`, the shake-down's mode, matched pair and seed;
- 00:09:57 to 00:31:09Z, under a quiet claim, the clock synchronised;
- 1.5 GHz, 47 then 56 °C, throttled `0x0`.

```text
matched-pair candidates_drawn=27 fixed-a expand_s_bytes=2488 expand_a_rejected=10 replicates=true fixed-b expand_s_bytes=2488 expand_a_rejected=10 replicates=true
check=replica replicated=true verdict=as-intended
information=fixed-a-vs-varied max_abs_t=1.33
pass-line=fixed-a-vs-fixed-b max_abs_t=7.12 verdict=INCONCLUSIVE
null=fixed-a-vs-fixed-a max_abs_t=2.12 verdict=no-evidence
null=varied-vs-other-varied max_abs_t=1.84 verdict=no-evidence
control=planted-leak planted_ns=22124 max_abs_t=127.31 verdict=detected
result=INCONCLUSIVE fixed_pair=7.12 worst_null=2.12 control=127.31 information_fixed_vs_varied=1.33
```

- **It is valid.** Every check held (790 of 790 kept signatures verified
  per comparison), the control was detected, and both nulls are below
  4.5.
- **It reproduces: the pair reads 7.12, at or above 4.5.** The maximum is
  at the lowest cut-off (below 2.99 ms, the single-attempt signatures).
  Key A is about 0.62 µs slower there, and 0.63 to 0.76 µs slower from
  the 1st to the 25th percentile: the shake-down's direction and mode, at
  somewhat less than its 0.9 to 1.3 µs.
- **It depends on the build.** On the same mode, pair, seed and device,
  the second localisation's build (`0619324b93`, the same timed path) read
  3.52, with key A 0.24 to 0.33 µs slower in the same percentiles.
  - The composed call therefore carries a per-key effect whose size
    follows the code layout.
  - Its likely carrier is the branch predictor learning each repeated
    key's rejection pattern under a given layout. The test repeats each
    key 25,000 times, and production signs with each output key about
    once. It is not identified.
- **What it decides** (the ruling): the composed call cannot be a
  reliable line, so the pass line is signing alone from the working slot,
  with the key decode timed. The composed call and key generation alone
  are information.

**Captures:** `floor_oldbin_*` with `SHA256SUMS`, redacted as before. The
raw files are in the estate's private captures.
