# `CA-3`, ML-DSA-65: the transaction authorisation's signing time, registered 2026-11-22

**State of this record: post-fork revision 3 — floor PASS (2026-11-24),
physical Windows desktop PASS (2026-11-25). CA-3 is closed.** Revision 2 on published
fips204 0.5.0 passed on the laptop and was inconclusive (7.55) on the
floor. The maintainer ordered a fresh-seed run after #1545 merged the
fips204 fix. Revision 3 below fixes that run's inputs and conditions;
the earlier registrations and results remain records of their own builds.

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

## Registered before the run: revision 2 (2026-11-23)

The maintainer's ruling of 2026-11-22, after the two localisations and the
old-binary diagnostic below. **The size and the line were set after those
runs had been seen**, for the reasons in "Why the line and the size
changed". This section is complete in itself: where it and the first
registration differ, this one holds.

**The question.** Does the time ML-DSA-65 signing takes depend on the value
of the output's key, in the build that ships, counting the key's decode
that every signature performs?

**The line: signing alone, from one working slot, the key decode timed.**
- Each key is held as its encoded secret-key bytes. Before each entry,
  untimed, the entry's bytes are copied into one working slot, allocated
  once and used by every entry of both classes.
- Timed: `PrivateKey::try_from_bytes` on the slot, then fips204's
  `try_sign_with_seed` on a 64-byte message with an empty context. That is
  the shipped call's: it decodes the key on every call
  (`rust/shekyl-crypto-pq/src/signature.rs:354`) and signs the nested
  combiner's 64-byte inner message with an empty context (`:439`, the
  seeded twin of the production `try_sign` at `:458`).
- The harness is `rust/shekyl-crypto-pq/examples/ca3_pq_sign_timing.rs`,
  mode `ml-dsa-registered` (`ml_dsa_registered`, `sign_comparisons`).

**The classes and the pair.** Key A and key B, generated from shared
secrets drawn from the registered seed. The pair is matched by the existing
rule, equal ExpandS bytes and equal ExpandA rejections, with the replica
checks as in the first registration.

**The comparisons on the line.**
- **Pass line:** the matched pair, `sign-fixed-a-vs-fixed-b`.
- **Null, which voids:** `sign-fixed-a-vs-fixed-a-again`. Key A's bytes are
  held as two separate copies, one per class, through the same slot.
- **Control:** 0.5 % of the null's median time, planted inside the timed
  region for one class of that null.

**Information: the same size, in the same session, after the line.** Each
comparison is printed and recorded, and never read against the lines.
- **The composed call:** `sign_pqc_auth_for_output` through its seeded
  twin, as in the first registration, with its pair, its null
  (`fixed-a-vs-fixed-a`) and its control.
- **Key generation alone:** the output's seed derivation and
  `keygen_from_seed`, from one working slot, with its pair, its null (key
  A's two copies) and its control.

**The checks. Each can fail, and a failure in any comparison of the
session, information included, voids the run.**
1. The replica, for key A and key B, as in the first registration.
2. In every comparison:
   - every timed call returned;
   - every signature's hint section is well formed by fips204 0.5.0's own
     rules (`hint_bit_unpack`, `conversion.rs:340-400`);
   - one result in 64 is kept, and each kept one is checked after the loop.
     A signature must verify under its key; a generated public key must
     equal the one generated for that key before the loop.

**The lines, read in this order.**
1. A check fails: **void**.
2. The control is not detected (`|t|` ≤ 10): **void**.
3. The null's `|t|` is ≥ 4.5: **void**.
4. The pass line's `|t|` is > 10: **fail**.
5. The pass line's `|t|` is from 4.5 to 10: **inconclusive**.
6. The pass line's `|t|` is below 4.5: **pass**.

**Reported beside the verdict, as information,** for each comparison with
signatures:
- each class's mean hint count;
- the hint-count chi-square with its `z`;
- the figure within equal hint counts;
- the raw-mean difference, with its `t`.

**Stated sensitivity: δ₁₀.** For each attempt, δ₁₀ = planted ns × 10 /
the control's `|t|`. It is the per-key difference that would read 10 at
this size on that device. A pass excludes a dependence of δ₁₀ or more, and
nothing smaller. The harness prints it (`delta10_ns`).

**Size: 50,000 samples per comparison, on each device.**
- **Assumption, the basis:** an ML-DSA output key signs about once, so an
  observer gets about one sample per key (CRYPTO_AUDIT.md §3.2).
- At this size, the localisations' controls (0.5 % planted) read 141 to
  211 on the floor device. A pass therefore excludes a per-key dependence
  of a few µs, about 0.04 % of the call. An observer would need several
  hundred thousand signatures from one key to see a dependence of that
  size.
- This is the rule ruled for SLH-DSA on 2026-11-21: the size comes from the
  signer's threat model, not from FN-DSA's long-lived, unboundedly sampled
  receipt key. It replaces the inherited 500,000.

**The inputs.** The harness's ML-DSA registered seed,
`ML_DSA_REGISTERED_SEED` (`0x4341_335f_4d4c_3233`), with no seed argument;
the run prints `inputs=registered`. It is new with this revision, and no
run before it drew from it. The matched pair is drawn first, so both
devices hold the same keys. The diagnostic modes now require an explicit
seed, so none of them can draw the registered pair by default.

**One registered run per device**, each with its own verdict, from a fresh
recursive clone of the commit that carries this revision.
- **The floor device:** the 4 GB Raspberry Pi 4 (rule 76's floor), target
  `aarch64-unknown-linux-gnu`, built on the device at `-j 2` and not timed,
  under a quiet claim.
- **The maintainer's Windows laptop** (Intel Core i9-11950H), through the
  agent on that machine: target `x86_64-pc-windows-msvc` with `+crt-static`
  and no `RUSTFLAGS`, pinned to one logical processor, behind the same
  quiet gate as FN-DSA's laptop runs.
- **One build path on x86_64.** fips204 0.5.0 has no architecture-specific
  code: no `target_arch`, `target_feature`, `cpufeatures` or
  `is_x86_feature_detected` in its source. Its hashing, sha3 0.10.9 over
  keccak 0.1.6, has a run-time dispatch only on aarch64 behind keccak's
  `asm` feature (`keccak` `src/lib.rs:66-70`). Nothing in the workspace
  enables that feature, so keccak has one path on both devices.
- **Outside the line:** the composed call also runs Ed25519, whose SHA-512
  (sha2 0.10.9) picks an AVX2 path at run time on x86_64
  (`sha512/x86.rs:14-21`). That covers information only, and the record
  says which path the laptop took.

**Conditions recorded for each run** are as the first registration records
them (by reference to FN-DSA's): the binary's SHA-256, `rustc -vV`, the
times and the exit code.

**A shake-down on each device first.** Before each registered run, its own
binary runs once on its device: `ml-dsa-registered 20261126`, a seed that is
not the registered one, at the registered size. It shows that the binary
builds, runs, holds its checks and detects its control there. It is not an
attempt, and it is kept with the captures. If its control is not detected,
or a null crosses, the gap goes to the maintainer before an attempt is
spent.

**Attempts.**
- One registered attempt per device.
- A fail or an inconclusive is not re-run.
- A void may be made again once, and only after its cause is named and
  fixed.
- Every attempt is recorded with its full output under
  `ca3_ml_dsa_tx_auth_timing_20261122_captures/`, with a `SHA256SUMS`.

**What closes it.** ML-DSA's row of `CA-3` closes on a pass on both devices
together with the recorded source read (CRYPTO_AUDIT.md §3.2). `CA-3` then
closes with all three signers in. A void, a fail or an inconclusive goes to
the maintainer with its figures and options, and no option is chosen
before that.

**Why the line and the size changed.**
- **The composed call cannot be a reliable line.** The old-binary
  diagnostic reproduced the shake-down's crossing with the shake-down's own
  build (7.12). The second localisation's build read 3.52 on the same mode,
  pair, seed and device and the same timed path. The composed call
  therefore carries a per-key effect whose size follows the code layout.
  Its likely carrier is the test repeating each key: the branch predictor
  learning each key's rejection pattern under a given layout. Production
  signs with each output key about once.
- **The pair figures sat above their nulls in every mode at 50,000.** The
  localisations read 2.6 to 3.7, against nulls of 1.2 to 2.2. That is
  probably a per-key difference of about 0.3 µs, about 0.01 % of the call.
  Its likely carrier is the same repetition, but it is not identified. A
  run at 500,000 might cross on it, which is why the size is stated with
  its basis rather than inherited.
- **No retry-count stratification**, and no counted copy of fips204's
  signing loop:
  - By design, the key reaches the retry rate only through the hint bound,
    ω = 55. The z and r0 checks accept or reject independently of the key,
    or essentially so, and the ct0 bound is far out of reach.
  - The localisations' matching raw-mean differences came from one draw of
    attempt counts timed twice, because the seed was the same, not from a
    replicated key effect. Signing alone read −45.33 µs and −45.48 µs; the
    composed call read −11.35, −11.60 and −12.10 µs. The composed call's
    same-key null repeats its difference too: +19.48, +20.27 and
    +19.26 µs. The registered run uses a fresh seed.
- **The second localisation's signing-alone mode read each hint count
  inside its timed call:** a scan of at most 61 public bytes, about tens
  of nanoseconds, against the 0.49 µs that comparison showed. Its method,
  fixed before the run, said untimed. The registered harness reads it
  after the timer stops, in every mode.

**Development trial (not a result).** On the maintainer's x86_64 Linux
workstation, with seed `20261125`, at the registered size:
- the pair matched after 56 candidates;
- every check held, with 790 of 790 kept results verified per comparison;
- sign pair 1.39, null 2.37, control 40.16 (δ₁₀ 688 ns);
- composed pair 1.75, key generation pair 1.45.

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

### Revision 2: the laptop's shake-down and registered attempt 1 (2026-11-23): attempt 1 VOID

Both runs were made by the agent on the maintainer's Windows laptop (Intel
Core i9-11950H).
- **Build:** a fresh recursive clone of `84f9d24714`, `git status` clean.
  Unelevated, no `RUSTFLAGS`, 279 of 279 rustc invocations with
  `+crt-static`, `rustc` 1.94.0. The binary's SHA-256 is
  `d5fc9dbc0c5e0b634330f60a6d898eac966962d92a49be9698b39c2e9769bf19`.
- **AVX2:** reported, both by `IsProcessorFeaturePresent` and by .NET. So
  Ed25519's SHA-512, in the composed information only, took its AVX2 path.
- **Pinning:** logical processor 4 (affinity read back `0x10`), behind the
  quiet gate.

**The shake-down** (`ml-dsa-registered 20261126`, not an attempt;
00:55:46 to 01:00:22Z): every check held. Logical processor 5 was at 0.01
to 0.23 % in each one-minute sample.

```text
pass-line=sign-fixed-a-vs-fixed-b max_abs_t=2.26
null=sign-fixed-a-vs-fixed-a-again max_abs_t=1.75
control=sign-planted-leak planted_ns=2239 max_abs_t=59.20 delta10_ns=378
information=composed-fixed-a-vs-fixed-b max_abs_t=2.03
information=keygen-fixed-a-vs-fixed-b max_abs_t=2.53
result=PASS sign_pair=2.26 sign_null=1.75 sign_control=59.20 delta10_ns=378 information_composed_pair=2.03 information_keygen_pair=2.53
```

**Attempt 1** (`ml-dsa-registered`, `inputs=registered`; 01:03:03 to
01:09:01Z, 358 s; exit 1): **VOID.** The control was not detected.

```text
matched-pair candidates_drawn=51 fixed-a expand_s_bytes=2511 expand_a_rejected=6 replicates=true fixed-b expand_s_bytes=2511 expand_a_rejected=6 replicates=true
pass-line=sign-fixed-a-vs-fixed-b max_abs_t=1.61 median_ns=509600 raw_sd_ns=704163
null=sign-fixed-a-vs-fixed-a-again max_abs_t=2.83 median_ns=1071400 raw_sd_ns=1131832
control=sign-planted-leak planted_ns=5357 max_abs_t=3.49 delta10_ns=15363
information=composed-fixed-a-vs-fixed-b max_abs_t=1.85
information=composed-planted-leak planted_ns=5438 max_abs_t=28.56 delta10_ns=1904
information=keygen-fixed-a-vs-fixed-b max_abs_t=4.21
information=keygen-planted-leak planted_ns=873 max_abs_t=66.38 delta10_ns=132
result=VOID (the control was not detected, so a pass would mean nothing) sign_pair=1.61 sign_null=2.83 sign_control=3.49 delta10_ns=15363 information_composed_pair=1.85 information_keygen_pair=4.21
```

Read against the lines:
- Line 1: every check held, in every comparison of the session (790 of
  790 kept results verified each time, no malformed hint section, the
  replica as intended).
- Line 2: the control read 3.49, at or below 10, so the run is **void**.
  The pair's figure is not read.

**The cause, named:** load on the measured core's sibling during the run.
- The gate passed just before the launch, with logical processor 5 at 1.5
  to 4.8 %.
- In the run's six one-minute samples it was at 55, 57, 42, 39, 64 and
  64 % (mean 53.5 %), against at most 0.23 % in the shake-down minutes
  earlier.
- Logical processor 4's performance counter fell to 149 to 178 %, against
  177 to 181 % in the shake-down. Signing's spread rose from about 0.46 ms
  to 0.70 to 1.13 ms, enough to hide the 5.4 µs control.
- A browser was running at the start (18 processes) and had exited by the
  end. The desktop AI client used 86 s of CPU over the run. The gate
  measured load before the launch, not during the run, and did not check
  for a browser.

**Attempt 2: ruled by the maintainer on 2026-11-23.** The registration
allows a void to be made again once, after its cause is named and fixed.
The fix is this gate, recorded before the run:
- **The same binary and command:** `d5fc9dbc…`, from the `84f9d24714`
  clone; `ca3_pq_sign_timing ml-dsa-registered`, with no argument. No new
  shake-down.
- **Before the launch:**
  - the same four quiet 30-second samples: Defender under 10 % of one
    logical processor, total under 15 %, logical processor 5 under 5 %;
  - no browser process running (Chrome, Edge, Firefox, Brave, Opera);
  - the process list snapshotted into the conditions file.
- **During the run:**
  - logical processor 5 is sampled every 10 seconds, beside the
    one-minute samples, all kept;
  - any 10-second sample at 5 % or more is recorded with a process
    snapshot taken at that moment;
  - **the stop rule:** three consecutive 10-second samples of logical
    processor 5 at 5 % or more stop the run, which is then killed. This
    judges the conditions, never the output.
- **A stopped run is not an attempt.** Its partial output is kept in the
  private captures and not read; no figure from it is reported. The gate
  is then passed again and the run restarted. After a third stop, nothing
  further runs and the conditions go to the maintainer.
- **A run that completes is attempt 2**, read against the lines as
  registered. Its sibling samples are reported as conditions, and they do
  not void a completed run. The control's detection is what guards
  against noise.
- **The maintainer** leaves the laptop alone from the gate to the end
  (about 10 minutes), with no browser open. Whether the desktop AI client
  is paused for those minutes is his call, and the record states which.
- **Whatever attempt 2 reads, it is not made again.** A second void goes
  to the maintainer.

**Captures** (public): `laptop_reg2_shakedown_50000.txt` and
`laptop_reg2_registered_attempt1.txt`, the outputs byte for byte;
`laptop_reg2_rustc_vV.txt`; `laptop_reg2_cpu_avx2.txt`. They are stored
byte for byte (`.gitattributes`), with `SHA256SUMS`. The conditions,
process snapshots and samples name the machine's user profile and
processes, so they stay in the estate's private captures.

### Revision 2: the laptop's registered attempt 2 (2026-11-23): PASS

Made under the gate recorded above, with the same binary (`d5fc9dbc…`) and
command. The run completed on its first try, so no run was stopped.
- **Before the launch:** the gate passed at 01:31:04Z on its first four
  samples: logical processor 5 at 0.1 to 1.3 %, total 0.6 to 1.3 %,
  Defender 0.0 to 0.9 %, no browser in any sample.
- **Conditions:** no browser at the start or the end. The desktop AI client
  was not running: it was closed, not paused.
- **Run:** 01:31:09 to 01:35:40Z (271 s), exit 0.
- **Logical processor 5 during it:** 26 ten-second samples, from 0.00 to
  0.43 %, mean 0.06 %. None was at 5 % or more.
- **Logical processor 4's performance counter:** 175 to 181 %.

```text
matched-pair candidates_drawn=51 fixed-a expand_s_bytes=2511 expand_a_rejected=6 replicates=true fixed-b expand_s_bytes=2511 expand_a_rejected=6 replicates=true
pass-line=sign-fixed-a-vs-fixed-b max_abs_t=1.32 median_ns=456600 raw_sd_ns=459656
  hints mean0=37.40 mean1=38.42 chi2=396.87 df=37 chi2_z=15.63 | within-equal-hints max_abs_t=1.35 at crop 9 at 456600 ns (n=21843, strata need >= 100 per class) | raw_mean_diff_ns=-3668.9 raw_t=-0.89
null=sign-fixed-a-vs-fixed-a-again max_abs_t=3.38 median_ns=544900 raw_sd_ns=459785
control=sign-planted-leak planted_ns=2724 max_abs_t=65.73 delta10_ns=415
information=composed-fixed-a-vs-fixed-b max_abs_t=1.43
information=composed-planted-leak planted_ns=4139 max_abs_t=16.36 delta10_ns=2530
information=keygen-fixed-a-vs-fixed-b max_abs_t=3.35
information=keygen-planted-leak planted_ns=854 max_abs_t=113.01 delta10_ns=76
result=PASS sign_pair=1.32 sign_null=3.38 sign_control=65.73 delta10_ns=415 information_composed_pair=1.43 information_keygen_pair=3.35
```

Read against the lines:
- every check held in every comparison;
- the control was detected (65.73);
- the null is below 4.5 (3.38);
- the pass line reads 1.32: **PASS**.

On the laptop, a pass excludes a per-key dependence of signing, the decode
included, of δ₁₀ = 415 ns or more (about 0.08 % of the median signature),
and nothing smaller.

**Captures:** `laptop_reg2_registered_attempt2.txt`, byte for byte (9,654
bytes, `ca7f918c…`). The gate's script, its log, the 10-second sibling
series and the conditions are in the estate's private captures.

### Revision 2: the floor device's shake-down and registered attempt 1 (2026-11-23): INCONCLUSIVE

The floor device is the 4 GB Raspberry Pi 4 (rule 76's floor, Rev 1.2,
`c03112`). The maintainer confirmed it as the floor for these runs on
2026-11-23, after checking that memory was not a factor:
- 3.30 to 3.31 GB was available at the start and the end of every run;
- no swap is configured, so nothing was paged to the SD card (the kernel's
  swap counters read 0);
- the harness uses tens of MB.

The build and the runs:
- **Build:** a fresh recursive clone of `84f9d24714`, `git status` clean,
  built on the device at `-j 2` (00:45:33 to 01:04:28Z). The binary's
  SHA-256 is
  `e13550daad61d4b39f150fb2a0e3a9e67bb10ec5b54fa5e442264e0a3a4fd1ce`.
- Both runs were made under a quiet claim, at 1.5 GHz, 53 to 57 °C,
  throttled `0x0`, with the apt timers enabled (none fired).

**The shake-down** (`ml-dsa-registered 20261126`, not an attempt; 01:05 to
01:29Z) was not void, so the attempt followed as registered.

```text
pass-line=sign-fixed-a-vs-fixed-b max_abs_t=8.48
  hints mean0=39.19 mean1=37.51 chi2=988.63 df=36 chi2_z=25.75 | within-equal-hints max_abs_t=2.26 at crop 22 at 5114580 ns (n=39797, strata need >= 100 per class) | raw_mean_diff_ns=39575.9 raw_t=1.96
null=sign-fixed-a-vs-fixed-a-again max_abs_t=3.39
control=sign-planted-leak planted_ns=11139 max_abs_t=90.29 delta10_ns=1234
result=INCONCLUSIVE sign_pair=8.48 sign_null=3.39 sign_control=90.29 delta10_ns=1234 information_composed_pair=1.83 information_keygen_pair=2.95
```

The pair's maximum is at the lowest cut-off (below 1.244 ms, the
single-attempt signatures). Key A is slower there: +0.30 µs at that
cut-off, and +0.50 to +0.67 µs from the 1st to the 10th percentile.

**Attempt 1** (`ml-dsa-registered`, `inputs=registered`; 01:30 to 01:53Z;
exit 1):

```text
matched-pair candidates_drawn=51 fixed-a expand_s_bytes=2511 expand_a_rejected=6 replicates=true fixed-b expand_s_bytes=2511 expand_a_rejected=6 replicates=true
check=replica replicated=true verdict=as-intended
pass-line=sign-fixed-a-vs-fixed-b max_abs_t=7.55 median_ns=2229474 raw_sd_ns=2238428
  hints mean0=37.40 mean1=38.42 chi2=396.87 df=37 chi2_z=15.63 | within-equal-hints max_abs_t=1.93 at crop 5 at 1744336 ns (n=14246, strata need >= 100 per class) | raw_mean_diff_ns=-16283.5 raw_t=-0.81
null=sign-fixed-a-vs-fixed-a-again max_abs_t=3.15 median_ns=2701446 raw_sd_ns=2238295
control=sign-planted-leak planted_ns=13507 max_abs_t=118.00 delta10_ns=1145
information=composed-fixed-a-vs-fixed-b max_abs_t=1.81
information=composed-planted-leak planted_ns=22121 max_abs_t=136.46 delta10_ns=1621
information=keygen-fixed-a-vs-fixed-b max_abs_t=3.85
information=keygen-planted-leak planted_ns=4749 max_abs_t=145.95 delta10_ns=325
result=INCONCLUSIVE sign_pair=7.55 sign_null=3.15 sign_control=118.00 delta10_ns=1145 information_composed_pair=1.81 information_keygen_pair=3.85
```

Read against the lines:
- every check held in every comparison (790 of 790 kept results verified
  each time, no malformed hint section, the replica as intended);
- the control was detected (118.00);
- the null is below 4.5 (3.15);
- the pass line reads 7.55, from 4.5 to 10: **INCONCLUSIVE.** It is not
  made again, and it goes to the maintainer with the options.

The maximum is at the lowest cut-off (below 1.243 ms, the single-attempt
signatures). Key A is faster there: −0.26 µs at that cut-off, and −0.41 to
−0.44 µs from the 1st to the 10th percentile. That is about 0.03 % of a
single-attempt signature. Above the 10th percentile the quantiles do not
move together (−1.3 to −0.3 µs, then −5 and −19 µs in the tail), and the
raw means do not differ (t −0.81).

**An observation, not a registered statistic: the direction follows the
hint count on every floor pair.** Signing alone on the floor device, three
matched pairs, the fastest signatures:

| Pair | Hint means, A and B | A − B, 1st to 10th percentile | Figure |
| --- | --- | --- | --- |
| Second localisation (seed `20261124`, decode untimed) | 37.53 and 38.76 | −0.09 to +0.09 µs; −0.49 µs below the crop-1 cut-off | 3.66 |
| Revision 2's shake-down (seed `20261126`) | 39.19 and 37.51 | +0.50 to +0.67 µs | 8.48 |
| Revision 2's attempt 1 (registered seed) | 37.40 and 38.42 | −0.41 to −0.44 µs | 7.55 |

In each, the key with more hints per signature is the slower one in the
single-attempt mode. The size is about 0.3 to 0.4 µs per hint. The laptop
shows the same direction on the same pairs at about 0.1 µs (shake-down
+0.1, attempt 2 −0.1, at the 1st percentile).
- The within-equal-hints figure cannot test this where the effect sits.
  At the lowest cut-off, no hint count holds the 100 per class the method
  requires: about 1,500 signatures per class are spread over some 30 hint
  counts.
- The registered captures keep summaries, not per-signature times. So
  this observation cannot be tested from them.
- The hint count is public: it is the signature's last byte. If it is the
  carrier, the timing tells an observer nothing the signature does not.
  It is not established.

**Captures:** `floor_reg2_*` with `SHA256SUMS`: the build's files and
log, both runs' outputs, and their conditions. They are redacted as before;
the raw files are in the estate's private captures.

## Diagnostics after the floor's registered attempt (2026-11-23)

The maintainer's direction of 2026-11-23: an inconclusive result is a reason
to investigate. **Everything in this section is a diagnostic.** The registered
floor attempt stays recorded as inconclusive at 7.55, and no figure here is a
pass or a second attempt, whatever a run's result line prints.

### Step 1, method, fixed before the run: is the public hint count the carrier?

**The run.** The floor device under a quiet claim, a fresh clone of the commit
that carries this section, and `ca3_pq_sign_timing ml-dsa-dump DIR`.
- **A new build, so a new code layout.** Its SHA-256 is recorded with the
  result. From the registered commit `84f9d24714` to this one, nothing on the
  signing path moved: the toolchain file, the build profiles, `rust/.cargo`,
  `shekyl-crypto-pq/src`, and the locked versions of fips204, sha3, keccak,
  zeroize, sha2, ed25519-dalek, curve25519-dalek, hkdf and digest.
- **The same inputs.** The registered seed, with the same draws in the same
  order: the matched pair, then the signing pair, its null and its control at
  50,000 samples. `compare_op` and `sign_comparisons` are unchanged.
- **The dump.** The three comparisons' per-signature class, time and hint count
  are held in memory and written only after the control's loop, so no file I/O
  falls inside or between the timed loops.

**The analysis** is `ca3_ml_dsa_hint_carrier_20261123.py`, committed here and
tested on synthetic dumps with a known slope and key term. On the entries after
the calibration batch, in two windows:
- **First-attempt signatures:** time below **1,500,000 ns**, a fixed time inside
  the gap between the first-attempt mode (about 1.24 to 1.27 ms) and the
  second-attempt mode (about 1.74 ms).
- **The lowest sub-mode:** time below a boundary set once, blind to class, from
  the null's pooled first-attempt times: the centre of the first valley in a
  500 ns histogram (at or below 20 % of the first peak). If no valley begins
  within 30 µs, the boundary is 1,250,000 ns.

No sample inside a window is removed. Interrupt-hit samples stay, and the
standard errors are heteroskedasticity-robust (HC1). Per window:
- each key's slope of time on hint count, in ns per hint, with its standard
  error;
- the pooled model `time ~ key + hints`: the key term (A − B, ns) with its `t`,
  and the shared slope with its `t`;
- the unadjusted A − B difference, with its Welch `t`.

**The prediction:** tens of ns per hint. `hint_bit_pack`
(`conversion.rs:277`) is a branch and a store per hint.

**Void, and made again only after its cause is named:**
- a registered check fails, the control is not detected, or the null is at or
  above 4.5;
- the hint statistics differ from the registered attempt's (pair 37.40 and
  38.42, χ² 396.87, 25,134 and 24,866 entries; null χ² 21.58; control χ²
  42.05). Hint counts do not depend on the device or the build, so a difference
  means the inputs differ;
- the model's key term on the null reaches `|t|` 4.5 in either window;
- the model's key term on the control is more than 25 % from the planted size.

**The reading, on the pair:**
- **Carried by the hint count:** a difference is present (unadjusted `|t|` ≥ 4.5
  in a window), and in **both** windows the shared slope is at least 100 ns per
  hint with `|t|` ≥ 4.5 and the key term's `|t|` is below 4.5. It is then
  harmless, and the diagnostics go to the close.
- **Vacuous:** this build's unadjusted `|t|` is below 4.5 in both windows, so
  there is no difference for the hint count to carry. That proves nothing about
  the carrier. It is recorded as a layout data point, and Step 2 follows.
- **Not carried:** anything else. Step 2 follows.

### Step 1, result (2026-11-23): valid; vacuous; the hint count is not the carrier

**The run.** A fresh clone of `e2ebdc5ec3` (`git status` clean), built on the
floor device from 14:24:46 to 14:43:43Z. **This is a new build:** SHA-256
`961a293f49a4d8ffc783376f476e4aab2f3899f2a43b2af65722c1486aa21458`. At 1.5 GHz,
56 to 58 °C, throttled `0x0`, 3.30 GB available, no swap.

```text
diagnostic=sign-fixed-a-vs-fixed-b max_abs_t=3.01 median_ns=2220009 raw_sd_ns=2225619 n0=25134 n1=24866
  hints mean0=37.40 mean1=38.42 chi2=396.87 df=37 chi2_z=15.63 | within-equal-hints max_abs_t=1.37 at crop 4 at 1738019 ns (n=12724, strata need >= 100 per class) | raw_mean_diff_ns=-15352.0 raw_t=-0.77
null=sign-fixed-a-vs-fixed-a-again max_abs_t=3.82
control=sign-planted-leak planted_ns=13453 max_abs_t=91.77 delta10_ns=1466
diagnostic-result=PASS sign_pair=3.01 sign_null=3.82 sign_control=91.77 delta10_ns=1466
```

That `PASS` is the harness's line on a diagnostic. It is **not** a pass of the
registered floor attempt, which stays inconclusive at 7.55.

**Valid.** Every void condition is clear:
- every check held (790 of 790 kept signatures verified per comparison);
- the hint statistics reproduce the registered attempt's exactly, so the inputs
  are the same;
- the null's key term is below 4.5 in both windows (−1.14 and 2.14);
- the control's key term recovers 12,689 ns of the 13,453 ns planted (5.7 % off).

**The figures** (A − B). The lowest sub-mode's boundary, set from the null, is
1,249,742 ns.

| Window | Entries (A, B) | Slope A, ns per hint | Slope B | Shared slope (`t`) | Key term, ns (`t`) | Unadjusted, ns (Welch `t`) |
| --- | --- | --- | --- | --- | --- | --- |
| First-attempt | 4,978, 4,879 | 65.9 ± 50.3 | 44.5 ± 49.3 | 55.2 (1.57) | −463.8 (−1.03) | −524.9 (−1.17) |
| Lowest sub-mode | 1,925, 1,820 | 23.1 ± 9.8 | 4.1 ± 10.3 | 13.9 (1.96) | −265.5 (−3.04) | −277.0 (−3.18) |

**The reading, as fixed before the run: vacuous.** The unadjusted `|t|` is below
4.5 in both windows, so this build shows no difference for the hint count to
carry.

**What it does show:**
- **The hint slope is tens of ns per hint,** the size `hint_bit_pack` predicts,
  not hundreds. Across the pair's gap of about one hint, that is about 14 to
  56 ns. Adjusting for the hint count moves the lowest sub-mode's difference
  only from −277 to −266 ns. So the hint count does not carry the difference,
  and the earlier observation of 0.3 to 0.4 µs per hint, drawn from three
  pairs' summaries, does not hold on per-signature data.
- **The same pair, inputs and timed source read 3.01 on this build and 7.55 on
  the registered one.** The direction is the same (key A faster). This is one
  more build-to-build change, and the next step tests it directly.

**Captures:** `floor_step1_*` with `SHA256SUMS`, including the analysis's output
and the hashes of the three per-signature dumps. The dumps are in the estate's
private captures.

### Step 2, method, fixed before the runs: is it a layout-dependent repetition artifact?

**Why.** The fixed pair repeats each key 25,000 times, so the branch predictor
can learn each key's patterns, and how well it learns them depends on where the
code sits. A dependence on the key's values keeps its direction wherever the
code is placed.

**Step 1's build is not a layout variant.** The verifier below compares it with
the registered build and finds different code: adding the dump mode changed how
the compiler emitted three fips204 functions (`sig_encode`, `rej_ntt_poly`,
`sample_in_ball`), alongside the harness's own. Its source for the timed path is
the same, but its 3.01 is not evidence about layout, and it is not read here.

**The builds.** All come from the registered commit `84f9d24714`, in the floor
device's existing clean clone of it, with the same toolchain:
1. **Registered:** the registered binary itself, `e13550da…`, not rebuilt.
2. **Alignment:** every function aligned to 128 bytes
   (`RUSTFLAGS="-C llvm-args=-align-all-functions=7"`).
3. **Moved:** the registered build's objects relinked with `.text` starting
   0x1240 bytes later (`-C link-arg=-Wl,--section-start=.text=0x9640`, against
   0x8400). That is padding ahead of all the code, fips204 included.

If the alignment build's code differs from the registered build's, it is
replaced before any timing run by a relink of the same objects with the
functions in a different order (`-Wl,--sort-section=name`).

**Verified before any timing run** by
`ca3_ml_dsa_layout_compare_20261123.py`, which compares each variant's `.text`
with the registered binary's, by disassembly. Every function's name and
instruction stream must match once address-only content is removed, and
fips204's functions must have moved. The check was shown able to fail: it
refuses a binary against itself (nothing moved) and the Step 1 build (code
differs). A variant that does not pass is not run.

**The runs.** `ca3_pq_sign_timing ml-dsa-registered`, the registered pair and
inputs at 50,000 samples, under a quiet claim, in this order:
registered, alignment, moved, registered again. The identical binary brackets
the variants, so a change between runs of one binary is not mistaken for a
layout effect. Only the signing pair, its null and its control are read; the
information comparisons those runs also print are recorded and not read.

**A run is void** if its checks fail, its control is at or below 10, or its null
is at or above 4.5. A void run is made again once, after its cause is named.

**Direction:** the sign of A − B at the cut-off where the pair's `|t|` is
largest (the `max_at_crop` line). The registered attempt's is negative: key A
faster.

**The reading:**
- **The baseline reproduces** when both registered runs read `|t|` ≥ 4.5 with
  key A faster.
- **Unstable, a layout-dependent repetition artifact:** the baseline reproduces,
  and at least one variant reads below 4.5 or has the opposite direction. The
  diagnostics go to the close.
- **Stable, a dependence on the key's values:** the baseline reproduces, and both
  variants read `|t|` ≥ 4.5 with key A faster. Step 3 follows.
- **Not reproduced:** a registered run reads below 4.5 or has the opposite
  direction. The figure then moves between runs of one identical binary. That is
  **not** a layout finding, and it does not close anything. It goes to the
  maintainer with the figures.

**Device scheduling.** These runs use the floor device; scheduling records
are maintained in the private infrastructure usage ledger.

### Step 2, the builds as verified, before any timing run

All were built on the floor device from the clean clone at `84f9d24714`.

| Build | SHA-256 | How | Against the registered binary |
| --- | --- | --- | --- |
| Registered | `e13550da…` | the registered binary | the baseline |
| Alignment | `a7d0db96…` | every function aligned to 128 bytes | **layout only:** 1,059 functions and 152,297 instructions identical; 78 of 78 fips204 and 2 of 2 keccak functions moved |
| Moved | `d8f2969a…` | same objects, `.text` 0x1240 bytes later | **layout only:** the same counts, all moved |
| Sorted (the fallback) | `22721d0c…` | same objects, `--sort-section=name` | **rejected, not run:** it reorders data as well as code (`.rodata` and `.bss` change size) |

**A correction to the verifier, before any timing run.** It first refused the
alignment build on one instruction in `__init_cpu_features_constructor`: an
`ldr` whose ADRP page offset is zero in that layout, which disassembles as
`[x11]` rather than `[x11, #imm]`. That is address-only content the normaliser
missed, so the fallback in the method was not needed. With the form handled, the
verifier still refuses a binary against itself, the Step 1 build and the sorted
relink. Its outputs are `floor_step2_verify_*`.

**The timing runs** each copy their binary to one path of the same length as
the registered run's, from the same working directory, with the same command.
The size of the arguments does not vary between them. Any address randomisation
the kernel applies per process still applies to each run.

### Step 2, result (2026-11-23): not reproduced; closes nothing

**The runs.** On the floor device under a quiet claim, 15:20 to 16:57Z, in the
order below, the registered pair and inputs at 50,000 samples. At 1.5 GHz, 53 to
57 °C, throttled `0x0`, the apt timers enabled and none firing. All four are
valid: every check held, every null is below 4.5, every control was detected,
and the hint statistics reproduce the registered attempt's. These are
diagnostics. Their result lines print `FAIL` or `PASS`, and neither is a verdict
on the registered attempt, which stays inconclusive at 7.55.

| Run | Build | Signing pair | A − B at that cut-off | A − B at the 1st, 5th, 10th percentile, ns | Null | Control | δ₁₀ |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Registered attempt 1 (earlier, for reference) | registered | 7.55 | −258 ns | −444, −407, −444 | 3.15 | 118.00 | 1,145 ns |
| 1 | registered | **10.50** | −354 ns | −592, −519, −463 | 3.15 | 72.77 | 1,861 ns |
| 2 | alignment | 2.75 | −123 ns | −130, +1, −37 | 3.58 | 68.43 | 1,970 ns |
| 3 | moved | 1.90 | +326 ns | −18, +55, −20 | 2.77 | 74.49 | 1,801 ns |
| 4 | registered | **4.05** | −139 ns | −259, −296, −240 | 3.20 | 117.63 | 1,144 ns |

**The reading, as fixed before the runs: not reproduced.** The second run of the
registered binary reads 4.05, below 4.5, so the baseline does not hold. The
figure moves between runs of one identical binary. By the method, that is not a
layout finding and it closes nothing.

**What the figures do and do not show.** These are observations after the fact,
not the committed reading:
- The registered binary read 7.55, 10.50 and 4.05 across three runs, always with
  key A faster, and by 0.24 to 0.59 µs at the low percentiles.
- The two layout variants, one run each, read 2.75 and 1.90, and sit within
  −0.13 to +0.06 µs at the same percentiles. That points towards layout.
- It does not establish it. One identical binary spans 4.05 to 10.50, and each
  variant has a single run, so the spread between runs is as large as the
  difference between builds.
- The composed call, which is the shipped path, read 2.72, 2.60, 2.00 and 1.29
  in these runs (information).
- Key generation alone read 10.84, 4.44, 5.94 and 5.33 (information). It moves
  between runs of the registered binary too.

**Captures:** `floor_step2_*` with `SHA256SUMS`. The raw files are in the
estate's private captures.


## Registered before the run: revision 3, post-fork (2026-11-24)

**Status: REGISTERED; no revision-3 run has been made.** This follows the
maintainer's final instruction for fork #1, core #1545 and CA-3: #1545 is
merged, and #1504 contains current dev, including the fips204 fork at
`54b76cf71430a406f3c96ab9c80c42b0d74ce2fd`.

**The line and size stay revision 2's:** signing alone from one working
slot, with the secret-key decode inside the timed call; 50,000 samples
per comparison, calibration 500, the same 100 crops. The pair is matched
on ExpandS bytes and ExpandA rejections; both replicas must agree with
the library. The composed call and key generation remain information.
All checks, retained-signature verification, null, planted 0.5 % control,
sensitivity calculation and ordered verdict lines stay as registered:
any check failure, control at or below 10, or null at or above 4.5 voids
the run; otherwise the signing pair below 4.5 passes, 4.5 through 10 is
inconclusive, and above 10 fails.

**Fresh inputs, fixed before either device runs.**
`ML_DSA_REGISTERED_SEED = 0x4341_335f_4d4c_4633`. Run
`ca3_pq_sign_timing ml-dsa-registered` with no argument, which prints
`inputs=registered`. This seed has not been used by an earlier run.
Both devices draw the same matched pair first. Each binary first makes
one shake-down at the same size with explicit seed `2026112801`, outside
the registered inputs. A void shake-down stops the attempt until the
cause is identified and fixed; it does not spend the registered attempt.

**Build and conditions.** Each device uses a fresh recursive checkout of
the commit carrying this registration, release profile, rustc 1.94.0,
locked dependencies and no additional RUSTFLAGS. Record its clean source
SHA, toolchain, binary SHA-256, start/end conditions, times and exit code.
- **Floor:** the 4 GB Raspberry Pi 4, native aarch64, build at two jobs,
  under a quiet claim. Set the governor to `performance` before the
  shake-down and attempt, record it with frequency, temperature and
  throttling, and restore the original governor after the session.
- **Laptop:** native Windows MSVC, `+crt-static` from workspace config,
  pinned to logical processor 4 at Normal priority. Use the recorded
  revision-2 attempt-2 quiet gate, including the ten-second sibling
  monitor and its stop rule; no browser and Defender left enabled.

**Attempts and reading.** One registered attempt per device. A void may
be repeated once only after its cause is recorded and fixed. A completed
fail or inconclusive is recorded and localised without repeating it as
an attempt. Interrupted laptop runs stay unread as the quiet gate requires.
Pass on both devices closes ML-DSA and CA-3; anything else stays open
while localisation continues, returning to the maintainer for a decision
only when one is needed. Keep full outputs and SHA256SUMS beside the
existing captures, with operational conditions in the private estate record.


### Revision 3 device amendment, before the Windows run (2026-11-24)

**REGISTERED by the maintainer's instruction:** use a fleet Windows machine
in place of the unavailable personal laptop. The second device is now a
Windows Server 2025 x86_64 VM with eight virtual cores, no guest SMT,
and native MSVC. The source and seed remain registration commit
`63bcfab1d45fb9a1a71cf9f9a6231d1f291307d1`; the line, sample size,
null, control, checks, sensitivity and attempt rules do not change.
The floor build and run are unaffected by this device substitution.

Use the same quiet gate and core-4 affinity, with logical processor 5 as
an additional load sentinel. It is **not** identified as core 4's SMT
sibling on this VM. Record guest CPU and virtualization, other workload,
disk latency, power state, Defender settings and the actual execution
privilege; the SSH session is elevated, unlike the personal laptop's.
Pause the fleet's default mining task during the measurement and restore
its prior state afterward, without changing its configuration. No timing
on storage affected by the live infrastructure notice is accepted until
that condition is cleared. Hypervisor scheduling is outside the guest's
quiet gate; the null and control remain required. This run establishes
only the sensitivity it reports on this virtualized device, not the
unavailable laptop's or dedicated physical-core scheduling.


### Revision 3: fleet Windows shake-down 1 (2026-11-24): VOID; no attempt spent

**Status: VOID preflight; registered seed unused on Windows.** A fresh
recursive checkout of `63bcfab1d45fb9a1a71cf9f9a6231d1f291307d1`,
rustc 1.94.0, release MSVC with workspace `+crt-static`, no extra
RUSTFLAGS. Binary SHA-256:
`1fb971bdf7e2adde1118f4e7125cb1fb5fecd4ec53929ead203914f23a9f055c`.
The Windows Server VM has eight virtual cores and reports AVX2.

The shake-down used explicit seed `2026112801`, not the registered seed,
from 01:33:54 to 01:45:36Z on 2026-11-25 (702 seconds; exit 1).
The quiet gate passed on its first four samples. The harness ran on
logical processor 4, affinity read back `0x10`, Normal priority. Logical
5's 69 ten-second samples averaged 1.91 %, maximum 12.06 %, with two
samples at or above 5 % and no stop. The original power plan and
Defender settings were unchanged; operational captures stay private.

```text
pass-line=sign-fixed-a-vs-fixed-b max_abs_t=1.73
null=sign-fixed-a-vs-fixed-a-again max_abs_t=2.00
control=sign-planted-leak planted_ns=5724 max_abs_t=6.28 delta10_ns=9118
result=VOID (the control was not detected, so a pass would mean nothing) sign_pair=1.73 sign_null=2.00 sign_control=6.28 delta10_ns=9118 information_composed_pair=1.70 information_keygen_pair=3.02
```

Every replica and comparison check held: 50,500 calls returned per
comparison and 790 retained results verified, with no malformed hints.
The control is at or below 10, so the session is void before the pair's
line is read. The registered attempt did not launch. The default workload
was restored by the driver. This result is retained, not replaced.

**Localisation, not an attribution:** at the control's largest cut-off,
class 1 is 4,884 ns slower, near the intended 5,724 ns delay, but only
reads 6.28. The composed and key-generation controls also read below 10
(4.53 and 5.46). Guest timing spread is a candidate cause; it is not
established by these figures. Short unregistered diagnostics compare
Balanced and High Performance before deciding whether conditions can be
fixed. No threshold, sample size or control fraction has changed.

**Capture:** `windows_reg3_shakedown1_void.txt`, byte for byte (9,910 bytes,
SHA-256 `2f35a914ef99cdb3ba04946cf5ec844c84c958627941ac5d32e5c62f59b84945`),
with the toolchain and binary hash beside the earlier captures.


### Revision 3 replacement Windows conditions, before its preflight (2026-11-24)

**REGISTERED before using the registered seed on any Windows device.** The
first fleet VM's void preflight and both hosts' short diagnostics are
retained. High Performance did not establish a fix on the first VM; the
second could detect the control in several of its short diagnostics.
Use that replacement VM, with a fresh native build of the same registered
source `63bcfab1d4`. It is another eight-vCPU Windows Server 2025 guest.
Selection uses the unregistered diagnostics, not a registered pair result.

Set High Performance for the session, do five fixed warm-ups of keygen
only (`ml-dsa-keygen 5000 2026112901`, diagnostic seed), then allow two
minutes to settle before the existing four-sample quiet gate. Pin the
warm-ups and timed process to logical processor 4 at Normal priority.
Restore the prior plan and default workload afterward. The fixed warm-up
count is not extended until a diagnostic happens to look favourable.

The full preflight remains `ml-dsa-registered 2026112801`. Only a valid
preflight permits `ml-dsa-registered` with the still-unused Windows
registered seed. The signing line, timed decode, 50,000 samples, 0.5 %
control, 100 crops, all checks and ordered verdict thresholds are unchanged.
A void is retained and localised, not read as a passing pair.


### Revision 3: the floor's registered attempt 1 (2026-11-24): PASS

**Status: PASS on the registered signing line.** A fresh recursive checkout
of `63bcfab1d45fb9a1a71cf9f9a6231d1f291307d1`, built natively on the
4 GB Raspberry Pi 4 at two jobs, rustc 1.94.0, release with locked
dependencies and no extra RUSTFLAGS. Binary SHA-256:
`a366cb8dc150af16efad08c9e48b69e348ce5f850deab9b405ab55483dd98210`.

**The shake-down, not an attempt:** explicit seed `2026112801`,
01:16:14–01:38:51Z on 2026-11-25. It was valid but inconclusive: pair
7.86, null 1.66, control 180.92, delta10 602 ns. Its full output stays
in `floor_reg3_shakedown.txt`. The registered inputs were not used.

**Registered attempt 1:** 01:39:51–02:02:31Z on 2026-11-25 (1,360 seconds),
no seed argument, `inputs=registered`, exit 0. The two keys matched after
62 candidates, on 2,504 ExpandS bytes and five ExpandA rejections; both
replicas agreed with the fork. The performance governor held at both
ends, 1.5 GHz, 50.1 to 54.0 °C, no throttling (`0x0`), NTP synchronised,
about 3.13 GiB available. The original governor was restored after the
session and read back. Operational logs stay in the private record.

```text
pass-line=sign-fixed-a-vs-fixed-b max_abs_t=3.57 median_ns=2116473
null=sign-fixed-a-vs-fixed-a-again max_abs_t=2.16
control=sign-planted-leak planted_ns=10567 max_abs_t=160.82 delta10_ns=657
result=PASS sign_pair=3.57 sign_null=2.16 sign_control=160.82 delta10_ns=657 information_composed_pair=3.44 information_keygen_pair=16.55
```

Read in the registered order: every check held in every comparison;
the control exceeds 10; the null is below 4.5; the signing pair is below
4.5. **PASS.** Each comparison returned all 50,500 calls and verified all
790 retained results, with no malformed hint sections.

The stated sensitivity is delta10 657 ns, about 0.031 % of the signing
median. The pass says nothing below that bound. The key-generation pair
reads 16.55 as information, outside the registered signing line; it stays
in the output and no attribution is inferred from it here. The composed
pair is also information (3.44).

**Captures:** `floor_reg3_registered_attempt1.txt`, the shake-down,
`floor_reg3_rustc_vV.txt` and `floor_reg3_binary_sha256.txt`, with SHA256SUMS.
Windows still needs a valid preflight and a passing registered attempt;
CA-3 is not closed by the floor result alone.


### Revision 3: replacement Windows preflight (2026-11-24): VOID; registered seed unused

**Status: VOID preflight; the maintainer selected the standalone laptop run.** The second
eight-vCPU Windows Server VM used its own fresh native MSVC build of
`63bcfab1d4`, rustc 1.94.0, release, workspace static CRT. Binary SHA-256:
`281b1efe6190b54c9452e279eaa32d959312eff1c80437380e4862b02895f84e`.
High Performance, five fixed keygen warm-ups, the settling pause and the
original quiet gate were applied as registered. The process ran on
logical 4 at Normal priority, affinity read back `0x10`.

The full unregistered preflight (`2026112801`) ran from 02:24:49 to
02:36:10Z on 2026-11-25 (682 seconds; exit 1). Every functional check
held, including the replicas and retained results. Its lines are:

```text
pass-line=sign-fixed-a-vs-fixed-b max_abs_t=1.56
null=sign-fixed-a-vs-fixed-a-again max_abs_t=1.72
control=sign-planted-leak planted_ns=5922 max_abs_t=4.39 delta10_ns=13478
result=VOID (the control was not detected, so a pass would mean nothing) sign_pair=1.56 sign_null=1.72 sign_control=4.39 delta10_ns=13478 information_composed_pair=1.64 information_keygen_pair=1.52
```

The control is at or below 10, so the pair is not read as evidence. No
registered Windows attempt launched on either VM. The original Balanced
plan and default workload were restored and read back. Power settings and
a fixed warm-up did not make this platform's full preflight valid. This
does not establish which guest or host mechanism caused the weak control.

The maintainer selected the standalone physical laptop runner under the
existing method. The 50,000 samples, 0.5 % control and verdict thresholds
remain unchanged. No further fleet VM attempt is planned. The floor's
registered PASS remains its own result; CA-3 remains open pending the
laptop's valid preflight and registered result.

**Capture:** `windows_reg3_replacement_shakedown_void.txt`, byte for byte,
9882 bytes, SHA-256 `1d2a2953b02bd82eb5e5dde7deefcbb88c540c1921af93a342b4b170df403199`, with SHA256SUMS.

### Revision 3 replacement physical Windows host, before its preflight

The maintainer selected a physical Core i9-13900K desktop for the outstanding
Windows run. The Windows CPU-set API reports logical processors 4 and 5 on
one performance core. Use logical 4 at Normal priority and observe sibling
5 with the laptop quiet gate. Use the existing Balanced plan on mains power,
with Defender active and no browser processes during the four quiet samples.
Build and run under a limited token. Build a fresh native MSVC release from
the registered revision with rustc 1.94.0 and the workspace static CRT.

Run the full preflight with seed `2026112801` and check its controls before
launching the single registered attempt. Use the revision-3 size, planted
control, null, functional checks and verdict thresholds above. Retain each
completed result and apply the existing gate stop and repeat rules. Neither
fleet VM used the registered Windows seed.

### Revision 3 registered result on physical Windows (2026-11-25)

**PASS on attempt 1.** The physical i9-13900K completed the release build
of `63bcfab1d45fb9a1a71cf9f9a6231d1f291307d1` with rustc 1.94.0, native
x86_64 MSVC and workspace static CRT. Executable SHA-256
`059efe5218650531648d669f9740c5e1a49678d663f99b27f97258e213fa1cb7`.
An elevated observer read the Windows performance counters. The harness
ran with the Administrators group deny-only, Normal priority and affinity
0x10. Both runs passed the four-sample quiet gate and completed on their
first launch under the ten-second sibling monitor.

| Inputs | Signing pair | Null | Planted control | delta10 |
| --- | ---: | ---: | ---: | ---: |
| Unregistered preflight, 2026112801 | 1.59 | 1.86 | 111.94 | 143 ns |
| Registered, 05:24:26–05:27:26 UTC | 3.33 | 2.04 | 96.68 | 139 ns |

The registered binary reported `inputs=registered`. The matched pair took
62 candidates, with 2,504 ExpandS bytes and five ExpandA rejections for
both keys. Both replicas agreed. Each of the nine comparisons returned
all 50,500 calls and verified all 790 retained signatures, with zero
malformed hint sections. Exit code 0. The planted delay was 1,345 ns.
The informational composed and key-generation pairs were 2.11 and 7.15.

The capture directory contains `windows_desktop_reg3_shakedown.txt` and
`windows_desktop_reg3_registered_attempt1.txt`. Both hashes match the
observer logs. The floor also passed (pair 3.57, delta10 657 ns).
These results meet the registered signing criterion on both devices.
