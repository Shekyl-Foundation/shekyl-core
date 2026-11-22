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

No run has been made.
