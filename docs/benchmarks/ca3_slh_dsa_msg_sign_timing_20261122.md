# `CA-3`, SLH-DSA-SHA2-192s: the message signature's signing time, registered 2026-11-22

**State of this record: registered; no run has been made.** Results, and
each device's noise calibration, are added below "Registered before the
run". That section is not edited afterwards.

## Why this run

[`CRYPTO_AUDIT.md`](../design/CRYPTO_AUDIT.md) §3.3 holds this signer's
threat model and source read:
- Its exposure is very low.
- Since `fips205` 0.5.0 every signature does the same number of hash
  calls.
- Every index its signing selects with is a function of a digest the
  signature reveals.

`CA-3` is still closed only by measurement. This run follows the
maintainer's rulings of 2026-11-21: three comparisons, a size taken from
the threat model, and a control sized from each device's measured noise. A
pass on both devices closes SLH-DSA's row.

## Registered before the run

**The question.** Does the time the message signature takes depend on the
value of the wallet's message key, in the build that ships?

**The subject.** `fips205` 0.5.0 (SLH-DSA-SHA2-192s), through
`sign_message_pq_half` (`rust/shekyl-crypto-pq/src/message_signing.rs`) as
the wallet calls it:
- it derives the message-signing identity from the master seed and signs
  one fixed message (one network, one bound segment);
- the signing is hedged with the OS's randomness (`try_sign(..., true)`),
  as shipped;
- every signature is verified after the loop.

It is built in the release profile from this workspace's lock file
(`--locked`), from a fresh clone of the commit that carries this record, in
a new directory.

**The harness.** `rust/shekyl-crypto-pq/examples/ca3_pq_sign_timing.rs`,
mode `slh-dsa`, at the commit that carries this record, by RT-P4's method.
The discarded calibration batch is 10 % (200 samples), since 1 % of 2,000
would leave 20, too few to place 100 cut-offs. A cut-off counts when both
classes keep more than 20 samples below it.

**The comparisons. Three:**
- **Pass line, `fixed-a-vs-fixed-b`:** two master seeds, each fixed for its
  class.
- **Null, `fixed-a-vs-fixed-a`:** voids the run.
- **Control:** the null again, with δ nanoseconds of work planted inside the
  timed region for one class. δ comes from the device's noise calibration
  (below) and is given on the command line.

There is no fixed-against-fresh comparison and no fresh-against-fresh null,
by the ruling:
- production reuses the one key;
- key generation, and signing in 0.5.0, are the same amount of work for
  every key;
- a fresh `opt_rand` moves only addresses that are functions of the
  revealed `R`.

Varied classes would add hours on the floor device and nothing else.

**Assumption: the size.** 1,000 signatures per class, 2,000 per comparison.
- The message key signs only when the user asks, or when an enrolled client
  asks, and that client can already sign.
- So comparing two keys over 1,000 local signatures each, on a quiet core,
  gives more samples, with less noise, than any observer of one wallet
  gets.
- This is an assumption about the threat model, not a measured fact. It
  reopens if the message key comes to sign on someone else's request.

**The noise calibration, on each device, before its registered run.**
- The same binary, a seed that is not the registered one, run as
  `ca3_pq_sign_timing slh-dsa-noise SEED`: the a/a null alone, 200 samples.
- It prints σ, the standard deviation of the raw per-signature times, and
  δ = 15 · σ · √(2/1000), about 0.67 σ.
- Its output, σ and δ are committed into this record before that device's
  registered run. δ is that run's stated sensitivity: a pass excludes a
  key dependence of δ or more, and nothing smaller.
- If the registered run is noisier than its calibration, the control goes
  undetected and the run is void, by the lines.

**The checks. Each can fail, and a failure voids the run.** Every timed
call returned a signature. Every signature, all of them, verifies under the
identity derived from its master seed, over the preimage the harness
computes. Printed as `check entries=… returned=… verified=…`.

**The lines, read in this order.**

1. A check fails: **void**.
2. The control is not detected (`|t|` ≤ 10): **void**.
3. The null's `|t|` is ≥ 4.5: **void**.
4. The fixed pair's `|t|` is > 10: **fail**.
5. The fixed pair's `|t|` is between 4.5 and 10: **inconclusive**.
6. The fixed pair's `|t|` is below 4.5: **pass**.

**The inputs.** The registered seed, given as no seed argument:
`ca3_pq_sign_timing slh-dsa δ`. The segment and the two master seeds are
drawn first from the stream. Every device draws the same ones.

**Two registered runs**, each with its own verdict:
- **The maintainer's Windows laptop (Intel Core i9-11950H, Tiger Lake).**
  Target `x86_64-pc-windows-msvc` with `+crt-static`, no `RUSTFLAGS`.
- **The floor device: the second Raspberry Pi 4, the 4 GB board** (rule
  76's floor; Cortex-A72; no SSD).
  - Target `aarch64-unknown-linux-gnu`, built on the device at `-j 2`.
  - Under a quiet claim, queued after `CA-3`'s FN-DSA run and the ML-DSA
    run.

**Cost.** About 3 × 2,200 signatures per device, plus the calibration's
220:
- about 1 hour on x86 (0.59 s a signature);
- about 8 hours on the floor device (about 4.3 s, `message_signing.rs`'s
  own figure).

**Conditions recorded** are as the FN-DSA registration records them
([`ca3_fn_dsa_receipt_sign_timing_20261121.md`](ca3_fn_dsa_receipt_sign_timing_20261121.md)).

**Attempts.**
- A fail or an inconclusive is not re-run.
- A void may be made again once, after its cause is named and fixed. A
  void for an undetected control also takes a new calibration.
- Every attempt is recorded, in order, with its full output, under
  `ca3_slh_dsa_msg_sign_timing_20261122_captures/` with a `SHA256SUMS`.

**What closes it.** SLH-DSA's row of `CA-3` closes when both runs pass.
A void, a fail or an inconclusive goes to the maintainer with its output.

**Development trials (not results).** On the maintainer's x86_64 Linux
workstation, shared, with seeds that are not the registered one:
- At 100 samples, under the earlier five comparisons: every signature
  verified; the lines read 0.77 and 1.68, and the nulls 1.52 and 0.51. A
  planted 0.5 % (2.9 ms) read 1.27 and was not detected. That miss is the
  reason this registration sizes its control from noise.
- One `slh-dsa-noise` trial, at load average about 0.9: σ 19.4 ms, so δ
  13.0 ms, with every signature verified. A quiet device sets its own.

## Results

No run has been made.
