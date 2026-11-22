# `CA-3`, SLH-DSA-SHA2-192s: the message signature's signing time, registered 2026-11-22

**State of this record: the floor device's registered run is in, and it
PASSES; the laptop's calibration and run are not yet made.** Results, and
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

### The floor device's noise calibration (2026-11-22, before its registered run)

The 4 GB Pi 4, under the lane's quiet claim with the host's apt timers
paused (the maintainer's go). The run:
- the binary built on the device from a fresh clone of `43ac1dff98`;
- `ca3_pq_sign_timing slh-dsa-noise 20261125`, a seed that is not the
  registered one;
- 06:30:49 to 06:52:00Z;
- clock synchronised, 1.5 GHz, 49 to 56 °C, throttled `0x0`, no
  under-voltage.

```text
  check entries=220 returned=220 verified=220 verdict=as-intended
null=fixed-a-vs-fixed-a max_abs_t=0.96 median_ns=5272664283 raw_sd_ns=1821911 n0=110 n1=90 verdict=no-evidence
noise-calibration sigma_ns=1821911 delta_ns=1222175 (delta = 15 * sigma * sqrt(2/1000))
```

- **σ = 1,821,911 ns** (0.035 % of the 5.27 s median signature).
- **δ = 1,222,175 ns.** That is the floor run's planted control and its
  stated sensitivity: a pass there excludes a key dependence of 1.22 ms
  (0.023 % of a signature) or more, and nothing smaller.
- The floor run is `ca3_pq_sign_timing slh-dsa 1222175`.
- A signature takes 5.27 s on the device, not the 4.3 s the estimate
  assumed, so the run takes about 9.7 hours (3 × 2,200 signatures).
- The output and its conditions are
  `ca3_slh_dsa_msg_sign_timing_20261122_captures/floor_slh_noise_*`, with
  `SHA256SUMS`. The device's paths are written `<clone>` and `<home>`, its
  login `<agent>`, and the raw files are in the estate's private captures.

### The floor device's registered run: PASS

**The attempt.** One attempt, on the 4 GB Pi 4 under the lane's quiet claim,
with the host's apt timers paused (the maintainer's go).
- **Source:** a fresh recursive clone of `0f2012233e`, the commit that
  carries this registration and the calibration above, with `git status`
  clean.
- **Build:** on the device at `-j 2`, 06:56:48 to 07:15:32Z, untimed. The
  binary's SHA-256 is
  `2f031c261928ef08287ff71eacb7b939cd0bfa21e86fd17695d72d88233c546a`.
- **Run:** started once the clock reported synchronised, 07:15:32 to
  17:51:26Z (10 h 36 min), as `ca3_pq_sign_timing slh-dsa 1222175` with no
  seed. Exit code 0.
- **Output:** `ca3_slh_dsa_msg_sign_timing_20261122_captures/floor_registered_attempt1.txt`.

```text
arch=aarch64 os=linux mode=slh-dsa samples_per_comparison=2000 calibration=200 crops=100 inputs=registered
pass-line=fixed-a-vs-fixed-b max_abs_t=1.40 median_ns=5273882407 raw_sd_ns=3165761 n0=1003 n1=997 verdict=no-evidence
null=fixed-a-vs-fixed-a max_abs_t=2.21 median_ns=5273936591 raw_sd_ns=3323716 n0=1002 n1=998 verdict=no-evidence
control=fixed-a-vs-fixed-a max_abs_t=22.89 median_ns=5275010240 raw_sd_ns=3396860 n0=1027 n1=973 verdict=control
control=planted-leak planted_ns=1222175 max_abs_t=22.89 verdict=detected
result=PASS fixed_pair=1.40 worst_null=2.21 control=22.89
```

**Read against the lines, in order.**

| Line | Registered | Observed | |
| --- | --- | --- | --- |
| 1 | a check fails: void | 2,200 signatures per comparison, every one returned and verified | holds |
| 2 | control `\|t\|` ≤ 10: void | 22.89 (raw 8.62; planted δ = 1.22 ms) | detected |
| 3 | the null's `\|t\|` ≥ 4.5: void | 2.21 | clean |
| 4–6 | the fixed pair's `\|t\|` | 1.40 | **pass** |

The run is not void, and the fixed pair is below 4.5: **PASS**. On the
floor device, a pass excludes a dependence of the message signature's time
on the key's value of δ = 1.22 ms (0.023 % of a signature) or more, and
nothing smaller.

**Noisier than its calibration.** The run's raw spread was 3.2 to 3.4 ms,
against the calibration's σ of 1.82 ms. The control was still detected,
because the cut-offs reach it at 22.89 where the raw figure was 8.62.
Recorded because the registration sized δ from σ, and the next device's
calibration should be read with this in mind.

**Conditions** (`floor_conditions_start.txt`, `floor_conditions_end.txt`):
- clock synchronised;
- 1.5 GHz throughout, 59 then 56 °C;
- throttled `0x0`, no under-voltage;
- load 1.58 at the start, just after the build, and 1.00 at the end;
- 11,666 frequency transitions over the run.

**Captures**, with `SHA256SUMS`:
- the attempt's output, its conditions, the clone's head and clean status,
  the build's times, log and `rustc -vV`, and the binary's SHA-256;
- `floor_build_log.txt`, named so because the repository ignores `*.log`.

The device's paths and login are written `<clone>`, `<home>` and `<agent>`.
The unredacted files, whose own SHA256SUMS verified after the copy, are in
the estate's private captures.

### The laptop

Not yet made: its noise calibration, then its run.
