# `RT-P4`: is ML-KEM-768 decapsulation constant-time? Runs of 2026-10-10

**State of this record: the x86 run PASSES; the floor-device run FAILS its
registered lines.** RT-P4 is therefore **not met**. What the failure is a
failure of — the crate or the harness — is not yet established; see "The
floor device" below.
Everything under "Registered before the run" was committed and pushed
(`cd65ab8af1`) before the first timed run that counts. Results are added
below it and that section is not edited afterwards.

## The question

`RPC_CHANNEL.md` §4.3: before anything has authenticated, any sender makes
the daemon decapsulate an attacker-chosen ciphertext with its **long-term**
ML-KEM-768 key. If the time that takes depends on the ciphertext, the
difference is a remote oracle on that key (KyberSlash was this class of
defect, in implementations). RT-P4 asks whether the pinned crate,
`fips203` 0.4.3, shows such a dependence, on the floor device and on x86,
including the implicit-rejection path.

## Registered before the run

**Subject.** `fips203` 0.4.3, `ml_kem_768`, `try_decaps`, built in release
profile from this workspace's lock file. The harness is
`rust/shekyl-rpc-channel/examples/rt_p4_decaps_timing.rs`.

**Method.** After `dudect`. Two classes of ciphertext are interleaved by a
coin and each decapsulation is timed. Welch's t compares the two timing
distributions, on the raw samples and on the samples below each of 100
cut-offs placed from a first batch of 10,000 that is then discarded. The
figure reported is the largest `|t|` over the raw comparison and every
cut-off that keeps more than 10,000 samples in each class.

**Comparisons**, each over 1,000,000 timed decapsulations:

| Name | Class 0 | Class 1 | What a difference would mean |
|---|---|---|---|
| `fixed-vs-valid` | one fixed valid ciphertext | a fresh valid ciphertext | time depends on the ciphertext's content |
| `fixed-vs-invalid` | the fixed valid ciphertext | random bytes | time depends on validity |
| `fixed-vs-bitflip` | the fixed valid ciphertext | the same with one bit flipped | time depends on being nearly valid |
| `valid-vs-invalid` | a fresh valid ciphertext | random bytes | time depends on validity, with both classes equally varied |

**Pass lines.**

- **(a)** Every comparison reports `|t|` below **4.5**. That is `dudect`'s
  bound for "no evidence of a leak".
- **(b)** The control (below) reports `|t|` above **10**.
- A comparison between 4.5 and 10 is **inconclusive**, not a pass. A
  comparison above 10 is a **fail**.
- If the control is not detected the whole run is **void**: a harness that
  cannot see a planted leak has said nothing by seeing none.

**The control, and what it bounds.** The same harness is run on a wrapper
that, after a `fixed-vs-invalid` decapsulation, spends extra time on the
rejected class only. The extra is calibrated at run time to **0.5 %** of one
decapsulation's median time. Detecting it shows the harness can see a
ciphertext-dependent difference of that size on that machine in that run.
**A pass therefore excludes a leak of 0.5 % of a decapsulation or more, and
nothing smaller.** That figure is the reach of this probe and is to be
quoted with any verdict.

**Machines.**

- **x86:** the dev box. It is a shared machine and is **not quiet**; other
  sessions build and test on it. Noise widens both distributions and lowers
  sensitivity; it does not by itself create a difference between two
  interleaved classes. The control says whether enough sensitivity was left.
- **The floor device** (rule 76): the Pi 4, under a quiet claim in the
  estate's usage ledger for the length of the run.

**What is not measured, and is read instead.** Timing statistics cannot
show the absence of a branch. The decapsulation path is read at source for
secret-dependent branches and divisions, and the reading is recorded with
the results.

**Changes to the harness before registration, disclosed.** A 30,000-sample
shake-down on the dev box, while it was running twelve model-checker
processes, was used to confirm the harness runs. It showed one thing that
was fixed before this registration: the harness built only the ciphertext
its class needed, so each class did different work immediately before the
timed region — an encapsulation for one, a copy for another — and so
entered it with different cache and predictor state. Every candidate is now
built for every sample and the class only selects one. No threshold, sample
count or comparison was chosen from that shake-down's figures; they are
`dudect`'s bounds and were written in the harness before it was first run.

## Results

### x86, the dev box — PASS

Run once, 2026-10-10 05:56:15Z to 06:16:11Z, at `1c32a8c5a9` (the
registration commit merged with `dev`; the harness and the lock file's
`fips203` entry are unchanged by the merge). `rustc` 1.94.0, release
profile, `--locked`. Intel Core i9-11950H, 16 logical cores. This is the
first and only run at the registered sample count; nothing was re-run.

```text
RT-P4 ML-KEM-768 decapsulation timing (fips203)
arch=x86_64 os=linux samples_per_comparison=1000000 calibration=10000 crops=100
pass: |t| < 4.5 on every real comparison; control: |t| > 10
comparison=fixed-vs-valid max_abs_t=2.66 median_ns=64133 n0=499521 n1=500479 verdict=no-evidence
comparison=fixed-vs-invalid max_abs_t=2.00 median_ns=134313 n0=500483 n1=499517 verdict=no-evidence
comparison=fixed-vs-bitflip max_abs_t=1.84 median_ns=132877 n0=500478 n1=499522 verdict=no-evidence
comparison=valid-vs-invalid max_abs_t=1.76 median_ns=132371 n0=499020 n1=500980 verdict=no-evidence
control=planted-leak fraction=0.005 planted_ns=662 max_abs_t=102.35 verdict=detected
result=PASS worst_real_abs_t=2.66 control_abs_t=102.35
```

| Line | Registered | Observed | |
|---|---|---|---|
| (a) every comparison | `\|t\|` < 4.5 | worst 2.66 | met |
| (b) the control | `\|t\|` > 10 | 102.35 | met |

**What this says, with its reach.** On this machine, in this run, the time
`fips203` 0.4.3 takes to decapsulate does not depend on the ciphertext by
0.5 % of a decapsulation (662 ns here) or more. It says nothing about a
smaller dependence.

**Conditions, as they were.** The box was loaded throughout by other
sessions' builds and tests and by one model-checker process: the one-minute
load average was 4.3 at the start and 14.6 at the end. The median
decapsulation was 64 µs in the first comparison and about 133 µs in the
other three and in the control. The step was not investigated; it is what a
core shared with another busy thread would look like, and that is a guess.
The control was calibrated and run under the later, slower condition and
was still detected by a wide margin, so the sensitivity line was met where
it was hardest to meet.

### The floor device — FAIL

Run once, 2026-10-10 19:34:26Z to 20:15:16Z, on the Pi 4 (Model B rev 1.4,
kernel 7.0.0-1020-raspi, governor `ondemand`), under a quiet claim in the
estate's usage ledger. A fresh checkout of the pushed commit `67faff8290`,
`rustc` 1.94.0, release profile, `--locked`; binary sha256 `76aa66d0…`.
The device's resident testnet daemon was running throughout, as it always
is, at about 1 % of one core; nothing else was. SoC temperature 55.5 °C at
the start and 57.5 °C at the end.

```text
RT-P4 ML-KEM-768 decapsulation timing (fips203)
arch=aarch64 os=linux samples_per_comparison=1000000 calibration=10000 crops=100
pass: |t| < 4.5 on every real comparison; control: |t| > 10
comparison=fixed-vs-valid max_abs_t=502.54 median_ns=267888 n0=499521 n1=500479 verdict=LEAK
comparison=fixed-vs-invalid max_abs_t=12.16 median_ns=267480 n0=500483 n1=499517 verdict=LEAK
comparison=fixed-vs-bitflip max_abs_t=19.73 median_ns=267592 n0=500478 n1=499522 verdict=LEAK
comparison=valid-vs-invalid max_abs_t=463.66 median_ns=267684 n0=499020 n1=500980 verdict=LEAK
control=planted-leak fraction=0.005 planted_ns=1338 max_abs_t=952.25 verdict=detected
result=FAIL worst_real_abs_t=502.54 control_abs_t=952.25
```

| Line | Registered | Observed | |
|---|---|---|---|
| (a) every comparison | `|t|` < 4.5 | 502.54, 12.16, 19.73, 463.66 | **not met**, all four above 10 |
| (b) the control | `|t|` > 10 | 952.25 | met |

**This is the registered run and it is a fail.** It is not re-run to get a
different answer and the lines are not moved.

**What the figures do and do not say.** The harness draws the same inputs
on both machines (the class counts are identical to the x86 run's), so the
x86 run passed on the very ciphertexts this one failed on. The two
comparisons that involve a *freshly encapsulated* ciphertext stand apart
(502, 464); the two that do not are far smaller (12, 20), though still over
the line. A fixed valid ciphertext and a fresh valid one take the same path
through decapsulation, so validity is not what separates them. In this
harness a fresh valid ciphertext is one this same thread encapsulated
immediately before the timed region. Whether the difference belongs to the
decapsulation or to what that encapsulation leaves behind in the core is
the open question, and nothing in this section answers it.

**Shake-down, disclosed.** Before the registered run the same binary was
run at 30,000 samples to confirm it works on the device. It reported no
comparison above 3.22 and a detected control (142.54). No threshold, count
or comparison was changed after it. At that size few of the cut-offs keep
the 10,000 samples per class the harness requires, so it could not have
seen what the full run saw.

### The source, read

`fips203` 0.4.3 as vendored by the lock file (checksum `c8bdb645…`), the
files on the decapsulation path: `ml_kem.rs`, `k_pke.rs`, `helpers.rs`,
`types.rs`, `ntt.rs`, `byte_fns.rs`, `sampling.rs`. Every `if`, `match`,
`while`, early `return`, `/` and `%` in them was looked at. A reading of
source says what the author wrote, not what the compiler emitted; the
timing run above is the only evidence here about the built binary.

- **Implicit rejection is a constant-time select.** The re-encrypted
  ciphertext is compared with `ct_ne` and the rejection key is moved in with
  `conditional_assign` (`ml_kem.rs:132`); both shared secrets are always
  computed. There is no branch on validity.
- **No division by `q` on a secret.** `Compress` — where KyberSlash was —
  multiplies by a precomputed reciprocal and shifts (`helpers.rs:214-220`).
  Field multiplication reduces the same way and addition and subtraction
  correct with a mask, not a branch (`types.rs:40-106`). The `/` and `%`
  that remain compute compile-time constants and the constant zeta table.
- **Loops are bounded by bit counts**, not by values.
- **Two things that are data-dependent, and why neither is an oracle on
  this path.** `byte_decode` ends with a range check that stops at the first
  out-of-range value (`byte_fns.rs:108-109`): for the ciphertext's 10- and
  4-bit fields no value can be out of range, and for the 12-bit decode of
  the secret key it depends on the key alone and never fires for a key the
  crate generated. Matrix sampling rejects (`sampling.rs:39`, `:51`), on the
  public seed, the same for every ciphertext.
