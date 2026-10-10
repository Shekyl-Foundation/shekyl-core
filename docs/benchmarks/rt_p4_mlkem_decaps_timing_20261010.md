# `RT-P4`: is ML-KEM-768 decapsulation constant-time? Runs of 2026-10-10

**State of this record: REGISTERED, NOT YET RUN.** Everything under
"Registered before the run" was committed and pushed before the first timed
run that counts. Results are added below it and that section is not edited
afterwards.

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
