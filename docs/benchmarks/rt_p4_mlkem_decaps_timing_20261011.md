# `RT-P4`: is ML-KEM-768 decapsulation constant-time? Re-registration of 2026-10-11

**State of this record: REGISTERED, NOT YET RUN.** Everything under
"Registered before the run" is committed and pushed before the first run
that counts on either machine. Results are added below it and that section
is not edited afterwards.

This replaces the method of
[`rt_p4_mlkem_decaps_timing_20261010.md`](rt_p4_mlkem_decaps_timing_20261010.md),
whose floor-device run failed its lines. That record stays as it is: the
failure, and the diagnosis that traced it to how the harness prepared its
inputs. A diagnosis is made after looking. This is the same question asked
again with the corrected method, its lines written first.

## The question

Unchanged. `RPC_CHANNEL.md` §4.3: before anything has authenticated, any
sender makes the daemon decapsulate an attacker-chosen ciphertext with its
long-term ML-KEM-768 key. If the time that takes depends on the ciphertext,
the difference is a remote oracle on that key. RT-P4 asks whether the
pinned crate, `fips203` 0.4.3, shows such a dependence, on the floor
device and on x86, including the implicit-rejection path.

## Registered before the run

*Amended once before any run, 2026-10-11, on the maintainer's review of the
registration as first pushed (`b1b9193c5`): the limit on attempts after a
void, the floor device's recorded conditions, and which machine is the x86
one. Nothing else changed.*

**Subject.** `fips203` 0.4.3, `ml_kem_768`, `try_decaps`, built in release
profile from this workspace's lock file. The harness is
`rust/shekyl-rpc-channel/examples/rt_p4_decaps_timing.rs` at the commit
that carries this registration.

**Method.** After `dudect`. Two classes of ciphertext are interleaved by a
coin and each decapsulation is timed. Welch's t compares the two timing
distributions, on the raw samples and on the samples below each of 100
cut-offs placed from a first batch of 10,000 that is then discarded. The
figure reported is the largest `|t|` over the raw comparison and every
cut-off that keeps more than 10,000 samples in each class.

**Input preparation — what changed.** Every ciphertext of a comparison is
generated before its loop, into one preallocated array, with the classes
interleaved by a coin drawn then. The loop reads entry `i`, times the
decapsulation call and nothing else, and stores the time. Which class an
entry belongs to is not looked at until the loop is over. Nothing is
encapsulated, chosen or copied by class inside the loop.

**Comparisons**, each over 1,000,000 timed decapsulations:

| Name | Class 0 | Class 1 | What a difference would mean |
|---|---|---|---|
| `fixed-vs-valid` | one fixed valid ciphertext | a fresh valid ciphertext | time depends on the ciphertext's content |
| `fixed-vs-invalid` | the fixed valid ciphertext | random bytes | time depends on validity |
| `fixed-vs-bitflip` | the fixed valid ciphertext | the same with one bit flipped | time depends on being nearly valid |
| `valid-vs-invalid` | a fresh valid ciphertext | random bytes | time depends on validity, with both classes equally varied |

**Null comparisons — new.** Two more, each a kind of ciphertext against
itself: `invalid-vs-invalid` and `valid-vs-valid`. There is nothing in
them to find. Whatever they report is the harness or the machine.

**The control, and what it bounds.** Unchanged in size. The same loop is
run with extra work inside the timed region for one class of a
`fixed-vs-invalid` comparison, calibrated at run time to **0.5 %** of one
decapsulation's median time. **A pass excludes a leak of 0.5 % of a
decapsulation or more, and nothing smaller**; that figure is quoted with
any verdict. What the run could resolve below that, estimated from how far
over its line the control lands, is reported with the results as an
estimate and is not part of the verdict.

**Lines, read in this order.** The thresholds are the first registration's
and `dudect`'s: 4.5 and 10.

1. **The control is not detected** (`|t|` ≤ 10): the run is **void**. A
   harness that cannot see a planted leak has said nothing by seeing none.
2. **A null comparison reports `|t|` ≥ 4.5:** the run is **void**. A
   harness that sees a difference where there is none has said nothing by
   seeing one elsewhere.
3. **Any of the four comparisons reports `|t|` > 10:** **fail**.
4. **Any of the four is between 4.5 and 10:** **inconclusive**, not a pass.
5. **All four are below 4.5:** **pass**.

Each comparison is read on its own figure. In particular
`valid-vs-invalid` and `fixed-vs-bitflip`, the two an attacker's choice of
ciphertext corresponds to, are not cleared by any other comparison's
result.

**Runs.** One run per machine. A fail or an inconclusive is not re-run to
get a different answer. A **void** run may be made again, within these
limits, fixed before anything runs:

- **At most two attempts per machine.** If both are void, that machine has
  no result and RT-P4 is not met there; the next step goes to the
  maintainer.
- **The second attempt runs under a quiet claim** on that machine, filed in
  the estate's usage ledger before it starts. On a shared machine "it was
  noisy" can always be said, so a second attempt has to remove the noise,
  not hope for less of it. (Both machines are claimed quiet from the first
  attempt here.)
- **Every attempt is recorded, in order, whatever it shows**, with its full
  output.

**Inputs.** The registered run draws its inputs from a seed that no run
has used: not the first registration's, and not any diagnostic's. The
harness prints `inputs=registered` when it uses it.

**Machines.**

- **The floor device** (rule 76): the Pi 4, under a quiet claim in the
  estate's usage ledger, from a fresh clone of the pushed commit in a new
  directory. Its conditions are recorded at the start and the end of the
  run, for the record and not as a line: the CPU governor (it was
  `ondemand` for the first record, which changes clock speed during a run;
  the classes are interleaved, so that cannot favour one, and the null
  comparisons would show it if it did); the SoC temperature; and the
  firmware's throttle flags.

  *The throttle flags, as far as this lane can read them.*
  `vcgencmd get_throttled` needs root on this device (`/dev/vcio` is
  root-only and the lane's account has no passwordless `sudo`). The command
  is attempted at the start and the end and its output recorded as it
  comes. Beside it, three things the account can read are recorded at both
  ends: the kernel's under-voltage alarm (`rpi_volt`,
  `in0_lcrit_alarm`), the time the core has spent at each clock speed
  (`cpufreq/stats/time_in_state`), and the count of clock-speed changes
  (`total_trans`). The last two say directly whether and how much the
  clock moved during the run, which is what the flags would be read for.
- **x86:** the Windows dev box, a native Windows build, run there by the
  remote agent on that machine. *Changed before any run, on the
  maintainer's direction (2026-10-11):* the Linux dev box, named here when
  this registration was first pushed, is too busy and too noisy to be the
  x86 machine. The run is from a fresh clone of the pushed commit, built
  with `--locked` in release profile. Recorded at the start and the end:
  the processor, the power plan, the CPU load, and what else of weight is
  running. Two things differ from the floor device and are stated so the
  result is read with them: the operating system, and the clock, which on
  Windows ticks every 100 ns, about 0.15 % of a decapsulation there. The
  statistic averages over a million samples and resolves below a tick; the
  control says whether it resolved enough. With null comparisons in the
  lines, a machine too disturbed to compare a class with itself voids its
  own run instead of passing by default.

**What has already been seen, disclosed.**

- The diagnostic run D5 of the first record used this input preparation
  and these comparisons, on the floor device, with the first
  registration's seed, and came out under 4.5 throughout. This
  registration was written knowing that. What it has not seen is these
  inputs, or this method on x86 at full size.
- To check that the committed harness runs, it was run once on the Linux dev box
  at 20,000 samples with a seed given on the command line, which the
  harness labels `inputs=NOT-REGISTERED`. At that size the control was not
  detected, which means nothing at that size. There is no shake-down with
  the registered inputs on either machine.

**What is not measured, and is read instead.** Timing statistics cannot
show the absence of a branch. The aarch64 code was read for the first
record (comparison loop, rejection select, every conditional branch, the
NTT's division). The x86 code is read the same way and recorded with the
results.

**What closes RT-P4.** A **pass on both machines** under these lines:
RT-P4 is met, and `RPC_CHANNEL.md` §4.3's "demonstrated by RT-P4" stands,
with the reach above. **Anything else** is reported as it is. If a
dependence survives, `libcrux-ml-kem` and RustCrypto `ml-kem` are measured
on this same harness and the choice of implementation goes to the
maintainer with those numbers.
