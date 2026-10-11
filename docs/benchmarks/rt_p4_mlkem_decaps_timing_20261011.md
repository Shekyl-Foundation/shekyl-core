# `RT-P4`: is ML-KEM-768 decapsulation constant-time? Re-registration of 2026-10-11

**State of this record: REGISTERED, NOT YET RUN.** Everything under
"Registered before the run" is committed and pushed before the first run
that counts on any machine. Results are added below it and that section
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

*Amended twice on the maintainer's review, both times before any timed
run. First (`1ce9f13d0`): a limit on attempts after a void, and the floor
device's recorded conditions. Second (2026-10-11): the x86 machine is a
Windows laptop with two registered runs, one per core design; the shared
Linux dev box is dropped; the re-run limit is per registered run and needs
the cause fixed; and the closing rule names which runs close RT-P4. The
method, the comparisons, the thresholds, the control and the inputs are as
first pushed (`b1b9193c5`).*

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

**Runs.** Three registered runs: one on the floor device, and two on the
laptop, one pinned to a performance core and one to an efficiency core
(below). Each is one run and each has its own verdict. A fail or an
inconclusive is not re-run to get a different answer. A **void** run may
be made again, within these limits, fixed before anything runs:

- **At most two attempts per registered run.** If both are void, that run
  has no result; the next step goes to the maintainer.
- **The second attempt is made only after the cause of the first void is
  named and fixed.** On any machine "it was noisy" can always be said, so
  a second attempt has to remove the cause, not hope for less of it.
- **Every attempt is recorded, in order, whatever it shows**, with its full
  output.

**Inputs.** The registered runs draw their inputs from a seed that no run
had used when this was registered: not the first registration's, and not
any diagnostic's. All three draw the same inputs, so they are the same
question put to three cores. The harness prints `inputs=registered` when
it uses that seed.

**Machines**, by role and processor.

- **The floor device** (rule 76): a Raspberry Pi 4 (Cortex-A72), under a
  quiet claim in the estate's usage ledger, from a fresh clone of the
  pushed commit in a new directory. Recorded at the start and the end of
  the run, for the record and not as a line: the CPU governor (it was
  `ondemand` for the first record, which changes clock speed during a run;
  the classes are interleaved, so that cannot favour one, and the null
  comparisons would show it if it did), `vcgencmd get_throttled`, and the
  SoC temperature.

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

- **x86: a Windows laptop with a 14th-generation Intel Core i9 (Raptor
  Lake)**, a hybrid processor with two core designs. The exact processor
  and its core layout are enumerated from the machine before the run and
  recorded with the results. Two registered runs, each on **one logical
  processor**, with that core's hyperthread sibling, where it has one,
  left idle:

  - **the P-core run**, pinned to a logical processor of a performance
    core;
  - **the E-core run**, pinned to a logical processor of an efficiency
    core.

  Each is its own verdict, for that core design. The P-core run is made
  first.

  *Conditions.* A release build for the MSVC target, with `--locked`, from
  a fresh clone of the pushed commit. Mains power; best-performance mode;
  Defender real-time scanning paused; Windows Update and search indexing
  deferred; nothing else running. Recorded with each run: the value of
  `QueryPerformanceFrequency`; which logical processor was used and its
  core type; the CPU temperature and clock speed at the start and the end;
  and, since "idle" should be a recorded fact, how busy the sibling
  logical processor was over the run. Any of these conditions that cannot
  be set or read from the session that makes the run is recorded as not
  set or not read, with the reason, and is not passed over.

  Two things differ from the floor device and are stated so the results
  are read with them: the operating system, and the clock, which on
  Windows is read through `QueryPerformanceCounter`; at its usual 10 MHz
  one tick is 100 ns, a larger share of a decapsulation than the floor
  device's 18.5 ns tick is of its own. The statistic averages over a
  million samples and resolves below a tick; the control says whether it
  resolved enough.

*The shared Linux dev box is dropped.* It was the x86 machine of the first
record and of this registration as first pushed. It is too busy and too
noisy, and no registered run is made on it.

**What has already been seen, disclosed.**

- The diagnostic run D5 of the first record used this input preparation
  and these comparisons, on the floor device, with the first
  registration's seed, and came out under 4.5 throughout. This
  registration was written knowing that. What it has not seen is these
  inputs, or this method on x86 at full size.
- To check that the committed harness runs, it was run once on the shared
  Linux dev box at 20,000 samples with a seed given on the command line,
  which the harness labels `inputs=NOT-REGISTERED`. At that size the
  control was not detected, which means nothing at that size. There is no
  shake-down with the registered inputs on any machine.
- **A floor-device start that was stopped before it timed anything.** After
  the first amendment was pushed (`1ce9f13d0`) the floor device was cloned
  and its build started, at 2026-10-11 00:15Z. The second amendment
  arrived two minutes later. The session was stopped while still compiling
  dependencies: the harness binary did not yet exist, no decapsulation was
  timed, and no output file was created. That directory was removed, and
  the floor-device run is made from a fresh clone of the commit that
  carries this amendment. It is not counted as an attempt, because nothing
  ran.

**What is not measured, and is read instead.** Timing statistics cannot
show the absence of a branch. The aarch64 code was read for the first
record (comparison loop, rejection select, every conditional branch, the
NTT's division). The x86 code is read the same way, from the laptop's own
binary, and recorded with the results.

**What closes RT-P4.** A **pass on the floor device and on the laptop's
P-core run**, under these lines: RT-P4 is met, and `RPC_CHANNEL.md` §4.3's
"demonstrated by RT-P4" stands, with the reach above. The **E-core run is
recorded as coverage** of a second x86 core design and does not gate the
close. A **fail on any of the three runs is a finding for that core
design**, reported with its evidence, and sends `libcrux-ml-kem` and
RustCrypto `ml-kem` through this same harness, so that the choice of
implementation goes to the maintainer with those numbers.
