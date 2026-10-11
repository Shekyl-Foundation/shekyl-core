# `RT-P4`: is ML-KEM-768 decapsulation constant-time? Re-registration, runs of 2026-10-11

**State of this record: both registered runs are in and both PASS.** By
the closing rule registered below, RT-P4 is met for the two core designs
measured, Cortex-A72 and Tiger Lake, with the reach the control gives: no
dependence on the ciphertext of 0.5 % of a decapsulation or more. No
efficiency-core design has been measured. The reading of the laptop's x86
code, which the registration also asks for, is at the end.
The registration was first pushed on 2026-10-10 at 23:46Z and amended
three times before any result was read, as its own note says. Results are
added below "Registered before the run" and that section is not edited
afterwards.

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

*Amended three times, each before any result was read. First (`1ce9f13d0`): a limit on attempts after a void, and the floor
device's recorded conditions. Second (2026-10-11): the x86 machine is a
Windows laptop with two registered runs, one per core design; the shared
Linux dev box is dropped; the re-run limit is per registered run and needs
the cause fixed; and the closing rule names which runs close RT-P4.
Third (2026-10-11, before any build on the laptop and while the
floor-device run was under way, none of its output read): the laptop's
processor is corrected from the machine's own enumeration, it has one core
design and so one run, and its conditions are stated as that machine can
meet them. The method, the comparisons, the thresholds, the control and
the inputs are as first pushed (`b1b9193c5`).*

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

**Runs.** Two registered runs: one on the floor device, and one on the
laptop, pinned to one logical processor (below). Each is one run and each
has its own verdict. A fail or an
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
any diagnostic's. Both draw the same inputs, so they are the same
question put to two processors. The harness prints `inputs=registered` when
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

- **x86: a Windows laptop with an 11th-generation Intel Core i9
  (i9-11950H, Tiger Lake-H).** Enumerated from the machine before any
  build there: one socket, eight physical cores, sixteen logical
  processors; every core is the same design (one efficiency class) and
  every core has two hyperthreads, logical processors `2n` and `2n+1`.
  **One registered run, pinned to one logical processor, with its
  hyperthread sibling left idle.**

  *How this amendment reached the record.* The maintainer was at that
  machine and gave these rulings there: that this is the machine, and that
  Defender stays on. They came to this lane relayed by the agent on that
  machine, not directly, and are recorded as relayed.

  *This is not what the second amendment registered, and the difference is
  stated.* That amendment named a 14th-generation hybrid processor and two
  runs, one per core design. The processor was named from memory; the
  machine, asked, is the one above, and it has one core design. There is no
  efficiency core to pin to, so the E-core run does not exist and is not
  replaced by anything.

  *Conditions, as they can and cannot be met on this machine.* A release
  build for the MSVC target, with `--locked`, from a fresh clone of the
  pushed commit, on a drive that holds no synced folder. Mains power. The
  session that makes the run is not elevated, and the rest follows from
  that and from the machine:

  | Condition registered in the second amendment | On this machine |
  |---|---|
  | Best-performance mode | recorded as found at the start; the session cannot change it. If the maintainer sets it before the run, that is what is recorded |
  | Defender real-time scanning paused | **left on, as found.** The maintainer's ruling: most Windows machines run with it on, so a result measured with it on is the one an operator sees. (It also could not have been paused: with Tamper Protection on, the command to disable it is accepted silently and does nothing, which was found by reading the state back.) The maintainer reports having excluded the run's directory and binary from scanning; the session cannot read the exclusion list, so that is recorded as reported, not verified. A daily scan is scheduled for 02:00 local time, and the run is started well clear of it |
  | Update and indexing deferred | cannot be stopped from this session. Recorded as found, with each service's CPU time over the run |
  | Nothing else running | the session starts nothing else. What else is running, and its CPU time over the run, is recorded; closing the file-sync clients and the editor is the maintainer's to do |
  | CPU temperature at start and end | **not readable** on this machine. Recorded as not measurable |
  | CPU clock at start and end | the nominal figure does not move; the live reading is the processor-performance counter (a percentage of base clock), recorded at the start and the end and sampled through the run |

  Also recorded: the value of `QueryPerformanceFrequency` (10,000,000 when
  enumerated); which logical processor was used; and how busy its sibling
  was over the run, since "idle" should be a recorded fact.

  None of these conditions is a line. They are what a void or a marginal
  figure would be read against, and the null comparisons are what says
  whether the machine was quiet enough: a machine too disturbed to compare
  a class with itself voids its own run.

  Two things differ from the floor device and are stated so the results
  are read with them: the operating system, and the clock. Each
  decapsulation is timed on its own, and on this machine one clock tick is
  100 ns, so the per-class percentiles the harness prints move in 100 ns
  steps and cannot show a difference smaller than that. The t statistic
  averages over a million samples and resolves below a tick; the control
  says whether it resolved enough.

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
run**, under these lines: RT-P4 is met, and `RPC_CHANNEL.md` §4.3's
"demonstrated by RT-P4" stands, with the reach above, for the two core
designs measured: Cortex-A72 and Tiger Lake. No efficiency-core design has
been measured, and the record says so wherever the result is quoted. A
**fail on either run is a finding for that core design**, reported with
its evidence, and sends `libcrux-ml-kem` and
RustCrypto `ml-kem` through this same harness, so that the choice of
implementation goes to the maintainer with those numbers.

## Results

### The floor device — PASS

One attempt, 2026-10-11 00:22:41Z to 01:01:40Z, on the Raspberry Pi 4
(Cortex-A72, kernel 7.0.0-1020-raspi), under a quiet claim, from a fresh
clone in a new directory. `rustc` 1.94.0, release profile, `--locked`;
binary sha256 `735105f4…`. The full output is
`rt_p4_mlkem_decaps_timing_20261011_captures/floor_registered_attempt1.txt`,
its checksum taken on the device and matched after copying.

```text
RT-P4 ML-KEM-768 decapsulation timing (fips203), inputs prepared before the loop
arch=aarch64 os=linux samples_per_comparison=1000000 calibration=10000 crops=100 inputs=registered
pass: |t| < 4.5 on every real comparison; null comparisons: |t| < 4.5; control: |t| > 10
comparison=fixed-vs-valid max_abs_t=1.33 median_ns=263221 n0=499545 n1=500455 verdict=no-evidence
comparison=fixed-vs-invalid max_abs_t=1.89 median_ns=263536 n0=499434 n1=500566 verdict=no-evidence
comparison=fixed-vs-bitflip max_abs_t=3.00 median_ns=262574 n0=498225 n1=501775 verdict=no-evidence
comparison=valid-vs-invalid max_abs_t=1.65 median_ns=262518 n0=500011 n1=499989 verdict=no-evidence
null=invalid-vs-invalid max_abs_t=2.27 median_ns=262499 n0=500041 n1=499959 verdict=no-evidence
null=valid-vs-valid max_abs_t=3.63 median_ns=262388 n0=499595 n1=500405 verdict=no-evidence
control=planted-leak fraction=0.005 planted_ns=1312 max_abs_t=1520.00 verdict=detected
result=PASS worst_real_abs_t=3.00 worst_null_abs_t=3.63 control_abs_t=1520.00
```

Read in the registered order:

| Line | Registered | Observed | |
|---|---|---|---|
| 1. the control | `|t|` > 10 | 1,520.00 | detected; not void |
| 2. the null comparisons | `|t|` < 4.5 | 2.27, 3.63 | not void |
| 3–5. the four comparisons | all `|t|` < 4.5 | 1.33, 1.89, 3.00, 1.65 | **pass** |

**The two comparisons an attacker's choice corresponds to, each on its
own figure.** `valid-vs-invalid`: 1.65, at a cut-off where the class means
differ by 0.8 ns. `fixed-vs-bitflip`: 3.00, at a cut-off where they differ
by 1.1 ns. The larger of the two is smaller than what one of the null
comparisons reported with nothing to find (3.63).

**What this says, with its reach.** On the floor device, the time
`fips203` 0.4.3 takes to decapsulate does not depend on the ciphertext by
0.5 % of a decapsulation (1,312 ns here) or more. That is the registered
claim and it is all the verdict says.

*An estimate beside it, not part of the verdict.* The control landed 338
times over the 4.5 line. If the statistic grows in proportion to a shift
of the whole distribution, the line corresponds to about 4 ns, 0.0015 % of
a decapsulation. The null comparison at 3.63 is a reminder of how close to
the line nothing at all can come at this sensitivity.

**Conditions, recorded as registered.**

| | Start | End |
|---|---|---|
| Governor | `ondemand` | `ondemand` |
| SoC temperature | 59.9 °C | 58.4 °C |
| Load, 1 min | 3.93 (the build had just finished) | 1.00 |
| `vcgencmd get_throttled` | refused: needs root | refused: needs root |
| Under-voltage alarm | 0 | 0 |
| Clock-speed changes, total | 5,029,725 | 5,029,846 |

Of the 39 minutes of the run, the core's time-at-speed counters put all
but about 0.3 seconds at the top speed, 1.8 GHz, and count 121 changes of
speed. The clock did not wander. The firmware's throttle flags were not
read; the under-voltage alarm, which is one of the things those flags
report, stayed clear.

**Disclosed.** The run was made from `ba4677446`, the commit that carried
the registration when it started. The registration was amended once more
after that (`7b7046579`), for the laptop alone; the two commits differ in
this file and nowhere else, so the harness the laptop builds is the one
this run used. That amendment was pushed before this run's output was
read: the file was copied off the device with its checksum and not opened
until then.

### The laptop — PASS

One attempt, 2026-10-11 01:41:14Z to 01:50:15Z, on the Windows laptop
(Intel Core i9-11950H, family 6 model 141; Windows 11 Enterprise build
22631), made by the agent on that machine from a fresh clone of
`7b7046579` on a drive holding no synced folder. `rustc` 1.94.0,
`x86_64-pc-windows-msvc`, release profile, `--locked`; binary sha256
`1077f646…`. The binary was not executed before this run. Its output is
`rt_p4_mlkem_decaps_timing_20261011_captures/laptop_registered_attempt1.txt`,
as relayed by that agent; the relayed text is 4,959 bytes, the size the
agent reports for the file on the machine.

```text
RT-P4 ML-KEM-768 decapsulation timing (fips203), inputs prepared before the loop
arch=x86_64 os=windows samples_per_comparison=1000000 calibration=10000 crops=100 inputs=registered
pass: |t| < 4.5 on every real comparison; null comparisons: |t| < 4.5; control: |t| > 10
comparison=fixed-vs-valid max_abs_t=1.15 median_ns=63200 n0=499545 n1=500455 verdict=no-evidence
comparison=fixed-vs-invalid max_abs_t=2.46 median_ns=65000 n0=499434 n1=500566 verdict=no-evidence
comparison=fixed-vs-bitflip max_abs_t=3.00 median_ns=63800 n0=498225 n1=501775 verdict=no-evidence
comparison=valid-vs-invalid max_abs_t=2.29 median_ns=61300 n0=500011 n1=499989 verdict=no-evidence
null=invalid-vs-invalid max_abs_t=1.50 median_ns=64200 n0=500041 n1=499959 verdict=no-evidence
null=valid-vs-valid max_abs_t=1.71 median_ns=60800 n0=499595 n1=500405 verdict=no-evidence
control=planted-leak fraction=0.005 planted_ns=304 max_abs_t=182.88 verdict=detected
result=PASS worst_real_abs_t=3.00 worst_null_abs_t=1.71 control_abs_t=182.88
```

The class counts are the floor device's to the sample: the two machines
were asked about the same ciphertexts.

Read in the registered order:

| Line | Registered | Observed | |
|---|---|---|---|
| 1. the control | `|t|` > 10 | 182.88 | detected; not void |
| 2. the null comparisons | `|t|` < 4.5 | 1.50, 1.71 | not void |
| 3–5. the four comparisons | all `|t|` < 4.5 | 1.15, 2.46, 3.00, 2.29 | **pass** |

**The two comparisons an attacker's choice corresponds to, each on its
own figure.** `valid-vs-invalid`: 2.29, at a cut-off where the class means
differ by 1.4 ns. `fixed-vs-bitflip`: 3.00, at a cut-off where they differ
by 2.4 ns.

**What this says, with its reach.** On this processor, with this build,
the time `fips203` 0.4.3 takes to decapsulate does not depend on the
ciphertext by 0.5 % of a decapsulation (304 ns here) or more.

*An estimate beside it, not part of the verdict.* The control landed 41
times over the 4.5 line, against 338 times on the floor device. By the
same proportion the line corresponds to about 7.5 ns here, 0.012 % of a
decapsulation: this run saw about an eighth as finely as the floor
device's, relative to the work measured. The clock is why the per-class
percentiles are nearly all equal: they move in 100 ns steps, as
registered. The means the statistic is computed from differ by a few
nanoseconds or less at the cut-offs where it peaks.

**The exit code was not captured.** The agent started the process in a
way that lost the handle before the code could be read, and did not run
again to get it, which a second run would not have been allowed to
supply. The verdict above is read from the printed statistics. The
harness has one exit path, which returns 0 exactly when it prints `PASS`;
that is a reading of the source, not an observation of this run.

**Conditions, recorded as registered.**

| | Start (01:40Z) | End (01:50Z) |
|---|---|---|
| Logical processor | 4, pinned from the first instruction (`start /affinity 10`); affinity read back from the running process as `0x10`; normal priority | |
| Its sibling, logical 5 | idle: 0 % in six of eight one-minute samples, at most 1.03 % | |
| Logical 4 | 100 % in every sample of the run | |
| `QueryPerformanceFrequency` | 10,000,000 | 10,000,000 |
| Power | mains, 91 %; plan Balanced, no overlay | same |
| Processor performance, % of the 2,611 MHz base | 164 to 174 through the run, no downward drift (73 before, 110 after) | |
| CPU temperature | not measurable | not measurable |
| Defender | real-time protection on, Tamper Protection on | same; no scan started in the window |
| Total CPU load | 5.3 % | 5.4 % |

CPU time used over the run by the things that could have disturbed it:
Defender 4.67 s; the search indexer 0.01 s; Nextcloud 0.06 s; Google
Drive, OneDrive and rust-analyzer none; the editor, idle, 10.5 s across
its nineteen processes. The maintainer's exclusion of the run's directory
from scanning is as reported; the session could not read the exclusion
list. Best-performance mode was not set: the plan was Balanced, as found.

One thing about how these were read, kept because it nearly falsified
them: an unelevated process query returns zero CPU time for the system's
own services, which reads as "Defender used nothing". The figures above
for Defender and the indexer come from the performance counters, which
can read them, and agree with the process query wherever both can.

**Disclosed.** The rulings that shaped this run's registration reached
this lane relayed, as the registration says. So did this run's output and
conditions: they are the agent's report from that machine, not files this
lane copied.

### The x86 code, read

From `dumpbin /disasm` of the laptop's own binary (listing sha256
`95ad5e80…`, 51,637 lines), made after the run. The excerpts were pulled
and sent by the agent on that machine with the script that counted them;
the passages the reading quotes or rests on are kept in
`rt_p4_mlkem_decaps_timing_20261011_captures/laptop_x86_disasm_excerpts.txt`,
and the full listing stayed on the machine. The reading below is this
lane's, and where it rests on the crate's source and not on the listing it
says so. It is the counterpart of the aarch64
reading in the first record, and it finds the same things.

- **Ciphertext comparison** (inline in `ml_kem_decaps_internal`): a loop of
  exactly 1,088 iterations (`cmp r14, 440h`). Each compares one byte,
  materialises the result with `sete`, passes it through
  `subtle::black_box` and `and`s it into an accumulator. Its only
  conditional jump is on the counter. There is no early exit.
- **Implicit-rejection select:** the 0-or-1 choice is negated to a byte
  mask, broadcast, and applied to the 32-byte key with two rounds of
  `pand` / `pandn` / `por`. Both inputs are always read and both halves
  always written. Its one conditional jump, `jo` after the `neg`, is the
  overflow guard and fires only for `0x80`, which the choice cannot be.
- **The other six conditional jumps in the decapsulation function:** four
  bounds checks against constant lengths, and the two tests of whether
  decrypt and re-encrypt returned an error. None reads ciphertext content.
- **Every conditional jump in decrypt and in both re-encrypt bodies** (177
  of them) was listed with its target and the two instructions before it.
  The backward jumps are loop ends on a counter against a constant. The
  forward jumps are bounds and length checks against constants, guards
  into the shift-overflow panic, and tests of the decoder's result. All
  targets are direct; there are no indirect or table-driven branches.
- **Branches on values, which exist and do not vary with the ciphertext.**
  The decoder's range check leaves its loop at the first coefficient that
  is out of range, so in form its running time depends on a value. Where
  it can fire is a question about its callers, and is read from the
  source: every decoded value is masked to `d` bits first, and for `d`
  below 12 the bound is 2^d, so the check cannot fail. On this path the
  ciphertext is decoded with `d` = 10 and 4 and the recovered message with
  `d` = 1. The listing agrees and goes further: the `d` = 10 and `d` = 4
  decodes carry no range check at all, the compiler having removed it; the
  `d` = 1 check is present, comparing against 2, and cannot be taken. The
  checks against 3,329 (`0D01h`) are the `d` = 12 decodes, of key
  material: two call sites in the source, each over the key's three
  polynomials, which is why the check appears several times in each
  function. Key material is the same for every ciphertext, and in range
  for any key the crate generated.
- **Division:** two in the ML-KEM code, one in each of the forward and
  inverse NTT, as on aarch64. Each divides the constant 256 by twice an
  entry of a seven-entry table of constants written to the stack as
  immediates and indexed by the outer loop's counter. Nothing derived from
  the ciphertext or the key reaches either operand. (One more division
  exists in the binary, in the standard library's sort, which the harness
  uses for its percentiles after the timed loop.)
- **Counts**, for the 30 functions of `fips203`, `subtle` and Keccak: 8,480
  instructions, 325 conditional jumps, 78 conditional moves or sets, 2
  integer divisions, no floating-point division.

What a reading of this kind does not give: a proof that no instruction's
latency depends on its operands on this processor. The timing run above is
the evidence for that, to its stated reach.

## Where RT-P4 stands

By the closing rule registered above: **a pass on the floor device and a
pass on the laptop. RT-P4 is met**, for `fips203` 0.4.3's ML-KEM-768
decapsulation as built by this workspace, on a Cortex-A72 and on a Tiger
Lake core, to this reach: no dependence of decapsulation time on the
ciphertext of 0.5 % of a decapsulation or more. Estimated from each run's
control, and not part of either verdict, the runs would have shown about
4 ns on the floor device and about 7.5 ns on the laptop.

What it does not cover, so that nobody reads more into it:

- **No efficiency-core design was measured.** A hybrid x86 processor's
  second core design is a different machine for this question.
- **Two builds, two processors.** A different compiler version, target or
  optimisation setting produces different code; the code reading above is
  of these two binaries.
- **Time only.** Nothing here measures power, emanations or cache
  side-effects observable by code sharing the machine.
- **The first registration's floor-device failure stands in its own
  record**, with the diagnosis that it was the harness.
