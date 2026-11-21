# Crypto audit — advisories and audit findings against the cryptographic stack

**Status:** OPEN — register opened 2026-10-24 (family `CA-`, registered at
birth in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2). `CA-1` is
ignored in `cargo audit` by ruling (Rick, 2026-10-24); its long-term fix is
not yet designed. `CA-2` opened 2026-10-24 from CA-1's dynamic measurement:
operand-dependent timing in the vendored `HelioseleneField` on x86_64,
mechanism open (§2). `CA-3` opened 2026-11-21 by Rick's ruling: no
constant-time evidence covers any of Shekyl's post-quantum signing (§3).

One row per advisory or audit finding that touches a cryptographic
dependency or primitive and cannot be closed by a routine lockfile bump. A
row records what is affected, where secrets meet it, why it is not fixed
now, and what reopens it. A finding a bump clears does not get a row; the
bump's commit is its record.

## Register

| Id | Finding | Status |
| --- | --- | --- |
| `CA-1` | `crypto-bigint` 0.5.5, RUSTSEC-2026-0387 (timing variability) | **IGNORED BY RULING 2026-10-24** — fix undesigned (§1) |
| `CA-2` | Operand-dependent timing in the vendored `HelioseleneField` on x86_64, outside BINSEC's model | **OPEN 2026-10-24** — mechanism open (§2) |
| `CA-3` | No constant-time evidence for post-quantum signing: FN-DSA (receipt countersignature), ML-DSA-65 (transactions), SLH-DSA-192s (messages) | **OPEN 2026-11-21** — unmeasured (§3) |

## 1. `CA-1` — crypto-bigint 0.5.5, RUSTSEC-2026-0387

**Advisory.** Published 2026-10-23, category `crypto-failure`. Operations
meant to be constant-time could execute secret-dependent branches,
depending on compiler and target: subtraction, zero counting, division,
Montgomery multiplication. Patched only in 0.7.6. The advisory lists no
affected functions, so it covers every 0.5.x release.

**Consumers in `rust/Cargo.lock`.** `dalek-ff-group` 0.4.6 and 0.5.0
(crates.io, serai), `elliptic-curve` 0.13.8 and `minimal-ed448` 0.4.2 (both
via `ciphersuite` 0.4.2), and our `helioselene`, `ec-divisors` (vendored
`shekyl-oxide`) and `shekyl-curve-generators`.

**Where secrets meet it.** `helioselene::Field25519` is
`dalek_ff_group::FieldElement`, whose arithmetic is crypto-bigint's
`Residue` (Montgomery mul/sub). `Field25519` is the Ed25519 base field (the
coordinates of the output being spent) and Selene's scalar field (that
layer's blinds), so it carries the FCMP++ prover's secret witness on the
wallet. The adversary is a co-located timing or microarchitectural observer
of the proving machine. The daemon only verifies, on public data.

**Measurement (2026-10-24).** Upstream's fixes (crypto-bigint PRs #1358
and #1360) target 0.7's code, so whether 0.5.5 compiles to
secret-dependent branches was measured directly with cargo-checkct / BINSEC, the tool
upstream used, on the operations our stack reaches. The harness, its
calibration and the full verdict tables are
[`docs/formal/checkct/`](../formal/checkct/README.md); the dated tables are
`results/2026-10-24/`.

- Calibration: the pipeline reports upstream's known leaks on the pre-fix
  crypto-bigint tree (`riscv32imac` 7/8, `thumbv6m` 8/8 entrypoints) and
  synthetic secret-dependent branches and lookups on every target; 0.7.6 is
  secure everywhere.
- crypto-bigint 0.5.5 as `dalek-ff-group` uses it (modular add/sub, Montgomery
  new/retrieve/add/sub/neg/mul/square/invert, `U512::rem`, `ct_lt`), and
  `dalek_ff_group::FieldElement` itself (from/to_repr, add, sub, neg, mul,
  square, invert, sqrt, sqrt_ratio_i, is_odd, pow with a secret exponent,
  wide_reduce): **secure** on x86_64, the one shipped target BINSEC
  decodes, and on `riscv32imac` and `thumbv7em`, the nearest stand-ins for
  the shipped riscv64 and aarch64 (every product is 64-bit; the 32-bit
  targets are instruments, not products), under the tool's nightly and
  under a nightly on the LLVM 21 line the shipped 1.94.0 uses; the
  `dividend`/`divisor` checks add no finding.
- **One leak:** crypto-bigint's own `Residue::pow` with a secret exponent
  branches on a 4-bit exponent window, on `riscv32imac` under both
  toolchains and on x86_64 under LLVM 21. So 0.5.5 is not clean, and the
  advisory's range is not wrong. **Our call graph never hands it a secret
  exponent:** `FieldElement::invert`/`sqrt`/`sqrt_ratio_i` use
  `dalek-ff-group`'s own table-walk `pow` (measured secure with a secret
  exponent on every target), and the remaining `Residue::pow` /
  `DynResidue::pow` uses in `dalek-ff-group`, `ec-divisors` and
  `minimal-ed448` are const-evaluated with public exponents;
  `elliptic-curve 0.13.8` does not use `Residue`.
- `HelioseleneField`: secure on `riscv32imac` and `thumbv7em` for all twelve
  operations and on x86_64 for ten; `pow` (public exponent in production) and
  `sqrt` on x86_64 are **not assessed**: BINSEC's exploration did not finish
  in 3600 s under either toolchain (a timeout is never a pass). The call
  graph reaches `HelioseleneField::sqrt` only through point decompression
  (`recover_y` from `from_bytes`) and transcript-sampled points, public
  inputs; the sqrt on the secret path is `Field25519`'s (ec-divisors'
  Edwards x-recovery), which is measured secure.
- Not covered statically: the shipped aarch64 and riscv64 (BINSEC has no
  64-bit ARM or RISC-V decoder; `thumbv7em` and `riscv32imac` stand in,
  for the ISA only). aarch64 gets a *dynamic* row (dudect-style, the
  harness's `dynamic/` crate on the Pi floor device; method-checked on
  x86_64 against the static verdicts: **method check passed** — it found,
  reproducibly on two x86_64 hosts, operand-dependent timing in
  `HelioseleneField` that the static tool cannot see, on code the static
  tool cleared; `Field25519` is flat on every row and the `Residue::pow`
  branch is invisible to timing. That finding is **`CA-2`** (§2), not part of
  CA-1: the 0.7 bump does not touch it. The floor-device run (Rick's go
  2026-10-24; Cortex-A72, idle, the daemon inactive): every field row flat
  at 20k and at 200k samples, both positive controls detected; the x86_64
  difference does not appear on aarch64.
  riscv64 is **not assessed**: no board, and the `pow` select became a
  branch on riscv32 under both toolchains, so it was the shipped target most
  likely to inherit that rewrite. **Ruled 2026-10-24 (Rick): riscv64 is
  switched off in the Gitian matrix, not deleted (#1184); it returns when a
  user asks for it and there is a way to measure it.** Also outside
  the tool: micro-architectural channels beyond control flow, addresses
  and division, and any toolchain other than the two run. A toolchain bump
  re-measures: `scripts/ci/check_checkct_toolchain.py` fails when
  `rust/rust-toolchain.toml` moves without `results/measured.toml`.
- Profile: the drivers match `[profile.release]` (`opt-level 3`,
  `panic = "abort"`, `overflow-checks = true`, no LTO, no `target-cpu`);
  deltas are `debug = true`, `-Zbuild-std` and a static relocation model.

**Upstream (Rick's brief, 2026-10-24): three notices, no PRs.** The harness,
drivers and dynamic crate were written with an LLM coding agent, which
upstream's Contributing.md rule 1 bars from contributions, so what goes
upstream is the result and a link to this tree, with authorship stated in
every post. The links are pinned to commits; the drafts are in
shekyl-dev's crypto-audit directory.

1. monero-oxide/monero-oxide, an issue: they are red on the same advisory
   (`deny.toml` `ignore = []`, `yanked = "deny"`; helioselene asks for
   `crypto-bigint = "0.5"`, lock 0.5.5), and helioselene is theirs. The
   static method, targets, toolchains, the one leak, calibration, links to
   the records; and, as a separate finding, CA-2 (§2) with its records.
   Posted 2026-10-25:
   <https://github.com/monero-oxide/monero-oxide/issues/210>
2. RustCrypto/crypto-bigint, a comment on #1365: the 0.5.5 `Residue::pow`
   window branch as a data point for the 0.5.x range; no code, no 0.5.6
   asked. Posted 2026-10-24:
   <https://github.com/RustCrypto/crypto-bigint/pull/1365#issuecomment-6386574661>
3. serai-dex/serai, an issue: `next`'s `prime-field` is on 0.7.5, 0.7.6 is
   the fix; is a release of `dalek-ff-group`/`ciphersuite` from `next`
   planned? A request for a path, not a leak report. Posted 2026-10-24:
   <https://github.com/serai-dex/serai/issues/1271>

An `unaffected = ["< 0.6.0"]` advisory-db PR is not among them: 0.5.5 does
branch.

**Acceptance for the pin (definition of done).** The pin PR runs this
harness against `prime-field`'s `FieldElement` on crypto-bigint >= 0.7.6
with the same entrypoints and targets; upstream's checkct covers their own
drivers, not that field. Vectors byte-identical, drivers green, ignore
dropped.

**Why it is not fixed now.** No released `dalek-ff-group` or `ciphersuite`
uses crypto-bigint 0.7 (latest 0.5.0 / 0.4.2 as of 2026-10-24). serai's
`next` branch (2026-09-22) has already moved `dalek-ff-group` onto a new
`prime-field` crate over crypto-bigint 0.7, unreleased; serai `develop` and
the crates.io releases are still on 0.5. The fix is therefore a pin of that
branch by git rev, with every pinned FCMP++ and curve-tree vector held
byte-identical, not a port of our own. `HelioseleneField` is outside it: it
takes only U256 limb plumbing from crypto-bigint (`sbb`/`adc`, wide
multiplication, `ct_eq`/`ct_lt`, `conditional_select`; its division calls
are all under `cfg(test)`) and its core is the Veridise-verified code, so
it stays on 0.5.5 with upstream monero-oxide, whose manifest asks for
`"0.5"` and whose lock resolves 0.5.5.

**Disposition.** `RUSTSEC-2026-0387` is in the `ignore` list of
[`rust/.cargo/audit.toml`](../../rust/.cargo/audit.toml), whose block
repeats the consumers and the reopen criteria. The fix is one pre-genesis
row in [`FOLLOWUPS.md`](../FOLLOWUPS.md).

**Reopen when any of:**

1. serai releases `dalek-ff-group` / `ciphersuite` on crypto-bigint
   >= 0.7.6 — bump, re-run the harness against the new field (acceptance
   above), drop the ignore;
2. the toolchain is bumped — re-measure, with the result tables and
   `results/measured.toml` updated in the same PR (the gate makes a bump
   without them red);
3. a static or dynamic row on a shipped target shows a branch, a
   secret-dependent access or a class difference in an operation our call
   graph reaches with a secret (the `FieldElement` entrypoints of
   `drivers/dfg050.rs`, or a new secret-exponent path into `Residue::pow`) —
   the pin becomes blocking for the next release.

## 2. `CA-2` — operand-dependent timing in the vendored `HelioseleneField` on x86_64

**Finding (2026-10-24).** CA-1's dynamic test (dudect's method, the
harness's `dynamic/` crate) shows that `HelioseleneField` mul, square and
sqrt take measurably different time for different operands on x86_64, while
BINSEC rules the same code free of secret-dependent branches, addresses and
division under the same toolchain. The evidence, all in
[`docs/formal/checkct/results/2026-10-24/`](../formal/checkct/results/2026-10-24/):

- two x86_64 hosts (`dynamic-x86_64-method-check.txt`, a Tiger Lake
  workstation; `dynamic-x86_64-fleet-measurement-host.txt`, an idle fleet
  VM on different silicon): the fixed-against-fresh difference grows with
  the sample as a real difference does (square −7 → −35 → −106 for 20k →
  200k → 1M on the fleet host), and a single constant operand against fresh
  ones shows it too;
- the null controls (both classes fresh) are flat, and every `Field25519`
  row is flat under the identical protocol, so it is not the measurement;
- at 200k samples the equal-familiarity `[fixed-pair]` row for square
  crossed on the fleet host (−14): two different fixed operand sets time
  differently, which is the signature of operand dependence rather than of
  any harness asymmetry (on the workstation's direct path, 2026-10-25, the
  `[fixed-pair]` rows stay flat at 1M and the operand evidence is the fresh
  shape rows instead; see the code-path run below);
- the floor device (`dynamic-aarch64-floor-device.txt`, Cortex-A72) shows
  nothing on any row, so it is x86_64-specific as far as measured.

**Disassembly (2026-10-24, the dynamic crate's own binary, 1.94.0).** Both
fields' `square` call the same `crypto_bigint::Uint::square_wide` (106
instructions) and differ only in the reduction that follows: Veridise's
`red512`, inlined (~160 instructions of `mul`/`adc`/`add`/`shld`/`sar` with
`setb`/`cmovb`/`cmovae` selects), against crypto-bigint's
`montgomery_reduction` (224, the same instruction classes plus `imul`,
`sbb`, `cmovne`). Neither contains an instruction whose latency depends on
its operands by the ISA (no division, no variable shift, no bit scan), and
neither is vectorised: the eight `xmm` instructions in `mul` are 16-byte
struct moves (`movups`/`movaps`) that survive `-C no-vectorize-slp`. So the
SLP hypothesis is out for `square`, and the carrier is the reduction step
or the multiplier's behaviour on these operands. `wide_reduce`, which is
`red512` on its own with uniform 512-bit input, is flat in every run; the
split that remains is `square_wide` alone against `red512` fed with a
square's output, both fixed against fresh (rows `half:` in the crate).

**Operand property (fleet host, `dynamic-x86_64-fleet-measurement-host-property.txt`).**
Sparse operands (one random byte per limb), small ones (high limbs zero)
and dense ones (2^254 − 1) each differ from uniformly random ones for
`HelioseleneField::square`, and at 1M samples two uniformly random fixed
sets differ from each other strongly (`[fixed-pair]` square +37, mul +38);
`Field25519::square` is flat for every class. No single operand property
is the cause; the direction is that lower-activity operands run faster
(sparse and small are faster, and so is 2^254 − 1, whose square
2^508 − 2^255 + 1 has almost no bits set). That fits a switching-activity →
clock mechanism and not an instruction-level one.

**SLP on/off, and how the operation is compiled (fleet host,
`dynamic-x86_64-fleet-measurement-host-slp-ab.txt`).** `-C no-vectorize-slp`
changes nothing: the SLP hypothesis is closed. In that build the plain
fixed-set rows and their `[fixed-pair]` companions called the operation
behind a non-inlined wrapper and went flat, while the constant-operand and
structured-operand rows, which still called it directly and inlined, kept
crossing; in the earlier builds, every row inlined, the plain fixed-set
rows crossed too. The two kinds of row ran different code, so this record
alone cannot say whether the contrast or the code path moved the time; the
code-path run below says it is the code path.

**The halves (fleet host, `dynamic-x86_64-fleet-measurement-host-halves.txt`).**
`square_wide` alone, `mul_wide` alone, `red512` alone and `red512` fed with
a square's output are all flat, fixed against fresh and fixed against
fixed; so are the plain fixed-set `square` rows, which called the
operation behind a call. What crosses, strongly and only for
`HelioseleneField`, in rows that called the operation directly, is a
constant operand (the same uniformly random value
for every operation of a batch: −44 at 200k, −72 at 1M) and the structured
operands (sparse, small, dense: −17 to −57), all faster than uniformly
random ones; `Field25519` is flat for the same classes. The asymmetry that
matches this is the **representation**: `dalek_ff_group::FieldElement`
holds values in Montgomery form, so `from_repr` turns a sparse, small,
dense or constant input into a dense residue before any arithmetic, while
`HelioseleneField` holds the canonical value, so the operand's structure
reaches the multiplier and the reduction intact. The timer then sees
whatever the platform does with low-activity versus high-activity
operand streams. Every half here sits behind a call (`square_wide` and
`wide_reduce` are out-of-line calls in this binary), and behind a call
nothing crosses (below), so the halves are flat for the same reason the
wrapped square is and do not localise the effect. The representation
argument is partial. It explains the shape rows, but a constant uniformly
random operand is dense in both representations and still crosses for
`HelioseleneField` (−139 on the direct path) while `Field25519` stays
flat, so `red512`'s instruction sequence, or how it overlaps with
`square_wide` across inlined iterations, is needed even for dense
operands. A `Field25519` row whose Montgomery residues are sparse (operand
= sparse · R⁻¹ mod p) splits the two: if it crosses, the multiplier path
carries the effect; if not, `red512` does. A Montgomery or blinded
representation stays a candidate code-side mitigation.

**Pinned clock (workstation, `dynamic-x86_64-workstation-pinned-clock.txt`;
Rick ran the root steps 2026-10-24).** With `intel_pstate/no_turbo = 1` and
the `performance` governor, the core held at base (2.59 GHz) throughout:
the `HelioseleneField` constant and structured rows cross as before or
harder (dense square −113, constant sqrt −266 at 1M), every half, every
null and every `Field25519` row is flat. **The P-state controller is not
the mechanism**: the Hertzbleed class is eliminated. What this run left
open, activity-dependent timing below the P-state level, the code-path run
below closes as well. The MSR driver refuses unprivileged APERF/MPERF
reads, so cycles against wall time, which would name it further, needs a
root-run sampler; it is not required to act. (The constant and
structured square and mul rows of this run called the operation directly,
inlined; sqrt is an out-of-line call in every binary.)

**The code path decides (workstation, 2026-10-25,
[`results/2026-10-25/dynamic-x86_64-workstation-code-path.txt`](../formal/checkct/results/2026-10-25/dynamic-x86_64-workstation-code-path.txt)).**
The dynamic crate now runs `mul` and `square` on two code paths, each
under every contrast, every contrast of a path through one compiled loop:
behind the non-inlined wrapper, and `(direct)`, the operator called in the
loop and inlined (`HelioseleneField`'s compiles to the same 167 and 177
instructions as the earlier control rows). On the same workstation as the
pinned-clock run, turbo on: with `(direct)`, `HelioseleneField` square
crosses on the fixed set (−165 cropped at 1M), a constant operand (−139)
and every operand shape (sparse −86, small −108, dense −134), and mul on
the fixed set (−61) and a constant (−67); behind the wrapper, every one of
those rows is flat at 1M (|t| ≤ 4.0). Nulls and `[fixed-pair]` rows are
flat on both paths. The harness reads a fixed-set crossing with a flat
`[fixed-pair]` companion as familiarity, and that reading is benign only
while the companion is flat: a repeat-against-fresh difference that does
not depend on which values repeat tells an observer nothing it lacks
(operands do repeat across a proof, and that is known), while two fixed
sets that time differently are operand dependence by another name. On the
fleet host the `[fixed-pair]` rows did cross (+37 square, +38 mul at 1M,
`dynamic-x86_64-fleet-measurement-host-property.txt`, binary `e8902ca27`,
before the wrappers, so every row there ran direct), and the code-path
table run there on 2026-10-25
([`dynamic-x86_64-fleet-measurement-host-code-path.txt`](../formal/checkct/results/2026-10-25/dynamic-x86_64-fleet-measurement-host-code-path.txt))
confirms it on the direct path (mul −35, square +7 at 1M) with every
wrapped `[fixed-pair]` row flat. So the hosts differ in which contrast
shows it, not in whether it is there: on the fleet host two fixed operand
sets time differently when inlined; on the workstation the operand
evidence is the shape rows, whose values are fresh and distinct for every
element (sparse −86, small −108), and the constant row. The fleet host
reproduces the rest of the split too: direct square crosses on the fixed
set (−20), a constant (−35) and every fresh shape (−26 to −38), mul on the
fixed set (−7) and a constant (−24), the wrapped path is flat at 1M,
`Field25519` is flat on every row, and `sqrt` again crosses only where one
value repeats. `Field25519` is flat on every null, test, `[fixed-pair]`
and constant row on both paths at 1M; only its operand-shape rows sit near
the threshold, on both paths and in the cropped t alone (sparse +6 / +9,
dense −6 / −5, small under; full-sample |t| ≤ 2.5), with mixed signs and
no consistent growth from 200k: unsettled at this size, two orders below
`HelioseleneField`'s, and not a code-path effect. So for square and mul
the operand dependence is real and needs the operation inlined among its
neighbours in the loop: behind a call boundary it is not observed at 1M
samples. The call boundary changes little else: at 1M the wrapped
square's batch takes 614 ns against the direct path's 580 ns, the same
arithmetic with a call, a return and a few spills added, so the activity
the loop sustains over time is nearly unchanged. A mechanism keyed to
activity over time (the P-state controller, or adaptive clocking below
it) would survive that dilution as a somewhat smaller crossing; this one
vanishes, so it is keyed to the instruction stream itself: an
operand-dependent behaviour of the core on back-to-back dependent
multiply and carry chains that a call boundary breaks. `sqrt`, an out-of-line call in every binary whose body is a loop
of inlined squares and multiplies, crosses behind its call only on the
rows whose operands repeat (fixed set −49 and constant −46 at 1M, dense
−21 at 200k) and is flat on its `[fixed-pair]` row and on the fresh
sparse and small shapes: the familiarity pattern, not shown operand
dependence. `Field25519` sqrt is flat on every row.

**Mechanism: narrowed to the core.** BINSEC's model left two candidates.
(a) Power → frequency (the Hertzbleed class) is eliminated by the
pinned-clock run, and with it, by the call-boundary argument above, any
mechanism keyed to activity over time. (b) Data-dependent behaviour of
the compiled instruction stream remains. The disassembly shows no
instruction whose latency the ISA ties to its operands and no
vectorisation, so what is left of (b) is a microarchitectural
data-dependent optimisation on dependent multiply and carry chains: the
class Intel does not promise against unless DOITM (Data Operand
Independent Timing Mode, bit 0 of `IA32_UARCH_MISC_CTL`, MSR `0x1b01`) is
set. The workstation enumerates it (`IA32_ARCH_CAPABILITIES` = `0xa007c6b`,
bit 12 set) and Linux leaves it off (`0x1b01` read 0 on all 16 CPUs).
With DOITM set on every CPU (Rick's root session, 2026-10-25) the direct
path crosses as hard as with it off (square fixed set −154, constant −97,
shapes −99 / −175 / −173, mul −87 / −61 cropped at 1M) and the wrapped path
stays flat: **not a DOITM-governed optimisation**. turbostat on the
measured core, one class at a time (the crate's one-class mode, joined on
the timing windows it prints): the direct constant and small classes run
at the same busy frequency as fresh operands (4741 and 4742 against
4736 MHz, t ≤ 0.6 across windows) and at higher IPC (3.058 and 3.047
against 3.014: +1.5 % and +1.1 %, t 3.9 and 3.4), the size of their timing
difference; the instruction stream is the same for every class, so higher
IPC is fewer cycles. The wrapped control shows neither (IPC t −1.0, MHz
t −1.5). **Equal clock, fewer cycles: the effect is in the core.** CA-2 is
an operand-dependent cycle count of this Tiger Lake core on inlined
`HelioseleneField` square and mul streams, outside what DOITM controls;
the fleet host is a VM on other silicon that reproduces the timing but
whose MSRs and counters are not reachable. Which part of the inlined
stream carries it is the next PR's question: the halves on the inlined
path (fat LTO, or inline hints in the vendored crate) and the
`Field25519` row with sparse Montgomery residues.

**Threat frame.** `HelioseleneField` is the Helios/Selene base field, the
curve-tree layers of the FCMP++ prover where it touches the blinded
membership path. A ~1–2 % per-operation dependence on an operand property
leaks that property (a few bits per operation) to a co-resident observer
of the proving machine, accumulating over the thousands of operations in
one proof; harm if exploitable is deanonymisation of that spend, the CA-1
envelope. Not remote. Nothing in the prover puts a call boundary around
these operators, so the direct path is the closer analogue and the wrapped
path's flatness is no mitigation; the prover's neighbouring code is its
own, and is not what this harness measures.

**Disposition.** Open; no waiver is involved (nothing in `cargo audit`
covers it). Owner: this row. Reported upstream with the records (§1,
monero-oxide/monero-oxide#210, 2026-10-25): inlined `HelioseleneField`
square and mul show operand-dependent time on two x86_64 hosts; the same
two operations behind a call boundary do not; DOITM does not remove it;
turbostat shows equal frequency and fewer cycles for the faster classes;
the disassembly shows no data-dependent instruction, and SLP vectorisation
is not involved. The RustCrypto and serai notices are independent of CA-2.

**Reopen / close.** The platform offers no mitigation here: the clock is
not the carrier and DOITM does not govern it. So this closes on the code
side: a representation or code shape of `HelioseleneField` (Montgomery or
blinded operands, as `Field25519`'s flat rows suggest) fixed in the
vendored crate or upstream and re-measured flat with this harness on the
direct path on both x86_64 hosts, with a note in the wallet's threat model
for the release that predates it.

## 3. `CA-3` — no constant-time evidence for post-quantum signing

**Opened 2026-11-21 by Rick's ruling**, from shekyl-core #1494's review of
fips203/204/205 0.5.0. Owner: the crypto-audit lane. It is not part of
#1494: that pull request did not create the gap, and the 0.4 crates had it.

**The question.** Is each post-quantum signer's signing constant-time with
respect to its secret key, on the floor device (Raspberry Pi 4, rule 76)
and on x86?

**What covers post-quantum code today.** checkct's drivers and its dynamic
harness (`docs/formal/checkct/`) cover crypto-bigint 0.5.5,
`dalek_ff_group::FieldElement` and `HelioseleneField`, and nothing in
fips203, fips204, fips205 or fn-dsa. RT-P4
([`RPC_CHANNEL.md`](RPC_CHANNEL.md) §9) times ML-KEM-768 decapsulation
only. No registered run covers any signing.

**The signers, by exposure.**

| Signing | Code path | Who can trigger it | Exposure |
| --- | --- | --- | --- |
| FN-DSA hybrid receipt countersignature (`fn-dsa` 0.4.0) | The host's `PassKey::sign_pass` (`shekyl-p-host/src/signer.rs:155`, `HostSigner`) → the persona's `ResidentReceiptKey::sign_pass` (`shekyl-engine-core/src/engine/stake_engine/serving/receipt_key.rs:152`) → `persona.rs:229` → `types.rs:166` → `sign_receipt_transcript` (`shekyl-p-serve/src/countersign.rs:184`); signing in `shekyl-crypto-pq/src/fn_dsa_hybrid.rs:416` (`sign`), `:382` (`sign_with_rng`) and `:513` (`sign_decoded_key`) | Anyone fetching a shard from a persona's public onion: each served pass is signed with the persona's long-lived receipt key | Remote and repeatable, rate-limited only by the onion's proof-of-work. FN-DSA is also the scheme whose timing is hardest to get right, because of its Gaussian sampling |
| ML-DSA-65, transaction signing (`fips204` 0.5.0) | `shekyl-tx-builder/src/sign.rs:418` (`sign_pqc_auths`) → `shekyl-crypto-pq/src/output.rs:1182` (`sign_pqc_auth_for_output`) → `shekyl-crypto-pq/src/signature.rs:450` (`HybridEd25519MlDsa::sign`, `try_sign` at `:458`) | The wallet's own user, or an enrolled wallet-RPC client | Local or already-authorised callers |
| SLH-DSA-SHA2-192s, message signing (`fips205` 0.5.0) | `shekyl-crypto-pq/src/message_signing.rs:385` (`sign_message_pq_half`, `try_sign` at `:399`), reached from `sign_message` (`:436`) | The same | Local or already-authorised callers |

**Method.** Per signer, one or both of: classes in the checkct dynamic
harness, or an RT-P4-style timing run (dudect's method, a planted control,
null comparisons), each registered before any run with its classes, lines
and devices; and a source read of each signing path for branches, memory
accesses or divisions that depend on the secret key. The registered runs
share the floor device's quiet-claim schedule with RT-P4.

**Reopen / close.** Open while any of the three signers has no passing
registered run. Each signer's row closes on its own passing run on both
devices, with its source read recorded here.

