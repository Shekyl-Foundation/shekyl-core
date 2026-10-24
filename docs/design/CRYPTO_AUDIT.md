# Crypto audit — advisories and audit findings against the cryptographic stack

**Status:** OPEN — register opened 2026-10-24 (family `CA-`, registered at
birth in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2). `CA-1` is
ignored in `cargo audit` by ruling (Rick, 2026-10-24); its long-term fix is
not yet designed. `CA-2` opened 2026-10-24 from CA-1's dynamic measurement:
operand-dependent timing in the vendored `HelioseleneField` on x86_64,
mechanism open (§2).

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
every post, and nothing from `dynamic/` until its method check is closed.
Posted after #1178 merges (the links must resolve on `dev`), monero-oxide
first; the drafts are in shekyl-dev's crypto-audit directory, and the three
URLs come back into this section in the PR that follows the posts.

1. monero-oxide/monero-oxide, an issue: they are red on the same advisory
   (`deny.toml` `ignore = []`, `yanked = "deny"`; helioselene asks for
   `crypto-bigint = "0.5"`, lock 0.5.5), and helioselene is theirs. The
   static method, targets, toolchains, the one leak, calibration, links to
   the records. Waits for CA-2's mechanism (§2): not yet posted.
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
  any harness asymmetry;
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
changes nothing: the SLP hypothesis is closed. In a build where each
operation sits behind a non-inlined call, the plain fixed-set rows and
their `[fixed-pair]` companions go flat while the constant-operand and
structured-operand rows keep crossing (and `Field25519` stays flat
everywhere); in the earlier builds, with the operation inlined into the
timing loop, the plain fixed-set rows crossed too. So what the timer sees
depends on how consecutive operations overlap in the pipeline, which fits
activity-dependent timing of the instruction stream, a platform property,
better than any single-operand or single-instruction cause.

**The halves (fleet host, `dynamic-x86_64-fleet-measurement-host-halves.txt`).**
`square_wide` alone, `mul_wide` alone, `red512` alone and `red512` fed with
a square's output are all flat, fixed against fresh and fixed against
fixed; so are the plain fixed-set `square` rows in a build where the
operation sits behind a call. What crosses, strongly and only for
`HelioseleneField`, is a constant operand (the same uniformly random value
for every operation of a batch: −44 at 200k, −72 at 1M) and the structured
operands (sparse, small, dense: −17 to −57), all faster than uniformly
random ones; `Field25519` is flat for the same classes. The asymmetry that
matches this is the **representation**: `dalek_ff_group::FieldElement`
holds values in Montgomery form, so `from_repr` turns a sparse, small,
dense or constant input into a dense residue before any arithmetic, while
`HelioseleneField` holds the canonical value, so the operand's structure
reaches the multiplier and the reduction intact. The timer then sees
whatever the platform does with low-activity versus high-activity
operand streams. That makes CA-2 both: a platform behaviour (activity-
dependent timing) and a code property that exposes it (canonical
representation), with a code-side mitigation available in principle
(Montgomery or blinded representation) besides the platform one (fixed
frequency).

**Mechanism: open.** Two remain once BINSEC's model is exhausted, with
different owners and fixes: (a) power → frequency (the Hertzbleed class:
operand Hamming weight or toggle count changes core power, the P-state
controller turns it into frequency, the wall-clock timer sees time; a
platform property that would follow the field onto crypto-bigint 0.7
unchanged; consistent with the aarch64 null, a fixed-governor board); (b)
instruction-level data-dependent latency in the compiled code (rare for
integer code on Tiger Lake, and the disassembly above shows no candidate
instruction and no vectorisation in `square`). Discriminators, in order, in the follow-up PR: the disassembly diff of
`HelioseleneField::square` against `Field25519::square` from the same
binary; a `-C no-vectorize-slp` rebuild of the dynamic crate; the run with
`intel_pstate/no_turbo = 1` and the `performance` governor on the
workstation (root), and APERF/MPERF against wall time if the msr module
is available. The fleet host is a VM and cannot carry the frequency
discriminator; the operand-property sweep (sparse, small, dense operands)
says which property moves the time but not why.

**Threat frame.** `HelioseleneField` is the Helios/Selene base field, the
curve-tree layers of the FCMP++ prover where it touches the blinded
membership path. A ~1–2 % per-operation dependence on an operand property
leaks that property (a few bits per operation) to a co-resident observer
of the proving machine, accumulating over the thousands of operations in
one proof; harm if exploitable is deanonymisation of that spend, the CA-1
envelope. Not remote.

**Disposition.** Open; no waiver is involved (nothing in `cargo audit`
covers it). Owner: this row. The monero-oxide notice waits for the
mechanism, or at least for the no-turbo result and the disassembly diff:
"two fixed operand sets time differently on two x86_64 hosts" is not
actionable upstream; "the SLP-vectorised limb loops in `red512` show
operand-dependent time with turbo on / off" is. The RustCrypto and serai
notices are independent of CA-2.

**Reopen / close.** Closes when the mechanism is named and either (a) it is
the platform, recorded with the mitigation the platform offers (fixed
frequency on the proving machine) and a note in the wallet's threat model,
or (b) it is the code, fixed in the vendored crate or upstream and
re-measured flat with this harness on both x86_64 hosts.
