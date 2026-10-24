# Constant-time verification — cargo-checkct / BINSEC

**Status: dated run data — first run 2026-10-24, for `CA-1`
([`CRYPTO_AUDIT.md`](../../design/CRYPTO_AUDIT.md) §1).** A verdict here is a
statement about one binary: the named driver, target, toolchain and flags.
It is not a property of the source. Re-run after any toolchain bump.

```text
docs/formal/checkct/
├── setup.sh            builds the pinned tool container, clones the pinned trees,
│                       lays out the workspaces under .build/ (git-ignored)
├── run.sh <workspace>  verifies one workspace; log + compact record in results/<date>/
├── drivers/cb055.rs    crypto-bigint 0.5.5 as dalek-ff-group uses it: U256 add/sub mod,
│                       Residue new/retrieve/add/sub/neg/mul/square/invert/pow, U512 rem, ct_lt
├── drivers/dfg050.rs   dalek_ff_group::FieldElement 0.5.0 (= helioselene::Field25519):
│                       from/to_repr, add, sub, neg, mul, square, invert, sqrt, sqrt_ratio_i,
│                       is_odd, pow with a secret exponent, wide_reduce
├── drivers/helio.rs    the vendored HelioseleneField: the same operations
├── drivers/ctl.rs      controls: crypto-bigint 0.7.x sub_mod, a branch on a secret bit,
│                       a table lookup indexed by a secret
└── results/<date>/     one .txt per run: pins, run window, verdict table, leak lines
```

## What the tool sees, and does not

cargo-checkct (Ledger-Donjon, commit `85271e5`) compiles each `#[checkct]`
entrypoint into a freestanding binary and has BINSEC 0.11.3 explore it
symbolically. Bytes read from `PrivateRng` are secret; from `PublicRng`,
public. A conditional jump or a memory address that depends on a secret is a
leak (`control-flow`, `memory-access`); with `dividend,divisor` a division
whose operands depend on a secret is one too. It explores the real machine
code, so the verdict includes what LLVM did.

**Targets.** Every shipped target is 64-bit: x86_64 (Linux, Windows,
FreeBSD, macOS) and aarch64 (Linux, macOS; the rule-76 floor device is an
aarch64 Pi 4); riscv64 was in `contrib/gitian/gitian-linux.yml` `HOSTS`
until 2026-10-24 (#1184); `.github/workflows/depends.yml` records 32-bit as
retired in alpha.5. BINSEC decodes x86_64, 32-bit RISC-V and Thumb, so:

| Shipped target | Static (BINSEC) | What stands in | Dynamic |
| --- | --- | --- | --- |
| x86_64 | **verdict**, both toolchains | — | — |
| aarch64 | no decoder | `thumbv7em` (conditional execution, like `csel`): ISA proxy only, not the Cortex-A LLVM backend | *dynamic* row on the Pi floor device 2026-10-24 (`results/2026-10-24/dynamic-aarch64-floor-device.txt`): every field row flat at 20k and 200k, controls detected; bounds, does not clear, while the method check is open |
| riscv64 (switched off 2026-10-24, #1184) | no decoder | `riscv32imac`: same ISA family, no conditional move; the `pow` select became a branch there under **both** toolchains, so riscv64 was the shipped target most likely to inherit it | no board; **not assessed**; no longer shipped until a user asks and it can be measured |

The 32-bit targets are instruments, not products: `riscv32imac` and
`thumbv7em` stand in as above, `thumbv6m` is used for calibration only
(upstream's known leak shows there) and cannot build our stack anyway.

**Profile parity.** The wallet is built with `rust/Cargo.toml`
`[profile.release]`: `opt-level = 3` (the release default; the crypto
crates are also listed at 3), `panic = "abort"`, `overflow-checks = true`,
no LTO, no `target-cpu`. `setup.sh` gives the driver workspaces the same
`opt-level`, `panic` and `overflow-checks`; the known deltas are
`debug = true` (debuginfo only), `-Zbuild-std` for `core`/`alloc`, the
static relocation model, and that the controls use upstream's
`panic = "immediate-abort"`. Each record file prints the profile and
rustflags it was made with.

**Toolchain gate.** `results/measured.toml` names the shipped channel the
latest run covers, and `dynamic/rust-toolchain.toml` pins the same channel;
`scripts/ci/check_checkct_toolchain.py` (docs-gates, which runs on every PR
to `dev`) fails when `rust/rust-toolchain.toml` names another, so a
toolchain bump re-measures in the same PR.

It also does not see micro-architectural effects beyond control flow,
addresses and division, or anything the driver does not call. Each verdict
is for the toolchain that compiled the driver: the template pins
`nightly-2026-10-06`, and the wallet ships from `1.94.0` (LLVM 21.1.8), so
the runs are repeated on `nightly-2025-12-04`, the last nightly on that
LLVM line.

Two tool gaps met on 2026-10-24: BINSEC does not model `movmskps`, which
LLVM emits when it SLP-vectorises the four-limb `is_zero` compare in
`FieldElement::invert` (the path is cut, verdict `unknown`; the surrounding
code is a `cmp`/`sbb` mask, branchless by inspection), so `subject-noslp`
repeats x86_64 with `-C no-vectorize-slp`; and the template's `thumbv6m`
cannot build our stack (`spin` needs compare-and-swap), so the low-end
targets are `riscv32imac` and `thumbv7em`.

## Calibration (why a `secure` here means something)

The pipeline must report leaks before any `secure` counts. Both toolchains,
2026-10-24 (records `ctl75.*`, `ctl76.*`, `ctlpre.*`):

| Control | Expectation | Result |
| --- | --- | --- |
| `ctl_positive_leaky_branch`, `ctl_positive_leaky_lookup` (in `ctl75` and `ctl76`) | insecure | insecure on x86_64, `thumbv6m`, `riscv32imac` |
| upstream's own driver on the pre-fix tree (`eeaabbe`, parent of crypto-bigint #1358) | insecure (upstream's #1358/#1360 finding) | `thumbv6m` 8/8 insecure; `riscv32imac` 7/8 insecure; `thumbv7em` and x86_64: 4 secure, 4 did not finish in 900 s under `overflow-checks = true` |
| crypto-bigint 0.7.5 `sub_mod` (the #1358 leak) | insecure where upstream saw it | insecure on `thumbv6m`; secure on x86_64 and `riscv32imac` |
| crypto-bigint 0.7.6 `sub_mod` (the fix) | secure | secure on every target |

So the leak class the advisory describes, a constant-time select lowered to
a branch, is visible to this pipeline on `riscv32imac` (the riscv64 stand-in)
and `thumbv6m` (calibration only), and the 0.7.5 → 0.7.6 fix is visible as
such. Upstream's x86_64 reproduction of #1358 did not reproduce under either
toolchain here; x86_64 detection rests on the synthetic positives.

## Results 2026-10-24

The verdict tables are the record files in `results/2026-10-24/`; the table
at the end of this README is rendered from them by `summarize.py` (every
record names its toolchain, profile and rustflags). Reading them:

- **crypto-bigint 0.5.5 as dalek-ff-group uses it, and `Field25519` itself:
  secure** on x86_64 (the shipped target BINSEC decodes) and on the
  `riscv32imac` / `thumbv7em` stand-ins, under both toolchains, with the
  `dividend`/`divisor` checks adding nothing. `dfg_invert` on x86_64 is the
  `movmskps` tool gap in the plain workspace and secure in `subject-noslp`.
- **One leak: `cb055_residue_pow_secret_exp`**, crypto-bigint's own
  `Residue::pow` with a secret exponent, on `riscv32imac` under both
  toolchains and on x86_64 under LLVM 21 (not under the tool's newer
  nightly). See below.
- **`HelioseleneField`: secure** for all twelve operations on `riscv32imac`
  and `thumbv7em` and for ten on x86_64; `pow_secret_exp` and `sqrt` on
  x86_64 are **not assessed**: BINSEC did not finish in 3600 s under either
  toolchain. (`pow` takes a public exponent in production.)
- Calibration: upstream's pre-fix tree leaks on `riscv32imac` (7/8) and
  `thumbv6m` (8/8) under both toolchains; crypto-bigint 0.7.5's `sub_mod`
  leaks on `thumbv6m` and 0.7.6's does not; the synthetic positives are
  caught on every target. With `overflow-checks = true` (profile parity),
  four of upstream's own division/Montgomery entrypoints do not finish on
  x86_64 and `thumbv7em` within 900 s (`unknown`), so x86_64 detection
  calibration rests on the positive controls.

**The one leak.** `Residue::pow` in crypto-bigint 0.5.5 with a secret
exponent. On `riscv32imac` under both toolchains the code extracts a 4-bit
window of the exponent (`srl`, `andi 0xf`) and branches on it (`beq`);
under LLVM 21 the x86_64 build does the same (`and $0xf,%eax; cmp $1,%rax;
je`), while LLVM's newer release keeps it branchless there. The window
select in `multi_exponentiate_montgomery_form` is what the compiler lowers
to a branch, which is the advisory's "depending on the compiler and target"
made concrete; the riscv32 result is the one to read for the shipped
riscv64, whose base ISA has no conditional move either. Nothing in our stack hands crypto-bigint's
`pow` a secret exponent: `dalek-ff-group`'s `invert`/`sqrt`/`sqrt_ratio_i`
go through its own `FieldElement::pow` (the 16-entry table walk, measured
secure with a secret exponent on all three targets); the remaining
`Residue::pow` / `DynResidue::pow` uses in `dalek-ff-group`, `ec-divisors`
and `minimal-ed448` are const-evaluated with public exponents, and
`elliptic-curve 0.13.8` does not use `Residue` at all. This is why the
advisory's 0.5.x range is not wrong: 0.5.5 does have a secret-dependent
branch, in an operation we do not reach with a secret.

## Running it

```bash
docs/formal/checkct/setup.sh                 # docker; ~5 min the first time
docs/formal/checkct/run.sh ctlpre            # must end INSECURE (calibration)
docs/formal/checkct/run.sh subject --timeout 900
docs/formal/checkct/run.sh subject-noslp --checks control-flow,memory-access,dividend,divisor
docs/formal/checkct/run.sh helio --timeout 3600
CHECKCT_NIGHTLY=nightly-2025-12-04 docs/formal/checkct/setup.sh && docs/formal/checkct/run.sh subject-noslp
```

`run.sh` exits with cargo-checkct's own status: non-zero for any insecure
or unknown entrypoint. A new `unknown` is a tool gap or a timeout, never a
pass; find the reason with `-sse-loglevel debug` on the printed command. A
cell that stays `unknown` after the long timeout is recorded as **not
assessed**, never as clean.

## Dynamic test for the targets BINSEC cannot decode

`dynamic/` is a small standalone crate (dudect's method: two input
classes, fixed and random, interleaved; Welch's t on batch timings, full
and 1 %-cropped; threshold `|t| > 4.5`, with two positive controls that
must exceed it). It runs the same `Field25519` and `HelioseleneField`
operations, plus the 0.5.5 `Residue::pow` BINSEC found branching, on the
device itself:

```bash
cd docs/formal/checkct/dynamic
cargo build --release --target aarch64-unknown-linux-gnu   # linker in .cargo/config.toml
# copy target/aarch64-unknown-linux-gnu/release/ct-dynamic to the device and run it;
# paste its table into results/<date>/dynamic-<device>.txt
```

A dynamic row is evidence of another kind: it sees this device, this
binary and this run, and can only fail to observe a difference. It never
turns a static gap into a pass; it is recorded as *dynamic*.

**Method check on x86_64: OPEN.** (`results/2026-10-24/dynamic-x86_64-method-check.txt`
and `dynamic-x86_64-diagnostics.txt`, a development workstation, Tiger Lake,
the shipped 1.94.0 / LLVM 21.1.8.) Null controls flat, both positive controls
far over the threshold, every `Field25519` row flat, the `Residue::pow` branch
BINSEC found under LLVM 21 invisible to timing. But `HelioseleneField` mul,
square and sqrt show a fixed-against-fresh difference that BINSEC's model
(branches, addresses, division) does not predict, on the same toolchain: it
grows with the sample as a real difference does (mul −7 → −19 → −45, square
−11 → −32 → −66 for 20k → 200k → 1M), it is proportional (0.9–2.2 % of the
operation, present on the 220 µs `sqrt` as on the 0.6 µs `square`, which
rules out a cache miss on the operand load), and it is absent from all nine
`Field25519` rows under the identical protocol, which rules out a property of
the measurement as such. The equal-familiarity `[fixed-pair]` companion is
flat except one `square` run at 1M (+8.4 against −3.2 in its sibling), which
is the ambiguity, not a footnote: a genuine operand-dependent path whose
fixed set happens to be timing-typical would look exactly like this. Two
harness lessons are settled and built in (generate every input before the
timing loop; never repeat a value inside a timed batch). What is not settled
is whether the remaining difference is the harness (the two classes' memory
construction) or operand-dependent timing of the vendored crate on this CPU
that BINSEC cannot see. The discriminating tests are in the record's next
revision; until one of them settles it, no dynamic row is a verdict and the
`dynamic/` crate is not offered upstream.

## Record table 2026-10-24

Rendered by `python3 docs/formal/checkct/summarize.py docs/formal/checkct/results/2026-10-24`;
regenerate it after any run. The `helio` records from the committed harness
are being produced as this is written (the two slow x86_64 entrypoints run
to their 3600 s timeout on each toolchain) and land in the follow-up commit;
their verdicts above come from the same drivers run from a scratch copy of
the harness.

| record | workspace | toolchain | options | target | secure / insecure / unknown | not secure |
| --- | --- | --- | --- | --- | --- | --- |
| `ctl75.nightly-2025-12-04.txt` | ctl75 | nightly-2025-12-04 | `--timeout 900` | riscv32imac-unknown-none-elf | 1 / 2 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup |
| `ctl75.nightly-2025-12-04.txt` | ctl75 | nightly-2025-12-04 | `--timeout 900` | thumbv6m-none-eabi | 0 / 3 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup, ctl_sub_mod_u256 |
| `ctl75.nightly-2025-12-04.txt` | ctl75 | nightly-2025-12-04 | `--timeout 900` | x86_64-unknown-linux-gnu | 1 / 2 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup |
| `ctl75.nightly-2026-10-06.txt` | ctl75 | nightly-2026-10-06 | `--timeout 900` | riscv32imac-unknown-none-elf | 1 / 2 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup |
| `ctl75.nightly-2026-10-06.txt` | ctl75 | nightly-2026-10-06 | `--timeout 900` | thumbv6m-none-eabi | 0 / 3 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup, ctl_sub_mod_u256 |
| `ctl75.nightly-2026-10-06.txt` | ctl75 | nightly-2026-10-06 | `--timeout 900` | x86_64-unknown-linux-gnu | 1 / 2 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup |
| `ctl76.nightly-2025-12-04.txt` | ctl76 | nightly-2025-12-04 | `--timeout 900` | riscv32imac-unknown-none-elf | 1 / 2 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup |
| `ctl76.nightly-2025-12-04.txt` | ctl76 | nightly-2025-12-04 | `--timeout 900` | thumbv6m-none-eabi | 1 / 2 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup |
| `ctl76.nightly-2025-12-04.txt` | ctl76 | nightly-2025-12-04 | `--timeout 900` | x86_64-unknown-linux-gnu | 1 / 2 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup |
| `ctl76.nightly-2026-10-06.txt` | ctl76 | nightly-2026-10-06 | `--timeout 900` | riscv32imac-unknown-none-elf | 1 / 2 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup |
| `ctl76.nightly-2026-10-06.txt` | ctl76 | nightly-2026-10-06 | `--timeout 900` | thumbv6m-none-eabi | 1 / 2 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup |
| `ctl76.nightly-2026-10-06.txt` | ctl76 | nightly-2026-10-06 | `--timeout 900` | x86_64-unknown-linux-gnu | 1 / 2 / 0 | insecure: ctl_positive_leaky_branch, ctl_positive_leaky_lookup |
| `ctlpre.nightly-2025-12-04.txt` | ctlpre | nightly-2025-12-04 | `--timeout 900` | riscv32imac-unknown-none-elf | 1 / 7 / 0 | insecure: div_exact_u64, div_rem_u64, leading_zeros_u512, montgomery_form_p384, pow_amm_u128, rem_wide_u64, trailing_zeros_u512 |
| `ctlpre.nightly-2025-12-04.txt` | ctlpre | nightly-2025-12-04 | `--timeout 900` | thumbv6m-none-eabi | 0 / 8 / 0 | insecure: div_exact_u64, div_rem_u64, leading_zeros_u512, montgomery_form_p384, pow_amm_u128, rem_wide_u64, sub_mod_u256, trailing_zeros_u512 |
| `ctlpre.nightly-2025-12-04.txt` | ctlpre | nightly-2025-12-04 | `--timeout 900` | thumbv7em-none-eabihf | 4 / 0 / 4 | unknown: div_rem_u64, montgomery_form_p384, pow_amm_u128, rem_wide_u64 |
| `ctlpre.nightly-2025-12-04.txt` | ctlpre | nightly-2025-12-04 | `--timeout 900` | x86_64-unknown-linux-gnu | 4 / 0 / 4 | unknown: div_rem_u64, montgomery_form_p384, pow_amm_u128, rem_wide_u64 |
| `ctlpre.nightly-2026-10-06.txt` | ctlpre | nightly-2026-10-06 | `--timeout 900` | riscv32imac-unknown-none-elf | 1 / 7 / 0 | insecure: div_exact_u64, div_rem_u64, leading_zeros_u512, montgomery_form_p384, pow_amm_u128, rem_wide_u64, trailing_zeros_u512 |
| `ctlpre.nightly-2026-10-06.txt` | ctlpre | nightly-2026-10-06 | `--timeout 900` | thumbv6m-none-eabi | 0 / 8 / 0 | insecure: div_exact_u64, div_rem_u64, leading_zeros_u512, montgomery_form_p384, pow_amm_u128, rem_wide_u64, sub_mod_u256, trailing_zeros_u512 |
| `ctlpre.nightly-2026-10-06.txt` | ctlpre | nightly-2026-10-06 | `--timeout 900` | thumbv7em-none-eabihf | 4 / 0 / 4 | unknown: div_rem_u64, montgomery_form_p384, pow_amm_u128, rem_wide_u64 |
| `ctlpre.nightly-2026-10-06.txt` | ctlpre | nightly-2026-10-06 | `--timeout 900` | x86_64-unknown-linux-gnu | 4 / 0 / 4 | unknown: div_rem_u64, montgomery_form_p384, pow_amm_u128, rem_wide_u64 |
| `subject-noslp.nightly-2025-12-04.division.txt` | subject-noslp | nightly-2025-12-04 | `--checks control-flow,memory-access,dividend,divisor --timeout 900` | x86_64-unknown-linux-gnu | 25 / 1 / 0 | insecure: cb055_residue_pow_secret_exp |
| `subject-noslp.nightly-2025-12-04.txt` | subject-noslp | nightly-2025-12-04 | `--timeout 900` | x86_64-unknown-linux-gnu | 25 / 1 / 0 | insecure: cb055_residue_pow_secret_exp |
| `subject-noslp.nightly-2026-10-06.division.txt` | subject-noslp | nightly-2026-10-06 | `--checks control-flow,memory-access,dividend,divisor --timeout 900` | x86_64-unknown-linux-gnu | 26 / 0 / 0 | — |
| `subject-noslp.nightly-2026-10-06.txt` | subject-noslp | nightly-2026-10-06 | `--timeout 900` | x86_64-unknown-linux-gnu | 26 / 0 / 0 | — |
| `subject.nightly-2025-12-04.txt` | subject | nightly-2025-12-04 | `--timeout 900` | riscv32imac-unknown-none-elf | 25 / 1 / 0 | insecure: cb055_residue_pow_secret_exp |
| `subject.nightly-2025-12-04.txt` | subject | nightly-2025-12-04 | `--timeout 900` | thumbv7em-none-eabihf | 26 / 0 / 0 | — |
| `subject.nightly-2025-12-04.txt` | subject | nightly-2025-12-04 | `--timeout 900` | x86_64-unknown-linux-gnu | 24 / 1 / 1 | insecure: cb055_residue_pow_secret_exp; unknown: dfg_invert |
| `subject.nightly-2026-10-06.txt` | subject | nightly-2026-10-06 | `--timeout 900` | riscv32imac-unknown-none-elf | 25 / 1 / 0 | insecure: cb055_residue_pow_secret_exp |
| `subject.nightly-2026-10-06.txt` | subject | nightly-2026-10-06 | `--timeout 900` | thumbv7em-none-eabihf | 26 / 0 / 0 | — |
| `subject.nightly-2026-10-06.txt` | subject | nightly-2026-10-06 | `--timeout 900` | x86_64-unknown-linux-gnu | 25 / 0 / 1 | unknown: dfg_invert |
| `dynamic-x86_64-diagnostics.txt` | dynamic | see file | — | — | — | not a checkct record |
| `dynamic-x86_64-method-check.txt` | dynamic | see file | — | — | — | not a checkct record |
