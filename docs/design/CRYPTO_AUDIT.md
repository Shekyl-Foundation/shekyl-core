# Crypto audit — advisories and audit findings against the cryptographic stack

**Status:** OPEN — register opened 2026-10-24 (family `CA-`, registered at
birth in [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2). `CA-1` is
ignored in `cargo audit` by ruling (Rick, 2026-10-24); its long-term fix is
not yet designed.

One row per advisory or audit finding that touches a cryptographic
dependency or primitive and cannot be closed by a routine lockfile bump. A
row records what is affected, where secrets meet it, why it is not fixed
now, and what reopens it. A finding a bump clears does not get a row; the
bump's commit is its record.

## Register

| Id | Finding | Status |
| --- | --- | --- |
| `CA-1` | `crypto-bigint` 0.5.5, RUSTSEC-2026-0387 (timing variability) | **IGNORED BY RULING 2026-10-24** — fix undesigned (§1) |

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
  x86_64 against the static verdicts: **method check OPEN.** `Field25519` is
  flat on every row and the `Residue::pow` branch is invisible to timing, but
  `HelioseleneField` mul, square and sqrt show a fixed-against-fresh
  difference BINSEC's model does not predict, proportional to the operation
  and growing with the sample; whether it is the harness or operand-dependent
  timing of the vendored crate on that CPU is not yet settled, so no dynamic
  row is a verdict and the crate goes nowhere upstream until it is). The
  floor-device run (Rick's go 2026-10-24; Cortex-A72, idle, the daemon
  inactive): every field row flat at 20k and at 200k samples, both positive
  controls detected; the workstation's `HelioseleneField` difference does
  not appear on aarch64. Recorded as *dynamic*, under the open method check.
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

**Upstream, in order of leverage** (none sent yet; each is Rick's call):

1. monero-oxide: red on the same advisory with `ignore = []`, and
   helioselene is theirs. Offer the harness (the `Field25519` and
   `HelioseleneField` drivers and the result tables) to the `fcmp++`
   branch; it is Monero's own evidence for its pinned 0.5.5 and keeps our
   helioselene pin aligned with theirs.
2. RustCrypto: the 0.5.5 `Residue::pow` window branch as a confirming data
   point on #1360/#1365, informational; a 0.5.6 is not expected (0.5 has no
   maintenance branch).
3. serai: `next`'s `prime-field` sits on 0.7.5; the bump to 0.7.6 is one
   line, and the ask is a release of `dalek-ff-group`/`ciphersuite` from
   `next`.

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
