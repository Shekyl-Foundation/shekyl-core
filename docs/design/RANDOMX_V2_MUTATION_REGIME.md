# RandomX v2 — mutation-regime redesign (T18 execution shape)

## Front-matter

| Field | Value |
| --- | --- |
| Status | **Design round 1 — OPEN.** Substrate survey (§2) is measured and complete; findings MR-F1–MR-F5 (§4) are source-verified; design questions MR-DQ-1–MR-DQ-8 (§5) are **awaiting ratification**. No implementation commit lands before the round closes, per [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc). |
| Kind | Test-regime redesign (assurance-gate execution shape). **Not** a change to what T18 asserts — the gate's premise is unchanged; only how it is executed. |
| Amends | [`RANDOMX_V2_PHASE2G_PLAN.md`](../completed/RANDOMX_V2_PHASE2G_PLAN.md) **§5.5.6** (the nightly-mutants CI row) and **§4.6 M2** (mutation testing as active-threat-surface mitigation). The 2g plan's §5.7 + §8.3 require that any change to harness behavior carry a plan-doc amendment; this document **is** that amendment carrier. The 2g plan is in `docs/completed/` and is not reopened as an active design — §11 records the amendment against it. |
| Spec authority | 2g plan §4.5 (active threat surface T-A1–T-A11), §4.6 M2 (mitigation premise), §6 T18 row (the assertion). This doc **cites**; it does not re-derive the threat model. |
| Substrate pin | `6441c1e29` (`dev` tip at survey time). All mutant counts, timings, and line references in §2 are against this commit. |
| Fork pin | `external/randomx-v2` at `aaafe71` (v2.0.1) — unchanged by this round. |
| Tooling pin | `cargo-mutants 27.1.0` (the version measured in §2; CI installs via `cargo install cargo-mutants --locked`). |
| Working branch | `design/randomx-mutation-regime` (off `dev`; design docs land on `dev` per [`06-branching`](../../.cursor/rules/06-branching.mdc) and the design-branch policy). |
| Scope | The **execution shape** of T18 only: invocation, cadence, scoping, parallelism, branch coverage, and the skip-list mechanism. See §1. |
| Out of scope | (a) The `dev` → `main` sync carrying `50cf03545` (T8 ceiling) + `477a448b1` (severed-header restore) — a separate validation surface per [`19-validation-surface-discipline`](../../.cursor/rules/19-validation-surface-discipline.mdc); this round neither blocks nor depends on it. (b) What T18 asserts (survival bounded by the skip-list) — unchanged. (c) The T5/T7/T8 runtime modes. (d) Any change to the verifier or harness under test. |
| Predecessor record | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) T18 entry (added 2026-08-10, dispatch run `31346130482`). This round **extends** that entry rather than contradicting it: the entry's diagnosis (suite outgrew the budget) is confirmed and its four candidate options are carried into §6 with measurements attached. The entry did not have MR-F1 or MR-F2. |

---

## 0. Why this document exists

T18 is the gate that asks whether the differential harness would notice
if it stopped working. Every other gate in
`randomx-v2-differential.yml` asks "does the verifier match the spec?";
T18 asks "would these assertions catch a change that broke them?" Per
the 2g plan §4.6 M2 it is the standing mitigation for three active
threat classes (§3), and per §4.5 T-A1 the failure mode it defends
against is explicitly silent: *"A harness with weakened assertions
silently passes every input; the leg-3 catch capacity collapses to zero
without any CI failure surfacing."*

**T18 has never produced a result.** Of the 60 most recent
`randomx-v2-differential` runs, ten carry a `mutants` job at all; nine
concluded `skipped` and one `cancelled` (dispatch `31346130482`,
2026-08-10, 01:07:24 → 07:07:40, killed at the 6-hour hosted-runner
ceiling having completed zero mutants). The skip-list in
`.cargo/mutants.toml` still reads as it did at C10 landing — "the
skip-list begins empty" — because no run has ever surfaced a survivor
to triage.

This document exists because fixing that is not a parameter change.
The survey below found that the gate as specified is **internally
contradictory** (MR-F1), that its skip-list mechanism is **inert**
(MR-F2), that it has **no coverage of the branch where the threat
arrives** (MR-F3), that its invocation **forecloses the parallelism**
that would make it affordable (MR-F4), and — the finding that outranks
the budget problem — that **the differential harness never participates
in judging verifier mutants**, so the layer of the T-A1 defense that
M2 is supposed to provide is not operative at all (MR-F5). Each has a
different remedy, and three of them change what the gate means — which
is amendment territory, not a CI tweak.

Note the ordering that matters for triage: even a T18 that fit its
budget perfectly would still not be doing the job §4.6 M2 describes.

Per [`05-system-thinking`](../../.cursor/rules/05-system-thinking.mdc)
"specification first, code second" and rule 26's halt condition, no
implementation commit lands before §5 closes.

---

## 1. Scope

### 1.1 In scope

The execution shape of T18:

1. **Invocation** — the `cargo mutants` command line and its
   relationship to the §5.5.6 pinned contract (MR-F1).
2. **Skip-list mechanism** — `.cargo/mutants.toml` discovery and
   glob semantics (MR-F2).
3. **Scoping** — which crates/modules are mutated, and on what
   trigger.
4. **Parallelism and sharding** — how the work is divided to fit a
   hosted-runner ceiling (MR-F4).
5. **Branch coverage** — which branch's code T18 actually tests
   (MR-F3).
6. **Cadence** — per-PR, weekly, or both.

### 1.2 Not in scope

- **What T18 asserts.** "Zero surviving mutations, or all survivors in
  the skip-list with substrate-anchored justification" is unchanged.
  This round changes how that assertion is *reached*, never its
  content.
- **The `dev` → `main` sync.** The nightly redness on `main` has two
  causes (a stale T8 ceiling and the severed mutants-job header), both
  already fixed on `dev`. That is a different validation surface and a
  different PR. It is noted here only because the severed header is
  what kept MR-F1–MR-F5 latent: with T18 never triggering, none of
  them could surface.
- **The verifier and harness under test.** No `shekyl-pow-randomx` or
  `shekyl-randomx-differential` behavior changes in this round.

---

## 2. Substrate survey (measured)

All measurements taken at `6441c1e29` in a dedicated worktree
(`cargo-mutants` mutates source in place; it must never run in a shared
checkout), with the C reference built from the fork-pinned submodule
per `.github/actions/build-randomx-v2-ref`.

### 2.1 Mutant inventory

`cargo mutants --package shekyl-randomx-differential --package
shekyl-pow-randomx --list` → **1322 mutants**, matching the CI log
exactly. By file:

| Mutants | File | Crate | Class |
| ---: | --- | --- | --- |
| 396 | `src/vm.rs` | verifier | hot path |
| 296 | `src/superscalar.rs` | verifier | hot path |
| 95 | `src/mode_concurrent.rs` | harness | **assertion-bearing** |
| 61 | `src/mode_adversarial_ratio.rs` | harness | **assertion-bearing** |
| 57 | `src/cache_precondition.rs` | harness | **assertion-bearing** |
| 42 | `src/corpus_random.rs` | harness | corpus |
| 41 | `src/cache.rs` | verifier | hot path |
| 40 | `src/mode_latency.rs` | harness | **assertion-bearing** |
| 33 | `src/mode_correctness.rs` | harness | **assertion-bearing** |
| 31 | `src/seed_epoch.rs` | verifier | schedule |
| 28 | `src/main.rs` | harness | dispatch |
| 28 | `src/adversarial_corpus.rs` | harness | corpus |
| 26 | `src/bin/gen_canonical_outputs.rs` | harness | **tooling (should be excluded)** |
| 23 | `src/fpu_rounding.rs` | verifier | hot path |
| 16 | `src/blake2_generator.rs` | verifier | hot path |
| 13 | `src/cache_store.rs` | verifier | residency |
| 13 | `src/c_oracle.rs` | harness | **assertion-bearing** |
| 11 | `src/aes.rs` | verifier | hot path |
| 9 | `src/vm_pool.rs` | verifier | residency |
| 9 | `src/adversarial/canonical.rs` | harness | corpus |
| 7 | `src/prepared_cache.rs` | verifier | residency |
| 7 | `src/adversarial/interpreter.rs` | harness | corpus |
| 6 | `src/bin/gen_parity_corpus.rs` | harness | **tooling (should be excluded)** |
| 6 | `src/rust_subject.rs` | harness | **assertion-bearing** |
| 6 | `src/adversarial/recipes/boundary_values.rs` | harness | corpus |
| 4 | `src/seedhash.rs` | verifier | schedule |
| 4 | `src/failure_output.rs` | harness | reporting |
| 4 | `src/parity_corpus.rs` | harness | corpus |
| 3 | `src/invocation_banner.rs` | harness | reporting |
| 2 | `src/adversarial/mod.rs` | harness | corpus |
| 2 | `src/adversarial_canonical_outputs.rs` | harness | corpus |
| 2 | `src/adversarial/recipes/dataset_item_extrema.rs` | harness | corpus |
| 1 | `src/argon2d.rs` | verifier | hot path |

Aggregates that matter for §6:

- **Verifier total: 848** (64%). `vm.rs` + `superscalar.rs` alone are
  **692 (52% of everything)**.
- **Harness total: 474** (36%).
- **Assertion-bearing harness modules: 305** (23% of everything) —
  `mode_concurrent`, `mode_adversarial_ratio`, `cache_precondition`,
  `mode_latency`, `mode_correctness`, `c_oracle`, `rust_subject`.
  **This is where T-A1 and T-A3 live** (§3).
- **Tooling binaries: 32**, which the skip-list is *supposed* to
  exclude and does not (MR-F2).

### 2.2 Baselines

| Measurement | Value | Source |
| --- | ---: | --- |
| Debug baseline test (CI, 4 vCPU) | 1263 s | run `32103276707`, 2026-08-18 |
| Debug baseline test (CI, 4 vCPU) | 1334 s | run `31346130482`, 2026-08-10 |
| Auto-set per-mutant test timeout (CI) | 6317 s | run `32103276707` (= 5.001 × baseline) |
| Hosted-runner hard ceiling | 360 min | GitHub Actions |

#### 2.2.1 Local measurements (i9-11950H, 8c/16t)

Same crate pair, same `--skip canonical_pins_full` as CI, warm target
directory:

| Profile | Build | Baseline test | Dominant binary |
| --- | ---: | ---: | ---: |
| debug | 9 s | **798 s** | 738.90 s |
| release | 20 s | **66 s** | 54.92 s |

Two derived constants that §6 depends on:

- **Release speedup on the test phase: 12.1×** (798 / 66). The
  FOLLOWUPS entry's *"~40× faster tests"* estimate is **too
  optimistic by ~3×**; the direction is right, the magnitude is not.
  `rust_subject.rs`'s docstring — *"~150–200 ms in debug; ~5–10 s in
  release"* — is **backwards** and should be corrected in the doc tail
  (§10); release is faster, substantially.
- **CI-to-this-box hardware factor: 1.58×** (CI debug baseline 1263 s
  ÷ local debug baseline 798 s). Every local number in §6 is scaled by
  this to reach a CI estimate, and the scaling is stated rather than
  hidden so a future re-derivation can re-measure the factor instead
  of inheriting it.

Applying both: the **estimated CI release baseline is ~104 s**
(66 × 1.58), against the measured CI debug baseline of 1263 s.

### 2.3 Structural facts

- **`--in-place` is incompatible with `--jobs`.** cargo-mutants'
  documentation: *"`--in-place` is currently incompatible with the
  `--jobs` option, because running multiple jobs requires making
  multiple copies of the tree."* The pinned invocation uses
  `--in-place`, so the run is **strictly serial** (MR-F4).
- **`--check` runs no tests.** From cargo-mutants' source, `--check`
  sets `check_only`, whose phase list is `[Phase::Check]`; the field's
  own doc comment reads *"Don't run the tests, just see if each mutant
  builds."* The non-check path is `[Phase::Build, Phase::Test]`
  (MR-F1).
- **Config discovery works; the globs do not.** `timeout_multiplier =
  5.0` from `.cargo/mutants.toml` demonstrably applies (CI's auto-set
  timeout is 5.001 × baseline), but `exclude_globs` never matches
  (MR-F2).
- **Schedule events run the default branch's workflow.** `main` is the
  default branch, so a scheduled T18 tests `main` regardless of what
  is on `dev` (MR-F3).

### 2.4 Tooling capabilities (verified present in cargo-mutants 27.1.0)

Confirmed against the installed binary's `--help`, so §7 proposes
nothing the pinned tooling cannot do:

| Flag | Effect | Used by |
| --- | --- | --- |
| `--profile <PROFILE>` | Build/test under a named cargo profile. The first-class form of the FOLLOWUPS entry's `-- --release` suggestion. | MR-DQ-3 |
| `--in-diff <FILE>` | Mutate only code touched by a diff. **Takes a diff file, not a git ref** — CI must generate it (`git diff origin/dev...HEAD`). | MR-DQ-2 |
| `--shard k/n`, `--sharding` | Split mutants across independent jobs; no runtime coordination, but every shard must see identical arguments. | MR-DQ-4 |
| `--jobs` | Local parallelism. **Mutually exclusive with `--in-place`.** | MR-DQ-5 |
| `--test-tool cargo\|nextest` | Alternative test runner. | not proposed |

---

## 3. What T18 defends (cited, not re-derived)

Per 2g plan §4.6 M2, T18 is the mitigation for three active-threat
classes. Restated here only so §6's preservation matrix is readable:

| Class | Attack (2g §4.5) | Where it lands in the tree |
| --- | --- | --- |
| **T-A1** — comparison-operator tampering | An attacker with PR access weakens a byte-equality assertion (`assert_eq!(rust_hash, c_hash)` → `assert!(rust_hash.len() == c_hash.len())` or `assert!(true)`). One-line diff; reviewer attention may not catch it. Explicitly named targets include the cache-equivalence precondition (R1-D14) and **the RSS-bound assertion (T8)**. | Assertion-bearing harness modules (**305 mutants**) |
| **T-A3** — precondition tampering | The R1-D14 SHA-256-of-full-cache precondition narrowed to compare only the first 64 bytes, so divergent Argon2d fills pass. | `cache_precondition.rs` (**57 mutants**) |
| **T-A9** — optimization-as-laundering | A `compute_hash` optimization that changes an edge case, passes corpus-bounded tests, lands, and forks the daemon on a real-world input later. | Verifier hot path (**692 mutants** in `vm.rs` + `superscalar.rs`) |

### 3.1 Where the *evidence* appears is not where the *attack* lands

The natural reading — "T-A1 and T-A3 are PR-access attacks, so mutate
the PR's diff" — is **wrong**, and getting it wrong would design the
regime around the wrong surface. The attack arrives in a diff; the
evidence appears somewhere else.

M2's stated mechanism (2g §4.6 M2) is: *"mutations that survive (i.e.,
don't cause any test failure) reveal assertion gaps."* So a weakened
assertion is detected **not** by mutating the line that was weakened,
but by mutating the code that assertion used to protect and observing
that survivors appear. Mutating `assert!(true)` itself yields nothing.

Corrected mapping, which is what §6 is built on:

| Class | Detection surface | Why |
|---|---|---|
| **T-A1** | The code the tampered assertion covers — i.e. survivors rise across the covered surface | The weakening is invisible at its own line; it shows up as lost catching power elsewhere |
| **T-A3** | The cache-fill path the precondition covers | Same shape as T-A1 |
| **T-A9** | The **changed lines** of the PR introducing the optimization | New code whose edge case no corpus exercises produces survivors *in that new code* — this is exactly what `--in-diff` mutates |

So `--in-diff` is the **T-A9** instrument, not the T-A1 one, and the
broad sweep is what carries T-A1/T-A3 — the reverse of the intuitive
assignment. **MR-F5 (§4) then shows that the broad sweep, as
configured, does not actually carry T-A1 either.**

---

## 4. Findings

### MR-F1 — the pinned invocation cannot assert the pinned property

The 2g plan §5.5.6 pins:

```
cargo mutants --package shekyl-randomx-differential \
              --package shekyl-pow-randomx --in-place --check
```

and, in the same row, pins T18 as *"Zero surviving mutations OR all
surviving mutations in `.cargo/mutants.toml`'s skip-list."*

These are incompatible. `--check` runs `[Phase::Check]` only — it
verifies that each mutant *builds*, and never runs a test. A
check-only pass cannot classify a mutant as caught or survived, so it
cannot produce the survival set that T18's assertion is defined over.

The implemented workflow (C10, `dd984d115`) drops `--check`, taking the
`[Phase::Build, Phase::Test]` path — semantically what T18 requires,
and the source of the cost. **This is not an implementation deviation
from a sound contract; the contract is unsound, and the implementation
silently picked the expensive coherent half without recording the
choice.** No amendment exists.

**This finding is not in the FOLLOWUPS entry** — it predates the
discovery. It is the root finding of this round: whichever regime §5
selects, §5.5.6's invocation text must be corrected, because as written
it specifies a gate that cannot fail for the reason it claims to.

### MR-F2 — the skip-list is inert

`.cargo/mutants.toml` `exclude_globs` are:

```toml
"rust/shekyl-randomx-differential/src/bin/**",
"rust/shekyl-randomx-differential/src/canonical_outputs.rs",
```

The Cargo workspace root is `rust/`, and cargo-mutants matches paths
relative to that root — so the actual path of the first file is
`shekyl-randomx-differential/src/bin/gen_canonical_outputs.rs`. The
leading `rust/` means neither glob ever matches.

Measured, at `6441c1e29`:

| Invocation | Mutants |
| --- | ---: |
| default discovery | 1322 |
| explicit `--config ../.cargo/mutants.toml` | 1322 |
| same config, `rust/` prefix removed from both globs | **1290** |

The 32-mutant delta is exactly the tooling binaries (26
`gen_canonical_outputs.rs` + 6 `gen_parity_corpus.rs`) that the
skip-list's own inline comments justify excluding.

The file is **half-working**, which is why this went unnoticed:
`timeout_multiplier = 5.0` from the same file *does* apply (CI's
auto-set timeout is 5.001 × the baseline), so the config is
demonstrably read. Only the path-dependent keys silently no-op.

The consequence is larger than 32 mutants. §4.6 M2's entire
survivor-triage discipline — *"every entry in `exclude_globs` /
`exclude_re` must cite a substrate-anchored justification"* — is
enforced through a mechanism that has never excluded anything. Any
future skip-list entry written in the same style would also silently
no-op, and the gate would report survivors the discipline believed
were carved out.

### MR-F3 — T18 has no coverage of `dev`

Schedule events fire on the default branch, and the workflow definition
used is that branch's. `main` is the default branch. The restored
`mutants` job (`477a448b1`) does a plain `actions/checkout@v5` with no
`ref:`, so on the Monday cron it tests **`main`'s** code.

The `runtime-modes` job needed an explicit `matrix.branch: [main, dev]`
for exactly this reason, and its comment says so: *"schedule events
fire on the default branch (main) only, so without a matrix this cron
would never measure dev, where verifier work lands first."* T18 has no
equivalent. Verifier and harness changes land on `dev` first and can
sit there for weeks — the current `main` is 11 days and two
harness-affecting commits behind.

So even a T18 that fit its budget would be testing the branch where
the threat has already been merged past, rather than the branch where
it arrives.

### MR-F5 — the harness never participates in catching verifier mutants

**The finding.** For all 848 `shekyl-pow-randomx` mutants — 64% of the
run — cargo-mutants runs **only `shekyl-pow-randomx`'s own tests**. The
differential harness, its C oracle, and its byte-equality assertions
never execute against a verifier mutant.

**Evidence, three parts:**

1. cargo-mutants' `--help`: *"`--test-workspace` … If false, only the
   tests in the mutated package are run."*
2. cargo-mutants' source: with no `--test-workspace`, no
   `--test-package`, and neither key in config, `test_package` falls
   through to `TestPackages::Mutated`.
3. `.cargo/mutants.toml` sets neither `test_workspace` nor
   `test_package`, and the workflow invocation passes neither flag.

**Why it matters.** M2's T-A1 layer is defined as: weaken the
byte-equality assertion, and mutants it used to catch now survive. That
signal requires harness tests to run against verifier mutants. They
never do — so **M2's layer of the T-A1 defense is not operative as
configured.** A weakened `assert_eq!(rust_hash, c_hash)` in
`mode_correctness.rs` cannot change the survival count of a single
`vm.rs` mutant, because `vm.rs` mutants are judged solely by the
verifier's own unit tests, which harness tampering does not touch.

**What this does not say.** T-A1 is not undefended. Its 2g disposition
is explicitly a **three-layer** mitigation, and M1 (committed canonical
outputs, `rust == c == committed_canonical`) is layer 1 and is
operative. What is inoperative is M2's layer. The residual T-A1 signal
M2 does provide comes from mutating the assertion-bearing harness
modules themselves (305 mutants), which *are* judged by harness tests.

**Latent spec ambiguity.** The 2g plan never pinned test scoping at
all — §5.5.6's invocation names packages to *mutate* and is silent on
packages to *test*. The tool's default was silently load-bearing. So
this is not only a misconfiguration; it is a gap in the pinned
contract, and the amendment must close it explicitly (MR-DQ-8).

**Fixable, and worth pricing.** The harness's integration tests do
perform real rust-vs-C comparison — `adversarial_corpus_byte_equality.rs`,
`c_oracle_session_round_trip.rs`, `divergence_triage.rs`,
`worst_case_ratio.rs`, `canonical_pins_full.rs` all drive
`COracleSession` / `compute_hash`. (The mode modules' in-src
`#[cfg(test)]` blocks do not; the differential lives in `tests/`.) So
directing verifier mutants at the harness's suite would genuinely wire
M2's T-A1 layer rather than merely appearing to. It also raises
per-mutant cost, which §6 prices.

### MR-F4 — the invocation forecloses its own parallelism

`--in-place` was chosen (per the workflow comment) because *"the
runner's 14 GB SSD is tight for multi-worktree mutation runs at
workspace scale."* That is a real constraint, but it is also
mutually exclusive with `--jobs`: the run is strictly serial by
construction. The 8-core runner executes one build+test at a time,
and the disk-space rationale was never weighed against the
throughput it costs, because the gate never ran long enough for
anyone to see the cost.

---

## 5. Design questions

Each carries a recommendation with its substrate. **None is closed
until ratified.**

### MR-DQ-1 — how is MR-F1 resolved: correct the invocation, or correct the assertion?

Two coherent regimes exist. (a) Keep `--check` and redefine T18 as a
*build-viability* gate — cheap, but it defends none of T-A1/T-A3/T-A9,
because a mutant that builds tells you nothing about whether a test
would catch it. (b) Drop `--check` from §5.5.6's pinned text,
matching what C10 implemented, and solve the cost problem in
MR-DQ-2–MR-DQ-5.

**Recommendation: (b).** Option (a) preserves the gate's name and
discards its content; the 2g threat table would then cite a mitigation
that mitigates nothing. §5.5.6's invocation text is corrected by
amendment (§11), and the `--check` flag is recorded as a
specification error, not re-litigated.

### MR-DQ-2 — per-PR `--in-diff`, weekly whole-crate sweep, or both?

Per §3.1 the assignment is the reverse of the intuitive one.
`--in-diff` mutates the lines a PR touches, which is precisely where
**T-A9**'s evidence appears: a new optimization whose edge case no
corpus exercises leaves survivors *in the new code*. It bounds the work
by the size of the change rather than the size of the tree, and it runs
at the moment the code arrives — including on `dev`, which closes part
of MR-F3.

**T-A1 and T-A3 are not served by `--in-diff`**, because a weakened
assertion is invisible at its own line (§3.1). They need mutation of
the surface the assertion covers — which, per MR-F5, currently means
the **assertion-bearing harness modules** (305 mutants), and would
additionally mean the verifier surface if MR-DQ-8 fixes test scoping.

**Recommendation: both legs, mapped correctly** — per-PR `--in-diff`
as the merge-blocking T-A9 leg, and a periodic sweep carrying
T-A1/T-A3. §6 prices whether that sweep is the 305-mutant
assertion-module slice, the full 1290, or the full set under corrected
scoping.

### MR-DQ-8 — how is test scoping pinned (MR-F5)?

The 2g contract never pinned which packages *test* a mutant; the tool's
`TestPackages::Mutated` default silently became the contract, and it is
the reason M2's T-A1 layer is inoperative. Whatever §7 selects, the
amendment must state test scoping explicitly rather than inherit a
default — that is the specific failure this whole round exists to stop
recurring.

Options: (a) leave `Mutated` and record honestly that M2 covers T-A9
plus assertion-module T-A1, with M1 carrying the rest — cheap, and
truthful once written down; (b) `test_package = ["shekyl-randomx-differential"]`
for verifier mutants, so the differential judges them — implements M2
as described, at higher per-mutant cost (the harness suite replaces the
verifier suite); (c) `test_workspace = true` — broadest, most
expensive.

**Recommendation: (b), pinned in `.cargo/mutants.toml` with a comment
naming MR-F5**, contingent on §6's price. (a) is acceptable only if
§6 shows (b) is unaffordable, and then the 2g threat table must be
amended to stop claiming an M2 T-A1 layer it does not have — an
inoperative-but-documented gate is recoverable; an inoperative gate
described as operative is the failure mode of this entire round.

### MR-DQ-3 — release-mode or debug-mode per-mutant test runs?

The FOLLOWUPS entry proposes `cargo mutants -- --release` on the
estimate *"~40× faster tests, slower per-mutant rebuilds."* That
number was unmeasured, and the repo contradicts itself about the
direction: `rust_subject.rs`'s docstring claims a cache derive is
*"~150–200 ms in debug; ~5–10 s in release,"* which is backwards for
Argon2d. §2.2.1 settles it by measurement.

**Recommendation: see §2.2.1 and §6** — this question is answered by
the measured build/test trade, not by argument.

### MR-DQ-4 — sharding, and at what denominator?

`--shard k/n` is cargo-mutants' designed answer to a per-job wall-clock
ceiling, and composes with `--in-diff` and with filters so long as
every shard sees identical arguments. It converts a wall-clock problem
into a runner-cost problem. The denominator falls out of §2.2.1's
per-mutant cost against the 360-minute ceiling, with margin.

**Recommendation: shard the periodic sweep; do not shard the per-PR
leg** (an `--in-diff` run small enough to be merge-blocking should not
need a matrix). Denominator pinned in §7 from measurement, with the
sizing rule recorded so it can be re-derived when the suite grows
again — the failure this round is fixing is precisely a budget that
was written once and never re-derived.

### MR-DQ-5 — does `--in-place` stay?

`--in-place` forecloses `--jobs` (MR-F4). Its justification is the
runner's 14 GB disk. Sharding changes this calculus: each shard is its
own runner with its own disk, so per-shard `--in-place` keeps the disk
guarantee while parallelism comes from the matrix rather than from
`--jobs`.

**Recommendation: keep `--in-place` per shard**, and take parallelism
from sharding. This preserves the disk rationale on the record instead
of silently dropping it.

### MR-DQ-6 — how is MR-F3 (branch coverage) closed?

Options: (a) a `matrix.branch: [main, dev]` on the sweep job, mirroring
`runtime-modes`; (b) rely on the per-PR `--in-diff` leg, which runs on
PRs targeting `dev` and therefore covers `dev` at the moment code
arrives; (c) both.

**Recommendation: (c)**, weighted to (b). The per-PR leg is the real
fix — it puts mutation coverage at the point where T-A1/T-A3 enter —
and the matrix on the sweep closes the residual for T-A9 on code that
reaches `dev` by a path with no PR (merge commits, direct pushes).

### MR-DQ-7 — is the corrected skip-list re-scoped, or only repaired?

MR-F2's minimal repair is deleting the `rust/` prefix, restoring the
32-mutant carve-out the discipline always intended. The open question
is whether the *mechanism* also needs a guard: a skip-list whose
entries can silently no-op is a discipline failure waiting to recur,
and the same class of error (a gate that looks armed and is not) is
what this whole round is about.

**Recommendation: repair, plus a mechanical guard** — a test or CI
assertion that every `exclude_globs` entry matches at least one real
path, so a future no-op entry fails loudly. Shape pinned at
implementation; the principle is that a carve-out that matches nothing
is a bug, not a no-op.

---

## 6. Option matrix

*(Filled from §2.2.1 measurements — see §6.1.)*

---

## 7. Recommended regime

*(Pinned after §5 ratification.)*

---

## 8. Commit plan

*(Pinned after §5 ratification; ≤10 commits per rule-26 / rule-06
rule-2 ceiling.)*

---

## 9. Test plan

*(Pinned after §5 ratification. Must include: the MR-DQ-7 skip-list
liveness guard; a T18-fits-its-budget assertion that fails loudly
rather than by timeout; and the §5.5.6 invocation-text parity check.)*

---

## 10. Documentation tail (rule 91)

Landing this round updates, in the same PR as the implementation:

- `docs/design/IMPLEMENTATION_INDEX.md` — the `MR-` registry row
  (rule 94 §1, minted at birth) and an inventory row for the regime.
- `docs/FOLLOWUPS.md` — the T18 entry, **including its heading**,
  which currently reads *"no longer fits its 360-minute budget"* and
  must read as redesigned-and-carried once this lands (rule 91's
  sweep-the-indexes clause; a corrected body under a stale heading is
  worse than an uncorrected item).
- `docs/completed/RANDOMX_V2_PHASE2G_PLAN.md` — §11 amendment row
  recording the §5.5.6 + §4.6 M2 change and pointing here.
- `.cargo/mutants.toml` — the skip-list header comment, which
  currently documents the `--check` invocation (MR-F1) and a
  cadence ("nightly only") that has not been true since the weekly
  move.
- `.github/workflows/randomx-v2-differential.yml` — the job comments.
- `CHANGELOG.md`.

---

## 11. Amendment record against the 2g plan

*(Written at round close: the §5.5.6 row's corrected invocation text,
the §4.6 M2 cadence/scope change, and the §6 T18 row's cadence column.
Per the 2g plan's own §5.7 + §8.3, this is the required carrier.)*

---

## 12. Round record

| Round | Date | Substance |
| --- | --- | --- |
| Survey | 2026-08-18 | Substrate measured at `6441c1e29` (§2): 1322-mutant inventory by file, config/glob behavior, `--check` semantics from cargo-mutants 27.1.0 source, branch-coverage read. Findings MR-F1–MR-F5 recorded (MR-F5 — default `TestPackages::Mutated` scoping — found by reading cargo-mutants' source while pricing MR-DQ-3). Design questions MR-DQ-1–MR-DQ-8 opened with recommendations. **Round 1 not closed.** |
