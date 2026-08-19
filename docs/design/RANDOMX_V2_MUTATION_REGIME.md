# RandomX v2 — mutation-regime redesign (T18 execution shape)

## Front-matter

| Field | Value |
| --- | --- |
| Status | **RATIFIED 2026-08-18; items 1–3 LANDED/IN-REVIEW as of 2026-08-19 — round 1 CLOSED on the §7.5 re-scope; item 1 LANDED (`1cbb21fab`, 9/9 on the verdict surface). MR-F12 then established that §4.6 M2's T-A1 mechanism was never mechanically possible, which makes item 1 its precondition rather than a convenience.** MR-DQ-1 RULED; MR-DQ-8 HELD (C1 withdrawn); item 2 carries construction requirements MR-R1–MR-R4 (§7.9). MR-DQ-2/4/6 remain open by design — they change meaning under the re-scope, and MR-DQ-4 is to be **re-derived, not dispositioned**, once item 1 lands. Substrate survey (§2) is measured and complete; findings MR-F1–MR-F12 (§4) are source-verified (MR-F2 superseded by **MR-F2′**); MR-DQ-1 + MR-DQ-8 are ruled (§5). The rule-26 halt is **discharged for item 1 only**; items 2 and 3 remain design-gated per [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc). |
| Kind | Test-regime redesign. **Opened** as execution-shape-only; the second review round established that T18 is the wrong instrument for two of its three claimed threats (MR-F10, MR-F11), so the round now also re-scopes **what T18 is for** — §7.5. §4.6 M2's premise is amended, not merely its cadence. |
| Amends | [`RANDOMX_V2_PHASE2G_PLAN.md`](../completed/RANDOMX_V2_PHASE2G_PLAN.md) **§5.5.6** (the nightly-mutants CI row) and **§4.6 M2** (mutation testing as active-threat-surface mitigation). The 2g plan's §5.7 + §8.3 require that any change to harness behavior carry a plan-doc amendment; this document **is** that amendment carrier. The 2g plan is in `docs/completed/` and is not reopened as an active design — §11 records the amendment against it. |
| Spec authority | 2g plan §4.5 (active threat surface T-A1–T-A11), §4.6 M2 (mitigation premise), §6 T18 row (the assertion). This doc **cites**; it does not re-derive the threat model. |
| Substrate pin | `6441c1e29` (`dev` tip at survey time). All mutant counts, timings, and line references in §2 are against this commit. |
| Fork pin | `external/randomx-v2` at `aaafe71` (v2.0.1) — unchanged by this round. |
| Tooling pin | `cargo-mutants 27.1.0` (the version measured in §2). CI currently installs via `cargo install cargo-mutants --locked`, which does **not** pin the version — see MR-F7. |
| Working branch | `design/randomx-mutation-regime` (off `dev`; design docs land on `dev` per [`06-branching`](../../.cursor/rules/06-branching.mdc) and the design-branch policy). |
| Scope | The **execution shape** of T18 only: invocation, cadence, scoping, parallelism, branch coverage, and the skip-list mechanism. See §1. |
| Out of scope | (a) The `dev` → `main` sync carrying `50cf03545` (T8 ceiling) + `477a448b1` (severed-header restore) — a separate validation surface per [`19-validation-surface-discipline`](../../.cursor/rules/19-validation-surface-discipline.mdc); this round neither blocks nor depends on it. (b) What T18 asserts (survival bounded by the skip-list) — unchanged. (c) The T5/T7/T8 runtime modes. (d) Any change to the verifier or harness under test. |
| Predecessor record | [`docs/FOLLOWUPS.md`](../FOLLOWUPS.md) T18 entry (added 2026-08-10, dispatch run `31346130482`). This round **extends** that entry rather than contradicting it: the entry's diagnosis (suite outgrew the budget) is confirmed and its four candidate options are carried into §6 with measurements attached. The entry did not have MR-F1, MR-F2′, or MR-F5. |

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
contradictory** (MR-F1), that its skip-list config **is never loaded at all**
(MR-F2′), that it has **no coverage of the branch where the threat
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
2. **Skip-list mechanism** — `.cargo/mutants.toml` **placement**,
   discovery, and glob semantics (MR-F2′).
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
  what kept MR-F1–MR-F8 latent: with T18 never triggering, none of
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
verifies that each mutant *builds*, and never runs a test. The tool is
explicit about this beyond the phase list: under `check_only` the test
timeout is set to literally zero, with the comment *"We won't have run
baseline tests, and we won't run any other tests either."* A
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

### MR-F2′ — the skip-list config is never loaded (supersedes MR-F2)

**Supersede note.** MR-F2 as first written said the skip-list globs are
inert because they carry a dead `rust/` prefix. That is true and
insufficient. The deeper fault is that **the config file is never read
at all** in the CI invocation, so the entire skip-list discipline —
not merely two globs — is unwired. MR-F2's glob claim is retained
below as the second of two independent defects. The original
supporting argument ("`timeout_multiplier` demonstrably applies, so
the file is read") is **withdrawn as unsound**; see "the trap" below.

**Defect 1 — wrong path.** cargo-mutants reads its config from
`<workspace_root>/.cargo/mutants.toml`. The Cargo workspace root is
`rust/` (the workspace manifest is `rust/Cargo.toml`), and the mutants
job runs with `working-directory: rust` and passes neither `-d` nor
`--config-file`. So the file it looks for is
`rust/.cargo/mutants.toml`. That does not exist — `rust/.cargo/`
contains only `audit.toml`. The one `mutants.toml` sits at the **repo
root**, where nothing reads it. A missing config silently defaults to
empty.

**Defect 2 — dead prefix.** Independently, both `exclude_globs` are
written as `rust/shekyl-randomx-differential/…`, but globs match
against the tree-relative path, which is already relative to `rust/`.
So even once the file is placed where the tool reads it, the globs
match nothing until the prefix is removed.

**The decisive measurement**, at `6441c1e29`, bare `--list` with no
`--config`:

| Config situation | Mutants |
| --- | ---: |
| repo-root `.cargo/mutants.toml` only (**this is CI**) | 1322 |
| corrected globs planted at `rust/.cargo/mutants.toml` | **1290** |

Planting the file at the workspace root changes the count; the
repo-root file does not. That isolates defect 1 cleanly, and the
1322 → 1290 delta isolates defect 2.

**The trap, recorded because it nearly closed this finding wrongly.**
The earlier reasoning was: CI's auto-set timeout is 5.001 × baseline,
`timeout_multiplier = 5.0` is in the config, therefore the config is
read. This is **wrong**: cargo-mutants' *default* multiplier is also
5.0 (`test_timeout_multiplier.unwrap_or(5.0)`). The configured value
coincides with the tool default, so on that axis an unread file is
observationally identical to a read one. The two earlier probe rows
that both returned 1322 (default discovery, and explicit
`--config ../.cargo/mutants.toml`) returned the same number for
**different reasons** — not-loaded versus loaded-but-globs-inert — and
reading them as one result is what hid defect 1. The probe found the
config only because it was pointed at it explicitly; that is precisely
the axis under test, and CI does not do it.

**Consequence, and why this outranks a 32-mutant miscount.** §4.6 M2's
survivor-triage discipline — *"every entry in `exclude_globs` /
`exclude_re` must cite a substrate-anchored justification"* — is
enforced through a file the gate has never read. Every future entry
written in good faith would silently no-op.

**This also reshapes MR-DQ-8.** Pinning `test_package` in
`.cargo/mutants.toml` at its current location would be a **no-op that
reads as fixed** — reproducing, inside the fix, the exact failure mode
this round exists to end. Placement is therefore a prerequisite of
MR-DQ-8 option C, not a detail of it.

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
   `test_package`, and the workflow invocation passes neither flag —
   and per MR-F2′ that file is not read in CI regardless.

The dependency direction seals it: the harness path-depends on the
verifier (`rust/shekyl-randomx-differential/Cargo.toml`), so a
verifier mutant is judged solely by the verifier's own tests. Nothing
in the harness executes.

**Why it matters.** M2's T-A1 layer is defined as: weaken the
byte-equality assertion, and mutants it used to catch now survive. That
signal requires harness tests to run against verifier mutants. They
never do — so **M2's layer of the T-A1 defense is not operative as
configured.** A weakened `assert_eq!(rust_hash, c_hash)` in
`mode_correctness.rs` cannot change the survival count of a single
`vm.rs` mutant.

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

### MR-F12 — assertion macros are invisible to the tool, so M2's T-A1 mechanism was never possible

**This is the round's largest finding, and it subsumes MR-F5.**

cargo-mutants does not mutate macro invocations. Its own book is
explicit: *"cargo-mutants does not currently mutate calls to macros, or
the expansion of a macro."* Structurally: the visitors are syn `Visit`
impls over typed expression nodes, and a macro call parses as
`Expr::Macro` whose body is an unparsed `TokenStream` — there is no
`Expr::Binary` inside it to visit.

**Confirmed empirically on this branch**, which is the evidence that
matters because it rules out "currently" having changed:

| Site | Contents | Mutants generated |
| --- | --- | ---: |
| `cache_precondition.rs:378` | `debug_assert_eq!(prev_start + prev_bytes.len(), …)` | **0** |
| `cache_precondition.rs:364` | `-` in ordinary code | 1 |
| `cache_precondition.rs:379` | `-` in ordinary code | 1 |
| `cache_precondition.rs:389` | `>` in ordinary code | 1 |

Structurally identical arithmetic, one inside a macro and the rest not.
Only the non-macro sites are mutation sites. (Two mutants *anchor* at
lines that happen to hold a `debug_assert` — `:156`, `:286` — but both
are whole-function-body replacements reported at the function's first
statement, not mutations of the macro.)

**The consequence for §4.6 M2.** Its flagship T-A1 mechanism is *"weaken
the byte-equality assertion and mutants it used to catch now survive."*
The artifact under attack — `assert_eq!(rust_hash, c_hash)` — **is not
a mutable expression**. The mechanism could not fire at any scoping, any
profile, any budget. MR-F5 diagnosed a scoping defect
(`TestPackages::Mutated`) and that diagnosis is correct, but it sits
downstream of this harder fact: fix the scoping perfectly and the
mechanism still cannot fire, because the target is invisible to the
tool. **The 2g plan specified a defense whose stated mechanism the
chosen tool cannot implement.**

#### What this makes item 1

Item 1 was recorded as a testability refactor. It is more than that:
moving the verdicts out of macro-space into functions returning
`Result` is what made them **visible to the gate at all**. The §6.6
result — 9/9 on the verdict surface — is the first time in this
project's history that the T-A1 surface has been mutation-reachable,
and §6.6's phrase "not a low kill rate, an unreachable branch set" is
more literally true than it was written: the branches were not merely
untested, they were not *there* in the sense the tool operates on.

#### The construction constraint this generates

> **Harness verdicts are functions returning `Result`, never bare
> assertion macros.**

This is the invariant item 3's ratchet silently depends on. A future
comparison written as a bare `assert_eq!` drops out of the gate's
coverage **without changing a single number** — the survivor count
stays clean because the surface vanished. That is this round's
signature failure mode (a gate that reads as armed) in its purest form,
and it would be undetectable by inspection of the gate's own output.

Enforcement, not documentation, is the answer — the doc line is the
thing that decays. A grep gate over the verdict modules in
`scripts/ci/check_randomx_crate_invariants.sh`, in the shape that
script already uses, costs one rule and fails loudly.

#### Retraction recorded

A prior review turn raised a `debug_assert`-under-release-profile
hazard — that release builds compile the assertions out, manufacturing
unkillable survivors, and that item 3 therefore needed either a
class-level `exclude_re` or a debug-profile lane. **That hazard does
not exist**, for the reason above: those expressions are not mutation
sites in *either* profile. The proposed `exclude_re` would have been a
skip-list entry defending against a class that cannot occur — a
justified-sounding exclusion covering nothing, which is precisely the
shape this round exists to catch. It is recorded rather than deleted
because a withdrawn hazard that leaves no trace invites its own
rediscovery.

### MR-F6 — every `workflow_dispatch` launches the doomed mutants job

The job's condition is:

```yaml
if: github.event_name == 'schedule' && github.event.schedule == '0 6 * * 1' || github.event_name == 'workflow_dispatch'
```

`&&` binds tighter than `||`, so this parses as
`(schedule && monday-cron) || dispatch` — **any** dispatch runs
mutants, including a `parity_scope=full` parity-recovery dispatch that
has nothing to do with T18. Each such dispatch spends a 6-hour runner
on a run guaranteed to red.

This is corroborated rather than theoretical: the job's only execution
ever (`31346130482`) was a `workflow_dispatch`, not the Monday cron.

The house pattern already exists in this same workflow — `runtime-modes`
is gated on an explicit `inputs.runtime_modes` boolean precisely so a
dispatch does not spend a runner on an unrelated leg. Mutants should
take the same shape.

### MR-F7 — the tool version is unpinned

```yaml
run: cargo install cargo-mutants --locked
```

`--locked` pins cargo-mutants' *own dependency tree*, not the
cargo-mutants **version**. Every behavior this round calibrates
against — the 5.0 default timeout multiplier, `TestPackages::Mutated`
scoping, shard semantics, config discovery, and the measured
per-mutant costs — can shift silently under the gate on any release
day.

Given that this round's findings are *specifically* about defaults
that were load-bearing without being pinned (MR-F5, and the
multiplier trap in MR-F2′), leaving the tool version floating would
re-arm the same class of failure. Pin `cargo-mutants@<version>` so a
bump is a reviewed change.

### MR-F8 — cadence language is a fossil

`.cargo/mutants.toml`'s header says *"Cadence: nightly only"* in five
places and refers to a `mutants-nightly` job that does not exist; the
2g plan §5.5.6 row likewise says nightly. The landed cadence is
**weekly, Monday 06:00 UTC**. Low severity on its own, but it is
documentation that describes a gate other than the one running, and it
belongs in the same amendment as MR-DQ-1 rather than a separate sweep
(rule 91's sweep-the-indexes clause).

### MR-F9 — the corpus never grows, and that is the gap T18 was hired to cover

`corpus_random.rs` generates the "random" corpus from
`ChaCha20Rng::from_seed(RANDOM_CORPUS_SEED_V1)` — a pinned constant
(`SHA-256("shekyl-randomx-differential-corpus-v1")` per §3.18 R6-D1).
Deterministic by design, and the rationale is sound in itself
(reproducible failures, T9 byte-stability).

The consequence compounds, though. Five lanes — x86 per-PR, x86 cron,
native-arm per-PR, native-arm cron, full-dataset parity — re-verify the
**same 1024 pairs**, every branch, every day since 2g landed. Total
input space ever explored by the project's flagship consensus gate:
1024 random pairs plus 8 adversarial recipes, **constant**.

Meanwhile the C oracle is built in every one of those lanes, and
`--mode=latency` already prices 1024 interleaved rust+C pairs at
10–20 min. **A never-before-tested input costs about what a re-verified
one costs.**

And the house already knows this pattern. Eight crates carry
`cargo-fuzz` lanes — `shekyl-fcmp`, `shekyl-proofs`,
`shekyl-crypto-pq`, `shekyl-engine-state`, `shekyl-multisig`,
`shekyl-tx-builder`, `shekyl-daemon-rpc`, `shekyl-archival-retention`.
`shekyl-pow-randomx` is **not** among them. The one crate with a free,
executable, byte-exact reference oracle — the ideal differential-fuzz
target — is the one without a fuzz lane.

§4.5 T-A9's own disposition concedes that "no finite corpus can prove
spec-equivalence." True, and beside the point: **a static finite corpus
and a growing one are not the same object.** A rotating-seed lane moves
the coverage boundary every run. Mutation testing does not move it at
all.

### MR-F10 — the verdict is untestable by construction, so C1 would misreport

`cache_precondition.rs`:

```rust
pub fn assert_equivalent(
    rust_subject: &RustSubjectSession,
    c_oracle: &COracleSession,
) -> Result<(), PreconditionMismatch> {
    …
    if rust_sha == c_sha { Ok(()) } else { Err(PreconditionMismatch { … }) }
}
```

The verdict is two SHA-256 values compared — but the function takes
**live sessions**, so reaching the `Err` branch requires a 256 MiB
Argon2d derive and a linked C oracle. Predictably, there is no negative
test: the module's tests cover `find_first_divergence` and the `Display`
impls; the verdict itself has none. Repo-wide, the harness's only
`#[should_panic]` tests are input validation in
`adversarial/interpreter.rs` and a rationale-format check in
`mode_adversarial_ratio.rs`. **Nothing anywhere induces a divergence and
asserts the harness reports it.** The three call sites
(`mode_correctness.rs` ×2, `mode_latency.rs`) all pass live sessions.

This breaks C1's premise. Mutation testing detects a vacuous assertion
only through a test that fails when the assertion is weakened. Mutate
`rust_sha == c_sha` to `true` and nothing fails — **not** because of an
assertion gap worth acting on, but because the signature forbids the
cheap test. So under C1, harness assertion mutants survive and the
skip-list's first population is a catalogue of **API-shape artifacts**,
each demanding a substrate-anchored justification and a FOLLOWUPS cite
per the M2 discipline. A 12.6 h weekly gate generating paperwork about
a refactor.

**Direct enforcement is cheaper and stronger.** Split the verdict into
a pure `fn verdict(seedhash, rust_sha, c_sha) -> Result<(), PreconditionMismatch>`
with the session-taking wrapper calling it. The negative test is then
three lines and no cache derive. That is
[`19-validation-surface-discipline`](../../.cursor/rules/19-validation-surface-discipline.mdc)
and "make bad states unrepresentable" pointing the same way, and
[`50-testing`](../../.cursor/rules/50-testing.mdc)'s
test-the-production-code rule is satisfied because the wrapper still
runs the real path.

### MR-F11 — the T-A9 leg claims a defense §4.5 says is unavailable

§4.6 M2 asserts verifier mutation "catches more edge-case-mutations
than corpus-bounded byte-equality tests can." Read against §4.5 T-A9's
own text — the harness "cannot defend against this class structurally"
— that is the weaker claim dressed as the stronger one.

The mechanism does not hold either. A surviving verifier mutant means
some implementation variant agrees on the 1024 fixed pairs; for
operator swaps and constant perturbations that is the **expected**
outcome across a large fraction of 848 mutants, and it localizes no
real input. And cargo-mutants' mutation distribution (comparison swaps,
return-value perturbation, branch inversion) is not the distribution of
plausible laundering changes (inlining, constant folding, strength
reduction) — the attack §4.5 actually describes.

§6.5's own reasoning contains the seed of this: survival can only fall
as suites are added. Push it one step and the question becomes *what a
survivor would license you to do* — and for verifier mutants under a
frozen corpus, the answer is "add corpus." Which is MR-F9, reached from
the other direction, and reachable **without** first spending 12.6 h of
mutation.

## 5. Design questions

Each carries a recommendation with its substrate. **None is closed
until ratified.**

### MR-DQ-1 — how is MR-F1 resolved: correct the invocation, or correct the assertion? — **RULED 2026-08-18**

Two coherent regimes exist. (a) Keep `--check` and redefine T18 as a
*build-viability* gate — cheap, but it defends none of T-A1/T-A3/T-A9,
because a mutant that builds tells you nothing about whether a test
would catch it. (b) Drop `--check` from §5.5.6's pinned text,
matching what C10 implemented, and solve the cost problem in
MR-DQ-2–MR-DQ-5.

**Recommendation: (b).** Option (a) preserves the gate's name and
discards its content; the 2g threat table would then cite a mitigation
that mitigates nothing.

**RULING (2026-08-18): (b). Option (a) is not live.** T18's row asserts
survival bounded by the skip-list and names T-A1/T-A3/T-A9 — properties
`[Phase::Check]` cannot observe, since under `check_only` the test
timeout is zero by construction and no test ever runs. Keeping the name
while discarding the content manufactures a documented-but-false gate,
which is the exact failure this round exists to end.

**Amendment scope pinned by this ruling:** §5.5.6's invocation text and
the §6 T18 row are corrected **together**, and the MR-F8 cadence fossil
("nightly" → weekly Monday) folds into the same amendment rather than a
separate sweep. The 2g plan lives in `docs/completed/`, so the
amendment follows the completed-doc convention (§11) — the doc is not
reopened as an active design.

### MR-DQ-2 — per-PR `--in-diff`, weekly whole-crate sweep, or both? — **RULED 2026-08-19**

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

**RULING (2026-08-19): per-PR, converged with item 3 — the
verdict-scoped ratchet IS the per-PR leg.**

The question was posed before §6.6 re-derived item 3's scope, and the
re-derivation collapses it. `--in-diff` was proposed as a way to bound
per-PR cost; at verdict scope no bounding is needed, because the whole
population is **11 mutants in 36 s** (measured; ~58 s on the committed
runner class). That finishes inside the structural job's measured
31–44 min many times over, so the per-PR leg is free in wall-clock
terms and needs no diff-scoping machinery at all.

Two consequences worth stating rather than leaving implicit:

- **`--in-diff` is not adopted.** It would have served T-A9 (§3.1),
  and per MR-F11 T-A9 is the claim this regime no longer makes. Adding
  diff-scoping to bound a 36-second job would be machinery bought for
  a threat the gate does not defend.
- **Paths filtering is inherited, not re-declared.** The workflow-level
  positive `pull_request: paths:` filter (R1-D12) already means an
  unrelated PR never triggers the workflow, so it never pays the
  C-reference build — the one real cost. The structural job relies on
  exactly the same mechanism and carries no filter of its own;
  re-declaring one at job level would be a second source of truth for
  the same decision.

The periodic whole-crate sweep stays **HELD** under MR-DQ-8, unchanged.

### MR-DQ-3 — release-mode or debug-mode per-mutant test runs?

The FOLLOWUPS entry proposes `cargo mutants -- --release` on the
estimate *"~40× faster tests, slower per-mutant rebuilds."* That
number was unmeasured, and the repo contradicts itself about the
direction: `rust_subject.rs`'s docstring claims a cache derive is
*"~150–200 ms in debug; ~5–10 s in release,"* which is backwards for
Argon2d. §2.2.1 settles it by measurement.

**Recommendation: see §2.2.1 and §6** — this question is answered by
the measured build/test trade, not by argument.

### MR-DQ-4 — sharding, and at what denominator? — **DISSOLVED 2026-08-18 (not answered)**

`--shard k/n` is cargo-mutants' designed answer to a per-job wall-clock
ceiling, and composes with `--in-diff` and with filters so long as
every shard sees identical arguments. It converts a wall-clock problem
into a runner-cost problem. The denominator falls out of §2.2.1's
per-mutant cost against the 360-minute ceiling, with margin.

**DISSOLVED, with reasoning — a struck row reads as abandoned and the
next reader re-asks it.** A denominator is only meaningful over a
population where survival is *informative*. Once item 3's scope is the
verdict functions (§6.6), every mutant in the population is
informative, the run is seconds, and the ratio carries no information
the raw list does not. There is nothing left to divide.

**But the ratchet still needs a guard — a different one.** At 9 mutants
and seconds of runtime the failure mode is not budget, it is **the
scope regex silently matching nothing**. `--re` targeting is name-based,
so a renamed verdict function yields a *clean green run over an empty
set* — the round's signature failure mode once more, this time inside
the fix. The fail-loud shape is a **minimum-mutant-count assertion**:
fail if fewer than N mutants were generated. Same defensive pattern as
`ctest --no-tests=error`, already used in the full-parity job.

Superseded recommendation, retained for its reasoning: **shard the
periodic sweep; do not shard the per-PR leg** (an `--in-diff` run small enough to be merge-blocking should not
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

### MR-DQ-6 — how is MR-F3 (branch coverage) closed? — **RULED 2026-08-19**

Options: (a) a `matrix.branch: [main, dev]` on the sweep job, mirroring
`runtime-modes`; (b) rely on the per-PR `--in-diff` leg, which runs on
PRs targeting `dev` and therefore covers `dev` at the moment code
arrives; (c) both.

**RULING (2026-08-19): single leg on `pull_request`, alongside the
cron matrix.** Budget answered the question — measured per-PR critical
path is `structural-validate` at ~26 min, and the rotating mode is
444 s plus ~44 s of setup, so the leg hides inside the existing
critical path: **+8 runner-minutes, +0 wall-clock**.

The argument that decided it is not cost but a gap: **before this leg
no per-PR gate exercised a single input outside the pinned corpus.**
`structural-validate` runs `--mode=correctness` over the pinned corpus,
`native-arm` runs the pinned 1024, the verdict ratchet mutates verdict
functions. A verifier change diverging only *off-corpus* passed every
per-PR gate, landed on `dev`, and waited for a cron that — per MR-R1a —
does not exist until `dev` reaches `main`.

**It is a tripwire, not coverage, and the distinction is pinned in the
type.** The index is days-since-epoch, so every PR on a given day
re-checks the *same* inputs; the per-PR leg advances nothing. A third
provenance `pull-request` was added rather than reusing either sibling,
because both would be untrue: not `schedule-derived` (it advances no
boundary) and not `operator-supplied` (nobody chose the index). Only
`schedule-derived` may ever be credited as coverage (T-A11), asserted
by `only_schedule_derived_counts_as_coverage`.

**No index override on the PR leg**, deliberately: a tripwire whose
index a contributor could choose would let a diff be checked against an
input set the contributor picked (T-A7/T-A11).

**A per-PR red is ambiguous and cheaply disambiguated** — "this PR
broke it" versus "today's index already diverges on `dev`" — by
replaying the same index against `dev`, which is a one-command question
rather than an investigation. That is the derived seed paying off a
second time, and the instruction is in the job comment because a
halt-and-escalate posture with an ambiguous trigger is how false
escalations start.

Superseded recommendation: **(c)**, weighted to (b). The per-PR leg is the real
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

### MR-DQ-8 — how is test scoping pinned (MR-F5)? — **DISSOLVED 2026-08-19**

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

**DISSOLVED (2026-08-19), superseding both the C1 ruling and the hold.**

DQ-8 asks which suite judges a **verifier** mutant: `Mutated` (a),
`test_package = ["shekyl-randomx-differential"]` (b/C1), or
`test_workspace` (c). After item 3 deletes the whole-crate sweep, the
question has **no live subject**. Item 3's scope is
`cache_precondition.rs` + `mode_correctness.rs`, both in
`shekyl-randomx-differential` — **no verifier mutants exist in scope**,
so (a)/(b)/(c) have nothing to decide between, and the rule-21
8-shards×6h trigger has nothing to fire on.

Third instance of one cause, after MR-DQ-2 and MR-DQ-4: a question
posed before §6.6 re-derived the scope, dissolved *by* the
re-derivation rather than answered. Recorded with its reasoning rather
than struck, because a struck row reads as abandoned and the next
reader re-asks it.

**Two obligations survive the dissolution, and both land with item 3:**

1. **Test scoping is pinned explicitly even though the pin equals the
   default.** DQ-8's own text is the binding part — *"the amendment
   must state test scoping explicitly rather than inherit a default —
   that is the specific failure this whole round exists to stop
   recurring."* Under `Mutated`, a harness-crate mutant is judged by
   the harness suite, which is now the eleven negative tests: correct,
   but correct **by luck of scope**. Inheriting it silently would close
   the round by re-committing its founding error with the excuse that
   the default happened to be right this time. The ratchet therefore
   passes `--test-package shekyl-randomx-differential` on both
   invocations, with a comment saying it currently equals the default
   and is pinned anyway. Verified identical: 11 mutants listed, 11
   caught.
2. **The orphaned config is disposed of, not queued.**
   `.cargo/mutants.toml` at the repo root is read by nothing (MR-F2′),
   and once the sweep is deleted its skip-list and multiplier have no
   consumer at all. A file that looks like live configuration and is
   not is the exact artifact that cost this round five sessions —
   rule-15 debris of the worst kind. Item 3 is CLI-only, so it is
   **deleted**, in the same diff.

**Lineage.** Prerequisite 2 of the withdrawn C1 ruling — a structural
guard asserting the config is live, using the 1322→1290 delta — carries
over in *shape* rather than substance: the ratchet's
minimum-mutant-count assertion is the same defensive pattern (a config
present but unread, or a scope present but empty, must fail loudly)
applied to what item 3 actually has. That is the third instance of one
rule, alongside the §13 grep gate and `ctest --no-tests=error`, and the
generalization is what should survive this round.

---

**Superseded hold, retained for its analysis (2026-08-18).** The C1
reasoning below stands *on its own terms* — the timing inversion is
real and C1-over-C2 is correct — but it prices an instrument whose
**yield has never been derived**. The round built a rigorous cost model
and no yield model, and per MR-F10 the yield is predictable: C1's first
survivors are API-shape artifacts, not assertion gaps. Derive-don't-
hardcode applies to test regimes too. Superseded by the re-scope in
§7.5; retained here because the cost analysis feeds item 3.

**Withdrawn ruling, retained for its analysis: C1 — harness-only
scoping — with B as the named fallback.** §6.4 prices it and §6.5 explains why the maximal-looking
option is wrong:

- **C1 costs less than the status quo** (12.6 h vs 23.9 h CI, 5 shards
  vs 8), because the harness suite is 2.4× cheaper than the verifier's.
- **C1 is the only configuration where the T-A1 signal exists**, because
  it is the only one where the harness assertion is the sole judge.
  C2 ("run both suites") re-masks the signal exactly as today.

**Two prerequisites, both of which must land with the ruling:**

1. **Placement is a prerequisite, not a detail (MR-F2′).** Pinning
   `test_package` in `.cargo/mutants.toml` at its current repo-root
   location would be a **no-op that reads as fixed** — the fix
   reproducing the round's own failure mode. The file moves to
   `rust/.cargo/mutants.toml` (where the tool reads it) with the dead
   `rust/` glob prefix removed **in the same motion**. Policy stays in
   the config file rather than on the CLI: the file already hosts the
   skip-list discipline, so it should own scoping too — one source of
   truth, relocated to where it is actually read.
2. **A structural guard, so this cannot silently regress.** The
   crate-invariant script (or the job itself) asserts that
   `rust/.cargo/mutants.toml` exists **and** that the excludes are
   live — the measured 1322 → 1290 count delta is a ready-made
   assertion. A config that is present but unread must fail loudly.

**Rule-21 reversion trigger, named now rather than left implicit:** if
the priced regime ever exceeds **8 shards × 6 h**, fall back to B,
amend §4.6 M2 in the same PR to stop claiming the T-A1 layer, and queue
C1 in `docs/FOLLOWUPS.md` with the timing evidence attached. C1 sits at
5 shards today, so the trigger has 60% headroom against measured cost.

The decision rule behind all of this: an inoperative-but-documented
gate is recoverable; an inoperative gate described as operative is
not — and that principle has to survive the fix's own wiring, which is
what prerequisite 1 protects.

**Deliberately left open for implementation-time measurement:** C1's
first run is expected to surface genuine survivors (§6.4), since
verifier mutants stop being judged by the verifier's fast unit tests.
The skip-list's intended first use is triaging that output. The
implementation PR reports the survivor count; it is not pre-declared
here.

## 6. Option matrix

### 6.1 The empirical per-mutant cost

Probe: `--shard 0/128` of the repaired 1290-mutant set, release
profile, default (`Mutated`) scoping, `--in-place`, on the local box.

```text
Found 11 mutants to test
ok  Unmutated baseline in 1s build + 45s test
INFO Auto-set test timeout to 230s
11 mutants tested in 8m: 9 caught, 2 unviable
```

| Quantity | Value |
| --- | ---: |
| Mutants in shard | 11 |
| Outcome | 9 caught, 2 unviable, **0 survivors** |
| Mean per mutant (all) | **41.2 s** |
| Mean per mutant (viable only) | 50.2 s |
| Unviable fraction | 0.18 |
| Per-mutant build phase | ~1.0 s |
| Per-mutant test phase | ~45–53 s |

The build phase is negligible (~1 s incremental) — the FOLLOWUPS
entry's worry that release mode would cost "slower per-mutant rebuilds"
does not materialize at this scale, because only the mutated crate
rebuilds and the link is warm. **Per-mutant cost is essentially the
test suite.**

### 6.2 Sizing constants

- `N` = **1290** mutants (skip-list repaired, MR-F2)
- local mean per mutant, release, default scoping = **41.2 s**
- CI hardware factor = **1.58×** → **65.1 s** per mutant on CI
- debug/release factor = **12.1×**
- shard ceiling = **360 min = 21 600 s**
- assertion-bearing slice = **305** mutants; verifier = **848**;
  harness = **442**

### 6.3 The matrix

Every row assumes MR-F2 repaired (1290, not 1322) and MR-F1 resolved
per MR-DQ-1(b).

| # | Regime | CI cost | Shards @ 6 h | T-A1 / T-A3 | T-A9 |
| --- | --- | ---: | ---: | --- | --- |
| **A** | **Status quo** — debug, default scoping, serial, unsharded | **~282 h** | 47 | partial (assertion modules only) | ✓ |
| **B** | Release, default scoping, sharded | **~23.3 h** | **6** (≈3.9 h each) | partial (assertion modules only) | ✓ |
| **C1** | Release, **harness-only scoping**, sharded | **~12.6 h** | **5** | **✓ (M2 layer operative)** | ✓ |
| **C2** | Release, **both-suites scoping**, sharded | ~41.9 h | 14 | masked — see §6.5 | ✓ |
| **D** | Per-PR `--in-diff`, release, unsharded | minutes (bounded by diff) | 1 | ✗ (§3.1) | **✓ at arrival, incl. `dev`** |
| **E** | Release, **assertion-module slice only** (305), sharded | **~5.5 h** | 1 | ✓ direct signal | ✗ |

Row A is what runs today, and it is the arithmetic that explains the
timeout: 282 h against a 6 h ceiling is not a budget overrun, it is a
regime that could never have completed. **The single largest lever is
the profile** — release alone takes A to B, a 12.1× reduction, and is
the difference between "needs 47 runners" and "needs 6."

Row E is notable: the slice that carries the *direct* T-A1/T-A3 signal
fits in a **single** unsharded job with margin. That makes an
assertion-module sweep affordable at a much tighter cadence than the
full sweep.

### 6.4 Pricing corrected scoping (row C)

Per-crate release suites, measured separately on the local box (same
`--skip canonical_pins_full` as CI):

| Suite | Wall | Note |
| --- | ---: | --- |
| `shekyl-pow-randomx` alone | **63 s** | 130 passed, 2 ignored |
| `shekyl-randomx-differential` alone | **26 s** | 90 + 35 + 3 + 1 passed; the 17.4 s binary is the differential integration leg |

**This inverts the expected trade.** The assumption behind "corrected
scoping costs more" was that the differential is the expensive side. It
is not: the harness suite is **2.4× cheaper** than the verifier's own.

Per-mutant cost model, with the measured 0.18 unviable fraction (an
unviable mutant pays build only, ~1 s):

`c = 0.82 × (build + suite) + 0.18 × build`

| Scoping | Suite(s) per mutant | `c` (local) |
| --- | --- | ---: |
| `Mutated` (today) | verifier 63 s / harness 26 s by crate | 52.7 s / 22.3 s |
| `Named(["shekyl-randomx-differential"])` | harness 26 s for **every** mutant | **22.3 s** |
| `Named([both])` | 89 s for every mutant | 74.0 s |

Scaled by the 1.58× CI factor and sharded by the §7.4 rule:

| Row | Regime | CI cost | Shards (§7.4 rule) |
| --- | --- | ---: | ---: |
| **B** | `Mutated` (today's scoping) | 23.9 h | 8 |
| **C1** | harness-only scoping | **12.6 h** | **5** |
| **C2** | both-suites scoping | 41.9 h | 14 |

**C1 is cheaper than the status quo *and* wires the T-A1 layer.**

### 6.5 Why C2 ("strictly stronger") is in fact weaker for T-A1

C2 looks like the safe maximal choice and is not, because T18's
assertion is *survival*, and running more suites can only **reduce**
survivors. A verifier mutant caught by the verifier's own unit tests is
caught under C2 no matter what the harness does — so weakening the
harness assertion changes nothing, and the T-A1 signal is masked
exactly as it is today (MR-F5).

The signal exists only where the harness assertion is **load-bearing**
— i.e. where it is the sole judge. That is C1.

| Row | T-A1 signal from a weakened harness assertion |
| --- | --- |
| B | none from verifier mutants (MR-F5); residual from the 305 assertion-module mutants only |
| **C1** | **present** — verifier mutants survive when the assertion stops catching |
| C2 | masked again — verifier unit tests catch regardless |

So "add more tests to be safer" is the wrong instinct for a mutation
gate. C1 wins on cost *and* on the property the gate exists to
provide, which is a rare enough alignment to state explicitly rather
than leave the reader to infer.

**The honest cost of C1**, which ratification should price in: verifier
mutants stop being judged by the verifier's fast unit tests, so mutants
the differential corpus does not exercise will **survive**. The first
run may well be red with real survivors. That is not a regression — it
is precisely the assertion-gap discovery §4.6 M2 promises, arriving for
the first time. It does mean the first run's output is a triage
workload, and the skip-list discipline finally gets its intended first
use.


---


### 6.6 Post-item-1 measured yield (re-derivation, not inheritance)

Item 1 landed on `feat/randomx-verdict-negative-tests` (`1cbb21fab`).
Row E's yield was re-measured against it, per the §7.5 rule that row
E's **cost** carries over but its **yield** must not be inherited.

`cargo-mutants` over the two refactored files, release profile,
`Mutated` scoping:

| File | Mutants | Caught | Missed | Unviable | Wall |
| --- | ---: | ---: | ---: | ---: | ---: |
| `cache_precondition.rs` | 58 | 45 | 13 | 0 | 4 min |
| `mode_correctness.rs` | 38 | 12 | 24 | 2 | 5 min |

Split by surface — this is the number that matters:

| Surface | Mutants | Caught | Kill rate |
| --- | ---: | ---: | ---: |
| **Verdict functions** (the T-A1 surface) | 9 | **9** | **100%** |
| Everything else in the same files | 27 | 3 | 11% |

Every mutant on both new pure functions dies:
`three_leg_verdict -> Ok(())`, `cache_canonical_verdict -> Ok(())`,
both `!=` → `==` flips, and all four match-guard forcings
(`true`/`false` on each guard). Before item 1 that surface had **zero**
killable mutants — not a low kill rate, an unreachable branch set.

#### What the survivors actually are, and what it means for item 3

The 24 misses in `mode_correctness.rs` are **not** verdict mutants.
They are loop and index arithmetic inside `run` (corpus-subset
slicing, `+= 1` counters) plus a `Display` impl — and `run` requires
live sessions, so no unit test reaches it. The 13 misses in
`cache_precondition.rs` are the same shape: `byte_diff` /
`build_divergence_window` arithmetic, plus `rust_cache_sha256`
returning a constant, plus the `assert_equivalent` wrapper.

So the residual is **MR-F10 one level up**: orchestration is
untestable without the expensive path, exactly as the verdicts were.

**This refines item 3's scope, and the refinement is measured rather
than argued.** "Assertion modules only" is still too broad — those
modules are dominated by orchestration whose survivors are the API-
shape artifacts MR-F10 predicted. The scope that carries signal is the
**verdict functions themselves**, which `cargo-mutants` can target
directly with `--re`. At 9 mutants and ~10 s each, that lane is
**seconds, not shards** — and its claim is exactly the narrow true one
§7.5 item 3 specifies: *the negative tests are load-bearing.*

This also answers MR-DQ-4 by dissolving it: a verdict-scoped ratchet
needs **no denominator at all**. Recorded here rather than
dispositioned, per the ratification note that MR-DQ-4 be re-derived
once item 1 exists.


#### The `assert_equivalent -> Ok(())` survivor, justified properly

This mutant is the T-A1 attack applied one layer up, so its skip-list
entry must name **both** halves rather than stopping at "the wrapper
still needs live sessions":

- **What still bites.** The hash-comparison legs are independent of the
  cache precondition, so a dead precondition does not blind
  `rust == c` or `rust == canonical`. A divergence still surfaces.
- **What stops biting.** Cache-level divergence between the two
  implementations goes undetected *until* it manifests as a hash
  divergence — which it will, but later and with materially worse
  diagnostics (the operator loses the R1-D14 fingerprint and the
  `--debug-cache-divergence` offset window).

A narrow, honest, non-zero residual. Stating both halves is what stops
a future reader from either over- or under-crediting the skip. Item 1
already minimised it by construction — the smaller the wrapper's body,
the less a wrapper mutant can hide — and that is the principled
stopping point, not a compromise.

#### Ordering-as-triage-routing is its own property class

The leg-ordering test (§7.5 item 1) generalises past the case it
covers. A verdict that evaluates the canonical leg first is **green on
every equality property** and still wrong: it routes a genuine rust/C
divergence to a *canonical-regeneration* PR instead of the §7.3
consensus escalation. The defect is not in what the code computes but
in **which incident class it declares**, and no equality assertion
catches it.

That failure mode recurs anywhere the harness maps a comparison result
onto a triage path — the concurrent mode's cross-worker-versus-rust/C
distinction and the adversarial-ratio mode's category assignment are
the immediate other instances. Pinned here as a property class so it is
tested deliberately rather than rediscovered.

#### A yield the round did not predict

Nine of `cache_precondition.rs`'s survivors are arithmetic in
`byte_diff` / `build_divergence_window` — functions that **do** have
tests (`find_first_divergence_*`, `build_divergence_window_*`), which
pass while the arithmetic is mutated. Those tests assert something
weaker than the arithmetic they cover. That is a real assertion gap,
found in four minutes on one file, and it is the first genuine
T18-style yield the project has produced.

It qualifies MR-F10 in one direction worth stating: outside the verdict
surface the yield is **not** purely paperwork. It does not revive C1 —
these are diagnostic-path helpers, not the T-A1 surface, and finding
them cost minutes rather than 12.6 h — but "mutation testing here
produces only artifacts" would be too strong a reading of MR-F10, and
the record should not overstate it.

Filed as its own item per rule 19 (different validation surface); not
fixed in item 1.

---

## 7. Recommended regime

**Not binding until §5 is ratified.** Recorded now so ratification is a
decision about a concrete proposal rather than an open field.

### 7.1 Two legs, mapped to the threats they actually detect — **SUPERSEDED by §7.5**

**Leg 1 — per-PR `--in-diff` (merge-blocking).** Release profile,
unsharded, mutating the diff of the PR against its base. Bounded by
change size, so it runs in minutes and can block a merge. Detects
**T-A9** at the moment new code arrives, and — because PRs target
`dev` — it is also the part of MR-F3's fix that matters, putting
mutation coverage on `dev` for the first time.

**Leg 2 — periodic sweep (sharded).** Release profile, `--in-place`
per shard, `--shard k/n` across a matrix, on both `main` and `dev`.
Carries **T-A1/T-A3** (per §3.1, the surface the assertion covers) and
backstops **T-A9** across code that reached `dev` without a PR.

### 7.2 Pins

| Item | Value | Source |
| --- | --- | --- |
| Profile | `--profile release` | MR-DQ-3; §6.2 — the single largest lever (12.1×) |
| Mutant set | 1290 (skip-list repaired) | MR-F2 / MR-DQ-7 |
| `--check` | **removed** from §5.5.6's pinned text | MR-F1 / MR-DQ-1(b) |
| Test scoping | `test_package = ["shekyl-randomx-differential"]`, explicit | MR-F5 / MR-DQ-8 (C1) |
| Config location | **moves** to `rust/.cargo/mutants.toml` + guard | MR-F2′ / MR-DQ-8 |
| Dispatch trigger | boolean input, house `runtime_modes` pattern | MR-F6 |
| Tool version | `cargo-mutants@<pinned>` | MR-F7 |
| Parallelism | sharding, not `--jobs`; `--in-place` retained per shard | MR-DQ-4 / MR-DQ-5 |
| Branch coverage | leg 1 covers `dev` inherently; leg 2 carries a `[main, dev]` matrix | MR-F3 / MR-DQ-6 |
| Skip-list | repaired **and** guarded by a liveness assertion | MR-DQ-7 |

### 7.3 The one genuinely open trade

MR-DQ-8 is the decision that changes what the gate *means*, and §6.4
prices it:

- **Row B** (keep `Mutated` scoping) is cheap and honest-if-documented,
  but M2's T-A1 layer stays inoperative and the 2g threat table must be
  amended to stop claiming it.
- **Row C** (verifier mutants judged by the harness suite) implements
  M2 as written, at higher per-mutant cost absorbed by a larger shard
  denominator.

**RULED (2026-08-18): C1**, per MR-DQ-8. §6.4 priced it below the
status quo (12.6 h / 5 shards vs 23.9 h / 8), and §6.5 showed C2 —
the maximal-looking option — re-masks the very signal the fix exists to
restore. Reversion trigger per
[`21-reversion-clause-discipline`](../../.cursor/rules/21-reversion-clause-discipline.mdc):
**if the priced regime exceeds 8 shards × 6 h**, fall back to B, amend
§4.6 M2's T-A1 claim in the same PR, and queue C1 in FOLLOWUPS with the
timing evidence — never leave the threat table asserting a layer the
regime does not run.

Two prerequisites ride with it (MR-DQ-8): the config file **moves** to
`rust/.cargo/mutants.toml` with the dead glob prefix removed, and a
structural guard asserts the excludes are live. Without the move, the
scoping pin is a no-op that reads as fixed.

### 7.4 Sizing rule (so this does not recur)

The failure this round fixes is a budget written once from intuition
and never re-derived. So §7 pins a **rule**, not just a number:

> Shard denominator `n` = `ceil(N × c × f / (0.5 × ceiling))`, where
> `N` = mutant count, `c` = measured local mean per-mutant cost, `f` =
> the CI hardware factor, and `ceiling` = 21 600 s. The 0.5 keeps a
> 2× margin.

The test plan (§9) asserts this arithmetic against the live mutant
count, so the gate reds when the suite outgrows its shards **as a
loud assertion**, not as a six-hour timeout.

---


### 7.5 Re-scope: three separable items (supersedes §7.1)

The re-scope follows from MR-F9–MR-F11: T18 is the wrong instrument for
two of its three claimed jobs, and the instrument that was missing is
the one the house already uses in eight other crates.

Procedural freedom worth naming: **T18 has never produced a verdict**,
so no skip-list exists, no survivor has ever been dispositioned, and
nothing downstream consumes a T18 result. There is no regression risk
in re-scoping and no sunk verdict to preserve.

**Item 1 — verdict-path testability + negative tests.** Refactor
`assert_equivalent` and the analogous verdict points
(`mode_correctness.rs` ×2, `mode_latency.rs`) into pure `verdict(…)`
functions with session-taking wrappers; add induced-divergence negative
tests. **Minutes of CI, per-PR, runnable locally.** This delivers the
T-A1 defense *structurally* rather than detecting its absence weekly.
Per [`50-testing`](../../.cursor/rules/50-testing.mdc)'s
coverage-boundary rule each test carries a "bites against X; does NOT
cover Y" rationale.

**Item 2 — rotating-seed differential lane (new T#).** Fresh seed per
run, derived from run ID or date; N new pairs against the C oracle;
halt-and-escalate on divergence, the posture already pinned for the
concurrent and arm lanes. Two properties make this the ratchet the plan
has been missing:

1. the seed is **recorded in the run**, so any divergence is
   reproducible — preserving the T9 rationale that motivated the fixed
   seed in the first place;
2. any divergent pair found is **promoted into the adversarial corpus**
   (§7.9 MR-R2), under the ordering in §7.9 MR-R3.

Budgeted against the same runner-hours C1 wanted, this buys thousands
of genuinely new pairs per week instead of zero.

**Claim discipline — the *explored* boundary advances, the *pinned* one
does not.** An earlier draft of this item said "leg-3's coverage
boundary actually advances," which is true of exploration and false of
the pinned corpus: the pinned corpus grows **only on divergence**,
which — if the verifier is correct — is never. The lane's value is
exploration. Its `50-testing.mdc` coverage-boundary rationale, which
belongs verbatim in the T# row and not only here:

> *Bites against spec-non-equivalence on inputs outside the pinned
> corpus. Does **not** grow the regression corpus absent a finding, and
> does **not** prove spec-equivalence at any sizing.*

Without that negative half stated in the row itself, a reader eighteen
months out sees "corpus lane, weekly" and credits it with accumulation
it does not do — the exact decay this round exists to stop.

**Item 3 — mutation as a narrow ratchet, after item 1.** **Scope
re-derived post-item-1 in §6.6: the verdict functions, not whole
assertion modules.** The modules are dominated by orchestration whose
survivors are API-shape artifacts; the verdict functions kill 9/9. At
that scope the lane is seconds, needs no sharding, and MR-DQ-4
dissolves rather than being answered. Re-derive against the §6.3 row-E slice — **but note row
E was measured before item 1 exists**, so its survivor profile will
change substantially. Precisely: row E's **cost** carries over, its
**yield** does not. After item 1 some fraction of those 305 mutants
become genuinely killable, so the survivor profile must be
**re-measured post-item-1, never inherited** — that is this round's own
trap in miniature, named here so it is not walked into twice. The claim then becomes narrow and true, and per MR-F12 it has **two**
halves rather than one:

> Item 3 asserts that the harness's verdicts **stay mutation-reachable**
> (they remain functions, not macros) **and** that their negative tests
> **stay load-bearing**. It makes no T-A9 claim.

The first half is new and is the one MR-F12 forces: before item 1 the
verdicts were not reachable at all, so "the tests are load-bearing" was
not merely unverified, it was unaskable. §4.6 M2's amended text must
say that its original T-A1 mechanism was **unavailable by construction
until item 1**, not merely mis-scoped — MR-F5's scoping defect is real
but downstream.

Guarded by the minimum-mutant-count assertion (MR-DQ-4), without which
a rename turns the whole lane into a clean green over an empty set.


### 7.9 Item 2 construction requirements (MR-R1–MR-R4)

Item 2 carries the least design and the subtlest failure modes. These
four are **construction requirements**, not nice-to-haves: each is a
property the lane must have on the day it lands.

#### MR-R1 — a rotating seed makes its own red self-erasing — **REVISED: derive the seed, do not draw it**

**The hazard.** Under a pinned corpus a red reproduces on every rerun,
so rerun-until-green is bounded by not working. Under a seed drawn from
fresh entropy, **rerunning does make it green** — with a different,
innocent input set — and the run looks identical in the UI. Every
halt-and-escalate posture in this workflow (concurrent, native-arm)
rests implicitly on a reproducibility that a fresh-entropy lane
removes.

**The first countermeasure, now downgraded.** Artifact-uploading the
emitted `FailureOutput` line is the house pattern
(`economics-c2a-prime.yml`: `if: failure()`, run-id-named,
`retention-days: 14`) and it *works*. But it is the weak form: a
consensus divergence is the one finding class whose record must outlive
any retention window, and 14 days — or 90 — is a countdown on evidence
that may not be read in time. It also makes recoverability depend on CI
infrastructure state rather than on a property of the design.

**The revision: make the seed a deterministic function of a time
index.**

```text
seed(i) = cSHAKE256("shekyl/randomx-rotating-corpus-v1", i)[..32]
```

where `i` is a stable integer — ISO week number, or days-since-epoch —
computed **once at lane start** and emitted in the M4 banner.

This keeps every property that motivated pinning
`RANDOM_CORPUS_SEED_V1` in the first place — reproducible CI failures,
T9 byte-stability, and the runtime-recompute-from-source-string
discipline whose own rationale reads *"a hard-coded hex pin would pass
even if the constant and the source-string comment drifted apart"* —
while making coverage **monotonic instead of constant**. Week 47's
input set is reconstructable in three years by anyone, offline, from
the integer alone. No artifact, no retention, no CI archaeology.
**MR-R1 does not get mitigated; it stops existing.**

Three consequences, pinned explicitly:

1. **It fixes rerun-until-green in the right direction.** A same-day
   rerun regenerates the *same* set, so the red reproduces — the
   property the fixed corpus had and that fresh entropy would have
   thrown away. A rerun the following day gives a different set, so the
   triage rule is **"replay by index,"** never "re-run the lane," and
   the banner is what makes the distinction auditable.
2. **Compute `i` once at process start, not per mode.** A lane
   straddling midnight UTC that re-derives mid-run produces a run whose
   banner index does not describe all of its own inputs — a record that
   lies while looking complete.
3. **It largely dissolves MR-R4.** See below.

**Prohibition — do not retrofit the pinned corpus into the sequence.**
The elegant-looking unification ("the pinned corpus is just index 0")
is a trap. `RANDOM_CORPUS_SEED_V1` is
`SHA-256("shekyl-randomx-differential-corpus-v1")`, re-derived at
runtime by `tests::seed_v1_matches_source_sha256`, and all 1024
`CANONICAL_RANDOM_HASHES` entries plus 32 `CANONICAL_CACHE_SHAS`
entries are **positionally bound to that seed**. Any redefinition
invalidates the entire canonical table and every pin gate consuming it,
across five lanes. The rotating sequence is a **separate,
domain-separated namespace that never touches the v1 derivation.**
Stated as a prohibition rather than an omission because the
unification is exactly what a later reader proposes as cleanup.

**Domain-separator registration is mandatory, not optional.**
`shekyl/randomx-rotating-corpus-v1` is a new cSHAKE domain separator,
so it registers in
[`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv) (SA-3b, 207
rows at time of writing) in the **same PR** that introduces it, and
`scripts/ci/domain_registry_gate.sh` enforces the row-presence and
const-binding tripwires. Note the gate reads comment-stripped source
precisely so a doc comment quoting the literal cannot keep it green
after the definition moves — the same discipline §13 names.

**Where the artifact upload still earns its place: forensics, not
recovery.** The 11-field `FailureOutput` schema carries `rust_hash`,
`c_hash`, both cache SHAs, `class_tag`, `harness_version` and
`fork_pin`. The *inputs* are reconstructable from the index; the
*observed outputs on that runner at that toolchain state* are not — and
for a divergence that later fails to reproduce locally, that delta is
the whole investigation. So: keep the `if: failure()` upload at the
house shape, raise retention to the maximum, and let

> **the index carry recoverability, the artifact carry forensics.**

That division goes in the doc because it tells the next reader **which
one they are allowed to lose.**

#### MR-R1a — no pre-`main` run advances the explored boundary

A consequence of MR-F3 applied to the rotating lane itself, recorded
because it is invisible from a run history.

Schedule events use the **default branch's** workflow file. Until the
lane exists on `main` it therefore has **no scheduled execution at
all**, and every run is a dispatch. Every dispatch is
`operator-supplied` by construction (MR-R4). So in the pre-`main`
window:

- the **explored boundary does not advance**, at all;
- **no green run may be credited as coverage**, ever.

The hazard is not the delay, it is the record. A run history full of
green `operator-supplied` rows reads like coverage to any reader who
was not present when the lane landed — the same decayed-claim shape
§13 names, arriving through the lane built to fix it. The workflow
comment carries this text too, so the reader who checks the job rather
than the doc also finds it.

#### MR-R2 — the promotion target is the adversarial corpus, not the random one

"Promote into the pinned corpus" cannot mean the random corpus. That
corpus is seed-derived and positionally index-coupled:
`canonical_outputs.rs` asserts
`CANONICAL_RANDOM_HASHES.len() == NIGHTLY_SEEDHASH_COUNT * NIGHTLY_DATA_PER_SEEDHASH`
and `CANONICAL_CACHE_SHAS.len() == NIGHTLY_SEEDHASH_COUNT`. Appending a
pair breaks the length invariant and desynchronises the index mapping.

The correct destination exists and is better shaped: `adversarial_corpus.rs`
(T10-pinned `ADVERSARIAL_CORPUS_SHA256`, per-class arrays, the
`Category N:` rationale requirement) plus its
`adversarial_canonical_outputs.rs` counterpart. A new
**divergence-discovered** class inherits the whole pin-and-justify
discipline for free, and makes the promotion PR reviewable in the shape
§4.6 M1 already specifies for canonical regeneration.

Corroboration from source: `canonical_outputs.rs` records that the
adversarial corpus "stays empty through 2g per §3.19 R7-D4 (post-2g
design round decides the replacement methodology)." **This is that
round.** The destination was designed to be decided here.

**Provenance inherited from MR-R1's revision, for free.** With an
index-derived sequence a promoted entry cites `(index, pair position)`
— a complete, checkable **derivation** of where the input came from,
not an assertion that it came from somewhere. A reviewer regenerates
the pair from the citation and confirms it is what the lane actually
saw, rather than trusting the claim. That discharges the T-A2
pin-and-justify discipline with a derivation, which is the stronger
form and is available here at no cost. (Under fresh entropy the best
available provenance would have been "found by fuzzing," which is an
assertion.)

#### MR-R3 — promotion ordering, or the wrong value gets pinned

At the moment of discovery `rust != c`, and **neither leg is
authoritative** — that is what a divergence means. So promotion cannot
happen at discovery. The required ordering:

> divergence → **halt and escalate** → root-cause → **fix lands** →
> *then* the pair is promoted, with its canonical derived by
> `gen-canonical-outputs` against the **fixed** build.

Promoting at discovery would either pin whichever leg happened to be
sampled — a wrong canonical, permanently, with T16 defending it — or
let a promotion PR encode the divergent value as "expected," which is
exactly the §4.5 T-A10 harness-extension-laundering shape. The ordering
goes in the lane's T# row **explicitly**, because the natural
automation instinct is to promote automatically and that instinct is
wrong here.

#### MR-R4 — seed provenance must reach the banner

**Largely dissolved by MR-R1's revision, and retained in reduced
form.** With entropy-based seeds an operator-supplied seed is an
unbounded attacker-selectable value, and the banner's provenance field
is the *only* defense. With index-based seeds a dispatch input is a
**bounded integer whose corresponding input set anyone can regenerate
and check**, so "the operator chose a benign one" becomes a claim that
can be falsified offline. The banner must still distinguish
schedule-derived from operator-supplied — a green replay must not be
citable as a sweep (T-A11) — but it is now a **provenance label rather
than the load-bearing control**.

The M4 banner substrate is already the right answer —
`invocation_banner.rs`'s `emit_banner` writes mode and fork-pin before
any test output, and T17 pins the substrings. Extend it to carry **the
seed and its provenance** (schedule-derived vs operator-supplied), with
a T17 assertion on both. A green replay then cannot be read as a sweep,
because the banner says which it was.

### 7.6 Necessary, sufficient, or additive?

The question the round had not asked. Answering it is what re-scoped it.

| Instrument | T-A1 / T-A3 | T-A9 | Verdict |
| --- | --- | --- | --- |
| Three-leg correctness + canonical pins | partial | partial | **Necessary core** — already live |
| Item 1 negative tests | **necessary & near-sufficient** — enforces the property directly | — | The right instrument, absent today |
| Item 2 rotating corpus | — | **closest to necessary** for the residual | Absent today; the real gap (MR-F9) |
| Item 3 mutation ratchet | **uniquely correct, narrowly** — nothing else verifies tests are load-bearing | no | Additive, and only after item 1 |
| T18 as specified (B / C1 / C2) | additive at best; misreports today (MR-F10) | **neither** (MR-F11) | Additive everywhere, necessary nowhere |

So: **T18 is additive everywhere and necessary nowhere — while being
documented as a primary defense in two places it is not.** That is the
same decayed-claim shape this round has been chasing throughout: a
statement about state that was true when written, carried forward
because it was written down.

Mutation testing does retain one property nothing else has — it
verifies that tests are load-bearing. That makes item 3 *uniquely
correct* for the narrow question "are the negative tests vacuous?", and
worthless for the two questions §4.6 M2 hired it for.

### 7.7 Cadence: local, sharded, or spread across days?

The three items answer differently, and the difference is structural
rather than a matter of taste:

| Item | Cadence | Why |
| --- | --- | --- |
| 1 — negative tests | **per-PR, local-runnable** | Minutes. A merge-blocking structural gate; no reason to defer it to a cron |
| 2 — rotating corpus | **spread across days, cumulative** | Its value *is* the union over time |
| 3 — mutation ratchet | **periodic, one unsharded job** | Same answer each run; only needs to be recent, not constant |

The decisive distinction for the budget question:

> **Sharding a mutation sweep across five runners buys the same answer
> faster. Distributing a rotating-seed lane across five days buys a
> different, larger answer each day.** Identical runner-hours;
> monotonically increasing coverage versus constant coverage.

That is the argument for spending the recovered C1 budget on item 2
rather than on shards, and it is why "break it up across days" is the
right instinct — but applied to the corpus lane, not to the mutation
sweep. Breaking a mutation sweep across days would just be the same
1290 verdicts arriving more slowly.

**Local runnability is a requirement, not a nicety.** Items 1 and 3 must
both be invocable locally with a documented command — the full probe in
§6.1 ran here in 8 minutes, and the per-crate baselines in ~90 s. A
gate that only exists in CI is a gate nobody runs before pushing, which
is how the suite outgrew its budget unobserved in the first place.

### 7.8 Rule-21 reopen criteria for the re-scope

- **Item 3 scope reopens** if a negative test is ever found vacuous by
  other means — that is the mutation gate's premise failing, and it
  would argue for widening the ratchet.
- **The fixed-corpus decision reopens as closed** if item 2 runs N
  consecutive weeks with zero divergences: evidence the input space is
  saturated *at that sizing*, which argues either to grow the sizing or
  to retire the lane. Pin N at ratification.
- **The re-scope itself reopens** if item 1's refactor proves
  infeasible without changing harness behavior — the §5.7 scope-creep
  boundary — in which case C1 returns as the detection fallback with
  its cost model intact.

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

---

## 12. Round record

| Round | Date | Substance |
| --- | --- | --- |
| Survey | 2026-08-18 | Substrate measured at `6441c1e29` (§2): 1322-mutant inventory by file, config/glob behavior, `--check` semantics from cargo-mutants 27.1.0 source, branch-coverage read. Findings MR-F1–MR-F5 recorded (MR-F5 — default `TestPackages::Mutated` scoping — found by reading cargo-mutants' source while pricing MR-DQ-3). Design questions MR-DQ-1–MR-DQ-8 opened with recommendations. **Round 1 not closed.** |
| Review | 2026-08-18 | Reviewer verdicts: MR-F1/F3/F4/F5 CONFIRMED at source; **MR-F2 CONFIRMED BUT UNDERSTATED → superseded by MR-F2′** (the config file is never loaded in CI; the "timeout_multiplier proves it is read" argument withdrawn as unsound, since 5.0 is also the tool default). Three new findings recorded: **MR-F6** (`&&`/`||` precedence sends every `workflow_dispatch` into the doomed job), **MR-F7** (`--locked` does not pin the tool version), **MR-F8** (cadence fossil). **MR-DQ-1 RULED** (drop `--check`; fold in MR-F8). **MR-DQ-8 RULED C1** after the per-crate suite measurement inverted the expected trade — harness suite 26 s vs verifier 63 s — with §6.5 establishing that C2 masks the T-A1 signal. Placement (MR-F2′) made a prerequisite of the ruling. MR-DQ-2–MR-DQ-7 remain open. |
| Re-scope | 2026-08-18 | Second review round, read against the threat model and harness source rather than this doc's own artifacts. Three findings recorded: **MR-F9** — the "random" corpus is a pinned `ChaCha20Rng` seed, so five lanes re-verify the same 1024 pairs forever, and `shekyl-pow-randomx` is the **only** crate with a byte-exact reference oracle and **no** `cargo-fuzz` lane (eight other crates have one); **MR-F10** — `assert_equivalent` takes live sessions, so its verdict has no negative test anywhere and mutating it would survive for API-shape reasons, meaning C1's first skip-list would be a refactor catalogue; **MR-F11** — §4.6 M2's T-A9 claim exceeds §4.5 T-A9's own "cannot defend structurally" disposition, and cargo-mutants' mutation distribution is not the laundering distribution. **MR-DQ-8's C1 ruling WITHDRAWN → HELD**: sound on its own terms, but it priced an instrument whose yield was never derived. Re-scoped into three separable items (§7.5): verdict-path testability + negative tests; a rotating-seed differential lane that promotes divergences into the pinned corpus; mutation as a narrow ratchet over assertion modules only, after item 1. §7.6 answers necessary-vs-sufficient-vs-additive; §7.7 answers the cadence question. MR-DQ-1, MR-F6, MR-F7 survive unchanged. |
| Ratification | 2026-08-18 | Re-scope **RATIFIED**, item 1 first — the sequencing is self-reinforcing: item 1 is what converts "assertion mutant survives" from an API-shape artifact into a real signal, so item 3 cannot be sized honestly until item 1 exists, and item 1 is the only one of the three that is merge-blocking-cheap. Item 2 gained four construction requirements from a source read (§7.9): **MR-R1** — a rotating seed makes its own red self-erasing, since rerunning *does* turn it green with a different innocent input set; countered by artifact-uploading the `failure_output` JSON line (which already carries `seedhash` + `data`, so no T11 amendment) and documenting replay-the-pair, never re-run-the-lane. **MR-R2** — the promotion target cannot be the random corpus (length- and index-coupled per `canonical_outputs.rs`); it is the adversarial corpus, whose methodology `§3.19 R7-D4` explicitly deferred to a post-2g round — this one. **MR-R3** — promotion must follow divergence → halt → root-cause → fix → *then* promote against the fixed build, or a wrong canonical is pinned permanently (T-A10 laundering shape). **MR-R4** — the seed and its provenance must reach the M4 banner with a T17 assertion, since an operator-suppliable seed is attacker-selectable. Also corrected item 2's claim: the **explored** boundary advances, the **pinned** one does not, and the negative half of that rationale belongs in the T# row. Item 3 sizing: row E's **cost** carries over, its **yield** must be re-measured post-item-1. |
| Macro finding | 2026-08-18 | **MR-F12 — the round's largest finding, and it subsumes MR-F5.** cargo-mutants does not mutate macro invocations (its book says so; the visitors are syn `Visit` impls and a macro body is an unparsed `TokenStream`). Confirmed empirically on this branch: the `+` inside `debug_assert_eq!` at `cache_precondition.rs:378` produced **zero** mutants while structurally identical arithmetic at `:364`, `:379`, `:389` outside macros each produced one. So `assert_eq!(rust_hash, c_hash)` — §4.6 M2's flagship T-A1 target — **is not a mutable expression**, and the mechanism could not fire at any scoping, profile, or budget. MR-F5's scoping defect is real but downstream. This makes **item 1 the precondition** for M2's T-A1 claim to be mechanically true rather than aspirational, and generates the construction constraint *"harness verdicts are functions returning `Result`, never bare assertion macros"* — enforced by a grep gate, because the doc line is what decays. A prior turn's `debug_assert`-under-release-profile hazard is **retracted and recorded as retracted**: those expressions are not mutation sites in either profile, so the proposed class-level `exclude_re` would have been an exclusion covering nothing — this round's own signature failure shape. **MR-DQ-4 DISSOLVED** with reasoning (a denominator needs a population where survival is informative; at verdict scope every mutant is), and replaced by the guard the new scope actually needs: a **minimum-mutant-count assertion**, since `--re` is name-based and a rename yields a clean green over an empty set. Also pinned: the `assert_equivalent` skip-list entry states both halves of its residual, and **ordering-as-triage-routing** is named as its own property class. |

---

## 13. The round's general finding: a gate must assert its own subject exists

Everything specific in this document is a repair. This section is the
part that generalises, and it is the only part likely to matter to
someone who never touches RandomX.

**Every defect in this round has one shape.** Not "the gate computed
the wrong answer" — in every case the gate computed a *correct* answer
about a surface that was not there, and reported it as a clean signal.

| Instance | The surface that wasn't there | What it looked like |
| --- | --- | --- |
| Severed job header (2026-07, `477a448b1`) | the job itself | Monday cron green |
| MR-F2′ skip-list config | the file, at the read path | discipline "enforced" |
| MR-F5 test scoping | the harness, in the judging set | mutants "caught" |
| **MR-F12 assertion macros** | **the mutable expression** | **survivor count clean** |
| MR-F10 verdict reachability | the reachable branch | tests "passing" |
| MR-F6 dispatch precedence | the intended trigger condition | job "gated" |

And — the part that makes this a finding rather than an observation —
**three of the proposed fixes had the same shape as the defect**:

| Proposed fix | Would have been |
| --- | --- |
| pin `test_package` in `.cargo/mutants.toml` | a setting in a file nothing reads |
| class-level `exclude_re` for `debug_assert` mutants | an exclusion covering a class that cannot occur |
| `--re`-scoped verdict ratchet | a clean green over an empty mutant set |

Each was caught, but none by noticing the fix was wrong on its own
terms — each was caught by asking *"does the thing this acts on
exist?"* That question is cheap, mechanical, and was not part of the
process at the round's start.

### The rule

> **A gate must assert that its own subject exists, and fail loudly
> when it does not. Absence of signal is not evidence of absence of
> defect — it is, first, evidence that the subject may be absent.**

The countermeasures this round landed are not three fixes. They are
three instances of one rule:

- **grep gate** on verdict shape (MR-F12) — asserts the mutable
  expression exists;
- **minimum-mutant-count assertion** (MR-DQ-4) — asserts the mutant
  population is non-empty;
- **skip-list liveness assertion** (MR-DQ-7) — asserts each exclusion
  matches at least one real path;
- and two that predate the round and are the same rule:
  `ctest --no-tests=error` in the full-parity job, and the
  domain-registry gate reading **comment-stripped** source so a doc
  comment quoting a literal cannot keep it green.

That last one is the tell: the house already had the rule, applied in
two places, without the rule being written down. Which is why it was
not applied to T18.

### Why it belongs outside this document

The pattern is not RandomX-specific — it is a property of gates. It has
precedent for promotion:
[`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
was itself "promoted from RandomX v2 Phase 2c" for the same reason. A
`docs/FOLLOWUPS.md` entry proposes promoting this to a rule; the
promotion is **not** made here, because minting a rule from inside the
round that discovered it is precisely the self-auditing move this round
has been arguing against. It wants a reader who was not in it.
| PR #505 review | 2026-08-19 | Four findings on the rotating lane, all confirmed at source. **PR-F1** — the job's `if:` omitted `pull_request`, so **#505's CI did not exercise the job #505 adds**; the Rust side was covered by the harness suite but the YAML wiring was not. **PR-F2** — and it was unexercisable by dispatch either, since `ref:` was pinned to the matrix branch, so a dispatch ran this workflow file while checking out `main`/`dev`, which lack `mode_rotating`. Fixed by a `checkout_ref` dispatch input defaulting to the matrix branch, **wired into `runtime-modes` too** because it carried the identical limitation — one mechanism, two jobs, converting "first execution is in production" into "first execution is a rehearsal". This matters more than an ordinary CI red: a wiring defect on a lane whose documented posture is halt-and-escalate arrives dressed as a plausible consensus finding, training the response you least want trained. **PR-F3** — provenance was keyed on input-emptiness, correct only while the `if:` refused an empty-index dispatch, an invariant held thirty lines away with nothing asserting the coupling; now bound to `github.event_name == 'schedule'` so the label is true by construction however the `if:` evolves (a fourth instance of the fix-reproduces-the-defect shape). **PR-F4** — the timeout was extrapolated through a non-uniform factor; replaced by a direct measurement at the exact CI sizing (32×32 = 1024 pairs, **515 s**, ~13.6 min on CI). Also recorded: **MR-R1a** (no pre-`main` run advances the explored boundary), and the deliberate choice that both matrix legs share one index so "diverged on dev, clean on main" stays informative. |
| MR-DQ-2 ruled | 2026-08-19 | Per-PR leg **converged with item 3**: the verdict-scoped ratchet is the per-PR leg. Measured **11 mutants in 36 s, 11 caught** (~58 s on CI) — it fits inside the structural job's measured 31–44 min many times over, so no diff-scoping machinery is needed. `--in-diff` **not adopted**: it served T-A9, which per MR-F11 this regime no longer claims. Paths filtering **inherited** from the workflow-level positive filter rather than re-declared per job. The ratchet carries the §13 guard the scope demands — a minimum-mutant-count floor, because `--re` matches names and a rename would otherwise green over an empty population. |
