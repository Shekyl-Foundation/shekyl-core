# Bond-PR S6 — `certify_draw` session self-cert wiring (plan + scoping pre-flight)

**Arc / numbering authority:** [`ARCHIVAL_BOND_PR2_CHAIN.md`](ARCHIVAL_BOND_PR2_CHAIN.md).
S6 is **not a new `Bond-PR 2x` number** — it is the deferred S6 scope item of
Bond-PR 2c-2b (the `certify_draw` session self-cert), split out as a small
follow-on PR per the 2c-2b §3.6 / FOLLOWUPS "Archival bond request path —
deferred items" block (R0-D# of 2c-2b deferred the *wiring*, settled the
*design*).
**Branch:** `feat/archival-stake-certify-draw` (off `dev`) — **opens only after
PR #163 (2c-2b) merges**, because S6 wiring consumes 2c-2b substrate:
`OsRngGapAdapter`, `StakeEngine::on_start`, `DEFAULT_ENTRY_GAP`
(`stake_engine.rs` / `stake_timing.rs`).
**Parent design:** `ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md` §3.3 (S6 design settled),
§4 R0-D4 (sample size pinned + measured); `ARCHIVAL_FIREWALL_GATE6.md` §10.12;
`shekyl-standoff` crate doc (single-source + float-free-production doctrine).
**Process rule:** `26-sub-pr-design-discipline.mdc` (opt-in; cited because this
touches the gate-6 firewall RNG surface — but **scoped tighter than 2c-2b**: the
design is already settled in 2c-2b §3.3, so this is a **2-round** effort, not 6).
**Status:** **DRAFT — scoping pre-flight open; design rounds + impl-time
pre-flight pending. Blocked on PR #163 merge before code lands.**

---

## 0. Framing

2c-2b shipped the **live, float-free, per-draw degeneracy guard**
(`draw_entry_gap_guarded`) into the production `SignBond` path. It deferred the
**session-level statistical self-cert** (`certify_draw`) — the stronger,
float-bearing check that catches the correlated-walk pattern the per-draw guard
structurally cannot (it needs lag-1 autocorrelation over `n` draws). That
deferral is this PR.

The decision the option-selection already fixed (and the substrate forces):
**the self-cert is `conformance`-feature-gated with zero default-production
surface.** Three independent reasons converge on this:

1. **Float / cross-arch.** `certify_draw`'s grade is a float goodness-of-fit
   (`grade_sample`), which `shekyl-standoff` keeps **x86-only** — float is not
   bit-identical across architectures, and the production wallet path is
   deliberately **float-free** (the integer golden vector is the cross-arch
   contract; the grading is not). A default-production self-cert would either
   ship float onto aarch64 or be unrunnable there.
2. **Dependency surface.** The grade pulls `shekyl-stats` via
   `shekyl-standoff`'s `conformance` feature (`Cargo.toml:20`). The production
   wallet must not carry the statistics crate.
3. **Design of record.** 2c-2b §3.3 already states: "*runs at session start,
   gated (not per-draw) … `conformance` feature, not shipped into production
   builds.*"

**What the wiring still adds over the existing test.** Today `certify_draw` is
exercised only by `conformance_grading.rs::self_cert_passes_reference_rng`, which
feeds a **reference `SplitMix64`**. Wiring it into `on_start` over the
**`OsRngGapAdapter`** certifies the **actual shipping CSPRNG** at the **actual
session-start**, in a conformance build — the §1.1-S6 intent ("the *shipping
wallet's* RNG, not merely the reference"). That is the value-add; it is realized
**in a conformance build**, not the default binary.

---

## 1. Scope enumeration (SP-1)

### 1.1 In scope

| # | Item | Substrate at pin |
| --- | --- | --- |
| S6.1 | **Wire `certify_draw` into `StakeEngine::on_start`**, gated behind a new `shekyl-engine-core` `conformance` feature that enables `shekyl-standoff/conformance`. Draws over `OsRngGapAdapter` at the canonical `DEFAULT_ENTRY_GAP.as_blocks()` window. | `on_start` (`stake_engine.rs:515`); `OsRngGapAdapter` (`stake_engine.rs`); `certify_draw` (`conformance.rs:377`); `DEFAULT_ENTRY_GAP` (`stake_timing.rs`). |
| S6.2 | **Failure handling — fail-stop.** A failed grade refuses to spawn the StakeEngine (no staking on a CSPRNG that fails conformance — a non-conformant timing RNG defeats the gate-6 decorrelation firewall). Resolve the `on_start` `Infallible` → real-error question (DQ2). | `Actor::Error = Infallible` (`stake_engine.rs:510`); `CertifyReport::passed()` (`conformance.rs`). |
| S6.3 | **Named sample-size constant.** Reuse R0-D4's measured `n = 200_000` (tolerance ≈ 0.0179, wall-clock ≈ 14–15 ms debug incl. startup). Name it (no unnamed literal). | 2c-2b §4 R0-D4; `conformance_grading.rs:175`. |
| S6.4 | **CI conformance job + spawn test.** A test that spawns `StakeEngine` under `--features conformance` and asserts the self-cert ran and passed over `OsRng`; a CI lane that builds/tests engine-core with the feature on x86. | mirrors `conformance_grading.rs`; CI lane addition. |
| S6.5 | **Remove the `TODO(S6)` marker(s)** in `stake_engine.rs` as the wiring lands. | `stake_engine.rs:762`. |

### 1.2 Out of scope

| Out | Why |
| --- | --- |
| Default-production runtime self-cert | Float / x86-only grade + `shekyl-stats` dep — production stays float-free (Framing). |
| Per-draw certification | Already shipped (the live degeneracy guard, 2c-2b S5). |
| Periodic / mid-session re-certification | Session-start (per spawn = per wallet open) is the design unit (§3.3); a periodic cadence is speculative (rule 21) until a need exists. |
| Changing `certify_draw` / `grade_sample` itself | The grader is landed and tested in `shekyl-standoff`; S6 only *calls* it. |

### 1.3 Land posture

Unlike 2c-2b (land-inert), S6 has **no production surface to keep inert** — the
default build is unchanged (the `conformance` cfg compiles the call out). The
"activation" is purely *building with `--features conformance`* (CI + opt-in
operator diagnostic). No phantom-accrual or user-invocability concern.

---

## 2. Design questions (to resolve in the rounds)

- **DQ1 — Gating mechanism (essentially settled).** A `shekyl-engine-core`
  `conformance` feature → `shekyl-standoff/conformance`; the `on_start` call site
  is `#[cfg(feature = "conformance")]`. *Open detail:* feature naming +
  whether it also gates anything else (keep it single-purpose).
- **DQ2 — `on_start` failure path.** `Actor::Error` is `Infallible`. Options:
  (a) change it to a real `StakeEngineStartError` so a failed grade returns
  `Err` and the spawn fails loudly; (b) `panic!` in `on_start` (rides the
  existing fail-stop posture). *Lean:* (a) — a typed start error is the honest,
  greppable failure; but it must stay zero-cost in the default build (the error
  variant / branch compiles out under `#[cfg]`). **Verify kameo `on_start`-error
  semantics at source before committing.**
- **DQ3 — x86-only execution.** The grade is float / x86-only. The conformance
  spawn test + CI lane run on x86; an aarch64 conformance build must **skip**
  the grade (cfg on target_arch, or the CI lane is simply x86-only and the
  call is `#[cfg(all(feature = "conformance", target_arch = "x86_64"))]`).
  *Settle which.*
- **DQ4 — Sample-size constant home + value.** Reuse `n = 200_000` (R0-D4).
  Home: `stake_engine.rs` (single consumer) vs `stake_timing.rs` (the timing
  constants home). *Lean:* `stake_timing.rs`, beside `DEFAULT_ENTRY_GAP`.

### Round plan (rule 26, tightened)

- **Round 1 — gating + failure path (DQ1/DQ2/DQ3).** The load-bearing round:
  feature wiring, the `on_start` error decision (verified against kameo source),
  and the x86 cfg. Produces the exact `on_start` shape.
- **Round 2 — closure + R0-D# pre-flight.** Audit-against-actual-code once the
  branch exists (#163 merged): re-pin substrate, confirm the conformance build
  compiles + the grade runs + fail-stop bites (inject a degenerate RNG into the
  spawn path and assert spawn fails). Numeric: confirm the wall-clock at spawn
  matches R0-D4's ≈ 15 ms.

(Two rounds, not six: the *design* — what `certify_draw` is, why session-level,
the sample size — was settled and measured in 2c-2b §3.3 / R0-D4. S6 is a
**wiring** decision, not a fresh design.)

---

## 3. Dependencies & sequencing

- **Hard prerequisite: PR #163 (2c-2b) merges first.** S6 consumes
  `OsRngGapAdapter`, `on_start`, and `DEFAULT_ENTRY_GAP`, all introduced by #163.
  The S6 branch is cut **off `dev` after #163 lands**.
- **No CT-5 dependency.** S6 is RNG-conformance wiring; orthogonal to the
  curve-tree verify path (CT-5 closed in #162).
- **Forward-action bookkeeping.** On S6 close, flip the FOLLOWUPS "S6 —
  `certify_draw` session self-cert wiring" item from deferred → landed.

---

## 4. Gates (rule 45 / 50)

`cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`;
`cargo test --workspace` (default build); **plus** the conformance lane:
`cargo test -p shekyl-engine-core --features conformance` on x86. No
`STAKING_BLOCK_VERSION` perturbation (no persisted-format change). No new
third-party crate enters the default graph (`shekyl-stats` is feature-gated,
already in the workspace).
