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
**Status:** **DRAFT (review-revised 2026-06-20) — scoping pre-flight open;
design rounds + impl-time pre-flight pending. Prerequisite #163 **merged**; S6
branch can be cut off `dev` now. Findings F1–F4 + sequencing/coupling +
fossil-sweep folded in.**

---

## 0. Framing

2c-2b shipped the **live, float-free, per-draw degeneracy guard**
(`draw_entry_gap_guarded`) into the production `SignBond` path. It deferred the
**session-level statistical self-cert** (`certify_draw`) — the stronger,
float-bearing check that catches the correlated-walk pattern the per-draw guard
structurally cannot (it needs lag-1 autocorrelation over `n` draws). That
deferral is this PR.

**The self-cert is `conformance`-feature-gated with zero default-production
surface.** Two reasons hold; a third commonly-stated one does **not**, and the
distinction matters (it is the difference between an intrinsic law and an
artifact of today's grader):

1. **Dependency surface (intrinsic).** The grade pulls `shekyl-stats` via
   `shekyl-standoff`'s `conformance` feature (`Cargo.toml:20`). The production
   wallet must not carry the statistics crate.
2. **Design of record.** 2c-2b §3.3 already states: "*runs at session start,
   gated (not per-draw) … `conformance` feature, not shipped into production
   builds.*"
3. **NOT a law — float/x86 is an artifact of *this grader*.** `grade_sample`
   (`conformance.rs`) happens to compute its goodness-of-fit in `f64` (decile
   fractions, `max_decile_dev`, the `8/√n` tolerance), which `shekyl-standoff`
   correctly keeps x86-only because float is not bit-identical across
   architectures. But a session-level RNG check is **not inherently float**: a
   lag-1 autocorrelation test is a ratio of sums of products, which a fixed-point
   implementation with a defined **integer** tolerance could compute
   cross-arch-deterministically and float-free. So the constraint that pins this
   to a conformance build is an **implementation property of the current grader**,
   not a property of session-level certification. We keep the **float-free
   default-production** call — it is right on consensus-determinism grounds — but
   we do **not** claim the gating is forced by the nature of the task.

**Honest framing of what this delivers (F1).** Because the grade runs only in a
`conformance` build (typically CI's x86 lane, or an opt-in operator diagnostic),
a default-production wallet — frequently aarch64, on the user's box — **never runs
it**. So this is **CI/diagnostic certification of the `OsRngGapAdapter` (the RNG
*adapter*)**, *not* runtime certification of the *user's* wallet at their session.
That is still a real gain over the status quo (today `certify_draw` is exercised
only by `conformance_grading.rs::self_cert_passes_reference_rng` over a **reference
`SplitMix64`** — never the production `OsRng` adapter), but the §1.1-S6 phrase
"the *shipping wallet's* RNG at the *actual* session-start" overstates it and is
corrected here.

**Named residual (rule 21).** The correlated-walk failure mode — the one the S5
per-draw degeneracy guard structurally **cannot** catch (`correlated_walk`,
`conformance.rs:208`) — is therefore checked **nowhere at runtime in any
default-production build**, only in CI. For a firewall where a degenerate timing
RNG defeats the gate-6 decorrelation, this is a real residual. It is
**low-probability** (`OsRng` is a vetted CSPRNG, not a stuck/correlated source)
but **unmitigated at production runtime**. *Reopen trigger:* a **fixed-point,
integer, cross-arch-deterministic session grader becomes feasible or needed** —
at which point the session self-cert can move onto the float-free production path
and certify the *user's* RNG at *their* session. The trigger is explicitly **not**
the implicit "never"; it is gated on the grader, which §1.2 marks out of scope
for S6 but reachable.

**Why S6 *now* — coupling, not freshness.** The load-bearing reason to take S6 as
the interstitial before 2d-1 is **shared-surface coupling, not "the #163 substrate
is fresh."** S6 modifies `StakeEngine::on_start` (`stake_engine.rs:515`), and
**2d-1 (the `P`-scan layer) will also hook session-start on the same actor**
(scan-store open, cursor recovery at spawn). Landing the small `on_start` wiring
**before** 2d-1 churns `StakeEngine` is the clean order: defer S6 past 2d-1 and the
`certify_draw` call site rebases onto a moved/widened `on_start`. Doing S6 first
makes the ordering correct **by construction** (and lets the start-error type be
designed once for both — see DQ2/F3). Freshness is the weaker restatement of this.

---

## 1. Scope enumeration (SP-1)

### 1.1 In scope

| # | Item | Substrate at pin |
| --- | --- | --- |
| S6.1 | **Wire `certify_draw` into `StakeEngine::on_start`**, gated behind a new `shekyl-engine-core` `conformance` feature that enables `shekyl-standoff/conformance`. Draws over `OsRngGapAdapter` at the canonical `DEFAULT_ENTRY_GAP.as_blocks()` window. | `on_start` (`stake_engine.rs:515`); `OsRngGapAdapter` (`stake_engine.rs`); `certify_draw` (`conformance.rs:377`); `DEFAULT_ENTRY_GAP` (`stake_timing.rs`). |
| S6.2 | **Failure handling — fail-stop.** A failed grade refuses to spawn the StakeEngine (no staking on a CSPRNG that fails conformance — a non-conformant timing RNG defeats the gate-6 decorrelation firewall). Resolve the `on_start` `Infallible` → real-error question (DQ2). | `Actor::Error = Infallible` (`stake_engine.rs:510`); `CertifyReport::passed()` (`conformance.rs`). |
| S6.3 | **Single-source the sample size `n` (F4).** `n = 200_000` (R0-D4: tolerance `8/√n` ≈ 0.0179, wall-clock ≈ 14–15 ms debug) **already exists** as a bare literal **6×** in `conformance_grading.rs` (lines 37, 70, 105, 108, 175, 190). Do **not** add a 7th copy at the `on_start` call site — define **one** named constant and have **both** the production call site **and** the reference KAT consume it (repoint `conformance_grading.rs` in the *same* PR). If the reference grade and the production grade ever used different `n`, the `8/√n` tolerance forks and the two certs stop being comparable. | 2c-2b §4 R0-D4; `conformance_grading.rs:37,70,105,108,175,190`. |
| S6.4 | **CI conformance job + spawn test.** A test that spawns `StakeEngine` under `--features conformance` and asserts the self-cert ran and passed over `OsRng`; a CI lane that builds/tests engine-core with the feature on x86. | mirrors `conformance_grading.rs`; CI lane addition. |
| S6.5 | **Remove the `TODO(S6)` marker(s)** in `stake_engine.rs`; **fold in** the stale CT-5 comment fix in `local_pending_tx.rs:3404–3408` (calls the now-live verify KAT the "`#[ignore]`d sibling … gated on CT-5" — a fossil after #162). | `stake_engine.rs:762`; `local_pending_tx.rs:3404–3408`. |

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
- **DQ2 — `on_start` failure type, designed for 2d-1's incoming failures (F3).**
  `Actor::Error` is `Infallible`. Change it to a real `StakeEngineStartError`
  (typed, greppable) rather than `panic!` in `on_start`. **But scope the enum for
  what is *known* to be coming, not just the grade:** 2d-1 adds `P`-scan init to
  this same `on_start` (scan-store open, cursor recovery) — failures that can
  occur **in production**, not just under `conformance`. So design
  `StakeEngineStartError` *now* as the real start-failure surface:

  ```text
  enum StakeEngineStartError {
      #[cfg(feature = "conformance")]
      RngSelfCertFailed(CertifyReport),   // S6 — grade variant, compiles out by default
      // (2d-1 adds always-on variants here: ScanStoreOpen, CursorRecovery, …)
  }
  ```

  so 2d-1 **adds a variant** rather than reshaping the type a release later — the
  make-bad-states-unrepresentable move applied to a coupling we already know is
  incoming. **Constraint:** it must stay **zero-cost in the default build** — with
  no `conformance` and (today) no always-on variants, the enum is empty/`Err` is
  unconstructible and `on_start` cannot fail, so the branch compiles out. *Verify*
  that an empty-by-default error enum + `Result<Self, _>` `on_start` compiles
  clean and warns nowhere (an uninhabited error may need a small shim).
  **Verify kameo `on_start`-error semantics at source before committing.**
- **DQ3 — x86-only execution must be LOUD, not a silent compile-out (F2).** The
  grade is float / x86-only, so an aarch64 `conformance` build cannot run it. A
  bare `#[cfg(all(feature = "conformance", target_arch = "x86_64"))]` compiles
  the call **out silently** — an operator who builds `--features conformance` on
  aarch64 as a diagnostic then gets **false assurance** ("conformance passed"
  when the grade never ran). Per the project's state-it-don't-hide-it posture, the
  skip must be **visible**: either a **`compile_error!`** on
  `conformance && not(x86_64)` ("the session self-cert grader is x86-only; build
  the conformance lane on x86_64") so the unsupported combination fails to build,
  **or** — if aarch64 conformance builds must still compile — a **loud runtime
  log/marker** that the grade was **skipped, not passed**. *Settle which; default
  to `compile_error!`* (a diagnostic build that can't run the diagnostic should
  say so at compile time, not pretend success at runtime).
- **DQ4 — Sample-size constant home.** The constant from S6.3 (single-sourced,
  consumed by both the production call site and the repointed reference KAT).
  Home: `stake_timing.rs`, beside `DEFAULT_ENTRY_GAP` (the timing-constants home).
  Value `200_000` per R0-D4 — unchanged, just named and shared.

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

- **Prerequisite SATISFIED: PR #163 (2c-2b) merged 2026-06-20** (merge
  `701febc87`; branch archived `archive/feat-archival-bond-request-2026-06-20`).
  S6 consumes `OsRngGapAdapter`, `on_start`, and `DEFAULT_ENTRY_GAP`, all now on
  `dev`. The S6 branch can be cut **off `dev` now**.
- **Order before 2d-1 — by construction, not incidental (coupling, see §0).**
  S6 and 2d-1 both hook `StakeEngine::on_start`; landing S6's small wiring +
  start-error type *before* 2d-1 churns the actor avoids a rebase of the
  `certify_draw` call site onto a moved/widened `on_start`, and lets
  `StakeEngineStartError` be designed once for both (DQ2/F3).
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
