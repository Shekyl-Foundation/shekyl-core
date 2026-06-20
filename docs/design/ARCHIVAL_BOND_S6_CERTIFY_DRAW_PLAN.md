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
surface.** The gating is correct, but be precise about *why* — it is **one design
choice resting on two artifacts of *this grader***, none of which is an intrinsic
law of session-level certification:

1. **Artifact — float / cross-arch.** `grade_sample` (`conformance.rs`) computes
   its goodness-of-fit in `f64` (decile fractions, `max_decile_dev`, the `8/√n`
   tolerance), which `shekyl-standoff` correctly keeps **x86-only** because float
   is not bit-identical across architectures, and production is deliberately
   float-free.
2. **Artifact — `shekyl-stats` dependency.** The grade pulls `shekyl-stats` via
   `shekyl-standoff`'s `conformance` feature (`Cargo.toml:20`); production must
   not carry the statistics crate. **This is the *same class* as (1), not an
   independent law:** a fixed-point reimplementation of the grade would pull
   neither float *nor* `shekyl-stats`.
3. **Choice — design of record.** 2c-2b §3.3 records the decision: "*runs at
   session start, gated (not per-draw) … `conformance` feature, not shipped into
   production builds.*"

Both (1) and (2) are **implementation properties of the current grader**, not
properties of the task: a session-level RNG check is not inherently float or
stats-bearing — a lag-1 autocorrelation test is a ratio of sums of products, which
a fixed-point implementation with a defined **integer** tolerance could compute
cross-arch-deterministically, float-free **and** `shekyl-stats`-free. We keep the
**float-free default-production** call (right on consensus-determinism grounds) but
do **not** claim the gating is forced by the nature of session-level certification.

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
integer, cross-arch-deterministic *and* `shekyl-stats`-free session grader becomes
feasible or needed** — at which point the session self-cert can move onto the
float-free production path and certify the *user's* RNG at *their* session. Both
clauses matter: a fixed-point grader that *still* pulled `shekyl-stats` would
satisfy a float-only trigger yet remain unshippable to production, so the residual
would read closed while it isn't. The trigger is explicitly **not** the implicit
"never"; it is gated on the grader, which §1.2 marks out of scope for S6 but
reachable.

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
| S6.3 | **Single-source the sample size `n` (F4) — define it *down* in `shekyl-standoff`.** `n = 200_000` (R0-D4: tolerance `8/√n` ≈ 0.0179, wall-clock ≈ 14–15 ms debug) **already exists** as a bare literal **6×** in `conformance_grading.rs` (lines 37, 70, 105, 108, 175, 190). Do **not** add a 7th copy at the `on_start` call site, and do **not** home it in engine-core (the standoff KAT can't reach upward — DQ4). Define **`CERTIFY_SAMPLE_N` in `shekyl-standoff`** (beside the grader), have **both** the production `on_start` call site (via a `stake_timing.rs` re-export) **and** the reference KAT consume it (repoint `conformance_grading.rs` in the *same* PR). If the reference grade and the production grade ever used different `n`, the `8/√n` tolerance forks and the two certs stop being comparable. | 2c-2b §4 R0-D4; `conformance_grading.rs:37,70,105,108,175,190`; `shekyl-standoff` (new const). |
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
  Kameo `on_start`-error semantics **RESOLVED 2026-06-20** — see §2.1 below; DQ2
  is now execution-ready.
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
- **DQ4 — Sample-size constant home: it must live *down* in `shekyl-standoff`.**
  The single-sourced `n` (S6.3) is consumed by **two crates**: the six
  `conformance_grading.rs` literals (in `shekyl-standoff` itself) **and** the
  `on_start` call site (`shekyl-engine-core`, which depends *up* on standoff). A
  home in `stake_timing.rs` (engine-core) **cannot compile** — the standoff KAT
  would reference an engine-core symbol against the dependency edge. So the source
  of truth is **`CERTIFY_SAMPLE_N` in `shekyl-standoff`**, beside `certify_draw` /
  the grader (it is a grader constant — `8/√n` is the grade's own tolerance
  contract). `stake_timing.rs` gets a **re-export**, not the definition:
  `pub use shekyl_standoff::CERTIFY_SAMPLE_N;` (beside `DEFAULT_ENTRY_GAP`, for
  call-site ergonomics) — **exactly the pattern the file already uses**, where
  `DEFAULT_ENTRY_GAP` wraps `shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW` (source of
  truth down, alias up). Value `200_000` per R0-D4 — unchanged, just named, shared,
  and reachable by both consumers.

### 2.1 Pre-Round-1 substrate findings — kameo `on_start` error semantics (RESOLVED 2026-06-20)

Verified at `kameo-0.20.0` source (the exact-pinned `=0.20.0` this crate uses).
DQ2/F3 are now execution-ready; Round 1 implements rather than investigates.

1. **Error-type bound is trivial.** `Actor::Error: ReplyError`, and `ReplyError`
   has a **blanket impl for any `T: Debug + Send + 'static`**
   (`kameo/src/reply.rs:206–207`). So `StakeEngineStartError` needs only
   `#[derive(Debug)]` — **no `thiserror` / `std::error::Error`** required (a
   `Display`/`thiserror` impl is optional polish, not a bound).
2. **`on_start` *can* fail, in-task.** `on_start(args, ref) -> Result<Self,
   Error>` runs **inside the spawned actor task** (`kameo/src/actor/spawn.rs:185`);
   an `Err` is wrapped `PanicError(.., PanicReason::OnStart)` and the actor goes
   straight to shutdown — it never enters the message loop.
3. **Two ways to observe the failure:**
   - **Eager (chosen):** `actor_ref.wait_for_startup_result().await ->
     Result<(), HookError<A::Error>>` (`kameo/src/actor/actor_ref.rs`) — returns
     the typed error, **but bounds `A::Error: Clone`**.
   - **Lazy (rejected):** don't wait; the dead actor makes the first message
     return `ActorNotRunning` → existing `collapse_send_error` →
     `StakeActorUnavailable`. Rejected: it **loses the specific reason** at the
     wallet-open boundary, which defeats a *diagnostic* build whose whole purpose
     is to say loudly *why* the RNG failed (F2 posture).
4. **`CertifyReport` is `#[derive(Debug, Clone)]`** (`conformance.rs:276`) — a
   valid `Clone` payload for the error variant.
5. **The spawn site is sync.** `Engine::spawn_stake_engine_if_staker`
   (`lifecycle.rs`) is a **sync** fn returning `OpenError`. Eager observation
   therefore needs a sync→async bridge to `.await wait_for_startup_result()` —
   `tokio::task::block_in_place` + `Handle::block_on`, the **same pattern
   `drive_persistence` already uses** (the crate's `rt-multi-thread` justification,
   `Cargo.toml`). **Crucially this bridge is needed only under `conformance`** —
   the default build never waits.

**Resolved DQ2 shape (execution-ready):**

```text
#[derive(Debug, Clone)]
enum StakeEngineStartError {
    #[cfg(feature = "conformance")]
    RngSelfCertFailed(CertifyReport),   // CertifyReport: Clone ✓
    // 2d-1 adds always-on variants (ScanStoreOpen, CursorRecovery, …)
}
```

- **Default build:** the only variant is `#[cfg]`-compiled out, leaving an
  **empty enum**. `on_start` always returns `Ok(self)`; `Err` is unconstructible;
  zero-cost. (Empty enums derive `Debug`/`Clone` vacuously — *verify it compiles
  warning-free* in Round 1; the F3 "uninhabited-error shim" worry looks
  unnecessary but is a 5-minute compile check.)
- **Conformance build:** `on_start` runs the (x86-gated, DQ3) `certify_draw` over
  `OsRngGapAdapter`; on `!report.passed()` returns
  `Err(RngSelfCertFailed(report))`. `spawn_stake_engine_if_staker` then
  `block_in_place`-awaits `wait_for_startup_result()` and maps
  `HookError::Error(RngSelfCertFailed(_))` → a **new `#[cfg(feature="conformance")]`
  `OpenError` variant**, so wallet-open fails **loudly with the RNG reason**.
- The sync→async bridge **and** the `OpenError` widening are **both
  `conformance`-gated** → zero default-production surface (consistent with §0).

**2d-1 hand-off — what it inherits, and what it does *not* (scope it now).** The
F3 win is real but bounded: 2d-1 inherits the **error *type*** (it adds always-on
variants like `ScanStoreOpen` / `CursorRecovery` rather than reshaping it), **but
not a ready-made startup-failure *path***. S6's observation plumbing — the eager
`wait_for_startup_result()`, the `block_in_place` bridge, the `OpenError`
widening — is **`conformance`-gated and S6-specific**. When 2d-1 adds production
failures, it must **lift that plumbing out of the `conformance` cfg into the
default build**, and it may not even want S6's model: eager-block-on-open is fine
for a ~15 ms RNG grade but questionable for a potentially-slow `P`-scan sweep,
where **async-with-status** (open proceeds, scan readiness surfaced separately)
likely beats blocking wallet-open. So "designed once for both" is true **only of
the enum**; 2d-1 still builds its own always-on observation and picks its own
surfacing model. 2d-1's plan must budget for that, not assume S6 paved it.

**Round-1 verify (contained to conformance, but panic-not-error if wrong):**
`tokio::task::block_in_place` **panics on a current-thread runtime**. Confirm the
conformance spawn test **and** any wallet-open call site that reaches the bridge
run under the **multi-threaded** runtime (the "same pattern as `drive_persistence`"
note implies they do — `drive_persistence` is the `rt-multi-thread`-gated branch —
but verify, since the failure mode is a panic, not a graceful error).

Round-1 first action is now *implementation* of this shape + the empty-enum
compile check, not investigation.

### Round plan (rule 26, tightened)

- **Round 1 — implement the gating + failure path (DQ1/DQ2/DQ3).** DQ2 is now
  resolved (§2.1) — this round **implements** the `StakeEngineStartError` shape +
  the conformance `on_start` call + the `block_in_place` startup-result bridge +
  the `OpenError` widening, and settles DQ3's loud-skip mechanism
  (`compile_error!` vs runtime marker) and DQ1's feature name. Gate: the
  empty-enum default build compiles warning-free; the conformance build wires
  end-to-end.
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
