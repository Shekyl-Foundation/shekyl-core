# Engine cadence driver

**Status: OPEN — design of record (2026-09-07); implementation PR pending.**

Ruling of record: `.cursor/plans/wallet_rewrite_audit_cbf7c720.plan.md`
§"Engine cadence driver" (2026-09-07). This document is the
specification the implementation PR builds against (rule 05:
specification first). Index row: `IMPLEMENTATION_INDEX.md` §5.

---

## 0. The problem and the ruling

Nothing in production drives anything on a wallet-wide cadence. The
surfaces that need one are built and idle:

- `Engine::run_submit_lifecycle_tick` (`engine/mod.rs`) — the §5.3
  submit watchdog tick. Zero production callers; its own doc says
  "cadence is the embedding runtime's."
- `Engine::submit_emission_claim` (`claim_dispatch.rs`) —
  `#[allow(dead_code)]`; four comments defer scheduling to "the GF-4
  seam," a seam that will never be a caller.
- Serving first-publish (`serving/start.rs` / `task.rs`) — one attempt,
  deliberately; a failed start ends the serving lifecycle for the
  session and the remedy is a wallet reopen.
- Terminal-reject prune / byte-identical resubmit for the
  claim/drain/unbond lanes — unbuilt (`docs/FOLLOWUPS.md`
  "Drain/claim/unbond dispatch driver" entry), user-visible since PR-C
  as `-29522 UNSTAKE_FATE_UNKNOWN` with no recovery verb.

A per-leg scheduler (one timer per concern) is the wrong shape: four
timers with four ownership stories, four close paths, and four chances
for an embedder to forget one.

**Ruling (2026-09-07): one engine-owned driver.** The **Engine starts
it** — an embedder that must remember to start it fails by omission
and never announces. This overturns the standing "cadence is the
embedding runtime's, not the Engine's" policy; see §1 for why that
premise is refuted rather than superseded.

`claim` / `claim_rewards` stay REJECTED in the wallet-RPC contract
(rule 23): the cadence driver's claim leg **is** the production
caller. `USER_GUIDE.md` "Rewards arrive automatically" becomes true
when the implementation PR lands.

## 1. Why engine-owned (premise refuted, not preference changed)

The rejected-background-sync policy (`engine/mod.rs` §"No wallet-internal
background sync", WI-1 embedder-held handles) was written when the only
cadenced work was **principal refresh** — an interactive, user-visible
catch-up whose progress the embedder must own and render. That premise
does not extend to the four legs above:

1. None of them is interactive. They are correctness/liveness
   maintenance: a held transaction that is never re-relayed expires; a
   settled epoch that is never claimed forfeits; a serving obligation
   that is never published breaches the bond contract.
2. All of them fail **silently** when unstarted. A missing refresh is
   visible (stale balance); a missing submit-watchdog tick is invisible
   until funds are stuck. The failure asymmetry is the design driver:
   per rule 16's inheritance corollary, a defence that cannot fail —
   here, a leg that exists but is never scheduled — consumes the
   attention that would have found the gap.
3. The embedder-held pattern already produced exactly this outcome
   once: `run_submit_lifecycle_tick` landed 2026-08 with a doc comment
   naming its natural call site ("after each completed refresh cycle"),
   and no embedder ever called it.

Refresh itself stays embedder-driven and on-demand. The driver does
not subsume `start_refresh`, pscan, or the serving task; it is the
**scheduler for the entry points that have none**.

### Why a spawned task, not a tick method (the shape is forced)

The first question a reviewer of the overturned policy asks is why
the engine now owns a *task* instead of exposing a tick the embedder
calls — so the answer is recorded. Exposing a tick **is** the refuted
premise restated: `run_submit_lifecycle_tick` is exactly that shape,
and it has zero callers. The other non-task shape — a pure `advance()`
hung off an existing host loop — has no host: there is no push tip
signal (the tip is polled), pscan runs only for stakers while leg 1
must run for every wallet, and refresh is on-demand. No production
loop exists that every wallet already runs, so the driver brings its
own: a spawned task, `Weak` upgrade per tick, `CadenceHandle` per
§"Ownership and close". The conclusion is forced by the survey
findings, not preferred.

### Ownership and close

WI-1's embedder-held-handles rule exists so `Arc::try_unwrap → close`
works. The driver preserves that property structurally:

- The driver task holds a **`Weak<RwLock<Engine>>`**. Every tick
  upgrades; a failed upgrade means the engine is closing, and the task
  exits. The driver can never keep the engine alive.
- The spawn returns a `CadenceHandle` (cancel-on-drop
  `CancellationToken` + `JoinHandle`, the `PScanHandle` shape) that the
  wrap point parks alongside `OpenTasks { pscan, serving }`. Shutdown
  order: serving → pscan → cadence.

### The structural start guarantee

"The Engine starts it" cannot mean "at construction" — constructors
are sync and pre-`Arc`, and the driver needs the shared handle. The
guarantee is placed at the **wrap point** instead: `shekyl-engine-core`
gains the canonical wrap-and-start entry

```rust
impl Engine {
    /// The only public way to obtain a shared engine. Spawns the
    /// cadence driver; the handle joins the embedder's task set.
    pub fn into_shared(self) -> (SharedEngine, CadenceHandle);
}
```

and the bare `Arc::new(RwLock::new(engine))` wrap in embedders is
replaced by it. Skipping the driver is then a **compile-time** failure
(no other path yields `SharedEngine`), which satisfies "fails by
omission and announces." In-tree adopters: `shekyl-wallet-rpc`'s
`wrap_and_start_tasks` (Shape A, and Shape B via `spawn_in_process`,
which covers the CLI). The GUI's `EngineSession` (separate repo)
adopts on its next engine-core bump; until then it compiles against
the old crate version, not a silent no-driver build.

**Runtime context (decided here, not discovered in commit review):**
`into_shared` is sync and spawns, so it requires an ambient tokio
runtime. That is not a new constraint — `Engine` construction already
spawns the key-engine and curve-tree actors, so every call site that
holds an `Engine` to wrap is already inside a runtime. The
implementation still asserts it by name:
`tokio::runtime::Handle::try_current()` with an `expect` message that
names `into_shared` and the requirement, so a non-runtime embedder
fails with the named reason instead of a bare `tokio::spawn` panic.
Rejected shapes: `async fn` (nothing is awaited; it would infect sync
wrap sites for no benefit) and a `runtime::Handle` parameter
(pre-provisioning; ambient context is the crate-wide convention).

If making `into_shared` the *only* Arc mint proves too invasive for
one PR (test embedders construct raw Arcs pervasively), the fallback
is `into_shared` + a `#[cfg(not(test))]`-deprecated raw path — but the
default disposition is the structural version; the fallback needs the
implementation PR to name why (rule 21 shape).

## 2. Tick architecture: chain-progress base, wall-clock watchdog

The driver has two clocks and must not pick a side arbitrarily.

**Chain progress is the tick base.** The loop polls the daemon tip on
a fixed wall-clock interval (60 s, `FixedRateSchedule` /
`MissedTickBehavior::Skip`, the pscan pattern) but **fires legs only
when the observed tip height advanced** past the last fired height. A
wall-clock tick that fires regardless keeps evaluating against a stale
view when the daemon stalls or the node is eclipsed; an eclipsed
staker auto-claiming against an attacker's chain view is the failure
mode designed out here.

**Absence of ticks must be observable.** A chain-progress tick goes
silent when the chain does, so the loop carries a wall-clock watchdog
*on the tick*: if no height advance is observed for
`CHAIN_STALL_ALARM_SECONDS` (provisioned at 30 minutes = 15 blocks at
the 120 s target; rationale and bounds in the constant's doc per rule
75), the driver raises the `ChainProgress` operator alarm and keeps
polling. The alarm clears on the next observed advance. Legs do not
fire while stalled — firing against a known-stale view is the thing
the tick base exists to prevent.

**Seconds-denominated horizons are evaluated against observation.**
The submit leg's escape horizon (`DAEMON_RE_RELAY_CUTOFF_SECONDS`,
converted to ~540 blocks for intuition only) is measured against
observed chain progress, not a free-running timer — the existing
`WatchdogConfig::from_block_target` block-denominated conversion
already has this shape and is kept. A consequence worth stating
before a reviewer flags it: **the submit watchdog goes quiet exactly
when the chain does.** That is correct, not the watchdog sleeping
through its own failure mode — its horizons are progress-denominated,
so nothing accrues against a held tx while nothing advances, and the
stall itself is surfaced by the `ChainProgress` alarm rather than by
legs firing against a stale view.

**Tip source.** The driver reads the same daemon the engine holds
(`self.daemon`), not a persona-isolated transport: the tick base is
principal-side liveness, and every query it makes (tip height) is one
the principal wallet already makes on refresh. Persona-isolated
transports remain confined to the legs that need them (claim-source
fetch inside the claim leg).

**Merge write-lock constraint (kept).** The tick issues daemon
round-trips; it must not run under a merge write-lock
(`engine/mod.rs:1300–1310`). The driver upgrades its `Weak`, takes
read locks per leg, and never holds an engine lock across a leg await.

## 3. The four legs

Registered at driver construction. **Order within a tick is fixed:
retire before assemble** — leg 1 (which releases reservations and
bumps the pending-block `generation`) runs before leg 3 (which
snapshots `reserved_gindexes` for assembly), so a tick's claim
assembly sees the freshest funding set. PR #572's
reservation-release generation stays as the backstop for concurrent
assemblies; **ordering is the discipline, the generation check is the
gate that can fail** (rule 47) — the implementation keeps the
`SealAdmission::Stale` path testable, not vestigial.

**User work always wins; the claim leg yields.** The generation gate
answers only one direction of the race — the leg's assembly going
stale. The other direction is worse: leg 3's snapshot-await-seal span
racing a user-initiated build/submit, where a background claim that
wins fails a foreground send with a staleness error the user did
nothing to cause — a user-visible failure mode that does not exist
today and must not be introduced by a maintenance driver. The ruling
is asymmetric: the leg **skips its fire for the tick** when user
build/submit work is in flight (try-acquire on the shared pending
write lock; never queue against it), and `SealAdmission::Stale` is a
normal outcome only on the leg's side. A background action never
fails a foreground one. Tested in §7 as the mirror of the generation
test.

**Leg isolation: shared tick, not shared failure state.** A leg in
backoff, or one that returns an error, or one that panics
(`catch_unwind` at the leg boundary, panic → that leg parks with an
operator alarm), must not stop the other legs. No leg's error aborts
the loop; the loop exits only on cancellation or failed `Weak`
upgrade.

### Leg 1 — submit lifecycle (every tick)

Calls `run_submit_lifecycle_tick` (F40 targeted re-scan + escape
ladder over every held tx, resubmit-same-bytes, release on
confirmed-absent). Runs for **every wallet**, staker or not — this is
why the driver cannot ride pscan's end-of-sweep (pscan starts only
for stakers). `signal_mempool_evicted` is **not** this leg's job —
its consumer of record is the Stage-4 `MempoolMonitorActor` (§6); the
escape ladder's terminal probe already handles confirmed-absent.

### Leg 2 — serving liveness (predicate, every tick)

For staker wallets, the leg's predicate is **"a serving obligation
exists AND the serving task is not live,"** evaluated every tick; when
it holds, the leg makes one `start_serving_if_staker` attempt. The
predicate is self-arming — no unregister, no session state — and one
condition covers both the start that failed and the serving that
started and later **died** (Tor drops, the task panics, the host loses
its descriptor). An earlier draft had the leg retry until first
success and then unregister for the session; that recovers only the
failed start and reintroduces fire-once one level up — after a single
success the leg is gone, and a died-later serving is back to
wallet-reopen as the remedy, the exact failure this driver replaces.
The predicate shape also makes the leg identical in kind to the
others (evaluate every tick, may no-op), which keeps the registry
uniform.

Liveness is read from the serving task's posture channel
(`ServingHandle::posture`): a dropped sender is a dead task. Restart
makes the driver the natural owner of the *current* handle, so the
`ServingHandle` parks with the driver rather than in
`OpenTasks`; embedder shutdown order becomes cadence (which tears
down any serving it holds, awaited, before exiting) → pscan,
preserving today's serving-before-pscan property. wallet-rpc's
fail-closed open is untouched: a staker whose serving path will not
configure at open still does not open; the leg is the recovery for
post-open death, not a relaxation of the open gate.

One attempt per chain-progress tick gives natural backoff (≥ block
cadence) with no retry storm against a broken Tor config; repeated
failure alarms via the existing serving alarm surface. The
one-attempt ruling inside `task.rs` (§"One attempt, deliberately") is
**amended, not deleted**: one attempt per start call stays; the
driver owns retry across calls.

### Leg 3 — per-epoch claim (every tick; may no-op)

Fires on settlement close, uniform across all wallets, **no jitter** —
see §4. Reads epoch geometry as **data** (rule 71): the leg computes
"newly settled epoch" from the tip height and
`effective_settlement_epoch_blocks()`; there is no nettype control
flow and no driver-local "regtest ticks fast" skip. The test
affordance is the existing **armed** override
`SHEKYL_SETTLEMENT_EPOCH_BLOCKS` (PR-C's composed-arc walk uses
`= 2`), which the driver inherits by calling the same helper.

### Leg 4 — terminal-reject prune / byte-identical resubmit (slot registered now, body unimplemented)

The leg is **registered at construction with an empty body** that
no-ops and names its debt: the `docs/FOLLOWUPS.md` "Drain/claim/unbond
dispatch driver — terminal-reject prune + byte-identical resubmit"
entry (pre-genesis; the prune half is a security item — the retained
terminal-reject copy is a replay channel). Registering the slot now is
the point: when the body lands it inherits this driver's tick,
ordering, and isolation, and **must not grow its own timer**. The
empty leg is a STAGED surface with a named consumer (rule 23), not
dead code; `-29522 UNSTAKE_FATE_UNKNOWN` (PR-C) is the model already
in production for how its absence is honestly surfaced.

## 4. Claim leg policy

### Un-GF-4

Four comments defer claim scheduling to "the GF-4 seam"
(`claim_dispatch.rs:15–17`, `claim_orchestrator.rs:45`,
`stake_engine/claim.rs:56`, `stake_engine/handle.rs:319–320`; banner
echo at `engine/mod.rs:216`). GF-4's grading concern (cadence graded
jointly with amount and holdings stratum) resolved to **uniform,
no-jitter, per-epoch** — stated precisely, because the claim has two
layers that must not be conflated. The **schedule** is uniform: every
wallet evaluates at every settlement close, and "no jitter" means no
deliberate randomized delay, not synchronized submission — actual
submission spreads across each wallet's 60 s poll phase plus
propagation, which is acceptable and mildly helpful. The **inclusion
decision** is value-conditional and therefore weakly observable; that
is the stated concession below, not part of the uniformity claim.
The comments are rewritten to
name this driver as the scheduler (rule 16's
comment-that-outlived-its-architecture: the mechanism they defer to is
now built, so reasoning *from* its absence is invalidated).

### Shape: value-defer, sibling of `size_deferred`

`AssembledClaims.size_deferred` already defers youngest epochs past
the byte budget. The value axis is its sibling: **hold epoch E until
Σreward across held epochs covers the claim fee.** The cadence still
fires every close; the fire may no-op (nothing settled, nothing above
water).

**Shape amendment (implementation, commit 6).** The doc originally
specified a `value_deferred: Vec<u64>` field alongside `size_deferred`.
Implementation showed that shape is wrong for this axis: the hold is
**all-or-nothing** by construction — one claim tx carries every held
epoch, so the floor gates the set's Σreward, never a per-epoch cut —
which means a successful assembly's `value_deferred` field would be
empty always (an all-deferred assembly has no vin to build; an empty
claims leg is unrepresentable on the wire). The gate therefore
surfaces as a typed refusal, `EmissionClaimError::ValueDeferred
{ value_deferred: Vec<(epoch, reward)>, total_reward, fee_floor }`,
raised in `assemble_claims` **before** the size loop (a set that
cannot pay for its one tx has no subset that should). The rewards
ride the refusal because they are recomputed inside derivation and
are no longer derivable once the window expires an epoch — the leg
needs them to price a forfeit honestly. The floor reaches the
assembly as a field on `AssembleEmissionClaim`, passed by its sole
production sender (the claim orchestrator) from
`shekyl_economics::EMISSION_CLAIM_FEE_FLOOR` — a parameter for the
same reason `assemble_claims` takes its size budget: testable at
exact boundaries.

### The floor and the window

- **Value floor:** the claim fee the assembly would pay, compared
  against Σreward of the candidate set. The fee-floor input is a
  **compiled-in constant in a shared crate**
  (`shekyl-economics::fee`, next to the ladder it summarizes),
  uniform across wallets — anti-fingerprint: a per-wallet knob or a
  config value partitions the anonymity set by fee policy. It is
  **not** `config/consensus_constants.json`: freezing a wallet
  fee-policy threshold into consensus buys nothing and costs a
  consensus retune to adjust. Not a per-wallet setting (rule 00 §2:
  privacy is never a setting). The constant's doc carries rationale
  and safe-adjustment bounds (rule 75).
- **At the window floor: evaluate-and-forfeit, never force.** The
  claim window is bounded by the existing prune horizon
  (`prune_below_epoch_at_height`). When held epochs reach the window
  floor (~26 epochs), the leg evaluates once more: claim if the
  accumulated set now clears the fee; otherwise **let it expire and
  alarm**. Still underwater after 26 epochs means the persona earned
  less than one sweep fee in ~12 months — forcing the claim converts
  a zero into a negative. Forfeiture raises the epoch-unclaimed
  operator alarm with the forfeited amount, so the operator's record
  is honest.
- **Stated concession:** skip/batch behavior is observable —
  `reward_P(E)` is public, so an observer can see that a persona
  claimed epochs {E..E+k} in one transaction. This is a weak signal
  (it reveals fee-policy bucketing, which is uniform by construction)
  and is accepted; recorded here so it is a decision, not an
  oversight. One more expected behavior, stated so it is not read as
  a violation of uniform-on-close: a wallet closed for months claims
  its whole backlog on the first post-open tick that observes settled
  epochs, not retroactively at each close. Harmless — a serving
  persona's liveness is already public.

### Failure surfacing (rule 82)

- **Pre-seal** failures (assembly, transport, daemon refusal before
  the pending record seals): leg-local backoff + OA-1-style operator
  alarm; retry next tick. Nothing user-visible is pending yet, so
  retry is safe.
- **Post-seal** failures follow the sealed record's lifecycle (WI-3
  settles it, or leg 4's future body prunes/resubmits). The driver's
  own observability duty is the aggregate: **"epoch E unclaimed after
  N ticks"** raises the epoch-unclaimed alarm.

## 5. Alarms

Named here per rule 05 (landed as implementation commit 1, so this
section and the crate cannot drift). `shekyl-operator-alarm` gains:

- `AlarmCondition::ChainProgress` —
  `OperatorAlarm::ChainProgressStalled { last_height,
  stalled_for_secs }`; clears on the next observed advance. The alarm
  cannot distinguish "the chain stalled" from "this wallet's daemon is
  unreachable or behind," and the second is the more likely cause —
  the variant doc instructs renderers to name **both** and the
  daemon-side remedy first (rule 82: say what the operator can act
  on).
- `AlarmCondition::EpochClaim` — `OperatorAlarm::EpochUnclaimed
  { oldest_epoch, outstanding_epochs }`; faults only — value-deferred
  epochs are policy, not backlog, and do not raise it.
- `AlarmCondition::ClaimForfeiture` — `OperatorAlarm::ClaimForfeited
  { epoch, forfeited_atomic }`; its own condition so the forfeit
  record coexists with a live claim backlog. `Episode` lifetime; its
  non-durability across restart is a named FOLLOWUPS row
  ("Forfeited-claim record does not survive a wallet restart",
  pre-genesis).
- `DisarmedReason::DriverLegParked` — §3's panic-parking rendering.

None of these maps onto an existing condition — `ServeSetIntegrity` /
`ServingDiskHeadroom` / `TransportLiveness` / `VanguardIntegrity` are
all serving-side. WI-3's stall alarms (today `tracing::error` only)
are out of scope here; a FOLLOWUPS row already tracks promoting them.

## 6. What this driver does not do

- **Refresh.** Principal refresh stays on-demand and embedder-driven.
- **Pscan.** The persona scan loop keeps its own 60 s schedule and its
  WI-3 dispatch tick (bond-post due-check, reservation settle). The
  cadence driver does not duplicate WI-3's legs; they compose through
  the shared pending file + `pending_write_lock`, same as today.
- **Mempool monitoring.** The driver does not poll the mempool.
  `signal_mempool_evicted`'s consumer of record is the Stage-4
  `MempoolMonitorActor`
  (`docs/completed/STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.10 G1;
  FOLLOWUPS row "`MempoolMonitorActor` consumer actor", pre-genesis,
  blocked on the Stage 4 actor migration) — cited concretely because
  "a mempool monitor" without the citation is the R-1 shape this
  workstream exists to close. The trait method's `V3.x` allow-comment
  fossil is retagged to this record in this design round (rule 15:
  `V3.x` is not a target).
- **Unbond scheduling.** `unbond_dispatch` is a request path
  (immediate submit) and stays one.

## 7. Test plan

- Driver-loop unit tests with an injectable schedule + scripted tip
  source: fires only on height advance; watchdog alarm on stall +
  clear on resume; leg order (retire before assemble) asserted via
  recording legs; leg isolation (a panicking leg parks, others fire).
- Leg-4 slot: registered **and invoked** each tick (recording legs
  prove invocation). An empty leg that no-ops is otherwise
  indistinguishable from a leg never registered — the failure class
  this workstream exists to close — so the body must land into proven
  wiring.
- Claim-leg policy tests on the armed `SHEKYL_SETTLEMENT_EPOCH_BLOCKS
  = 2` override: no-op tick, value-defer accumulation across closes,
  clear-the-floor fire, evaluate-and-forfeit at the window floor
  (forfeit alarm carries the amount), and **policy determinism**: a
  given tip + held set yields the same inclusion decision on every
  wallet — the uniformity §4 actually claims. Timing is deliberately
  not asserted; production spreads submission across poll phase, so a
  "no-jitter timing" test would pin a property production does not
  have.
- Generation backstop: a test that retires a reservation between a
  claim leg's snapshot and seal and asserts `SealAdmission::Stale` —
  the gate must be able to fail (rule 47).
- Its mirror (§3 "user work always wins"): a user build/submit in
  flight across a claim-leg tick — assert the leg **skipped** and the
  user path completed. A background claim must never fail a
  foreground send.
- Wrap-point test: `into_shared` spawns the driver; dropping the
  handle cancels the task; engine close is not blocked by the driver
  (`Weak` upgrade failure exits the loop).
- Live-daemon rows land in the phase6-ci workstream, not here.

## 8. Implementation checklist (one PR, ordered commits)

1. `shekyl-operator-alarm`: chain-progress + epoch-claim conditions
   (§5's named surface).
2. Driver skeleton in `engine/cadence.rs`: loop, tip poll, watchdog,
   leg registry, isolation, `CadenceHandle`; leg 4 empty slot with
   FOLLOWUPS citation and the §7 registered-and-invoked test.
3. `Engine::into_shared`; wallet-rpc `wrap_and_start_tasks` adopts;
   `OpenTasks` gains the cadence handle; shutdown order. Ordered
   directly after the skeleton so every subsequent leg commit lands
   into a driver production already starts — legs land observable,
   not into wiring nothing exercises.
4. Leg 1 wiring (`run_submit_lifecycle_tick`); delete the
   "cadence is the embedding runtime's" doc claim (premise refuted).
5. Leg 2 predicate; amend the one-shot ruling text in `task.rs`;
   `ServingHandle` ownership moves `OpenTasks` → driver.
6. Value floor constant in `shekyl-economics`; value-defer in
   assembly (`value_deferred` sibling); leg 3 + evaluate-and-forfeit
   + user-work-yield; un-GF-4 the four comments.
7. Docs: this banner → implemented; index row; FOLLOWUPS (repair the
   truncated "Emission-claim retire/resubmit driver legs" title while
   editing); `USER_GUIDE.md` rewards sentence; CHANGELOG (user-visible:
   rewards claim automatically; stuck-tx watchdog runs unattended).

Rule 91's doc task is commit 7; rule 90 scope-per-commit holds within
the PR.
