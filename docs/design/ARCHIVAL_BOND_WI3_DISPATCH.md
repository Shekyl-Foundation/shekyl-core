# WI-3 — Block-timed bond-post dispatch driver

> **Status: design round 1, 2026-07-05.** The spec-first round the WI-3
> implementation anchors on (rule `05-system-thinking`; process shape per
> `26-sub-pr-design-discipline` — this slice touches a broadcast-privacy
> surface and a persisted-schema bump, so it gets an explicit round). This
> is an addendum to
> [`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md`](ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md)
> (the SP-T4a seam this driver is the gated consumer of) and
> [`ARCHIVAL_BOND_WI2_ASSEMBLY.md`](ARCHIVAL_BOND_WI2_ASSEMBLY.md) §3.5
> (the sealed pending post this driver consumes). Index row: `WI-3` in
> [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md).
>
> **Timeframes (rule 05):** *now* — genesis JoinMarket bond-post dispatch.
> *Mining-era end* — no coupling: the clock is block height (consensus-
> native), the driver consumes sealed bytes and typed plans. *V4* — no
> cryptographic surface: the driver never constructs or signs; it re-sends
> bytes minted behind the WI-2 seams, which migrate independently.

## 1. Scope

Make the sealed pending post actually reach a wire at its planned block.
In scope:

1. The **due-check** on the `P`-scan block clock (§3.1).
2. **Dispatch mechanics**: re-lift the sealed bytes, route through
   `BroadcastSubmitter::submit_bound`, seal the state transition (§3.3).
3. **Outcome handling**: accept / F31 in-pool / F40 already-in-chain /
   terminal rejection (§3.4).
4. **Confirmation and retirement** via the pscan's own bond-post matches
   (§3.5).
5. **Retry / re-anchor semantics** — what late means, what stale means,
   and what never re-draws (§3.6).
6. **D1 entry-event coordination** — no shared-tick co-launch (§3.2).
7. Live **`BondPostDispatched`** GF-7 emission (§3.7).
8. `PENDING_POST_VERSION` 1 → 2 (rule 42) for the new state arms.
9. Failure modes (rule 82) and the acceptance gate, including the named
   WI-4 reconvergence gate (§5).

Out of scope: the WI-2 Engine-side assemble orchestrator (WI-2's remaining
slice — this driver consumes whatever sealed posts exist, zero or more);
serve-credit challenge-response broadcast (SP-T4b, separate gated slice);
posture-aware `PBlockSource` and external-spend reconcile (2d-2).

## 2. Substrate (verified at `feat/bond-assembly`, 2026-07-05)

| Fact | Where |
| --- | --- |
| The pscan task is the only per-`P` block clock: one `tip_height()` read per cadence tick, per-`P` block source, per-`P` circuits | `pscan/task.rs` `pscan_sweep` |
| `PendingBondPost` carries `anchor_t0` + `bond_post_offset_blocks`; the due-check is pure: `due = anchor_t0 + bond_post_offset_blocks` | `pending_post_block.rs` |
| `PendingPostState` v1 is `Pending`-only **by design** — the dispatched/confirmed arms are WI-3's to add with a version bump | `pending_post_block.rs` doc |
| `PBoundBytes::from_pending` re-lifts the sealed `(persona, tx_bytes)` twin; pin P-2 = retries re-send the *stored* value | `bond_assembly.rs` |
| `submit_bound` panics on persona mismatch; `②→PerP` routing is by type (`BroadcastPosture`), never the principal submitter | `transaction_submitter.rs` §3.1 |
| F31: an in-pool byte-identical resubmit is an idempotent status query; escalation beyond it is the alarm rung | `submit_watchdog.rs` |
| F40: `AlreadyInChain { height }` places the awaiting-lock, never releases early — no selectable-input window | `transaction_submitter.rs`, `local_pending_tx.rs` §2.5 |
| The dual extractor already emits `BondPostMatch { height, p_canonical_id, post_kind }` for every scanned bond post, reorg-deep by the sweep horizon | `pscan/scan_step.rs`, `task.rs` `record_unbonds` |
| The entry-gap draw decorrelates bond-post↔funding **ordering only** — not the principal lifecycle, not `P`'s other broadcasts (the D1 finding) | `stake_engine.rs` GF-7 scope note; `GF7_HOOKS` §1 |
| Sim-synthesized `BondPostDispatched` is interim; the live emission is this driver's, and WI-4's seal re-runs against it | `GF7_HOOKS` §5.1 constraint 5 |

## 3. Design decisions

### 3.1 D-B1 — The block clock is the pscan sweep's tip read

**Decision.** The due-check runs at the end of every pscan sweep tick,
against the same `tip_height()` the sweep already fetched. No new network
read, no separate timer task, no wall-clock schedule.

- **Clock value:** the **raw claimed tip**, not the finality horizon. The
  plan's offsets are relative to `anchor_t0`, which WI-2 stamps as the raw
  tip at assemble time; due-checking against the same clock keeps the
  offsets meaning what the draw drew. (The finality horizon lags by
  `ARCHIVAL_REORG_DEPTH_BLOCKS`; due-checking against it would silently add
  a constant ~reorg-depth delay to every post — harmless for privacy,
  wrong for the plan's semantics.)
- **Why this clock and not the principal's refresh:** the dispatch time
  must be a function of `P`'s own isolated view. Deriving it from the
  principal's refresh loop would couple `P`'s broadcast timing to the
  principal's activity rhythm — manufacturing exactly the axis-(iii)
  correlation GF-7 measures.
- **Tip dishonesty:** an over-claiming source can make a post due early by
  at most the over-claim; an under-claiming source delays it. Both degrade
  timing *noise*, neither creates linkage the plan didn't already accept
  (the plan is jitter, not a commitment), and tip-honesty is the 2d-2
  posture residual already named in `pscan/task.rs`. No new machinery.

### 3.2 D-B2 — D1: no shared-tick co-launch

The index-row D1 invariant, discharged in three parts:

1. **WI-3 dispatches exactly one event class: the bond post.** The entry
   event is not this driver's to launch. At genesis fund-from-earnings,
   `P`'s observable funding/entry events materialize through the earnings
   flow on their own timeline; any future wallet-authored entry event gets
   its own driver, its own anchor, and the principal-side submitter — it
   must never be enqueued on the pscan tick. This is structural (the
   driver's input type is the pending-post seal, which carries only bond
   posts), not disciplinary.
2. **At most one dispatch per sweep tick.** Distinct personas' posts have
   independently-anchored due blocks (independent draws, independent
   `anchor_t0`), so same-tick collisions are rare in steady state — but a
   catch-up sweep after downtime makes *every* overdue post due on one
   tick, and co-launching them links the wallet's personas to each other
   by simultaneity. The driver dispatches the single overdue post with the
   **lowest due block** (ties: lowest `anchor_t0`, then persona id — pinned
   so replay is deterministic) and leaves the rest for subsequent ticks.
   The added delay is monotone noise (§3.6).
3. **Send-time dispersal within the tick.** A sweep tick is also a burst
   of per-`P` block fetches, and every dispatch fired "at the tick" is
   phase-locked to the wallet's cadence — a wallet-level fingerprint
   shared across its personas. The dispatch therefore sleeps an
   independently drawn uniform delay in `[0, tick_interval)` (fresh
   `OsRng` draw at dispatch time, per post) before the submit call. This
   is behavioral wall-clock, which is fine — the GF-7 *payload* ban on
   wall-clock (hooks-spec §3) governs event fields, not behavior. The
   dispersal draw is deliberately **not** the entry-gap draw machinery: it
   decorrelates from the sweep phase, not from the funding seam, and
   conflating them would muddy what WI-4 grades. Whether `[0, tick)` is
   enough is exactly a WI-4 question; the a-priori threshold artifact
   grades it (§5).

### 3.3 D-B3 — Dispatch mechanics and the seal-before-send ordering

**Decision.** Per dispatch:

1. Read the sealed `PendingPostBlock`; find due posts (`state == Pending`,
   `tip >= due`).
2. Transition the chosen post to `Dispatched { at, attempts: 1 }` and
   **seal the block before any network send**. A crash between seal and
   send resumes as "maybe sent", which is safe *because* the resend is
   byte-identical (pin P-2 idempotence); the reverse ordering (send, then
   seal) can lose the fact of a send, which is not recoverable. This is
   the same fail-shape asymmetry as WI-2's persist-before-dispatch and the
   pscan's seal-then-act.
3. Re-lift `PBoundBytes::from_pending(&post)` and submit through
   `BroadcastSubmitter::submit_bound` — the single choke path; the P-1/P-2
   pins compose: stored value → provenance-typed wrapper → persona-checked
   PerP egress. There is no other call site.

**New state arms** (`PENDING_POST_VERSION` 1 → 2, rule 42; pre-genesis, a
v1 seal fails closed and the operator re-assembles):

```text
PendingPostState::Pending                              // as v1
PendingPostState::Dispatched { at: BlockHeight,        // tip at first send
                               attempts: u32 }         // total send attempts
```

There is no persisted `Confirmed` arm: confirmation *removes* the record
(§3.5) — retirement and reservation release are one atomic seal, and a
live record always means a live reservation.

**Writer discipline.** The pending seal now has two writers: the WI-2
assemble path (append) and this driver (transition/remove). Two writers
racing one read-modify-seal cycle is the exact bug class D-A4's sibling-
block split exists to avoid, so the seal gets a single shared write path:
one `PendingPostStore` handle owning an async mutex around
load→modify→seal; both writers go through it. (Same shape as `PScanStore`,
plus the lock because unlike the pscan seal this one legitimately has two
writers on two cadences.)

### 3.4 D-B4 — Outcome handling

| Daemon outcome | Disposition | Record after |
| --- | --- | --- |
| Accepted | normal path; await pscan confirmation (§3.5) | `Dispatched` |
| F31 in-pool duplicate | success-equivalent: the bytes are relayed; a later byte-identical resubmit is an idempotent status query | `Dispatched`, `attempts` bumped on each resubmit |
| F40 `AlreadyInChain { height }` | success-equivalent: mined; **do not** release the reservation on the daemon's claim — release only on the pscan's own reorg-deep observation (§3.5). Fund-safety-first: no window where the funding is selectable while the spend may still be real | `Dispatched` |
| Transport failure (timeout, circuit down) | unknown-outcome: state already says `Dispatched`, so the next due tick resubmits the same bytes; watchdog-bounded (below) | `Dispatched`, `attempts` bumped |
| Terminal verify rejection (invalid, double-spend conflict, stale membership reference) | **fail loud, stop resending**: remove the record, release the reservation, surface a typed error/alarm. No automatic re-assembly (§3.6) | removed |

**Resubmit cadence and bound.** A `Dispatched` post whose persona has no
confirmation yet is re-sent (same bytes, same choke path) on subsequent
sweep ticks, subject to the same one-per-tick rule and dispersal draw,
with a bounded attempt budget in the submit-watchdog's shape: beyond the
bound, resending is pointless by construction (F31 — the pool either has
it or is censoring) and the escalation is the operator alarm, not a
faster loop. The alarm is a wallet-side diagnostic, never an on-chain or
network probe.

### 3.5 D-B5 — Confirmation via the pscan's own matches

**Decision.** Confirmation is observed, never claimed: the dual extractor
already emits a `BondPostMatch` for every bond post the sweep scans, and
everything the sweep scans is reorg-deep (the horizon). When a sweep
yields a JoinMarket match whose `p_canonical_id` equals a live record's
persona, the driver removes the record — retiring the post and releasing
the funding reservation in the same seal.

- **Persona-level matching is sufficient at genesis** because of the
  one-live-post-per-persona invariant: there is at most one in-flight post
  a match could confirm. Reopen criterion (rule 21): the multi-kind /
  multi-post future (Rebond etc., CONSTRUCTION §9) adds a txid or
  post-hash discriminator to both `BondPostMatch` and the record — a
  version-bumping change owned by that slice.
- **State-agnostic**: the check runs against `Pending` records too. A
  `Pending` record whose persona shows a confirmed post is the
  seal-before-send crash case (sealed `Dispatched`… never actually
  transitioned but bytes were sent — or a prior process instance sent and
  died pre-seal); observed reality wins, the record retires.
- **No daemon-claim shortcut**: F40's `height` claim never releases the
  reservation (§3.4). The pscan observation is the wallet's own verified
  view; the daemon's word is not.

### 3.6 D-B6 — Retry / re-anchor semantics

**Decision — late is noise, stale is terminal, re-anchor means re-assemble.**

- **Late dispatch.** A post whose due block passed while the wallet was
  down dispatches on the first sweep that observes `tip >= due`. Lateness
  only ever *adds* delay after a privately-anchored plan — monotone noise
  on top of the drawn jitter, no re-correlation. The plan is **never
  re-drawn for existing bytes**: the bytes commit to nothing temporal, and
  a re-draw would break the draw→plan→dispatch audit chain (the golden-
  vector discipline) for zero privacy gain.
- **Staleness.** The sealed bytes embed an FCMP membership proof anchored
  at the assemble-time tree reference. If the chain outruns the daemon's
  acceptance window for that reference, the submit fails verify — that is
  the terminal-rejection row of §3.4: remove, release, alarm. The record
  itself never expires by local timer; staleness is adjudicated by the
  verifier, not guessed at by the wallet.
- **Re-anchor = a fresh WI-2 assemble.** New funding selection (the
  reservation was released), fresh entry-gap draw, fresh `anchor_t0`,
  fresh bytes, sealed as a new pending post. It is **not automatic**: an
  auto-re-assemble loop driven by rejections hands a malicious daemon a
  lever to pump the wallet into repeated assemble+broadcast cycles on the
  adversary's clock (a probe amplifier). The rejection surfaces loudly;
  the re-assemble fires on the next natural bond-attempt trigger with the
  operator aware. Reopen criterion (rule 21): if 2d-2's posture work
  lands a daemon-response authentication story that demotes "malicious
  daemon" below this threat, an automatic re-assemble with capped backoff
  can be reconsidered in that design round.

### 3.7 D-B7 — Live `BondPostDispatched` emission

**Decision.** The driver takes its own injected
`BroadcastTimelineObserver` (gf7-hooks feature-gated, `NoOpObserver`
production default — the hooks-spec §3/§4 discipline verbatim) and emits
`BondPostDispatched { persona, at }` at the submit call site, after the
dispersal sleep, with `at` = the logical block (the tip the due-check
fired against) and `persona` = the opaque wallet-local slot ordinal
already used by the assemble-side emissions. Payload discipline holds: no
wall-clock, no txid, no identity. This retires the hooks-spec §0 interim
(sim-synthesized dispatch events) and arms WI-4's sealing re-run (§5).

## 4. Failure modes (rule 82)

| Failure | Shape | State after |
| --- | --- | --- |
| Sweep tick with no due posts | not a failure; no-op | unchanged |
| Seal write fails at the `Dispatched` transition | error logged; **no send happens** (seal-before-send); retried next tick | `Pending`, nothing sent |
| Crash after seal, before send | resume treats `Dispatched` as maybe-sent; byte-identical resubmit next due tick | `Dispatched` |
| Transport failure on submit | unknown-outcome resubmit path (§3.4) | `Dispatched`, attempt bumped |
| Attempt budget exhausted | operator alarm; resubmits stop; record held (reservation intact — funds-safety over liveness) | `Dispatched`, alarmed |
| Terminal verify rejection | remove + release + typed alarm; no auto-re-assemble | removed |
| Confirmation observed | retire + release in one seal | removed |
| v1 seal under a v2 binary | fails closed on version; operator re-assembles (pre-genesis, rule 15) | n/a |

## 5. Acceptance criteria — including the WI-4 reconvergence gate

Functional gates (all must pass to merge):

1. Due-check correctness: pure `anchor_t0 + offset` arithmetic, boundary
   tests at `tip == due − 1 / due / due + k`.
2. One-per-tick and deterministic ordering under a synthetic multi-overdue
   backlog.
3. Seal-before-send ordering pinned by a test that fails the send and
   asserts the sealed state already says `Dispatched`.
4. Byte-identical resubmit: the submitted bytes on attempt *n* equal the
   sealed bytes, every attempt, via the `submit_bound` choke (P-2 pin
   extended to the retry path — closing SP-T4 §3.1.1 open-as-frozen H2).
5. Confirmation retire + reservation release atomicity; state-agnostic
   confirmation (the `Pending`-but-confirmed crash case).
6. Terminal rejection releases the reservation and never resends.
7. Schema: v2 round-trip; v1 fails closed.
8. GF-7: emission-completeness test extends to `BondPostDispatched` (the
   stake-engine emission test's shape, driver edition).

**Reconvergence gate (rule 21, named per the index row):** WI-3's
**GF-7 acceptance does not close at merge.** It closes when:

- **(a)** WI-4's a-priori threshold artifact exists — the committed
  `P(link | T_obs)` bound derived from a stated adversary-advantage claim
  *before* any grading run (GF7_HOOKS §5.1 constraint 1); and
- **(b)** WI-4's sealing re-run against **this driver's live
  `BondPostDispatched` emission** (not the sim-synthesized interim)
  passes under that threshold (§5.1 constraint 5).

Until (a)+(b), the WI-3 index row carries "merged, GF-7 acceptance
pending WI-4 artifact" — the armed-gate-without-trigger inversion the
WI-4 review pinned: the gate exists before the thing it gates is graded,
never the reverse. A failed re-run is a **decorrelation-redesign signal
against this doc's §3.2/§3.6 dispositions** (reopening this round), never
a move-the-threshold signal.

## 6. Round-1 closure

Open for round-2 review (none block the seams above):

- **(a)** The dispersal draw's range (`[0, tick_interval)`) — held cheap
  here; WI-4's grading is the arbiter and can send it back.
- **(b)** The attempt-budget constant — proposed to reuse the
  submit-watchdog's bound rather than a new tunable (rule 75: every
  tunable needs a rationale; reuse inherits the existing one).
- **(c)** Whether the one-per-tick rule should also space *first*
  dispatches a minimum number of ticks apart when the backlog is deep
  (beyond one-per-tick) — deferred to WI-4 evidence, same reopen shape
  as (a).
