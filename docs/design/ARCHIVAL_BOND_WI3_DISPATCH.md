# WI-3 — Block-timed bond-post dispatch driver

> **Status: design rounds 1–2, 2026-07-05.** The spec-first rounds the WI-3
> implementation anchors on (rule `05-system-thinking`; process shape per
> `26-sub-pr-design-discipline` — this slice touches a broadcast-privacy
> surface and a persisted-schema bump, so it gets explicit rounds). Round 2
> was an adversarial review pass; its findings and dispositions are §7, and
> the affected dispositions (D-B1, D-B3, D-B6, §5) are amended **in place**
> — this doc is the living spec, §7 is the change record. This
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

### 3.1 D-B1 — The dispatch clock: sweep-corroborated, never
### daemon-authoritative (amended, round 2 R2-1)

**Round-1 shape and why it was wrong.** Round 1 due-checked against the
raw claimed `tip_height()` — a bare daemon-controlled number. An inflated
claim makes every pending post read as due immediately: the drawn jitter
(`spread`, `bond_first`, the §3.2 dispersal) is denominated in that clock,
so a lying tip spends the whole GF-7 decorrelation budget to zero and
re-introduces D-B2's co-launch-by-simultaneity through the clock instead
of the backlog. That is a **privacy** failure, which under `00-mission`
priority-2 outranks the plan-frame argument that motivated the raw tip.
Round 1's own D-B6 refused the rejection pump on exactly the
"daemon-controlled input driving the dispatch path" ground; the same
ground indicts the raw tip.

**Decision (amended).** The due-check runs at the end of every pscan
sweep tick — no new network read, no separate timer task, no wall-clock
schedule — against the **dispatch clock**, a monotone, sweep-corroborated
value:

```text
dispatch_clock = min(claimed_tip,
                     verified_frontier + ARCHIVAL_REORG_DEPTH_BLOCKS)
```

where `verified_frontier` is the accrual's exhaustiveness-verified scan
frontier (`PScanAccrual::next_height`) — a height the sweep has actually
fetched, chained via `verify_exhaustive` to the wallet's own sealed
`frontier_hash`, and sealed. The frontier can only advance behind a
`VerifiedBatch` (`accrual.rs`'s structural guard), so the clock's
corroborated component is anchored to scanned reality, not to a claim.

- **Honest steady state is unchanged.** Once caught up, the frontier
  tracks `tip − reorg_depth` exactly (the sweep scans to the horizon every
  tick), the clamp is inactive, and the clock equals the claimed tip — the
  round-1 frame argument (offsets mean what the draw drew; no silent
  reorg-depth delay) is preserved wherever the daemon is honest.
- **The free lie is structurally forbidden.** A daemon that inflates the
  claimed tip without serving blocks strands the sweep at `MissingBlock`
  (or fails the exhaustiveness gate); the frontier does not advance, the
  clamp holds, and no post becomes due early. Making the inflation
  effective now requires fabricating and serving a coherent block sequence
  that chains to the wallet's own sealed frontier hash and scans clean —
  the attack cost rises from "report a number" to "manufacture a chain",
  and a manufactured chain is the 2d-2 **tip-honesty posture residual**
  already named at `PScanTaskError::Exhaustiveness` — a known, owned
  residual, not a new surface this driver adds.
- **Stalling is the safe direction.** An under-claimed tip (or a frontier
  held back by withheld blocks) only *delays* dispatch — monotone noise on
  a privately-anchored plan (§3.6 late-is-noise), degrading to the same
  liveness-not-privacy class as an eclipsing daemon, which is
  network-layer scope. The dangerous direction (under-jitter via
  inflation) is the one the clamp forbids.
- **Frame consistency.** `anchor_t0` is stamped from the **same
  `dispatch_clock` function** at assemble time — a pin on WI-2's
  Engine-side orchestrator (not yet built; recorded at
  `ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.5's anchor bullet). Anchor and
  due-check reading one clock keeps the offsets' meaning invariant under
  the clamp.
- **Why this clock and not the principal's refresh:** unchanged from
  round 1 — the dispatch time must be a function of `P`'s own isolated
  view; deriving it from the principal's refresh loop would manufacture
  exactly the axis-(iii) correlation GF-7 measures.

**Reopen criterion (rule 21), shared with D-B6:** both are "how much does
the dispatch path trust the daemon's clock", and both reopen together in
the 2d-2 posture design round (daemon-response authentication /
tip-honesty machinery). Until then the clamp is the structural floor.

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

**Crash-atomicity (round 2, R2-2).** The lock above is a *thread-safety*
guarantee; the resume-after-crash story needs a *crash-atomicity*
guarantee, and they are not the same thing. Here the second is structural
rather than transactional: the **entire** pending-post state — every
record, its `state` arm, its held bytes — lives in **one** sealed
postcard blob committed by **one** `atomic_write_file` (the `.wallet.pscan`
seal shape), and the reservation is **derived, never stored** —
`PendingPostBlock::reserved_gindexes()` is computed from the live records
on every read, so there is no second write a crash could tear it apart
from. A crash leaves either the old seal or the new seal, both
self-consistent by construction; the "sealed-`Dispatched` but reservation
in the pre-dispatch state" tear is *unrepresentable*, which is stronger
than a multi-write transaction that merely makes it atomic. The invariant
this rests on is pinned for implementation and review: **no pending-post
state exists outside the blob** — no side files, no split writes, no
cached reservation table, no field whose truth lives anywhere but the
sealed records themselves. Any future change that externalizes a piece of
this state must bring its own transaction boundary and reopen this
disposition.

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
  verifier, not guessed at by the wallet. **Removal is also the byte-prune
  and the reservation release, in one seal (round 2, R2-4):** the record
  *is* the stored signed bytes and *is* the reservation (derived, §3.3
  R2-2), so a terminal reject cannot leave an abandoned key-image-bearing
  spend at rest for a restart to resurrect, and cannot leave a record
  whose reservation is gone — both torn intermediates are unrepresentable
  under the single-blob invariant. When a manual re-anchor then mints
  fresh bytes, at most one broadcast-ready bundle per persona exists at
  any instant, preserving WI-2 §3.5.1's retention bound.
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
9. Clock integrity (R2-1): an inflated claimed tip with a non-advancing
   frontier makes **no** post due (the clamp holds); frontier catch-up to
   the inflated height releases the clamp only through verified batches;
   an under-claimed tip only delays. Honest steady state: clamp inactive,
   clock == claimed tip.
10. Single-blob invariant (R2-2/R2-4): a review-gate assertion that no
    pending-post state lives outside the sealed block (no side files, no
    split writes), plus a test that terminal removal prunes the bytes and
    the derived reservation in the same seal.

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

**Dispersal is provisional in the same sense as the emission (round 2,
R2-3).** The §3.2 dispersal draw is a *new* timing-entropy primitive that
exists only in the live driver; the sim's `--gf7-timeline` synthesis does
not contain it unless it is modeled. WI-4's pre-live run must therefore
treat the dispersal **distribution** (shape and range, not just presence)
as a swept parameter of the synthesis — otherwise the "range suffices"
conclusion is drawn against a correlator that never saw dispersal, and
§6(a)'s held-open question gets a false answer nobody re-checks. The
sealing re-run in (b) is where the *actual* dispersal timing is graded;
any pre-live conclusion about the range is provisional-until-live-re-run
exactly as the emission itself is. This constraint binds WI-4's
measurement design (an addendum obligation on the WI-4 row), not just
this driver.

## 6. Round-1 closure

Open at round-1 close (none block the seams above):

- **(a)** The dispersal draw's range (`[0, tick_interval)`) — held cheap
  here; WI-4's grading is the arbiter and can send it back. *(Round 2:
  subsumed by R2-3 — the range question is answerable only against a
  synthesis that sweeps the dispersal distribution, and any pre-live
  answer is provisional; see §5.)*
- **(b)** The attempt-budget constant — proposed to reuse the
  submit-watchdog's bound rather than a new tunable (rule 75: every
  tunable needs a rationale; reuse inherits the existing one). *(Stands
  open for the implementation PR.)*
- **(c)** Whether the one-per-tick rule should also space *first*
  dispatches a minimum number of ticks apart when the backlog is deep
  (beyond one-per-tick) — deferred to WI-4 evidence, same reopen shape
  as (a).

## 7. Round 2 (2026-07-05) — adversarial review findings and dispositions

Round 2 verified all seven round-1 dispositions at source and wargamed
the dispatch path. Four findings, severity-ordered; dispositions amended
in place (§3.1, §3.3, §3.6, §5) with this section as the change record.

| # | Finding | Severity | Disposition |
| --- | --- | --- | --- |
| R2-1 | The round-1 dispatch clock trusted the daemon's bare claimed tip; an inflated claim makes every post due at once, collapsing the entire GF-7 jitter budget (spread, order-coin, dispersal) to zero — D-B2's co-launch re-introduced through the clock. Privacy failure; priority-2 outranks the fund-safety framing round 1 led with, and D-B6's own "daemon-controlled input" ground indicts it | **Load-bearing** | D-B1 amended: sweep-corroborated `dispatch_clock = min(claimed_tip, verified_frontier + reorg_depth)`. Free lie structurally forbidden (frontier advances only behind `VerifiedBatch`); fabricated-chain inflation named to the 2d-2 tip-honesty residual; stalling is the safe direction; `anchor_t0` pinned to the same clock function (WI-2 orchestrator pin). Reopen shared with D-B6 (2d-2 posture round) |
| R2-2 | "One locked write path" states thread-safety, not crash-atomicity; a torn seal-vs-reservation write would void the P-2 safe-resend guarantee at resume | Pin now | §3.3 amended: crash-atomicity is structural — one blob, one `atomic_write_file`, reservation derived-never-stored, torn states unrepresentable. "No pending-post state outside the blob" pinned as implementation invariant + §5 gate 10 |
| R2-3 | The dispersal draw exists only in the live driver; WI-4's pre-live run grades a synthesized timeline that lacks it, so a "range suffices" conclusion could be drawn against a correlator that never saw dispersal | Sequencing | §5 reconvergence gate amended: the dispersal *distribution* is a swept parameter of the sim synthesis; any pre-live range conclusion is provisional-until-live-re-run, same status as the emission. Binds WI-4's measurement design (WI-4 row obligation). §6(a) subsumed |
| R2-4 | Terminal reject must not strand the signed key-image-bearing bytes at rest, nor leave a record whose reservation is gone — a restart would resurrect an abandoned spend | Minor | Structurally closed by R2-2's shape: the record *is* the bytes *is* the reservation; removal is one seal. Stated explicitly in §3.6; test in §5 gate 10 |

Round 2 closes with no open structural items; (b)/(c) of §6 remain the
implementation-PR and WI-4-evidence questions they were. Reopen per the
per-disposition criteria above, not by sequential numbering (rule 21).
