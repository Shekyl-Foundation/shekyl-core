# CT-5d (reanchor slice) — proactive horizon + reorg-fork-crossing re-anchor (design round)

**Status:** Design round conducted 2026-06-18 (two passes — the second absorbed
six seam findings validated against the code: F-A consent-keys-on-realized-delta,
F-B/§3a three-phase prover-lock-free, F-C two-sided ingested-tip gate, F-D
point-query staleness + drop the `merge.rs` coupling, F-E the `in_flight`
ambiguous-state slot, and F-F refuted — pending state is runtime-only, no
migration). Decisions locked below. This is the frozen contract the CT-5d
reanchor slice cuts against, per
[`05-system-thinking`](../../.cursor/rules/05-system-thinking.mdc) and
[`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc).
Scope split per [`19-validation-surface-discipline`](../../.cursor/rules/19-validation-surface-discipline.mdc):
this slice is the **engine reorg/horizon validation surface**; the Tier-B
reconstruct-root fixture (`ct2_tier_b.json` + un-ignoring `recon_tier_b.rs`) is a
**separate curve-tree slice** (partly daemon-blocked on the `0x07` adversarial
oracle), not bundled here. Refines [`CT5_ENGINE_WIRING.md`](CT5_ENGINE_WIRING.md)
§3.6 / §5 O1-sub (E5).

**Mission framing.** A built-but-unsubmitted proof anchors to a reference block
that a tip-advance or reorg can stale/orphan; absent a guard this degrades to
submit-time daemon rejection (DoS, never a witness leak — O5). The slice also
carries a **consent** obligation (mission #2 axis): a re-anchor must never
broadcast transaction content the user did not authorize.

---

## 1. Problem: two staleness events, one of them invisible to the age predicate

A pending tx anchors at `reference_height = tip − REF_ANCHOR_AGE` (=6) at build.
Before submit, two events can stale/orphan it:

1. **Age (proactive horizon).** The tip advances until the reference ages past
   the daemon acceptance window — `reference::should_reanchor(tip, ref_h)` fires
   (`age ≥ REBUILD_AT = 50`).
2. **Reorg-fork-crossing (E5 / O1-sub).** A reorg *deeper than `REF_ANCHOR_AGE`*
   orphans the reference (`reference_height ≥ fork_height`) while the new tip
   stays above it, so `age` is `Some(< 50)` and the age predicate **stays
   quiet**. Only the engine knows `fork_height` (`reference.rs` sees only tip +
   reference), so this trigger is CT-5's responsibility, not the curve-tree
   crate's.

**Parameter pin (do not "fix" by tuning).** `REF_ANCHOR_AGE` is
**consensus-uniform for privacy** (X1 / O1-priv): a deeper per-wallet reference
would cut reorg-crossings but fingerprint the wallet. Handling staleness
in-architecture is mandatory; the window is not a knob. `REF_ANCHOR_AGE`'s own
reversion clause (`reference.rs`) moves it only on a `MIN_AGE` consensus change
or an observed deep-reorg-rate change, not by preference.

---

## 2. Shape: lazy-rebuild, eager-mark, stable id

Three scheduling/identity decisions, resolved:

- **Eager mark, lazy rebuild.** The reorg branch *marks* crossing txs; the
  expensive rebuild (prover work) happens only at submit. Nobody pays the prover
  cost for a tx that may never submit, and the E5 burst (every in-flight proof
  orphaned at once) is not paid for abandoned txs.
- **Stable `ReservationId`.** The handle never invalidates across a re-anchor.
  The lazy model assumes the consumer built and walked away, so there is no
  channel to hand back a freshly-minted id — minting one only works if someone
  is listening at reorg time, which is exactly when they are not.
- **Consent is carried by a content generation, not the id** (§4).

### Prerequisite (a CT-5b deferral to land first)

`ConsumerHeldEntry` does **not** record the reference the tx was built against
(CT-5b §3.5-step-4 was specified but never landed). Step one: store the built
`ReferenceBlock` on `ConsumerHeldEntry` (and surface `reference_height` on the
`PendingTx` handle for diagnostics). `should_reanchor` / `reference_orphaned`
read it.

---

## 3. Re-anchor is two operations on the lock axis — consent is separate (Finding 1)

"Re-anchor = rebuild for recipients" over-specifies. Reselection is only forced
when the reorg orphaned a **selected output**, not merely the reference. The
spent outputs are matured and typically well below `tip − 6`; a reorg whose
`fork_height` sits *between* the selected outputs' creation heights and the
reference height orphans the **anchor only** — the spend is fully valid (same
outputs, key images, destinations). So fork on **"did the reorg orphan any
selected output,"** not "did it cross the reference":

- **Reprove — the common path.** Trigger: `fork_height >` every selected output's
  creation height (or pure age-staleness with no reorg). Action: re-select the
  *reference* at the fresh (ingested-gated, §3a) tip, re-assemble the membership
  paths, re-sign. **Same inputs ⇒ same output locks ⇒ no reservation swap.**
- **Reselect — the rare deep path.** Trigger: `fork_height ≤` some selected
  output's creation height — a spent output was orphaned. Action: full rebuild
  (re-select outputs + reference + re-assemble + re-sign), swapping the old
  output locks for new ones under the same `ReservationId` (§3a phase 1/3).

This is the **lock-mechanics** axis only — does the reservation's input set
change. It is **not** the consent axis: a reprove can still change the realized
`(fee, change)` (tree-depth growth or a moved fee snapshot — §4 F-A), so consent
is gated on the realized delta in §4, *not* on which path ran here. Reprove
"usually" preserves content and reselect "usually" changes it, but the gate keys
on the delta, never on the correlation.

### 3a. Three-phase: the prover runs **lock-free** (Finding 2 + B, and the actor-forward shape)

Re-anchor includes re-sign, which runs the FCMP++ prover. CT-5c's build flow
deliberately `drop(state)`s the pending-tx lock **before** `assemble_tx().await`
(via `CurveTreeActor`) and `sign_transfer().await` (via `KeyActor`), so the
prover never holds the lock (`local_pending_tx.rs:1080`). Submit-time re-anchor
has the identical obligation — holding the lock across the prover stalls every
other build/submit. So re-anchor is **three-phase**, not one hold:

1. **under lock₁** — authoritative staleness check (§5) + snapshot the selected
   inputs; for *reselect*, reserve the new outputs now, holding **both** old and
   new locked across the prover (so a concurrent build can't grab them).
2. **lock dropped** — `assemble_tx` (CurveTreeActor) + sign (KeyActor). The prover
   runs here, lock-free.
3. **under lock₂** — **re-check** staleness (the tip/tree can move during the
   prover run — the TOCTOU the lock-drop opens), then commit the swap
   (`tx_bytes`, `reference`, `content_gen`, release the *old* locks) — or, if
   re-staled, discard the just-built artifact and bounded-retry / fail clean.

So the authoritative staleness check is **at commit (after the prover)**, not
merely "before broadcast"; and reselect's reservation **spans** the prover with a
commit re-validation, rather than a single lock hold.

**Why this is the kameo-actor-forward shape (not just a lock fix).** The Stage-4
`PendingTxActor` (`local_pending_tx.rs:166`) replaces `Mutex<PendingTxState>` with
a kameo actor. An actor handler that `await`ed the prover would block its mailbox
exactly as holding the Mutex blocks callers today. The three phases are pure-sync
critical sections (snapshot+reserve, commit+swap) that map directly to actor
messages, with the prover's cross-actor awaits (`CurveTreeActor`, `KeyActor`)
*between* them. Designing re-anchor three-phase now makes the actor migration a
mechanical lift; the commit re-validation is the TOCTOU guard whether the
critical section is a `Mutex` guard or a message handler.

### 3b. The ingested-tip gate is two-sided (Finding C)

A reorg is exactly the window where the tree's `ingested_tip_height` **lags** the
chain tip (rolling back + re-ingesting the new fork). The fresh reference is
selected against `min(chain_tip, ingested_tip) − REF_ANCHOR_AGE` — the same
`ingested_tip_height().await` gate CT-5c's build already applies. But that lower
bound is **one-sided**: if the tree is far behind (post-reorg resync, or a wallet
that woke with an old `consumer_held` tx), `ingested_tip − 6` can sit *below*
`chain_tip − MAX_AGE` (=100), so the daemon rejects the anchor as **too old**
even though it is real and ingested. So the gate also needs an **upper-age arm**:
fail clean ("tree too far behind to anchor a submittable reference; resync") when
`chain_tip − reference_height` would exceed **`REBUILD_AT` (=50)** — the
conservative ceiling, since anchoring something already due for re-anchor is
pointless. Both arms are never-submit-a-bad-proof obligations, not optional. KAT
(d) (not-yet-ingested) gains a sibling (ingested-but-too-old).

---

## 4. Consent: a content generation makes silent mutation unrepresentable (Finding 3)

A stable id must not be a license for a silent byte swap. The re-anchored tx can
carry a different fee and change output than what `build` returned and the user
reviewed — and by the priority order, consent integrity (mission #2) beats the
performance ergonomics. The Finding-1 split tells us exactly when a swap is
honest:

- **Content-preserving reprove** — outputs / key images / destinations / amounts
  / change byte-identical modulo the proof. A proof refresh is **not** a consent
  event → transparent broadcast under the same id is legitimate.
- **Content-changing reselect** — different outputs and/or materially different
  fee or change → a *different artifact* than the consumer reviewed.

**The consent gate keys on the realized `(fee, change)` delta, not on which
re-anchor path ran (F-A — the headline correction).** The reprove/reselect split
(§3) is the **lock-mechanics** axis (do we swap the reservation); consent is a
**different axis** and the two only *correlate*. A reprove can change authorized
content: (1) the tree grew a layer between build and a 50-block-later age
re-anchor, so `(tree_depth − 1) × FCMP_PROOF_BYTES_PER_DEPTH_LAYER` rises → bigger
proof → higher minimum fee → smaller change; or (2) the fee snapshot moved
between build and re-anchor at constant depth (`build` re-fetches it). Either way
a path-keyed gate ("reprove is transparent") would broadcast a higher fee and
smaller change than the consumer reviewed — the exact mission-#2 violation §4
exists to prevent.

So the entry carries a consumer-visible **`content_gen`** that advances **iff the
realized `(fee, change_outputs)` differ from the consumer's last-seen artifact**,
computed *after* re-anchor, **independent of which path (reprove/reselect) ran**.
The membership-proof refresh has its own internal version and does **not** bump
`content_gen`. Submit becomes compare-and-advance:

```text
submit(id, seen_gen):
  // (the re-anchor itself is three-phase across the prover — §3a)
  if a re-anchor occurred and realized (fee, change_outputs) == last-seen
       → content_gen unchanged
  else if they differ
       → content_gen += 1
  if seen_gen == content_gen → broadcast               // (fee, change) unchanged → transparent
  else (content_gen > seen_gen)                         // authorized content changed
       → DO NOT broadcast; return the new artifact + (fee, change) delta,
         leave the entry awaiting re-confirm; consumer reviews and resubmits
         with the fresh content_gen.
```

This makes "broadcast a tx whose authorized content changed out from under me"
**unrepresentable** — a stale token cannot match — which is stronger than a flag
a dumb retry loop could auto-confirm past. Cost: threading `content_gen` through
`submit` (a small, accepted API change). Mirrors the spendable-with-reason
"state it, don't hide it" posture.

**KAT (the test that catches F-A):** a *depth-growth reprove* (same inputs, but
the tree gained a layer so the fee rose) **bumps `content_gen` and withholds
broadcast** — proving the gate keys on the delta, not the path.

**Re-confirm convergence (stated assumption, not a guarantee).** The re-confirm
loop has no formal bound: under churn `content_gen` could advance faster than a
human re-confirms (livelock). It is safe only because re-anchor frequency
(`REBUILD_AT = 50` blocks / rare deep reorgs) ≪ re-confirm latency. Stated so it
is an assumption on the record, not an implicit hope.

---

## 5. Staleness is a point query; the mark is deferred-rebuilder scaffolding (F-D)

**`reference_orphaned` is a stateless point query** (`reference.rs` sees only
tip + reference, so this is the engine's): is the canonical block at
`ref.height` still `ref.block_hash`? — i.e. `ledger.block_hash_at(ref.height) !=
Some(ref.block_hash)`. That handles arbitrarily many intervening reorgs for free,
needs no retained fork history, and leans on the E3 6-field-header/block-hash
correctness. **Per-selected-output survival is the same query at each output's
creation height** (this is the §3 reprove-vs-reselect classifier: any orphaned
selected output ⇒ reselect).

**The authoritative staleness check is at commit (§3a lock₂), under the lock:**
`should_reanchor(current_tip, ref.height) || reference_orphaned(ref) || any
selected output orphaned`, composed with the §3b ingested-tip gate.

**The eager reorg-branch mark does no correctness work in this lazy slice — so it
moves out (F-D).** Submit re-derives staleness authoritatively (above), so a
`merge.rs`-set flag saves nothing at submit. Its only consumer is a background
scanner that *proactively* rebuilds stale entries — the deferred §7 item. So this
slice **drops the `merge.rs` reorg-branch coupling entirely** (no `PendingTxEngine`
reorg method, no `stale` field): one fewer cross-component edge (reorg handler ↔
pending-tx state), and the deferred feature's hook is not built early. The mark
lands *with* the background rebuilder it serves. (A UX "needs re-anchor" indicator
without a submit attempt, if ever wanted, is the same on-demand point query.)

### Relational pins (state them so downstream cannot assume otherwise)

- **`ReservationId` is a stable consumer handle, not a fingerprint of the locked
  input set.** In the reselect case the underlying outputs (and their locks)
  change while the id persists. Nothing downstream may assume `same-rid ⇒
  same-inputs` — true today, false after CT-5d.
- **Lifecycle has three states, and the ambiguous one is where the hazard lives
  (F-E).** `consumer_held` (re-anchorable) → `in_flight` (submit attempted,
  daemon outcome unknown — the existing `in_flight` map / `DaemonAmbiguous`
  path) → terminal (accepted / terminally-rejected). Re-anchor scopes to
  `consumer_held` **only**. A re-submit while `in_flight` is **await/query the
  daemon — not a rebuild and not a blind no-op**: marking terminal on *attempt*
  and rebuilding on a transient failure would broadcast a second proof for the
  same intent (double-spend reject + correlation surface). The correlation hazard
  lives in `in_flight`, not in the clean terminal state.

---

## 6. Commit plan (one engine slice, off dev — submit-centric, no `merge.rs` edit)

The slice is **submit-centric**: staleness is re-derived authoritatively at
submit via point queries (§5), so there is **no `merge.rs` reorg-branch coupling
and no `stale` field** (F-D moved both to the deferred background rebuilder).
`PendingTxState` is a runtime `Mutex` (not persisted), so adding `reference` /
`content_gen` is a **runtime-only change — no schema migration** (F-F, §7).

1. **Record `reference` + `content_gen`** on `ConsumerHeldEntry` (+
   `PendingTx.reference_height` for diagnostics) — the CT-5b deferral.
2. **Re-anchor primitives (three-phase, §3a)**: refactor `build` internals into a
   reusable reprove (re-reference + re-assemble + re-sign, same locks) and
   reselect (full rebuild + atomic lock swap), both gated on the two-sided
   ingested-tip window (§3b). The prover runs lock-free between lock₁ (snapshot +
   reselect-reserve) and lock₂ (re-validate + commit).
3. **Submit pre-flight**: authoritative staleness re-derivation at commit (§5) →
   reprove/reselect (§3) → realized-`(fee, change)`-delta → `content_gen`
   compare-and-advance broadcast gate (§4). `submit` gains the `seen_gen`
   parameter; re-anchor scopes to `consumer_held` (never `in_flight`).
4. **KATs (DoD)**: (a) horizon-age re-anchor (reprove, transparent);
   (b) shallow-reorg-crossing (reprove, **locks untouched**, `content_gen`
   unchanged); (c) **depth-growth reprove** (same inputs, fee rose → `content_gen`
   bumped, broadcast withheld — the F-A test); (d) deep-reorg-crossing (reselect,
   lock swap, `content_gen` bumped, withheld); (e) reference-not-yet-ingested →
   clean submit failure; (f) reference-ingested-but-too-old (tree far behind) →
   clean submit failure (§3b upper arm).
5. **Closeout (lightweight)**: FOLLOWUPS — close the CT-5 poison drop-and-reopen
   item (absorbed by R1-Q4 respawn); add the E8 row "unify multisig intent
   reference-age validation onto `reference.rs` predicates"; add the §7
   record-and-defer rows. Docs: `CT5_ROUND1_CLOSEOUT.md`, `CURVE_TREE_CLIENT.md`
   §9 (Round 1 closed) / §4.3 (gindex resolution + X3×X1 conformance corollary),
   CHANGELOG. The Tier-B `recon_tier_b.rs` un-ignore is **out of scope** (separate
   slice).

**Privacy-neutral by construction (recorded so it is not re-litigated as a
fingerprint).** Re-anchor re-selects the *canonical* `tip − REF_ANCHOR_AGE`, so a
long-deferred tx submitted after re-anchor is indistinguishable from a fresh
build (same canonical reference age). The stale window cannot be tuned away
without fingerprinting (X1, §1).

---

## 7. Scope notes + record-and-defer

**F-F does not apply — no schema migration.** `PendingTxState` /
`ConsumerHeldEntry` are a runtime `Mutex<PendingTxState>`, **not** persisted (no
serde derive; `shekyl-engine-file` does not serialize them) — pending txs are
already ephemeral across restart. Adding `reference` / `content_gen` is
runtime-only: no `WALLET_STATE_MIGRATION` row, no rule-42 schema bump. (If the
Stage-4 `PendingTxActor` ever persists `consumer_held`, *that* PR owns the
force-expire-vs-rebuild decision; recorded here so it is not forgotten.)

FOLLOWUPS rows this slice adds:

- **Background opportunistic rebuild — and the eager reorg mark it needs.** A
  throttled background task re-anchors stale `consumer_held` entries proactively,
  so submit usually finds a fresh tx — trading wasted prover work on abandoned
  txs for lower submit latency. **This is the home for the eager `merge.rs`
  reorg-branch mark** (the `stale` flag + `PendingTxEngine` reorg method) that
  F-D moved out of the lazy slice: the mark is scaffolding the *rebuilder*
  consumes, useless without it. Whether the feature wins hinges on the **built-tx
  submit-vs-abandon rate**, currently unmeasured. **Reopening trigger:** that
  measurement. Don't build now.
- **Broadcast-but-unmined orphan (symmetric hazard).** A tx broadcast *before* a
  reorg that then orphans its reference is evicted from the daemon mempool — the
  wallet believes it is in-flight, the payment silently dies. "Daemon owns it" is
  true only until the daemon drops it. Out of CT-5d scope (it lives past the
  `consumer_held` → `in_flight` boundary, where re-anchor stops); FOLLOWUPS row.

---

## 8. Risks

- **E6c burst cost** — lazy means only *submitted* txs pay, and the Finding-1
  split makes the common reorg the cheap reprove (no N-input reselect). The
  remaining concentration (many in-flight proofs orphaned by one deep reorg) is
  bounded by the "deep reorgs are rare, else it's a consensus problem upstream"
  premise.
- **Reselect lock-swap across the prover (§3a)** — confined to the rare deep
  path; the new outputs are reserved in lock₁ (both old and new held across the
  prover), and lock₂ commits the swap or fails clean leaving the original entry
  intact. The TOCTOU the lock-drop opens is closed by the lock₂ re-validation.
- **Submit-path TOCTOU** — the tip/tree can move during the lock-free prover run;
  the authoritative staleness check is therefore at **commit** (lock₂), not at
  entry. A re-stale on commit triggers a bounded retry / clean fail, never a
  broadcast against a stale reference.
- **Actor migration** — the three-phase shape (§3a) keeps each critical section
  sync, so the Stage-4 `PendingTxActor` migration is mechanical; nothing here
  bakes in `Mutex`-only assumptions.
