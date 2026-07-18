# Archival stake activation — the production first-stake path (Rounds 0–1)

**Arc / numbering authority:** [`ARCHIVAL_BOND_PR2_CHAIN.md`](ARCHIVAL_BOND_PR2_CHAIN.md)
§3.6. This is the **`(b) RPC stake entry`** co-gate named in the GF4b witness rule-21 note —
the production path by which a wallet **becomes a staker**. It is the **genesis front** for the
entire archival-`P` subsystem: nothing downstream runs in production until it lands.

**Status:** ROUND 0 (scoping) + **ROUND 1 (per-SA-DQ design, §5 — source-grounded; SA-R1-a/c/d
ratified, SA-R1-b ratified-with-crash-taxonomy, §5.7, 2026-07-18)** — for review; no code. Rounds
accrete in this one doc. **Process rule:**
[`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc) (the
first-stake bootstrap derives persona key material — getting the derive boundary wrong is a
privacy break, so the boundary is decided first). **Target: V3.0 pre-genesis** — it gates every
genesis-critical archival arm.

---

## 0. Why this is the front (the constellation of built-unwired pieces)

Verified at `dev = 40805d7d0` and at every open PR (#328/#329/#330): **nothing in production
sets `staking_enabled`.** `persist_bond_record` (`stake_persist.rs:147`) is the sole setter and
has **zero production callers** (all `#[cfg(test)]`/`regtest_e2e`); **no stake/bond RPC exists**
in `shekyl-wallet-rpc`. `spawn_stake_engine_if_staker` (`lifecycle.rs:779`, wired into prod
open) gates on `staking_enabled` (`lifecycle.rs:894`, `if !staking.staking_enabled { return
Ok(None) }`), so with the flag never set it always returns `None`.

Consequence: in production, **no staker → no StakeEngine → no personas derived → no scan → no
posts.** The whole archival-`P` production wiring is a **constellation of built-unwired
pieces**, each individually "landed" but jointly inert, all gated on this one front:

| Piece | State | Home |
|-------|-------|------|
| P-scan driver (WI-1) | wired, dormant (staker-gated) | PR #329 |
| Drain planner (`plan_drain`) | built, "no data source / no consumer yet" | PR #328 |
| Bond assemble | compile-blocked on the `SpentRecordsDurablyPruned` witness | GF4b §3.2 |
| SP-R0 GCs (arms #1/#2/#3) | scoped; production-inert until this front | [`ARCHIVAL_BOND_SP_R0_PLAN.md`](ARCHIVAL_BOND_SP_R0_PLAN.md) |

Landing any of these "green" while this front is missing freezes a **non-firing** piece and
reads its reopen line as discharged — the `pscan/mod.rs:28` fossil class. The SP-R0 doc's
**DQ-F** (fires-in-prod, CI-asserted) is the general counter, and it depends on *this* path
existing to drive the fire.

---

## 1. The design content — the first-stake chicken-and-egg

This is not a bullet; it is a real derive-boundary round. The knot:

- `spawn_stake_engine_if_staker` derives personas **only if `staking_enabled`** (`lifecycle.rs:894`).
- `staking_enabled` is set **only by `persist_bond_record`** (`stake_persist.rs:147`), atomically
  with the first `bonded_slots` entry.
- `persist_bond_record` follows a **signed** bond (`PersistedBondTicket` persist-before-use,
  consumed by 2c-2b `sign_bond`), which needs a **derived persona**.
- …which needs the engine spawned — back to the top.

**The break (source-anchored, not new architecture).** `spawn_stake_engine_if_staker` already
holds the transient `master_seed` at open. First-stake collapses onto **reopen**: derive the
first persona from the transient seed **outside** the `staking_enabled` gate, sign the bond,
`persist_bond_record` (flips the flag + writes `bonded_slots` atomically), then **reopen**
re-runs `assemble()` — now `staking_enabled` is true and the StakeEngine spawns for real.
`stake_engine.rs:26-28`: *"Lookahead-exhaustion and first-stake-mid-session collapse onto
reopen (re-runs `assemble()` with the transient seed); there is no re-auth/KEK machinery."*
The reopen friction's removal is a V3.x polish (`FOLLOWUPS:2026`), not part of this front.

The design work is **that bootstrap derive under the firewall's constraints** (Model D
derive-forward set, DQ1 isolation, the seed-lifetime trilemma) plus the **RPC surface** that
drives it — sign + `persist_bond_record` + the reopen handshake — reachable from
`shekyl-wallet-rpc`.

---

## 2. Round-0 questions (to work in subsequent rounds)

Two are **named genesis gates** this round must own (SA-DQ-4, SA-DQ-5); the rest shape the
mechanism.

- **SA-DQ-1 — the RPC surface + two hooks.** What method(s) drive first-stake (a `stake`/`bond`
  RPC), and how does the reopen handshake surface to the embedder (the WI-1 `Tenant` lifecycle)?
  Ties to `81-no-protocol-knowledge` (the user asks to stake; the protocol dance is hidden). The
  method **moves funds and creates a durable commitment**, so it (a) lands on the
  **restricted-method list** (`DAEMON_RPC_RUST.md` restricted mode — admin-only, rejected pre-C++
  in `--restricted-rpc`), and (b) needs an **idempotency guard**: a second `stake` call while
  `staking_enabled` is already true must not mint a second first-stake.
- **SA-DQ-2 — bootstrap derive *equivalence* (the real risk).** The bootstrap derive (outside the
  `staking_enabled` gate) and the normal derive (`spawn_stake_engine_if_staker`, inside it) must
  produce the **same persona** for the same seed + slot — else the wallet stakes under persona-A
  and then scans/operates under persona-B, and the bond is attributed to a persona it never
  watches → **lost**. Enforce by sharing the **one** derivation primitive (`derive_archival_p_keys`),
  never reimplementing — a make-bad-states-unrepresentable candidate. (The seed's live window
  widening by one sign is real but secondary; keep it inside the Model-D transient-seed
  discipline, never handed to the actor.)
- **SA-DQ-3 — the durable phantom window is persist↔broadcast-confirmation, not persist↔reopen.**
  Reopen is local and fast; the window that strands a phantom `bonded_slots` is the **network
  gap** — persisted-as-staker, first bond never confirmed on-chain. Name that window. **Synergy:**
  arm #3's SP-R0 **DQ-F fire fixture *is* an activation-induced persist-then-no-broadcast crash** —
  the two rounds **co-design that one fixture** rather than each inventing one; it closes arm #3's
  CI fire condition naturally.
- **SA-DQ-4 — own GF4b-2: the first bond's funding-input-count discipline (genesis gate).** This
  round **is** the `stake_in` site, so it **owns** how many inputs the first bond post reveals —
  a **priority-1 genesis gate** (`ARCHIVAL_GF4B_BACKING_LINEAGE.md:390-422`, `FOLLOWUPS:158-169`:
  "until `stake_in` lands, every bond post exposes the raw funding-input count"). The common-case
  first bond must consume **one** structured funding input (or an equivalent input-count
  discipline). This is **distinct** from *where the funds come from* (the cover / `C_min` /
  SP-7 / drain seam), which stays deferred — SA-DQ-4 owns the **count**, not the source; do not
  scope-and-punt the count.
- **SA-DQ-5 — GF-7: first-stake is the worst-case principal↔`P` linkage (genesis gate).** GF-7 is
  the load-bearing unlinkability gate — "genesis cannot ship until `P(link | T_obs)` under
  threshold" (`ARCHIVAL_BOND_2C_GF7_HOOKS.md:54/65`, GATE6 §10.12 S-1). First-stake is the **one
  moment principal and persona co-occur in a single operation** (the operator issues an RPC and a
  persona's first bond debuts on-chain), so its RPC→broadcast timing is exactly a `T_obs` the
  GF-7 model measures — plausibly the strongest linkage in the system. **The fork:** the GF-7
  decorrelation lives in the 2c-2b scheduler, which exists only **after** the engine spawns (i.e.
  after reopen; `ARCHIVAL_BOND_2C_GF7_HOOKS.md:35`). So **broadcast-before-reopen** (no scheduler →
  GF-7-exposed debut) vs **broadcast-after-reopen** (routes through the scheduler → GF-7-preserved,
  but the signed bond must be **held across the reopen**). The answer is almost certainly *hold
  across reopen, broadcast through the scheduler*; ratify it as a Round-0 pin, since getting it
  wrong breaks GF-7 at the persona's debut.

---

## 3. Cross-links

- Front for [`ARCHIVAL_BOND_SP_R0_PLAN.md`](ARCHIVAL_BOND_SP_R0_PLAN.md): SP-R0's arms sequence
  **behind** this round, each gated on the SP-R0 **DQ-F** CI fire condition (which this path
  makes drivable).
- Retires the **`(b)`** half of the GF4b rule-21 `#[allow(dead_code)]` on the five witness
  consumers (SP-R0 arm #1 retires `(a)`).
- Consumes the WI-1 (`#329`) scan driver and the persona-derivation driver
  (`spawn_stake_engine_if_staker`) — turns both from dormant to live.

---

## 4. Round-0 exit

The spine (the constellation front + the first-stake reopen break) is sound. The question set
now carries the **two named genesis gates** first-stake sits on — SA-DQ-4 (GF4b-2 input-count
discipline, owned not deferred) and SA-DQ-5 (the GF-7 broadcast-before/after-reopen fork) —
plus the three mechanism refinements (SA-DQ-1 restricted-method + idempotency; SA-DQ-2 derive-
equivalence; SA-DQ-3 the persist↔broadcast-confirmation phantom window co-designed with SP-R0
arm #3's DQ-F fixture). With those in the set, the round is **Round-1-ready** — the design pass
resolves the SA-DQ-5 fork and the SA-DQ-4 count discipline, both of which have a strong
proposed answer to ratify rather than an open space to explore.

---

## 5. Round 1 — per-SA-DQ design (source-grounded; enforcement-point-with-the-type)

Grounded at `dev` (three source sweeps, 2026-07-18). **Headline: most of the machinery already
exists** — the transient-seed discipline, the pure derivation primitive, the durable
`.wallet.pending` hold-across-reopen store, the GF-7 dispatch scheduler, and the phantom-vs-
confirmed reconcile verdict are all built. Round 1 is chiefly **composing them in the one safe
order**, plus two genuine new decisions (SA-R1-a spawn-gate, SA-R1-c ownership split).

### 5.0 The first-stake bootstrap, end to end (what the SA-DQs compose into)

The knot in §1 is tighter than "derive outside the gate, sign, persist, reopen": `sign`/
`assemble` live on the **actor** (need a spawned StakeEngine + `PersonaHandle`), `persist_bond_record`
needs the assembled **Engine**, and the seed is **transient** (borrowed in `assemble()`, dropped
at open-scope end — `lifecycle.rs:869-874`, confirmed). Sign-before-persist is *unrepresentable*
(the persist-before-use typestate has no ticket to sign against — `stake_persist.rs:70`,
consumed by value). So the bootstrap must run **inside a credentialed (re)open's `assemble()`
with the seed live**, in this order:

1. **`stake` RPC** (FULL wallet) arrives with the password + funding reference. The password is
   load-bearing, not UX: a mid-session wallet holds **no seed** (dropped at open), and only a
   credentialed open re-materializes it — this is why `stake_engine.rs:26-28` pins first-stake to
   **reopen**. Idempotency-guarded up front (SA-DQ-1).
2. Inside that (re)open's `assemble()` (`lifecycle.rs:689`, seed live): derive persona for slot
   `S` via the **one** primitive `derive_archival_p_keys` (`archival_p.rs:369`) — SA-DQ-2.
3. **Spawn the StakeEngine for `{S} ∪ lookahead`** *even though `staking_enabled` is still false*
   (SA-R1-a, the one gate change), so a `PersonaHandle` exists to assemble against.
4. **Sweep** the one `stake_in` funding output → **one input** (SA-DQ-4), **in-memory** — funding is
   validated *before* any durable staker state, so an insufficient-funding first-stake **fails closed**
   leaving nothing to reconcile (§5.7 W1).
5. **`persist_bond_record(S)`** (`stake_persist.rs:138`) → mint the `PersistedBondTicket` + flip
   `staking_enabled` + write `bonded_slots[S]` atomically, crash-safe. **This precedes sign** — the
   persist-before-use typestate (this section's intro): sign has no ticket to consume otherwise. The
   slot is now **durable-but-phantom** until confirmed (SA-DQ-3).
6. **Sign + assemble** the first bond (`AssembleBond`, consuming the ticket) → **persist the post to
   the durable `.wallet.pending` store** (`bond_orchestrator.rs:283-289`, written **post-sign**); it
   does **not** broadcast (SA-DQ-5).
7. `start_pscan` (already in the open path once staking) → the **bond** dispatch driver loads the
   pending post and **broadcasts it at its GF-7 offset** (`pscan/dispatch.rs:259-263,556`). No reopen
   #2 needed: the whole bootstrap completes inside the credentialed open.

### 5.1 SA-DQ-1 — RPC surface, seed re-materialization, idempotency

- **Surface.** One arm in the flat `handlers::dispatch` match (`handlers.rs:24-52`); no
  `stake`/`bond` method exists today. It mirrors `send::build_pending_tx`: `require_open_engine`
  → engine call. **No wallet-rpc restricted-mode exists** (that mechanism is the *daemon* RPC,
  `DAEMON_RPC_RUST.md:76-115`, a separate process); wallet-rpc gates fund-moving methods by
  **`Capability::Full`** (`engine.capability()`, `mod.rs:943`; wallet-rpc opens FULL only,
  `lifecycle.rs:143`). So `stake` is FULL-gated + an explicit `CapabilityForbids` (-29005) check,
  **not** an allowlist. *(Round-0's "restricted-method list" pin is corrected here: the analog is
  capability-gating, since wallet-rpc has no restricted map.)*
- **Seed re-materialization = the reopen.** The method takes the **password** because first-stake
  needs the transient seed; it drives a credentialed (re)open carrying a first-stake intent, reusing
  the WI-1 `Tenant` lifecycle (close → open-with-intent). The reopen-friction removal is the V3.x
  polish (`FOLLOWUPS:2026`), not this front.
- **Idempotency (checkable).** `staking_enabled` is readable at the handler
  (`engine.ledger().staking.staking_enabled`, `mod.rs:1314` / `staking_block.rs:117`); a second
  `stake` reads it and refuses (`-29xxx`), and `persist_bond_record` is already slot-set-idempotent
  (`stake_persist.rs:117-119`). Enforcement: read-and-reject on the flag before any derive.

### 5.2 SA-DQ-2 — derive-equivalence (already structural)

`derive_archival_p_keys` (`archival_p.rs:369`) is a **pure function** of `(seed, net, fmt, slot)`
— no RNG/time/IO — **fixed-vector KAT-pinned** (`kat_archival_p_derive_v1_vectors`,
`tests/kat_archival_p_derive_v1.rs:330`, a CI-run `#[test]`: derived output asserted `==`
`expected.out_hex` per `(seed,net,fmt,slot)` at `:180`, over a corpus-hash-pinned `vectors.json`
`:338-342`, with a `--ignored` regenerator — a real input→output KAT that catches an algorithm
change, not just a determinism/property test), and `spawn_stake_engine_if_staker` (`lifecycle.rs:934`)
is its **sole production caller**. So bootstrap-derive ≡ post-reopen-derive is guaranteed by
construction. **Enforcement-point-with-the-type:** the bootstrap calls this one primitive (never a
second derivation); the equivalence is the KAT plus a one-site grep guard. The seed's window widens
by one derive, staying inside the same `&master_seed` borrow (no new lifetime; the actor never gets
the seed — `stake_engine.rs:2600` takes no seed).

### 5.3 SA-DQ-3 — phantom window + arm #3 fixture (co-designed, evidence already exists)

The window is `persist_bond_record` → the pscan's own **reorg-deep** `BondPostMatch` confirmation
(`accrual.rs:416`; released never on a daemon claim — `dispatch.rs:596-607`). Un-confirmed within
an exhaustively-scanned range = `ReconcileVerdict::AbsentWithinCovered` (`reconcile.rs:50`) = the
exact GC-eligible phantom SP-R0 arm #2/#3 consume. **The DQ-F fire fixture writes itself:** drive
first-stake to `persist_bond_record`, skip/crash the dispatch, advance the scan past `covered`,
assert arm #3 collects the phantom `bonded_slots[S]` — through the real production path, no
`for_test()` (SP-R0 DQ-F Guard 1). This is the *one* fixture both rounds share.

### 5.4 SA-DQ-4 — the input-count invariant (owned here) realized by `stake_in`'s shape

- **Ground truth:** the bond post **sweeps the entire eligible funding set** (`sweep_funding_outputs`,
  `bond_assembly.rs:363-384`, no subset), so the first bond's input count = the number of
  `PFundingOutputRecord`s P holds. To reveal **one** input, the funding must arrive as **one** output.
- **`stake_in` is the realization, and it is a *distinct* surface** (a **precisification** of the
  Round-0 "#332 *is* the stake_in site"). `stake_in` is an **unbuilt principal-orchestrator wallet
  method** — `stake_in(amount) -> PendingTx`, an ordinary FCMP++ transfer principal→persona
  (`PRINCIPAL_STAKE_LIFECYCLE.md:108/336`), whose *design* funds each admission as **one structured
  `bond_floor + cover` output** (`ARCHIVAL_GF4B_BACKING_LINEAGE.md:388-391`); that `cover` output **is**
  the SP-7 cold-start cover ("one design across two surfaces", `PRINCIPAL_STAKE_LIFECYCLE.md:226-227`).
- **Ownership split (SA-R1-c):** this round owns the **invariant** — *the common-case first bond
  consumes exactly one funding input* (the checkable GF4b-2 criterion, `FOLLOWUPS:168-172`) — and the
  **enforcement** (a debug-assert / gate at assemble that the swept count is 1 in the common case,
  multi-tranche a **consciously-logged** exception, `GF4B:421-422`). The principal-side `stake_in`
  **funding-shape** (emit one structured output) is a co-gating method homed in
  `PRINCIPAL_STAKE_LIFECYCLE.md`; **both land pre-genesis** (`GF4B:406-414`) and cross-reference. The
  round does not defer the count — it enforces the invariant and points at `stake_in` for the shape.

### 5.5 SA-DQ-5 — GF-7 preserved by construction (hold-across-reopen already built)

Bond broadcast exists **only** in the running **bond** dispatch driver (`pscan/dispatch.rs:584`;
read as the bond path specifically — `claim_dispatch.rs:14` is a *separate* reward-claim broadcast,
not on the first-stake path); `SignBond` does not broadcast (`stake_engine.rs:1318`), and the
broadcast seam is private to `start_pscan` (`start.rs:595`). The GF-7 entry-gap **offset is drawn at sign** (`stake_engine.rs:806`) but
**realized** — due-block gating + dispersal jitter — only by the post-reopen scheduler
(`dispatch.rs:259-263,556`). So the fork resolves to **hold-across-reopen, broadcast through the
scheduler**, and the mechanism is **already built**: assemble persists to the durable
`.wallet.pending` seal (`bond_orchestrator.rs:283-289`), which survives reopen and is dispatched at
its offset. **Enforcement-point-with-the-type:** there is *no inline broadcast path to misuse* — a
pre-reopen/inline send is not expressible, so GF-7 is structurally preserved as long as first-stake
uses `AssembleBond`→pending-store (never a bespoke send).

### 5.6 Round-1 decisions to ratify

- **SA-R1-a — the spawn-gate relaxation (the one genuine code change).** `spawn_stake_engine_if_staker`
  gates on `staking_enabled` (`lifecycle.rs:894`). First-stake needs a spawned StakeEngine + handle to
  assemble against **before** persist flips the flag. **Proposed:** relax the gate to
  `staking_enabled || first_stake_intent(S)`, and derive `{S} ∪ lookahead` for the intent so the
  bootstrap spawn **is** the real spawn (no throwaway bootstrap actor). The intent is a transient
  parameter to `assemble()`, never persisted (persistence is `persist_bond_record`'s job). Confirm
  this over the alternative (a distinct short-lived bootstrap StakeEngine for `{S}`).
- **SA-R1-b — the typestate-forced order + sweep-before-persist.** The order is **not a free choice**:
  the persist-before-use typestate forces `persist_bond_record` (mint ticket) **before** sign/assemble
  (§5.0; sign has no ticket otherwise). The one degree of freedom is **sweeping before persist** —
  validate funding first, so an insufficient-funding first-stake fails closed with **no** durable
  staker state (§5.7 W1), rather than flipping `staking_enabled` and *then* finding the funding short.
  The unavoidable window this leaves (persist done, sign/assemble not) is §5.7's W2, handled by
  seed-gated resume.
- **SA-R1-c — the SA-DQ-4 ownership split** (§5.4): invariant + enforcement here; funding-shape in
  `stake_in`. Confirm both are pre-genesis and cross-referenced, and that a debug-assert-on-count at
  assemble is the right enforcement locus (vs. only shaping `stake_in`).
- **SA-R1-d — the credentialed-`stake`-RPC shape** (§5.1): first-stake takes the password and drives a
  first-stake-intent (re)open. Confirm this over a create-time-only first-stake (which would forbid
  staking an existing wallet — likely too restrictive).

### 5.7 Ratifications + pins (maintainer review, 2026-07-18)

**SA-R1-a — RATIFIED, with a pin.** Equivalence is stronger than §5.2 stated: `derive_archival_p_keys`
has *one* production caller (`lifecycle.rs:934`); the others are `#[cfg(test)]`. So the gate relaxation
routes first-stake through the **same call site** as reopen-derive — one path, not one-primitive-two-callers.
**Pin (firewall gate):** `first_stake_intent(S)` must be **transient** (never persisted; the gate decides
whether personas derive *at all*, so a sticky intent would derive personas for a non-staker). It is set
**only** by the credentialed `stake` RPC's open-with-intent parameter and is `false` in every other open;
an **aborted first-stake** (spawn without persist) leaves **only transient** derivation (dropped at
open-scope end), **no persistent persona** — the durable staker state is exactly what `persist_bond_record`
writes, nothing sooner.

**SA-R1-c — RATIFIED as framed.** `stake_in:108` is an ordinary FCMP++ transfer to P's stealth address
(touches no P secret; P is a public recipient), so the source-linkage break is the base membership proof —
correctly deferred. "Common-case one-input" is the right characterization, not an under-sell: GF4b-2 is
**self-privacy**, so a **wallet-local default** is the correct discharge (consensus cannot force one-input
without breaking legitimate multi-input bonds), and the first bond is the strongest slice because it is
one-input **by construction** of the clean path (P holds exactly the one `stake_in` output at first-stake).

**SA-R1-d — RATIFIED, with two pins.** (1) the re-materialized seed stays **transient** — dropped at the
reopen function's end, never handed to the actor (SA-DQ-2's own rule); (2) the `stake` RPC is
**local-transport + `Capability::Full`** (`types.rs:211`), so the password crosses only a local boundary.

**SA-R1-b — RATIFIED the ordering; the crash taxonomy is the one real gap (resolved below, in-doc, not a
Round 2).** The typestate forces **sweep → `persist_bond_record` → sign → assemble-persist(`.wallet.pending`)
→ dispatch** (sign needs the persist-produced ticket; the pending seal is written *after* assemble/sign —
`bond_orchestrator.rs:283`, over `assembled.bound_tx`). That is **three** crash windows, only the last cleanly
held-across-reopen. "Crash-after-persist yields the SA-DQ-3 phantom" is a *sub-case of the middle window*; the
three, against the typestate order, with recovery each:

| # | Window | Persisted state at crash | Recovery |
|---|--------|--------------------------|----------|
| **W1** | after sweep, before `persist_bond_record` | **none** — the sweep is in-memory; `.wallet.pending` is written only post-sign, so there is **no orphaned pending entry** (this corrects the Round-0 "unsigned sweep in `.wallet.pending`" framing); `funding_outputs` intact; `staking_enabled` **false** → non-staker | **retry.** The idempotency read (§5.1) sees `staking_enabled=false` and allows a fresh first-stake; the earlier sweep left nothing to reconcile. Clean. |
| **W2** | after `persist_bond_record`, before sign/assemble-persist | `staking_enabled=true` + `bonded_slots[S]` durable; **no** pending post (assemble never completed); the in-memory ticket is lost | **resume-first-stake, arm-#3-independent.** On reopen the wallet is a staker (persona `S` derives); the reopen path detects `bonded_slots[S]` with no pending/confirmed post for `S` and **re-mints the ticket** — `persist_bond_record` is **re-entrant** (slot-set push is idempotent, `stake_persist.rs:117-119/149-151`, and it returns a fresh ticket for the slot regardless) — then re-signs (a fresh GF-7 offset draw is fine) and re-assembles. This does **not** depend on arm #3 (which lands after activation per the DQ-F split); arm #3 is the **backstop** only for a truly-abandoned slot (user never resumes). |
| **W3** | after sign/assemble-persist, before dispatch | signed post durable in `.wallet.pending`; `staking_enabled`+`bonded_slots[S]` | **held-across-reopen (existing).** `start_pscan` reloads the seal and the bond dispatch driver sends it at its GF-7 offset. Clean. |

The **load-bearing recovery decision** is W2: **re-entrant `persist_bond_record` + resume-first-stake on
reopen**, *not* "arm #3 GCs and the user re-stakes" — because arm #3 is not live at first-stake's genesis
window, and a resume keeps a crashed first-stake progressing without a live GC. (SA-R1-b's sweep-before-persist
ordering from §5.6 keeps W1 clean; the persist-before-use typestate — persist mints the ticket sign consumes —
is what makes W2 exist at all, with W3 the success outcome.)

**W2 resume is seed-gated (the genesis-window behavior, stated not inferred).** Re-signing needs the spend
key → the **seed**, so resume is a **credentialed path**: it fires on a `stake` **re-invoke** (seed present,
`first_stake_intent` set), **not** on a plain reopen. A credentialed reopen that does *not* re-invoke `stake`
therefore does not auto-complete a W2 crash — the advisory `bonded_slots[S]` persists until a `stake`
re-invoke or (post-genesis) arm #3. This is **benign by the `StakingBlock` design**, not a new hazard:
`bonded_slots` is a *derive-time hint, not truth* (`staking_block.rs:47-63`), and a "`bonded_slots` entry
with no corresponding bond" is exactly the case it anticipates (`:51-54`); no aggregator treats it as
authoritative (`:62`). The only effects are local — persona `S` re-derived/scanned each open "for nothing"
(`:53-54`) and slot `S` burned from the monotone cursor (`:75`, preserving the no-reuse invariant) — never
an external observable. (An **open-time auto-resume** — the seed is live in every `assemble()` — is the
alternative if that window is later judged worth closing before arm #3; deferred here to avoid a surprise
on-chain broadcast on a plain open.)

**Two flags folded:** (1) §5.2's KAT citation corrected — the **fixed-vector** KAT
(`kat_archival_p_derive_v1_vectors`, corpus-hash-pinned, CI-run) already exists, so the genesis
freeze-the-frozen-primitive obligation is **met**, not outstanding. (2) §5.5's "DispatchDriver" read as the
**bond** dispatch driver specifically (`claim_dispatch.rs:14` is a separate reward-claim broadcast); the
no-inline-broadcast-from-first-stake property that GF-7 rests on is unaffected.
