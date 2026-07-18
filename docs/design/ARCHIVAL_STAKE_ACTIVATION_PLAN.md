# Archival stake activation — the production first-stake path (Round 0 scoping)

**Arc / numbering authority:** [`ARCHIVAL_BOND_PR2_CHAIN.md`](ARCHIVAL_BOND_PR2_CHAIN.md)
§3.6. This is the **`(b) RPC stake entry`** co-gate named in the GF4b witness rule-21 note —
the production path by which a wallet **becomes a staker**. It is the **genesis front** for the
entire archival-`P` subsystem: nothing downstream runs in production until it lands.

**Status:** ROUND 0 (scoping) — for review; no code. **Process rule:**
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
  after reopen; `2C_GF7_HOOKS.md:35`). So **broadcast-before-reopen** (no scheduler →
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
