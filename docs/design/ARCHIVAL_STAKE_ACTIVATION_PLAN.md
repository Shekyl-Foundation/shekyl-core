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

- **SA-DQ-1 — the RPC surface.** What method(s) drive first-stake (a `stake`/`bond` RPC), and
  how does the reopen handshake surface to the embedder (the WI-1 `Tenant` lifecycle)? Ties to
  `81-no-protocol-knowledge` (the user asks to stake; the protocol dance is hidden).
- **SA-DQ-2 — the bootstrap derive boundary.** Deriving the first persona **before**
  `staking_enabled` widens the seed's live window by one sign; verify it stays inside the Model-D
  seed-lifetime discipline (transient, dropped at function end) and does not hand the seed to the
  actor.
- **SA-DQ-3 — crash atomicity across the reopen.** A crash between sign and `persist_bond_record`,
  or between persist and reopen, must not strand a phantom `bonded_slots` — this is precisely
  arm #3's phantom domain (SP-R0 DQ-C); co-design the atomic step so #3 has a well-defined
  phantom set to GC.
- **SA-DQ-4 — funding the first bond.** First-stake needs funding P; how the principal funds the
  cold-start persona (the cover / `C_min` path) intersects SP-7 and the drain (#328) — scope the
  seam, do not re-solve it here.

---

## 3. Cross-links

- Front for [`ARCHIVAL_BOND_SP_R0_PLAN.md`](ARCHIVAL_BOND_SP_R0_PLAN.md): SP-R0's arms sequence
  **behind** this round, each gated on the SP-R0 **DQ-F** CI fire condition (which this path
  makes drivable).
- Retires the **`(b)`** half of the GF4b rule-21 `#[allow(dead_code)]` on the five witness
  consumers (SP-R0 arm #1 retires `(a)`).
- Consumes the WI-1 (`#329`) scan driver and the persona-derivation driver
  (`spawn_stake_engine_if_staker`) — turns both from dormant to live.
