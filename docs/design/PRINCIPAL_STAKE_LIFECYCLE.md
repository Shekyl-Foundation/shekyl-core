# Principal stake / unstake / drain lifecycle (design — Round 0 scoping)

**Status:** Round 0 — scoping pre-flight (opened 2026-07-01). Names the surface,
pins its shape against the rebased substrate, enumerates gates, and separates
buildable-now from genesis-seal-blocked. **No implementation is authorized by
this doc** — the surface as a whole is genesis-seal-gated (see §5). This is the
missing plan-home for the *user-facing* economic staking surface; the
`WALLET_REWRITE_PLAN.md` Phase-2 banner names it "the biggest genuinely-unscoped
2b chunk."

**What this is / is not.** This is the **principal** (human-facing) lifecycle:
stake in, top up / partially unbond, unbond, drain rewards back to yourself. It is
**not** the archival persona `P` bond/scan machinery — that is
[`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §3 (the `P`-state FSM)
and the built `StakeEngine`. This doc sits one layer up, at the orchestrator.

## 0. Binding framing (do not re-litigate)

- **Write against the rebased §2.4/§3 model, never the claim-era body.** The
  confidential-principal design (`StakeInstance`, `stake()` / `claim()` /
  `unstake()`, tiers, entitlement, nullifiers) is a **deletion target**
  ([`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.1 *Delete*
  table; §4–§6 body is explicitly stale — `SECTION_4_CLAIM_ERA`, §6 API claim-era).
  A method that carries `claim` / `tier` / `StakeInstance` is wrong by construction.
- **The principal has no consensus FSM of its own.** Its lifecycle is a set of
  **ordinary `RCTTypeFcmpPlusPlusPqc` transfers** to/from `P` plus firewall
  discipline (`PHASE_2B_STAKE_LIFECYCLE.md` §2 — *"principal→`P` stake-in,
  `P`→principal unstake drain, reward sweeps are ordinary transfer, firewalled by
  base FCMP++ privacy"*). The only consensus-special collateral leg is the gate-4
  `txin_archival_bond_post`. The consensus FSM belongs to `P`
  (`AdmissionPending / Bonded / Slashed / Exited`, §3.1).
- **Secret-locality (rule 36 / gate-6 §9.6).** `P.view_sk` and `P`-keys never
  leave the `StakeEngine` actor. Principal-side transfer building routes through
  `KeyEngine` / `PendingTxEngine`; only signed vins / public views cross the
  boundary. Principal methods attach at the **orchestrator**, composing the
  existing engines — **not** on the `StakeEngine` actor.
- **No consensus or wallet minimum on admission** (gate-7 closed bonds-only;
  gate-6 §2.5). Stake-in is value movement, not a consensus action.

## 1. The four principal↔`P` legs (all transfers except the bond post)

Per [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4 tx-legs table:

| Leg | Tx shape | Notes |
|-----|----------|-------|
| **Stake-in** | ordinary FCMP++ transfer, principal → `P` stealth outputs (main tree) | privacy = base FCMP++; **no minimum**; GF-7 funding shape/timing discipline applies |
| **join-Market / re-bond / holdings-update / unbond** | `txin_archival_bond_post` (gate 4, the only consensus-special leg) | post_kind table in [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) |
| **Reward emission** | special mint leg (membership-only backing + work payload) | **not a principal action** — consensus mints to `P`; see [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) |
| **Reward sweep / terminal drain** | ordinary FCMP++ transfer(s) `P` → principal | **decorrelated, output-count-disciplined** (GF-4); bond returns via gate-4 `Unbond`, **not** the drain |

## 2. Proposed method surface (Round-0 sketch — to be ratified, not built)

Layered on the orchestrator, over the existing persona/bond `StakeEngineHandle`
(`spawn` / `mint_handle` / `activate_persona` / `sign_bond` / `scan_step` /
`retire_bonded_persona`). None of the below exists today (only three
`StakeInstance` future-work comments in `shekyl-scanner/src/scan.rs`).

- **`stake_in(amount) -> PendingTx`** — ordinary FCMP++ transfer principal → `P`
  stealth outputs. No band / range-proof / tier / minimum. Composes
  `PendingTxEngine` + `KeyEngine`. GF-7 funding-shape hygiene (ramp-not-lump).
- **`fund_bond` / `join_market`** — formalize the driving path over the existing
  `sign_bond → JoinMarketVin` (currently `#[allow(dead_code)]`, inert until 2c-2b).
- **`partial_unbond(shard)`** — voluntary `HoldingsUpdate` (gate-4 post_kind 3,
  `bond_debit = FLOOR`). **Genesis-scope (V3.0)** — see §5.
- **`unbond() -> PendingTx`** — terminal collateral return (gate-4 post_kind 2),
  only from `Exited` post-cooldown; refund at `bond_floor`.
- **`drain(to_principal) -> Vec<PendingTx>`** — the decorrelated `P` → principal
  exit. **Not a single tx** — multiple outputs / txs under GF-4 output-count
  discipline (§3). Consumes `P`'s **non-escrowed** outputs only.
- **Query surface** — owner-grade, secret-free projections: `principal_stakes()`,
  `bonded_holdings()`, `drainable_balance(P)`, `unbond_readiness(P)` (cooldown
  countdown). Report emission **receipts**, not claim entitlements.

## 3. Firewall discipline this surface must enforce (load-bearing)

- **GF-4 — decorrelated-drain output-count discipline.** The delay floor is
  pinned (`≥ RELEASE_COOLDOWN × SETTLEMENT_EPOCH_BLOCKS` ≈ 28 days,
  [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)); the **open**
  piece is the output-count rule — *a single lump sweep re-links reward history to
  one principal cluster even with the delay satisfied*
  ([`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §2.4). Applies to
  terminal drain **and** recurring `HoldingsUpdate`. **Round-4 hard exit** — see §5.
- **GF-7 — principal→`P` bond-funding structural distinguishability.** Lump
  funding from a fresh principal output immediately before first emission is a
  correlation channel (§2.5); the disposition (fund-from-earnings ramp vs lump) is
  an open wallet-hygiene call. Applies to first join **and** recurring rebond-topup.
- **GF-10 — within-epoch timing** now applies to bond ops, not just emission.

## 4. Round-0 design questions (to close before any implementation round)

- **DQ1 — does any principal-side committed-stake wire survive?** §2.4 leans "plain
  transfer to `P`" (no `C_stake` / range-proof / band); §2.1 keeps "principal role
  open" as the reopen-pointer. Ratify plain-transfer-for-genesis or reopen.
- **DQ2 — attachment point.** Confirm the surface lives at the orchestrator
  (composing `PendingTxEngine` + `KeyEngine`), not on the `StakeEngine` actor
  (secret-locality). Only `fund_bond`/`unbond`/`partial_unbond` touch the actor's
  bond path.
- **DQ3 — drain output-count discipline shape** (GF-4): fixed count? amount-scaled?
  jittered? This is the Round-4 hard exit and blocks `drain()`/`unbond()`.
- **DQ4 — bond-funding shape** (GF-7): fund-from-earnings ramp vs lump default.
- **DQ5 — query surface secret-locality**: which projections are owner-grade and
  how they avoid crossing the `P`-secret boundary.
- **DQ6 — `shekyl-staking` deletion sequencing** (rule 15): `entitlement.rs` /
  `tiers.rs` / `rewards.rs` / `StakeRegistry` / `StakeEntry` are still compiled
  workspace members with live dependents; schedule their removal, don't build on
  them.

## 5. Gates — what must close first (and what is buildable now)

**BLOCKED (genesis-seal / consensus-gated) — do not build the surface yet:**

1. **Rebond/unbond FSM pin — the hard blocker (genesis-seal dependency).**
   `HoldingsUpdate` (voluntary partial-unbond) was promoted **V3.1 → V3.0**
   (2026-06-15); the full `JoinMarket / Rebond / HoldingsUpdate / Unbond` FSM must
   ship at genesis (bond is a consensus-tracked balance under a gate-4 conservation
   law — completing it post-genesis is a hard fork). It is also a **pre-genesis-seal
   sim dependency** — the age-stratified bond-mobility reconciliation cannot be
   computed until the FSM frictions are pinned. Authority:
   [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) (P2B-1..7),
   [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md),
   [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §6 R4 / §9.6.
2. **Gate 6 R4 (output + bond-funding hygiene).** GF-4 output-count discipline and
   GF-7 funding shape are open Round-4 exits; shipping `drain()` before GF-4 is
   pinned would ship a lump-sweep correlation beacon.
3. **Reward-emission leg.** The drain consumes reward outputs that do not exist
   until emission is built ([`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md);
   C-1 ML-DSA hard gate = PR-E3 step 8).

**BUILDABLE NOW (design + non-consensus enabling work):**

- **This scoping doc + its Round-1 ratification** — pure design, commit-direct-to-dev.
- **Persona/bond driving-path completion** — `sign_bond` / `JoinMarketVin` exist
  but are inert; wiring the driving path forward (2c-2b) is buildable.
- **Firewall-hygiene defaults** — decorrelated-drain spacing and fund-from-earnings
  ramp are non-consensus wallet-local, buildable once the FSM shape is pinned.

## 6. References (authoritative — reference, do not restate)

- [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4 (tx-legs),
  §3 (`P`-state FSM), §2.1 (retain/delete, principal-role-open).
- [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-1..7 (FSM authority).
- [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) (bond wire, post_kind table,
  Unbond/refund).
- [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §2.4/§2.5 (GF-4/GF-7),
  §6 R4, §9.6 (secret-locality).
- [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) (cooldown / delay
  floors).
- [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) /
  [`REWARD_EMISSION_VIN_PLAN.md`](REWARD_EMISSION_VIN_PLAN.md) (the emission the
  drain is downstream of).
