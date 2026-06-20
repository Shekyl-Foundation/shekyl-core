# Archival bond construction — PR 2 sub-chain arc (Bond-PR 2a → 2d)

**This is the index/arc doc** for the wallet-side archival bond-post
construction PR-2 sub-chain. It maps every sub-PR, records the landed ones, and
nests the full per-PR plan docs for the unstarted ones. It is the **single
authority** for the chain's numbering, the 2b→Model-D supersession, the KAT
lineage, and the CT-5 cross-series gate.

**Parent design:** `ARCHIVAL_BOND_CONSTRUCTION.md` (the frozen design; Round 1
closed §11.1). **Process:** `26-sub-pr-design-discipline.mdc` (opt-in, cited per
its Scope clause — the chain is multi-round per-trait work on the gate-6 firewall
surface).

---

## 0. Numbering disambiguation (the collision this doc fixes)

Two independent schemes both used the tokens `2a / 2b / 2c / 2d`:

| Scheme | Tokens | Meaning | Docs |
| --- | --- | --- | --- |
| **Engine layer** (`WALLET_REWRITE_PLAN.md`) | **Phase 2a–2d** | 2a send path, 2b stake lifecycle, 2c addresses/proofs, 2d cold bundles | `PHASE_2A_SEND_PATH.md`, `PHASE_2B_STAKE_LIFECYCLE.md` (+ `_AUDIT`) |
| **Bond construction** (this chain) | **Bond-PR 2a–2d** | 2a KAT, 2b StakeEngine actor, 2c-1/2c-2a/2c-2b, 2d transport | this arc + nested plans |

**Resolution (decided 2026-06-19): the bond construction sub-chain is prefixed
`Bond-PR` everywhere in docs going forward.** "Phase 2x" stays the engine layer.
Branch names are unchanged (they are immutable history: `feat/archival-stake-
engine`, `feat/archival-stake-wiring`, `feat/archival-bond-request`, …); the
disambiguation lives at the doc-token level. A bare "2b" in older prose
(`ARCHIVAL_BOND_CONSTRUCTION.md` §10, `FOLLOWUPS.md`) resolves to **Bond-PR 2b**
within the bond-construction context and **Phase 2b** within the engine context;
new prose uses the prefix.

---

## 1. Predecessors (Bond-PR 0 / 1 — landed, foundation)

- **Bond-PR 0** (`#152`) — `shekyl-crypto-pq::archival_p`: the `P`-identity +
  `bond_spend_pk` derivation (gate-6 §9.3/§9.4) with the `ARCHIVAL_P_DERIVE_V1`
  aarch64-qemu KAT (third cross-arch-deterministic primitive) + label-sensitivity
  negative.
- **Bond-PR 1** (`#155`) — `shekyl-archival-bond-builder` (JoinMarket vin +
  hybrid signature + credit funding rule) **plus** the single-sourced
  `shekyl-rct-balance` crate (§11.1 Q2: the cleartext balance equation +
  `InputTerm`/`OutputTerm` live once, imported by both `shekyl-tx-builder`
  construct and `shekyl-archival-retention` verify).

---

## 2. The arc at a glance

| Bond-PR | Branch / PR | Status | One-line scope | Full plan doc |
| --- | --- | --- | --- | --- |
| **2a** | `feat/archival-bond-roundtrip-kat` #156 | **landed** | Synthetic-tree round-trip KAT | §3.1 (record) |
| **2b** | `feat/archival-stake-engine` #157 | **landed inert — partly superseded** | StakeEngine actor, *seed-owning* model | §3.2 (record + supersession §4) |
| **2c-1** | `feat/archival-bond-realtree-kat` #158 | **landed** | Real-tree composition KAT (prove half; verify half now **live** — CT-5 closed #162) | §3.3 (record) |
| **2c-2a** | `feat/archival-stake-wiring` | **landed inert** | **Model D** wiring (seed-free actor + typed contracts + `StakingBlock`) | §3.4 (record) |
| **2c-2b** | `feat/archival-bond-request` #163 (archived) | **landed inert** | JoinMarket bond request path (wired + KAT-exercised, not user-invocable until 2d) | [`ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md`](ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md) + S6 follow-on §3.5.1 |
| **2d-1** | — | **not started — prerequisite** | **`P`-scan layer**: `P.view_sk` sweep over the chain (scan-layer firewall, StakeEngine owns `P.view_sk`). **Two readers**: steady-state funding-output discovery (2c-2b SP-2.e) **and** the 2d-2 reconciliation | §3.6 (foundation) |
| **2d-2** | — | **not started** | `P`-isolated Arti transport + broadcast/re-anchor + full-scan `bonded_slots`/`p_slot` reconcile — **depends on 2d-1** (cannot reconcile bonds it has not scanned for) | §3.6 |

---

## 3. Status-of-record per sub-PR

### 3.1 Bond-PR 2a — synthetic-tree round-trip KAT (landed #156)

Full-prover synthetic-tree round-trip: the JoinMarket bond drives the **real**
FCMP++ prover (`sign_transaction_with_terms`, `bond_credit` as the sole
output-side cleartext term) and checks prover-emitted commitments against the
verify side, plus accept/reject negatives (wrong `bond_credit`, tampered
commitment, tampered preimage, replay). **This is the synthetic-tree KAT
milestone** (see §5).

### 3.2 Bond-PR 2b — StakeEngine actor, seed-owning model (landed inert #157)

The first `StakeEngine` kameo actor (`shekyl-engine-core::engine::stake_engine`):
lazy per-`P` `ArchivalPKeys` (`!Clone`/`ZeroizeOnDrop`), `spawn_blocking`
derivation, atomic slot rotation, **re-derive-on-restart**, fail-stop
`StakeActorUnavailable`; typed values `PSlot`, **`StakeMasterSeed`**,
`PersonaIdentity` (public `HybridPublicKey` only). Landed inert (tests only, no
`Engine` wiring). **The seed-owning model here was superseded in part by Model D
(Bond-PR 2c-2a) — see the §4 supersession ledger.**

### 3.3 Bond-PR 2c-1 — real-tree composition KAT (landed #158)

`local_pending_tx::join_market_bond_post_signs_and_verifies_over_real_tree`
drives the bond's cleartext `credit_term` through `sign_transaction_with_terms`
over a **real depth-2 `assemble_path` tree** (the `funded_ledger_and_tree`
fixture), asserting BP+, the RCT balance over prover-emitted commitments, and
vin/signature accept+reject. The **construct→prove half over genuine branch
layers is proved**; the FCMP++ **verify-accept half is now live** —
`join_market_bond_post_fcmp_verify_over_real_tree`
(`local_pending_tx.rs:3709`) runs as a normal `#[tokio::test]` (the `#[ignore]`
was lifted when CT-5 closed in #162: the partial-branch-chunk bug was fixed by
zero-padding branch chunks to circuit width in `shekyl_fcmp::proof::prove`).
(Split from 2c-2 when CT-5c made the real `assemble_path` available earlier than
planned.)

> **Fossil note (2026-06-20):** the sibling comment in
> `join_market_bond_post_signs_and_verifies_over_real_tree`
> (`local_pending_tx.rs:3404–3408`) still describes the verify KAT as the
> "`#[ignore]`d sibling … gated on CT-5." That is stale — fold a one-line comment
> correction into the next PR touching that crate (S6).

### 3.4 Bond-PR 2c-2a — Model D wiring (landed inert)

Seed-free actor under **Model D** (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.2): at
`assemble()` a staker-flagged wallet derives the **derive-forward set**
(`{personas with live bonds} ∪ {p_slot ..= p_slot + k}`, `k = 2`), hands the
pre-derived `ArchivalPKeys` bundles to the actor, and drops the borrowed seed.
New persisted surface: a sealed **`StakingBlock` in `WalletLedger`**
(`STAKING_BLOCK_VERSION = 1`; `WALLET_LEDGER_FORMAT_VERSION` bumped) carrying
`staking_enabled`, the scan-reconciled-monotone `p_slot` cursor, and the
`bonded_slots` reconcilable hint. Typed contracts: `PersistedBondTicket`
persist-before-use (#1, the cross-split seam consumed by 2c-2b), operation-scoped
`PersonaHandle` (#2), `HeldPersona` Bonded/Ephemeral wipe-only-ephemeral (#4).
**Inert** — wired, derived, spawned, test-exercised, **no JoinMarket request
path**. Substrate: `stake_engine.rs`, `stake_persist.rs`,
`lifecycle.rs::spawn_stake_engine_if_staker` (`:879`).

### 3.5 Bond-PR 2c-2b — JoinMarket request path (landed inert — PR #163)

Full plan: [`ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md`](ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md).
Consumes the 2c-2a inert surface (`PersistedBondTicket`, `PersonaHandle`); adds
the parallel request type, `sign_bond`, funding selection with decorrelation
defaults, `CoverAmount`, the two typed timing seams, the live RNG degeneracy
guard, and the **request-path composition** milestone KAT (§5). Design rounds
1–6 + impl-time pre-flight (`R0-D1`–`R0-D4`) closed. Branches off `dev` after
2c-2a. **Lands inert by the chain's own pattern (like 2b / 2c-2a):** the request
path is wired and KAT-exercised but **not user-invocable** until 2d completes
broadcast + transport + reconciliation — which is also what prevents phantom
`bonded_slots` accruing in the 2c-2b→2d window (a built-but-unbroadcastable bond
is `consumer_held` forever-until-2d; see the 2c-2b plan §1.4).

#### 3.5.1 S6 follow-on — `certify_draw` session self-cert wiring (planned)

The **`certify_draw` session self-cert** is the one S6 scope item 2c-2b settled
the *design* for (§3.3) but deferred the *wiring* of (`R0-D#` / FOLLOWUPS): the
grade is float / x86-only and `shekyl-stats`-bearing, so it cannot live on the
float-free default-production path. Split into a small **`conformance`-gated**
follow-on PR (off `dev`, **after #163 merges** — it consumes #163's
`OsRngGapAdapter` / `on_start` / `DEFAULT_ENTRY_GAP`). Full plan:
[`ARCHIVAL_BOND_S6_CERTIFY_DRAW_PLAN.md`](ARCHIVAL_BOND_S6_CERTIFY_DRAW_PLAN.md)
(2-round, tightened — the design is already settled in 2c-2b §3.3).

### 3.6 Bond-PR 2d — `P`-scan layer (2d-1) + transport/broadcast/reconcile (2d-2)

**2d-1 — `P`-scan layer (the foundation; tracked, not orphaned).** A `P.view_sk`
sweep over the chain, inside StakeEngine (the scan-layer firewall — StakeEngine
owns `P.view_sk`, disjoint from LedgerEngine; the `combined_ss` recovery of
§10.1). It is **one sweep with two readers**: (a) **steady-state funding-output
discovery** — the `P`-local output set 2c-2b's fund-from-earnings ramp selects
from (2c-2b SP-2.e), and (b) the **2d-2 reconciliation** input. This is not a
loose "someday" parallel to 2d: 2d-2's reconciliation **sits on top of it** — you
cannot reconcile bonds you have not scanned for, and steady-state funding has
nothing to select from until this exists. Named here as 2d's first sub-part so it
is a tracked prerequisite, not a surprise discovered when someone drafts the 2d-2
reconciliation. Substrate today: `ArchivalPKeys` **carries `view_sk`**
(`shekyl-crypto-pq/src/archival_p.rs:332`) — the capability — but **no scan
pipeline is built** (2c-2b SP-2.e).

**2d-2 — transport + broadcast/re-anchor + reconcile (depends on 2d-1).**
`arti-client` security-critical pre-flight (guard isolation verified at source,
`cargo audit`, Guix repro, `AUDIT_SCOPE.md`) + the **`P`-isolated outbound
`DaemonEngine`** (outbound-only; inbound onion-service HS deferred to the
announce-wire item) + **broadcast/re-anchor** wiring (activates the CT-5d
persona-pin) + the **full-scan reconciliation** of `bonded_slots` / `p_slot`
(GCs phantom records; no second `STAKING_BLOCK_VERSION` bump) — **the reconcile
consumes 2d-1's scan**. Full plan drafted when 2c-2b closes. Reopen anchors:
`FOLLOWUPS.md` lines 945–960.

---

## 4. The 2b → Model D supersession ledger

What Bond-PR 2b (#157) shipped vs what Bond-PR 2c-2a (Model D) replaced. This is
the record that was missing — `ARCHIVAL_BOND_CONSTRUCTION.md` §10.1 marks the
prose "SUPERSEDED by Model D" but no per-PR doc carried the element-level diff.

| Element (2b, #157) | Model D disposition | Where (current substrate) |
| --- | --- | --- |
| Actor **owns the master seed** (session-long) | **DELETED** — seed dropped after `assemble()`; actor holds pre-derived bundles only | `stake_engine.rs:16–28`, `StakeEngineArgs` `:334` (no seed field) |
| **`StakeMasterSeed`** typed value | **DELETED** — no seed type in the actor | absent from `stake_engine.rs` |
| **Lazy per-`P` `spawn_blocking`** derivation in handler | **CHANGED** — eager pre-derive of the union at `assemble()` (relocated, not in-handler) | `lifecycle.rs:879` `spawn_stake_engine_if_staker` |
| **Re-derive-on-restart** (seed held for it) | **CHANGED** — restart = **reopen**, which re-runs `assemble()` with the transient seed | §10.2; `stake_engine.rs:75–82` |
| `PSlot` typed slot | **SURVIVED** | `stake_engine.rs:119` |
| `PersonaIdentity` (public `HybridPublicKey` only) | **SURVIVED** | `stake_engine.rs:265` |
| **Atomic single-transition rotation** | **SURVIVED — load-bearing** (§10.1 #2 / §10.9) | `ActivatePersona` handler `stake_engine.rs:525` |
| Fail-stop `StakeActorUnavailable` (no restart-supervision) | **SURVIVED** | `stake_engine.rs:290–300` |
| `!Clone` / per-field `ZeroizeOnDrop` bundles | **SURVIVED** (held bundles, same class as `AllKeysBlob`) | `stake_engine.rs:43–51` |

**Added by Model D** (no 2b antecedent): the derive-forward bonded-union rule,
`PersistedBondTicket` / `PersonaHandle` / `HeldPersona` typed contracts, the
sealed `StakingBlock`, and the generation-counter handle invalidation.

---

## 5. KAT lineage (three distinct KATs — do not conflate)

| KAT | Bond-PR | Tree | Proves | Gate |
| --- | --- | --- | --- | --- |
| Synthetic-tree round-trip | 2a (#156) | synthetic | construct ↔ verify over a synthetic balance witness | none |
| Real-tree composition | 2c-1 (#158) | **real** depth-2 `assemble_path` | construct→**prove** over genuine branch layers; BP+ + RCT balance | verify half **live** (CT-5 closed #162) |
| **Request-path composition** | **2c-2b (#163)** | (composition, not a new prover path) | mint handle → `persist_bond_record` → `sign_bond` → `build_join_market_vin` → verify accept | none new (real-tree verify now live; on-chain bond gated on **2d** broadcast/transport) |

2c-2b's "milestone KAT" is the **request-path composition** — it exercises the
*orchestration seam* (handle + ticket + request → signed vin → verify), **not** a
new prover round-trip; the prover round-trips are already closed by 2a/2c-1. With
CT-5 closed (#162), the real-tree verify half is live; the **on-chain** bond now
remains gated on **2d** (broadcast + `P`-isolated transport), **not** CT-5.

---

## 6. Cross-series gate: CT-5

The bond chain depends on the parallel CT-5 series (production `CurveTreeClient`
into the 2A signer):

- **CT-5c** (assembler cutover) — **landed 2026-06-18** (`feat/ct-5c-assembler-
  cutover`); made the real `assemble_path` available (unblocked Bond-PR 2c-1's
  prove half). `CT5C_ASSEMBLER_CUTOVER.md`.
- **CT-5d** (reanchor slice) — **landed 2026-06-18**; the content-preserving
  reprove path ships, content-changing reselect deferred under rule-21. Pins the
  persona re-sign behavior Bond-PR 2d's broadcast/re-anchor activates.
  `CT5D_REANCHOR.md`.
- **CT-5 full closure** (FCMP++ prove↔verify over real multi-layer branch layers)
  — **CLOSED 2026-06-20 (#162)**. The blocker was a first-party prover bug, not
  vendored-crypto unsoundness: `shekyl-curve-tree::assemble` emitted **narrow**
  branch chunks for incomplete nodes, but the FCMP membership circuit needs the
  full chunk width; the fix zero-pads branch chunks to width in
  `shekyl_fcmp::proof::prove` (zero scalars vanish in the layer hash, so the
  consensus root is unchanged). The real-tree **verify** KATs are now **live**
  (no `#[ignore]`). **Bond-PR 2d is no longer gated on CT-5** — its remaining
  gate is **internal** (2d-1's `P`-scan layer, then 2d-2 broadcast/transport).

---

## 7. Plan-doc convention going forward

- This arc doc is the index; **full per-PR plan docs exist only for unstarted
  PRs** (2c-2b now, 2d when 2c-2b closes), each following the
  `26-sub-pr-design-discipline.mdc` round + pre-flight shape.
- Landed PRs are **status-of-record** here (§3), not retrofitted into full plan
  docs — the design rationale already lives in `ARCHIVAL_BOND_CONSTRUCTION.md`
  §10 and is not re-derived.
- `R0-D#` IDs stay reserved for each PR's **impl-time** pre-flight pass (after its
  design rounds close); opening scoping pre-flights use `SP-#` (see the 2c-2b
  plan doc §0).

## Revision history

- **2026-06-19:** Created. Numbering disambiguation (`Bond-PR` prefix),
  2b→Model-D supersession ledger, KAT lineage, CT-5 gate. Opens the Bond-PR 2c-2b
  plan-doc nesting.
