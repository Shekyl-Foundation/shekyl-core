# Phase 2b — `StakeState` FSM retool (rebased substrate)

**Status:** **P2B-1 confirmed; P2B-4 expanded; R1 + R1b + G4-1–G4-7 closed (2026-06-07).**
join-Market seam (lag-forced); gate-4 wire lean **(b)** `txin_archival_bond_post` incl.
`Unbond` ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md)).
Supersedes [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) **§3–§5.2** (claim-era
FSM) until those sections are rewritten against this doc.

**Authority:** [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §2.4 (rebased scope);
[`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §6 (bond record, dedup, `pop_block`);
[`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §9 (`P` keys, `P_canonical_id`).

**Why now:** §2.4 and the emission leg already describe the rebased model. §3 still runs the
**opposite** mechanism — output-keyed instances, nullifier-derived `claimed_epochs`, tier-lock
yield states. Retool is **two inversions + a collapse**, not a field rename.

---

## P2B-0 — Master diagnosis

| Axis | Stale §3 (claim era) | Rebased model (§2.4 + emission leg) |
|------|----------------------|-------------------------------------|
| Instance primary key | `StakeId` = cSHAKE(`shekyl/stake-id-v1`, tx_hash ‖ index) | `P_canonical_id` = cSHAKE(`shekyl/archival-p-id-v1`, `HybridPublicKey`) |
| Claim dedup | Wallet learns from on-chain nullifier `N_{i,S}` | Consensus `bond.claimed_settlement_epochs.check_and_set(E)` |
| `claimed_epochs` locus | Wallet-sealed `EpochSet` (§3.3.2) | Public consensus state on `ArchivalBondRecord` |
| Yield lifecycle | `Locked` / `Accruing` / `Claimable` (tier lock + ρ×weight) | Continuous serve-while-good; **emit** is an action |
| Reorg (wallet) | Clear/replay nullifier mask (§5.2) | Re-read bond record after consensus `pop_block` |

---

## P2B-1 — Re-home instance key on `P_canonical_id` (MASTER — confirmed)

### Finding

§3.3.3 keys the wallet on the **staked output** and calls output identity "stable" (line 950).
Under transfer-shaped admission + membership-only backing, the **admission/backing UTXO rotates**
(E-4 gate-6 hygiene) while **`P` persists**. Output-keyed instances **orphan on every backing
rotation**; `P_canonical_id`-keyed instances survive it.

### Disposition (proposed — confirm or push back)

1. **Wallet primary key = `P_canonical_id`** — same 32-byte id consensus uses for
   `ArchivalBondRecord` lookup (emission §6.1). One key, wallet and chain agree.
2. **Carry §3.3.3 discipline verbatim** — cSHAKE256, SP 800-185 customization domain,
   full 32-byte output, wallet-internal KAT, `v1` bump = migration — **only** swap:
   - customization: `"shekyl/archival-p-id-v1"`
   - input: `HybridPublicKey::to_canonical_bytes()` (from [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §9.5)
3. **Delete `StakeId` / `shekyl/stake-id-v1`** from the rebased FSM — no output-derived
   primary key. Optional **secondary** `OutputRef` fields track rotatable backing UTXOs; they
   are not instance identity.
4. **Rename (suggested):** `StakeInstance` → `ArchivalPInstance` (or `PInstance`) in wallet
   docs/code when retool lands — signals per-`P` not per-stake-output.

### Two rotation concepts (do not conflate)

| Concept | What changes | `P_canonical_id` | Gate-6 / wallet |
|---------|--------------|------------------|-----------------|
| **Backing UTXO rotation** (E-4 hygiene) | Admission/membership outputs on main tree | **Unchanged** | Update `backing_outputs` on same instance |
| **`P` pseudonym rotation** (decorrelation) | HKDF `p_slot` → new keys (§9.2) | **New** id | New instance; old slot retired |

P2B-1 is about the **first** row. Gate-6 §9 `p_slot` governs the **second**.

### Compatibility with Gate-6 Round 1

**Aligned.** §9 already pins `p_canonical_id` as bond identity. §9 `p_slot` is derivation input
only; it does not replace `P_canonical_id` as the wallet/consensus primary key.

### `PHandle` — closed (no reopen)

`P_canonical_id` exists at HKDF derivation (gate-6 §9.3–§9.5) — before announce, before
first emission, before bond record. The GUI always has a stable row id from instance creation.
**No `PHandle`.**

### P2B-1 exit

- [x] Primary key = `P_canonical_id`; backing demoted to rotatable field.
- [x] `PHandle` rejected.
- [x] §3.3.3 rewritten as archival `P_canonical_id` pin (PHASE_2B §3.3; gate-6 §9.5).

---

## P2B-2 — Dedup inversion (`claimed_epochs` leaves wallet authority)

### Finding

§3.2 / §3.4: wallet derives `claimed_epochs` from nullifier scan + §5.2 replay. Emission leg:
**no published tag**, dedup on bond record, `pop_block` reverts atomically (§7.1 step 3, §8).

§2.4 (same doc, ~line 575) already states relocation — §3 contradicts it.

### Disposition

1. **Delete** `OwnNullifierObserved` and all nullifier-scan claim transitions (§3.2 table).
2. **`claimed_settlement_epochs` is public consensus state** — wallet holds a **cache**
   (daemon RPC / scan of bond record), not a sealed secret set. §3.3.2 "sealed regardless,
   leaks no cardinality" is **moot**.
3. **Move §3.3.2 wire encoding spec** out of PHASE_2B →
   [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) + emission §6.3; PHASE_2B
   **references** semantics only.
4. **Survives in wallet:** `emission_pending_epochs` (runtime-only reservation — don't build
   a second emission vin for an in-flight `E`). Hybrid-B boundary unchanged: `PendingTxEngine`
   stays spend-pure; emission is non-spending.

### Cascade from P2B-1

Cache is keyed by **`P_canonical_id`**, refreshed after each emission confirm and after reorg
notification — not rebuilt from nullifiers.

---

## P2B-3 — `ClaimedEpochSet` encoding reopened (coupled to `W`)

### Finding

§3.3.2 `u16` relative mask: ≤15 contiguous epochs from tier lock — **wrong envelope**.
Reopen criterion in §3.3.2 (lines 901–903) **has fired**: sparse gaps from gate-6 lapse,
bound is **`W`** not tier window.

### Disposition

1. **Shape:** absolute sparse set of settlement-epoch indices `E` (sorted list or bitmap over
   `(tip − W, tip]` window) — semantics pinned emission §6.3; **encoding TBD until `W` pinned**
   (joint with F1/F4 epoch-length / forfeiture).
2. **Reject for genesis encoding options:**
   - **LMDB `dup-keys (P_id, E)`** — collides with Shekyl composite-key discipline
     ([`LMDB_SCHEMA.md`](../LMDB_SCHEMA.md): curve-tree tables explicitly **no `MDB_DUPSORT`**).
     Prefer composite key `P_id ‖ BE(E)` or separate table keyed by `(P_id, E)` without DUPSORT.
   - **Roaring** — overkill unless `W` is very large; defer unless size proof demands it.
3. **Emission leg §6.3** amended to drop `dup-keys` option (see that file).

### Not independent of P2B-1

Encoding lives on **`ArchivalBondRecord` keyed by `P_canonical_id`** — same key as wallet instance.

---

## P2B-4 — State collapse (four states + graph; R1 closed)

### Finding

§3.1 "states unchanged in shape" is false. `Locked` / `Accruing` / `Claimable` encode
tier-lock + confidential yield — **deleted subsystem**. Archival: serve continuously while
good-standing; reward is per-epoch **work**, claimed by **emission** action.

### `AdmissionPending` — keep (§9.4-forced)

Gate-6 §9.4 persists `p_slot`, public `p_canonical_id`, and holdings metadata from
derivation — before any on-chain anchor. "No row until bonded" drops state §9.4 requires.
Gate-6 §3 lifecycle (derive → announce/backing → serve) fits in one setup state; sub-phases
do not need separate FSM states.

### Bond vs. backing (load-bearing split)

| Object | Role | Lifetime |
|--------|------|----------|
| **Bond** | Gate-4 slashable collateral; `ArchivalBondRecord` anchor | Persists across `P`'s service life |
| **Backing / admission UTXO** | Ordinary transfer(s) ≥ MIN; membership-only proof at emission | Rotatable (gate-6 E-4 hygiene); rotation consensus-invisible |

Soft-admission safety (§2.4): challenge failure slashes **bond** regardless of backing
UTXO state. Instance fields: `bond_ref` (stable) + `backing_outputs` (rotatable) — never
conflate.

### Collapse (deleted)

`Locked` / `Accruing` / `Claimable` (tier yield); `FullyUnstaked { principal_spent }`
(no staked commitment); §8.3 Accruing/Claimable split (lock-window UX); claim-as-state →
**emit** is an action.

### Four states

| State | Defining predicate | Consensus footprint | Persisted (wallet) |
|-------|-------------------|---------------------|-------------------|
| `AdmissionPending` | No bond record | Gate-2 retention bits may accrue but **don't count** (`R_market` filters `P ∈ Market`; §3.3) | `p_slot`, `p_canonical_id`, holdings-being-served (§9.4) |
| `Bonded` | Bond record ∧ `bonded_total > 0` | Counted retention; `Σwork`; **partial slash** shrinks holdings in-place | + `bond_ref`, `backing_outputs`, `claimed_epochs` cache |
| `Slashed` | Bond record ∧ `bonded_total == 0` | Terminal slash only; out of Market until re-bond | Same; cache frozen |
| `Exited` | Drain confirmed; retiring; collateral in release cooldown until **Unbond** | Record until prune | Same; backlog cache; bond cooldown |

**`good_standing`:** predicate from bond record, **not** an FSM state. Grace-window
(`good_standing = false`, slash pending) stays `Bonded`; blocks emit-new (emission §6.5
posture) but not FSM transition. **G1 (a) — highest-priority surfacing:** wallet shows
"challenge failure pending, N blocks to respond" (R4) — actionable cure window.

**Partial vs terminal slash (gate-4 §4.2):** dropping one shard from `ShardSetCompact`
reduces `bonded_total` and `holdings`; `P` **stays `Bonded`** in Market on remaining shards.
Only last-shard slash (or CompleteTree whole) → `bonded_total == 0` → **`Slashed`**. Wallet
must surface slash cause (which shard) for re-bond hygiene; must not conflate partial slash
with `Slashed` transition.

**`Exited` refinements:**

1. **Not claim-terminal.** E-3: pre-exit good epochs claimable within `W`. Emit-backlog
   persists in `Exited` (and `Slashed`) until `W` lapses on the last good epoch.
2. **Not collateral-terminal.** Escrowed bond returns via **`Unbond`** after release
   cooldown (grace past last serve) — shorter than `W`. Drain does not release bond
   (G4-1). Full retirement = bond released ∧ backlog exhausted/lapsed; then `p_slot` burn.
3. **Graph, not ladder.** `Slashed ⇄ Bonded` via re-bond (foundation §3.2). Re-entry of
   `Exited` → **new `p_slot` / new `P`** (R2), not revive — reviving re-links decorrelation.

### join-Market seam (R1 — closed)

**Supersedes:** "privacy-first → bundled initial bond-post with first mint" — **structurally
impossible** given §4.5 lag + invariant 2 (finalized-at-E-close).

#### Five functions of first on-chain bond presence

| Function | Gates | Load-bearing from | At join-Market? | At first mint? |
|----------|-------|-------------------|-----------------|----------------|
| Locked bond present | Ledger admission (anti-bloat) | join | yes | — |
| Gate-2 writes `(P,s,E)` bits | `P` starts serving | join | yes | — |
| `P ∈ Market` | `R_market` / `Σwork` counting | `E ≥ E_join + 1` | yes | — |
| Claim eligibility | which epochs `P` may mint | `E ≥ E_join + 1` | yes | — |
| Drop-after-pay deterrent | ongoing retention | first paid epoch | bond from join | yes |
| Slash teeth | bond collateral | join | yes | — |
| Dedup register | double-claim | first mint | empty set at join | yes |

Rows 1–4 and slash fire at **join-Market**. Row 5–6 (mint/dedup) fire at **first paying
emission** (≥ `E_join + 1` for work in `E_join`).

#### Why lag forbids bundling record creation with first paying mint

To claim epoch `E`, emission cites `Σwork(E)` finalized at **E-close** (§4.5), typically
in **`E+1` or later**. `Σwork(E)` counts only `P' ∈ Market` at E-close (§4.2, §4.4;
archival state §3.3, invariant 2).

If `ArchivalBondRecord` is created at first paying mint (≥ `E+1`), then at E-close `P ∉
Market` → `E` is neither counted nor claimable → first mint would claim nothing. Retroactive
inclusion would mutate finalized `R_market(s,E)` — violates invariant 2.

**Conclusion:** bond record creation must precede the first **paying** mint by at least the
settlement lag. Bundling is not a privacy tradeoff; it is a **consensus impossibility**.

#### join-Market event (one seam, triple duty)

One on-chain event — **join-Market** — that:

1. Posts locked bond (`bonded_total_atomic == bond_floor(holdings)`).
2. Creates `ArchivalBondRecord` with empty `claimed_settlement_epochs`.
3. Stamps `E_join` (settlement epoch of join).
4. From join: gate-2 may write `(P,s,E)` bits (**no bits pre-join** — state-bloat closed).
5. From join: `P ∈ Market` for `E ≥ E_join + 1` (partial epoch `E_join` forfeited).
6. First paying emission batches `[E_join + 1, …]` subject to `W` and batch cap.

**Counted ⟺ claimable ⟺ `E ≥ E_join + 1`** — deterministic; no gate-2 coupling.

**Anti-replica-flooding:** Market entry without bonded collateral would let attackers flood
fake `P` replicas, crater `R_market` scarcity, and drive honest reward toward zero. Bond +
8c make each counted replica cost `ARCHIVAL_BOND_FLOOR` and real storage. Pre-mint bond job
= **`R_market` integrity**; drop-after-pay is an additional ongoing job.

#### Gate-6 consequence (honest posture)

join-Market is an **unavoidable distinct on-chain timing event** — lag guarantees it cannot
hide inside a mint. Gate-6 §2.3 invariant 3 and §2.5 must **defang** join-Market directly
(jitter, decorrelated bond sourcing, delay between principal funding and join-Market) — not
wish it away via bundling.

#### Emission / PHASE_2B amendments

**Landed (2026-06-07):** [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) + emission
§2.4/§6/§7.1/§8, PHASE_2B §2.4 tx-leg table, archival state `Market`/`E_join`, gate-6 §3.

**Registration fusion (preserved meaning):** no separate *registration transaction type*
in the old stake sense; fusion does **not** remove the registration **event** (PHASE_2B
§2.4 already says this).

#### Wire shape (only open sub-question)

Lag answers "one tx or two" for join vs paying mint (separate events, full stop). Remaining
choice:

| Option | Shape | Notes |
|--------|-------|-------|
| **(a)** | Zero-mint variant of `txin_archival_reward_emission` | Preserves literal "first emission creates record"; join = emission claiming `∅` + bond |
| **(b)** | Dedicated `txin_archival_bond_*` (gate-4) | Same vin for **initial join** and **re-bond**; mint fully separate |

**Lean (b):** one bond-posture vin type for create/update; rows 1–4 vs row 5 separation
on the wire matches the function decomposition. Re-bond needs (b) regardless.

**R1b closed:** first counted/claimable epoch = **`E_join + 1`** ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) §2.2).

### Transition graph (replaces §3.2 ladder)

| From | Event | To |
|------|-------|-----|
| — | HKDF derive `P` (§9.4) | `AdmissionPending` |
| `AdmissionPending` | **join-Market** confirm (bond-post vin; record + `E_join`) | `Bonded` |
| `Bonded` | Partial slash (shard dropped; bond > 0) | `Bonded` |
| `Bonded` | Terminal slash (`bonded_total → 0`) | `Slashed` |
| `Slashed` | Standalone re-bond (gate-4) | `Bonded` |
| `Bonded` / `Slashed` | Decorrelated drain confirms | `Exited` |
| `Exited` | Release cooldown elapsed | **Unbond** (collateral returned) |
| `Exited` | Bond released ∧ backlog exhausted/lapsed (`W`) | Terminal (`p_slot` burn) |
| `Bonded` | Reorg disconnects **join-Market** block (§8.2) | `AdmissionPending` |
| `Exited` / `Slashed` | Reorg on drain/slash block | Re-read bond → prior state |

Every reorg edge: **re-fetch, don't replay** (P2B-5).

### Actions (tx lifecycle, not P-state)

Build → broadcast → confirm uses `PendingTxEngine` substates on the **tx**. P-state moves
on load-bearing confirms (**join-Market** → `Bonded`; drain → `Exited`). First **paying**
emission is the first emit action within `Bonded`:

| Action | When | Notes |
|--------|------|-------|
| Fund admission | `AdmissionPending` | Ordinary transfer to `P` |
| Emit | `Bonded` / `Slashed` / `Exited` | `txin_archival_reward_emission`, batch ≤ 15. **Emit-new:** `Bonded` + `good_standing`. **Emit-backlog:** any of three + `good_through(E)` + `W` + dedup |
| Rotate backing | `Bonded` | Membership-only; updates `backing_outputs`; no state change |
| Exit / drain | `Bonded` / `Slashed` | Decorrelated `P`→principal — **non-escrowed** outputs only |
| Unbond | `Exited` (post-cooldown) | Gate-4 collateral return; independent of backlog emit (`W`) |

`emission_pending_epochs` (P2B-2) attaches to emit action.

### `ArchivalPInstance` shape

Keyed `P_canonical_id`: `p_slot`, `state`, `bond_ref`, `backing_outputs`, holdings/shard-set,
`claimed_epochs` (public cache), `emission_pending_epochs` (runtime). Secrets re-derived from
`master_seed_64` + `p_slot` only (§9.4). `good_standing` / `good_through(E)` = bond reads,
never authoritative locally.

### Residuals

| ID | Item | Owner |
|----|------|-------|
| **R1** | **Closed** — join-Market seam; wire lean **(b)** `txin_archival_bond_post` | [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) |
| **R1b** | **Closed** — `E ≥ E_join + 1`; partial `E_join` forfeited | Gate-4 §2.2 |
| **G4-1** | `Unbond` + release cooldown vs `W` backlog | Gate-4 §4.3 |
| **G4-3** | **Closed** — conservation law `already_generated == circulating + bonded + burned` | Gate-4 §4.5 |
| **Custody** | **Closed** — consensus balance + `bond_credit`/`bond_debit` | Gate-4 §3.2 |
| **R2** | `Exited` re-entry → new slot only | Gate-6 rotation round |
| **R3** | §8.3 amendment (Accruing/Claimable closed) | PHASE_2B retool write-up |
| **R4** | Grace-window GUI surfacing (**G1a — priority-1 UX**) | §7 G1 + gate-6 §5 |
| **Substrate verify** | **Closed (2026-06-07)** — LMDB pattern on `dev` verified; bond wire greenfield | PHASE_2B §7.11 |

---

## P2B-5 — Reorg simplifies to re-read (largely closed)

### Finding

§5.2 nullifier replay dies with nullifier dedup. Emission: `pop_block` reverts
`claimed_settlement_epochs` atomically (§7.1, §8).

### Disposition

1. **Consensus:** per-block pop **all-types-atomic** (gate-4 §5): bond credit/debit,
   `total_bonded_atomic`, record create/delete, same-block retention bits, FCMP outputs,
   interval-log pop — single LMDB txn. Cross-block join cascade via archival state §6
   ordered pop (tip → `H`).
2. **Wallet:** on reorg notification, **re-fetch `ArchivalBondRecord` for each live
   `P_canonical_id`**; refresh `claimed_epochs` cache; clear `emission_pending_epochs` for
   disconnected heights. `Bonded` → `AdmissionPending` on join-Market revert only.
3. **Delete:** §3.3.2 reorg-stable anchor / eligible_height drain argument (tier-era).

---

## P2B-6 — Threat model re-center (last structural piece)

### Finding

§7 wargames F0 + nullifiers — both gone. Re-center on gate-6 long-lived correlation; F1
(epoch-granularity retention fingerprint vs rotation) is a first-class §7 entry. Bond
conservation law (gate-4 §4.5) extends G11 — loud bond terms cannot mask inflation.

### Disposition

**Landed (2026-06-07):** [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) §7;
claim-era wargame → §7.A. Draft retained as [`PHASE_2B_SECTION7_DRAFT.md`](PHASE_2B_SECTION7_DRAFT.md).

**Closed in review:**

- [x] F1 — conditionally finally accepted (T-A1 v2); SEB **not** F1 lever; timing cluster pinned.
- [x] T-A16 (A6 grief) + T-A15b (HoldingsUpdate evasion) + T-A17 (join censorship, low).
- [x] G11 — positive KAT invariants G11-E1/E2/E3; full-node vs light-client split.
- [x] G1 — three-tier surfacing; partial slash stays `Bonded` (FSM amended).
- [x] LMDB substrate verify on `dev` — pattern clean (§7.11).

PHASE_2B §3.1–§3.4 + §7 landed. §4–§6 still claim-era. **T-A1** blocks F1 final accept.

---

## Forward order

```text
T-A1 sim (F1 gate) → numeric cluster values → §4–§5 retool
```

P2B-1, R1, R1b, custody, G4-3, **§3 FSM graph** closed. P2B-5 largely closed (gate-4 §5).
Parallel: gate-6 §2.3/§2.5 join-Market defanging; gate-2 slash trigger.

---

## Revision history

- **2026-06-07 (h):** P2B-6 review r1; partial-slash FSM; R4/G1a elevation; substrate verify item.
- **2026-06-07 (g):** PHASE_2B §3.1–§3.4 archival FSM landed; P2B-1 §3.3.3 closed;
  `ARCHIVAL_TIMING_CONSTANTS.md` stub; forward order → §7 then numeric values.
- **2026-06-07 (f):** Gate-4 round-1 custody base; conservation law; P2B-5/forward order.
- **2026-06-07 (e):** G4-1–G4-7 pins in gate-4 doc; `E_join+1`; Unbond; FSM/emit table.
- **2026-06-07 (d):** [`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md) Round 0; corpus
  amendments (emission, PHASE_2B, archival state, gate-6).
- **2026-06-07 (c):** R1 closed — join-Market seam (lag-forced); bundled lean overturned;
  gate-6 must defang join event; FSM edge = join confirm not first mint.
- **2026-06-07 (b):** P2B-1 confirmed; `PHandle` closed; P2B-4 expanded (graph, bond/backing,
  R1–R4); AdmissionPending §9.4-forced; Exited refinements.
- **2026-06-07 (a):** Initial retool disposition (P2B-0–6); P2B-1 opened.
