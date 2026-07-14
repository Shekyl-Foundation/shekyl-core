# Phase 2b — `StakeState` FSM retool (rebased substrate)

**Status:** **P2B-1 confirmed; P2B-4 expanded; R1 + R1b + G4-1–G4-7 closed (2026-06-07);
P2B-7 `HoldingsUpdate` friction pinned (genesis, 2026-06-15).**
join-Market seam (lag-forced); gate-4 wire lean **(b)** `txin_archival_bond_post` incl.
`Unbond` + `HoldingsUpdate` ([`ARCHIVAL_BOND_GATE4.md`](ARCHIVAL_BOND_GATE4.md)).
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
Under transfer-shaped admission + membership-only backing, the **funding output designated by an
emission changes per emission** while **`P` persists** (per-emission selection from `P`'s funding
pool — not a "rotation," not consensus-tracked, §7.3). Output-keyed instances **orphan whenever the
designated output changes**; `P_canonical_id`-keyed instances survive it.

### Disposition (proposed — confirm or push back)

1. **Wallet primary key = `P_canonical_id`** — same 32-byte id consensus uses for
   `ArchivalBondRecord` lookup (emission §6.1). One key, wallet and chain agree.
2. **Carry §3.3.3 discipline verbatim** — cSHAKE256, SP 800-185 customization domain,
   full 32-byte output, wallet-internal KAT, `v1` bump = migration — **only** swap:
   - customization: `"shekyl/archival-p-id-v1"`
   - input: `HybridPublicKey::to_canonical_bytes()` (from [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) §9.5)
3. **Delete `StakeId` / `shekyl/stake-id-v1`** from the rebased FSM — no output-derived
   primary key. The `funding_outputs` pool an emission designates backing from is **not** instance
   identity (and is not a "rotatable field" — see the corrected table below).
4. **Rename (suggested):** `StakeInstance` → `ArchivalPInstance` (or `PInstance`) in wallet
   docs/code when retool lands — signals per-`P` not per-stake-output.

### "Rotation" is not a mechanism — settled, recorded at the root (do not re-litigate)

**There is no "`P` rotation," and neither thing below is a decorrelation lever.** Pinned here at the
origin because this keeps getting re-litigated. "Rotation" is loose shorthand for two unrelated
things, and *both* the "hygiene" and "decorrelation" framings the earlier table carried are wrong at
source:

| Loose term | What it actually is (verified at source 2026-07-12) | `P_canonical_id` |
|------------|------------------------------------------------------|------------------|
| **Backing-output "rotation"** | `P` designates a (possibly different) output from its **own `funding_outputs` pool** to back each emission, membership-only (`BackingSet::designate_backing`). **Not a mechanism, not a hygiene action, not consensus-tracked:** there is **no `backing_outputs` field** anywhere in the code, and the **consensus backing-rotation rule was dropped** — [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) §7.3, "Consensus does not require backing-output rotation." No backing output is ever shared between personas (each is scanned under one `P`'s view key). | **Unchanged** |
| **Pseudonym "rotation"** | Retire `P_old` (`Unbond` + drain) + create `P_new` (fresh `JoinMarket`): **unlink-and-relink**, two independent lifecycle ops with **no bond migration** ([`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) S-5: migration "would be a new consensus op … out of scope for V3.0"). **Not a decorrelation lever** — it provides **correlation** (T-A1 portfolio re-linkage: `P_old`↔`P_new` re-links on the public portfolio), which is precisely why **long-lived `P` is the committed architecture** (S-5). | **New** id (a *fresh* persona, unlinked by design) |

**The one load-bearing takeaway (the actual P2B-1 point):** key the instance on `P_canonical_id`,
**never on an output** — because the funding outputs a persona uses change per emission while `P`
persists. `p_slot` (Gate-6 §9.2) is a wallet-internal key-derivation index for deriving a *fresh*
persona; it is **not** a rotation of an existing one. Do not describe either item above as
"decorrelation," "E-4 hygiene," or a "rotation action."

### Compatibility with Gate-6 Round 1

**Aligned.** §9 already pins `p_canonical_id` as bond identity. §9 `p_slot` is derivation input
only; it does not replace `P_canonical_id` as the wallet/consensus primary key.

### `PHandle` — closed (no reopen)

`P_canonical_id` exists at HKDF derivation (gate-6 §9.3–§9.5) — before announce, before
first emission, before bond record. The GUI always has a stable row id from instance creation.
**No `PHandle`.**

### P2B-1 exit

- [x] Primary key = `P_canonical_id`; backing is not instance identity (the `funding_outputs` pool, designated per emission — not a "rotatable field").
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

1. **Shape:** absolute sparse set of settlement-epoch indices `E` — semantics pinned emission
   §6.3. **Encoding decided (2026-06-11, `W = 26`):** inline sorted absolute-epoch list on
   `ArchivalBondValue` (v3 → v4), `u32` count + `u64` BE entries, cap 32; bitmap and
   separate-table options rejected with reversion clause — see emission §6.3.
   **Landed (2026-06-12):** v4 codec in `blockchain_db/shekyl_types.h` with decode
   invariants (cap, strict monotone, span ≤ `W`); windowed dedup semantics in
   `shekyl-archival-retention::claimed_epochs` (`LMDB_SCHEMA.md` §`archival_bond`).
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
| **Backing / funding output** | Ordinary `P`-owned output; membership-only proof at emission | Designated per emission from `funding_outputs`; **not** a "rotation" and **not** consensus-tracked (§7.3) |

Soft-admission safety (§2.4): challenge failure slashes **bond** regardless of which funding
output an emission designates. Instance fields: `bond_ref` (stable) + the `funding_outputs` pool
(designated-from per emission, not a rotatable field) — never conflate.

### Collapse (deleted)

`Locked` / `Accruing` / `Claimable` (tier yield); `FullyUnstaked { principal_spent }`
(no staked commitment); §8.3 Accruing/Claimable split (lock-window UX); claim-as-state →
**emit** is an action.

### Four states

| State | Defining predicate | Consensus footprint | Persisted (wallet) |
|-------|-------------------|---------------------|-------------------|
| `AdmissionPending` | No bond record | Gate-2 retention bits may accrue but **don't count** (`R_market` filters `P ∈ Market`; §3.3) | `p_slot`, `p_canonical_id`, holdings-being-served (§9.4) |
| `Bonded` | Bond record ∧ `bonded_total > 0` | Counted retention; `Σwork`; **partial slash** shrinks holdings in-place | + `bond_ref`, `funding_outputs`, `claimed_epochs` cache |
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

**Voluntary holdings adjustment (`HoldingsUpdate`, genesis — P2B-7):** add/drop one shard
shares the partial-slash *shape* — `bonded_total` and `holdings` mutate in-place, `P` **stays
`Bonded`** — but differs on three load-bearing points: (1) it is **voluntary** (a self-posted
`txin_archival_bond_post` `post_kind = HoldingsUpdate`), not consensus-imposed; (2) **grace-tail**
(ratified 2026-07-15) — the dropped shard's release cooldown must have elapsed **before** the drop
posts, and at connect the `FLOOR` returns immediately (no post-drop cooldown sub-state); (3) the
anti-dodge is the precondition itself — the drop cannot post until the shard's slashes are settled
through its last-served anchor **and** its `bond_duration(age)` retention horizon has elapsed, so no
in-flight challenge is escaped. Friction semantics, the slashable-when boundary, and the
mutable-holdings serve-credit reconciliation are pinned in **P2B-7**.

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
| `Bonded` | **HoldingsUpdate add shard** (credit `+FLOOR`; holdings grows) | `Bonded` |
| `Bonded` | **HoldingsUpdate drop shard** (debit `FLOOR`; **≥1 shard remains**; grace-tail — cooldown/slash-settlement are drop *preconditions*, FLOOR returns at connect) | `Bonded` |
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
| Designate backing (per emission — *not* a "rotation") | `Bonded` | membership-only selection from `funding_outputs`; consensus-untracked (§7.3); no state change |
| HoldingsUpdate add shard | `Bonded` | `txin_archival_bond_post` `post_kind = HoldingsUpdate`; `bond_credit = +FLOOR`; new shard's serve begins, counted/claimable for that shard from `E_add + 1` (per-shard R1b) |
| HoldingsUpdate drop shard | `Bonded` (**≥1 shard remains**) | `post_kind = HoldingsUpdate`; `bond_debit = FLOOR`; **grace-tail** (P2B-7 Pin 2/3): the dropped shard's release cooldown must have elapsed and its slashes settled **before** the drop posts (no drop-to-dodge), and its `bond_duration(age)` retention horizon must have elapsed; at connect the shard leaves `holdings` and the `FLOOR` returns immediately. Dropping the last shard is rejected; use `Unbond` (→ `Exited`) |
| Exit / drain | `Bonded` / `Slashed` | Decorrelated `P`→principal — **non-escrowed** outputs only |
| Unbond | `Exited` (post-cooldown) | Gate-4 collateral return; independent of backlog emit (`W`) |

`emission_pending_epochs` (P2B-2) attaches to emit action.

### `ArchivalPInstance` shape

Keyed `P_canonical_id`: `p_slot`, `state`, `bond_ref`, `funding_outputs` (the pool an emission designates backing from — not a `backing_outputs` field), holdings/shard-set,
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
| **P2B-7** | `HoldingsUpdate` FSM/read pins (genesis); open: per-shard `E_add+1` connect rule, age-stratified sim reconciliation (seal-gating) | gate-4 §4.4; `shekyl-archival-retention`; Step 3 sim |
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
claim-era wargame → §7.A. Draft retained as [`PHASE_2B_SECTION7_DRAFT.md`](../completed/PHASE_2B_SECTION7_DRAFT.md).

**Closed in review:**

- [x] F1 — conditionally finally accepted (T-A1 v2); SEB **not** F1 lever; timing cluster pinned.
- [x] T-A16 (A6 grief) + T-A15b (HoldingsUpdate evasion — now structurally foreclosed by
  P2B-7 Pin 3 grace-tail: a drop cannot post until the shard's slashes are settled and its
  retention horizon has elapsed) + T-A17 (join censorship, low).
- [x] G11 — positive KAT invariants G11-E1/E2/E3; full-node vs light-client split.
- [x] G1 — three-tier surfacing; partial slash stays `Bonded` (FSM amended).
- [x] LMDB substrate verify on `dev` — pattern clean (§7.11).

PHASE_2B §3.1–§3.4 + §7 landed. §4–§6 still claim-era. **T-A1** blocks F1 final accept.

---

## P2B-7 — `HoldingsUpdate` friction pin (genesis; FSM + consensus-read consequences)

### Why now

`HoldingsUpdate` (voluntary add/drop of one held shard) was deferred-V3.1; **promoted to
V3.0 (2026-06-15)** — the bond lifecycle is consensus-state-machine balance, so adding
mid-life shard adjustment post-genesis is a hard fork (gate-4 §4.4). The bond *wire* and the
*principle* land in gate-4; this section pins the pieces that are **FSM-state and
consensus-read** consequences PHASE_2B owns, so the retool and the
`shekyl-archival-retention` connect paths implement them rather than inherit a tip-holdings
assumption that no longer holds.

All bond-lifecycle verify/connect logic is **Rust-native** (`shekyl-archival-retention`);
the C++ daemon delegates via FFI (gate-4 §6, FOLLOWUPS V3.0). The pins below are
specification, not C++ behavior.

### Pin 1 — both adjustments stay `Bonded`; floor mutates in-place

Add and drop both keep `P` in `Bonded` (transition graph above). `bonded_total_atomic` and
`holdings` move together under the `== bond_floor(holdings)` pin (gate-4 §3.2, §3.5 step 4).
Dropping the **last** shard is rejected at verify (post-state holdings must be non-empty);
full exit is `Unbond` (→ `Exited`). This keeps `HoldingsUpdate` total-preserving on the FSM:
it never lands in `Slashed` or `Exited`.

### Pin 2 — per-shard release cooldown (the friction) — GRACE-TAIL, ratified 2026-07-15

**The cooldown is a verify PRECONDITION on the drop, not a post-drop state** (grace-tail,
the same model as `Unbond` — `release_cooldown.rs` names HoldingsUpdate-drop as a consumer
of the identical predicates). A drop of shard *s* cannot be posted until *s*'s release
cooldown has elapsed (`release_cooldown_elapsed` on *s*'s `last_served_epoch`) **and** the
slash scheduler has settled through that anchor (`slashes_settled_through`); at connect the
shard leaves `holdings`, `bonded_total −= FLOOR`, and the `FLOOR` **returns immediately** via
the `bond_debit` source term (§3.2). There is **no `collateral-in-cooldown` sub-state, no
`bond_event_log` drop interval, and no clean-close marker** — `P` stays `Bonded` with ≥1
shard, so there is no exit epoch to record. The friction (freed capital cannot recycle until
the cooldown elapses) is real and identical to the superseded reading — it is just enforced
*before* the drop rather than tracked *after* it.

*Satisfiability + why this is the right call (ratified 2026-07-15).* The cooldown epochs
after last-serve are unserved-by-definition and exit-forgiven at the drop connect
(`release_cooldown.rs` guarantee), so grace-tail-DROP is satisfiable exactly as
grace-tail-Unbond is — the persona freezes `last_served`, the pending challenges through the
anchor resolve on still-bonded collateral, then the drop posts. The two models are
**economically identical** (both leave *s* unserved and its `FLOOR` frozen for exactly the
cooldown window; coverage is accounted by serve-credit, not holdings, so a held-but-unserved
shard is uncovered under either — see the confirmations below), so this fork is
**sim-agnostic**: no L18 re-run, no seal impact. That removes the only thing that could have
forced drop-then-cool; grace-tail then wins on FSM shape alone (a gated shrink vs. a
sub-state machine).

Add (top-up) carries no cooldown: `bond_credit = +FLOOR` is immediate; the new shard's
serve obligations begin at the add confirm.

### Pin 3 — slashable-when boundary (no drop-to-dodge) — under grace-tail

The retention-commitment horizon (`bond_duration(age)`, gate-4 §4.4; HoldingsUpdate slice A)
is the *earlier* gate: a shard younger than its horizon is **ineligible for voluntary drop at
all**. The anti-dodge is then the **precondition**: the drop cannot post until *s*'s cooldown
has elapsed and the slasher has settled through *s*'s last-served anchor, so no challenge that
was in-flight or within the window for *s* is escaped — it has already resolved (on bonded
collateral) or the drop simply cannot verify yet. This is the exact per-shard analogue of the
`Unbond` cooldown, applied to the one dropped shard. **Bounded forgiveness carries
(confirmed at source 2026-07-15):** the slash scheduler challenges *currently-held* shards on
the serve-credit bit (`process_archival_slash_for_epoch` iterates `held_shard_ids`), and the
exit forgiveness applies only once the drop *connects* — so "stop serving, hold, never drop"
keeps being slashed for non-service (the gap is capped at one cooldown, the persona is pushed
to actually drop). **Re-coverage keys on serve-credit, not holdings (confirmed):**
`r_market_count` skips `!serve_credit`, so a held-but-unserved shard is not counted as
covered — grace-tail's immediate-shed-vs-precondition choice does not delay re-seeding.

*(Superseded framing: the earlier Pin 2/3 wording described drop-then-cool — the shard leaves
holdings immediately with the `FLOOR` withheld into a per-shard cooldown that "stays
slashable." That is the same fossil as the `Unbond` "stays slashable" language; the operative
model is grace-tail above. Gate-4 §4.4 is aligned.)*

### Pin 4 — mutable-holdings serve-credit reconciliation (the consensus-read fix)

With immutable holdings, "does `P` hold shard *s* now?" was a sound proxy for "did `P` hold
*s* at `at_height`?" — so reads keyed on tip holdings (e.g.
`BlockchainLMDB::has_archival_bond_shard(p_id, s, at_height)`) ignored `at_height`. **Under
mutable holdings this proxy is invalid:** `P` may have served *s*, dropped it, or added it
between `at_height` and tip.

**Reconciliation principle (gate-4 §4.4 safety, promoted to a read rule):** serve-credit,
challenge-eligibility, and `work_P(E)` accounting read the **immutable per-`(P,s,E)`
retention bits** (gate-2 ground truth) and the `bond_event_log` membership intervals — **not**
the current `holdings` descriptor. The descriptor answers "current membership / current floor /
current serve obligation"; the bits answer "did `P` serve *s* in epoch `E`." Any read that
needs the historical answer must consult bits/intervals, not tip holdings.

**Action item:** `has_archival_bond_shard` (and any sibling tip-holdings read used for a
historical question) must either (a) take and honor `at_height` against the
`bond_event_log`/retention bits, or (b) be restricted by name/contract to current-membership
questions only, with historical callers rerouted to the bits. Resolved as part of the
`shekyl-archival-retention` connect-path work (FOLLOWUPS V3.0); flagged in
`src/blockchain_db/lmdb/db_lmdb.cpp`.

### Pin 5 — added-shard counting + sim dependency

- **Per-shard `E_add + 1`.** A shard added mid-life is counted/claimable for that shard from
  `E_add + 1` (the per-shard analogue of R1b's `E_join + 1`); the partial add epoch is
  forfeited for *s*. The record-level `E_join` is unchanged. This keeps "counted ⟺ claimable
  ⟺ shard present at E-close + good_standing" deterministic per shard.
- **Sim is a pre-seal dependency.** The sim modeled bond churn as frictionless per-epoch
  acquire/drop. Pins 2–3 make real mobility **age-stratified** (cooldown + `bond_duration`
  worst on the deep tail, where the +1 deep-tail replica margin lives). The reconciliation
  must model friction age-stratified — not re-tune a flat seating cost to a network average,
  which stays structurally optimistic on the binding deep-tail constraint. Gates the
  genesis-seal redundancy-floor re-derivation (Step 3; `STAKER_ARCHIVAL_SIM.md` §*steady-state
  frame* item 6).

### P2B-7 exit

- [x] FSM transition edges + actions for add/drop (above).
- [x] Friction semantics pinned: per-shard cooldown (Pin 2), slashable-when (Pin 3),
  drop-last-shard rejected (Pin 1).
- [x] Mutable-holdings serve-credit read rule pinned (Pin 4); `has_archival_bond_shard`
  flagged for the connect-path work.
- [x] **Per-shard `E_add + 1`** verify/connect rule landed in `shekyl-archival-retention`
  (gate-4 connect paths, FOLLOWUPS V3.0). As of 2026-07-13 the
  `HoldingsUpdate` add/drop and `Unbond` verify+connect+pop paths are **landed and wired**
  (`bond_post.rs` / `bond_connect.rs` + the C++ dispatch via `shekyl-ffi`); the record v6
  `shard_add_epochs` substrate carries the per-shard add-epoch. **Pin-4 and Pin-5 CLOSED
  (2026-07-14, PR #303 review round):** both consumption rules land in the ONE accessor both
  consumers bottom out in — `archival_bond_holds_shard(P, s, at_height)` now bounds a tip-held
  compact shard below by its v6 add-epoch (held only in epochs strictly after `E_add`; the
  slash-log reconstruction honors the row's journaled add-epoch the same way), so serve-credit
  acceptance (holds-at-`h_fire` gate) and challenge eligibility (`archival_challenge_failed_at_height`)
  enforce `E ≥ E_add + 1` symmetrically with no second predicate to drift: the partial add
  epoch is forfeited for credit AND challenge alike (no add-epoch serve credit, no unjust
  slash for a challenge that fired before the add). A voluntarily dropped shard answers
  not-held everywhere (grace-tail keeps no drop interval — Pin 2), forfeiting the drop
  epoch's pending acceptances, the add-forfeit's symmetric twin. What **remains open** here
  is `Rebond` verify+connect.
- [x] **Age-stratified sim reconciliation (Step 3) — DONE; seal cleared.**
  [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §L18 (R-3 reconciliation, 2026-06-16):
  **`HoldingsUpdate` is sealable at genesis with `RELEASE_COOLDOWN = 2` and no change to
  `r_target_deep`.** Binding seal number `committed_deep_under = 0.0138` (< 0.10); hold-the-floor
  `oldest_min_committed = 6` (`oldest_margin ≥ 0`); `sole_source = 0` on the primary `lag0`
  channel; committed floor survives `lag2` stress; not on a cliff at `c2`.
  **Adversarial read confirmed (2026-07-12, `fsm/l18-age-stratified-review`):** this clears P2B-7
  Pin 5's *"age-stratified, not a re-tuned flat scalar"* bar — the friction is **flat freeze,
  age-stratified harm** (Faithfulness pin 1: the frozen amount is flat `ARCHIVAL_BOND_FLOOR` per
  §8.1, *not* age-scaled; the age-stratification lives in the `bond_duration(age)` drop-lock
  incidence + thinnest-tail coverage, `agent.rs:277` / `model.rs:417`, not the frozen magnitude —
  the earlier "flat" tells were the correctly-flat bond *amount*, not the friction). The seal-arm
  is consensus-faithful (`bond_age_scale = 0`, matching `bonded_total == bond_floor`).
  **Residuals (not the reconciliation — named reopen/carry):** (1) **numerics provisional** — the
  age-scaled-duration *shape* is sealed but `BOND_DURATION_{BASE,AGE_SCALE}` are post-testnet
  `fetch_latency_per_unit` (saturates `scale 4 ≡ 8`, calibration-insensitive in `[2,8]`);
  (2) **no-cushion reopen** — the `+1` is fully consumed with no emergent slack (findings 4/6), so
  reopen triggers on *any* new deep-band friction, named live candidates incl. **(c) the Gate-6
  GF-4/GF-7 recurring rebond/unbond surface** (`ARCHIVAL_FIREWALL_GATE6.md` §12 — the exit-seam
  frictions can consume this margin) and a `RELEASE_COOLDOWN` rise past ~3.
  **Gate-6 cross-link:** the §L18 routed residual — a **wallet-conformance guard that warns/refuses
  a `HoldingsUpdate` drop whose freed capital is redeployed within the cooldown** — is a
  Gate-6-class safe-by-default (the standoff-draw conformance posture); it belongs with the F-D2/F-D3
  drain-event work (`ARCHIVAL_FIREWALL_GATE6.md` §12.4/§12.5), not the consensus floor.

---

## P2B-8 — Verify/connect design questions (pinned pre-impl, 2026-07-12)

**Why.** The bond-FSM verify/connect is **JoinMarket-only** at source (`bond_post.rs`
`verify_join_market_bond_post`; the wire carries all four `post_kind`s but verify rejects the other
three at genesis). Building `Rebond` / `Unbond` / `HoldingsUpdate` verify+connect is the real
seal-blocking work (the age-stratified sim reconciliation is **done** — §L18 sealable at genesis;
P2B-7 exit). Four questions the specs left thin are pinned here so the impl lands M1-clean
(arm the trigger before the identifier exists). Verify contract per `post_kind`: gate-4 §3.5 (order),
§3.2 (credit/debit terms), §4.1 (record shape). Verify/connect logic is **Rust-native**
(`shekyl-archival-retention`), C++ daemon thin-glue + FFI; every connect path gets a pop twin (§5).

### Q1 — Per-shard release-cooldown anchor (`HoldingsUpdate` drop) — **RESOLVED, no new field**

**Question.** P2B-7 Pin 2's per-shard cooldown is measured from *shard `s`'s* last-served epoch, but
§4.1 stores only a **record-level** `last_served_epoch`. Where does the per-shard anchor come from?

**Pin (source-grounded).** **Derive it — no per-shard stored field.** The serve-credit table is keyed
**`P_id[32] ‖ BE64(shard_id) ‖ BE64(settlement_epoch)`** — a big-endian composite whose byte-sort *is*
`(P_id, shard, epoch)` ascending (`serve_credit_decisions.rs:58-62`; BE is load-bearing for LMDB sort
order, `shekyl_types.h:405`, SCE audit). So *shard `s`'s last-served epoch* = the max `E` carrying a
bit = a single **reverse-cursor seek** over the `P_id ‖ BE64(shard)` prefix (`MDB_SET_RANGE` to
`‖ BE64(u64::MAX)`, one `MDB_PREV`; guard the "no bit for `s`" empty case → shard never served, drop
cooldown anchors at its add epoch). At drop **connect**, capture that value into the **`bond_event_log`
drop interval** — Pin 2 already makes the cooldown a `bond_event_log` predicate — fixing the anchor at
drop time: reorg-clean (pops with the log), no mutable per-shard field to desync. Pin 3
(slashable-through-cooldown) reads the same interval.

### Q2 — Record-level `Unbond` cooldown anchor — **RESOLVED: derive, drop the §4.1 field**

**Question.** §4.1 stores `last_served_epoch: Option<u64>` for the whole-record `Unbond` cooldown.
Store-and-maintain, or derive?

**Pin (source-confirmed).** **Derive; drop the field.** Verified at source that the record-level
`last_served_epoch` has **exactly one consumer** — the `Unbond` release cooldown (gate-4 §4.1 line
399 / §4.3); the emission-leg mention (`REWARD_EMISSION_LEG.md:534`) only *lists* it as a gate-4-owned
field, it does not read it. With no other consumer, a maintained field only adds pop-symmetry surface
and a desync risk against the serve-credit table (the single source of truth). So at `Unbond` verify,
derive whole-record last-served = **max over the record's current shards** of the Q1 per-shard value
(O(#shards) reverse-cursor seeks; `Unbond` is once-per-record, lean year-30 ≈ 60 shards). **§4.1
amendment (drop the field) routed to gate-4.** *Alternative held (rule-21):* keep an `O(1)`-maintained
field with a pop twin only if the O(#shards) `Unbond`-time seek is ever shown to bind.

### Q3 — `bond_duration(age)` is a consensus gate ⇒ genesis-frozen, not post-genesis tunable — **RESOLVED**

**Question.** Drop-eligibility (Pin 3, gate-4 §3.4: "before the horizon elapses, the shard is ineligible
for voluntary drop") is **consensus-visible verify logic**, but `BOND_DURATION_{BASE,AGE_SCALE}` are
"provisional pending testnet."

**Pin.** Because it gates a consensus verify decision, `bond_duration` is **frozen at genesis like any
consensus constant**. The "provisional / drift within `scale ∈ [2,8]`" clause
([`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §1 fn.1) is a **pre-genesis calibration
window** (testnet `fetch_latency_per_unit` closes it before seal), **not** a post-genesis tunable — a
post-genesis change is a hard fork. Resolves the "amends this table only" vs "consensus gate" tension:
the amend window is *pre-seal*. The impl reads the **generated** consensus constant (never a hardcode),
and the drop-eligibility check is `current_epoch − shard_add_epoch ≥ bond_duration(age)`.

### Q4 — `Rebond` precondition + recovery path — **RESOLVED**

**Question.** §3.4:319 gives the `Rebond` precondition as `good_standing == false` (post-slash);
§3.2/P2B-4 frame it as `Slashed → Bonded`. These read as disagreeing on *which* post-slash state
`Rebond` recovers, and the partial-slash recovery path was unstated.

**Resolved at source — and this corrects the earlier P2B-8 lean.** The wire settles it: the bond-post
vin carries `holdings: HoldingsDescriptor` for **every** `post_kind` (§3.4 line 237 / §3.4.1 layout),
and `bond_spend_pk` **only** for `JoinMarket` (§3.4:234 — `Rebond` reuses the record's committed one).
(That last clause is the **wire-field coupling**, not an auth pin: the record *keeps* the join-time
`bond_spend_pk` for future debits; `Rebond`'s own pqc auth is the identity key per the bullet below
and gate-4 §3.4 — misread once, clarified 2026-07-14, P2B-9 Pin 4.)

- **Precondition is `good_standing == false`** (§3.4, authoritative — it supersedes the FSM-table
  "`Slashed` only" simplification). `Rebond` recovers **both** partial slash (record stays `Bonded`,
  `good_standing==false`, holdings reduced with floor re-established — §4.2 step 3) **and** terminal
  slash (`Slashed`, `bonded_total==0`). **The earlier lean ("partial slash recovers via `HoldingsUpdate`
  add") is withdrawn:** `HoldingsUpdate` add is *voluntary growth requiring `good_standing == true`*, so
  it cannot fire while `good_standing==false` — `Rebond` is the only recovery.
- **`Rebond` re-specifies holdings** (the vin carries them; `post ⊇ current`, non-empty — P2B-9
  Pin 1) and credits `bonded_total` to `bond_floor(holdings)` (floor-equality, §3.5 step 4; the
  credit is `|added|·FLOOR`, **zero for the common standing-only reinstatement** — P2B-9 Pin 2;
  auth = identity `P_pubkey`, credit path
  `bond_debit==0`, §3.4). Effect: floor re-established + **`good_standing → true`** (re-enables emit-new,
  emission §6.5) + re-bond interval (F3). **Record preserved:** reuses the existing `P_canonical_id`,
  committed `bond_spend_pk`, `claimed_epochs`, `join_market_height` — distinct from `JoinMarket` (new
  record + commits `bond_spend_pk`).

**Grace-window slash-evasion — RESOLVED by the landed timing + mechanism (traced 2026-07-12).** The
concern was whether `Rebond` during the grace window could cancel a *pending* slash (a `T-A15b`-class
evasion). It cannot, on **two independent grounds**:

1. **The slash is bit-gated and fires at `H_slash_deadline`** (`= H_close + CHALLENGE_RESOLUTION_BLOCKS`,
   gate-2 §6; landed `process_archival_slash_at_height`), keyed on the *serve-credit bit*, **not** on
   `good_standing`. `Rebond` writes no bit, so the slash lands at `H_slash_deadline` regardless.
2. **`Rebond` is structurally ineligible during grace.** Good-standing is **not a mutable flag** — it is
   **`good_through(P, E)`**, a pure function of `bad_intervals` (`consensus_state.rs:81-112`;
   `market_member_at_epoch` *is* `good_through`). A **slash writes an open bad interval**
   `[E_slash, u64::MAX)` **at `H_slash_deadline`** (post-grace); **`Rebond` closes it**
   (`end_exclusive = E_rebond + 1`, P2B-9 Pin 3). During grace there is **no bad interval**, so
   `good_through` is `true` and there is nothing to recover — a mid-grace `Rebond` is
   **unrepresentable**, not merely guarded.

**Consequent impl pins:** (i) `good_standing` is a **derived view** of `good_through` / `bad_intervals`,
**not** a stored authority (same derive-don't-store answer as Q2) — the §4.1 field is a cache at most;
the operative `Rebond` precondition is **"an open bad interval exists."** (ii) `Rebond`'s effect on the
interval log is to **close the open bad interval** — `end_exclusive = E_rebond + 1`, restoring
`good_through` from `E_rebond + 1` (amended from `E_rebond` by P2B-9 Pin 3, ratified 2026-07-14: the
partial rebond epoch is forfeited in both directions, the Pin-5 `E_add + 1` mirror). (iii) P2B-4's
"grace-window `good_standing = false`" wording is imprecise — during
grace `good_through` is `true`; "slash pending" is a gate-2 timeline condition, not a bad interval.

### P2B-8 exit

- [x] Q1 per-shard cooldown anchor — derive via BE-key reverse cursor, capture in `bond_event_log`.
- [x] Q2 record-level `Unbond` anchor — derive (sole consumer confirmed); drop the §4.1 field.
- [x] Q3 `bond_duration` genesis-freeze posture — pre-seal calibration only.
- [x] Q4 `Rebond` — precondition (`good_standing==false` = open bad interval, both slash cases),
  holdings-re-spec, record-preservation, **and** the grace-window slash-evasion — all resolved (slash
  bit-gated at `H_slash_deadline` + `Rebond` structurally ineligible during grace; `consensus_state.rs:81-112`).

**Design round CLOSED — all four resolved.** Recurring theme: **derive from the landed source of truth,
don't add a mutable stored field** — Q1/Q2 derive from the serve-credit table, Q4's `good_standing`
derives from `bad_intervals`/`good_through`. One forward doc-amendment (not a blocker): drop the §4.1
`last_served_epoch` field (gate-4, Q2). The impl surface is fully pinned; **`Unbond` → `HoldingsUpdate`
→ `Rebond`** all clear to build.

**Implementation locus (rule 20 — Rust-first).** All bond-FSM verify/connect logic — including the
**slash-apply body** (write the open `bad_interval`, `bond_debit` the `bonded_total`, remove the shard)
that the C++ `process_archival_slash_at_height` currently **stubs** — lands in **`shekyl-archival-retention`
(Rust)**, driven over the FFI from the C++ connect site (which owns the LMDB write txn). Push the FFI
boundary as needed; do **not** build this in C++ to rip it out at the Rust cutover. LMDB schema
(tables/keys) is the standing C++ exception.

---

## P2B-9 — `Rebond` reinstatement pins (ratified 2026-07-14; not a design round)

P2B-8 Q4 resolved `Rebond`'s semantics; these pins settle the remaining gates found while
grounding the build. The only two that needed judgment — the re-spec shape and the credit
equation — both fall out of one operating concept, ratified 2026-07-14:

**`Rebond` is reinstatement, not re-entry.** A slash is a bounded penalty — burn one `FLOOR`,
remove the failed shard, impose a zero-earning bad-standing gap — not a termination. `Rebond`
is the primitive that lets a persona pay that penalty and resume **in place**: same
`P_canonical_id`, same remaining shards, same add-epochs, same backlog. The "it's just
unbond + fresh bond" intuition breaks three ways: (1) a **terminal slash has nothing to
unbond** (`bonded_total == 0`; the only way out of `Slashed` is topping collateral back up);
(2) unbond+rejoin **annihilates exactly what `Rebond` preserves** — identity, tenure
(add-epochs), and the scarce-shard position the market would take during the
cooldown+exit+rejoin window; (3) **proportionality is what the seal needs** — if every slash
forced exit + re-acquisition, one missed challenge would churn a deep-shard holder's whole
position out of the tail, the exact instability `bond_duration` exists to prevent. A slash
costs the one shard + the burned `FLOOR` + the gap, never the portfolio + tenure + identity.

### Pin 1 — re-spec shape: `post ⊇ current` (sets), non-empty

Reinstatement, not restructuring. Floor-equality + credit-only does **not** force growth — a
**swap** (drop K shards, add K different ones, `credit = 0`) satisfies both, so without the
superset constraint a persona could deliberately no-show one challenge (cost: one burned
`FLOOR` + the gap) and shed the **carried** shards past `HU`-drop's gates (retention horizon,
per-shard cooldown, slash settlement) in one tx. `post ⊇ current` closes exactly that: you
cannot get slashed on `S1` and use the reinstatement to also dump `S2`/`S3`. Shedding stays
`HU`-drop's gated job.

**Coverage boundary (corrected 2026-07-14 — the original "you cannot get slashed to escape a
retention commitment" rationale was wrong at source).** The superset does **not** cover the
slashed shard itself: `apply_archival_slash_one` erases it from `held_shard_ids` (+ its
coupled add-epoch), so `current` at `Rebond` time already excludes it — re-acquiring is
optional. **Slash-to-shed of the slashed shard is priced, not prevented**, three layers deep:
(1) the burn destroys exactly the `FLOOR` the shed would free; (2) the bad-standing gap
zeroes the **whole portfolio's** serve-credit through `E_rebond` (standing resumes
`E_rebond + 1`, Pin 3); (3) a re-acquisition takes `add_epoch = E_rebond` (Pin 7), so its
`ShardAgeAtAdd` is older and its `bond_duration` **longer** than the commitment escaped —
the ADD-side "self-harm, not an attack" shape. **Rule-21 reopen:** this pricing rests on the
slash **burning** the `FLOOR`. If slash economics ever change to return collateral (in any
form), slash-to-shed opens as a real dodge that neither Pin 1 nor the burn prices — reopen
the re-spec shape (e.g., require re-acquisition or forfeit) at that boundary.

Non-empty post (`ShardSetCompactEmpty`
reuse): a terminal-slash record rebonding to `∅` at credit 0 would be a zombie (good standing,
no shards, no balance; `HU`-add rejects `RecordNotBonded`, `Unbond` rejects `NothingToUnbond`).
Under the superset pin the diff is an **added-set**, so the landed `rebuild_shard_add_epochs`
applies directly.

**Forward question (routed to the R-3 / §L18 reconciliation track — a question, not a
finding):** because abandoning a slashed shard is priced at one `FLOOR` + the portfolio-wide
gap, effective retention is `min(bond_duration, willingness-to-burn-a-FLOOR)` — rational for
an uneconomic shard once storage cost × remaining lock exceeds the `FLOOR`. Believed to be
the designed pressure-release (Rebond exists precisely so abandonment doesn't kill the
persona), but the seal rests on `bond_duration` holding deep capital: confirm the sim's
actors can take the priced valve rather than treating the horizon as absolute.

### Pin 2 — credit equation: `bond_credit == bond_floor(post) − bonded_total` (zero legal, common)

**Amends gate-4's "`bond_credit` restores `== bond_floor`" (it predates the landed slash
shape).** `apply_archival_slash_one` burns one `FLOOR` **and** removes the shard atomically
(demotion: burns the CT floor, clears to compact-empty), so every post-slash record still
satisfies `bonded_total == bond_floor(holdings)` — there is **no deficit to restore**.
`Rebond` restores **standing**, not collateral; credit is owed only for growth:
`bond_credit == bond_floor(post) − record.bonded_total == |added|·FLOOR ≥ 0` — zero for the
common standing-only reinstatement, the full floor after terminal slash (`bonded_total == 0`).
KAT owed: a zero-credit vin through CT-balance.

### Pin 3 — interval close: `end_exclusive = E_rebond + 1` (amends the Q4(ii) / gate-4 §4.1 pin)

The closed interval is `[E_slash, E_rebond + 1)`: bad through `E_rebond` **inclusive**;
standing, serve-credit, and emit-new all resume at `E_rebond + 1`. The partial rebond epoch is
forfeited in **both directions** — no serve credit is earnable in it (gate step 5 rejects) and
no challenge fired in it can slash (deadline processing reads `good_through(E_rebond) = false`)
— the exact mirror of Pin-5's `E_add + 1` partial-epoch rule. This kills the reslash edge the
`E_rebond` close left open (a challenge fired during bad standing — unservable all epoch —
becoming slashable at its deadline once standing flipped), and carried shards resume together
with added shards (whose `add_epoch = E_rebond` makes them countable from `E_rebond + 1`).

### Pin 4 — auth: identity key, credit path; no selector change

Q4:640's "`Rebond` reuses the record's committed one" is the **wire-field coupling** sentence
(only `JoinMarket` carries `bond_spend_pk`; `Rebond` doesn't re-commit — the record keeps the
join-time key for future debits), **not** an auth pin. The auth pin is Q4's own bullet
(`auth = identity P_pubkey, credit path bond_debit==0`) and gate-4 §3.4:306 agrees. The landed
GF-1 selector (`bond_debit == 0` → identity) already routes `Rebond` correctly: the committed
key protects value-**out**; a credit brings value in from self-authorizing `txin_to_key`
inputs, and the bond-vin signature only proves control of `P_canonical_id`. (An
"establishes→identity / operates→committed" reframe was considered and rejected 2026-07-14: it
would invert that rationale and silently flip landed `HU`-add.)

### Pin 5 — ≤ 1 open bad interval (the same-epoch coalescing fix; consensus-halt vector)

**Landed defect, found grounding this round:** `challenge_fire_height` always fires per
(P, shard, epoch), `CHALLENGES_PER_EPOCH = 1`, and the per-epoch slash pass iterates a
**stale** pre-scan record copy — so an offline N-shard record fails all N challenges in one
epoch and appends **N identical open intervals** `[E, MAX)`. With `MAX_HOLDINGS_SHARDS = 4096`
against `kMaxBadIntervals = 256`, the 257th append throws in `ArchivalBondValue::encode`
**inside the block-connect slash hook → deterministic consensus freeze**, reachable by
accident (a large provider offline one epoch). Cross-epoch accumulation is already blocked
(`good_through` fails while any open interval exists), so multiplicity is same-epoch only.
**Fix (commit 1 of the `Rebond` PR): append the open interval only when none exists.**
Apply-side only — the landed revert's `remove_if` strips every matching open interval on the
first same-epoch row and no-ops on the rest, so pop symmetry holds with no schema bump. This
establishes **≤ 1 open interval** as a machine-checkable invariant, which is what makes
"`Rebond` closes *the* open interval" well-defined; the `Rebond` fold belts on multiplicity
(loud corruption detector, not a tolerated state). The fix lands at the C++ slash-apply site
(a bug fix to landed code, the file's idiom) and migrates with the slash body at its pinned
Rust cutover (P2B-8 implementation locus).

### Pin 6 — interval-cap headroom: verify requires `bad_intervals.size() ≤ 254`

`Rebond` re-arms slashability, so it must guarantee the log can absorb what follows: one slot
reserved for the next slash **and** one for `Unbond`'s clean interval-close, so **exit is
always reachable** — a persona can never wedge both doors shut. At 255 the record's only
remaining path is `Unbond`. Same `INTERVAL_LOG_FULL` shape as the landed `Unbond` guard, one
slot stricter.

### Pin 7 — add-epochs: carried keep theirs; added take `E_rebond`

Forced by the landed `holds_shard` reconstruction ("held at tip ⇒ held strictly after the
shard's v6 add-epoch"): a re-specified shard carrying its original add-epoch would falsely
answer "held" across the bad-standing gap. Carried (still-held) shards keep their add-epochs;
every shard added at `Rebond` — including a re-acquired slashed shard, and everything after a
terminal slash — takes `E_rebond`. Tenure restarts for added shards (horizons re-arm — the
concept working, not a trap).

### Pin 8 — kind: `ShardSetCompact` only; demoted foundation reinstates as a normal market record

The vin's holdings kind must be `ShardSetCompact`; a `CompleteTree` record at `Rebond` verify
is unrepresentable (demotion flips the kind atomically with the interval append) — belt-reject
anyway. A demoted-then-rebonded foundation record enters the market as a **normal compact
participant by construction** (`FOUNDATION_EXCLUDED_FROM_MARKET` keys on the current
`CompleteTree` kind) — reinstatement is into the normal market. Re-promotion to `CompleteTree`
is **rejected now** (rule 21): it would be a separate deliberate consensus act, not a `Rebond`
side-effect; reopen only against a real re-promotion need.

### Impl surface (mechanical reuse of the landed Unbond/HU patterns)

Verify + connect/pop folds in `shekyl-archival-retention`; FFI entry points (shared
`BOND_POST` error space from code 37, a new `REBOND_APPLY` apply family); C++ dispatch on the
credit arm (identity-key pin already generic); a new height-keyed pre-image journal
(`bonded_total`, shard ids, add-epochs, the closed interval's index + pre-image) whose pop
re-opens `end_exclusive` to `MAX` byte-exactly; slash-revert-first pop ordering; per-post live
counter threading. KATs: zero-credit CT-balance, superset/swap rejection, terminal + partial
reinstatement connect/pop round-trips through the real block path, the Pin-5 coalescing
regression (multi-shard same-epoch slash → one interval; halt-vector scale case), Pin-6 cap
boundary.

---

## Forward order

```text
T-A1 sim (F1 gate) → numeric cluster values → §4–§5 retool
HoldingsUpdate (P2B-7) → age-stratified sim reconciliation → genesis-seal redundancy floor
```

P2B-1, R1, R1b, custody, G4-3, **§3 FSM graph** closed. P2B-5 largely closed (gate-4 §5).
Parallel: gate-6 §2.3/§2.5 join-Market defanging; gate-2 slash trigger.

---

## Revision history

- **2026-07-14:** **HoldingsUpdate review round — Pin-4/Pin-5 closed at the shared
  accessor; the Bonded gate; fast-path belt re-keyed on the debit.** The high review
  surfaced seven correctness findings; the load-bearing three: (1) the checkpoint
  fast-path GF-1 belt keyed on `post_kind != JoinMarket` rejected every valid
  HoldingsUpdate-**add** block under fast sync (the add is a credit arm, identity-key
  authorized) — re-keyed on the GF-1 selector itself, `bond_debit > 0`; (2) the HU
  verify arms had no Bonded-state gate, so an Exited record passed every add gate
  (zero-length clean close excludes nothing from `good_through`; `bond_floor(∅) == 0`
  vacuously satisfies the floor pins) and became a JoinMarket-bypassing resurrection
  whose connect threw on the empty-pre-image journal row — a verify-valid,
  unconnectable tx (chain-stall vector); the shared verify prologue now pins Pin 1's
  `Bonded → Bonded` (`HoldingsUpdateRecordNotBonded`), with a connect-fold belt
  (`RecordNotBonded`); (3) Pin-4/Pin-5 wired (see the P2B-7 exit item). Also:
  unfrozen-at-add now fails closed to the LONGEST horizon on both corners
  (`ShardAgeAtAdd::from_add` pins `freeze ≥ H_close(add_epoch)` to age-max, matching
  the C++ missing-freeze-row sentinel — previously the same condition got 4 or 20
  epochs depending on when the freeze landed relative to the drop attempt, a 5×
  early-recycle hole vs. the §L18 seal's age-stratified friction); the drop-then-dodge
  scenario is DOCUMENTED as the ratified grace-tail bounded forgiveness (Pin 3), not a
  defect — the slash-apply FATAL's HoldingsUpdate revisit is discharged (a dropped
  shard leaves `held_shard_ids`, so the scheduler never challenges it; the unserved
  tail past the shard's settled anchor is exit-forgiven, capped at one cooldown); the
  pop-ordering comment now states the real dependency (slash revert FIRST — the slash
  journal restores the same record fields; "compose in any order" was false);
  dedup: shared C++ debit-auth pin (Unbond + HU-drop), shared Rust verify prologue +
  FFI marshal prologue, shared HU connect-writer scaffold (add/drop differ only in
  the fold).
- **2026-07-13 (f):** **GF-1 review round — every codec refuses what the binary
  codec refuses, and the enable flip completes at the block level.** The boost
  serializer now enforces the §9.11 coupling both directions (it deserialized a
  non-canonical key and silently dropped a stray one — the one codec bypassing
  the length pin the record-commit relies on), and JSON `toJsonValue` refuses at
  write what `fromJsonValue` refuses at read (a producer failure, not a consumer
  parse error). The FFI vin marshaler stops placeholdering `bond_spend_pk`:
  both verify entry points take the real bytes and the shared marshaler
  enforces the coupling (`ERR_BOND_SPEND_PK_COUPLING`, code 23) — the
  `HoldingsUpdate` arm will inherit an honest marshal. `check_archival_bond_post_input`
  gains the coupling belts for non-parse callers on BOTH arms (the Unbond arm
  had none) and runs the committed-key pin BEFORE the per-shard cursor scans and
  the FFI verify (an unauthorized attempt no longer pays the LMDB walk). The
  block-level checkpoint fast-path arm executes the swap its (d) belt named:
  under `fast_check` it re-pins the debit's pqc auth key against the record's
  committed `bond_spend_pk` (fail-closed on missing record/keyless record/missing
  auth slot) instead of blanket-rejecting every debit kind — without the swap, a
  block carrying a valid `Unbond` was rejected by every node, contradicting (e)'s
  end-to-end contract; debit-side bond posts now also feed the per-`P`
  block-unique pass (`Unbond+Unbond` pairs were unreachable before). The gate-4
  lifecycle KAT stops embedding a copy of gate-2's integration section (the copy
  had silently drifted on dev); the serve-at-`E_first` leg reads
  `gate2_serve_credit_kat_v1.json` directly.
- **2026-07-13 (e):** **GF-1 `bond_spend_pk` wire+record LANDED — the debit side
  is enabled.** The §9.11 JoinMarket-coupled field now exists in all three C++
  serializers (binary/boost/JSON, exact canonical length both directions) and
  the Rust `bond_wire` codec (coupling enforced at write/read; §3.4.1 preimage
  binds it; gate-4 KAT fixture regenerated); the v5 record commits it once at
  JoinMarket connect (v4 rejected at decode, datadir reset); and the §3.5
  step-5 selection is live as the **shared debit authorizer** (credit →
  identity key, debit → the record's committed key) — the reject→auth swap
  landed in one change with the discriminating KATs (committed key accepts:
  **Unbond verifies end-to-end**; identity/foreign/no-key all reject
  fail-closed). The wallet seam simplified (the vin carries the key;
  `wire_bond_post_input` takes it from the vin; A-1 now pins the key
  byte-for-byte between prefix input and signed vin). **`HoldingsUpdate` is
  unblocked** — its drop-path auth rides the same selection.
- **2026-07-13 (d):** **`Unbond` release-gate hardening (review round).** Added
  the slash-settlement predicate to the release verify — the scheduler's settled
  watermark (`archival_last_slash_epoch`) must reach `P`'s last-served anchor,
  closing the one-block race where the connect dispatch precedes the per-block
  slash fold; a held-but-unserved failure through the anchor is thus slashed on
  bonded collateral before the exit. This **supersedes the (c) reverse-order-pop
  assumption**: slashability ends at the `Unbond` connect (an Exited record holds
  no shards → never a slash candidate), the post-connect exit tail is
  exit-forgiven (no clawback), and the pop-order slash revert is a defensive
  belt, not a real-case dependency (`apply_archival_slash_one` now FATALs on a
  not-held shard). Also: CompleteTree cooldown anchor via the all-shards
  `P`-prefix scan (`archival_bond_all_last_served_epochs`); block-level GF-1
  fail-closed belt for the checkpoint fast path; mempool/template dedup of
  archival block-unique keys (mining-stall vector); serve-credit + `Unbond`
  same-`P` same-block deliberately allowed.

- **2026-07-12 (c):** **`Unbond` C++ dispatch wiring landed** — `add_transaction`
  Unbond arm → `apply_archival_unbond` (pre-image journal
  `m_archival_bond_unbond_log`, Rust-fold write set, per-post live-counter
  threading — KAT-armed by the two-`P`-one-block test), `pop_block` →
  `revert_archival_unbonds_at_height` (after the slash revert — a defensive
  ordering belt; see (d), which retired the earlier reverse-order-pop
  assumption), verify dispatch in
  `check_archival_bond_post_input` (Q1/Q2 anchors via the
  `archival_bond_last_served_epochs` reverse-cursor helper), and the per-`P`
  block pass marshaled beside the emission `(P,E)` pass. **Unbond txs remain
  verify-rejected fail-closed at the §3.5 step-5 debit-auth step** (rule-22 named
  blocker, gate-4 §3.5 + FOLLOWUPS): no record commits a `bond_spend_pk` — the
  §9.11 field the Rust wallet wire carries is absent from the C++ vin serializer
  and the v4 record. The GF-1 wire+record sub-increment (C++ vin field, schema
  v5 commit at JoinMarket, §3.4.1 preimage binding, debit-auth check) is the
  enable flip and the next slice before `HoldingsUpdate`.
- **2026-07-12 (b):** **`Unbond` connect fold + pop twin landed Rust-native**
  (`shekyl-archival-retention::bond_connect`, driven over
  `shekyl_archival_unbond_connect` / `shekyl_archival_unbond_pop`; C++ dispatch
  wiring is the follow-on increment). The §4.3 clean interval-close is landed as a
  **zero-length interval `[E_unbond, E_unbond)`** in the record's interval log —
  `good_through`-inert by construction (KAT-pinned), records the exit epoch for the
  later `W`-lapse / `p_slot`-burn step, no schema change (gate-4 §4.1 note). Q2's
  forward amendment executed (gate-4 §4.1 `last_served_epoch` dropped). Verify
  gained the `IntervalLogFull` belt (a tx whose connect could not append the close
  never verifies — halt-vector foreclosure). Review round, same increment: the
  marker's storage half KAT-pinned end-to-end (codec/LMDB/`good_through`,
  `archival_substrate_lmdb.unbond_clean_close_marker_round_trips`; no path anywhere
  asserts `start < end`), `kMaxBadIntervals` pinned genesis-frozen (verify validity
  keys on it), and the block-level pass's **decision function landed**
  (`bond_post_block_unique`, keyed on `P` alone, reject-not-serialize — covers the
  whole same-`P` same-block class; §4.5 conservation is not a backstop). Named
  wiring obligations: marshal that pass at the block-verify site, pre-image journal
  table + FATAL mapping at the connect site.
- **2026-07-14:** **P2B-9 — `Rebond` reinstatement pins ratified** (not a design round — Q4
  resolved the semantics; these settle the build gates). Operating concept: **reinstatement,
  not re-entry** — a slash is a bounded penalty (one shard + one burned `FLOOR` + the gap),
  `Rebond` resumes in place (same `P_canonical_id`, tenure, backlog). Pins: `post ⊇ current`
  non-empty (closes swap-shedding of **carried** shards; the slashed shard's abandonment is
  **priced** — one burned `FLOOR` + the portfolio-wide gap — not prevented, with a rule-21
  reopen if slash economics ever return collateral; corrected 2026-07-14, the original
  "retention-escape" rationale was wrong at source); credit `== |added|·FLOOR ≥ 0`
  (zero legal/common — the landed slash preserves floor-equality; amends gate-4 "restores
  `== bond_floor`"); interval close `end_exclusive = E_rebond + 1` (partial-epoch symmetry
  with Pin-5 `E_add+1`; amends Q4(ii)/gate-4 §4.1); auth = identity key on the landed selector
  (Q4:640 clarified as wire-coupling, not auth; "operates→committed" reframe rejected);
  **≤ 1 open interval** via same-epoch slash coalescing (fixes a reachable consensus-halt
  vector: N same-epoch appends vs the 256-interval codec cap — commit 1 of the `Rebond` PR);
  cap headroom `≤ 254` at verify (exit always reachable); carried shards keep add-epochs,
  added take `E_rebond`; `ShardSetCompact` only, demoted foundation reinstates as a normal
  market record (re-promotion rule-21-rejected).
- **2026-07-12:** **P2B-8 — verify/connect design questions pinned pre-impl.** Q1 (per-shard
  `HoldingsUpdate`-drop cooldown anchor) resolved with **no new field** — derive shard `s`'s
  last-served via a reverse-cursor seek over the BE composite serve-credit key
  (`P_id ‖ BE64(shard) ‖ BE64(epoch)`), captured into the `bond_event_log` drop interval at connect.
  Q3 (`bond_duration` consensus gate) resolved — genesis-frozen; the provisional-numeric window is
  pre-seal calibration only. Q2 resolved — the record-level `last_served_epoch`'s sole consumer is the
  `Unbond` cooldown, so derive (drop the §4.1 field). Q4 fully resolved: at the wire (precondition
  `good_standing==false` covers both slash cases; `Rebond` re-specifies holdings on the existing
  record; earlier partial-slash-via-`HoldingsUpdate` lean withdrawn) **and** the grace-window
  slash-evasion — traced closed: the slash is bit-gated at `H_slash_deadline` and `good_standing` is
  `good_through(bad_intervals)` (`consensus_state.rs:81-112`), so no bad interval exists during grace
  and `Rebond` is structurally ineligible there. Design round CLOSED (all four; theme: derive from the
  landed source of truth, don't store). Rust-first locus pinned (rule 20): the slash-apply body the C++
  `process_archival_slash_at_height` stubs lands in `shekyl-archival-retention`, not C++. Also (same
  session): P2B-7 exit reconciled to the §L18 sealed
  verdict; the "`P` rotation" fossil killed at the P2B-1 root (backing "rotation" is not a mechanism
  — no `backing_outputs` field, consensus rule dropped; pseudonym "rotation" is unlink-relink →
  correlation, T-A1/S-5). Docs-only.
- **2026-06-15:** P2B-7 — `HoldingsUpdate` promoted deferred-V3.1 → **V3.0 (genesis)**. FSM
  transition edges + actions for voluntary add/drop; friction pins (per-shard release
  cooldown, slashable-through-cooldown anti-dodge, drop-last-shard rejected); mutable-holdings
  serve-credit read rule (retention bits / `bond_event_log` are ground truth, not tip
  holdings — `has_archival_bond_shard`/`at_height` flagged); per-shard `E_add+1` and
  age-stratified sim reconciliation carried as seal-gating opens. T-A15b foreclosed by Pin 3.
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
