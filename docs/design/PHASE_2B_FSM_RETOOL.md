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
`txin_archival_bond_post` `post_kind = HoldingsUpdate`), not consensus-imposed; (2) the dropped
shard's released `FLOOR` enters a **per-shard release cooldown** rather than returning at once;
(3) the dropped collateral **stays slashable** through that cooldown so a voluntary drop cannot
dodge an in-flight challenge. Friction semantics, the slashable-when boundary, and the
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
| `Bonded` | **HoldingsUpdate drop shard** (debit `FLOOR`; **≥1 shard remains**; dropped collateral → per-shard release cooldown, stays slashable) | `Bonded` |
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
| HoldingsUpdate drop shard | `Bonded` (**≥1 shard remains**) | `post_kind = HoldingsUpdate`; `bond_debit = FLOOR`; dropped collateral enters **per-shard release cooldown** (P2B-7) and **stays slashable** through it — no drop-to-dodge. Dropping the last shard is rejected; use `Unbond` (→ `Exited`) |
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
  P2B-7 Pin 3: dropped collateral stays slashable through cooldown) + T-A17 (join
  censorship, low).
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

### Pin 2 — per-shard release cooldown (the friction)

A dropped shard's released `FLOOR` does **not** return at the drop confirm. It enters the
**per-shard release cooldown** measured from that shard's `last_served_epoch` (gate-4 §4.4,
§4.3 asymmetry table). While `P` continues serving its remaining shards in `Bonded`, the
dropped shard's collateral sits in a **`collateral-in-cooldown` sub-condition** — the same
sub-condition `Exited` carries for whole-record `Unbond`, but scoped to one shard and held
**inside `Bonded`**. It is a predicate on the bond record (`bond_event_log` drop interval +
per-shard cooldown), **not** a new FSM state. The freed capital cannot recycle into a fresh
shard until cooldown elapses; this is the deep-tail mobility friction the sim must model
age-stratified (Pin 5).

Add (top-up) carries no cooldown: `bond_credit = +FLOOR` is immediate; the new shard's
serve obligations begin at the add confirm.

### Pin 3 — slashable-when boundary (no drop-to-dodge)

The dropped shard's collateral **stays slashable through its cooldown**. A voluntary drop
must not let `P` escape a challenge that was in-flight or within the challenge window for
shard *s* at the drop height. Concretely: a `slash(P,s)` triggered by a
`challenge_failed(P,s,E)` whose deadline falls on or before the cooldown expiry **still
applies** to the cooling collateral (gate-4 §4.2 atomic write set), even though `s` is no
longer in current `holdings`. This is the exact rationale §4.3 gives for the `Unbond`
cooldown ("no pending challenge can still slash for epochs after `P` stopped serving"),
applied per-shard. Without it, `HoldingsUpdate` drop is a slash-evasion lever (T-A15b).

The **retention-commitment horizon** (`bond_duration(age)`, gate-4 §3.4/§4.3) is the
*earlier* gate: a shard younger than its horizon is **ineligible for voluntary drop at all**.
Pin 3 governs the window *after* an eligible drop is posted; the horizon governs whether the
drop may be posted.

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
- [ ] **Per-shard `E_add + 1`** verify/connect rule landed in `shekyl-archival-retention`
  (gate-4 connect paths, FOLLOWUPS V3.0). **Still open (impl):** verified at source 2026-07-12 —
  `bond_post.rs` implements `verify_join_market_bond_post` only; the wire carries all four
  `post_kind`s (`bond_wire.rs`) but verify rejects the other three at genesis (the
  `PostKindNotJoinMarket` refusal). Rebond/Unbond/HoldingsUpdate verify+connect, the per-shard `E_add + 1` rule, and
  `verify_unbond_release` (release-cooldown spendability gate) are all unbuilt.
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

- **Precondition is `good_standing == false`** (§3.4, authoritative — it supersedes the FSM-table
  "`Slashed` only" simplification). `Rebond` recovers **both** partial slash (record stays `Bonded`,
  `good_standing==false`, holdings reduced with floor re-established — §4.2 step 3) **and** terminal
  slash (`Slashed`, `bonded_total==0`). **The earlier lean ("partial slash recovers via `HoldingsUpdate`
  add") is withdrawn:** `HoldingsUpdate` add is *voluntary growth requiring `good_standing == true`*, so
  it cannot fire while `good_standing==false` — `Rebond` is the only recovery.
- **`Rebond` re-specifies holdings** (the vin carries them) and credits `bonded_total` to
  `bond_floor(holdings)` (floor-equality, §3.5 step 4; auth = identity `P_pubkey`, credit path
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
   (`end_exclusive = E_rebond`). During grace there is **no bad interval**, so `good_through` is `true`
   and there is nothing to recover — a mid-grace `Rebond` is **unrepresentable**, not merely guarded.

**Consequent impl pins:** (i) `good_standing` is a **derived view** of `good_through` / `bad_intervals`,
**not** a stored authority (same derive-don't-store answer as Q2) — the §4.1 field is a cache at most;
the operative `Rebond` precondition is **"an open bad interval exists."** (ii) `Rebond`'s effect on the
interval log is to **close the open bad interval** (`end_exclusive = E_rebond`), restoring `good_through`
from `E_rebond`. (iii) P2B-4's "grace-window `good_standing = false`" wording is imprecise — during
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

## Forward order

```text
T-A1 sim (F1 gate) → numeric cluster values → §4–§5 retool
HoldingsUpdate (P2B-7) → age-stratified sim reconciliation → genesis-seal redundancy floor
```

P2B-1, R1, R1b, custody, G4-3, **§3 FSM graph** closed. P2B-5 largely closed (gate-4 §5).
Parallel: gate-6 §2.3/§2.5 join-Market defanging; gate-2 slash trigger.

---

## Revision history

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
