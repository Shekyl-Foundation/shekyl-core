# Phase 2b — `StakeState` FSM retool (rebased substrate)

**Status:** **P2B-1 opened (2026-06-07).** Master finding + cascade dispositions below.
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

## P2B-1 — Re-home instance key on `P_canonical_id` (MASTER — opened)

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

### Open question (for reviewer)

Keep a wallet-local **opaque handle** (`PHandle`) distinct from `P_canonical_id` for UI/RPC?
**Proposed no** — pre-genesis, extra indirection buys nothing if consensus id is already public.
Reopen if GUI needs stable row ids across in-flight key rotation before first emission anchors.

### P2B-1 exit

- [x] Disposition written.
- [ ] Reviewer confirms primary key = `P_canonical_id`, backing demoted to rotatable field.
- [ ] §3.3.3 rewritten as §3.3.3-bis (archival id) or merged into §9 cross-ref.

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

## P2B-4 — State collapse (fewer states, not re-fielded)

### Finding

§3.1 "states unchanged in shape" is false. `Locked` / `Accruing` / `Claimable` encode
tier-lock + confidential yield — **deleted subsystem**. Archival: serve continuously while
good-standing; reward is per-epoch **work**, claimed by **emission** action.

### Proposed lifecycle (pressure-tested)

**Persistent lifecycle states (4):**

| State | Meaning |
|-------|---------|
| `AdmissionPending` | `P` derived; off-chain announce/backing in flight; no bond record yet |
| `Bonded` | Bond record exists; serving / eligible for work while good-standing |
| `Slashed` | Bond gone or `good_standing` false; re-bond path per foundation §3.2 |
| `Exited` | Terminal drain complete; instance archived |

**Generic tx-broadcast substates** (reuse pattern from §3.1): `PendingBroadcast` /
`Unconfirmed` on **actions** (stake-in transfer, emission vin, drain) — attach to the
**action**, not a parallel yield-state machine.

**Actions (not states):**

- **Fund admission** — ordinary transfer to `P`
- **Emit rewards** — `txin_archival_reward_emission` (batch ≤15 epochs)
- **Rotate backing** — membership-only spend + new backing UTXO (same `P_canonical_id`)
- **Exit / drain** — decorrelated `P`→principal transfer

**Deleted as states:** `Locked`, `Accruing`, `Claimable`, `FullyUnstaked` (split into
`Slashed` / `Exited` + claim action), claim-as-state.

**§8.3 Accruing/Claimable split:** moot — was lock-window UX; close in retool, note in §8.3
amendment.

### Debate flag

Is `AdmissionPending` distinct from `Bonded`, or is pre-first-emission purely off-chain with
no wallet state? **Lean:** keep one setup state until first emission anchors bond record —
matches registration fusion.

---

## P2B-5 — Reorg simplifies to re-read

### Finding

§5.2 nullifier replay dies with nullifier dedup. Emission: `pop_block` reverts
`claimed_settlement_epochs` atomically (§7.1, §8).

### Disposition

1. **Consensus:** `pop_block` reverts bond mutations + dedup in documented order (emission §8;
   archival state schema when landed).
2. **Wallet:** on reorg notification, **re-fetch `ArchivalBondRecord` for each live
   `P_canonical_id`**; refresh `claimed_epochs` cache; clear `emission_pending_epochs` for
   disconnected heights. No mask replay, no `x·G_S` intersection.
3. **Delete:** §3.3.2 reorg-stable anchor / eligible_height drain argument (tier-era).

---

## P2B-6 — Threat model re-center (last)

### Finding

§7 wargames F0 + nullifiers — both gone. Re-center on gate-6 long-lived correlation; F1
(epoch-granularity retention fingerprint vs rotation) is a first-class §7 entry.

### Disposition

**Do not rewrite §7 until P2B-1–5 land** — otherwise the wargame targets the wrong mechanism.

---

## Forward order

```text
P2B-1 (instance key) → P2B-2/3 (dedup + encoding) → P2B-4 (states) → P2B-5 (reorg) → P2B-6 (§7)
```

Parallel: Gate-6 rounds 2–5, archival consensus schema, `W` pin.

---

## Revision history

- **2026-06-07:** Initial retool disposition (P2B-0–6); P2B-1 opened for reviewer confirm.
