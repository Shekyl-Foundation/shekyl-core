# Archival bond — gate 4 (join-Market + bond-post wire)

**Status:** **Round 0 draft (2026-06-07).** join-Market seam pinned; `txin_archival_bond_post`
wire sketch. Slash/unbond detail deferred to gate-4 follow-on rounds.

**Scope:** Consensus objects and vin wire for **bond posture** — initial **join-Market**,
**re-bond** after slash, holdings updates — **distinct** from reward **mint** (emission leg).

**Authority chain:**

| Doc | Role |
|-----|------|
| [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) | FSM edges; R1 closed (join ≠ first mint) |
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Consumer of bond record; mint + dedup only |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | `Market` membership; `R_market` / `Σwork` reads |
| [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | join-Market timing; §2.5 bond-funding hygiene |

**Out of scope here (interface only):** retention-proof construction (gate 2); emission
economics (gate 1); admission principal economics (gate 7); wallet FSM implementation.

---

## 1. Why join-Market is a separate event from first paying mint

### 1.1 Five functions — two instants

| Function | Gates | Active from | join-Market | First paying mint |
|----------|-------|-------------|-------------|-------------------|
| Locked bond posted | Ledger admission | join | yes | — |
| Gate-2 writes `(P,s,E)` retention bits | `P` serves | join | yes | — |
| `P ∈ Market` | `R_market` / `Σwork` | `E ≥ E_join` | yes | — |
| Claim eligibility | mintable epochs | `E ≥ E_join` | yes | — |
| Slash teeth | bond collateral | join | yes | — |
| Dedup + mint | `claimed_settlement_epochs` | first pay | empty at join | yes |

Rows 1–4 and slash fire at **join-Market**. Mint and dedup mutation fire at **first paying
emission** (≥ `E_join + 1` lag for work in `E_join` — §1.2).

### 1.2 Settlement lag makes bundling impossible

Emission §4.5: paying emissions for epoch `E` cite `Σwork(E)` finalized at **E-close**,
typically in **`E+1` or later**. `Σwork(E)` counts only `P' ∈ Market` at E-close (emission
§4.2; archival state invariant 2).

If `ArchivalBondRecord` is created only at first paying mint (≥ `E+1`), then at E-close
`P ∉ Market` → epoch `E` was never counted → nothing valid to claim. Retroactive Market
entry would mutate finalized `R_market(s,E)` — **forbidden**.

**Conclusion:** bond record creation (**join-Market**) must precede the first **paying**
mint by at least one settlement-epoch lag. This is consensus ordering, not a privacy
preference. See [`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) R1.

### 1.3 Anti-replica-flooding

`Market` entry without bonded collateral would let attackers register unbounded fake `P`
replicas, crater `R_market` scarcity, and drive honest reward toward zero. Bond at join
makes each counted replica cost `ARCHIVAL_BOND_FLOOR` (sim pin) and real storage (8c).
**Pre-mint bond job = `R_market` integrity**, not only post-hoc slash.

### 1.4 No pre-join consensus footprint

Gate-2 **does not write** `retention_bit(P, shard, E)` before join-Market. Bits may not
accrue for `P` without a bond record — closes state-bloat and grief vectors for
unbonded announced `P`.

---

## 2. join-Market event (genesis pin)

### 2.1 Definition

**join-Market** is the first on-chain event that:

1. Posts locked bond: `bonded_total_atomic ≥ bond_floor(holdings)`.
2. Creates `ArchivalBondRecord` keyed by `P_canonical_id` (emission §6.1).
3. Initializes `claimed_settlement_epochs` **empty**.
4. Stamps `join_market_height` and `join_settlement_epoch` (`E_join`).
5. Sets `good_standing = true` (initial posture).
6. Admits `P` to **`Market`** from this height forward.

After join, gate-2 may write retention bits; `P` is counted in `R_market` / `Σwork` for
eligible epochs; `P` may emit rewards for `E ≥ E_join` subject to lag, `W`, and dedup.

### 2.2 `E_join` boundary (R1b — genesis pin)

```text
E_join = settlement_epoch(join_market_height)
       = join_market_height / SETTLEMENT_EPOCH_BLOCKS    // integer division; emission §3
```

**Market counting and claim eligibility (consensus pin):**

```text
P ∈ Market at settlement-epoch E-close  ⇔  bond record exists ∧ E ≥ E_join
counted_in_R_market(P, shard, E)      ⇔  retention_bit ∧ good_through(E) ∧ E ≥ E_join
claimable_epoch(E) in paying emission ⇔  E ≥ E_join ∧ good_through(E) ∧ … (emission §6.5)
```

**Mid-epoch join:** join may land at any height within settlement epoch `E_join`. Gate-2
challenge scheduling (out of scope) must not grant **retrospective** retention credit for
epochs before `join_market_height`. At E-close for `E = E_join`, credit only if join
preceded the epoch's challenge close — verifier uses height-stamped join, not wallet
assertion. **No retroactive `E < E_join` counting** (invariant 2).

**First paying mint:** earliest epoch batch is `[E_join, …]` (or first epoch with passed
retention after join), emitted in settlement epoch **`≥ E_join + 1`** for work finalized at
`E_join` close (§4.5 lag).

### 2.3 Registration fusion (preserved meaning)

**Fusion** = no separate *registration transaction type* in the retired stake sense.
**Not fusion** = no on-chain anchor — join-Market **is** the registration **event**
(PHASE_2B §2.4). Off-chain announce + backing presentation still **precedes** join.

### 2.4 FSM coupling

| Wallet transition | On-chain event |
|-------------------|----------------|
| `AdmissionPending` → `Bonded` | join-Market confirm |
| First operator payout | First **paying** `txin_archival_reward_emission` in `Bonded` |
| `Bonded` → `AdmissionPending` (reorg) | join-Market block disconnected (§5) |
| `Slashed` → `Bonded` | Re-bond (§4.2) |

"Joined but not yet paid" = `Bonded` with empty `claimed_settlement_epochs` — **not** a
fifth state.

---

## 3. Wire shape — `txin_archival_bond_post` (genesis lean)

### 3.1 Disposition

| Option | Verdict |
|--------|---------|
| **(a)** Zero-mint `txin_archival_reward_emission` | Rejected — conflates bond posture with mint wire |
| **(b)** Dedicated `txin_archival_bond_post` | **Genesis lean** — one vin for join + re-bond |

Emission leg handles **mint + dedup only**; bond posture changes use this vin.

### 3.2 Transaction envelope

A bond-post transaction contains:

1. **Exactly one** `txin_archival_bond_post` (this spec).
2. **Zero or more** `txin_to_key` fee inputs (ordinary FCMP++ + key images).
3. **Forbidden:** reward mint fields; `txin_archival_reward_emission` in the same tx
   (separation of concerns — wallet may broadcast sequentially).

Bond collateral **locking** may be expressed as:

- value moved into a consensus-tracked bond pool via ordinary vins in the **same tx**, or
- attestation of locked UTXOs already controlled by `P` (gate-4 round-1 detail — must not
  bypass `bonded_total_atomic` accounting).

### 3.3 `txin_archival_bond_post` — logical fields

```text
ArchivalBondPostVin {
  P_pubkey:              HybridPublicKey,      // must match P_canonical_id derivation
  p_canonical_id:        [u8; 32],             // hint; verifier recomputes (emission §6.1)
  post_kind:             BondPostKind,         // §3.4
  holdings:              HoldingsDescriptor,   // shard set served
  bonded_total_atomic:   u64,                  // must satisfy bond_floor(holdings)
  bond_attestation:      BondAttestation,      // gate-4: proof collateral is locked/posted
  pqc_auths:             [...],                // P hybrid spend auth (gate-6 §9.6)
}

enum BondPostKind {
  JoinMarket,            // creates record; E_join stamped
  Rebond,                // after slash; restores good_standing posture
  HoldingsUpdate,        // shard add/drop with bond recalc (optional v3.1 scope)
}
```

**JoinMarket path:** reject if `ArchivalBondRecord` already exists for `P_canonical_id`.

**Rebond path:** require existing record with `good_standing == false` (post-slash);
update `bonded_total_atomic`, append re-bond event to gate-4 interval log (archival
state §3.4 F3).

### 3.4 Verify order (consensus) — bond-post tx

1. Structural — tx type, single bond vin, `P_canonical_id` recomputation matches.
2. `post_kind` preconditions — join vs re-bond vs holdings update.
3. Bond sufficiency — `bonded_total_atomic ≥ bond_floor(holdings)`.
4. Collateral attestation — locked bond matches declared total.
5. `P` hybrid signatures on vin.
6. FCMP++ balance — fee inputs only; **no mint**.

On block connect for **JoinMarket:** create `ArchivalBondRecord` (§4.1).

---

## 4. `ArchivalBondRecord` fields (gate-4 owned)

Amends emission §6.2 — emission **reads** this shape; gate 4 **writes** on bond-post and
slash paths.

```text
ArchivalBondRecord {
  P_pubkey:                  HybridPublicKey,
  holdings:                  HoldingsDescriptor,
  bonded_total_atomic:       u64,
  good_standing:             bool,
  join_market_height:        u64,       // block of JoinMarket bond-post
  join_settlement_epoch:     u64,       // E_join
  first_paying_emission_height: Option<u64>,  // set on first mint; None until then
  claimed_settlement_epochs: ClaimedEpochSet,  // emission §6.3; empty at join
  bond_event_log:            BondEventLog,     // slash / re-bond intervals (F3)
}
```

**Deprecated name:** `first_emission_height` → split into `join_market_height` +
`first_paying_emission_height`. Pre-genesis docs/code use new names only.

**`Market` predicate (consensus):**

```text
P_id ∈ Market  ⇔  ArchivalBondRecord exists for P_id
                  ∧ good_standing posture permits service (evaluated per epoch via good_through)
```

Foundation `CompleteTree` exclusion from `market_R` unchanged (E-2).

---

## 5. Reorg (`pop_block`)

On block disconnect at height `H`:

1. For each `txin_archival_bond_post` with `JoinMarket` in the block: **delete**
   `ArchivalBondRecord` iff `join_market_height == H` and no prior join at lower height.
2. For each `Rebond` / `HoldingsUpdate` in the block: revert bond record mutations in
   reverse connect order (interval log pop).
3. Revert any bond-pool / collateral state touched by bond attestations (same txn as
   block disconnect).

Emission leg §8 handles **paying emission** disconnect (dedup revert, mint undo) —
**separate** from join revert. Wallet: `Bonded` → `AdmissionPending` when (1) fires;
re-fetch record otherwise (P2B-5).

---

## 6. Gate-6 coupling (join-Market is a standing timing event)

join-Market cannot be hidden inside a mint (§1.2). Gate-6 must **defang** the event:

| Surface | Obligation |
|---------|------------|
| §2.3 Timing | Decorrelate principal funding from join-Market (delay, jitter) |
| §2.5 Bond-funding | Prefer fund-from-earnings ramp; avoid lump principal→`P`→join beacon |
| §2.4 Output | Unrelated to join; drain decorrelation remains separate |

Pin joint disposition in gate-6 Round 2+ with this doc's join event as the named anchor.

---

## 7. Rejected / deferred

| Item | Disposition |
|------|-------------|
| Bond record at first paying mint only | Rejected — violates §1.2 lag |
| Pre-join retention bits | Rejected — §1.4 |
| Zero-mint emission as join vehicle | Rejected — §3.1 (a) |
| `Bonded-not-emitted` FSM state | Rejected — empty dedup in `Bonded` |
| Slash wire bytes | Deferred — gate-4 round 1+ |
| Bond pool LMDB layout | Deferred — implement with archival state schema |

---

## 8. Open pins (gate-4 round 1)

- [ ] `BondAttestation` cryptographic shape (locked UTXO proof vs pool credit).
- [ ] `bond_floor(holdings)` formula reference to `ARCHIVAL_BOND_FLOOR` + per-shard table.
- [ ] `HoldingsUpdate` in genesis scope or V3.1 defer.
- [ ] C++ / Rust vin type registration in `rctTypes` successor.
- [ ] KAT: join → serve one epoch → paying emit in `E_join+1` integration fixture.

---

## 9. Related documents

| Doc | Relationship |
|-----|----------------|
| [`REWARD_EMISSION_LEG.md`](REWARD_EMISSION_LEG.md) | Mint consumer; §6.4+ amended for join |
| [`PHASE_2B_STAKE_LIFECYCLE.md`](PHASE_2B_STAKE_LIFECYCLE.md) | §2.4 tx legs; FSM retool target |
| [`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) | `Market`, `E_join`, no pre-join bits |
| [`ARCHIVAL_FIREWALL_GATE6.md`](ARCHIVAL_FIREWALL_GATE6.md) | Timing + bond-funding around join |
| [`FOUNDATION_GENESIS_IDENTITY_SET.md`](FOUNDATION_GENESIS_IDENTITY_SET.md) | Re-bond after slash |

---

## Revision history

- **2026-06-07:** Round 0 — join-Market seam; `txin_archival_bond_post` sketch; `E_join` pin;
  reorg; emission/FSM cross-amendments.
