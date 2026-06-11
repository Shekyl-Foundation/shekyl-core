# Archival bond — gate 4 (join-Market + bond-post wire)

**Status:** **Round 1 base (2026-06-07).** Consensus-balance custody; balance-equation
`bond_credit` / `bond_debit`; conservation law; `== bond_floor`; `Unbond`; `E_join+1`.
Numeric cluster pinned in [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md);
slash trigger interface pinned in [`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md) §6.

**Scope:** Consensus objects and vin wire for **bond posture** — **join-Market**, **re-bond**,
**clean unbond** (collateral return), holdings updates — **distinct** from reward **mint**
(emission leg).

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
| `P ∈ Market` | `R_market` / `Σwork` | `E ≥ E_join + 1` | yes | — |
| Claim eligibility | mintable epochs | `E ≥ E_join + 1` | yes | — |
| Slash teeth | bond collateral | join | yes | — |
| Dedup + mint | `claimed_settlement_epochs` | first pay | empty at join | yes |

Rows 1–4 and slash fire at **join-Market**. Mint and dedup mutation fire at **first paying
emission** (earliest claimable epoch **`E_join + 1`** — §2.2). Work in partial epoch
`E_join` is **forfeited** (deterministic boundary; no gate-2 coupling).

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

Gate-2 **does not write** `serve_credit_bit(P, shard, E)` before join-Market. Bits may not
accrue for `P` without a bond record — closes state-bloat and grief vectors for
unbonded announced `P`.

---

## 2. join-Market event (genesis pin)

### 2.1 Definition

**join-Market** is the first on-chain event that:

1. Posts locked bond: `bonded_total_atomic == bond_floor(holdings)` (§3.2, §4.1).
2. Creates `ArchivalBondRecord` keyed by `P_canonical_id` (emission §6.1).
3. Initializes `claimed_settlement_epochs` **empty**.
4. Stamps `join_market_height` and `join_settlement_epoch` (`E_join`).
5. Sets `good_standing = true` (initial posture).
6. Admits `P` to **`Market`** from this height forward.

After join, gate-2 may write serve-credit bits for **`E ≥ E_join + 1`**; `P` is counted in
`R_market` / `Σwork` and may emit for those epochs subject to lag, `W`, and dedup.

### 2.2 `E_join` boundary (R1b — closed)

```text
E_join = settlement_epoch(join_market_height)
       = join_market_height / SETTLEMENT_EPOCH_BLOCKS    // integer division; emission §3

E_first = E_join + 1    // first settlement epoch counted and claimable
```

**Single `Market` predicate (consensus pin — G4-5):**

```text
P ∈ Market for settlement-epoch E  ⇔
  ArchivalBondRecord exists for P_id
  ∧ E ≥ E_join + 1
  ∧ good_through(P, E)              // evaluated at E-close; archival state §3.4
```

**Derived reads (same predicate — no §2.2 vs §4 split):**

```text
counted_in_R_market(P, shard, E)  ⇔  serve_credit_bit(P,s,E) ∧ (P ∈ Market for E)
claimable_epoch(E) in emission    ⇔  (P ∈ Market for E) ∧ dedup ∧ W ∧ … (emission §6.5)
```

**Partial epoch `E_join`:** join may land at any height within `E_join`. **No counting or
claims for `E_join`** — avoids coupling claimability to gate-2 challenge-close ordering
inside the epoch. Cost: at most one forfeited partial epoch. **No retroactive `E < E_join+1`
counting** (invariant 2).

**First paying mint:** earliest batch `[E_first, …]` = `[E_join + 1, …]`; emitted in
settlement epoch **`≥ E_join + 2`** for work finalized at `E_first` close (§4.5 lag), or
later within `W`.

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
| `Exited` → collateral returned | **Unbond** after release cooldown (§4.3) |

"Joined but not yet paid" = `Bonded` with empty `claimed_settlement_epochs` — **not** a
fifth state.

**Exit vs bond (G4-1):** decorrelated **drain** (PHASE_2B §2.4) spends `P`'s ordinary
FCMP++ outputs only. **Bond collateral is a consensus balance**, not a spendable UTXO —
clean exit requires **`BondPostKind::Unbond`**, not drain.

**Release refund (gate-6):** Unbond creates a **P-attributed** refund output whose amount
equals public `bond_debit == bonded_total == bond_floor(holdings)`. FCMP++ tree membership
is value-agnostic (output mixes normally); gate-6 §2.4 decorrelated-drain discipline applies
to this output like reward outputs.

---

## 3. Wire shape — `txin_archival_bond_post` (genesis lean)

### 3.1 Disposition

| Option | Verdict |
|--------|---------|
| **(a)** Zero-mint `txin_archival_reward_emission` | Rejected — conflates bond posture with mint wire |
| **(b)** Dedicated `txin_archival_bond_post` | **Genesis lean** — one vin for join + re-bond |

Emission leg handles **mint + dedup only**; bond posture changes use this vin.

### 3.2 Custody model — consensus balance (round-1 base)

The bond is **not** a UTXO and **not** a spend-lock on a UTXO. It is
**`bonded_total_atomic`** on `ArchivalBondRecord` — a divisible consensus-held balance keyed
by public `P_canonical_id`.

**Maintained invariant (per record):**

```text
bonded_total_atomic == bond_floor(holdings)    // equality, not ≥
```

Over-bonding buys nothing (slash is floor-or-whole per FOUNDATION §3.2) and would make the
cleartext bond term a per-`P` fingerprint. **Floor it; do not tune** (FOUNDATION §3.1).

**Funding inputs** to bond-post txs are still ordinary FCMP++ UTXOs; only the **bond
instrument** is non-UTXO.

#### Rejected UTXO framings (G4-2 — closed)

| Framing | Why rejected |
|---------|----------------|
| Attest UTXOs P controls, leave spendable | Slash-unsound — consensus cannot seize; P front-runs |
| Attest + consensus spend-lock via key-image blacklist | FCMP++ spends are membership-unlinkable; lock requires pre-revealed key images → early linkability, stranded (not burned) supply, no per-shard `FLOOR` decrement |

#### Balance-equation terms (replaces `BondAttestation`)

Bond posture changes ride the **standard RCT balance proof** (emission leg §7.1 step 8 —
same class as loud emission mint). Cleartext terms on the vin:

```text
Σ input_commitments = Σ output_commitments + fee + bond_credit − bond_debit
```

| Term | Class | Soundness bar |
|------|-------|----------------|
| `bond_credit` | **Sink** — removes value from circulation | **Below mint bar** — cannot inflate; inputs must cover credit (balance equation) |
| `bond_debit` | **Source** — returns bonded value to outputs | **At or below mint bar** — authorization is `bond_debit == bonded_total` (single scalar read), strictly less surface than emission mint (work/Σwork/budget recompute) |

Emission already ships a loud cleartext **source** term (mint) inflation-checked on the vin
(emission §5.5). Bonds need less than that.

**Allowed terms per `post_kind` (exactly one direction per tx):**

| `post_kind` | `bond_credit` | `bond_debit` | Notes |
|-------------|---------------|--------------|-------|
| `JoinMarket` | yes (`== bond_floor`) | no | Creates record |
| `Rebond` | yes | no | Restores floor after slash |
| `Unbond` | no | yes (`== bonded_total`) | After release cooldown |
| `HoldingsUpdate` add shard | yes (`+FLOOR`) | no | Wire V3.1 |
| `HoldingsUpdate` drop shard | no | yes (`FLOOR`) | Wire V3.1; per-shard cooldown (§4.4) |

**Forbidden:** `bond_credit` or `bond_debit` on `txin_archival_reward_emission`; both
directions in one bond-post tx; either term on a paying emission tx.

On connect: `bonded_total_atomic` and global `total_bonded_atomic` (§4.5) move in lockstep
with the cleartext term.

### 3.3 Transaction envelope

A bond-post transaction contains:

1. **Exactly one** `txin_archival_bond_post` (this spec).
2. **Zero or more** `txin_to_key` inputs (ordinary FCMP++ + key images).
3. **Forbidden:** reward mint fields; `txin_archival_reward_emission` in the same tx.

### 3.4 `txin_archival_bond_post` — logical fields

```text
ArchivalBondPostVin {
  P_pubkey:              HybridPublicKey,
  p_canonical_id:        [u8; 32],             // hint; verifier recomputes (emission §6.1)
  post_kind:             BondPostKind,         // §3.5
  holdings:              HoldingsDescriptor,
  bonded_total_atomic:   u64,                  // must equal bond_floor(holdings) post-connect
  bond_credit:           u64,                  // cleartext; 0 unless credit path (§3.2 table)
  bond_debit:            u64,                  // cleartext; 0 unless debit path (§3.2 table)
  pqc_auths:             [...],                // P hybrid spend auth (gate-6 §9.6)
}

enum BondPostKind {
  JoinMarket,
  Rebond,
  Unbond,
  HoldingsUpdate,        // V3.1 wire; credit/debit directions §3.2
}
```

### 3.4.1 Byte layout (genesis pin)

Vin type tag **`5`** (`txin_archival_bond_post`). Varint discipline matches gate-2 §5.1.1 /
[`shekyl-io`](../../rust/shekyl-oxide/shekyl-oxide/io). Reference implementation:
`shekyl-archival-retention::bond_wire`.

```text
u8                      vin_type = 5
varint                  hybrid_pubkey_len   (≤ 2048)
[hybrid_pubkey_len]     HybridPublicKey::to_canonical_bytes()
[32]                    p_canonical_id      (hint; verifier recomputes)
u8                      post_kind           (0=JoinMarket, 1=Rebond, 2=Unbond, 3=HoldingsUpdate)
u8                      holdings_kind       (0=ShardSetCompact, 1=CompleteTree)
// if holdings_kind == 0:
varint                  shard_count         (≤ 4096)
repeat shard_count:
  varint                shard_id
// if holdings_kind == 1: no shard list (sentinel only)
varint                  bonded_total_atomic
varint                  bond_credit
varint                  bond_debit
```

Hybrid spend authorization uses **transaction-level** `pqc_auths[]` aligned with `vin[]`
indices (not an on-vin signature blob). Preimage:

```text
sig_preimage = cSHAKE256(
  customization = "shekyl/archival-bond-post-v1",
  input         = tx_prefix_hash
                  || p_canonical_id
                  || post_kind_u8
                  || encode_holdings_descriptor
                  || bonded_total_atomic_le64
                  || bond_credit_le64
                  || bond_debit_le64
)
```

`encode_holdings_descriptor` is the on-wire holdings section (`holdings_kind` byte plus
optional shard-id varint list). On-wire amount fields use varints; preimage uses fixed
`le64`.

**JoinMarket path:** reject if `ArchivalBondRecord` already exists for `P_canonical_id`;
`bond_credit == bond_floor(holdings)`; credit `bonded_total_atomic` and `total_bonded_atomic`.

**Rebond path:** require existing record with `good_standing == false` (post-slash);
`bond_credit` restores `== bond_floor`; append re-bond event to interval log (F3).

**Unbond path (G4-1):** clean release of bonded balance when:

1. `P` has initiated exit (decorrelated drain confirmed) **or** is in `Exited` posture, and
2. **Release cooldown** elapsed: no pending challenge can still slash for epochs after `P`
   stopped serving — i.e. grace window past `P`'s last served settlement epoch (gate-4;
   **shorter than `W`**).

On confirm: `bond_debit == bonded_total`; refund output(s) to `P`; zero
`bonded_total_atomic`; decrement `total_bonded_atomic`; append **clean interval-close** to
`bond_event_log` (F3) so `good_through(E)` stays true — **backlog emission still verifies
post-release** within `W`.

**Asymmetry (load-bearing):**

| Window | Duration | Governs |
|--------|----------|---------|
| Release cooldown | ~one grace window after last serve | When collateral may **Unbond** |
| Backlog claim (`W`) | `MAX_CLAIM_AGE_W` epochs | When reward epochs **forfeit** (E-3) |
| Retention commitment | `bond_duration(age)` per shard (below) | When a held shard may be **voluntarily dropped** |

Collateral return and reward mint are **independent value flows**.

**Retention-commitment horizon (sim L9/L10; decided 2026-06-11).** Each held shard carries a
minimum commitment of `bond_duration(age) = BOND_DURATION_BASE_EPOCHS · (1 +
BOND_DURATION_AGE_SCALE · age)` settlement epochs from acquisition (normalized shard age
`age ∈ [0,1]`; constants in [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md) §1,
shape pinned / numerics provisional). Before the horizon elapses, the shard is ineligible for
voluntary drop via `HoldingsUpdate` (V3.1 wire) or `Unbond`-with-remaining-holdings; slash and
full exit (`Unbond` of the entire record after release cooldown) are unaffected — duration
deters *shard-drop while staying*, not capital flight
([`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) §*L10 hardening* disposition and
reversion clause).

### 3.5 Verify order (consensus) — bond-post tx

1. Structural — tx type, single bond vin, `P_canonical_id` recomputation matches.
2. `post_kind` preconditions — join / re-bond / unbond / holdings-update paths.
3. **Term rigidity** — `bond_credit` / `bond_debit` match §3.2 allowed-terms table (one
   direction only).
4. **Floor equality** — post-connect `bonded_total_atomic == bond_floor(holdings)`.
5. `P` hybrid signatures on vin.
6. **FCMP++ balance** — `Σ in = Σ out + fee + bond_credit − bond_debit`; **no emission mint**.
   When `bulletproofs_plus` is non-empty, layout must be canonical (exactly one aggregated
   proof, `1 ≤ V.size() ≤ BULLETPROOF_PLUS_MAX_OUTPUTS`); credit-only join may omit proofs.

On block connect for **JoinMarket:** create `ArchivalBondRecord` (§4.1); credit
`total_bonded_atomic`.

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
  bond_event_log:            BondEventLog,     // slash / re-bond / unbond intervals (F3)
  last_served_epoch:         Option<u64>,      // release cooldown (§4.3)
}
```

**Deprecated name:** `first_emission_height` → split into `join_market_height` +
`first_paying_emission_height`. Pre-genesis docs/code use new names only.

**`Market` predicate:** §2.2 (per-epoch; includes `E ≥ E_join + 1` and `good_through(E)`).

Foundation `CompleteTree` exclusion from `market_R` unchanged (E-2).

### 4.2 Slash — consensus mutation (forward-only)

Slash is **not** a user transaction and has **no** balance equation. It is a
**consensus-internal transfer** between tracked counters (§4.5), same class as coinbase
emission being rule-driven rather than balance-proven.

**Trigger:** gate-2 `challenge_failed(P,s,E)` at `H > H_deadline` without
`serve_credit_bit` ([`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md) §6); gate-4
applies `slash(P, s)`.

**Atomic write set (entire slash on block connect):**

1. `bonded_total_atomic -= FLOOR` (or **whole balance** for `CompleteTree` — FOUNDATION §3.2)
2. `holdings` loses shard *s* (or full unbond for foundation)
3. Re-establish `bonded_total_atomic == bond_floor(holdings)` — **`==` pin prevents
   partial-slash theater**; last-shard slash → `0` → out of Market until re-bond
4. `total_bonded_atomic -= slashed_amount`; `burned_total += slashed_amount` (§4.5)
5. Append slash interval to `bond_event_log` (F3)

**Forward-only (invariant 2):** slash at `E_slash` does **not** rewrite finalized
`R_market(s,E)` / `Σwork(E)` for `E < E_slash`. Pre-slash honestly-earned epochs stay
claimable (E-3). `R_market` reduction is automatic at the **next** epoch-close when `P` no
longer satisfies the Market predicate — slash never mutates the finalized past.

### 4.3 Clean unbond vs slash unbond (G4-1)

| Path | Trigger | Collateral | `good_through` for served epochs |
|------|---------|------------|----------------------------------|
| **Slash** | Failed challenge | Forfeited → burn accounting (§4.5) | Pre-slash honest epochs preserved (E-3) |
| **Unbond** | Operator exit + cooldown | Returned to `P` | Clean interval-close in event log |

Without **Unbond**, a never-slashed exiting `P` cannot recover collateral — no rational
bonding. Corpus gap noted: [`STAKER_ARCHIVAL_SIM.md`](STAKER_ARCHIVAL_SIM.md) iteration-3
item 6 ("graceful-exit return") — now spec'd here.

**FSM ([`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md)):** `Exited` gains **Unbond**
action; sub-condition **collateral in cooldown** until release cooldown elapses. Full
retirement = **bond released** ∧ backlog exhausted or lapsed (`W`). `p_slot` burn follows.

### 4.4 HoldingsUpdate — partial unbond principle (G4-6)

**Wire:** deferred **V3.1** with `HoldingsUpdate` vin.

**Principle pinned now:** dropping shard *s* from `ShardSetCompact` reduces
`bond_floor(holdings)` by `ARCHIVAL_BOND_FLOOR`; released collateral for *s* inherits
**Unbond release cooldown** (per-shard last-served epoch) — cannot withdraw immediately.

**Safety for deferral:** `work_P(E)` is derived from per-`(P,s,E)` **retention bits**, not
the mutable holdings descriptor. HoldingsUpdate cannot corrupt historical work; descriptor =
current membership, bits = per-epoch ground truth.

### 4.5 Supply conservation law (G4-3 — closed)

Monero-lineage conservation with one new term (PHASE_2B §7 G11 cross-ref):

```text
already_generated_coins  ==  circulating + bonded + burned
```

| Event | `already_generated` | `circulating` | `bonded` | `burned` |
|-------|----------------------|---------------|----------|----------|
| Coinbase / emission mint | +R | +R | — | — |
| Post / fund (`bond_credit`) | — | −credit | +credit | — |
| Release (`bond_debit`) | — | +debit | −debit | — |
| Slash | — | — | −s | +s |
| Fee burn (`actually_destroyed`) | — | −b | — | +b |

`circulating` is the hidden-amount UTXO total (not directly summable on chain). RHS scalars
define **expected** circulating supply; per-tx RCT balance soundness keeps it honest — same
§9 / G11 inflation discipline as emission mint.

**Global audit scalar:**

```text
total_bonded_atomic  ==  Σ_P bonded_total_atomic     // full-node cross-check
```

LMDB placement: sibling to `already_generated_coins` and cumulative burn total (single-valued;
no DUPSORT). Slash soundness is audited by the conservation law, not a balance proof.

**Economic note:** at equilibrium, `FLOOR × Σ covered-(P,s)` is **deliberately immobilized
circulating supply** (locked fraction), not destroyed — distinct from burn. Worth one line in
gate-1 / sim economics when the numeric cluster lands (§8.2).

Slashed bond routes through the **existing burn counter** — one auditable burned total, not a
new sink. `get_block_reward` accumulation is undisturbed (bonds never mint).

---

## 5. Reorg (`pop_block`)

**Per-block pop is all-types-atomic** (single LMDB txn): revert every state type the block
touched — bond credit/debit + `bonded_total_atomic` + `total_bonded_atomic`, record
create/update/delete, same-block retention bits / counts, FCMP++ outputs, interval-log pop.

**Cross-block cascade:** JoinMarket gates gate-2 bit-writing (§1.4). Reverting join at `H`
un-authorizes retention / `R_market` / `Σwork` updates `P` contributed **after** `H`. That
cascade is handled by **ordered multi-block pop** (tip → `H`, archival state §6): later
blocks' bits revert in their own pops **before** the join block is reached — no orphan bits
when the record is deleted at `H`.

On block disconnect at height `H`:

1. **JoinMarket** in block: delete `ArchivalBondRecord` iff `join_market_height == H`;
   revert `bond_credit`, `total_bonded_atomic`, same-block gate-2 writes for `P`.
2. **Rebond / Unbond / HoldingsUpdate** in block: revert record + balance terms in reverse
   connect order.
3. Emission leg §8: paying-emission dedup + mint undo (separate vin path).

Wallet ([`PHASE_2B_FSM_RETOOL.md`](PHASE_2B_FSM_RETOOL.md) P2B-5): `Bonded` →
`AdmissionPending` when (1) fires; else re-fetch record and refresh caches.

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
| UTXO-shaped bond (attest / spend-lock) | Rejected — §3.2 G4-2 |
| `BondAttestation` proof object | Rejected — balance-equation terms suffice |
| `bonded_total > bond_floor` (over-bond) | Rejected — §3.2 `==` pin |
| Claim/count at `E_join` (partial epoch) | Rejected — §2.2; use `E_join + 1` |
| Bond recovery via drain only | Rejected — §4.3 G4-1 |
| Slash wire bytes | Deferred — gate-4 round 1+ |
| `total_bonded_atomic` LMDB placement | Deferred — with archival state schema (§4.5) |
| `HoldingsUpdate` wire | Deferred V3.1 — principle §4.4 |

---

## 8. Open pins (gate-4 round 1)

**Closed at round 1:** custody model (§3.2); `bond_credit`/`bond_debit` wire; conservation
law (§4.5); `== bond_floor`; UTXO framings rejected.

**Remaining (implementation):**

- [x] **Numeric cluster** — [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)
      (2026-06-07 pin).
- [x] **Slash trigger interface** — [`ARCHIVAL_RETENTION_GATE2.md`](ARCHIVAL_RETENTION_GATE2.md)
      §6 `challenge_failed` → §4.2 `slash(P,s)`; consensus hook landed (`process_archival_slash_at_height`).
- [x] C++ / Rust `txin_archival_bond_post` vin registration (`tag 0x05`, `bond_wire`, §3.4.1).
- [x] `bond_credit`/`bond_debit` in RCT balance verifier (`verRctSemanticsBondPost`; NIC path).
- [x] JoinMarket connect: `put_archival_bond_record` + `total_bonded_atomic` (Rebond/Unbond/HoldingsUpdate deferred).
- [x] **KAT phase-1 (bonded-aggregation sub-invariant only):** `gate4_lifecycle_kat_v1.json` +
      `gate4_lifecycle_kat.rs` — join wire, serve at `E_first`, `verify_conservation_snapshot`
      on `total_bonded == Σ_P bonded_total`. **Three qualifiers on closure:**
      (1) bonded-aggregation identity only, not the full supply law;
      (2) KAT-covered in Rust tests, not consensus-enforced per connect;
      (3) paying-emit leg and full `already_generated == circulating + bonded + burned`
      deferred to emission phase-0.
- [ ] KAT phase-2: paying-emit vin + full supply-law cross-check (blocked on emission leg).

**Rust-first disposition (gate-4 §8 slice):** new bond-post semantic rules live in
`shekyl-archival-retention`; C++ `blockchain.cpp` retains hybrid-pubkey bounds,
`P_canonical_id` recompute (pinned stay-C++), LMDB `record_exists`, and thin FFI
delegation. `ArchivalBondValue` LMDB encoding is v3-only at connect; pre-v3 bond
blobs are rejected at decode (pre-genesis posture: reset data-dir).

### 8.1 `bond_floor(holdings)` (G4-7)

```text
bond_floor(ShardSetCompact(set)) = ARCHIVAL_BOND_FLOOR × |set|
bond_floor(CompleteTree)         = ARCHIVAL_BOND_FLOOR × 1   // nominal; FOUNDATION §3.1
```

Foundation `CompleteTree` is **excluded from `Market`** but posts **one** floor bond per
`P`, not `FLOOR × all-shards`. Otherwise genesis foundation slots would owe
`FLOOR × |all shards|`.

### 8.2 Numeric cluster (pinned 2026-06-07)

**Authoritative enumeration:** [`ARCHIVAL_TIMING_CONSTANTS.md`](ARCHIVAL_TIMING_CONSTANTS.md)
(cluster table, §2 couplings, pin procedure). Gate-4 owns **release cooldown semantics**
(§3.4–§4.3); numeric values land in the joint cluster pass, not here in isolation.

**Summary (do not re-pin locally):**

| Constant | Role |
|----------|------|
| `SETTLEMENT_EPOCH_BLOCKS` | `E_join`, epoch-close cadence |
| `MAX_CLAIM_AGE_W` (`W`) | E-3 backlog forfeiture |
| `RELEASE_COOLDOWN_EPOCHS` | Anti front-run before `Unbond` (floored by L16 + gate-2) |
| `ARCHIVAL_REORG_DEPTH_BLOCKS` | Wallet + consensus `pop_block` depth |
| `RETENTION_HORIZON_BLOCKS` | Archival derived-state retention floor |

**Asymmetry (load-bearing):** `RELEASE_COOLDOWN_EPOCHS < W`. Collateral return and reward
backlog are independent value flows (§3.5).

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

- **2026-06-07 (R1 base):** Consensus-balance custody; `bond_credit`/`bond_debit`; conservation
  law; `== bond_floor`; slash forward-only; reorg all-types-atomic; §8.2 numeric cluster.
- **2026-06-07 (G4):** G4-1 `Unbond` + cooldown; G4-2 custody model; G4-3 supply coupling;
  G4-4 `E_join+1`; G4-5 unified Market predicate; G4-6 HoldingsUpdate principle; G4-7
  `bond_floor` CompleteTree exception.
- **2026-06-07:** Round 0 — join-Market seam; `txin_archival_bond_post` sketch; reorg;
  emission/FSM cross-amendments.
