# Foundation genesis identity set — consensus block

**Status:** Spec pin (pre-genesis). Legal concurrence on disclosure framing:
`docs/design/FOUNDATION_ARCHIVAL_DISCLOSURE.md`. Parent policy:
`docs/V3_STAKER_ARCHIVAL.md` §*Service promise*.

**Purpose.** This document is the **genesis consensus block** for foundation
complete-tree archivers: the immutable enumerated identity set, nominal bond
discipline, and the **holdings wire shape** that keeps "holder of everything"
compact without a foundation-only slash branch.

---

## 1. Wallet address shape — not in this block

Genesis does **not** enumerate wallet payment addresses.

| Identity | Role in genesis block | V3.0 address-shape status |
|---|---|---|
| **Wallet `AccountPublicAddress`** (spend / stake principal) | **Not listed.** FA-1 single static address backs stake via normal staking path; see `PHASE_2B_STAKE_LIFECYCLE.md` FA-1. | **Pinned for V3.0.** Hybrid FCMP++ PQC layout is load-bearing in `KeyEngine`; no subaddresses at V3.0 (`FOLLOWUPS.md` R2-F2 closed). No open work should materially change payment-address bytes before genesis. |
| **Archival pseudonym `P`** | **Listed.** HKDF-derived independent keypair; public under `P`, firewalled from spend/claim (`V3_STAKER_ARCHIVAL.md` §*Privacy firewall*). | **Lifecycle still to implement** (`ArchivalEngine`, Stage 5). **Wire shape for `P` pubkey is stable enough to enumerate at genesis** — it is a standard Shekyl hybrid public key, not a wallet subaddress index or spend derivation. |

**Answer to "are we past address-shape churn?"** **Yes for wallet payment
addresses.** Genesis enumeration uses **`P` pubkeys**, which are a separate
surface from the wallet address format. Remaining archival work is
`P` registration, backing proof, and challenge cadence — not a redesign of
what bytes go in this block.

---

## 2. One special dimension (recap)

Foundation archivers are special in **exactly one** protocol dimension:

- **Genesis enumeration → excluded from `market_R` and all reward / scarcity /
  servo inputs.**

Everywhere else they use the **same** holding, challenge, and slash paths as
market archivers. **No** `foundation → skip slash` branch in consensus code.

---

## 3. Nominal uniform bond (not zero, not per-shard economic skin)

### 3.1 Why nominal stake

A holding in the consensus model is **bonded stake + shard claim + challenge
path**. Zero bond would require an unstaked-holder exception in the
**consensus-critical slash path** — rejected.

The foundation does not need economic skin-in-the-game (no reward to gate;
reputational failure is the binding deterrent). It **does** need a
**representable, challengeable, slashable** holding on the uniform path.

**Policy:** each **active** genesis foundation identity posts **one**
retention bond at the **minimum valid bond floor** — the same constant used as
the per-shard bond floor for market archivers at gate-4 calibration
(`ARCHIVAL_BOND_FLOOR`), applied **once per `P`**, not once per shard.

| Property | Foundation | Market archiver |
|---|---|---|
| Bond purpose | Representability + uniform slash path | Sybil cost + deep-history guarantee |
| Bond sizing | **`ARCHIVAL_BOND_FLOOR` × 1** per active `P` | **`ARCHIVAL_BOND_FLOOR` × shards held** (flat rate at gate 4) |
| Slash on failed challenge | **Standard path**; nominal amount | **Standard path**; proportional to held shards |
| Reward path | **None** (fully outside formula) | Scarcity-priced market pot |

**Do not tune** the foundation amount — **floor it.** The value carries no
market signal (excluded from `market_R` regardless of size).

### 3.2 Backing stake

Each active foundation `P` must still prove **"some active stake backs me"**
via the standard membership proof against the active-stake root
(`V3_STAKER_ARCHIVAL.md`). The **eligibility lock** on that backing stake
follows normal staking rules; the **archival retention bond** is the nominal
floor above.

---

## 4. Holdings representation — compact complete tree (mandatory)

### 4.1 Problem

If consensus state stores **one row per `(P, shard)` bond** for a complete-tree
holder, foundation seeds imply **O(shards)** rows — state bloat that invites a
foundation-only "complete-tree holding type" (a second special case via the
state model).

### 4.2 Pin — general `HoldingsDescriptor`, not a foundation type

`ArchivalEngine` registration carries:

```text
ArchivalRegistration {
  P_pubkey: HybridPublicKey,
  bond_commitment: BondCommitment,   // nominal floor for genesis P; per-shard sum for market P
  holdings: HoldingsDescriptor,
}
```

```text
HoldingsDescriptor ::= ShardSetCompact(shard_set)
                     | CompleteTree   // sentinel: holder claims all shards present and future
```

- **`ShardSetCompact`** — compact encoding for partial portfolios (run-length
  ranges, fixed-width bitmap over shard index, or successor to the sim's
  per-shard model — **bounded size**, not O(shards) sparse rows in the
  **registration blob**).
- **`CompleteTree`** — **one sentinel** meaning "this `P` holds the full tree."
  Valid for any registrant who posts sufficient bond under market rules; for
  foundation genesis identities it is the normal registration shape.

**Per-shard nullifiers** `ν = H(P, shard)` remain the **`market_R` counting
primitive** for market archivers. Genesis foundation identities are
**excluded from `market_R`**; they do **not** mint O(shards) nullifier rows.
**`durability_count(shard)`** treats each **active** genesis complete-tree
identity as covering **every shard** by rule:

```text
durability_count(s) includes P  iff  P is active genesis foundation identity
                                 and P holds CompleteTree (or equivalent genesis pin)
```

Challenge path: sample shard `s`, verify retention proof against foundation's
complete copy — **same verifier** as market holders; only the **state
indexing** differs.

### 4.3 Rejection

- **Zero bond + skip-slash branch** — rejected (§3).
- **Per-shard bond rows for foundation complete tree** — rejected (state bloat).
- **Foundation-only holding type** — rejected; use `CompleteTree` sentinel on
  the **general** descriptor.

**Reopen:** If a future shard count makes even `ShardSetCompact` unwieldy for
*market* portfolios, widen the **general** compact encoding — not a foundation
carve-out.

---

## 5. Genesis consensus constant — wire block

Emitted into genesis-linked consensus constants (same authority pattern as
`config/consensus_constants.json` / `cmake/generate_consensus_constants.py`).

### 5.1 Schema (normative shape)

```json
{
  "foundation_archival_identities": {
    "version": 1,
    "bond_floor_atomic": "<uint64; ARCHIVAL_BOND_FLOOR at gate-4 pin>",
    "identities": [
      {
        "index": 0,
        "P_pubkey": "<hex; 32-byte seed for display — full hybrid key in genesis blob>",
        "status_at_genesis": "active | reserve",
        "endpoint_hint": "<optional URI template; operational, non-consensus-critical>"
      }
    ]
  }
}
```

**Field rules:**

| Field | Consensus-critical | Notes |
|---|---|---|
| `version` | yes | Increment on incompatible layout only (fork). |
| `bond_floor_atomic` | yes | Single floor for entire genesis set; must equal `ARCHIVAL_BOND_FLOOR`. |
| `identities[].index` | yes | Stable slot id; rotation burns slot, activates another **reserve** index. |
| `identities[].P_pubkey` | yes | Archival pseudonym public key material (hybrid encoding per PQC wire spec). |
| `identities[].status_at_genesis` | yes | `active` = expected to serve at launch; `reserve` = cold, not in `durability_count` until activated. |
| `identities[].endpoint_hint` | no | Public complete-tree fetch hint; may be updated off-chain; not a consensus branch. |

### 5.2 Over-enumeration ratio (operational pin)

- **Live at launch:** `N_active` (target: managed-N complete replicas, e.g. 3–5).
- **Enumerated:** `N_total ≥ 3 × N_active` (generous reserve; exact counts filled at genesis authoring time).
- **Cap:** Non-binding over the chain's life; hitting the cap is a key-management crisis → fork refresh acceptable (`V3_STAKER_ARCHIVAL.md` §*Key rotation*).

### 5.3 Identity table (placeholders — replace before genesis)

| Index | Status at genesis | `P_pubkey` | Endpoint hint (ops) |
|---:|---|---|---|
| 0 | active | `TBD` | `TBD` |
| 1 | active | `TBD` | `TBD` |
| 2 | active | `TBD` | `TBD` |
| 3 | reserve | `TBD` | — |
| 4 | reserve | `TBD` | — |
| … | reserve | `TBD` | — |

**Authoring checklist before genesis:**

1. Generate cold `P` keypairs (same ceremony discipline as release-signing material).
2. Fill `P_pubkey` bytes from hybrid wire encoding — **not** wallet payment addresses.
3. Set `bond_floor_atomic` to gate-4 `ARCHIVAL_BOND_FLOOR` pin.
4. Mark exactly `N_active` rows `active`; remainder `reserve`.
5. Counsel sign-off on public copy (`FOUNDATION_ARCHIVAL_DISCLOSURE.md`, `PUBLIC_NARRATIVE_FAQ.md`).

---

## 6. Runtime activation rules

| Event | Consensus effect |
|---|---|
| Reserve → active (operator begins stake + serve on slot `i`) | Slot `i` enters `durability_count`; posts nominal bond + `CompleteTree`; excluded from `market_R`. |
| Active → compromised / retired | Slot stays enumerated; ghost fails challenges; operator activates next reserve — **no** master revocation primitive. |
| Failed retention challenge | **Standard slash** of posted nominal bond; public audit + reputational consequence. |

---

## 7. Consumer matrix (foundation rows)

| Consumer | Foundation behavior |
|---|---|
| `market_R` | **Excluded** — no per-shard nullifier minting required. |
| `durability_count` | **Included** — active complete-tree slots count for all shards. |
| Reward / `Σwork` | **Excluded** — zero slice, not in denominator. |
| Slash path | **Identical code** — slashes nominal posted bond. |
| Reachability (production) | Discovery + public seed endpoints — **not** a third protocol count (`V3_STAKER_ARCHIVAL.md` consumer table). |

---

## 8. Related documents

- `docs/V3_STAKER_ARCHIVAL.md` — service promise, `market_R` / `durability_count`, accountability
- `docs/design/FOUNDATION_ARCHIVAL_DISCLOSURE.md` — counsel-facing disclosure
- `docs/PUBLIC_NARRATIVE_FAQ.md` — public narrative
- `docs/design/STAKER_ARCHIVAL_SIM.md` — sim uses abstract `foundation_floor()`; production replaces with this block

**Implementation gate:** `ArchivalEngine` (Stage 5, V3.x). This block is
consensus-authoritative at genesis; sim may approximate until engine ships.
