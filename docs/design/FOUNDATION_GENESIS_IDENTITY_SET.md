# Foundation genesis identity set — consensus block

**Status:** Spec pin (pre-genesis). Legal concurrence on disclosure framing:
`docs/design/FOUNDATION_ARCHIVAL_DISCLOSURE.md`. Parent policy:
`docs/V3_STAKER_ARCHIVAL.md` §*Service promise*.

**Purpose.** This document is the **genesis consensus block** for foundation
complete-tree archivers: the immutable enumerated identity set, nominal bond
discipline, and the **holdings wire shape** that keeps "holder of everything"
compact without a foundation-only slash branch.

**Prerequisite pin:** `docs/V3_STAKER_ARCHIVAL.md` §*Archival data scope*
(B/C vs wallet-minimum A) — gates legal and FAQ language before counsel lock.

---

## 1. Wallet and `P` pubkey wire — not payment addresses

Genesis does **not** enumerate wallet payment addresses.

| Identity | Role in genesis block | V3.0 wire status |
|---|---|---|
| **Wallet `AccountPublicAddress`** (spend / stake principal) | **Not listed.** FA-1 single static address backs stake via normal staking path; see `PHASE_2B_STAKE_LIFECYCLE.md` FA-1. | **Pinned for V3.0.** Hybrid FCMP++ PQC layout is load-bearing in `KeyEngine`; no subaddresses at V3.0 (`FOLLOWUPS.md` R2-F2 closed). |
| **Archival pseudonym `P`** | **Listed** (active slots: full pubkey; reserve slots: hash commitment). | **Hybrid public key wire format must be frozen before genesis authoring** — genesis bytes commit to the encoding. Same hybrid material class as account keys (ML-KEM-768 + ML-DSA-65 public components per PQC wire spec); **`ArchivalEngine` lifecycle unbuilt** (Stage 5) but **encoding must not change** after enumeration without regenerating the genesis block. |

**Answer to "are we past address-shape churn?"** **Yes for wallet payment
addresses.** Genesis enumerates **`P` pubkeys** (separate surface). Remaining
work is registration, backing proof, and challenge cadence — not payment-address
redesign.

---

## 2. One special dimension (genesis → durability credit only)

**Factored rule (cleaner than dual membership flags):**

| Property | Mechanism | Genesis membership test? |
|---|---|---|
| Absent from **`market_R`** | **`CompleteTree`** mints **no** per-shard nullifiers; `market_R` counts nullifiers | **No** — descriptor-only |
| Nominal **`CompleteTree`** bond path, uniform slash | General registration + `ARCHIVAL_BOND_FLOOR` once per `P` | **No** |
| Excluded from market reward / **`Σwork`** | No nullifiers → no market scarcity participation | **No** |
| **`durability_count` for all shards** | **`CompleteTree` + bonded-and-good-standing** | **Yes — only if genesis-enumerated active slot** |

Foundation archivers are special in **exactly one** consensus check: **genesis
enumeration grants full-tree durability credit.** Everywhere else they use the
**same** `CompleteTree` descriptor, bond, challenge, and slash paths as any
other complete-tree registrant. **No** `foundation → skip slash` branch.

---

## 3. Nominal uniform bond and slash → unbond → removal

### 3.1 Why nominal stake

A holding is **bonded stake + shard claim + challenge path**. Zero bond ⇒
unstaked-holder exception in slash code — rejected.

Foundation needs **representability + uniform slash path**, not economic skin
(no reward to gate; reputation is the deterrent).

**Policy:** each **active** genesis foundation identity posts **one**
retention bond at **`ARCHIVAL_BOND_FLOOR`** (gate-4 minimum per-shard floor
for market archivers), **once per `P`**, not per shard. **Floor it; do not tune.**

### 3.2 `CompleteTree` slash chain (explicit)

| Step | Market `ShardSetCompact` | `CompleteTree` (foundation or any) |
|---|---|---|
| Failed challenge on shard *s* | Slash **shard *s*'s bond**; other shards stay bonded | Slash **whole bond** (`ARCHIVAL_BOND_FLOOR` in full) |
| Fractional `FLOOR/shards` | N/A (per-shard bonds) | **Rejected** — no-op slash = skip-slash in disguise |
| Post-slash holding | Still bonded on remaining shards | **`P` unbonded** — invalid holding |
| `durability_count` | Drops *s* if shard bond gone / holder fails good-standing | **Drops entirely** until re-bond |
| Resume | Replace shard bond | **Re-post full nominal bond** + registration |

Re-bonding is the only resume path. One failed sample removes **one whole
seed** from the floor until re-bond — size **`N_active`** (typically 3–5) for
**seat-loss margin**, not only geographic diversity.

### 3.3 Backing stake

Each active foundation `P` proves **"some active stake backs me"** via standard
membership proof against the active-stake root (`V3_STAKER_ARCHIVAL.md`).

---

## 4. Holdings representation — compact complete tree (mandatory)

### 4.1 Problem

Per-`(P, shard)` bond rows for complete-tree ⇒ O(shards) state ⇒ temptation
for foundation-only holding type — rejected.

### 4.2 Pin — general `HoldingsDescriptor`

```text
ArchivalRegistration {
  P_pubkey: HybridPublicKey,
  bond_commitment: BondCommitment,
  holdings: HoldingsDescriptor,
}
```

```text
HoldingsDescriptor ::= ShardSetCompact(shard_set)
                     | CompleteTree
```

- **`ShardSetCompact`** — bounded compact shard set; mints `ν = H(P, shard)`
  per held shard for **`market_R`**; bond = `ARCHIVAL_BOND_FLOOR × |set|`.
- **`CompleteTree`** — one sentinel = all shards (sets **B + C** per data-scope
  pin); **no** per-shard nullifiers; nominal bond once per `P` for foundation
  genesis slots.

**`durability_count(s)` includes `P` iff:**

```text
  P.bonded
  AND P.good_standing
  AND (
        (P.holdings == CompleteTree AND P.genesis_foundation_slot_active)
     OR (P.holdings == ShardSetCompact AND s ∈ P.shard_set)
  )
```

Challenge: sample shard `s`; verify retention proof to `R_k` from held
material — **same verifier** for all holders.

### 4.3 Rejection

- Zero bond + skip-slash branch.
- Per-shard bond rows for foundation `CompleteTree`.
- Foundation-only holding type.
- Counting ghost / unbonded `P` in `durability_count`.

---

## 5. Genesis consensus constant — wire block

Same authority pattern as `config/consensus_constants.json` /
`cmake/generate_consensus_constants.py`.

### 5.1 Schema (normative shape)

```json
{
  "foundation_archival_identities": {
    "version": 1,
    "bond_floor_atomic": "<uint64; ARCHIVAL_BOND_FLOOR at gate-4 pin>",
    "P_pubkey_wire_version": 1,
    "identities": [
      {
        "index": 0,
        "status_at_genesis": "active | reserve",
        "P_pubkey": "<full hybrid wire bytes — active slots only>",
        "P_pubkey_commitment": "<32-byte hash — reserve slots only>",
        "endpoint_hint": "<optional; non-consensus>"
      }
    ]
  }
}
```

**Reserve encoding (genesis size optimization).** Hybrid `P` pubkeys are
multi-kB each. **Active** slots commit **full** `P_pubkey` wire bytes at
genesis. **Reserve** slots commit **`P_pubkey_commitment = H(full_pubkey)`**
(32 bytes) only; the full pubkey is **revealed and verified against the
commitment at activation** (registration / first serve). Reserves stay
committed and auditable; disclosure moves from genesis to activation — a
defensible transparency trade that decouples reserve generosity from genesis
blob size.

| Field | Consensus-critical | Notes |
|---|---|---|
| `version` | yes | Layout version; fork on incompatible change. |
| `bond_floor_atomic` | yes | Must equal `ARCHIVAL_BOND_FLOOR`. |
| `P_pubkey_wire_version` | yes | Must match frozen hybrid archival pubkey encoding. |
| `identities[].index` | yes | Stable slot; rotation burns slot. |
| `status_at_genesis` | yes | `active` vs `reserve`. |
| `identities[].P_pubkey` | active only | Full hybrid wire bytes. |
| `identities[].P_pubkey_commitment` | reserve only | `H(P_pubkey)`; mutually exclusive with `P_pubkey` in same row. |
| `endpoint_hint` | no | Operational fetch hint. |

### 5.2 Over-enumeration ratio

- **`N_active`:** managed-N complete replicas (typically 3–5) — sized for
  **whole-seat loss on one failed challenge** per `CompleteTree` slash chain.
- **`N_total`:** generous reserves; **not** genesis-size-limited thanks to
  hash commitments (§5.1).
- **Cap:** non-binding; exhaustion ⇒ key-management crisis / fork refresh.

### 5.3 Identity table (placeholders)

| Index | Status | Active: `P_pubkey` / Reserve: commitment | Endpoint |
|---:|---|---|---|
| 0 | active | `TBD` | `TBD` |
| 1 | active | `TBD` | `TBD` |
| 2 | active | `TBD` | `TBD` |
| 3 | reserve | `TBD` | — |
| … | reserve | `TBD` | — |

**Authoring checklist:**

1. Freeze `P_pubkey_wire_version` against PQC hybrid encoding spec.
2. Generate cold `P` keypairs; full bytes for actives, hash-only for reserves.
3. Set `bond_floor_atomic` at gate-4 pin.
4. Counsel sign-off after data-scope pin reflected in disclosure + FAQ.

---

## 6. Runtime activation rules

| Event | Effect |
|---|---|
| Reserve → active | Reveal full `P_pubkey` matching commitment; post nominal bond + `CompleteTree`; enters `durability_count` when good-standing. |
| Active → compromised | Ghost fails challenges → slash → unbond → **out of `durability_count`**; activate next reserve. |
| Failed retention challenge | Whole-bond slash → unbond → removal from `durability_count` until re-bond. |

---

## 7. Consumer matrix

| Consumer | `CompleteTree` foundation behavior |
|---|---|
| `market_R` | **Absent** (no nullifiers minted) — no genesis branch |
| `durability_count` | **In** when genesis slot + bonded + good-standing |
| Reward / `Σwork` | **Out** (no market participation) |
| Slash | Whole bond → unbond → count removal |
| Reachability | Discovery + public seeds — **not** a protocol count |

---

## 8. Related documents

- `docs/V3_STAKER_ARCHIVAL.md` — service promise, data scope, replication counts
- `docs/design/FOUNDATION_ARCHIVAL_DISCLOSURE.md`
- `docs/PUBLIC_NARRATIVE_FAQ.md`
- `docs/design/CURVE_TREE_CLIENT.md` §7.6

**Implementation gate:** `ArchivalEngine` (Stage 5, V3.x).
