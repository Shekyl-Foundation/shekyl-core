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
seed** from the floor until re-bond — **`N_active = 3`** (§9.1) for **seat-loss
margin**, not only geographic diversity.

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
**1996 bytes** each (`HybridPublicKey::to_canonical_bytes()` in
`shekyl-crypto-pq`). **Active** slots commit **full** `P_pubkey` wire bytes at
genesis. **Reserve** slots commit **`P_pubkey_commitment`** only (32 bytes):

```text
P_pubkey_commitment = cSHAKE256(
  customization = "shekyl/foundation-p-pubkey-v1",
  input         = canonical_pubkey_bytes
)[0..32]
```

Same cSHAKE discipline as `StakeId` (`PHASE_2B_STAKE_LIFECYCLE.md` §3.3.3).
The full pubkey is **revealed and verified against the commitment at
activation** (registration / first serve).

| Field | Consensus-critical | Notes |
|---|---|---|
| `version` | yes | Layout version; fork on incompatible change. |
| `bond_floor_atomic` | yes | Must equal gate-4-pinned `ARCHIVAL_BOND_FLOOR` (§9.3). **No guessed value in mainnet genesis.** |
| `P_pubkey_wire_version` | yes | Must equal `HYBRID_KEY_VERSION` (`1` today). Layout §9.1. |
| `identities[].index` | yes | Stable slot; rotation burns slot. |
| `status_at_genesis` | yes | `active` vs `reserve`. |
| `identities[].P_pubkey` | active only | Full hybrid wire bytes. |
| `identities[].P_pubkey_commitment` | reserve only | cSHAKE commitment (§5.1); mutually exclusive with `P_pubkey` in same row. |
| `endpoint_hint` | no | Operational fetch hint. |

### 5.2 Over-enumeration ratio (pinned)

- **`N_active`:** **3** — whole-seat loss margin (§3.2) + L15 domain floor.
- **`N_total`:** **12** (9 reserves); hash commitments (§5.1) keep genesis small.
- **Cap:** non-binding; exhaustion ⇒ key-management crisis / fork refresh.

### 5.3 Identity table

See **§9.5** for the full 12-slot structure (`PENDING` until key ceremony).

**Authoring checklist:**

1. Confirm `P_pubkey_wire_version = 1` still matches `HYBRID_KEY_VERSION`.
2. ~~Complete gate-4 iteration-2 fine bond sweep → set `bond_floor_atomic` (§9.3).~~ **Done** — use `750_000_000` from `config/consensus_constants.json`.
3. Run P key ceremony → replace `PENDING` in §9.5.
4. Counsel sign-off on disclosure + FAQ (data scope pinned).
5. Ops publish `endpoint_hint` (optional in genesis blob).

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

---

## 9. Genesis authoring workbook — TBD disposition

Tracks every genesis-block TBD: resolved pins, blockers, and closing artifact.

### 9.1 Resolved (pin now)

| Item | Pin | Source |
|---|---|---|
| **`N_active`** | **3** | L15 retrieval floor + `CompleteTree` whole-seat slash margin |
| **`N_total`** | **12** | 4× over-enumeration (9 cold reserves) |
| **`P_pubkey_wire_version`** | **1** | `shekyl_crypto_pq::signature::HYBRID_KEY_VERSION` |
| **`P` canonical encoding** | `HybridPublicKey::to_canonical_bytes()` | Scheme id `HYBRID_SCHEME_ID_ED25519_ML_DSA_65` (`1`); **1996 bytes** — not a `ShekylAddress` |
| **Reserve commitment** | cSHAKE `"shekyl/foundation-p-pubkey-v1"` | §5.1 |
| **`good_standing`** | Bonded **and** not post-slash unbonded **and** no failed challenge for current challenge epoch | Failed challenge ⇒ whole-bond slash ⇒ out of `durability_count` |
| **Endpoint hint shape** | `https://<host>/archival/v1/` (ops) | Non-consensus; may be empty at genesis |

### 9.2 Gate-4 fine sweep — **closed (sim pin)**

| Item | Pin | Notes |
|---|---|---|
| **`bond_rate*` (sim)** | **`0.75`** | Highest rate in `{0.50, 0.75}` triple intersection (lean + whale spread + P1 coloc). Run 2026-06-07; `STAKER_ARCHIVAL_SIM.md` §*Gate 4 iteration-2*. |
| **`ARCHIVAL_BOND_FLOOR` (atomic)** | **`750_000_000`** | `0.75 SKL`; §9.3 calibration (`bond_rate* × COIN`). |
| **`bond_floor_atomic` in genesis JSON** | **Ready** | Must match `config/consensus_constants.json` at authoring time. |
| **Challenge epoch length** | **Open** | L14 soundness pass step 3; `good_standing` references cadence. |

**Coarse envelope (iteration 1) — unchanged context:**

| Sim `bond_rate` | Role |
|---|---|
| **0.5** (low) | Coarse sweep lower bound |
| **2.0** (mid) | Baseline + lean attractor (`bondA ≈ 76` at ρ≈0.02) |
| **8.0** (high) | **Fails** L8 min-form (`dS/dN ≈ 0.83`) — upper bound, not a candidate |

Flat bond **magnitude** is resolved (L4); duration axis is separate (L9).

### 9.3 Sim → chain mapping — **closed (2026-06-07)**

Sim `bond_rate` is **dimensionless** (`shekyl-staking-sim` `AgentParams.bond_rate`).

**Calibration (normative):**

1. **Sim pin:** `bond_rate* = 0.75` (gate-4 fine sweep, §9.2).
2. **Capital scale anchor:** one sim `Agent.capital` unit ≡ **1 display SKL**
   (`COIN = 10⁹` atomic per `config/economics_params.json` / `shekyl-units`).
   Sim capital is liquid bond-posting capacity, not a consensus minimum stake
   (the chain has none).
3. **Reference co-located endowment (L8 min-form check):** baseline
   storage-rich `{C = 20, S = 22 shard-units}`; at `bond_rate* = 0.75` the
   actor contributes `min(⌊20/0.75⌋, 22) = 22` deep seats (storage-bound).
   With `ARCHIVAL_BOND_FLOOR = 750_000_000` atomic, an actor holding 20 SKL
   reproduces the same arithmetic.
4. **Formula:** `ARCHIVAL_BOND_FLOOR = bond_rate* × COIN = 750_000_000` atomic
   (**0.75 SKL** per per-shard floor; foundation `CompleteTree` posts **one**
   nominal bond at this floor).
5. **Emit:** `archival_bond_floor_atomic` in `config/consensus_constants.json`
   / `cmake/generate_consensus_constants.py` / `rust/shekyl-engine-core/build.rs`.

**Reopen if:** mainnet joint storage×capital survey shifts the reference profile;
whale-spread threshold or endowment model moves the sim triple intersection;
or `COIN` / display precision changes.

**Atomic unit basis:** `ATOMIC_UNITS_PER_SKL = 10⁹` (`shekyl-units`) — not
`GENESIS_TRANSPARENCY.md`'s legacy 10¹² example; reconcile that doc before
authoring if it still disagrees.

### 9.4 Blocked on key ceremony (operational)

| Item | Blocker | Closes when |
|---|---|---|
| Active `P_pubkey` (×3) | Cold-key generation | Ceremony fills indices 0–2 |
| Reserve commitments (×9) | Hash of cold reserve pubkeys | Ceremony fills indices 3–11 |
| `endpoint_hint` per active slot | Seed-node deployment | Ops (`shekyl-dev` plan) |

### 9.5 Identity table (structure pinned — material `PENDING`)

| Index | Status | `P_pubkey` (1996 B hex) | `P_pubkey_commitment` (32 B hex) | `endpoint_hint` |
|---:|---|---|---|---|
| 0 | active | `PENDING` | — | `PENDING` |
| 1 | active | `PENDING` | — | `PENDING` |
| 2 | active | `PENDING` | — | `PENDING` |
| 3 | reserve | — | `PENDING` | — |
| 4 | reserve | — | `PENDING` | — |
| 5 | reserve | — | `PENDING` | — |
| 6 | reserve | — | `PENDING` | — |
| 7 | reserve | — | `PENDING` | — |
| 8 | reserve | — | `PENDING` | — |
| 9 | reserve | — | `PENDING` | — |
| 10 | reserve | — | `PENDING` | — |
| 11 | reserve | — | `PENDING` | — |

**Row rules:** exactly one of `P_pubkey` or `P_pubkey_commitment`; active ⇒
full pubkey; reserve ⇒ commitment only.

### 9.6 Sequencing

1. ~~Gate-4 iteration-2 fine bond sweep → `bond_rate* = 0.75`.~~ **Done (2026-06-07).**
2. ~~Map `bond_rate*` → `archival_bond_floor_atomic` (§9.3).~~ **Done (2026-06-07).**
3. P key ceremony → §9.5 material.
4. Counsel lock on disclosure + FAQ.
5. Genesis authoring → emit `foundation_archival_identities` blob.
6. Ops → public fetch URLs (`endpoint_hint`).
