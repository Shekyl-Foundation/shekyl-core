# Foundation archival disclosure — draft for legal review

**Status:** DRAFT — not legal advice. For counsel review before genesis.
**Audience:** Shekyl Foundation, integrators, exchanges, institutional partners,
regulators (as applicable).

**Spec anchor:** `docs/V3_STAKER_ARCHIVAL.md` §*Service promise — genesis-pinned
commitments*.

**Public narrative:** `docs/PUBLIC_NARRATIVE_FAQ.md` §*Archival service promise*.

---

## 1. Purpose

This document states, in disclosure-oriented language, what the protocol
**commits to** regarding long-term chain archival, what role the **Shekyl
Foundation** (and genesis-enumerated foundation archiver identities) plays,
and what is **not** promised. It exists because:

1. **Durability security includes a disclosed foundation layer** — not hidden
   centralization discovered post-launch.
2. **Immutable genesis enumeration** of privileged archiver identities is a
   governance and regulatory fact, not an implementation detail.
3. **User-facing materials must not overclaim** trustlessness or instantaneous
   availability where the spec does not support them.

Counsel should review before genesis: jurisdiction-specific duties, securities
communications, exchange listing representations, and data-retention /
availability statements to users.

---

## 2. Summary for counsel (one page)

| Topic | Disclosure |
|---|---|
| **User promise** | Permanent retention of **deep archival substrate + canonical block history** (sets B + C); best-effort retrieval latency (no real-time bound). See §3.0. |
| **Foundation role** | Genesis-enumerated identities operate **complete-tree** replicas (**B + C**) at public endpoints; auditable via challenges (on **B**) and third-party fetch tests. |
| **Economics** | Foundation archivers **do not participate in market archival reward** (no slice, not in scarcity denominator). Not a profit-extraction path via protocol rewards. |
| **Bonds** | **Nominal uniform retention bond** per active genesis identity (`ARCHIVAL_BOND_FLOOR` × 1, standard slash path — not zero, not per-shard economic skin). |
| **Permanence** | Foundation privilege **does not sunset** by protocol — permanent-but-benign (non-extractive, verifiable). Decentralization = market redundancy **above** floor. |
| **Rotation** | Genesis **over-enumerates** identities; operational rotation activates cold reserve slots — no mutable master-authorization chain. |
| **Risk if market thins** | Decentralization failure (more foundation reliance), **not** silent data loss — if monitoring and floor operations are maintained. |
| **What we do not claim** | CDN-style availability; unbounded trustlessness; "no entity can affect your history." |

---

## 3. Protocol commitments (substantive)

### 3.0 Archival data scope (gates all retention language)

Three data sets — do not conflate in user-facing copy. Authoritative table:
`docs/V3_STAKER_ARCHIVAL.md` §*Archival data scope*.

| Set | What it is | Foundation holds |
|---|---|---|
| **A — Wallet-minimum** | Your scanned outputs + frontier (every syncing wallet) | No (user/wallet local) |
| **B — Deep archival shard** | Full curve-tree segment leaves + proof auxiliary; **challenges verify this** | **All shards** (`CompleteTree`) |
| **C — Block/tx corpus** | Canonical blocks/transactions for rescan, audit, history | **Complete canonical chain** |

**Counsel / marketing pin:** "Complete archival tree" means **B + C**, not
curve-tree structure alone. **Permanent retention** promises **B + C**.
**"Your transaction history won't disappear"** requires **C** retrievable for
rescan plus wallet persistence after scan — **not** satisfied by proof-state
(**B**) alone.

### 3.1 Permanent retention (hard)

The protocol design targets **no deletion** of canonical **deep archival
shards (B)** or **canonical block/transaction history (C)** required for
FCMP++ historical reference, wallet rescan, audit, and dispute backstop.

### 3.2 Best-effort retrieval latency (soft)

Historical user retrieval is **not** guaranteed within a bound. Anonymizing
transport and firewalled archivers imply variable latency. L16 analysis supports
**not** marketing instantaneous or three-nines **availability** for user queries.

**Draft user-facing line:** *"Data is retained permanently; retrieval time is
best-effort and not guaranteed."*

### 3.3 Foundation complete-tree floor

Genesis enumerates foundation archiver identities (see §5). Operated seeds maintain
**complete** copies of **B + C** across **diverse providers/jurisdictions**
(operational choice). The public durability anchor is this **managed multi-replica
archive** (many-nines operational target), not anonymous-market statistics alone.

### 3.4 Market layer (additive)

Independent stakers may archive shards and earn scarcity-priced retention rewards.
Their holdings increase **`durability_count`** and decentralization margin but are
**not** the sole basis of the public durability promise.

### 3.5 Replication counts (implementation discipline)

- **`market_R`:** derived ledger count for **`Market`** archivers with
  `ShardSetCompact` holdings — **`CompleteTree`** / foundation excluded by
  membership ([`ARCHIVAL_CONSENSUS_STATE.md`](ARCHIVAL_CONSENSUS_STATE.md) §3.3).
- **`durability_count`:** includes **bonded-and-good-standing** holders; genesis
  **`CompleteTree`** slots count for all shards; drops on slash → unbond until
  re-bond.
- **Reachability ("up now"):** not a consensus count; sim-only metric. Production
  uses discovery + try-list + public seeds.

---

## 4. Foundation economics and accountability

### 4.1 Excluded from reward formula

Foundation archivers:

- Do **not** receive market archival reward (`CompleteTree` excluded from `Market`
  / `market_R` path).
- Do **not** enter `Σwork` servo inputs.
- **Do** participate in retention challenges on **set B** (public pass/fail).

**Draft disclosure line:** *"Foundation archival nodes are not paid from the
staker archival reward pool; they are a separately operated durability floor."*

### 4.2 Bonds and slash

Foundation identities have **no reward claim path**; reputational failure on a
public challenge is the binding deterrent.

Each **active** genesis identity posts **one nominal bond** at
**`ARCHIVAL_BOND_FLOOR`**. A failed challenge **slashes the whole bond**,
**unbonds** the identity, and **removes it from `durability_count`** until
re-bond — same code path as other `CompleteTree` holders; **no** skip-slash
branch. Fractional per-shard slash on `CompleteTree` is rejected (no-op slash).

Wire: `docs/design/FOUNDATION_GENESIS_IDENTITY_SET.md` §3–§4.

### 4.3 No sunset of foundation privilege

Protocol does not automatically de-privilege genesis foundation identities when
market coverage grows. **Decentralization** is measured as market redundancy
beyond the floor, not foundation withdrawal. A future fork could amend the
enumeration; that is explicit governance, not silent decay.

---

## 5. Genesis enumeration and key lifecycle

### 5.1 Immutable identity set

Foundation archiver identities are listed in **genesis** (or genesis-linked
consensus constants). Properties:

- **Transparent** — same trust class as hard-coded seed discovery keys.
- **One protocol privilege** — genesis **`CompleteTree`** slots count in
  **`durability_count`** for all shards when bonded-and-good-standing.
- **Irreversible without fork** — even if vestigial later.

**Counsel flag:** Immutable on-chain declaration of operator-linked identities may
trigger jurisdiction-specific questions (availability representations, operational
control, securities marketing). Review user-facing copy against §3.

### 5.2 Rotation — over-enumeration (pinned)

Genesis lists **more identities than initially operated** (generous reserve;
reserve slots use **hash commitments** in genesis, full pubkey at activation).
Rotation = activate a cold reserve through normal staking/serving path.
**No** cross-authorizing master keys.

**Reversion:** per-root subkey lineage only if rotation frequency forces it;
**never** cross-minting master.

Compromised operational key: burns one slot; reserve activation; ghost identity
remains observable and excluded from market math.

---

## 6. Operational and monitoring obligations (non-protocol but disclosure-relevant)

The design avoids **silent** transition to foundation-as-sole-copy:

- **`durability_count` vs `market_R`** should be observable (dashboards, RPC,
  audit tools) so "market carrying durable coverage" vs "foundation alone" is
  visible — L13 "loud not silent" applied to durability.

Foundation operators should publish:

- Which genesis identities are **active** vs **reserve**.
- Endpoint locations for complete-tree fetch (public by design).
- Challenge pass/fail history (on-chain + operational status page optional).

---

## 7. Terminal subsidy framing (for partner economics)

Post–fee-era terminal subsidy is framed as funding **decentralization margin**
(market redundancy above foundation floor), **not** as the durability survival
mechanism. Foundation complete-tree cost is operational (bounded seed count),
not emission-gated durability.

**Draft line:** *"Tail emission buys distributed redundancy; it does not pay
for the foundation to exist — the foundation archive is a disclosed design
choice."*

---

## 8. Representations to avoid

Do **not** state or imply:

- "Fully trustless archival with no privileged operator."
- "Three-nines" or "instant" historical fetch availability globally.
- "Eventual retrieval within [X hours]" unless counsel approves a specific bound.
- Market `D*=0.999` or similar as **user-facing** permanent-loss rate.
- Foundation archivers earn competitive archival yield from the protocol.
- **"Complete tree" = everything needed to restore a wallet from seed** without
  also retaining **canonical block/transaction history (set C)**.
- Curve-tree / proof state alone satisfies full wallet history recovery.

Do state:

- Auditable foundation complete archive + market redundancy trajectory.
- Permanent retention; best-effort latency.
- Genesis-enumerated foundation role; challenge-tested.

---

## 9. Cross-references

| Document | Role |
|---|---|
| `docs/V3_STAKER_ARCHIVAL.md` §*Service promise* | Authoritative technical commitments |
| `docs/PUBLIC_NARRATIVE_FAQ.md` | User/partner FAQ |
| `docs/FOLLOWUPS.md` | Legal review tracking item |
| `shekyl-dev/docs/SEED_NODE_DEPLOYMENT.md` | Operational deployment (downstream) |

---

## 10. Counsel checklist (pre-genesis)

- [ ] User-facing site/FAQ aligned with §3.0 data scope (B + C, not tree-only).
- [ ] User-facing site/FAQ aligned with §3.1–§3.2 (no latency guarantee; permanent retention).
- [ ] Exchange/partner DD pack includes §2 summary and genesis enumeration fact.
- [ ] Securities / marketing review of "foundation-as-feature" framing.
- [ ] Data-retention / availability representations in ToS match soft latency pin.
- [ ] Incident communications plan if foundation challenge failures or market thinning.
- [ ] Jurisdiction-specific privacy / financial promotions review (if applicable).
