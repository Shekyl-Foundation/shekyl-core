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
| **User promise** | Permanent retention of canonical deep history; best-effort retrieval latency (no real-time bound). |
| **Foundation role** | Genesis-enumerated identities operate **complete-tree** archival replicas at public endpoints; auditable via challenges and third-party fetch tests. |
| **Economics** | Foundation archivers **do not participate in market archival reward** (no slice, not in scarcity denominator). Not a profit-extraction path via protocol rewards. |
| **Bonds** | **Nominal uniform retention bond** per active genesis identity (`ARCHIVAL_BOND_FLOOR` × 1, standard slash path — not zero, not per-shard economic skin). |
| **Permanence** | Foundation privilege **does not sunset** by protocol — permanent-but-benign (non-extractive, verifiable). Decentralization = market redundancy **above** floor. |
| **Rotation** | Genesis **over-enumerates** identities; operational rotation activates cold reserve slots — no mutable master-authorization chain. |
| **Risk if market thins** | Decentralization failure (more foundation reliance), **not** silent data loss — if monitoring and floor operations are maintained. |
| **What we do not claim** | CDN-style availability; unbounded trustlessness; "no entity can affect your history." |

---

## 3. Protocol commitments (substantive)

### 3.1 Permanent retention (hard)

The protocol design targets **no deletion** of canonical archival shards required
for FCMP++ historical reference, audit, and dispute backstop. This is not expressed
as a market-layer probability (e.g. internal `D*=0.999` sim targets).

### 3.2 Best-effort retrieval latency (soft)

Historical user retrieval is **not** guaranteed within a bound. Anonymizing
transport and firewalled archivers imply variable latency. L16 analysis supports
**not** marketing instantaneous or three-nines **availability** for user queries.

**Draft user-facing line:** *"Data is retained permanently; retrieval time is
best-effort and not guaranteed."*

### 3.3 Foundation complete-tree floor

Genesis enumerates foundation archiver identities (see §5). Operated seeds maintain
**complete** archival copies across **diverse providers/jurisdictions** (operational
choice, not hidden in protocol). The public durability anchor is this **managed
multi-replica archive** (many-nines operational target), not anonymous-market
statistics alone.

### 3.4 Market layer (additive)

Independent stakers may archive shards and earn scarcity-priced retention rewards.
Their holdings increase **`durability_count`** and decentralization margin but are
**not** the sole basis of the public durability promise.

### 3.5 Replication counts (implementation discipline)

- **`market_R`:** market archivers only — rewards, scarcity, coverage targets.
- **`durability_count`:** includes foundation — SLA audit, pruning safety, observability.
- **Reachability ("up now"):** not a consensus count; sim-only metric. Production
  uses discovery + try-list + public seeds.

---

## 4. Foundation economics and accountability

### 4.1 Excluded from reward formula

Foundation archivers:

- Do **not** receive market archival reward.
- Do **not** enter `market_R` or `Σwork` servo inputs.
- **Do** participate in retention challenges (public pass/fail).

**Draft disclosure line:** *"Foundation archival nodes are not paid from the
staker archival reward pool; they are a separately operated durability floor."*

### 4.2 Bonds

Foundation identities have **no reward claim path**; the slash amount is not the
economic deterrent — **reputational failure on a public challenge** is.

Each **active** genesis foundation identity still posts a **nominal retention bond**
at **`ARCHIVAL_BOND_FLOOR`** (minimum valid bond, uniform across the set, **once
per archival pseudonym**, not per shard). This keeps the foundation on the **same
holding + challenge + slash path** as market archivers without a consensus
`skip-slash` special case. Failed challenges execute the **standard slash** on
that nominal bond.

**Rejected:** zero bond (requires slash-path branch); per-shard bond rows for
complete-tree foundation holdings (state bloat). Wire shape:
`docs/design/FOUNDATION_GENESIS_IDENTITY_SET.md` §3–§4.

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
- **Permanent protocol privilege** — exclusion from `market_R`; inclusion in
  `durability_count` and challenge set.
- **Irreversible without fork** — even if vestigial later.

**Counsel flag:** Immutable on-chain declaration of operator-linked identities may
trigger jurisdiction-specific questions (availability representations, operational
control, securities marketing). Review user-facing copy against §3.

### 5.2 Rotation — over-enumeration (pinned)

Genesis lists **more identities than initially operated** (generous reserve).
Rotation = activate a cold reserve identity through normal staking/serving path.
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

- [ ] User-facing site/FAQ aligned with §3 (no latency guarantee; permanent retention).
- [ ] Exchange/partner DD pack includes §2 summary and genesis enumeration fact.
- [ ] Securities / marketing review of "foundation-as-feature" framing.
- [ ] Data-retention / availability representations in ToS match soft latency pin.
- [ ] Incident communications plan if foundation challenge failures or market thinning.
- [ ] Jurisdiction-specific privacy / financial promotions review (if applicable).
