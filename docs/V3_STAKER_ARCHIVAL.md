# V3 Design Notes — Staker Archival as Useful Work

**Status:** V3 ship feature. Originally drafted as V4-scoped; rescoped to
V3 by the 2026-04-27 actor-architecture decision-log entry, which
established `ArchivalEngine` as a Stage 5 actor (sibling to
`StakeEngine`, not a child) shipping in a V3.x dot-release gated on
simulation evidence. This document is the canonical archival-mechanism
design home; it is referenced by `docs/FOLLOWUPS.md` (V3.0 RPC boundary
refinements, V3.1 `assemble_tree_path_for_output` resolution, V3.x
Stage 5 native build) and by `docs/V3_WALLET_DECISION_LOG.md`
*2026-04-27 — Engine architecture: actor model with staged migration
from composition*.

The mechanism ships in a V3.x dot-release. The exact dot-version is
gated on the simulation work described in *Simulation as separate
project* below — the open design questions (shard granularity, query
routing protocol, price curve shape, quick-pick portfolio composition,
unstake-cascade dynamics, privacy-of-queries detailed protocol,
foundation-node integration) close against simulation evidence rather
than against speculation. V3.0 ships without this mechanism active;
V3.0's design surface (RPC boundaries, daemon-selection logic, reward
disbursement architecture) is built so the V3.x ship is purely
additive, not a refactor.

**Author / decision context:** Originated in Phase 1 wallet-rewrite
session (2026-04-26) as an answer to the long-running question "what
useful work do stakers actually do for the network?" The framing has
been held by Rick since approximately 2010 and crystallized when
FCMP++'s historical reference-block archival need (already in
`docs/FOLLOWUPS.md`) was paired with BitTorrent-style scarcity-priced
commons coverage as the mechanism shape. Rescoped to V3 ship in the
2026-04-27 actor-architecture decision; the rescoping does not change
the design — the actor model makes shipping it cleanly possible
within V3.x as a sibling actor to `StakeEngine`.

---

## The problem this solves

Two structural problems converge:

**Problem 1: Stakers don't do useful work.** Across PoW, PoS, and storage
chains, no system has cleanly answered "what real work do stakers perform?"
PoW miners do hash-function makework (wasted electricity). Generic PoS
validators do bookkeeping (attestation, proposal — necessary but not
externally valuable). Storage chains (Filecoin, Storj) make stakers run a
storage business, but storage *is the product*, not a service the chain
needs. None of these is "the staker performs useful work *the network
itself needs* as a side effect of staking." The staker's only contribution
is capital-at-risk, which is a security bond, not a service.

**Problem 2: FCMP++ has a real, growing archival problem.** Wallets
constructing transactions can reference blocks up to 100 blocks old, and
the proof construction needs the curve-tree state at that exact historical
height. Today this is served by foundation-operated `--no-prune` archival
nodes. As the chain grows, full archival becomes expensive (the curve tree
state alone scales linearly with output count, and FCMP++ outputs are
rich). Foundation-only archival is a centralization concern; pruning
without distributed archival is a data-loss concern.

These two problems have a joint solution: **stakers archive the chain.**
Stakers' unique properties — long-term presence, bonded reputation, and
long-horizon economic incentive — make them the only network actor
structurally suited to performing distributed long-term archival. Miners
optimize for current block; transactors are transient. Stakers are the
only class with skin-in-the-game on the chain's *long-term* health, and
archival is exactly long-term-health work.

The unconventional move: **decouple consensus-securing work (capital-at-risk)
from useful work (archival service), pay them from related but distinct
reward streams, let stakers self-select into how much of each they do.**
Most "useful PoS" attempts fail because they try to make consensus and
useful-work be the same activity. They aren't. They can be the same actor
class, paid from related sources, without being conflated.

---

## Service promise — genesis-pinned commitments

This section is a **set of commitments**, not a description. The sim
(`docs/design/STAKER_ARCHIVAL_SIM.md` §*Soundness pass*) validated market
retention economics **conditional** on these pins. Step 1 (L15d/L16d
durability rescore) is closed; **step 0 closes when this section ships.**
Several pins are **cheap at genesis, unfixable after** — key rotation,
replication-count semantics, and the on-chain foundation identity set.

### User-facing promise (one class)

**Permanent retention (hard guarantee).** Deep history is never deleted.
The chain retains irreplaceable state forever; this is not probabilistic
and is not expressed as a market-layer `D*` target.

**Best-effort retrieval latency (soft expectation).** Historical reads
may succeed over anonymizing transport; latency is **typical, not
guaranteed, and not real-time.** L16 proved that a latency bound over
rendezvous cannot be kept while location-hiding holds — so the product
does **not** promise CDN-style instantaneous availability for user
queries. Do not conflate the hard and soft legs under one word like
"eventual."

**Never gone, auditable.** The durability promise is **checkable, not
trust-me:** genesis foundation seed archivers are **public** endpoints
serving a **complete tree**; anyone can verify they hold and serve the
full archive. Frame this honestly as **auditable foundation-backed
durability with a decentralization trajectory** — not oversold
trustlessness.

**Disclosure posture.** Stating publicly that durability security rests
on a disclosed foundation backstop is a **strategic/regulatory fact**, not
only FAQ prose. Hidden-then-discovered centralization is worse than
disclosed-transparent backstop. **Legal review before genesis** is
required — draft in `docs/design/FOUNDATION_ARCHIVAL_DISCLOSURE.md`;
user-facing summary in `docs/PUBLIC_NARRATIVE_FAQ.md`.

### Engineering taxonomy (two classes — only one is a user promise)

| Class | Actor | Bindingness | SLA shape |
|---|---|---|---|
| **Historical / audit retrieval** | Wallet users, auditors, dispute backstop | **User-facing promise** | Permanent retention + best-effort latency (above) |
| **Archiver seeding / backfill** | Market archivers entering or replenishing holdings | **Internal maintenance SLO** | Bounded seeding latency; governs whether the market layer sustains — **not** promised to end users |

The seeding SLO lives in the maintenance / archiver section below, not
in user-facing materials.

### Archival data scope (design pin — gates legal, FAQ, and challenges)

Three **distinct** data sets appear in archival discourse; conflating them
makes user-facing retention claims unverifiable. This pin names each set,
who retains it, what challenges verify, and what each promise depends on.
Cross-ref: `docs/design/CURVE_TREE_CLIENT.md` §7.6 (one schema, footprint
varies).

| Set | Contents (normative) | Typical holder | Challenge verifies |
|---|---|---|---|
| **A — Wallet-minimum** | Sub-root frontiers (`R_k`), **owned-output chunks** (once scanned), active (unpruned) frontier segment — enough to forward-sync and assemble **your** spend paths | Every syncing wallet / lean node | **Not** archiver retention challenges |
| **B — Deep archival shard** | Full CT **segment leaves** per shard plus per-shard **canonical auxiliary** (headers, transactions, and per-height tree roots in the shard's position range) needed to construct **FCMP++ historical reference proofs** (Merkle path from a random leaf position to **`R_k`**) | Market archivers (subset of shards); foundation **`CompleteTree`** (all shards) | **Yes** — retention-proof challenges sample shard *s* and verify path to `R_k` from held material |
| **C — Full canonical block corpus** | Complete canonical **blocks and transactions** for chain history — output discovery, amount decryption context, rescan from seed, audit trail | Foundation complete archive; full nodes may retain; market archivers hold **C for their shard ranges** as part of shard auxiliary | Indirectly — pruning safety and wallet rescan depend on **C** being retrievable somewhere durable |

**What "complete tree" means.** Foundation and archiver **`CompleteTree`**
registrations commit to **all of B across all shards** (the deep archival
substrate), **not** "curve-tree structure alone." The curve tree is
commitments and proof paths (set **B**); it is **not** interchangeable with
**C** (full blocks/txs) or **A** (your wallet's already-scanned outputs).

**User-facing promise mapping (load-bearing):**

| Claim | Depends on |
|---|---|
| **Permanent retention** (hard) | **B + C** for all canonical history — deep proof substrate **and** block/tx corpus needed for rescan, audit, and dispute backstop |
| **"Your old transaction history won't disappear"** | **C** retrievable for rescan + wallet persistence of **A** after scan; **B** for spending with old reference blocks / deep proofs — **not** satisfied by **B alone** (proof-state-only archive cannot reconstruct full wallet history from seed) |
| **Auditable foundation floor** | Foundation **`CompleteTree`** holds **B + C** in full; public fetch + challenge pass/fail on **B** |

**Normal nodes vs archivers.** A non-staker wallet retains **A** only and
**prunes** deep segment leaves to `R_k`. Archivers retain **B** (and the
shard-scoped **C** auxiliary their challenges and serving require). The
foundation floor retains **B + C** completely. Market redundancy (set **B**
and shard-local **C** above the floor) is the decentralization trajectory;
the floor is the disclosed durability anchor for **B + C**.

**Legal / FAQ inheritance.** User-facing copy must **not** say "complete
archival tree" when meaning "everything needed to restore your wallet from
seed" unless **C** is included — say **complete deep archival substrate plus
canonical block history**, or cite this table. Counsel and
`docs/PUBLIC_NARRATIVE_FAQ.md` lock only after this pin.

### Durability guarantee — foundation floor + market redundancy

**Public anchor (foundation).** The durability number users and operators
should cite is the foundation's **managed complete archive**: *N*
replica-complete trees across diverse providers and jurisdictions,
actively maintained and restorable — the same shape as any serious
managed archive (many nines), **not** the market sim's internal
`D*=0.999` target. Quoting `0.999` publicly on irreplaceable data is
both alarming and wrong: it anchors the promise on the unobservable
anonymous layer.

**Additive market layer.** Market archivers provide **decentralization
and redundancy above the floor**, not the floor the promise rests on.
Decentralization means **the market grows to dwarf the floor** — not that
the foundation withdraws. There is **no sunset** that de-privileges
foundation seed archivers: that would reintroduce mutable governance
("who triggers sunset?") and gap risk if the market lags. The privilege
is **permanent but benign**: genesis enumeration grants **`CompleteTree`
durability credit** only; no market reward; real challenges, public
pass/fail — no economic extraction path.

#### Foundation complete-tree seeds (first subsection — the guarantee's base)

Foundation **seed nodes are seeds of the tree, not just of discovery:**
each holds **complete sets B + C** (deep archival substrate and canonical
block history; §*Archival data scope*) from genesis, at **known**
locations (Tor-client fetch to public addresses — not six-hop hidden-
service rendezvous for the fetch leg). They provide:

- **Durability floor** — observable, placement-controlled correlated-loss
  tail (you choose providers/jurisdictions; location-hiding does not
  apply here).
- **Bootstrap source** — real complete tree before any market archiver
  seats (L12 cold-start closes against a source, not a synthetic decay
  alone).
- **Fast seeding source** — new archivers backfill from public complete
  copies; onion rendezvous remains for **serving anonymous queriers**, not
  for fetching from a public foundation source (soundness pass step 2
  scope shrinks accordingly).
- **Fee-era backstop** — always present when the market thins (replaces
  L12 **decaying** floor — see gate-list item 5 amendment below).

**Accountability.** Foundation archivers are **registered and
challengeable** — public challenge pass/fail is the accountability
mechanism. They are **fully excluded from archival reward claims** (no
reward path exists). Reputational failure on a public challenge is the
binding deterrent for a known entity; the slash amount is not the
economic lever.

**Nominal uniform bond (pinned — not zero).** Each **active** genesis
foundation identity posts **one** retention bond at **`ARCHIVAL_BOND_FLOOR`**
(the same minimum valid per-shard bond floor pinned at gate 4), **once per
archival pseudonym `P`**, not per shard. This is **not** skin-in-the-game
economics — it is the price of keeping the foundation on the **single
uniform holding + challenge + slash path**. Zero bond would require a
`foundation → skip slash` branch in consensus-critical slash code;
rejected. On failed challenge the **standard slash path runs** — see
**`CompleteTree` slash semantics** below — removing the nominal bond and
**unbonding** the `P` until it re-posts.

**`CompleteTree` slash semantics (consensus chain — same code path, explicit
post-slash state).** A market holder with `ShardSetCompact` failing shard *s*
loses **that shard's bond** and remains bonded on other shards. A
**`CompleteTree`** holder has **one** nominal bond for the entire tree; a
failed retention challenge on **any** sampled shard:

1. **Slashes the whole bond** (`ARCHIVAL_BOND_FLOOR` in full — not
   `FLOOR/shards`, which would be a no-op slash and **skip-slash in disguise**;
   rejected explicitly).
2. **Clears the bonded holding** — `P` is **unbonded** (the state zero-bond
   was designed to avoid).
3. **Removes `P` from `durability_count`** until it **re-posts bond** and
   re-activates through the normal registration path.

Re-bonding is the only resume path; there is no partial bonded state for
`CompleteTree`. **`N_active = 3`** at genesis pin (see
`docs/design/FOUNDATION_GENESIS_IDENTITY_SET.md` §9.1) is sized so **one**
failed sample knocks **one whole seat** out of the durability floor until
re-bond — margin is **challenge-failure absorption**, not only geographic
diversity.

**Holdings wire (complete tree without state bloat).** Foundation seeds
register **`CompleteTree`** on the general `HoldingsDescriptor` (one
sentinel = holder of all shards), **not** O(shards) per-shard bond rows.
See `docs/design/FOUNDATION_GENESIS_IDENTITY_SET.md` §4. **`market_R`**
does not count `CompleteTree` holders (`Market` membership excludes foundation).
**`durability_count`** counts each **bonded-and-good-standing** genesis
`CompleteTree` slot for every shard — see replication table below.

**Reversion (bonding — ordered):**

1. **Now:** nominal **`ARCHIVAL_BOND_FLOOR` × 1** per active genesis `P`,
   uniform across the set; standard slash path.
2. **Never:** zero bond with skip-slash branch.
3. **Never:** per-shard bond rows for foundation complete-tree (state-bloat
   path to a foundation-only holding type).

**Reward economics — fully outside the formula.** Foundation archivers
draw **no slice** of the market reward pot and do **not** enter scarcity
denominators. The entire pot flows to the market; the foundation is a
pure reputational durability floor (counted for durability and audit,
present in the challenge path, **invisible to all reward math**). Partial
exclusion (out of denominator but earning on nominal stake) is rejected —
it buys a foundation-earnings line item with no benefit.

### Genesis-enumerated foundation identity set (immutable)

**Consensus block:** `docs/design/FOUNDATION_GENESIS_IDENTITY_SET.md`
(schema, placeholder table, bond floor, `HoldingsDescriptor` / `CompleteTree`
pin). Wallet **payment addresses are not enumerated** — only archival
pseudonym **`P` pubkeys** (V3.0 payment-address shape is pinned separately;
FA-1 single static address backs stake off this block).

The privileged set is **enumerated in genesis** — maximally transparent,
undeniable, auditable. Membership confers **one** distinctive protocol
consequence (see replication table): genesis enumeration is required for a
**`CompleteTree`** holder to count in **`durability_count`** for all shards.
All other properties (`CompleteTree` descriptor, nominal bond, reward
exclusion, challenge path) follow from the **general** archival model — any
`CompleteTree` registrant gets them; only durability credit for the full tree
requires genesis membership.

- **`durability_count`** credit for **`CompleteTree`** (all shards) — **genesis
  slot only**, when bonded-and-good-standing.
- Challenge path — **general** (any bonded archiver).
- **`market_R`** — **not** a membership check; see descriptor rule below.

This is the concrete form of "our security includes the foundation" —
same trust class as hard-coded seed discovery keys, not a hidden flag.
**Irreversible without fork:** even if the market eventually dwarfs the
seeds, protocol privilege remains; vestigial-but-benign is acceptable
because privilege is non-extractive and verifiable.

#### Key rotation — over-enumeration (pinned at genesis)

Immutability of the enumerated set does **not** mean operational keys
never rotate — compromise, hardware lifecycle, and handoff require it over
a multi-decade horizon. A compromised operational identity **lingers** as a benign ghost (failing
public challenges, **unbonded after slash**, absent from `durability_count`
until re-bond) — detectable, not revocable without a fork.

**Pinned resolution: pure over-enumeration.** Genesis lists **more
identities than initially operated** (several times the live count; cap
non-binding over the chain's life). Reserve slots are cold keys; rotation
**activates a reserve** by that identity beginning to stake and serve
through the normal path — **no authorization chain, no delegation
verification, no new consensus primitive.** Pubkeys in genesis are nearly
free; reserve keys use the same cold-custody discipline as release-signing
material.

**Why not master + operational subkeys.** A cross-authorizing master
reintroduces mutable membership and a systemic tail: master compromise
mints arbitrarily many `market_R`-excluded, `durability_count`-included
identities — durability credit without backing — with no clean revocation
short of fork. Over-enumeration's worst case is bounded and recoverable:
one compromised slot burns one reserve activation.

**Reversion (explicit, ordered):**

1. **Now:** pure over-enumeration.
2. **If rotation frequency makes slot-burning impractical:** per-root
   subkey hybrid — each genesis identity authorizes **only its own**
   subkey lineage (cold root / warm leaf); **never** a cross-minting
   master.
3. **Never:** cross-authorizing master.

Hitting the enumeration cap after pathological rotation frequency is a
key-management crisis; a fork to refresh the foundation set decades out
is an acceptable governance checkpoint, not a design failure.

### Replication count — `market_R` vs `durability_count` (disambiguate before code)

**`R` now names two different quantities.** Using one symbol for both is
a silent bug farm: reward paths that accidentally use `durability_count`
re-introduce foundation crowd-out; availability or pruning checks that
use `market_R` under-count and behave incorrectly.

| Symbol | Definition | Foundation / `CompleteTree` |
|---|---|---|
| **`market_R(shard, E)`** | At epoch close: count of **market** archivers `P` with `serve_credit_bit(P,s,E) ∧ good_through(P,E)` — **derived** from the serve-credit ledger keyed by public `P_id` ([`design/ARCHIVAL_CONSENSUS_STATE.md`](design/ARCHIVAL_CONSENSUS_STATE.md) §3.3). **No** `ν = H(P, shard)` primitive — incompatible with form **C** per-`P` cap grouping. | **`CompleteTree` / foundation excluded from `Market`** — absent from count by membership rule, not a nullifier shortcut |
| **`durability_count(shard)`** | Distinct **bonded-and-good-standing** archivers covering *s* | **`CompleteTree` + genesis-enumerated active slot → covers every shard**; market **`ShardSetCompact`** holders cover *s* iff set includes *s* |

**Good standing:** bonded retention commitment posted; not **unbonded** after
slash; most recent challenged sample for the holder passed (or within grace
per challenge cadence — exact window pinned at gate 4). A compromised ghost
that keeps failing challenges is **unbonded or not good-standing** and **does
not** inflate `durability_count`.

**Every consumer must declare which count it reads** (spec-first; the
two-implementations trap in a new costume):

| Consumer | Count | Notes |
|---|---|---|
| Scarcity pricing `∝ 1/R` | **`market_R`** | BitTorrent market signal |
| Per-shard reward / `Curve(Σ work)` inputs tied to scarcity | **`market_R`** | Foundation earns nothing |
| `Σwork` supply servo denominators | **`market_R`-derived work only** | Foundation invisible |
| Coverage / `R_target` obligation for **market** archivers | **`market_R`** | Foundation is extra floor |
| Durability SLA / audit / "is the complete tree held?" | **`durability_count`** | Includes foundation |
| Decentralization observability ("market vs floor") | **Both**, reported separately | Edge #2 — loud not silent |
| Local pruning / "safe to drop local copy?" | **`durability_count`** (or explicit policy) | Must not assume `market_R` alone suffices |
| Challenge / retention-proof accounting | **Per-holder**; aggregation for display uses context-appropriate count | Never shard-global read credit (L14) |
| **Reachability / "up now" (L15/L16)** | **Not a protocol count** | **Sim evaluation only** (`shekyl-staking-sim` `serving_availability`, `u_eff`). Production: holder discovery (try-list) + public foundation seed reliability — no third `R`-like symbol. If routing-quality scoring ships, it is **per-holder latency/performance**, not a shard-level reachable-now count. Seeding SLO source-availability is an **operational** metric (ops dashboards), not consensus state. |

Implementations must not expose a bare `R` without naming which count.
**Verification (2026-06):** `market_R` and `durability_count` are spec
pins pre-`ArchivalEngine`; no production Rust/C++ site computes L15/L16
reachability aggregates — the two-count table is complete for protocol
code paths today.

### Maintenance SLO (archiver class — not user promise)

Archivers seeding or backfilling deep shards should meet a **bounded
seeding latency** internal target (L10 timing channel). User historical
queries do not inherit that bound. Transport for seeding may differ from
user query transport (soundness pass step 2 — largely reduced if fetch
is from public foundation complete copies).

---

## The mechanism

### BitTorrent-style scarcity-priced commons coverage

Chain state is partitioned into **shards** — deterministic ranges of
blockchain history (e.g., curve-tree state for blocks 100,000–110,000,
plus the transactions and per-height tree roots needed to construct
historical reference proofs against any block in that range). Granularity
is tunable; per-epoch (~10,000 blocks) is the candidate scale.

Stakers archive shards. The archival commitment is **part of the staking
protocol itself**, not a separate service layer. The staking software
*is* the archival client. There's no "run an archival node alongside your
wallet"; if you stake, you archive.

Reward per shard is **inversely proportional to current market
replication count** (`market_R`; see §*Service promise* — foundation
replicas excluded). A shard held by 1 market archiver pays the maximum
per-byte rate; a shard held by 5 market archivers splits a smaller pool.
Rare shards pay more than common shards. Stakers actively hunting for
under-served shards earn more than stakers piling onto popular ones.

This is the BitTorrent insight applied to chain archival: distributed
coverage emerges from individual rational decisions when the price signal
is right. The protocol prices; it doesn't allocate.

### Quick-pick: opt-in market participation

Not every staker wants to play the rare-shard market. Tier-1 yield-seekers
who locked 1,000-block tier-1 stakes may have no interest in archival
strategy. **Quick-pick allocation** handles this: the staker opts into a
default allocation, the protocol assigns them a balanced portfolio of
shards (mix of common/rare, recent/historical, weighted to roughly
average market reward), and they earn average archival yield without
having to make decisions.

Active stakers opt out of quick-pick and pick their own shards. The two
classes coexist:

- **Active stakers**: hunt rare shards, earn premium archival yield, do
  the work of optimizing coverage.
- **Quick-pick stakers**: take the default allocation, earn average yield,
  do no optimization work.

Quick-pick has a useful secondary property: **its allocation algorithm is
the protocol's coverage backstop.** If active stakers are over-clustered
on rare-recent shards, quick-pick can be tuned to compensate by allocating
passive stakers more heavily to under-served shards. The passive class
becomes a tunable lever for uniform coverage, controlled by the protocol
designer rather than emerging purely from the market.

The lottery quick-pick analogy: same shape. Don't care about which numbers?
Take the auto-pick. Network gets the same participation either way.

### Verification: challenge-response

Stakers periodically receive on-chain challenges for shards they claim.
Challenge format: "produce the Merkle path for block H's curve tree root
showing leaf X." The path is cheap to verify on-chain (the network already
has the root). Failure to respond within a window slashes the *archival
reward* (not the principal stake; see "decoupling" below).

The verification doesn't try to detect "lazy storage" (re-fetching from
peers on demand). Instead, the protocol routes archival queries from
wallets to whichever stakers are *actually serving them efficiently* —
challenge response latency is tracked, and stakers with consistently
high latency lose query routing. Lazy storage stakers naturally lose to
honest-storage stakers in any shard with real demand. The market handles
laziness.

### Decoupling: archival reward separate from principal yield

> **Superseded in steady state by *Pay-for-service rebasing* below (pending
> sim/soundness ratification).** The two-stream framing here — an unconditional
> consensus-bond yield *plus* an additive archival stream — assumed staking
> renders a consensus service worth an unconditional yield. The enumeration in
> *Pay-for-service rebasing* shows it does not: archival is the only service, so
> the streams collapse into one work-paid reward and the unconditional
> `staker_emission_share` is retired (subject to the bootstrap caveat). The one
> property below that **survives unchanged** is *principal is never slashed* —
> it is load-bearing in both framings (resilience under archival stress) and is
> kept verbatim. Read the rest of this subsection as the decision history that
> led to the rebasing, not the current target.

Critical design property: **archival performance does not slash
principal.** A staker with archival outages loses archival yield only.
The principal stake's consensus-bond yield (the existing
`staker_emission_share=15%` from the V3 economy) flows regardless.

Why this matters: slashing principal for archival failures would create
perverse incentives. Stakers with infrastructure problems would unstake
rather than risk principal, and the network would lose both their security
bond *and* their archival capacity simultaneously. Decoupling preserves
the security model under archival stress.

In V3 economy structure terms:

- **V3.0 ships**: `staker_pool_share=25%`, `staker_emission_share=15%`,
  `staker_emission_decay=0.90/year`. Principal bond yield. Unconditional.
- **V3.x adds (this mechanism)**: archival reward stream. Conditional on
  archival performance. Funded from a separate slice (see "Funding"
  below).

A staker doing both consensus-bonding and archival earns the sum. A staker
doing only consensus-bonding (archival outage, intentionally passive,
not opted in) earns only the principal yield. The two yield streams are
additive and independent.

The actor-architecture decision-log entry locks this property
structurally as well: `StakeEngine` (Stage 3, principal yield) and
`ArchivalEngine` (Stage 5, archival yield) are sibling actors with
independent slashing domains. A bug in archival logic that slashes
archival-yield cannot be misrouted to slash principal-yield, because
the actors do not share state — the cross-actor query
`StakeEngine::is_active_staker(entity_id) -> bool` gates archival
eligibility, but the response is authoritative and there is no shared
mutable state for a bug to corrupt.

### Tier interaction: lock duration as archival commitment depth

> **Superseded in steady state by *Pay-for-service rebasing* below (the keystone /
> gate 4).** The tier-weighted pricing described here is the **tier oracle**
> F-ARCHIVAL identifies: it makes the public shard-set Bayesian evidence of the
> backing stake's tier. The rebasing **deletes the staker tier** and recovers the
> deep-history retention-horizon matching it provided with a **slashable per-shard
> retention bond** — *not* with demonstrated-longevity, which is a past signal that
> cannot bind future retention (an earlier draft proposed longevity-pricing for this
> and is corrected by the keystone). Read this subsection as the rationale for the
> property the per-shard bond must reproduce (deep-history retention-horizon
> matching), not the current target.

The existing tier system serves double duty.

- **Tier 1** (1,000-block lock, 1.0× yield): short-lock, can hold ephemeral
  shards, but archival commitment is shallow. Best for hot-set archival
  (recent, frequently-queried, low-rarity).
- **Tier 2** (25,000-block lock, 1.5× yield): medium-lock, medium
  archival commitment. Mixed roles.
- **Tier 3** (150,000-block lock, 2.0× yield): long-lock, deep archival
  commitment. Best for critical-history archival (deep, rarely queried,
  high redundancy value).

The shard pricing should reflect this: a shard held only by tier-1 stakers
(short locks, frequent turnover) is structurally riskier than a shard held
by tier-3 stakers at the same nominal replication count. The reward
formula should weight by tier, naturally driving critical-history shards
toward long-tier holders.

This is elegant because it means the *shape* of the staker class matters
for archival, not just the count. Tier-3 stakers become the network's
long-term archivists; tier-1 stakers are the marginal hot-set. The economy
already created these tiers; archival uses them.

**Privacy cost of this elegance — the portfolio becomes a tier oracle.**
Because tier sorts onto shard type (tier-1 → hot/recent, tier-3 →
deep/historical, reward weighted by tier), **which shards a staker holds is
strong Bayesian evidence of their tier.** This is a tier-disclosure channel
*entirely separate from* the confidential-staking claim wire — and it is the
channel the share feature (`docs/V3_SHARD_VISUALIZATION.md`) gamifies stakers
into advertising. Two consequences, analyzed in
`docs/design/PHASE_2B_STAKE_LIFECYCLE.md` §7.5.3 (finding **F-ARCHIVAL**): (1)
the claim-wire tier and this archival tier-weighting are **separable levers** —
**whole-system tier privacy requires weakening both**, so de-tiering the claim
alone would *not* close the tier leak while this coupling exists and portfolios
are observable; (2) whether this fires for *every* staker on-chain or *only* for
self-sharers depends entirely on the commitment-binding question below. Weakening
the tier-weighted pricing (toward tier-blind pricing or quick-pick-dominant
allocation) is an explicit **economics-vs-privacy** choice: it trades the
tier-archival alignment for portfolio privacy. Tracked as a Stage-5 design-review
item alongside the binding decision.

### Privacy: mandatory anonymization on queries

Open concern. A staker serving "wallet at IP X queried block H's curve
tree state" learns that wallet X is constructing a transaction with
reference block H. That's metadata FCMP++ specifically protects against;
distributing archival to many stakers means many parties have query
metadata.

**Defense (V3 ships):** mandatory Tor / I2P / mixnet routing for
archival queries. The wallet routes queries through anonymizing
infrastructure before reaching the staker. This is consistent with
Shekyl's existing privacy stance (the chain already supports Tor for
daemon connections per `docs/ANONYMITY_NETWORKS.md`). The cost is
latency, which is acceptable for archival queries (they're not in the
transaction-broadcast hot path).

**Stronger defense (post-V3-ship, optional):** wallets query for cover
traffic in addition to actual queries. The staker can't infer which
historical block the wallet actually needs. More expensive but stronger.

For V3.x ship of the archival mechanism, mandatory Tor/I2P is
sufficient. The privacy story for distributed archival is *better* than
foundation-only archival, because trust is distributed across stakers
(no single trusted operator) rather than concentrated.

**Second-order concern — self-advertisement bridges identity to the
claim cohort (cross-track to staking privacy).** This is separate from
query metadata. Two archival-side surfaces compose adversarially with
the confidential-staking claim-cohort leak analyzed in
`docs/design/PHASE_2B_STAKE_LIFECYCLE.md` §7.5.3 (finding F0): (1) the
**on-chain holder registry** candidate for "Query routing protocol"
(below) publishes which staker holds which shard; and (2) a staker's
**held shard-set is distinctive** for active rare-shard hunters. Because
shard visualizations are *designed to be shared*
(`docs/V3_SHARD_VISUALIZATION.md`, "print/share rendering"), a staker who
posts their portfolio bridges real-world identity → on-chain holder →
(composed with F0's revealed `tier`/`creation`) their claim cohort.
Tier-role legibility (tier-3 = deep archivist) lets ordinary bragging
leak `tier` for free. The mitigation is not more query anonymization;
it is a **privacy review of the holder-registry shape and the share
feature against claim-cohort linkage** before `ArchivalEngine` /
`shekyl-shard-visual` ship. Tracked in `docs/FOLLOWUPS.md` under the
F0 V3.1 entry. The query-routing design choice (DHT/registry vs. gossip,
below) should weigh registry-published holder presence as a privacy cost,
not only a routing-efficiency tradeoff.

**Commitment binding: public address-bound vs. privately membership-proof-bound
— RESOLVED IN DESIGN (private, firewalled pseudonym), pending sim/soundness
ratification.** The section above (and the V3 ship default) covers only *query
metadata*. It does not, on its own, decide how the archival *commitment* — "I
archive shard X, I earn the reward" — binds to identity, and that gap was the
highest-value open privacy item in the staking/archival surface
(`docs/design/PHASE_2B_STAKE_LIFECYCLE.md` §7.5.3, finding **F-ARCHIVAL**). It is
resolved below in *Pay-for-service rebasing and the firewalled-pseudonym identity
model* — **private**, via a membership-proof-registered pseudonym, subject to the
gate-list there. The remainder of this subsection records the question and the
presumption that drove the resolution. The existing draft mechanisms **lean
public**: on-chain
challenge-response to "shards they claim," an on-chain holder registry ("each
shard's holders publish presence"), and reward routing to identified servers.
The two outcomes are not close:

- **Public address-bound** ("address A archives shard X, A earns the reward"
  on-chain): combined with *mandatory* archival and tier-sorted shards (above),
  **every staker's membership and approximate tier become public by
  construction**, with no sharing required. This would be a larger staking-privacy
  leak than the claim wire itself.
- **Privately membership-proof-bound**: the commitment proves "a bonded stake of
  mine covers shard X" *without* revealing which stake or address; rewards route to
  **stealth outputs**; the archival identity is **HKDF-separated** from the
  claim/spend identity. Only stakers who *choose* to share expose themselves; the
  chain-side confidential-staking work retains its value.

**Presumption = private**, on architectural consistency: the rest of staking is a
privacy-first membership-proof + nullifier + stealth model, and public binding
would be the inherited "easier to count if public" convenience. The pattern is
not exotic — data availability is a public good answerable by anyone holding the
shard; only *reward eligibility* needs identity, and that can be proven privately,
exactly as claims are. **The hard part is private replication counting:** scarcity
pricing needs a per-shard distinct-**market**-holder count (reward ∝ `1/market_R`;
see §*Service promise* — `durability_count` is a different symbol), and counting
holders *without identifying them* (private set cardinality / proof-of-distinct-
holders) is the non-trivial primitive public binding gets for free. That is the
cost a private design must solve, and it does not move the presumption.

This decision **gates** the confidential-staking `W`-bucketing `W`-choice (a
non-sharer's bucketing privacy is undone if archival publishes their membership
and tier regardless). Decide it **before `ArchivalEngine` ships** and consistent
with the claim-privacy posture; the pre-genesis discount favors designing private
binding from the start over retrofitting it. Tracked in `docs/FOLLOWUPS.md`.

---

## Pay-for-service rebasing and the firewalled-pseudonym identity model

**Status: intended steady-state design (F-ARCHIVAL resolution). Supersedes the
two-stream / consensus-bond framing in *Decoupling* and the tier-elegance in
*Tier interaction* above. Gated on the simulation work and a fresh soundness
pass (the gate-list at the end of this section) before it is consensus-real.**

**Why this is a genesis-class decision, not a deferrable privacy refinement.**
Capital-bonded yield has **no justification in the fee-only era**: paying new
emission to lock idle coins is precisely the rent `00-mission.mdc` forbids, and it
is the one part of the staking design that *cannot re-justify itself* once the
block subsidy ends. Archival demand and its burn-redirect funding both persist past
the subsidy; capital-bonded yield does not. So this is not a refinement that could
land in V3.x — it is the version of staking that survives the chain's own lifecycle
(now / mining-era-end / fee-only), which is what makes pre-genesis the right (and
bounded) time to obsolete the partially-built confidential-yield subsystem.

This section follows the *Problem 1* enumeration ("what useful work do stakers
do?") all the way down and changes the answer's shape. The earlier draft answered
"decouple two kinds of work and pay two streams." Walking every candidate service
staking could provide shows there is only one, which collapses the two streams
into one and — as a free consequence — dissolves two of the hardest
confidential-staking privacy/soundness findings (F0 and F-INFLATION's 8a).

### Archival is the only service staking provides

Enumerating every candidate, the others are not services staking renders:

- **Consensus security — no.** Shekyl is a PoW chain. RandomX mining provides
  Sybil resistance, block production, fork choice, and difficulty. Staking has no
  block-production role, no finality gadget, no fork-choice weight, no checkpoint
  authority — which is exactly why the classic-PoS attack family was retired
  (`PHASE_2B_STAKE_LIFECYCLE.md` §7.5.3). Staking contributes zero to the property
  PoS systems invoke to justify staking.
- **Capital-at-risk "security bond" — not a service, and weaker than the label.**
  A bond secures something only if it is *slashable for the misbehavior it bonds
  against*. Here the principal is slashable for **nothing**: consensus is not
  staking's job, and the *Decoupling* design explicitly keeps archival failure off
  the principal. A bond that cannot be slashed for any network failure is not
  bonding anything; it is locked coins. (The keystone below restores a *genuinely*
  slashable bond — the **per-shard retention bond** — which bonds the actual
  service, distinct from the never-slashed principal. So capital does not leave; it
  is re-based from idle-principal-yield to slashable-per-shard-collateral.)
- **Supply / monetary effects — real, but not a service, and the machinery is not
  needed for it.** Locking coins reduces circulating supply, but *anyone* achieves
  that by not spending — no claims, tiers, nullifiers, or membership proofs
  required. The only thing the staking apparatus adds over just-holding is the
  reward; the reward therefore needs a justification holding-quietly does not get.
- **Governance signaling (lock-tier → emission) — downstream and parasitic.** A
  feedback loop the economy reads, not a service the network needs provided. It
  exists only because staking exists for some other reason, so it cannot *be* the
  reason.

The enumeration bottoms out at archival: the one genuine, growing, structural
network need staking fills — historical curve-tree state served on demand so
FCMP++ proofs against the 100-block window keep working as the chain outgrows full
retention. So the staking reward **is** payment for the archival service, and
"stake without archiving" is being paid for nothing — the exact *Problem 1*
rent-seeking this whole design set out to kill. **Opt-out staking is therefore
incoherent** (it re-creates the disease), and there is **no opt-out privacy
tier** to design; staking privacy is won inside the firewalled-pseudonym model,
not via an escape hatch that should not exist.

### One staker type, one reward, principal as collateral

- **One staker type: an archiver.** "If you stake, you archive" becomes load-bearing
  rather than aspirational.
- **One reward: performance-scaled payment for the service** (retention-based,
  scarcity-weighted; curve shape below). The two additive yield streams of
  *Decoupling* collapse into this single stream; the unconditional
  `staker_emission_share` consensus-bond yield — payment for no service — is
  retired (subject to the bootstrap caveat in the gate-list).
- **Principal becomes locked collateral, not yield-bearing-for-being-a-bond.** It
  always returns at unlock and is **never slashed** (preserving the resilience
  rationale of *Decoupling*: an infra outage costs reward, not principal, so a
  staker does not rage-unstake). The lock stops being a yield multiplier and becomes
  a **small eligibility gate** only. The Sybil cost and the deep-archival commitment
  are carried **not** by the lock but by the **per-shard retention bonds** (the
  keystone, below) — which is what *de-overloads* the lock: the lock can stay small
  (the monetary supply-sink knob) while the bonds scale (the anti-hoard / anti-Sybil
  capital), two separate parameters instead of one pulled two ways.

### The firewalled-pseudonym identity model

Archival **cannot** be made unlinkable the way a claim is, and stating that plainly
rules out the obvious wish. A claim is a one-shot event that proves membership and
vanishes; archival's function is the *opposite* of ephemerality — wallets must
**find** the holder to fetch block *H*'s tree state, and the protocol must
**challenge the same holder for the same shards over time** to prove retention.
Reachability + persistence + challengeability = a stable, discoverable identity.
You cannot hide *which holder* the way you hide *which leaf*, because the point is
to keep asking the same holder. So anonymity is off the table by function; the
achievable goal is a **firewalled pseudonym** — a long-lived archival identity
cryptographically, network-, timing-, and output-isolated from the
spend/claim/principal identity, whose unavoidable public surface leaks nothing past
"some pseudonym holds these shards."

**Transfer-shaped admission (leading genesis form — see
[`PHASE_2B_STAKE_LIFECYCLE.md`](design/PHASE_2B_STAKE_LIFECYCLE.md) §2.4).**
Replace `StakeEngine::is_active_staker(entity_id)` with firewalled **`P`** keyed off
the **bond record** (gate 4), not a linkable stake lookup.

**Two irreducible consensus-special surfaces:** per-shard **bond** (slashable,
consensus-tracked) and **reward emission** (mint authorized by public work +
membership-only backing). Stake-in (principal → `P`) and unstake-out (`P` →
principal) are **ordinary FCMP++ main-tree transfers** — firewall = base privacy.

- **`P` is an independent keypair, HKDF-derived from the wallet seed** — not an
  algebraic offset of the principal key; dual scan (principal + `P`).
- **Admission funding (no consensus role — gate 7 closed bonds-only 2026-06-11):**
  ordinary transfer to `P` on the main tree with **no consensus minimum**
  ([`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md) §10.2;
  [`design/STAKER_ARCHIVAL_SIM.md`](design/STAKER_ARCHIVAL_SIM.md) ledger G7); funding
  amounts are gate-6 §2.5 wallet hygiene only. Decision **3C** staking subtree is
  **not** shipped for genesis.
- **Off-chain backing before first reward:** `P` must be a known, serving, backed
  archiver **before** earning — peers present/observe backing off-chain; otherwise
  spam or ignored challenges. The **first on-chain reward emission** anchors bond
  state (holdings + claimed-epoch bitmap) — there is **no** separate registration
  transaction; fusion removes the tx, not the event.
- **Reward emission crypto:** FCMP++ **membership-only control** at settlement-epoch
  cadence (prove backing, **no** key image in spent set). **No published
  reward-dedup tag** — `N_arch = x·G_arch` is **rejected** (stake-keyed tags
  collide under shared admission stake and do not dedup epochs). **Double-claim
  prevention** = per-`P` **claimed-settlement-epoch set** on the bond record
  (`check_and_set(E)` semantics; sparse absolute epochs — see
  [`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md) §6), reorg-reverted
  with `pop_block`. **`R_market`** is a **derived ledger count** (gate 3 dissolved —
  no `ν` primitive; see [`design/ARCHIVAL_CONSENSUS_STATE.md`](design/ARCHIVAL_CONSENSUS_STATE.md)
  §2). **Wire + verifier:** [`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md).
- **Intra-epoch unbacked window:** between emissions (~one settlement epoch),
  backing is not re-verified on-chain; `P` may spend admission principal after a
  payout. This is safe **only because challenge failure slashes bond** regardless
  of admission state — **bond, not stake-tree, is the maintained anchor.**
- **Sybil-resistance** lives in **per-shard bonds** (total bond = shards × rate),
  not `P`-uniqueness or a published archival nullifier.

Net on-chain: **P ↔ shard-set ↔ performance is public; principal link is hidden by
transfer privacy + gate 6 firewall.** Crypto novelty on the reward leg is
**membership-only control** (subtraction from today's verify) — not
ClaimLinkability / non-spending SAL sibling — when dedup is state-based.

### Tier-neutral shard pricing — breaking the tier oracle

Even firewalled, P's shard-set is public, and the *Tier interaction* tier-weighted
pricing makes that shard-set a **tier oracle**: a deep-historical portfolio
Bayesian-signals a tier-3 backing stake, re-leaking the exact tier the
confidential-staking claim wire spends effort protecting (F0) and narrowing which
stakes could back P. The fix is **tier-neutral shard pricing** — price purely by
replication scarcity (the BitTorrent insight), so any tier profitably holds any
shard and the sorting disappears.

But tier-weighting was buying something real: **a credible commitment to
long-horizon retention of critical (deep-history) shards.** An earlier draft of
this section proposed recovering that with a **demonstrated-holding-longevity**
premium; that is **insufficient and is corrected below.** Longevity is a *past*
signal — it prices observed stability — but deep history needs a commitment to
*future* retention, and past stability does not guarantee it (a long-time holder
can drop a shard tomorrow). Observed longevity can still feed the scarcity/coverage
signal, but it **cannot carry the deep-history guarantee.** The keystone that can
is a per-shard bond.

### Per-shard retention bonds — the keystone (deep-history guarantee + Sybil cost + de-overloaded lock)

The deep-history commitment does **not** have to be a staker-wide property (a
tier). Make it **per-shard**: holding a deep-history shard requires posting
**slashable collateral against retaining it for a duration.** Drop the shard inside
the window → lose the bond (the *archival* bond only — principal stays
never-slashed, bounded and voluntary, consistent with *Decoupling*'s resilience
rationale). Three things fall out of one mechanism:

- **The deep-history guarantee becomes real, not inferred.** A bond at risk is a
  credible commitment to *future* retention — exactly what demonstrated-longevity
  could not provide. This is the property tier-weighting was actually buying,
  recovered honestly.
- **The staker-wide tier disappears, so F0 dies and the oracle dies with it.** With
  no principal tier driving shard allocation, there is no `tier_num` for the claim
  wire (F0) and the public residual is "**pseudonym P holds these shard-types**,"
  firewalled — *not* a stake-cohort key. The tier oracle (F-ARCHIVAL coupling #2)
  closes because per-shard bonds replace the tier, **not** because tier "falls out
  for free."
- **Sybil-resistance inverts in our favor (G-E).** The bond is the Sybil cost, and
  **total bond = shards-held × rate, independent of how many pseudonyms you split
  into** — you bond per shard whether you are one identity or ten thousand. So
  Sybil-splitting buys nothing, and the scarce, security-relevant input **flips back
  from cheap-invisible storage to expensive-countable capital**, Sybil-immune
  because it scales with work.

This **de-overloads the lock parameter**: the eligibility lock can stay small (the
monetary supply-sink knob you want small), while the **per-shard bonds** are the
anti-hoard / anti-Sybil capital cost (the thing you want to scale). They are now
**two separate parameters** instead of one pulled two ways.

**Holdings descriptor (wire pin — pre-`ArchivalEngine`).** Registration carries
`HoldingsDescriptor`: either **`ShardSetCompact`** (partial portfolio) or
**`CompleteTree`** (one sentinel = all shards). **`market_R`** is the **derived
ledger count** at epoch close ([`design/ARCHIVAL_CONSENSUS_STATE.md`](design/ARCHIVAL_CONSENSUS_STATE.md)
§3.3) — **`ShardSetCompact`** market holders with `serve_credit_bit ∧ good_through`;
**`CompleteTree`** / foundation identities are **excluded from `Market`**, so they
never appear in `market_R` **without any foundation flag on the pricing path**. Market archivers
use per-shard bond accounting (`total bond = shards × rate`). Genesis
foundation identities use **`CompleteTree`** plus **one nominal bond per `P`**
(`ARCHIVAL_BOND_FLOOR`); **`durability_count`** for all shards requires
**genesis enumeration** in addition. Full block:
`docs/design/FOUNDATION_GENESIS_IDENTITY_SET.md` §4–§6.

**The honest correction this forces.** "Pay for work, not wealth" was wrong, and
the per-shard bond is why: **capital re-enters, proportional to work.** The reframe
does not *escape* capital — it **re-bases** it, from "wealth as a yield multiplier"
(the old principal bond, which bonded nothing slashable) to "**capital as slashable
service-collateral**" (the bond, which bonds the actual service). That is the better
answer to the founding *Problem 1* critique: drop a shard, lose the bond, principal
untouched. The accurate slogan is **"pay for work, where doing the work requires
proportional capital-at-risk that bonds the work."** The real residual tension is
**calibration** — the bond rate must be high enough for Sybil-deterrence and the
deep-history guarantee, low enough not to exclude capital-poor-but-storage-rich
archivers — a genuine sim-and-design bind (it is G-E's overload, relocated to one
honest place), not a knob set by eye.

### The firewall is a stack, not a key

Cryptographic separation re-links if the operational layers leak — the same lesson
as everywhere else in the privacy design. Three layers must hold:

- **Network.** P's traffic — registration, liveness proofs, challenge responses,
  serving queries — must ride Tor/I2P on circuits **separate from** the wallet's
  spend/claim broadcasts, or a passive observer co-locates P and the wallet by
  circuit/IP and undoes the crypto. The query side is already mandated Tor/I2P;
  this extends the same discipline to P's own operations, and cover-traffic remains
  the right post-V3 strengthening.
- **Timing.** Stake-in (principal → `P`) and first emission pair if immediate.
  Decouple with a randomized delay/window so the pairing is ambiguous.
- **Output.** Rewards land in **stealth outputs `P` controls**; **decorrelated
  drains** on unstake-out (no lump sweep when a public `P` goes quiet). No
  linkable consolidation back to principal.
- **Bond funding.** Bond is `P`'s central collateral; lump principal→`P` bond
  funding is a correlation channel — weigh fund-from-earnings ramp vs lump initial
  bond in wallet hygiene.

### The reward curve — retention, scarcity, banded plateau-cap

- **Reward retention, not retrieval.** "Work" means **proven retention** —
  scarcity-weighted challenge-response passes over time — **not** query-serving
  volume. Rewarding retrieval volume starves the rarely-queried deep-historical
  shards (precisely the critical history), so nobody holds them. Retrieval latency
  stays where the *Verification* section puts it: a **routing-quality signal** that
  allocates queries (a secondary market), not the reward basis.
- **Challenge unpredictability.** The challenged leaf must be unpredictable
  (derive it from a *future* block hash, proof-of-retrievability style), or a holder
  stores only the challengeable subset and free-rides the rest.
- **Two composing layers.** The per-shard `1/R` inverse-replication price already
  does coverage *and* self-suppression (you become a replica when you hold a shard:
  pick up a singleton and you halve its per-shard reward; pile onto a covered shard
  and you earn almost nothing). Its job is **coverage**. The per-staker curve's only
  job is **bounding the aggregate** a single holder accumulates — it does not drive
  coverage, so a capped staker declining shard *S* simply leaves *S* scarce, paying
  more, for someone else. The two compose into "every shard covered, spread across
  many holders, none holding everything."
- **Shape: concave-to-plateau, and banded — for provability, not economics.** Per-shard
  scarcity composes into `work_P = Σ scarcity·serve_credit_bit`; the **genesis-pinned**
  payout is `reward_P = budget · Curve(work_P) / Σ_{P'∈Market} Curve(work_{P'})` (cap in
  the **numerator**, normalize by summed capped work — **not** `Curve(budget·work/Σwork)`,
  which strands budget when caps bind). See [`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md)
  §4.0. Every input is **public**, so `Curve` and `Σwork` are recomputed by verifiers. A smooth log/sqrt is a
  bad choice (transcendental-in-circuit if ever proven; awkward to recompute
  deterministically across implementations); a **piecewise-linear banded curve** is
  right — a few work-bands with monotonically decreasing marginal rates, top band
  → 0. That is the **plateau-cap**, it reuses the decade-log band machinery already
  used for the rate servo, and "more work = more reward, bounded" falls straight out
  of decreasing-slope segments ending in a flat cap.
- **Declining tail held in reserve.** A tail that *reduces* reward past the peak is
  stronger anti-hoarding but its failure mode is active shedding (stakers drop shards
  to climb back to the optimum) — the coverage gap reached by abandonment rather
  than passive non-pickup, worse in thin-population regimes. Default to the
  plateau-cap; reserve the declining tail for if cap-evasion proves live, gated on
  population so it cannot bite during thin coverage.

### What this dissolves (the convergence)

Work-based reward is **publicly computable**, which collapses the two hardest
confidential-staking threads:

- **F0 (cleartext tier reveal) dissolves at the source.** The tier was on the claim
  wire only because reward `= tier_num · amount` and the verifier needed `tier_num`
  to compute it. Reward `= f(archival work)` does not need the tier, so the
  cohort-collapse driver leaves the wire.
- **The portfolio tier oracle (F-ARCHIVAL coupling #2) dissolves too — the third
  convergence.** Because the deep-history commitment is now a **per-shard bond**
  rather than a staker tier (keystone above), there is no tier for a portfolio to
  Bayesian-signal. This is the convergence that is *earned*, not free: it holds
  **because per-shard bonds replace the staker tier**, so both tier levers (claim
  wire + portfolio) close together.
- **F-INFLATION 8a (confidential-reward soundness) transforms into a *loud* 8c.**
  With reward computed over public quantities there is no hidden amount in the
  entitlement: no `M·amount`, no bounded-remainder, no confidential reward range
  proof.   Anyone recomputes P's payout from public archival history; reward emission is
  "I am P (bond record), here is publicly-computed work, membership-only backing
  proves control, mint to stealth output; epoch *E* deduped on bond state." The only
  ZK left on the reward path is **membership-only control + stealth payout**. The existential
  soundness item does not vanish — it **moves to retention-proof unforgeability (the
  new 8c)** — but it moves from *silent* (confidential, undetectable) to *loud*
  (public, recomputable, detectable). Turning silent inflation into detectable
  inflation is the single best thing that can happen to a confidential system's
  soundness posture.

Privacy stops being "hide the amounts" and becomes entirely **firewall the
identity** — simpler to make sound and arguably more robust. **Reward is publicly
computable globally, not locally** (a P's payout needs the public aggregate
`Σwork` via the supply servo, gate 1) — but *public, not local,* is what kills
silent inflation, so 8a-dissolution survives the servo.

### Gate-list — what must be blessed before this is consensus-real

This rebasing is bigger than a curve; it changes *what staking is* (from
capital-bonded yield to **work-paid service collateralized by per-shard capital
bonds**). The near-term pin is the curve shape (banded plateau-cap,
retention-based, scarcity-weighted); the following must be resolved by simulation
and a fresh soundness pass before it ships:

1. **Σwork supply-safety servo (does not come free — but is differencing-clean).**
   Today `ρ_e = budget_e/band_sum_e` guarantees `Σreward ≤ budget_e` *by
   construction*; a per-staker plateau-cap alone bounds only per-staker *work credit*,
   not payout, unless composed correctly with the servo. The genesis-pinned composition
   is **`reward_P = budget · Curve(work_P) / Σ_{P'∈Market} Curve(work_{P'})`** — cap in
   the numerator, market-only denominator (`Σwork` = sum of capped work; foundation
   excluded per two-count table). This distributes the **full** `budget` when any market
   archiver has positive credited work; a capped whale’s foregone share flows to others.
   (Rejected: `Curve(budget·work/Σwork)` — strands budget when caps bind.) This concedes the
   earlier "locally computable" claim — a P's reward needs the public aggregate. But
   **the §14 differencing leak does *not* transfer:** `band_sum` leaked because it
   aggregated *confidential* amounts, so its deltas exposed hidden components.
   `Σwork` is a sum of **continuously public** numbers (challenge-responses are
   on-chain events, replication is a public count), so differencing it reveals
   nothing not already readable off P's public archival record. The servo is
   therefore supply-safe **and** differencing-clean — strictly better than `band_sum`
   on the privacy axis; the side-channel dies with the confidentiality of its inputs.
2. **Retention-proof soundness + state-cost (8a → loud 8c).** Reward is loud only if
   every node recomputes every P's challenge-pass record and per-shard replication —
   i.e. **per-P, per-shard retention state in consensus**, validated each claim. The
   existential soundness item moves from "hard *silent* ZK proof" to
   "**retention-proof unforgeability (8c)** + consensus state-growth/recompute cost,"
   and from undetectable to detectable. For a chain whose archival exists *because*
   tree state outgrows retention, putting the archival *reward accounting* into
   replicated state is the irony to weigh — but loud-and-bounded beats
   silent-and-existential.
3. **`R_market` derived ledger count (gate 3 dissolved — no `ν`).** Scarcity
   pricing drives the whole market reward, so a credible per-shard distinct-**market**-
   holder count is load-bearing. Under form **C**, per-`P` `Curve` grouping makes
   holdings **consensus-public**; the prior `ν = H(P_key, shard)` primitive promised
   hidden-`P` counting but is **incompatible** with the adopted reward shape (same
   dissolution as `N_arch`). **`market_R(s,E)`** is the count of market archivers with
   `serve_credit_bit ∧ good_through` at epoch close — derived from the serve-credit ledger keyed
   by public `P_id`. Privacy that remains is **P ↔ principal** (gate 6), not
   P-holdings hiding. See [`design/ARCHIVAL_CONSENSUS_STATE.md`](design/ARCHIVAL_CONSENSUS_STATE.md)
   §2–§3.
4. **Per-shard retention bond replacing tier (the keystone — collapses old G-D/G-E).**
   Deep-history retention needs a commitment to *future* retention; demonstrated
   longevity (a past signal) cannot provide it. A **slashable per-shard retention
   bond** does, and simultaneously kills the staker tier (→ F0 + portfolio oracle
   both close) and makes Sybil-splitting worthless (**total bond = shards × rate,
   independent of pseudonym count**), flipping the scarce input back to
   expensive-countable capital. It de-overloads the lock (small eligibility lock vs.
   scaling per-shard bonds = two separate parameters). The real residual is
   **bond-rate calibration** — high enough for Sybil-deterrence + deep-history
   guarantee, low enough not to exclude capital-poor-storage-rich archivers — a
   sim-and-design bind, not a knob set by eye. (This supersedes the earlier
   tier-decision / longevity-pricing framing of this gate.)
5. **Bootstrap shape — permanent foundation floor, market overlapped.**
   **Supersedes** the earlier "foundation sheds as staker coverage is
   demonstrated" bootstrap model. Foundation seed archivers hold a
   **permanent, complete-tree, reward-invisible** floor (§*Service
   promise*): bootstrap, fee-era backstop, seeding source, and
   durability anchor in one mechanism — **no `decay_pop` withdrawal.**
   Decentralization is market redundancy **above** the floor, not
   foundation withdrawal. The bootstrap **subsidy** shape remains
   **privacy-decided**: flat per-active-bonded-**market**-shard (not
   amount-scaled — resurrects F0); foundation-overlapped; sunset on the
   **subsidy**, not on the floor.
6. **`P` backing-and-firewall design (unbuilt; transfer-shaped — §2.4).**
   Off-chain backing presentation + first reward emission on-chain anchor;
   membership-only control on emission; **reward dedup on bond-record epoch bitmap**
   (no `N_arch` published tag). Bonds carry Sybil-resistance; `P` needs
   **unlinkability + firewall**, not uniqueness. Bond-funding hygiene (principal→`P`
   lump vs earnings ramp) is a residual correlation channel.
7. **Economic simulation re-priced (gate 7 — foundational; couples to §2.4 (iii)).**
   If admission principal goes soft or away, **bond-locked supply is the sole sink** —
   re-price macro `stake_ratio` / circulating-supply at the same severity as
   per-reward proof aggregate. Bond-rate calibration (item 4) is a sim output. Until
   the sim blesses the re-pricing, the rebasing is not consensus-real. The
   sim is specified (spec-first, pre-code) in
   [`design/STAKER_ARCHIVAL_SIM.md`](design/STAKER_ARCHIVAL_SIM.md); iteration 1 isolates
   **coverage dynamics** (does `1/R` + plateau-cap + per-shard bonds actually produce
   "every shard covered, spread, none-holds-everything"?), with the other gates layered as
   later iterations.

**Honest residual.** An opted-in staker has a **long-lived public pseudonymous
profile** — shard-set, longevity, performance — *by function*, and the count of
pseudonyms approximates the count of active stakes (an aggregate, like `band_sum`,
already in the accepted-leak column). Gate-3 ν dissolution and public `P_id` ledger
keying add **per-epoch retention timeline** resolution at settlement-epoch granularity
(see [`ARCHIVAL_CONSENSUS_STATE.md`](design/ARCHIVAL_CONSENSUS_STATE.md) §2, §9.2) —
distinct from the holdings-axis shard-set profile. No individual is deanonymized if
the firewall holds across all four layers (crypto + network + timing + output), but
"firewalled pseudonym" is a **discipline maintained over the pseudonym's whole life**,
not a property set once. Cross-pseudonym intersection is the residual class to name: a
person may run multiple Ps, and if those Ps share network/timing/output fingerprints
they re-merge into one profile — the firewall hygiene must hold *per pseudonym*.
(Note the keystone *relaxes* the Sybil concern here: because per-shard bonds, not
pseudonym-uniqueness, carry Sybil-resistance, running multiple Ps is not itself an
attack — it buys no bond savings — so the residual is a *privacy* hygiene concern,
not a *security* one.)

**Scope note (relation to existing sections).** This rebasing **replaces** the
two-stream confidential-yield subsystem rather than extending it: the
reserve-DLEQ entitlement, bounded-remainder range proof, and amount-scaled
`tier_num · amount` reward (`CONFIDENTIAL_STAKING.md`; `rust/shekyl-staking/`
`entitlement.rs` / `tiers.rs` / `rewards.rs`) are the *capital-bonded-yield*
machinery and are obsoleted by it, not adapted. Pre-genesis that is the right
trade — the audit-surface deletion is large and is exactly the convergence's
benefit — but it is a **replacement**, and `CONFIDENTIAL_STAKING.md` is **not**
edited to match until the tier decision (gate 4) and the supply normalizer
(gate 1) are settled, since that doc is the subsystem this would replace.

---

## Funding: where do archival rewards come from

Three candidate paths, each with tradeoffs:

**Path A: Slice from miner emission.** Reduce miner share slightly,
redirect to archival reward pool. Politically harder (miners feel taken
from). Economically clean.

**Path B: Wallet query fees.** Wallets pay per archival query, fees flow
to serving stakers. Politically easier. **Privacy concern**: query fees
create a tracked transaction stream that could undermine privacy
properties. Possibly dealbreaker.

**Path C: Component 3 adaptive burn redirect.** The Component 3 burn
mechanism is already an adaptive lever in the V3 economy. Redirecting a
small slice of the burn rate to archival rewards (during periods of high
archival demand or low staker count) flows naturally into existing
economic primitives. Aligns with existing framing of staking-as-governance:
stakers' lock-tier signal already affects emission; archival commitment
is a richer signal in the same family.

**Recommendation: Path C.** It uses the existing burn mechanism as the
adaptive lever, doesn't create new tracked transaction streams (privacy
preserved), doesn't take from miners (political ease), and matches the
existing economic philosophy of using burn rate as the network's tunable
parameter.

This needs detailed simulation. The burn-to-archival redirect rate, the
relationship between archival demand and burn modulation, the steady-state
distribution under various staker populations — all of these are the kind
of questions Rick's existing economic-simulation work on the V3 economy
would handle naturally with a parameter sweep.

---

## Bootstrap dynamics: archival load matches network maturity

Important property worth being explicit about: **the archival problem
doesn't exist at chain launch.** At block 45, the chain has 45 blocks of
state; full retention is trivial; no archival mechanism is needed.

The archival load grows with the chain. Approximately:

- **Months 0–6 post-launch (V3.0 era)**: chain is small, full retention
  is cheap for anyone. Foundation nodes carry whatever archival the
  network needs. The staker archival mechanism *exists in design* but
  has not yet shipped (V3.0 ships without it; the simulation work that
  gates V3.x ship is in flight). This is fine — the consensus-bond
  yield is the dominant return.

- **Months 6–18 post-launch (V3.x era, mechanism shipped)**: chain has
  grown enough that pruning becomes attractive for some operators.
  Foundation nodes stay full-archival. Active stakers start finding
  meaningful rare shards as pruning consumers shed deep history. The
  archival reward stream becomes meaningful. `ArchivalEngine` (Stage 5)
  has shipped in a V3.x dot-release; stakers running V3.x clients
  archive shards as part of staking.

- **Months 18+ post-launch**: archival is a real economic activity.
  Foundation nodes can selectively shed shards that are well-replicated
  by the staker market, becoming more of a coverage-floor than primary-
  archive. Staker archival is load-bearing.

This means the V3.x dot-release that ships the mechanism doesn't have
to be load-bearing immediately. The economic structure ships in place;
the load arrives when the chain is large enough to need it. No "the
mechanism has to work at launch" pressure — the V3.0 → V3.x window is
long enough for the mechanism to settle before it carries real weight.

It also means the bootstrap path naturally avoids the cold-start
allocation problem: when the first staker joins, *the network doesn't
need archival yet*, so it's fine that their allocation choices don't
cover history uniformly. By the time archival load matters, the staker
population is large enough for the market to converge to good coverage.

This phasing aligns with the V3 economy's existing late-cycle dynamics —
early-cycle stakers are mostly capital-anchoring (consensus bond
dominant), late-cycle stakers shift toward service provision (archival
reward dominant) as chain maturity demands it.

---

## V3 architectural requirements

This mechanism ships in a V3.x dot-release; V3.0 ships without it
active. V3.0's design choices must be aligned with the mechanism so the
V3.x ship is purely additive — no refactor of V3.0 surfaces required
when `ArchivalEngine` lands. Specifically:

**1. Staker reward distribution architecture supports layering an
archival reward stream.** The `staker_pool_share=25%` and
`staker_emission_share=15%` define the principal yield in V3.0. The
V3.x archival reward stream layers alongside, without modifying
principal payout. **Status: enforced by Stage 3 / Stage 5 actor
separation.** `StakeEngine` (Stage 3, principal yield) and
`ArchivalEngine` (Stage 5, archival yield) produce independent event
streams (`StakeEvent`, `ArchivalEvent`) that `LedgerEngine` merges. The
disbursement code paths accommodate two reward types by construction;
adding the second stream in V3.x is a new actor + a new event variant,
not a modification of existing disbursement logic.

**2. Tier system's lock-duration semantics remain consistent with using
lock duration as an archival commitment indicator.** Lock duration is
already a governance signal; the V3.x archival mechanism adds "archival
commitment depth" as a second meaning. **Status: already aligned.**
Lock duration is structural not nominal; nothing prevents adding a
second interpretation. The Stage 3 `StakeEngine` design pins
lock-duration semantics; the Stage 5 `ArchivalEngine` consumes those
semantics via the `is_active_staker(entity_id) -> bool` cross-actor
query plus a (TBD-by-Stage-5-design) `stake_tier(entity_id) -> Tier`
query for tier-weighted reward formulas.

**3. Component 3 governance burn redirect is flexible enough to fund a
new reward stream.** The burn-rate-to-archival path requires the
Component 3 mechanism to permit redirecting burn flow to a non-emission
target. **Status: needs confirmation against the Component 3 spec
before V3.x ship.** Tracked as a Stage 5 design-closure prerequisite;
if the existing Component 3 spec does not permit non-emission redirect
targets, the spec extension is itself a Stage 5 deliverable rather
than a V3.0 surface change.

**4. Daemon RPC surface permits "query historical state from staker
peer" alongside "query from foundation node."** Wallets need to be able
to route archival queries to either source. **Status: enforced by
Stage 4 RPC boundary refinements.** The multi-peer archival routing
client surface is drafted as part of the V3.0 RPC boundary refinements
(per `docs/FOLLOWUPS.md` V3.0 entry); activation pairs with Stage 5
shipping in V3.x. The `assemble_tree_path_for_output` RPC routing is
designed against a multi-source model from the start, not retrofitted.

**5. The wallet's daemon-selection logic does not foreclose multi-peer
archival.** V3.0's daemon-selection logic supports multi-peer routing
for historical-reference queries (foundation `--no-prune` archival as
floor; staker peers as the primary path once `ArchivalEngine` ships).
**Status: enforced by Stage 4 `DaemonEngine` migration** — the actor's
public message protocol exposes single-daemon and multi-peer routing
as first-class operations rather than retrofitting multi-peer onto a
single-daemon assumption. The V3.x ship of `ArchivalEngine` activates
the multi-peer path; V3.0 ships with the surface present and tested
against mock multi-source archival oracles.

---

## What this is not

Worth being explicit about what this design is not, because it's
adjacent to things it could be confused with.

**Not Filecoin / Storj / Sia.** Those systems make storage *the product*;
the chain coordinates storage. This design makes archival *a service the
chain needs anyway*, paid for by the chain's existing economic flow.
The currency stays a privacy currency.

**Not Helium-style infrastructure rental.** Helium pays for bandwidth
provision as the network's primary product. Stakers in Shekyl aren't
selling archival to external customers; they're providing it to their
own network's users.

**Not Ethereum validator duties.** Ethereum validators do bookkeeping
(attestation, proposal). Their work is necessary for consensus but not
externally valuable. Shekyl stakers in this model do externally
valuable work (archival service is a product the network actually
consumes).

**Not Proof-of-Useful-Work (Primecoin et al.).** Those tried to make
*mining* useful, and failed because verifiability constraints conflict
with most useful work. This design separates consensus from useful work,
which removes the conflict.

**Not a centralized service marketplace.** No Foundation-operated
"archival service" with stakers as employees. The mechanism is
permissionless: any staker can opt in, prices emerge from the market,
foundation nodes are the floor not the primary.

The structural difference from prior art: **decoupling consensus-securing
work from useful work, paying them from related but distinct streams.**
This is the move I haven't seen in any other PoS or PoW system. It's
either-or in prior art (PoW conflates them, PoS has no useful work).
Decoupling is the unconventional answer.

---

## Open design questions

These gate the V3.x ship dot-version. Each closes against simulation
evidence (per *Simulation as separate project* below) or against design
review during Stage 5.

**Shard granularity.** Per-block (too small, challenge overhead). Per-
epoch ~10,000 blocks (probably right). Needs modeling against expected
chain growth and FCMP++ state size per block.

**Query routing protocol.** DHT-style on-chain holder registry (each
shard's holders publish presence). Gossip protocol (BitTorrent-like).
Hybrid (on-chain registry of opted-in stakers, gossip for actual
discovery). Each has tradeoffs — DHT is deterministic but adds protocol
surface; gossip is more BitTorrent-faithful but less guaranteed.

**Challenge-response interval.** Per-block (excessive). Per-epoch
matched to claim windows (probably right). Per-claim-window for stakers
making active claims; longer interval for purely-passive archival.
**Consensus pin (2026-06-07):** `MAX_CLAIM_AGE_W` bounds unclaimable
epochs and prunes reward-accounting state (`ClaimedEpochSet`, retention
rows, `Σwork` history) — see
[`design/ARCHIVAL_CONSENSUS_STATE.md`](design/ARCHIVAL_CONSENSUS_STATE.md) §2.4;
[`design/REWARD_EMISSION_LEG.md`](design/REWARD_EMISSION_LEG.md) §6.6. Trades
state growth against lapse-forfeiture economics (not decorrelation — F1 T-A1).

**Price curve shape.** Naive 1/R (diminishing returns, may give weak
redundancy). 1/R² (sharper redundancy preference). Threshold function
(R=1→2 transition heavily rewarded, R=N→N+1 above some N rewarded
linearly). Needs simulation. The economic-simulation work already done
for the V3 economy is the right tool.

**Quick-pick portfolio composition.** What does "balanced portfolio"
mean concretely? Even mix across shard ages? Weighted by current
under-coverage? Tied to staker tier (tier-3 quick-pick gets deep-
history, tier-1 gets recent)? Needs design.

**Unstake-cascade dynamics.** When a staker unstakes, their shards
shift to the market's "available" pool. The lock-tier system means
unstaking happens on a schedule, but mass unstaking events (price
crash, foundation policy change) could compress this. Simulation would
clarify the failure modes.

**Privacy-of-queries detailed protocol.** Mandatory Tor/I2P is the V3
ship default; cover-traffic protocols are post-V3-ship. The exact
integration with existing `ANONYMITY_NETWORKS.md` infrastructure needs
design.

**Foundation-node integration.** Foundation seed archivers are
genesis-enumerated complete-tree holders (§*Service promise*). They
serve publicly auditable complete archives, participate in challenges,
and are **fully excluded from market reward math**. The market self-
organizes on `market_R`; `durability_count` observability reports how
much redundancy exists above the foundation floor. No "signal shards X,Y,Z
so the market de-prioritizes" protocol is required — the economic split
already prices as if the foundation is not there.

---

## Simulation as separate project

This design must be validated via simulation before the V3.x dot-
release that ships `ArchivalEngine`. Treat the simulation as a separate
project, parallel to (not blocking) the V3.0 ship. The simulation
output is the gating evidence for closing the open design questions
above.

**Scope of simulation:**

- Parameter sweep on the price curve shape (1/R vs 1/R² vs threshold
  variants). Measure equilibrium replication factor distributions across
  shard rarity classes.
- Stress tests on staker population dynamics: cold-start (few stakers),
  steady-state (large stable population), unstake cascade (mass exit
  event), tier-distribution skew (mostly tier-1 vs mostly tier-3).
- Economic stress tests: low query demand (reward signal weak), high
  query demand (reward signal strong), oscillating demand (does the
  market respond fast enough?).
- Adversarial scenarios: lazy-storage attackers, sybil attackers
  (multiple stake identities chasing the same shard), targeted-
  censorship attackers.
- Cold-start/late-cycle phase analysis: how does the mechanism behave
  through the months-0-to-18 maturity arc?

**Inputs:** good (well-distributed stakers, normal demand), bad
(over-clustering on hot shards, under-coverage of cold tail), ugly
(mass unstaking events, demand spikes, staker collusion).

**Outputs:** coverage maps (which shards have what replication),
reward distributions (who earns what under what conditions), failure
mode characterization (what breaks first as parameters degrade).

The economic-simulation infrastructure already built for the V3 economy
is the right starting point. The shape of the simulation is similar
(parameter sweep, scenario suite, heatmap visualization), just over a
different state space (shard coverage rather than supply curves).

The simulation project is a useful artifact independent of the V3.x
ship dot-version: it produces public documentation of how the mechanism
would behave, which can inform the community discussion that should
precede the V3.x activation.

---

## Conclusion

This design is the answer to the long-running "what real work do
stakers do?" question. The mechanism is:

1. **Stakers archive the chain** as part of the staking protocol, not as
   a separate service.
2. **Shards are priced by scarcity**, not by demand. Rare shards pay
   more.
3. **Quick-pick allocation** for passive stakers; active stakers play
   the rare-shard market.
4. **Challenge-response verification**, no human judgment.
5. **Decoupled rewards**: archival yield is additive to principal yield,
   never slashes principal.
6. **Tier system handles depth**: tier-3 long-lock stakers naturally
   take critical-history shards, tier-1 short-lock stakers take hot-set.
7. **Privacy preserved** via mandatory Tor/I2P routing on archival
   queries.
8. **Funding via Component 3 burn redirect**, leveraging existing
   adaptive economic mechanism.
9. **Bootstrap-aligned**: archival load grows with chain maturity, so
   the V3.x ship dot-release does not need to be immediately load-
   bearing.
10. **Actor-architecture aligned**: `ArchivalEngine` is a Stage 5 actor,
    sibling to `StakeEngine` (not a child), enforcing slashing-domain
    integrity, failure isolation, and the Hayekian shard-market
    property at the architectural level.

The structural innovation: **decoupling consensus-securing work from
useful work**, paying them from related but distinct streams, letting
stakers self-select. This pattern doesn't appear in prior PoS, PoW, or
storage-chain designs.

> **Update (F-ARCHIVAL resolution — see *Pay-for-service rebasing*).** Following
> *Problem 1* to its end shows there is no consensus-securing *service* to pay for
> (PoW does consensus; the principal bonds nothing slashable). The steady-state
> innovation is sharper and simpler than "decouple two streams": **staking is the
> opt-in to archival because staking = archiving**, one work-paid reward, principal
> as a small eligibility gate, the deep-history commitment and Sybil cost carried by
> **per-shard retention bonds** (the keystone — capital re-based to slashable
> service-collateral), privacy via a firewalled pseudonym. Points 5 (additive
> two-stream rewards) and 6 (tier-sorted depth) above are superseded by the
> single-stream, tier-neutral, **per-shard-bonded** model, pending the gate-list.

V3.0 ships with the architectural surface in place (Stage 4 RPC
boundary refinements, multi-peer archival routing client surface,
`StakeEngine` cross-actor query exposed) but with the mechanism not
yet active. V3.x ships `ArchivalEngine` itself (Stage 5), gated on
simulation evidence that closes the open design questions. The V3.x
activation is purely additive — no consensus-layer hard fork required,
no V3.0 surface refactor required, no migration code required.
Simulation work proceeds as a separate project; its conclusions gate
the dot-version, not the existence of the mechanism.

---

## References and cross-cutting concerns

- `docs/V3_WALLET_DECISION_LOG.md` — *2026-04-27 — Engine architecture:
  actor model with staged migration from composition* (canonical pin
  of `ArchivalEngine` as Stage 5 sibling actor; the rescoping of this
  document from V4 to V3 ship)
- `docs/V3_SHARD_VISUALIZATION.md` — companion shard-surface design
  (deterministic data art over shard content; shipped via the
  `shekyl-shard-visual` library crate; companion to this archival
  mechanism)
- `docs/FOLLOWUPS.md` — V3.0 RPC boundary refinements (multi-peer
  archival routing client surface), V3.1 sibling-resolution entry for
  `assemble_tree_path_for_output` (FCMP++ historical-reference cutover
  via Stage 5 `ArchivalEngine`), V3.x Stage 5 `ArchivalEngine` native
  build, V3.x no-tradeability invariant codification
- `docs/DESIGN_CONCEPTS.md` — V3 economic structure
  (`staker_pool_share`, `staker_emission_share`, lock tiers,
  Component 3 governance)
- `docs/ANONYMITY_NETWORKS.md` — existing Tor/I2P infrastructure
- `docs/PUBLIC_NARRATIVE_FAQ.md` — user/partner archival promise (2026-06)
- `docs/design/FOUNDATION_ARCHIVAL_DISCLOSURE.md` — legal disclosure draft
- `docs/SEED_NODE_DEPLOYMENT.md` — foundation `--no-prune` archival
  policy
- `docs/STAKER_REWARD_DISBURSEMENT.md` — existing reward distribution
  mechanics that the V3.x archival stream layers atop
