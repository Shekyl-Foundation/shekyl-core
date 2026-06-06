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

Reward per shard is **inversely proportional to current replication
count**. A shard held by 1 staker pays the maximum per-byte rate; a shard
held by 5 stakers splits a smaller pool. Rare shards pay more than common
shards. Stakers actively hunting for under-served shards earn more than
stakers piling onto popular ones.

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

> **Superseded in steady state by *Pay-for-service rebasing* below (the tier
> decision, gate 4).** The tier-weighted pricing described here is the **tier
> oracle** F-ARCHIVAL identifies: it makes the public shard-set Bayesian evidence
> of the backing stake's tier. The rebasing replaces tier-weighted pricing with
> **tier-neutral, longevity-priced** critical-shard stability, recovering the
> coverage property without the tier disclosure. Read this subsection as the
> rationale for the property longevity-pricing must reproduce (deep-history
> retention-horizon matching), not the current target.

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
pricing needs a per-shard distinct-holder count (reward ∝ `1/R`), and counting
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
  bonding anything; it is locked coins.
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
  staker does not rage-unstake). The lock stops being a yield multiplier and
  becomes three things: the **price of admission**, the **per-pseudonym Sybil
  cost** (below), and a **credibility/longevity signal** (longer lock buys
  deeper-archival standing, not a larger yield coefficient).

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

**Replace the direct `entity_id` binding with membership-proof registration — the
claim primitive in persistent shape.** Today `StakeEngine::is_active_staker(entity_id)
-> bool` is a direct, linkable lookup that ties archival to the stake. Replace it:

- At registration, the archival pseudonym **P** proves *"some active stake backs
  me"* via an FCMP++ membership proof against the active-stake root — **not** a named
  `entity_id`.
- A per-stake **archival nullifier `N_arch = x·G_arch`** over a NUMS base
  **independent of both `Hp(O)`** (spend image) **and `G_S`** (claim nullifier).
  The nullifier does double duty: **Sybil-resistance** (one stake → one archival
  identity, so a single bond cannot farm parallel reward streams) and **uniqueness
  without revealing which stake**.
- **P is an independent keypair, HKDF-derived from the wallet seed** exactly like
  the multi-account independent keypairs — *not* an algebraic offset of the stake
  key, so there is no cross-derivable link.
- **Eligibility-over-time is a periodic liveness re-proof** against the *current*
  active-stake root, folded into the challenge cadence. It lapses automatically when
  the backing stake unstakes (leaf gone → proof fails), with no re-linkage: all of
  P's proofs share `N_arch` and are all P anyway.

Net on-chain: **P ↔ shard-set ↔ performance is public under the pseudonym; which
stake backs it, that stake's tier/creation/amount, and the person's
claim/spend/principal identity are all hidden behind a membership proof.** This is
almost entirely re-composition — membership proof + DDH-independent nullifier +
HKDF key — so it is low-new-primitive in the project's sense. The one genuinely new
element is the **persistent-pseudonym lifecycle** (register once, live long,
re-prove liveness), and it **extends the T7 DDH requirement to a third independent
base `{Hp(O), G_S, G_arch}`** that must be mutually independent.

### Tier-neutral shard pricing — breaking the tier oracle

Even firewalled, P's shard-set is public, and the *Tier interaction* tier-weighted
pricing makes that shard-set a **tier oracle**: a deep-historical portfolio
Bayesian-signals a tier-3 backing stake, re-leaking the exact tier the
confidential-staking claim wire spends effort protecting (F0) and narrowing which
stakes could back P. The fix is **tier-neutral shard pricing** — price purely by
replication scarcity (the BitTorrent insight), so any tier profitably holds any
shard and the sorting disappears.

But tier-weighting was buying something real: **coverage stability for critical
shards** (tier-1 churn creates gaps). Recover that **without** the oracle by
pricing the critical-shard stability premium on **demonstrated holding-longevity
rather than tier-class**: a holder who keeps a shard a long time earns the stability
premium *regardless of tier*; a churner does not, regardless of tier. Longevity is
observable under the pseudonym but **is not tier** (a re-staking tier-1 holder can
be stable; a tier-3 can exit early), so it decouples the stability incentive from
tier disclosure. **The cost is losing the "tier-3 stakers naturally become the
archivists" emergent elegance** — a genuine privacy-vs-elegance trade, paid because
otherwise tier-neutralizing the claim wire is pointless while this sibling layer
re-publishes tier. (This is also why de-tiering the claim alone stays parked: it is
the *portfolio* channel that must be neutralized, and longevity-pricing does that
without touching the claim economics.)

### The firewall is a stack, not a key

Cryptographic separation re-links if the operational layers leak — the same lesson
as everywhere else in the privacy design. Three layers must hold:

- **Network.** P's traffic — registration, liveness proofs, challenge responses,
  serving queries — must ride Tor/I2P on circuits **separate from** the wallet's
  spend/claim broadcasts, or a passive observer co-locates P and the wallet by
  circuit/IP and undoes the crypto. The query side is already mandated Tor/I2P;
  this extends the same discipline to P's own operations, and cover-traffic remains
  the right post-V3 strengthening.
- **Timing.** Because the model is ~one P per stake, a P registering right after a
  stake tx pairs them. Decouple registration timing from stake creation with a
  randomized delay/window so the pairing is ambiguous.
- **Output.** P's reward (via the Path C burn-redirect funding, which correctly
  avoids a per-query fee stream) lands in a **stealth output P controls** and must
  not be consolidated back into the stake/spend wallet linkably — standard
  unlinkable-output hygiene applied to archival yield.

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
- **Shape: concave-to-plateau, and banded — for provability, not economics.** The
  reward is `Curve(Σ_shards scarcity(shard) · proven_retention(P, shard))`. Every
  input is **public** (P's challenge-pass record, public replication counts, public
  curve parameters), so `Curve` is recomputed by verifiers. A smooth log/sqrt is a
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
  cohort-collapse driver leaves the wire. (Whole-system tier privacy still requires
  the tier-neutral pricing above — that is the *portfolio* channel, F-ARCHIVAL
  coupling #2 — which is why both levers move together.)
- **F-INFLATION 8a (confidential-reward soundness) dissolves.** With reward computed
  over public quantities there is no hidden amount in the entitlement: no
  `M·amount`, no bounded-remainder, no confidential reward range proof. Anyone
  recomputes P's payout from public archival history; the claim collapses to "I am
  P, P is backed by some active stake (membership + `N_arch`), here is my
  publicly-computed reward, mint it to a stealth output." The only ZK left on the
  reward path is **membership/backing + the stealth payout**. Silent inflation has
  nothing confidential left to hide in — it becomes loud (recomputable) rather than
  silent.

Privacy stops being "hide the amounts" and becomes entirely **firewall the
identity** — simpler to make sound and arguably more robust.

### Gate-list — what must be blessed before this is consensus-real

This rebasing is bigger than a curve; it changes *what staking is* (from
capital-bonded yield to work-paid service with a capital eligibility gate). The
near-term pin is the curve shape (banded plateau-cap, retention-based,
scarcity-weighted); the following must be resolved by simulation and a fresh
soundness pass before it ships:

1. **Aggregate supply-safety normalizer (does not come free).** Today the servo
   `ρ_e = budget_e/band_sum_e` guarantees `Σreward ≤ budget_e` *by construction*.
   A per-staker plateau-cap bounds only per-staker reward; nothing bounds the
   aggregate. Restoring supply-safety needs `reward_P = budget · work_P / Σwork` —
   a servo over **`Σwork`** — which reintroduces a global-state dependency *and* a
   **differencing leak** (a large archiver entering/leaving moves `Σwork`
   observably), the §14 `band_sum`-differencing concern reborn on archival work.
2. **Retention-proof soundness + state-cost (8a transforms, not vanishes).** Reward
   becomes loud only if every node recomputes every P's challenge-pass record and
   per-shard replication — i.e. **per-P, per-shard retention state in consensus**,
   validated each claim. The existential soundness item moves from "hard ZK proof"
   to "retention-proof unforgeability + consensus state-growth/recompute cost." For
   a chain whose archival exists *because* tree state outgrows retention, putting
   the archival *reward accounting* into replicated state is the irony to weigh.
3. **Private replication counting becomes central, not peripheral.** Scarcity
   pricing now drives the *whole* reward, so a credible per-shard distinct-holder
   count `R` is load-bearing. Counting holders without identifying them (private set
   cardinality / proof-of-distinct-holders) is the unsolved primitive public binding
   gets for free; the firewalled-pseudonym model makes private binding the
   presumption, so this primitive must be solved.
4. **The tier decision (no "free" option).** Either tier **dies** system-wide
   (F0 + the portfolio tier-oracle both close, but the deep-history
   retention-horizon matching that tier-weighting provided must be fully recovered by
   longevity-pricing), **or** tier **lives** as retention-horizon matching and the
   oracle lives with it. "Tier falls out for free" is not available; longevity-pricing
   is the proposed replacement and must be shown to cover critical-history matching.
5. **Sybil scarce-input shift + overloaded lock.** The scarce, security-relevant
   input moves from **capital** (expensive, semi-visible on-chain) to **storage +
   bandwidth** (cheap, invisible, firewall-hidden): a data-center actor runs many Ps
   cheaply, and unlinkable Ps mean you cannot tell ten archivers from one actor
   running ten. The only lever is the per-P locked principal as Sybil cost — but
   that lock is **overloaded**: minimizing it (the monetary concern, since
   work-decoupled reward shrinks locked supply toward minimum × population) makes
   Sybiling cheap and the cap toothless. Calibrate the cap against "capital a whale
   must lock to evade," a **simulation input**, accepting that privacy and
   cap-enforced decentralization are in irreducible tension (an identity-counting
   problem a privacy chain refuses to solve).
6. **Bootstrap shape (months 0–6).** With no archival load yet, either pay nothing
   (zero staker population at the foundation→staker handoff — a cold-start coverage
   cliff exactly when archival begins to matter) or pay a **named, time-limited
   launch subsidy** that sunsets into archival-conditional. A subsidy is the retired
   rent, temporarily; its **privacy shape matters** — a flat per-P subsidy is clean,
   an amount-scaled one resurrects F0/8a for the bootstrap window.
7. **`P` / `N_arch` are unbuilt.** No `N_arch`, `G_arch`, or pseudonym primitive
   exists in code or design today. The persistent-pseudonym lifecycle and the
   one-P-per-stake binding are the crux on which the whole privacy reframe rests and
   must be designed and soundness-reviewed, not assumed.

**Honest residual.** An opted-in staker has a **long-lived public pseudonymous
profile** — shard-set, longevity, performance — *by function*, and the count of
pseudonyms approximates the count of active stakes (an aggregate, like `band_sum`,
already in the accepted-leak column). No individual is deanonymized if the firewall
holds across all four layers (crypto + network + timing + output), but "firewalled
pseudonym" is a **discipline maintained over the pseudonym's whole life**, not a
property set once. Cross-pseudonym intersection is the residual class to name: a
person with multiple stakes runs multiple Ps (one per stake, by the nullifier), and
if those Ps share network/timing/output fingerprints they re-merge into one
profile — the firewall hygiene must hold *per pseudonym*.

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

**Foundation-node integration.** Foundation `--no-prune` nodes are the
floor. How do they signal "I'm covering shards X, Y, Z so the staker
market can de-prioritize them"? Or do they just always serve and let
the market self-organize? The latter is simpler; the former is more
economically efficient. Needs design.

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
> as collateral-and-Sybil-cost, privacy via a firewalled pseudonym. Points 5
> (additive two-stream rewards) and 6 (tier-sorted depth) above are superseded by
> the single-stream, tier-neutral / longevity-priced model, pending the gate-list.

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
- `docs/SEED_NODE_DEPLOYMENT.md` — foundation `--no-prune` archival
  policy
- `docs/STAKER_REWARD_DISBURSEMENT.md` — existing reward distribution
  mechanics that the V3.x archival stream layers atop
